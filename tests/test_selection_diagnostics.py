"""Fixed first-failure diagnostics never change the existing C grammar."""
import base64
import ctypes
import hashlib
import json
import unittest
from test_guest_envelope import sample as guest_sample, POLICY, WP, GUEST, EPOCH, URL
from test_delivery_envelope import CC, DeliveryEnvelope, DocumentPointer
from test_public_selection import SelectionPointer, sample as selected_sample, URL as SELECTED_URL


@unittest.skipUnless(CC, 'Actual C compiler required; a skip is not acceptance')
class SelectionDiagnostics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        DeliveryEnvelope.setUpClass.__func__(cls)
        cls.lib.delivery_selection_free.argtypes = [SelectionPointer]
        cls.lib.delivery_guest_selection_parse_diagnostic.argtypes = [ctypes.c_void_p, ctypes.c_size_t]+[
            ctypes.c_char_p]*7+[ctypes.POINTER(SelectionPointer), ctypes.POINTER(ctypes.c_char_p)]
        cls.lib.delivery_guest_selection_parse_diagnostic.restype = ctypes.c_int
        cls.lib.delivery_public_source_parse_diagnostic.argtypes = [ctypes.c_void_p, ctypes.c_size_t]+[
            ctypes.c_char_p]*4+[ctypes.POINTER(SelectionPointer), ctypes.POINTER(ctypes.c_char_p)]
        cls.lib.delivery_public_source_parse_diagnostic.restype = ctypes.c_int
    tearDownClass = classmethod(DeliveryEnvelope.tearDownClass.__func__)

    def diagnostic(self, value, guest=True):
        raw = json.dumps(value).encode() if isinstance(value, dict) else value
        selected = SelectionPointer(); reason = ctypes.c_char_p(b'previous-call')
        if guest:
            accepted = self.lib.delivery_guest_selection_parse_diagnostic(raw, len(raw), b'42', URL.encode(),
                POLICY.encode(), WP.encode(), GUEST.encode(), EPOCH.encode(), b'/', ctypes.byref(selected), ctypes.byref(reason))
        else:
            accepted = self.lib.delivery_public_source_parse_diagnostic(raw, len(raw), b'42', SELECTED_URL.encode(),
                POLICY.encode(), WP.encode(), ctypes.byref(selected), ctypes.byref(reason))
        try:
            self.assertEqual(bool(selected), bool(accepted))
            return bool(accepted), reason.value.decode() if reason.value else None
        finally:
            self.lib.delivery_selection_free(selected)

    def source(self):
        value = selected_sample(); s = value['selectedPublic']
        s.pop('cookieUpdates'); s.pop('renderedFragments'); s['publicSource'] = dict(version=1, role='parent-v1')
        return value

    def test_valid_guest_and_source_reset_previous_failure(self):
        for guest, value in ((True, guest_sample()), (False, self.source())):
            self.assertEqual(self.diagnostic(value, guest), (True, None))

    def test_surrogate_privacy_rejects_both_roles_without_recording_values(self):
        for name, code in (('Surrogate-Control', 'header-surrogate-control-private'),):
            for guest, value, key in ((True, guest_sample(), 'guestPublic'), (False, self.source(), 'selectedPublic')):
                value[key]['headers'].append(name+': no-cache, private-secret-marker')
                self.assertEqual(self.diagnostic(value, guest), (False, code))

    def test_guest_reports_first_header_failure_and_clears_it_next_call(self):
        value = guest_sample(); value['guestPublic']['headers'] += ['Surrogate-Control: no-store', 'Set-Cookie: private=secret']
        self.assertEqual(self.diagnostic(value), (False, 'header-surrogate-control-private'))
        self.assertEqual(self.diagnostic(guest_sample()), (True, None))

    def test_bound_public_roles_preserve_restrictive_browser_policy(self):
        for guest, value, key in ((True, guest_sample(), 'guestPublic'), (False, self.source(), 'selectedPublic')):
            value[key]['headers'] += ['Cache-Control: private, no-store', 'Pragma: no-cache',
                'Expires: Thu, 19 Nov 1981 08:52:00 GMT']
            self.assertEqual(self.diagnostic(value, guest), (True, None))

    def test_guest_binding_digest_and_unexpanded_body_have_distinct_reasons(self):
        for key, code in (('policyDigest', 'guest-native-policy'), ('wordpressPolicyDigest', 'guest-wordpress-policy'),
                ('guestPolicyDigest', 'guest-policy'), ('registryEpoch', 'guest-epoch'), ('scope', 'guest-scope')):
            value = guest_sample(); value['guestPublic'][key] = 'unexpected-private-value'
            self.assertEqual(self.diagnostic(value), (False, code))
        value = guest_sample(); value['guestPublic']['publicParent']['generation'] = '0'*64
        self.assertEqual(self.diagnostic(value), (False, 'guest-body-digest'))
        body = b'<html><esi:include src="/private-secret-marker"/></html>'
        value = guest_sample(); value['guestPublic']['publicParent'].update(
            generation=hashlib.sha256(body).hexdigest(), bodyBase64=base64.b64encode(body).decode())
        self.assertEqual(self.diagnostic(value), (False, 'guest-unexpanded-esi'))

    def test_required_and_outer_grammar_remain_rejected(self):
        value = guest_sample(); del value['guestPublic']['cookieDelivery']
        self.assertEqual(self.diagnostic(value), (False, 'guest-required-fields'))
        self.assertEqual(self.diagnostic(json.dumps(guest_sample()).encode()+b'{}'), (False, 'guest-outer-grammar'))
        value = self.source(); value['selectedPublic']['publicParent']['generation'] = '0'*64
        self.assertEqual(self.diagnostic(value, False), (False, 'selection-body-digest'))

    def test_projected_parent_uses_the_same_first_header_rejection(self):
        function = self.lib.delivery_projected_selection_parse_diagnostic
        function.argtypes = [ctypes.c_void_p, ctypes.c_size_t]+[ctypes.c_char_p]*4+[
            ctypes.c_int, ctypes.POINTER(SelectionPointer), ctypes.POINTER(DocumentPointer),
            ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_char_p)]
        function.restype = ctypes.c_int
        for invalid in (False, True):
            value = self.source(); value['selectedPublic']['resolvedPublic'] = dict(
                version=1, bucket='orig', locale='en_US', language='en', cookieValues=[])
            value['selectedPublic']['headers'] += ['Cache-Control: private, no-store', 'Pragma: no-cache']
            if invalid: value['selectedPublic']['headers'].append('Surrogate-Control: no-store')
            raw = json.dumps(value).encode(); selected = SelectionPointer(); document = DocumentPointer()
            projection = ctypes.c_void_p(); reason = ctypes.c_char_p()
            try:
                accepted = function(raw, len(raw), b'42', SELECTED_URL.encode(), POLICY.encode(), WP.encode(),
                    1, ctypes.byref(selected), ctypes.byref(document), ctypes.byref(projection), ctypes.byref(reason))
                self.assertEqual(bool(accepted), not invalid)
                self.assertEqual(reason.value, b'header-surrogate-control-private' if invalid else None)
            finally:
                self.lib.delivery_selection_free(selected); self.lib.delivery_private_document_free(document)


if __name__ == '__main__': unittest.main()
