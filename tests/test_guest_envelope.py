"""Strict negotiated guest grammar executed by the real portable C parser."""
import base64
import copy
import ctypes
import hashlib
import hmac
import json
import unittest
import test_public_selection as selection
from test_reuse_cookie_inputs import seal_recipe

class ExtendedSelection(ctypes.Structure):
    _fields_=selection.Selection._fields_+[('source_only',ctypes.c_uint),('resolved',ctypes.c_void_p),('guest_inputs',ctypes.c_void_p)]

POLICY='a'*64
WP='b'*64
GUEST='d'*64
EPOCH='e'*64
URL='/guest/?functional=1'

def sample():
    body='<html>empty cart; nonce placeholder; Ελληνικά</html>'.encode()
    return dict(schemaVersion=1,requestId='42',originalUrl=URL,guestPublic=dict(
        policyDigest=POLICY,wordpressPolicyDigest=WP,guestPolicyDigest=GUEST,
        registryEpoch=EPOCH,scope='/',manifest='signed.guest',sourceManifest='signed.source',
        sourceGeneration='f'*64,resolvedOccurrences=13,
        publicParent=dict(generation=hashlib.sha256(body).hexdigest(),
            bodyBase64=base64.b64encode(body).decode(),freshRemaining=1234),
        headers=['Content-Type: text/html; charset=UTF-8','Vary: Accept'],cookieDelivery='deferred'))

@unittest.skipUnless(selection.CC,'C compiler required; skip is not acceptance')
class GuestEnvelope(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        selection.PublicSelection.setUpClass.__func__(cls)
        cls.lib.delivery_guest_selection_parse.argtypes=[ctypes.c_void_p,ctypes.c_size_t]+[ctypes.c_char_p]*7+[
            ctypes.POINTER(selection.SelectionPointer)]
        cls.lib.delivery_guest_selection_parse.restype=ctypes.c_int
        cls.lib.delivery_hmac_sha256.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p]
        cls.lib.delivery_hmac_sha256.restype=ctypes.c_int
    tearDownClass=classmethod(selection.PublicSelection.tearDownClass.__func__)
    def parse(self,value,**changes):
        body=json.dumps(value,ensure_ascii=False).encode() if isinstance(value,dict) else value
        result=selection.SelectionPointer()
        args=dict(request='42',url=URL,policy=POLICY,wordpress=WP,guest=GUEST,epoch=EPOCH,scope='/')
        args.update(changes)
        try:
            ok=self.lib.delivery_guest_selection_parse(body,len(body),*[v.encode() for v in args.values()],ctypes.byref(result))
            if not ok:return None
            p=result.contents.parent.contents
            return dict(guest=result.contents.guest,body=ctypes.string_at(p.body,p.length),
                ttl=p.fresh_remaining,privateCount=result.contents.occurrences,
                guestInputs=bool(ctypes.cast(result,ctypes.POINTER(ExtendedSelection)).contents.guest_inputs))
        finally:self.lib.delivery_selection_free(result)
    def test_hmac_rfc4231_vectors_and_independent_block_boundary_inputs(self):
        vectors=[(b'\x0b'*20,b'Hi There','b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'),
            (b'Jefe',b'what do ya want for nothing?','5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843')]
        vectors += [(bytes(range(256))[:n],b'context'+b'x'*length,None) for n in (0,1,63,64,65,131) for length in (0,1,55,56,63,64,65,1024)]
        for key,body,expected in vectors:
            out=ctypes.create_string_buffer(65)
            self.assertEqual(self.lib.delivery_hmac_sha256(key,len(key),body,len(body),out),1)
            self.assertEqual(out.value.decode(),expected or hmac.new(key,body,hashlib.sha256).hexdigest())

    def test_complete_guest_bytes_and_real_remaining_budget(self):
        s=sample();out=self.parse(s)
        self.assertEqual(out['guest'],1);self.assertEqual(out['ttl'],1234)
        self.assertEqual(out['privateCount'],0)
        self.assertEqual(out['body'],base64.b64decode(s['guestPublic']['publicParent']['bodyBase64']))

    def test_optional_exact_recipe_includes_expanded_private_multiplicity_not_public_count(self):
        recipe=seal_recipe(dict(inputs=dict(cookieNames=['actual_session'],cookiePrefixes=['auth_'],phpMaxInputVars=1000),
            fragments=[dict(url='/nested?token=€',provider='actual-provider',occurrences=6)]))
        v=sample();v['guestPublic']['guestInputs']=dict(version=1,privateOccurrences=6,recipe=recipe)
        self.assertTrue(self.parse(v)['guestInputs']) # six private within thirteen total
        self.assertTrue(self.parse(json.dumps(v,ensure_ascii=True).encode())['guestInputs'])
        v['guestPublic']['guestInputs']['privateOccurrences']=7
        self.assertFalse(self.parse(v)['guestInputs'])

    def test_empty_actual_closure_and_malformed_extension_preserve_legacy_guest(self):
        recipe=seal_recipe(dict(inputs=dict(cookieNames=[],cookiePrefixes=[],phpMaxInputVars=321),fragments=[]))
        valid=dict(version=1,privateOccurrences=0,recipe=recipe)
        v=sample();v['guestPublic']['guestInputs']=valid
        self.assertTrue(self.parse(v)['guestInputs'])
        for bad in (None,True,[],{},dict(valid,version=2),dict(valid,privateOccurrences=14),
                    dict(valid,recipe=dict(recipe,digest='0'*64))):
            v=sample();v['guestPublic']['guestInputs']=bad
            with self.subTest(bad=bad):
                out=self.parse(v);self.assertIsNotNone(out);self.assertFalse(out['guestInputs'])
        raw=json.dumps(sample()).encode().replace(b'"cookieDelivery": "deferred"',
            b'"cookieDelivery":"deferred","guestInputs":'+json.dumps(valid).encode()+
            b',"guestInputs":'+json.dumps(valid).encode())
        self.assertFalse(self.parse(raw)['guestInputs'])

    def test_extended_candidate_uses_existing_shared_fallback_and_explicit_actions(self):
        self.lib.delivery_selection_all_shared.argtypes=[ctypes.c_char_p,ctypes.c_char_p]
        self.lib.delivery_selection_all_shared.restype=ctypes.c_int
        rules=b'shared\tprefix\tmetric_\nvariant\texact\tcurrency\nprivate\texact\tauth\n'
        for raw,expected in ((b'metric_a=1; metric_b=2',1),(b'unknown=1',1),
            (b'metric_a=1; currency=EUR',0),(b'auth=1',0),(b'',0),(b'metric_a',0)):
            self.assertEqual(self.lib.delivery_selection_all_shared(raw,rules),expected)
    def test_all_owner_bindings_are_exact(self):
        for name in ('request','url','policy','wordpress','guest','epoch','scope'):
            with self.subTest(name=name):self.assertIsNone(self.parse(sample(),**{name:'different'}))
    def test_missing_unknown_and_duplicate_fields_are_rejected(self):
        for key in sample()['guestPublic']:
            v=sample();del v['guestPublic'][key]
            with self.subTest(key=key):self.assertIsNone(self.parse(v))
        v=sample();v['guestPublic']['unexpected']=True;self.assertIsNone(self.parse(v))
        raw=json.dumps(sample()).encode()
        self.assertIsNone(self.parse(raw.replace(b'"resolvedOccurrences": 13',b'"resolvedOccurrences": 13,"resolvedOccurrences": 13')))
        self.assertIsNone(self.parse(raw.replace(b'"requestId": "42"',b'"requestId": "42","requestId": "42"')))
    def test_every_truncated_prefix_and_trailing_bytes_reject(self):
        raw=json.dumps(sample()).encode()
        for end in range(len(raw)):self.assertIsNone(self.parse(raw[:end]),str(end))
        self.assertIsNone(self.parse(raw+b'{}'))
    def test_no_private_transport_or_issuer_fields_in_guest_headers(self):
        for header in ('Set-Cookie: owner=x','Set-Cookie2: owner=x','X-UltraCache-Delivery-Prepare: /private',
            'X-UltraCache-ESI-Private-Count: 0','X-UltraCache-Cookie-Delivery: 1',
            'Surrogate-Control: ESI/1.0',
            'Authorization: secret','X-SCP-Guest-Complete: 1','Vary: *'):
            v=sample();v['guestPublic']['headers'].append(header)
            with self.subTest(header=header):self.assertIsNone(self.parse(v))
    def test_valid_guest_does_not_relax_old_selection_schema(self):
        raw=json.dumps(sample()).encode();out=selection.SelectionPointer();document=selection.DocumentPointer()
        try:self.assertEqual(self.lib.delivery_selection_parse(raw,len(raw),b'42',URL.encode(),POLICY.encode(),WP.encode(),ctypes.byref(out),ctypes.byref(document)),0)
        finally:self.lib.delivery_selection_free(out);self.lib.delivery_private_document_free(document)
    def test_bad_body_digest_unresolved_esi_and_invalid_integer_claims_reject(self):
        v=sample();v['guestPublic']['publicParent']['generation']='0'*64;self.assertIsNone(self.parse(v))
        for val in (True,-1,1.5,'13'):
            v=sample();v['guestPublic']['resolvedOccurrences']=val;self.assertIsNone(self.parse(v))
        for body in (b'<html><esi:include src="/private"/></html>',b'<html><ESI:INCLUDE src="/private"/></html>'):
            v=sample();v['guestPublic']['publicParent'].update(bodyBase64=base64.b64encode(body).decode(),generation=hashlib.sha256(body).hexdigest())
            self.assertIsNone(self.parse(v))

if __name__=='__main__':unittest.main()
