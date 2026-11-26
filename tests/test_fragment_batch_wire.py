"""Actual portable C batch codec; not native dispatch or WP owner qualification."""
import base64
import copy
import ctypes
import hashlib
import json
import unittest
from pathlib import Path

from test_delivery_envelope import DeliveryEnvelope, CC


PRIVATE = '/?ultracache_esi=descriptor-a&esi_scope=private'
ADAPTIVE = '/?ultracache_esi=descriptor-b&esi_identity=wordpress'
REQUEST = '/shop/index.php?ultracache_fragment_delivery=public-token'


def payload():
    return dict(schemaVersion=1, sourceUrl='/catalog/', context=dict(
        policy='a'*64, bucket='html', cookies='b'*64, locale='en_US', language=''),
        fragments=[dict(url=PRIVATE, occurrences=2), dict(url=ADAPTIVE, occurrences=1)])


def token(value):
    raw = value if isinstance(value, bytes) else json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b'=') + b'.' + b'c'*64


def envelope(wire):
    return dict(schemaVersion=2, requestId='123', originalUrl=REQUEST,
        requestDigest=hashlib.sha256(b'ultracache-fragment-delivery-v1\n'+wire).hexdigest(),
        renderedFragments=[dict(url=PRIVATE, html='<div>actual</div>', occurrences=2)],
        failedFragments=[dict(url=ADAPTIVE, occurrences=1, status=503, code='renderer-unavailable')])


def authority():
    return dict(scope='/shop/', epoch='1'*64, incarnation='2'*64, scopeRevision='3'*64,
        nativePolicy='4'*64, wordpressPolicy='5'*64, reusePolicy='6'*64,
        fragments=[dict(url=PRIVATE, authority=[dict(tag='7'*64, revision='8'*64, generation='9'*64)])])


@unittest.skipUnless(CC, 'C compiler required; skipped is not qualification')
class FragmentBatchWire(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        DeliveryEnvelope.setUpClass.__func__(cls)
        cls.lib.delivery_fragment_batch_token.argtypes = [ctypes.c_char_p]
        cls.lib.delivery_fragment_batch_token.restype = ctypes.c_void_p
        cls.lib.delivery_fragment_batch_parse.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_void_p)]
        cls.lib.delivery_fragment_batch_parse.restype = ctypes.c_int
        cls.lib.delivery_fragment_batch_free.argtypes = [ctypes.c_void_p]
        cls.lib.delivery_fragment_results_free.argtypes = [ctypes.c_void_p]
        cls.lib.delivery_fragment_envelope_parse_v1.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        cls.lib.delivery_fragment_envelope_parse_v1.restype = ctypes.c_int
        cls.lib.delivery_fragment_results_json.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_size_t)]
        cls.lib.delivery_fragment_results_json.restype = ctypes.c_int

    @classmethod
    def tearDownClass(cls):
        DeliveryEnvelope.tearDownClass.__func__(cls)

    def batch(self, wire):
        out = ctypes.c_void_p()
        ok = self.lib.delivery_fragment_batch_parse(wire, len(wire), ctypes.byref(out))
        self.assertEqual(bool(ok), bool(out))
        return out

    def render(self, wire, value):
        batch = self.batch(wire)
        self.assertTrue(batch)
        result = ctypes.c_void_p()
        output = ctypes.c_void_p()
        length = ctypes.c_size_t()
        raw = value if isinstance(value, bytes) else json.dumps(value, ensure_ascii=False).encode()
        try:
            accepted = self.lib.delivery_fragment_envelope_parse_v1(raw, len(raw), b'123', REQUEST.encode(), batch, ctypes.byref(result))
            if not accepted:
                self.assertFalse(result)
                return None
            self.assertTrue(self.lib.delivery_fragment_results_json(batch, result, ctypes.byref(output), ctypes.byref(length)))
            return json.loads(ctypes.string_at(output, length.value))
        finally:
            self.lib.delivery_manifest_free(output)
            self.lib.delivery_fragment_results_free(result)
            self.lib.delivery_fragment_batch_free(batch)

    def test_request_framing_exactly_once_and_no_other_query_fields(self):
        for raw, expected in [
            ('/shop/index.php?ultracache_fragment_delivery=abc.def', b'abc.def'),
            ('/shop/index.php?ultracache_fragment_delivery=abc%2edef', b'abc.def'),
            ('/shop/index.php?ultracache_fragment_delivery=abc%252edef', b'abc%2edef'),
            ('/shop/index.php?ultracache_fragment_delivery=abc+def', b'abc+def')]:
            pointer = self.lib.delivery_fragment_batch_token(raw.encode())
            try:
                self.assertEqual(ctypes.string_at(pointer), expected)
            finally:
                self.lib.delivery_manifest_free(pointer)
        for raw in ('//outside.test/?ultracache_fragment_delivery=x',
            '/shop/index.php?ultracache_fragment_delivery=x&ultracache_fragment_delivery=x',
            '/shop/index.php?other=x&ultracache_fragment_delivery=x',
            '/shop/index.php?ultracache_fragment_delivery=%00',
            '/shop/index.php?ultracache_fragment_delivery=%',
            '/shop/index.php?ultracache_fragment_delivery='):
            self.assertFalse(self.lib.delivery_fragment_batch_token(raw.encode()))

    def test_public_request_codec_preserves_home_url_fragment_identity(self):
        wire = token(payload())
        batch = self.batch(wire)
        self.assertTrue(batch)
        self.lib.delivery_fragment_batch_free(batch)
        result = self.render(wire, envelope(wire))
        self.assertEqual(result, dict(schemaVersion=1, results=[
            dict(url=PRIVATE, status=200, html='<div>actual</div>'),
            dict(url=ADAPTIVE, status=503, error=dict(code='renderer-unavailable'))]))

    def test_actual_wordpress_unsigned_framing_vector(self):
        vector = json.loads((Path(__file__).parent/'fixtures/fragment-delivery-wire-v1.json').read_text())['validFraming']
        wire = vector['token'].encode()
        value = dict(schemaVersion=2, requestId='123', originalUrl=REQUEST,
            requestDigest=vector['requestDigest'], failedFragments=[],
            renderedFragments=[dict(row, html='actual') for row in vector['payload']['fragments']])
        self.assertEqual(len(self.render(wire, value)['results']), 2)

    def test_invalid_public_payload_or_base64_never_creates_batch(self):
        cases = []
        for change in (dict(fragments=[]), dict(schemaVersion=2), dict(owner='another'),
            dict(sourceUrl='https://outside.test/'), dict(context=dict(payload()['context'], cookies={})),
            dict(fragments=[dict(url=PRIVATE, occurrences=0)]),
            dict(fragments=[dict(url=PRIVATE, occurrences=1), dict(url=PRIVATE, occurrences=1)]),
            dict(fragments=[dict(url=PRIVATE, occurrences=2**64-1), dict(url=ADAPTIVE, occurrences=1)])):
            cases.append(token(dict(payload(), **change)))
        raw = json.dumps(payload()).encode()
        cases += [token(raw.replace(b'"schemaVersion": 1', b'"schemaVersion":1,"schemaVersion":1')),
            b'A.'+b'c'*64, token(payload())+b'x', b'bad=.'+b'c'*64, b'']
        for wire in cases:
            with self.subTest(wire=wire[:30]):
                batch = self.batch(wire)
                try:
                    self.assertFalse(batch)
                finally:
                    self.lib.delivery_fragment_batch_free(batch)

    def test_exact_descriptor_union_not_just_matching_total(self):
        wire = token(payload())
        valid = envelope(wire)
        cases = [dict(valid, requestId='wrong'), dict(valid, originalUrl='/another'),
            dict(valid, requestDigest='d'*64), dict(valid, schemaVersion=1), dict(valid, cookieDelivery=True)]
        for field, value in [('url', '/?ultracache_esi=another&esi_scope=private'), ('occurrences', 3)]:
            item = copy.deepcopy(valid)
            item['renderedFragments'][0][field] = value
            cases.append(item)
        item = copy.deepcopy(valid); item['failedFragments'][0]['url'] = PRIVATE; cases.append(item)
        cases.append(dict(valid, failedFragments=[]))
        for item in cases:
            with self.subTest(value=item): self.assertIsNone(self.render(wire, item))

    def test_failures_are_not_cached_or_projected_as_html(self):
        wire = token(payload())
        valid = envelope(wire)
        for field, value in [('status', 200), ('status', 204), ('status', 302), ('code', 'raw-secret'),
            ('cache', dict(key='e'*64, ttl=30, tags='not-authority')), ('html', '')]:
            item = copy.deepcopy(valid); item['failedFragments'][0][field] = value
            self.assertIsNone(self.render(wire, item))
        item = copy.deepcopy(valid)
        item['renderedFragments'] = []
        item['failedFragments'].append(dict(url=PRIVATE, occurrences=2, status=503, code='renderer-failed'))
        self.assertEqual([r['status'] for r in self.render(wire, item)['results']], [503, 503])

    def test_native_claim_needs_exact_nonempty_authority_and_is_never_in_projection(self):
        wire = token(payload())
        valid = envelope(wire)
        valid['renderedFragments'][0]['cache'] = dict(key='e'*64, ttl=30, tags='uc-owner-'+'7'*64)
        self.assertIsNone(self.render(wire, valid))
        valid['authority'] = authority()
        result = self.render(wire, valid)
        self.assertIsNotNone(result)
        self.assertNotIn('authority', json.dumps(result))
        self.assertNotIn('e'*64, json.dumps(result))
        for change in (dict(fragments=[]), dict(fragments=[dict(url=ADAPTIVE, authority=authority()['fragments'][0]['authority'])]),
            dict(fragments=[dict(url=PRIVATE, authority=[])]), dict(scope='/shop'), dict(epoch='bad')):
            item = copy.deepcopy(valid); item['authority'].update(change)
            self.assertIsNone(self.render(wire, item))

    def test_stateless_claim_requires_explicit_anonymous_and_exact_scope_authority(self):
        wire = token(payload())
        valid = envelope(wire)
        valid['renderedFragments'][0]['cache'] = dict(key='e'*64, ttl=30, tags='', identityState='anonymous')
        valid['authority'] = authority()
        valid['authority']['fragments'][0]['authority'] = []
        result = self.render(wire, valid)
        self.assertIsNotNone(result)
        self.assertNotIn('identityState', json.dumps(result))
        self.assertNotIn('authority', json.dumps(result))
        for change in (dict(identityState='personal'), dict(identityState=None), dict(identityState=True),
                       dict(tags='owner'), dict(tags=[]), dict(owner=None), dict(ttl=0)):
            item = copy.deepcopy(valid); item['renderedFragments'][0]['cache'].update(change)
            with self.subTest(change=change): self.assertIsNone(self.render(wire, item))
        for field in ('identityState', 'tags'):
            item = copy.deepcopy(valid); del item['renderedFragments'][0]['cache'][field]
            self.assertIsNone(self.render(wire, item))
        item = copy.deepcopy(valid); item['authority'] = authority()
        self.assertIsNone(self.render(wire, item), 'Anonymous claims cannot silently drop actual dependencies')
        item = copy.deepcopy(valid); del item['authority']
        self.assertIsNone(self.render(wire, item), 'Anonymous is not an authority-free claim')
        legacy = dict(schemaVersion=1, requestId='123', originalUrl='/article?q=original',
            renderedFragments=copy.deepcopy(valid['renderedFragments']))
        self.assertIsNone(DeliveryEnvelope.parse(self, legacy, occurrences=2), 'Parent schema1 stays unchanged')
        del legacy['renderedFragments'][0]['cache']['identityState']
        self.assertIsNotNone(DeliveryEnvelope.parse(self, legacy, occurrences=2))

    def test_html_length_aware_projection_keeps_unicode_nul_and_json_escapes(self):
        wire = token(payload())
        value = envelope(wire)
        value['renderedFragments'][0]['html'] = 'Ελληνικά 😀\x00"\\\n</script>'
        result = self.render(wire, value)
        self.assertEqual(result['results'][0]['html'], value['renderedFragments'][0]['html'])

    def test_all_truncated_producer_prefixes_and_duplicate_fields_reject(self):
        wire = token(payload())
        raw = json.dumps(envelope(wire), separators=(',', ':')).encode()
        for end in range(len(raw)):
            self.assertIsNone(self.render(wire, raw[:end]))
        for changed in (raw+b'null', raw.replace(b'"schemaVersion":2', b'"schemaVersion":2,"schemaVersion":2'),
            raw.replace(b'"occurrences":2', b'"occurrences":2,"occurrences":2')):
            self.assertIsNone(self.render(wire, changed))


if __name__ == '__main__':
    unittest.main()
