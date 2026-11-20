"""Portable real-C selection grammar; native lifecycle is qualified separately."""
import base64
import copy
import ctypes
import hashlib
import json
import random
import unittest
from test_delivery_envelope import CC,DeliveryEnvelope,Fragment,PublicParent,DocumentPointer


class Update(ctypes.Structure):pass
Update._fields_=[('next',ctypes.POINTER(Update)),('name',ctypes.c_void_p),('value',ctypes.c_void_p)]
class Header(ctypes.Structure):pass
Header._fields_=[('next',ctypes.POINTER(Header)),('line',ctypes.c_void_p)]
class Selection(ctypes.Structure):
    _fields_=[('policy',ctypes.c_char*65),('wordpress_policy',ctypes.c_char*65),
        ('manifest',ctypes.c_void_p),('target',ctypes.c_void_p),('occurrences',ctypes.c_uint64),
        ('updates',ctypes.POINTER(Update)),('headers',ctypes.POINTER(Header)),
        ('parent',ctypes.POINTER(PublicParent)),('fragments',ctypes.POINTER(Fragment))]
SelectionPointer=ctypes.POINTER(Selection)
NATIVE='a'*64
WORDPRESS='b'*64
TOKEN='public.target+token'
URL='/book/?actual=a%2Bb&actual=c+d'
RULES='private\texact\tlogged_in\nvariant\texact\tcurrency\nvariant\tprefix\tlang_\nshared\tprefix\tcampaign_\n'


def sample():
    body=b'<html>EUR20</html>'
    return dict(schemaVersion=1,requestId='42',originalUrl=URL,selectedPublic=dict(
        policyDigest=NATIVE,wordpressPolicyDigest=WORDPRESS,
        cookieUpdates=[dict(name='currency',valueBase64=base64.b64encode(b'EUR').decode())],
        manifest=TOKEN,occurrences=0,
        publicParent=dict(generation=hashlib.sha256(body).hexdigest(),
            bodyBase64=base64.b64encode(body).decode(),freshRemaining=120),
        headers=['Content-Type: text/html; charset=UTF-8',
            'X-UltraCache-Delivery-Prepare: /index.php?ultracache_delivery=public.target%2Btoken',
            'X-UltraCache-ESI-Private-Count: 0','X-UltraCache-Cookie-Settings: '+WORDPRESS,
            'Vary: Cookie','Content-Security-Policy: frame-ancestors self'],renderedFragments=[]))


@unittest.skipUnless(CC,'C compiler required; skipped is not acceptance')
class PublicSelection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        DeliveryEnvelope.setUpClass.__func__(cls)
        cls.lib.delivery_selection_parse.argtypes=[ctypes.c_void_p,ctypes.c_size_t]+[ctypes.c_char_p]*4+[
            ctypes.POINTER(SelectionPointer),ctypes.POINTER(DocumentPointer)]
        cls.lib.delivery_selection_parse.restype=ctypes.c_int
        cls.lib.delivery_selection_free.argtypes=[SelectionPointer]
        cls.lib.delivery_selection_free.restype=None
        cls.lib.delivery_selection_candidate.argtypes=[SelectionPointer,ctypes.c_char_p,ctypes.c_char_p,ctypes.POINTER(ctypes.c_void_p)]
        cls.lib.delivery_selection_candidate.restype=ctypes.c_int
        cls.lib.delivery_selection_digest.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p]
        cls.lib.delivery_selection_digest.restype=ctypes.c_int
        cls.lib.delivery_selection_projection.argtypes=[ctypes.c_char_p,ctypes.c_char_p]
        cls.lib.delivery_selection_projection.restype=ctypes.c_void_p
    tearDownClass=classmethod(DeliveryEnvelope.tearDownClass.__func__)

    def parse(self,value,*,original=None,rules=RULES,request='42',url=URL,native=NATIVE,wordpress=WORDPRESS):
        data=json.dumps(value,ensure_ascii=True).encode() if isinstance(value,dict) else value
        selection=SelectionPointer();document=DocumentPointer()
        ok=self.lib.delivery_selection_parse(data,len(data),request.encode(),url.encode(),native.encode(),wordpress.encode(),
            ctypes.byref(selection),ctypes.byref(document))
        candidate=ctypes.c_void_p()
        try:
            if not ok:
                self.assertFalse(selection);self.assertFalse(document)
                return None
            if document:return {'status':document.contents.status,'body':ctypes.string_at(document.contents.body,document.contents.length)}
            result={'policy':selection.contents.policy.decode(),'wordpress':selection.contents.wordpress_policy.decode(),
                'body':ctypes.string_at(selection.contents.parent.contents.body,selection.contents.parent.contents.length),
                'occurrences':selection.contents.occurrences,'remaining':selection.contents.parent.contents.fresh_remaining}
            if original is not None:
                accepted=self.lib.delivery_selection_candidate(selection,original.encode(),rules.encode(),ctypes.byref(candidate))
                result['candidate']=ctypes.string_at(candidate).decode() if accepted else None
            return result
        finally:
            # The portable parser's free wrapper is the same C allocator.
            if candidate.value:self.lib.delivery_manifest_free(candidate)
            self.lib.delivery_selection_free(selection);self.lib.delivery_private_document_free(document)

    def test_zero_fragments_and_independent_policy_identities(self):
        result=self.parse(sample())
        self.assertEqual((result['policy'],result['wordpress'],result['occurrences']),(NATIVE,WORDPRESS,0))
        self.assertEqual(result['body'],b'<html>EUR20</html>')
    def test_legal_header_optional_whitespace_is_preserved_without_changing_binding(self):
        value=sample()
        value['selectedPublic']['headers']=[line.replace(': ',':\t')+' \t' for line in value['selectedPublic']['headers']]
        self.assertIsNotNone(self.parse(value))
    def test_binding_does_not_accept_another_request_url_or_policy(self):
        for key,value in [('request','43'),('url','/other/'),('native','c'*64),('wordpress','d'*64)]:
            with self.subTest(field=key):self.assertIsNone(self.parse(sample(),**{key:value}))
    def test_private_document_alternative_is_exclusive(self):
        private=dict(schemaVersion=1,requestId='42',originalUrl=URL,privateDocument=dict(
            status=302,contentType='text/html',bodyBase64=base64.b64encode(b'redirect').decode()))
        self.assertEqual(self.parse(private),dict(status=302,body=b'redirect'))
        private['selectedPublic']=sample()['selectedPublic'];self.assertIsNone(self.parse(private))
    def test_unknown_missing_and_duplicate_fields_discard_whole_result(self):
        value=sample();value['selectedPublic']['extra']='unexpected';self.assertIsNone(self.parse(value))
        for key in sample()['selectedPublic']:
            value=sample();del value['selectedPublic'][key]
            with self.subTest(missing=key):self.assertIsNone(self.parse(value))
        raw=json.dumps(sample()).replace('"requestId": "42"','"requestId":"42","requestId":"42"').encode()
        self.assertIsNone(self.parse(raw))
    def test_target_pointer_and_count_are_bound_and_singleton(self):
        for field in ('X-UltraCache-Delivery-Prepare: /index.php?ultracache_delivery=other',
                      'X-UltraCache-ESI-Private-Count: 1','Content-Type: application/json'):
            value=sample();name=field.split(':')[0]
            value['selectedPublic']['headers']=[field if line.startswith(name+':') else line for line in value['selectedPublic']['headers']]
            with self.subTest(field=field):self.assertIsNone(self.parse(value))
        value=sample();value['selectedPublic']['headers'].append('Content-Type: text/html');self.assertIsNone(self.parse(value))
    def test_private_hop_transport_cookie_headers_and_crlf_are_never_public(self):
        for field in ('Set-Cookie: visitor=alice','sEt-CoOkIe2: visitor=alice','Authorization: secret',
                      'WWW-Authenticate: Basic','Connection: keep-alive','Content-Encoding: gzip',
                      'X-UltraCache-Delivery-Authorization: secret','Content-Length: 12',
                      'Cache-Control: max-age=100, private','Cache-Control: no-store',
                      'Surrogate-Control: no-store','Vary: Accept, *','Link: x\r\nSet-Cookie: evil=1'):
            value=sample();value['selectedPublic']['headers'].append(field)
            with self.subTest(field=field):self.assertIsNone(self.parse(value))
    def test_cookie_update_wire_is_strict_and_duplicates_are_rejected(self):
        for name,value in [('bad\x00name','RVVS'),('bad name','RVVS'),('currency','broken!'),
                           ('currency',base64.b64encode(b'EUR; logged_in=1').decode()),
                           ('currency',base64.b64encode(b'EU\r\nR').decode())]:
            payload=sample();payload['selectedPublic']['cookieUpdates']=[dict(name=name,valueBase64=value)]
            with self.subTest(name=name,value=value):self.assertIsNone(self.parse(payload))
        value=sample();value['selectedPublic']['cookieUpdates']*=2;self.assertIsNone(self.parse(value))
    def test_candidate_keeps_real_cookie_copy_and_unrelated_values(self):
        original='campaign_id=one;currency=USD; logged_in=actual; currency=stale; other=keep'
        result=self.parse(sample(),original=original)
        self.assertEqual(result['candidate'],'campaign_id=one; logged_in=actual; other=keep; currency=EUR')
        self.assertIn('currency=USD',original)
    def test_absence_empty_value_and_prefix_variant_are_distinct(self):
        value=sample();value['selectedPublic']['cookieUpdates']=[dict(name='currency',valueBase64=None),
            dict(name='lang_country',valueBase64='')]
        self.assertEqual(self.parse(value,original='currency=USD;other=ok')['candidate'],'other=ok; lang_country=')
    def test_shared_private_unknown_and_specificity_cannot_be_overridden(self):
        for name,rules in [('campaign_id',RULES),('logged_in',RULES),('unknown',RULES),
                           ('lang_country','shared\texact\tlang_country\n'+RULES)]:
            value=sample();value['selectedPublic']['cookieUpdates'][0]['name']=name
            with self.subTest(name=name):self.assertIsNone(self.parse(value,original='other=ok',rules=rules)['candidate'])
    def test_no_size_cap_and_no_freshness_extension(self):
        value=sample();body=b'x'*200000
        value['selectedPublic']['publicParent'].update(bodyBase64=base64.b64encode(body).decode(),
            generation=hashlib.sha256(body).hexdigest(),freshRemaining=0)
        result=self.parse(value);self.assertEqual(result['body'],body);self.assertEqual(result['remaining'],0)
    def test_fragments_count_and_native_claims_use_existing_grammar(self):
        value=sample();s=value['selectedPublic'];s['occurrences']=2
        s['headers']=[line.replace('Count: 0','Count: 2') for line in s['headers']]
        s['renderedFragments']=[dict(url='/index.php?ultracache_esi=actual&esi_scope=private',html='owned',occurrences=2)]
        self.assertEqual(self.parse(value)['occurrences'],2)
        s['renderedFragments'][0]['occurrences']=1;self.assertIsNone(self.parse(value))
    def test_generation_must_match_exact_snapshot_bytes(self):
        value=sample();value['selectedPublic']['publicParent']['generation']='f'*64
        self.assertIsNone(self.parse(value))
    def test_digest_agrees_with_sha256_vectors_and_binary_block_boundaries(self):
        rng=random.Random(4291)
        for length in (0,1,3,55,56,63,64,65,119,120,127,128,1000,100000):
            body=rng.randbytes(length);digest=ctypes.create_string_buffer(65)
            self.assertEqual(self.lib.delivery_selection_digest(body,len(body),digest),1)
            self.assertEqual(digest.value.decode(),hashlib.sha256(body).hexdigest())
    def test_native_variant_projection_is_canonical_and_keeps_only_variant_values(self):
        pointer=self.lib.delivery_selection_projection(b'lang_country=de; campaign_id=track; currency=EUR; logged_in=private; currency=ignored',RULES.encode())
        try:self.assertEqual(ctypes.string_at(pointer),b'currency=EUR; lang_country=de')
        finally:self.lib.delivery_manifest_free(pointer)
    def test_new_private_outcome_preserves_json_without_relaxing_old_html_wire(self):
        value=dict(schemaVersion=1,requestId='42',originalUrl=URL,privateDocument=dict(
            status=404,contentType='application/json; charset=UTF-8',bodyBase64=base64.b64encode(b'{"error":true}').decode()))
        self.assertEqual(self.parse(value),dict(status=404,body=b'{"error":true}'))


if __name__=='__main__':unittest.main()
