"""Compile/execute the actual portable C envelope parser, independent of VMOD.

These checks do not qualify Varnish body capture, restart or browser behavior.
"""
import ctypes
import base64
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
CC=shutil.which('cc') or shutil.which('gcc')


class Fragment(ctypes.Structure):pass
Pointer=ctypes.POINTER(Fragment)
Fragment._fields_=[('next',Pointer),('url',ctypes.c_void_p),('html',ctypes.c_void_p),
                  ('length',ctypes.c_size_t),('cache_key',ctypes.c_void_p),
                  ('cache_tags',ctypes.c_void_p),('cache_ttl',ctypes.c_uint64)]
class PublicParent(ctypes.Structure):
    _fields_=[('generation',ctypes.c_char*65),('body',ctypes.c_void_p),
              ('length',ctypes.c_size_t),('fresh_remaining',ctypes.c_uint64)]
ParentPointer=ctypes.POINTER(PublicParent)
class PrivateDocument(ctypes.Structure):
    _fields_=[('body',ctypes.c_void_p),('length',ctypes.c_size_t),
        ('content_type',ctypes.c_void_p),('status',ctypes.c_uint)]
DocumentPointer=ctypes.POINTER(PrivateDocument)


def sample():
    return dict(schemaVersion=1,requestId='123',originalUrl='/article?q=original',
        renderedFragments=[dict(url='/index.php?ultracache_esi=private&esi_scope=private',
            html='<div>actual output</div>',occurrences=2),
            dict(url='/index.php?ultracache_esi=adaptive&esi_identity=wordpress',
            html='nonce',occurrences=1)])


@unittest.skipUnless(CC,'C compiler required; portable-parser tests are not passed when skipped')
class DeliveryEnvelope(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder=tempfile.TemporaryDirectory(prefix='uc-delivery-envelope-')
        library=Path(cls.folder.name)/('parser.dll' if os.name=='nt' else 'parser.so')
        args=[CC,'-std=c99','-Wall','-Wextra','-Werror','-O2','-shared']
        if os.name!='nt':args+=['-fPIC']
        result=subprocess.run(args+[str(ROOT/'shared/native/delivery_envelope.c'),'-o',str(library)],
            capture_output=True,text=True)
        if result.returncode:raise AssertionError(result.stdout+result.stderr)
        cls.lib=ctypes.CDLL(str(library))
        cls.lib.delivery_envelope_parse.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_char_p,
            ctypes.c_char_p,ctypes.c_uint64,ctypes.POINTER(Pointer),ctypes.POINTER(ParentPointer),ctypes.POINTER(DocumentPointer)]
        cls.lib.delivery_envelope_parse.restype=ctypes.c_int
        cls.lib.delivery_cookie_envelope_parse.argtypes=cls.lib.delivery_envelope_parse.argtypes[:5]+[ctypes.c_int]+cls.lib.delivery_envelope_parse.argtypes[5:]
        cls.lib.delivery_cookie_envelope_parse.restype=ctypes.c_int
        cls.lib.delivery_free_fragments.argtypes=[Pointer]
        cls.lib.delivery_free_fragments.restype=None
        cls.lib.delivery_public_parent_free.argtypes=[ParentPointer]
        cls.lib.delivery_private_document_free.argtypes=[DocumentPointer]
        cls.lib.delivery_private_document_free.restype=None
        cls.lib.delivery_public_parent_free.restype=None
        cls.lib.delivery_buffer_growth.argtypes=[ctypes.c_size_t]*3+[ctypes.POINTER(ctypes.c_size_t)]*2
        cls.lib.delivery_buffer_growth.restype=ctypes.c_int
        cls.lib.delivery_manifest_token.argtypes=[ctypes.c_char_p]
        cls.lib.delivery_manifest_token.restype=ctypes.c_void_p
        cls.lib.delivery_manifest_free.argtypes=[ctypes.c_void_p]
        cls.lib.delivery_manifest_free.restype=None

    @classmethod
    def tearDownClass(cls):
        if os.name=='nt':
            import _ctypes
            _ctypes.FreeLibrary(cls.lib._handle)
            cls.lib=None
        folder=Path(cls.folder.name).resolve()
        assert folder.parent==Path(tempfile.gettempdir()).resolve()
        assert folder.name.startswith('uc-delivery-envelope-')
        cls.folder.cleanup()

    def parse(self,value,*,request='123',url='/article?q=original',occurrences=3,with_snapshot=False,with_cache=False,with_document=False,cookie_delivery=None):
        data=json.dumps(value,ensure_ascii=True).encode() if isinstance(value,dict) else value
        out=Pointer()
        parent=ParentPointer()
        document=DocumentPointer()
        args=[data,len(data),request.encode(),url.encode(),occurrences]
        if cookie_delivery is not None:args.append(int(cookie_delivery))
        args += [ctypes.byref(out),ctypes.byref(parent),ctypes.byref(document)]
        parser=self.lib.delivery_envelope_parse if cookie_delivery is None else self.lib.delivery_cookie_envelope_parse
        ok=parser(*args)
        result={};cache={}
        try:
            if not ok:
                self.assertFalse(out,'Failure must discard the complete partial envelope')
                self.assertFalse(parent,'Failure must discard the complete partial snapshot')
                self.assertFalse(document,'Failure must discard the complete partial document')
                return None
            f=out
            while f:
                row=f.contents
                result[ctypes.string_at(row.url).decode('utf-8')]=ctypes.string_at(row.html,row.length)
                if row.cache_key:
                    cache[ctypes.string_at(row.url).decode()]=dict(key=ctypes.string_at(row.cache_key).decode(),
                        ttl=row.cache_ttl,tags=ctypes.string_at(row.cache_tags).decode())
                f=row.next
            if with_cache:return result,cache
            if with_document:
                self.assertFalse(out);self.assertFalse(parent)
                row=document.contents
                return dict(body=ctypes.string_at(row.body,row.length),
                    contentType=ctypes.string_at(row.content_type).decode(),status=row.status)
            if not with_snapshot:return result
            snapshot=None
            if parent:
                row=parent.contents
                snapshot=dict(generation=bytes(row.generation).decode(),
                    body=ctypes.string_at(row.body,row.length),freshRemaining=row.fresh_remaining)
            return result,snapshot
        finally:
            self.lib.delivery_free_fragments(out)
            self.lib.delivery_public_parent_free(parent)
            self.lib.delivery_private_document_free(document)

    def test_cookie_only_empty_coverage_is_explicit_and_request_bound(self):
        value=dict(schemaVersion=1,requestId='123',originalUrl='/article?q=original',
            cookieDelivery=True,renderedFragments=[])
        self.assertEqual(self.parse(value,occurrences=0,cookie_delivery=True),{})
        self.assertIsNone(self.parse(value,occurrences=0))
        self.assertIsNone(self.parse(value,occurrences=0,cookie_delivery=False))
        self.assertIsNone(self.parse(value,occurrences=0,cookie_delivery=True,request='another'))
        for flag in (False, 'true', 1, None):
            changed=dict(value,cookieDelivery=flag)
            self.assertIsNone(self.parse(changed,occurrences=0,cookie_delivery=True))
        missing=dict(value);missing.pop('cookieDelivery')
        self.assertIsNone(self.parse(missing,occurrences=0,cookie_delivery=True))
        raw=json.dumps(value).replace('"cookieDelivery": true','"cookieDelivery": true, "cookieDelivery": true')
        self.assertIsNone(self.parse(raw.encode(),occurrences=0,cookie_delivery=True))
    def test_real_c_parser_preserves_utf8_escapes_binary_html_and_property_order(self):
        value=sample()
        html='Ελληνικά 😀 / " \\ \t\r\n\b\f \x00 τέλος'
        value['renderedFragments'][0]['html']=html
        expected={r['url']:r['html'].encode() for r in value['renderedFragments']}
        self.assertEqual(self.parse(value),expected)
        self.assertEqual(self.parse(json.dumps(value,ensure_ascii=False).encode()),expected)
        rng=random.Random(956)
        for _ in range(40):
            items=list(value.items());rng.shuffle(items)
            reordered=dict(items)
            reordered['renderedFragments']=[dict(rng.sample(list(r.items()),len(r)))
                for r in value['renderedFragments']]
            with self.subTest(order=list(reordered)):
                self.assertEqual(self.parse(reordered),expected)
        raw=json.dumps(value).encode().replace(b'"requestId"',b'"request\\u0049d"')
        self.assertEqual(self.parse(raw),expected)

    def test_every_truncated_prefix_and_trailing_bytes_are_rejected(self):
        raw=json.dumps(sample(),separators=(',',':')).encode()
        for end in range(len(raw)):
            with self.subTest(end=end):self.assertIsNone(self.parse(raw[:end]))
        for extra in (b'{}',b'null',b'\x00',b',',b'\v'):
            self.assertIsNone(self.parse(raw+extra))
        self.assertIsNotNone(self.parse(b' \t\r\n'+raw+b' \t\r\n'))

    def test_duplicate_decoded_keys_unknown_fields_and_invalid_grammar_reject(self):
        raw=json.dumps(sample(),separators=(',',':')).encode()
        malformed=[raw.replace(b'"schemaVersion":1',b'"schemaVersion":1,"schemaVersion":1'),
            raw.replace(b'"requestId":"123"',b'"requestId":"123","request\\u0049d":"123"'),
            raw.replace(b'"html":',b'"html":"extra","html":',1),
            raw.replace(b'"schemaVersion":1',b'"extra":[],"schemaVersion":1'),
            raw.replace(b'"html":',b'"extra":0,"html":',1),
            raw.replace(b',"requestId"',b',,"requestId"'),raw.replace(b'}]}',b'},]}'),
            raw.replace(b'"schemaVersion":1',b'"schemaVersion":true'),
            raw.replace(b'"html":"',b'"html":null,"unused":"',1)]
        for data in malformed:
            with self.subTest(data=data[:100]):self.assertIsNone(self.parse(data))
        for field in sample():
            value=sample();del value[field];self.assertIsNone(self.parse(value))

    def test_numbers_are_bounded_schema_integers_and_occurrence_sum_is_exact(self):
        raw=json.dumps(sample(),separators=(',',':')).encode()
        for n in (b'0',b'-1',b'01',b'1.0',b'1e0',b'"1"',b'1025',b'99999999999999999999'):
            with self.subTest(schema=n):
                self.assertIsNone(self.parse(raw.replace(b'"schemaVersion":1',b'"schemaVersion":'+n)))
        for n in (b'0',b'-2',b'02',b'2.0',b'2e0',b'"2"',b'1025',b'99999999999999999999'):
            with self.subTest(occurrences=n):
                self.assertIsNone(self.parse(raw.replace(b'"occurrences":2',b'"occurrences":'+n)))
        for expected in (0,1,2,4,1025):self.assertIsNone(self.parse(sample(),occurrences=expected))
        value=sample();value['renderedFragments']=[];self.assertIsNone(self.parse(value))

    def test_binding_text_and_urls_reject_null_foreign_or_ambiguous_paths(self):
        self.assertIsNone(self.parse(sample(),request='other'))
        self.assertIsNone(self.parse(sample(),url='/other'))
        for field in ('requestId','originalUrl'):
            value=sample();value[field]+='\x00extra';self.assertIsNone(self.parse(value))
        for url in ('','relative','//other/fragment','https://other/fragment','/path#hash',
                    '/path with space','/path\\evil','/path\x00extra','/path\r\nHeader: bad','/path\x7f'):
            value=sample();value['renderedFragments'][0]['url']=url
            with self.subTest(url=url):self.assertIsNone(self.parse(value))
        value=sample();value['renderedFragments'][1]['url']=value['renderedFragments'][0]['url']
        self.assertIsNone(self.parse(value))

    def test_invalid_unicode_controls_and_escape_sequences_reject(self):
        raw=json.dumps(sample(),separators=(',',':')).encode()
        marker=b'<div>actual output</div>'
        for bad in (b'\xc0\xaf',b'\xe0\x80\xaf',b'\xed\xa0\x80',b'\xf4\x90\x80\x80',
                    b'\x80',b'\xf0\x9f\x98',b'\x00',b'\n',b'\\x20',b'\\u123X',
                    b'\\ud800',b'\\udc00',b'\\ud800\\u0061',b'\\udc00\\ud800'):
            with self.subTest(bad=bad):self.assertIsNone(self.parse(raw.replace(marker,bad)))
        for valid in ('\u007f','\u0080','\u07ff','\u0800','\uffff','\U0010ffff'):
            value=sample();value['renderedFragments'][0]['html']=valid
            self.assertIsNotNone(self.parse(value))

    def test_existing_large_output_and_fragment_counts_have_no_fixed_product_cap(self):
        value=sample();value['renderedFragments']=[dict(url='/fragment/'+str(i),html='x',occurrences=1)
            for i in range(2050)]
        self.assertEqual(len(self.parse(value,occurrences=2050)),2050)
        value['renderedFragments'].append(dict(url='/overflow',html='x',occurrences=1))
        self.assertIsNone(self.parse(value,occurrences=2050))
        value=sample();value['renderedFragments'][0]['html']='x'*(9*1024*1024)
        result=self.parse(value)
        self.assertEqual(len(result[value['renderedFragments'][0]['url']]),9*1024*1024)
        value=sample();value['renderedFragments']=[dict(url='/large-count',html='x',occurrences=2**63-1)]
        self.assertEqual(self.parse(value,occurrences=2**63-1),{'/large-count':b'x'})
        value['renderedFragments'][0]['occurrences']=2**64-1
        self.assertEqual(self.parse(value,occurrences=2**64-1),{'/large-count':b'x'})
        value['renderedFragments'][0]['occurrences']=2**64
        self.assertIsNone(self.parse(value,occurrences=2**64-1))

    def test_native_size_arithmetic_fails_on_overflow_without_allocating_or_truncating(self):
        maximum=ctypes.c_size_t(-1).value
        for used,capacity,chunk in ((0,0,0),(0,0,64),(20,64,5),(63,64,1),
                                    (maximum-2,maximum-1,1)):
            needed=ctypes.c_size_t();target=ctypes.c_size_t()
            self.assertEqual(self.lib.delivery_buffer_growth(used,capacity,chunk,
                ctypes.byref(needed),ctypes.byref(target)),1)
            self.assertEqual(needed.value,used+chunk+1)
            self.assertGreaterEqual(target.value,needed.value)
        for used,chunk in ((maximum,0),(maximum-1,1),(maximum-2,2),(1,maximum)):
            needed=ctypes.c_size_t(17);target=ctypes.c_size_t(19)
            self.assertEqual(self.lib.delivery_buffer_growth(used,0,chunk,
                ctypes.byref(needed),ctypes.byref(target)),0)
            self.assertEqual((needed.value,target.value),(17,19))

    def test_nested_unknown_values_reject_without_general_json_recursion(self):
        raw=json.dumps(sample()).encode().replace(b'"schemaVersion": 1',
            b'"unknown":'+b'['*10000+b'0'+b']'*10000+b',"schemaVersion":1')
        self.assertIsNone(self.parse(raw))

    def test_manifest_metadata_extracts_one_literal_parameter_and_decodes_once(self):
        def token(pointer):
            out=self.lib.delivery_manifest_token(pointer.encode())
            if not out:return None
            try:return ctypes.string_at(out).decode('ascii')
            finally:self.lib.delivery_manifest_free(out)
        for pointer,expected in (
            ('/index.php?ultracache_delivery=signed-token','signed-token'),
            ('/shop/index.php?ultracache_delivery=v1%3Aabc%2Bdef%3D','v1:abc+def='),
            ('/index.php?other=metadata&ultracache_delivery=signed+token%252F&x=1','signed+token%2F'),
            ('/index.php?ultracache_delivery=%21%7e%2f','!~/')):
            with self.subTest(pointer=pointer):self.assertEqual(token(pointer),expected)
        for pointer in ('/index.php','/index.php?ultracache_delivery=',
            '/index.php?ultracache_delivery=a&ultracache_delivery=b',
            '/index.php?ultracache_delivery=ok&ultracache_delivery=',
            '/index.php?ultracache_delivery=%','/index.php?ultracache_delivery=%2',
            '/index.php?ultracache_delivery=%GG','/index.php?ultracache_delivery=%00',
            '/index.php?ultracache_delivery=%20','/index.php?ultracache_delivery=%0d%0a',
            '/index.php?ultracache_delivery=%7f','/index.php?ultracache_delivery=%cf',
            '/index.php?ultracache_delivery=a#fragment','//foreign/index.php?ultracache_delivery=a',
            '/index.php?not_ultracache_delivery=a','/index.php?ultracache%5fdelivery=a'):
            with self.subTest(pointer=pointer):self.assertIsNone(token(pointer))

    def test_optional_public_parent_preserves_exact_identity_bytes_and_lifetime(self):
        for body in (b'',b'f',b'fo',b'foo',bytes(range(256)),b'<html> \r\n\xff\x00 public </html>'):
            value=sample();generation=hashlib.sha256(body).hexdigest()
            value['publicParent']=dict(generation=generation,bodyBase64=base64.b64encode(body).decode(),freshRemaining=0)
            fragments,parent=self.parse(value,with_snapshot=True)
            self.assertEqual(parent,dict(generation=generation,body=body,freshRemaining=0))
            self.assertEqual(len(fragments),2)
        self.assertIsNone(self.parse(sample(),with_snapshot=True)[1])

    def test_optional_private_cache_claim_has_exact_owned_key_expiry_and_tags(self):
        value=sample();claim=dict(key='a'*64,ttl=61,tags='product-17 widget-9')
        value['renderedFragments'][0]['cache']=claim
        bodies,claims=self.parse(value,with_cache=True)
        self.assertEqual(claims,{value['renderedFragments'][0]['url']:claim})
        self.assertEqual(bodies[value['renderedFragments'][0]['url']],b'<div>actual output</div>')
        for invalid in (dict(claim,key='A'*64),dict(claim,key='a'*63),dict(claim,key='z'*64),
                dict(claim,ttl=0),dict(claim,ttl=-1),dict(claim,ttl=True),dict(claim,ttl=2**63),
                dict(claim,tags='safe\r\nSet-Cookie: bad'),dict(claim,tags='a\x00b'),
                dict(claim,extra=True),dict(key='a'*64,ttl=3)):
            value['renderedFragments'][0]['cache']=invalid
            with self.subTest(claim=invalid):self.assertIsNone(self.parse(value))
        value['renderedFragments'][0]['cache']=claim
        raw=json.dumps(value).encode()
        self.assertIsNone(self.parse(raw.replace(b'"ttl": 61',b'"ttl":61,"t\\u0074l":61')))

    def test_complete_private_document_is_bound_exclusive_and_preserves_status_and_exact_bytes(self):
        for status in (200,204,302,304,404,503,599):
            body=b'<html>private \xff\x00 body</html>'
            value=dict(schemaVersion=1,requestId='123',originalUrl='/article?q=original',
                privateDocument=dict(bodyBase64=base64.b64encode(body).decode(),
                    contentType='text/html; charset=ISO-8859-1',status=status))
            self.assertEqual(self.parse(value,with_document=True),
                dict(body=body,contentType='text/html; charset=ISO-8859-1',status=status))
            self.assertIsNone(self.parse(value,request='wrong'))
            self.assertIsNone(self.parse(value,url='/wrong'))
        good=dict(bodyBase64='Zg==',contentType='text/html; charset=UTF-8',status=200)
        for change in (dict(good,status=199),dict(good,status=600),dict(good,status=True),
                dict(good,status=200.5),dict(good,bodyBase64='Zh=='),dict(good,extra=0),
                dict(good,contentType='application/json'),dict(good,contentType='text/htmlx'),
                dict(good,contentType='text/html\r\nSet-Cookie: bad'),dict(good,contentType='text/html\x00')):
            self.assertIsNone(self.parse(dict(schemaVersion=1,requestId='123',originalUrl='/article?q=original',privateDocument=change)))
        for missing in good:
            bad=dict(good);del bad[missing]
            self.assertIsNone(self.parse(dict(schemaVersion=1,requestId='123',originalUrl='/article?q=original',privateDocument=bad)))
        self.assertIsNone(self.parse(dict(sample(),privateDocument=good)))
        value=dict(schemaVersion=1,requestId='123',originalUrl='/article?q=original',privateDocument=good,
            publicParent=dict(generation='a'*64,bodyBase64='Zg==',freshRemaining=1))
        self.assertIsNone(self.parse(value))

    def test_optional_public_parent_rejects_invalid_base64_generation_and_unknown_keys(self):
        good=dict(generation='a'*64,bodyBase64='Zg==',freshRemaining=9)
        for data in ('Z','Zg=','Zg===','Zh==','Zm9=','Zg==AAAA','Zg=+','Z g==','====','_w=='):
            value=sample();value['publicParent']=dict(good,bodyBase64=data)
            with self.subTest(base64=data):self.assertIsNone(self.parse(value,with_snapshot=True))
        for generation in ('a'*63,'A'*64,'g'*64,'a'*64+'\x00'):
            value=sample();value['publicParent']=dict(good,generation=generation)
            self.assertIsNone(self.parse(value,with_snapshot=True))
        for key in ('generation','bodyBase64','freshRemaining'):
            value=sample();value['publicParent']=dict(good);del value['publicParent'][key]
            self.assertIsNone(self.parse(value,with_snapshot=True))
        for fresh in (-1,1.2,True,'9'):
            value=sample();value['publicParent']=dict(good,freshRemaining=fresh)
            self.assertIsNone(self.parse(value,with_snapshot=True))
        value=sample();value['publicParent']=dict(good,headers=['Set-Cookie: forbidden'])
        self.assertIsNone(self.parse(value,with_snapshot=True))
        raw=json.dumps(dict(sample(),publicParent=good)).encode()
        self.assertIsNone(self.parse(raw.replace(b'"freshRemaining": 9',b'"freshRemaining":9,"freshRemaining":9')))


if __name__=='__main__':unittest.main()
