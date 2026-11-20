"""Compile/execute the actual portable C envelope parser, independent of VMOD.

These checks do not qualify Varnish body capture, restart or browser behavior.
"""
import ctypes
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
                  ('length',ctypes.c_size_t)]


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
            ctypes.c_char_p,ctypes.c_uint64,ctypes.POINTER(Pointer)]
        cls.lib.delivery_envelope_parse.restype=ctypes.c_int
        cls.lib.delivery_free_fragments.argtypes=[Pointer]
        cls.lib.delivery_free_fragments.restype=None
        cls.lib.delivery_buffer_growth.argtypes=[ctypes.c_size_t]*3+[ctypes.POINTER(ctypes.c_size_t)]*2
        cls.lib.delivery_buffer_growth.restype=ctypes.c_int

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

    def parse(self,value,*,request='123',url='/article?q=original',occurrences=3):
        data=json.dumps(value,ensure_ascii=True).encode() if isinstance(value,dict) else value
        out=Pointer()
        ok=self.lib.delivery_envelope_parse(data,len(data),request.encode(),url.encode(),occurrences,
            ctypes.byref(out))
        result={}
        try:
            if not ok:
                self.assertFalse(out,'Failure must discard the complete partial envelope')
                return None
            f=out
            while f:
                row=f.contents
                result[ctypes.string_at(row.url).decode('utf-8')]=ctypes.string_at(row.html,row.length)
                f=row.next
            return result
        finally:self.lib.delivery_free_fragments(out)

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


if __name__=='__main__':unittest.main()
