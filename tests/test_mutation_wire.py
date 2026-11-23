"""Independent Python HMAC oracle for the experimental, revoke-only C codec.

These tests do not qualify backend ownership, mutation persistence or admission.
All contexts/credentials are synthetic. No installed daemon is changed.
"""
import base64
import copy
import ctypes
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT/'tests/fixtures/private_mutation_wire_v1.json'
FIELDS = ('siteId','canonicalHost','scopeDigest','epoch','incarnation','nativePolicy',
          'wordpressPolicy','reusePolicy','requestId','challenge','method','url')
CC = shutil.which('cc') or shutil.which('gcc')


class Context(ctypes.Structure):
    _fields_ = [(name,ctypes.c_char_p) for name in FIELDS]


class Pair(ctypes.Structure):
    pass


Pair._fields_ = [('next',ctypes.POINTER(Pair)),('tag',ctypes.c_char*65),('transaction',ctypes.c_char*65)]


class Receipt(ctypes.Structure):
    _fields_ = [('state',ctypes.c_int),('pairs',ctypes.POINTER(Pair)),('count',ctypes.c_size_t)]


def lp(value):
    value = value.encode('utf-8') if isinstance(value,str) else value
    return struct.pack('>I',len(value))+value


def request_frame(context):
    return lp('ultracache-mutation-request-v1')+b''.join(lp(context[name]) for name in FIELDS)


def response_frame(proof,state,pairs):
    return (lp('ultracache-mutation-response-v1')+lp(proof)+lp(state)+struct.pack('>I',len(pairs))+
            b''.join(lp(tag)+lp(transaction) for tag,transaction in sorted(pairs)))


def json_header(value):
    return base64.b64encode(json.dumps(value,separators=(',',':'),ensure_ascii=False).encode('utf-8'))


@unittest.skipUnless(CC,'Portable C compiler required; skipped tests do not qualify the codec')
class MutationWire(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = json.loads(FIXTURE.read_text(encoding='utf-8'))
        cls.folder = tempfile.TemporaryDirectory(prefix='owned-mutation-wire-')
        library = Path(cls.folder.name)/('mutation.dll' if os.name=='nt' else 'mutation.so')
        command = [CC,'-std=c99','-Wall','-Wextra','-Werror','-O2','-shared']
        if os.name != 'nt': command += ['-fPIC']
        result = subprocess.run(command+[str(ROOT/'shared/native/delivery_envelope.c'),'-o',str(library)],
                                capture_output=True,text=True)
        if result.returncode: raise AssertionError(result.stdout+result.stderr)
        cls.lib = ctypes.CDLL(str(library))
        cls.lib.delivery_mutation_key.argtypes = [ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p]
        cls.lib.delivery_mutation_request_proof.argtypes = [ctypes.c_void_p,ctypes.POINTER(Context),ctypes.c_void_p]
        cls.lib.delivery_mutation_context_header.argtypes = [ctypes.c_void_p,ctypes.POINTER(Context),
                                                            ctypes.POINTER(ctypes.c_void_p),ctypes.c_void_p]
        cls.lib.delivery_mutation_header_free.argtypes = [ctypes.c_void_p]
        cls.lib.delivery_mutation_receipt_verify.argtypes = [ctypes.c_void_p,ctypes.c_char_p,ctypes.c_void_p,
                    ctypes.c_size_t,ctypes.POINTER(ctypes.POINTER(Receipt))]
        cls.lib.delivery_mutation_receipt_free.argtypes = [ctypes.POINTER(Receipt)]
        cls.secret = cls.vectors['syntheticSecret'].encode()
        cls.key = hmac.digest(cls.secret,b'ultracache-mutation-key-v1','sha256')

    @classmethod
    def tearDownClass(cls):
        if os.name == 'nt':
            import _ctypes
            _ctypes.FreeLibrary(cls.lib._handle)
            cls.lib = None
        cls.folder.cleanup()

    def context(self,value):
        return Context(*(value[name].encode('utf-8') if value[name] is not None else None for name in FIELDS))

    def proof(self,value,key=None):
        output = ctypes.create_string_buffer(65)
        result = self.lib.delivery_mutation_request_proof(key or self.key,ctypes.byref(self.context(value)),output)
        return result,output.value.decode()

    def verify(self,proof,header,key=None):
        if isinstance(header,str): header = header.encode()
        receipt = ctypes.POINTER(Receipt)()
        result = self.lib.delivery_mutation_receipt_verify(key or self.key,proof.encode(),header,len(header),ctypes.byref(receipt))
        try:
            if not result:
                self.assertFalse(receipt)
                return None
            self.assertTrue(receipt)
            pairs = []
            pair = receipt.contents.pairs
            while pair:
                pairs.append((pair.contents.tag.decode(),pair.contents.transaction.decode()))
                pair = pair.contents.next
            self.assertEqual(len(pairs),receipt.contents.count)
            return ('none','dirty','scope')[receipt.contents.state],pairs
        finally:
            self.lib.delivery_mutation_receipt_free(receipt)

    def receipt(self,proof,state,pairs):
        return dict(schemaVersion=1,state=state,transactions=[dict(tag=t,transaction=x) for t,x in pairs],
                    mac=hmac.new(self.key,response_frame(proof,state,pairs),hashlib.sha256).hexdigest())

    def test_purpose_key_matches_independent_oracle(self):
        output = ctypes.create_string_buffer(32)
        self.assertEqual(self.lib.delivery_mutation_key(self.secret,len(self.secret),output),1)
        self.assertEqual(output.raw,self.key)
        self.assertEqual(output.raw.hex(),self.vectors['derivedKeyHex'])
        self.assertNotEqual(output.raw,hmac.digest(self.secret,b'ultracache-delivery-reuse-key-v1','sha256'))
        self.assertEqual(self.lib.delivery_mutation_key(b'',0,output),0)

    def test_independent_request_vectors_and_generated_header(self):
        for row in self.vectors['vectors']:
            with self.subTest(name=row['name']):
                frame = request_frame(row['context'])
                self.assertEqual(frame.hex(),row['requestFrameHex'])
                self.assertEqual(hmac.new(self.key,frame,hashlib.sha256).hexdigest(),row['requestProof'])
                self.assertEqual(self.proof(row['context']),(1,row['requestProof']))
                output = ctypes.c_void_p()
                proof = ctypes.create_string_buffer(65)
                self.assertEqual(self.lib.delivery_mutation_context_header(self.key,
                    ctypes.byref(self.context(row['context'])),ctypes.byref(output),proof),1)
                try:
                    actual = ctypes.string_at(output)
                    self.assertEqual(actual.decode(),row['requestHeader'])
                    header = json.loads(base64.b64decode(actual,validate=True))
                    self.assertEqual(set(header),{'schemaVersion','proof',*FIELDS[:-2]})
                    self.assertEqual(header['schemaVersion'],1)
                    self.assertEqual(header['proof'],row['requestProof'])
                    for field in FIELDS[:-2]: self.assertEqual(header[field],row['context'][field])
                finally:
                    self.lib.delivery_mutation_header_free(output)

    def test_independent_response_vectors(self):
        for row in self.vectors['vectors']:
            with self.subTest(name=row['name']):
                pairs = [(p['tag'],p['transaction']) for p in row['response']['transactions']]
                self.assertEqual(response_frame(row['requestProof'],row['response']['state'],pairs).hex(),row['responseFrameHex'])
                self.assertEqual(json_header(row['response']).decode(),row['responseHeader'])
                self.assertEqual(self.verify(row['requestProof'],row['responseHeader']),(row['response']['state'],pairs))

    def test_request_is_bound_to_every_context_dimension_method_and_original_uri(self):
        row = self.vectors['vectors'][0]
        base = row['context']
        for name in FIELDS:
            changed = dict(base)
            if name == 'canonicalHost': changed[name] = 'other.example.test'
            elif name == 'method': changed[name] = 'PUT'
            elif name == 'url': changed[name] += '&other=1'
            else: changed[name] = ('e' if base[name][0] != 'e' else 'd')+base[name][1:]
            with self.subTest(field=name):
                result,proof = self.proof(changed)
                self.assertEqual(result,1)
                self.assertNotEqual(proof,row['requestProof'])
                self.assertIsNone(self.verify(proof,row['responseHeader']))
        self.assertIsNone(self.verify(row['requestProof'],row['responseHeader'],b'x'*32))

    def test_request_ids_and_metadata_require_exact_lowercase_hex(self):
        base = self.vectors['vectors'][0]['context']
        for field in ('siteId',*FIELDS[2:10]):
            for value in ('',None,base[field][:-1],base[field]+'0','A'+base[field][1:],'g'+base[field][1:]):
                changed = dict(base,**{field:value})
                with self.subTest(field=field,value=value): self.assertEqual(self.proof(changed),(0,''))

    def test_original_uri_and_method_are_not_rewritten_or_cookie_projected(self):
        context = dict(self.vectors['vectors'][0]['context'])
        first = self.proof(dict(context,url='/shop/?utm_source=one'))[1]
        second = self.proof(dict(context,url='/shop/?utm_source=two'))[1]
        self.assertNotEqual(first,second)
        self.assertNotEqual(self.proof(dict(context,method='POST'))[1],self.proof(dict(context,method='post'))[1])
        for value in ('','GET\r\nX: a','GET foo'):
            self.assertEqual(self.proof(dict(context,method=value)),(0,''))
        for value in ('','https://example.test/','/bad\r\n','/a b','/fragment#x'):
            self.assertEqual(self.proof(dict(context,url=value)),(0,''))

    def test_pairs_are_order_independent_but_unique_and_mac_bound(self):
        row = self.vectors['vectors'][1]
        receipt = copy.deepcopy(row['response'])
        receipt['transactions'].reverse()
        self.assertIsNotNone(self.verify(row['requestProof'],json_header(receipt)))
        for field in ('tag','transaction'):
            modified = copy.deepcopy(receipt)
            modified['transactions'][0][field] = 'f'*64
            self.assertIsNone(self.verify(row['requestProof'],json_header(modified)))
        pairs = [('1'*64,'2'*64),('1'*64,'2'*64)]
        self.assertIsNone(self.verify(row['requestProof'],json_header(self.receipt(row['requestProof'],'dirty',pairs))))
        pairs = [('1'*64,'2'*64),('1'*64,'3'*64)]
        self.assertIsNotNone(self.verify(row['requestProof'],json_header(self.receipt(row['requestProof'],'dirty',pairs))))

    def test_none_and_scope_cannot_hide_transactions_or_dirty_omit_them(self):
        proof = self.vectors['vectors'][0]['requestProof']
        for state,pairs in [('none',[('1'*64,'2'*64)]),('scope',[('1'*64,'2'*64)]),('dirty',[])]:
            self.assertIsNone(self.verify(proof,json_header(self.receipt(proof,state,pairs))))

    def test_schema_unknown_missing_duplicate_and_noncanonical_numbers_fail(self):
        row = self.vectors['vectors'][0]
        good = row['response']
        for field in good:
            changed = dict(good)
            del changed[field]
            self.assertIsNone(self.verify(row['requestProof'],json_header(changed)))
        for changed in (dict(good,other=True),dict(good,state='clean'),dict(good,schemaVersion=2),
                        dict(good,schemaVersion=True),dict(good,schemaVersion='1'),dict(good,transactions=None)):
            self.assertIsNone(self.verify(row['requestProof'],json_header(changed)))
        raw = json.dumps(good,separators=(',',':'))
        for field in good:
            invalid = '{'+json.dumps(field)+':'+json.dumps(good[field])+','+raw[1:]
            self.assertIsNone(self.verify(row['requestProof'],base64.b64encode(invalid.encode())))
        for replacement in ('01','1.0','1e0','-1'):
            invalid = raw.replace('"schemaVersion":1','"schemaVersion":'+replacement)
            self.assertIsNone(self.verify(row['requestProof'],base64.b64encode(invalid.encode())))

    def test_pair_unknown_missing_duplicate_and_nonhex_fields_fail(self):
        row = self.vectors['vectors'][0]
        for pair in ({'tag':'1'*64},{'transaction':'2'*64},
                     dict(tag='1'*64,transaction='2'*64,other=1),
                     dict(tag='A'*64,transaction='2'*64),dict(tag='1'*64,transaction='2'*63)):
            changed = dict(row['response'],transactions=[pair])
            self.assertIsNone(self.verify(row['requestProof'],json_header(changed)))
        raw = json.dumps(row['response'],separators=(',',':'))
        invalid = raw.replace('"tag":','"tag":"'+'1'*64+'","tag":')
        self.assertIsNone(self.verify(row['requestProof'],base64.b64encode(invalid.encode())))

    def test_base64_json_truncation_controls_and_invalid_mac_fail(self):
        row = self.vectors['vectors'][0]
        encoded = row['responseHeader'].encode()
        raw = base64.b64decode(encoded)
        cases = [b'',b'!!!!',encoded[:-1],encoded+b'\n',encoded+b'AAAA',base64.b64encode(raw+b' trailing'),
                 base64.b64encode(raw[:-1]),base64.b64encode(b'{"schemaVersion":1,"state":"dirty\x00"}'),
                 base64.b64encode(b'{"schemaVersion":1,"state":"\xff"}')]
        for case in cases:
            with self.subTest(case=case[:25]): self.assertIsNone(self.verify(row['requestProof'],case))
        for bad in ('0'*64,'A'*64,'1'*63,'g'*64):
            self.assertIsNone(self.verify(row['requestProof'],json_header(dict(row['response'],mac=bad))))
        self.assertIsNone(self.verify('A'*64,encoded))
        self.assertIsNone(self.verify('1'*63,encoded))

    def test_transport_whitespace_and_escaped_json_names_preserve_semantics(self):
        row = self.vectors['vectors'][0]
        raw = json.dumps(row['response'],indent=2).replace('"tag"','"ta\\u0067"')
        self.assertIsNotNone(self.verify(row['requestProof'],base64.b64encode(raw.encode())))

    def test_large_receipt_has_no_product_count_cap(self):
        proof = self.vectors['vectors'][0]['requestProof']
        pairs = [(f'{i:064x}',f'{i+1:064x}') for i in range(1100)]
        receipt = self.receipt(proof,'dirty',pairs)
        self.assertEqual(self.verify(proof,json_header(receipt)),('dirty',pairs))


if __name__ == '__main__': unittest.main()
