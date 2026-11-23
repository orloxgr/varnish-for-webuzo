"""Independent Python oracle for negotiated coverage v2; no provider SQL claim."""
import base64
import copy
import ctypes
import hashlib
import hmac
import json
import struct
import unittest
import test_mutation_wire as legacy

POLICY='c'*64
FIELDS=legacy.FIELDS
lp=legacy.lp
KEY=hmac.digest(('b'*64).encode(),b'ultracache-mutation-key-v1','sha256')

def request_frame(context):
    return (lp('ultracache-mutation-request-v2')+b''.join(lp(context[name]) for name in FIELDS[:10])+
        struct.pack('>I',1)+lp(context['coveragePolicy'])+lp(context['method'])+lp(context['url']))
def response_frame(proof,policy,result,state,pairs):
    return (lp('ultracache-mutation-response-v2')+lp(proof)+struct.pack('>I',1)+lp(policy)+lp(result)+lp(state)+
        struct.pack('>I',len(pairs))+b''.join(lp(tag)+lp(tx) for tag,tx in sorted(pairs)))
def completion_frame(context,result):
    return (lp('ultracache-mutation-completion-v2')+lp(context['proof'])+lp(context['requestId'])+
        lp(context['challenge'])+struct.pack('>I',1)+lp(context['coveragePolicy'])+lp(result))
def receipt(context,state='none',pairs=(),result='qualified',key=KEY):
    return dict(schemaVersion=2,state=state,transactions=[dict(tag=tag,transaction=tx) for tag,tx in pairs],
        coverageVersion=1,coveragePolicy=context['coveragePolicy'],coverage=result,
        mac=hmac.new(key,response_frame(context['proof'],context['coveragePolicy'],result,state,pairs),'sha256').hexdigest())
def completion_headers(context,result='qualified',key=KEY):
    return {'X-UltraCache-Private-Coverage-Version':'1',
        'X-UltraCache-Private-Coverage-Policy':context['coveragePolicy'],
        'X-UltraCache-Private-Coverage-Result':result,
        'X-UltraCache-Private-Coverage-Proof':hmac.new(key,completion_frame(context,result),'sha256').hexdigest()}

@unittest.skipUnless(legacy.CC,'Portable C compiler required')
class MutationCoverageWire(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        legacy.MutationWire.setUpClass.__func__(cls)
        cls.lib.delivery_mutation_request_proof_v2.argtypes=[ctypes.c_void_p,ctypes.POINTER(legacy.Context),ctypes.c_char_p,ctypes.c_void_p]
        cls.lib.delivery_mutation_context_header_v2.argtypes=[ctypes.c_void_p,ctypes.POINTER(legacy.Context),ctypes.c_char_p,ctypes.POINTER(ctypes.c_void_p),ctypes.c_void_p]
        cls.lib.delivery_mutation_receipt_verify_v2.argtypes=[ctypes.c_void_p,ctypes.c_char_p,ctypes.c_char_p,ctypes.c_void_p,ctypes.c_size_t,ctypes.POINTER(ctypes.POINTER(legacy.Receipt))]
        cls.lib.delivery_mutation_completion_proof.argtypes=[ctypes.c_void_p,*([ctypes.c_char_p]*4),ctypes.c_uint,ctypes.c_void_p]
    tearDownClass=classmethod(legacy.MutationWire.tearDownClass.__func__)
    context=legacy.MutationWire.context
    def verify(self,proof,policy,obj,raw=None):
        wire=raw if raw is not None else legacy.json_header(obj)
        output=ctypes.POINTER(legacy.Receipt)()
        result=self.lib.delivery_mutation_receipt_verify_v2(self.key,proof.encode(),policy.encode(),wire,len(wire),ctypes.byref(output))
        self.lib.delivery_mutation_receipt_free(output)
        return result
    def test_request_context_and_completion_match_independent_frames(self):
        vectors=json.loads((legacy.ROOT/'tests/fixtures/private_mutation_wire_v2.json').read_text())
        for row in vectors['vectors']:
            c=row['context'];proof=hmac.new(self.key,request_frame(c),'sha256').hexdigest()
            self.assertEqual(proof,row['requestProof'])
            out=ctypes.create_string_buffer(65);header=ctypes.c_void_p()
            self.assertEqual(self.lib.delivery_mutation_request_proof_v2(self.key,ctypes.byref(self.context(c)),c['coveragePolicy'].encode(),out),1)
            self.assertEqual(out.value.decode(),proof)
            self.assertEqual(self.lib.delivery_mutation_context_header_v2(self.key,ctypes.byref(self.context(c)),c['coveragePolicy'].encode(),ctypes.byref(header),out),1)
            try:
                value=json.loads(base64.b64decode(ctypes.string_at(header),validate=True))
                self.assertEqual(set(value),{'schemaVersion','proof','coverageVersion','coveragePolicy',*FIELDS[:10]})
                self.assertEqual((value['schemaVersion'],value['coverageVersion'],value['coveragePolicy'],value['proof']),(2,1,c['coveragePolicy'],proof))
            finally:self.lib.delivery_mutation_header_free(header)
            for result in ('qualified','unknown'):
                signed=dict(c,proof=proof)
                expected=hmac.new(self.key,completion_frame(signed,result),'sha256').hexdigest()
                self.assertEqual(expected,row['completionProofs'][result])
                self.assertEqual(self.lib.delivery_mutation_completion_proof(self.key,proof.encode(),c['requestId'].encode(),c['challenge'].encode(),c['coveragePolicy'].encode(),int(result=='qualified'),out),1)
                self.assertEqual(out.value.decode(),expected)
            for response in row['receipts']:
                self.assertEqual(self.verify(proof,c['coveragePolicy'],response),1)
    def test_independent_root_python_vectors_match_c_without_trusting_php_expected_bytes(self):
        vectors=json.loads((legacy.ROOT/'tests/fixtures/private_mutation_coverage_producer_v2.json').read_text())
        key=hmac.digest(vectors['syntheticSecret'].encode(),b'ultracache-mutation-key-v1','sha256')
        for row in vectors['vectors']:
            c=dict(row['context'],method=row['method'],url=row['url'])
            frame=request_frame(c);proof=hmac.new(key,frame,'sha256').hexdigest()
            self.assertEqual(frame.hex(),row['requestFrameHex']);self.assertEqual(proof,c['proof'])
            out=ctypes.create_string_buffer(65)
            self.assertEqual(self.lib.delivery_mutation_request_proof_v2(key,ctypes.byref(self.context(c)),c['coveragePolicy'].encode(),out),1)
            self.assertEqual(out.value.decode(),proof)
            response=row['response'];pairs=[(v['tag'],v['transaction']) for v in response['transactions']]
            frame=response_frame(proof,c['coveragePolicy'],response['coverage'],response['state'],pairs)
            self.assertEqual(frame.hex(),row['responseFrameHex'])
            self.assertEqual(hmac.new(key,frame,'sha256').hexdigest(),response['mac'])
            wire=legacy.json_header(response);record=ctypes.POINTER(legacy.Receipt)()
            self.assertEqual(self.lib.delivery_mutation_receipt_verify_v2(key,proof.encode(),c['coveragePolicy'].encode(),wire,len(wire),ctypes.byref(record)),1)
            self.lib.delivery_mutation_receipt_free(record)
            for result,expected in row['completions'].items():
                calculated=hmac.new(key,completion_frame(c,result),'sha256').hexdigest()
                self.assertEqual(calculated,expected['coverageProof'])
                self.assertEqual(self.lib.delivery_mutation_completion_proof(key,proof.encode(),c['requestId'].encode(),c['challenge'].encode(),c['coveragePolicy'].encode(),int(result=='qualified'),out),1)
                self.assertEqual(out.value.decode(),calculated)

    def sample(self):
        c=dict(self.vectors['vectors'][0]['context'],coveragePolicy=POLICY)
        c['proof']=hmac.new(self.key,request_frame(c),'sha256').hexdigest()
        return c,receipt(c,key=self.key)
    def test_receipt_requires_exact_seven_fields_and_bound_policy_coverage_state(self):
        c,good=self.sample();self.assertEqual(self.verify(c['proof'],POLICY,good),1)
        for name in good:
            bad=dict(good);del bad[name];self.assertEqual(self.verify(c['proof'],POLICY,bad),0)
        for bad in (dict(good,extra=True),dict(good,coverageVersion=2),dict(good,coverageVersion=True),
            dict(good,coveragePolicy='d'*64),dict(good,coverage='complete'),dict(good,schemaVersion=1),
            receipt(c,state='scope',result='qualified',key=self.key),receipt(c,state='none',pairs=[('1'*64,'2'*64)],key=self.key)):
            self.assertEqual(self.verify(c['proof'],POLICY,bad),0)
        self.assertEqual(self.verify(c['proof'],'e'*64,good),0)
        self.assertEqual(self.verify('e'*64,POLICY,good),0)
        raw=json.dumps(good,separators=(',',':'))
        for name in good:
            bad='{'+json.dumps(name)+':'+json.dumps(good[name])+','+raw[1:]
            self.assertEqual(self.verify(c['proof'],POLICY,None,base64.b64encode(bad.encode())),0)
        bad=raw.replace('"coveragePolicy":','"coveragePolicy":"'+POLICY+'","coverage\\u0050olicy":')
        self.assertEqual(self.verify(c['proof'],POLICY,None,base64.b64encode(bad.encode())),0)
    def test_v1_and_v2_cannot_cross_upgrade_or_downgrade(self):
        c,v2=self.sample()
        wire=legacy.json_header(v2);out=ctypes.POINTER(legacy.Receipt)()
        self.assertEqual(self.lib.delivery_mutation_receipt_verify(self.key,c['proof'].encode(),wire,len(wire),ctypes.byref(out)),0)
        old=self.vectors['vectors'][0]
        self.assertEqual(self.verify(old['requestProof'],POLICY,old['response']),0)
    def test_original_dimensions_and_policy_change_proof_and_completion_never_uses_new_policy(self):
        c,good=self.sample();proof=c['proof']
        for name in FIELDS+('coveragePolicy',):
            bad=dict(c);bad[name]=(('e' if c[name][0]!='e' else 'f')+c[name][1:]) if name not in ('canonicalHost','method','url') else {'canonicalHost':'other.test','method':('GET' if c[name]=='POST' else 'POST'),'url':'/different?raw=+'}[name]
            self.assertNotEqual(hmac.new(self.key,request_frame(bad),'sha256').hexdigest(),proof)
        out=ctypes.create_string_buffer(65)
        for args in ((proof,'1'*63,c['challenge'],POLICY,1),(proof,c['requestId'],c['challenge'],'A'*64,1),
            (proof,c['requestId'],c['challenge'],POLICY,2)):
            self.assertEqual(self.lib.delivery_mutation_completion_proof(self.key,*[v.encode() for v in args[:4]],args[4],out),0)

if __name__=='__main__':unittest.main()
