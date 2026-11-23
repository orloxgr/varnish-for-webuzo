"""Portable strict dispatch codec; independent Python and actual PHP vector."""
import base64,copy,ctypes,hashlib,hmac,json,struct,unittest
import test_mutation_wire as legacy

CONTEXT=('siteId','canonicalHost','scope','epoch','incarnation','nativePolicy','wordpressPolicy','reusePolicy')
FIELDS=('dispatch_id','target','site_id','host','scope','epoch','incarnation','native_policy',
        'wordpress_policy','reuse_policy','coverage_policy','request_id','challenge','header')
class Dispatch(ctypes.Structure):
    _fields_=[(name,ctypes.c_char_p) for name in FIELDS]

def frame(value):
    c=value['context'];e=value['execution'];lp=legacy.lp
    return (lp('ultracache-execution-drain-dispatch-v1')+lp('GET')+lp(value['target'])+lp(value['dispatchId'])+
        b''.join(lp(c[name]) for name in CONTEXT)+struct.pack('>I',1)+lp(c['coveragePolicy'])+
        lp(e['requestId'])+lp(e['challenge']))
def signed(value,key):
    value=copy.deepcopy(value);value['proof']=hmac.new(key,frame(value),'sha256').hexdigest()
    return value
def for_execution(original,scope='/',target='/wp-admin/admin-ajax.php?action=owned_read'):
    return dict(schemaVersion=1,dispatchId='e'*64,target=target,
        context={**{name:original[name] for name in CONTEXT if name!='scope'},'scope':scope,
                 'coverageVersion':1,'coveragePolicy':original['coveragePolicy']},
        execution={name:original[name] for name in ('requestId','challenge')})

@unittest.skipUnless(legacy.CC,'Portable C compiler required')
class ExecutionDrainWire(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        legacy.MutationWire.setUpClass.__func__(cls)
        cls.lib.delivery_execution_drain_verify.argtypes=[ctypes.c_void_p,ctypes.c_char_p,ctypes.c_size_t,ctypes.POINTER(ctypes.POINTER(Dispatch))]
        cls.lib.delivery_execution_drain_free.argtypes=[ctypes.POINTER(Dispatch)]
        cls.lib.delivery_execution_drain_proof.argtypes=[ctypes.c_void_p,ctypes.POINTER(Dispatch),ctypes.c_void_p]
        cls.vector=json.loads((legacy.ROOT/'tests/fixtures/private_execution_drain_producer_v1.json').read_text())
        cls.purpose=hmac.digest(cls.vector['syntheticSecret'].encode(),b'ultracache-mutation-key-v1','sha256')
    tearDownClass=classmethod(legacy.MutationWire.tearDownClass.__func__)
    def verify(self,value=None,raw=None,key=None):
        wire=legacy.json_header(value) if raw is None else raw
        out=ctypes.POINTER(Dispatch)()
        result=self.lib.delivery_execution_drain_verify(key or self.purpose,wire,len(wire),ctypes.byref(out))
        self.lib.delivery_execution_drain_free(out)
        return result
    def test_actual_php_vector_and_independent_python_frame_match_native(self):
        v=self.vector;value=v['value'];wire=v['header'].encode();out=ctypes.POINTER(Dispatch)()
        self.assertEqual(hashlib.sha256(frame(value)).hexdigest(),v['frameSha256'])
        self.assertEqual(signed(value,self.purpose)['proof'],value['proof'])
        self.assertEqual(self.lib.delivery_execution_drain_verify(self.purpose,wire,len(wire),ctypes.byref(out)),1)
        try:
            proof=ctypes.create_string_buffer(65)
            self.assertEqual(self.lib.delivery_execution_drain_proof(self.purpose,out,proof),1)
            self.assertEqual(proof.value.decode(),value['proof'])
            self.assertEqual(out.contents.target.decode(),value['target'])
        finally:self.lib.delivery_execution_drain_free(out)
    def test_exact_nested_schema_duplicate_names_and_base64_canonicality(self):
        value=self.vector['value'];self.assertEqual(self.verify(value),1)
        for container in ((),('context',),('execution',)):
            parent=value if not container else value[container[0]]
            for name in parent:
                bad=copy.deepcopy(value);node=bad if not container else bad[container[0]]
                del node[name];self.assertEqual(self.verify(bad),0)
                raw=json.dumps(value,separators=(',',':'))
                needle=json.dumps(name)+':'
                duplicate=needle+json.dumps(parent[name],separators=(',',':'))+','+needle
                self.assertEqual(self.verify(raw=base64.b64encode(raw.replace(needle,duplicate,1).encode())),0)
            bad=copy.deepcopy(value);node=bad if not container else bad[container[0]]
            node['unexpected']=True;self.assertEqual(self.verify(bad),0)
        raw=json.dumps(value,separators=(',',':')).replace('"challenge":','"challenge":"'+value['execution']['challenge']+'","challeng\\u0065":')
        self.assertEqual(self.verify(raw=base64.b64encode(raw.encode())),0)
        for raw in (self.vector['header'].encode()+b' ',b'!'+self.vector['header'].encode(),base64.b64encode(json.dumps(value).encode()+b'\x00')):
            self.assertEqual(self.verify(raw=raw),0)
    def test_all_signed_dimensions_wrong_key_and_invalid_typed_values_reject(self):
        original=self.vector['value']
        for path in [('dispatchId',),('target',)]+[('context',name) for name in CONTEXT+('coveragePolicy',)]+[('execution',name) for name in ('requestId','challenge')]:
            bad=copy.deepcopy(original);node=bad if len(path)==1 else bad[path[0]];name=path[-1]
            node[name]=node[name]+'x';self.assertEqual(self.verify(bad),0)
        for path,value in ((('schemaVersion',),True),(('context','coverageVersion'),True),
                           (('target',),'//other.test/x'),(('target',),'/a#fragment'),(('target',),'/a\x00b'),
                           (('context','scope'),'/store?query/')):
            bad=copy.deepcopy(original);node=bad if len(path)==1 else bad[path[0]];node[path[-1]]=value
            self.assertEqual(self.verify(signed(bad,self.purpose)),0)
        self.assertEqual(self.verify(original,key=b'X'*32),0)

if __name__=='__main__':unittest.main()
