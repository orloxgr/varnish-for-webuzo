"""Independent finalization vectors and optional legacy-envelope compatibility."""
import base64
import copy
import ctypes
import hashlib
import hmac
import json
import unittest
from test_reuse_cookie_inputs import CC, ROOT, Context, Recipe, ReuseCookieInputs, lp

class Candidate(ctypes.Structure):
    _fields_=[('request_id',ctypes.c_char*65),('challenge',ctypes.c_char*65),
              ('input_evidence',ctypes.c_char*65),('recipe',ctypes.POINTER(Recipe))]
class Finalize(ctypes.Structure):
    _fields_=[('page',Context)]+[(n,ctypes.c_char_p) for n in
        ('incarnation','scope_revision','request_id','challenge','delivery_request_id','binding','input_evidence')]

@unittest.skipUnless(CC,'Portable compiler required; skipping does not qualify integration')
class ReuseWire(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ReuseCookieInputs.setUpClass.__func__(cls)
        cls.lib.delivery_reuse_finalize_proof.argtypes=[ctypes.c_void_p,ctypes.c_char_p,ctypes.c_char_p,
            ctypes.POINTER(Finalize),ctypes.c_void_p]
        cls.lib.delivery_reuse_finalize_header.argtypes=cls.lib.delivery_reuse_finalize_proof.argtypes[:-1]+[ctypes.POINTER(ctypes.c_void_p)]
        cls.lib.delivery_reuse_envelope_split.argtypes=[ctypes.c_char_p,ctypes.c_size_t,ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_size_t),ctypes.POINTER(ctypes.c_void_p),ctypes.POINTER(ctypes.c_size_t)]
        cls.lib.delivery_reuse_candidate_parse.argtypes=[ctypes.c_char_p,ctypes.c_size_t,ctypes.c_uint64,ctypes.POINTER(ctypes.POINTER(Candidate))]
        cls.lib.delivery_reuse_candidate_free.argtypes=[ctypes.POINTER(Candidate)]
        cls.lib.delivery_reuse_record_parse.argtypes=[ctypes.c_char_p,ctypes.c_size_t,ctypes.POINTER(ctypes.c_void_p)]
        cls.lib.delivery_reuse_record_free.argtypes=[ctypes.c_void_p]
    @classmethod
    def tearDownClass(cls):ReuseCookieInputs.tearDownClass.__func__(cls)
    def split(self,wire):
        raw=wire.encode();out=ctypes.c_void_p();size=ctypes.c_size_t();candidate=ctypes.c_void_p();cs=ctypes.c_size_t()
        status=self.lib.delivery_reuse_envelope_split(raw,len(raw),ctypes.byref(out),ctypes.byref(size),ctypes.byref(candidate),ctypes.byref(cs))
        try:return status,ctypes.string_at(out,size.value) if out else None,ctypes.string_at(candidate,cs.value) if candidate else None
        finally:
            self.lib.delivery_reuse_frame_free(out,size.value+1)
            self.lib.delivery_reuse_frame_free(candidate,cs.value+1)
    def test_finalize_independent_frames_proofs_and_exact_headers(self):
        sources=[json.loads((ROOT/'tests/fixtures/private_reuse_finalize_v1.json').read_text()),
                 json.loads((ROOT/'tests/fixtures/private_reuse_finalize_producer_v1.json').read_text())]
        for fixture in sources:self.check_finalize_vectors(fixture)
    def check_finalize_vectors(self,fixture):
        key=hmac.digest(fixture['syntheticSecret'].encode(),b'ultracache-delivery-reuse-key-v1','sha256')
        if 'reuseKeyHex' in fixture:self.assertEqual(key.hex(),fixture['reuseKeyHex'])
        for row in fixture['vectors']:
            obj=row.get('context',row.get('message'));c=obj['context']
            uri=row.get('originalUrl',row.get('uri'))
            fields=('siteId','canonicalHost','scope','epoch','nativePolicy','wordpressPolicy','reusePolicy','publicationDigest','representation','recipeDigest')
            value=Finalize(Context(*(c[n].encode() for n in fields)),*(v.encode() for v in
                (c['incarnation'],c['scopeRevision'],obj['requestId'],obj['challenge'],obj['deliveryRequestId'],obj['binding'],obj['inputEvidence'])))
            proof=ctypes.create_string_buffer(65);out=ctypes.c_void_p()
            with self.subTest(name=row['name']):
                self.assertEqual(self.lib.delivery_reuse_finalize_proof(key,b'GET',uri.encode(),ctypes.byref(value),proof),1)
                self.assertEqual(proof.value.decode(),obj['proof'])
                self.assertEqual(proof.value.decode(),hmac.new(key,bytes.fromhex(row.get('proofFrameHex',row.get('frameHex'))),'sha256').hexdigest())
                self.assertEqual(self.lib.delivery_reuse_finalize_header(key,b'GET',uri.encode(),ctypes.byref(value),ctypes.byref(out)),1)
                header=ctypes.string_at(out);self.lib.delivery_reuse_frame_free(out,len(header)+1)
                self.assertEqual(header.decode(),row['header']);self.assertEqual(json.loads(base64.b64decode(header)),obj)
                self.assertEqual(self.lib.delivery_reuse_finalize_proof(key,b'POST',uri.encode(),ctypes.byref(value),proof),0)
                self.assertEqual(self.lib.delivery_reuse_finalize_proof(key,b'GET',b'//bad',ctypes.byref(value),proof),0)
                self.assertEqual(self.lib.delivery_reuse_finalize_proof(key,b'GET',(uri+'&changed=1').encode(),ctypes.byref(value),proof),1)
                self.assertNotEqual(proof.value.decode(),obj['proof'])
    def test_extension_split_preserves_legacy_bytes_and_isolates_optional_failure(self):
        for value in ('null','false','[1,true,{"nested":["x",null,-1.2e+3]}]','{"version":999}'):
            raw=' { "schemaVersion" : 1, "reuseCandidate": '+value+', "requestId":"12", "html":"\\u00e9 \\" q" } '
            result,wire,candidate=self.split(raw)
            self.assertEqual(result,1);self.assertEqual(candidate.decode(),value)
            self.assertEqual(wire,b'{"schemaVersion" : 1,"requestId":"12","html":"\\u00e9 \\" q"}')
            parsed=ctypes.POINTER(Candidate)()
            self.assertEqual(self.lib.delivery_reuse_candidate_parse(candidate,len(candidate),0,ctypes.byref(parsed)),0)
        self.assertEqual(self.split('{"reuseCandidate":{},"a":1,"reuseCandidate":{}}'),(1,b'{"a":1}',None))
        self.assertEqual(self.split('{"a":[],"b":{},"c":[[[]]]}'),(1,b'{"a":[],"b":{},"c":[[[]]]}',None))
    def test_malformed_transport_never_becomes_valid_legacy(self):
        for raw in ('{"a":01}','{"a":[1,]}','{"a":{"b":1,}}','{"a":tru}','{"a":1}x',
                    '{"a":1e}','{"a":-}','{"a":1.}','{"a":[}', '{"reuseCandidate":"\\ud800"}'):
            self.assertEqual(self.split(raw),(0,None,None),raw)
    def test_candidate_exact_ids_canonical_recipe_and_occurrence_coverage(self):
        fixture=json.loads((ROOT/'tests/fixtures/private_reuse_recipe_v1.json').read_text())
        recipe=fixture['vectors'][1]['recipe']
        obj=dict(version=1,requestId='1'*64,challenge='2'*64,recipe=recipe,inputEvidence='3'*64)
        n=sum(row['occurrences'] for row in recipe['fragments'])
        def parse(obj,count=n):
            wire=json.dumps(obj).encode();out=ctypes.POINTER(Candidate)()
            result=self.lib.delivery_reuse_candidate_parse(wire,len(wire),count,ctypes.byref(out))
            self.lib.delivery_reuse_candidate_free(out);return result
        self.assertEqual(parse(obj),1);self.assertEqual(parse(obj,n+1),0)
        for key in obj:
            bad=copy.deepcopy(obj);del bad[key];self.assertEqual(parse(bad),0)
        bad=copy.deepcopy(obj);bad['extra']=True;self.assertEqual(parse(bad),0)
        bad=copy.deepcopy(obj);bad['recipe']['digest']='0'*64;self.assertEqual(parse(bad),0)

    def metadata(self):
        fixture=json.loads((ROOT/'tests/fixtures/private_reuse_finalize_v1.json').read_text())['vectors'][0]['context']
        recipe=json.loads((ROOT/'tests/fixtures/private_reuse_recipe_v1.json').read_text())['vectors'][1]['recipe']
        context=dict(fixture['context'],recipeDigest=recipe['digest'])
        fragments=[]
        for row in recipe['fragments']:
            fragments.append(dict(descriptor=row['descriptor'],url=row['url'],
                cache=dict(key='e'*64,ttl=120,tags='owner product:123'),bodyValidUntil=2000000200,
                identity=dict(identityState='personal',identityInputs=recipe['inputs'],
                    identityBinding='f'*64,owner='1'*64,tags=['1'*64,'2'*64],validUntil=2000000300),
                authority=[dict(tag=tag,revision='3'*64,generation='4'*64) for tag in ('1'*64,'2'*64)]))
        return dict(schemaVersion=1,requestId='123',originalUrl='/original?raw=+%26',reuse=dict(version=1,
            context=context,recipe=recipe,admission=dict(binding='5'*64,validUntil=2000000100,
                cookieWork=dict(state='none',validUntil=2000000400),fragments=fragments)))
    def parse_metadata(self,obj):
        wire=obj.encode() if isinstance(obj,str) else json.dumps(obj).encode();out=ctypes.c_void_p()
        result=self.lib.delivery_reuse_record_parse(wire,len(wire),ctypes.byref(out))
        if result:self.assertTrue(out)
        else:self.assertFalse(out)
        self.lib.delivery_reuse_record_free(out);return result
    def test_metadata_requires_exact_complete_coverage_and_absolute_deadlines(self):
        obj=self.metadata();self.assertEqual(self.parse_metadata(obj),1)
        failures=[]
        def changed(mutator):
            bad=copy.deepcopy(obj);mutator(bad);failures.append(bad)
        changed(lambda b:b['reuse']['admission']['fragments'].pop())
        changed(lambda b:b['reuse']['admission']['fragments'].append(copy.deepcopy(b['reuse']['admission']['fragments'][0])))
        changed(lambda b:b['reuse']['admission']['fragments'][0]['authority'].pop())
        changed(lambda b:b['reuse']['admission']['fragments'][0]['authority'].append(dict(tag='9'*64,revision='3'*64,generation='4'*64)))
        changed(lambda b:b['reuse']['admission']['fragments'][0]['identity'].update(owner='9'*64))
        changed(lambda b:b['reuse']['admission']['fragments'][0]['identity'].update(identityState='anonymous'))
        changed(lambda b:b['reuse']['admission']['fragments'][0]['cache'].update(ttl=0))
        changed(lambda b:b['reuse']['admission']['fragments'][0].update(bodyValidUntil=1))
        changed(lambda b:b['reuse']['admission']['fragments'][0]['identity'].update(validUntil=1))
        changed(lambda b:b['reuse']['admission']['cookieWork'].update(validUntil=1))
        changed(lambda b:b['reuse']['admission']['cookieWork'].update(state='pending'))
        changed(lambda b:b['reuse']['context'].update(recipeDigest='0'*64))
        changed(lambda b:b['reuse']['recipe']['fragments'][0].update(occurrences=1))
        for bad in failures:self.assertEqual(self.parse_metadata(bad),0)
    def test_metadata_rejects_unknown_duplicate_or_missing_fields_at_every_level(self):
        obj=self.metadata()
        paths=[(),('reuse',),('reuse','context'),('reuse','recipe'),('reuse','admission'),
            ('reuse','admission','cookieWork'),('reuse','admission','fragments',0),
            ('reuse','admission','fragments',0,'cache'),('reuse','admission','fragments',0,'identity'),
            ('reuse','admission','fragments',0,'identity','identityInputs'),
            ('reuse','admission','fragments',0,'authority',0)]
        for path in paths:
            for remove in (False,True):
                bad=copy.deepcopy(obj);node=bad
                for key in path:node=node[key]
                if remove:del node[next(iter(node))]
                else:node['unexpected']=False
                self.assertEqual(self.parse_metadata(bad),0,(path,remove))
        wire=json.dumps(obj,separators=(',',':'))
        for field in ('schemaVersion','version','binding','validUntil','owner','tag'):
            needle='"'+field+'":';start=wire.index(needle);value_start=start+len(needle)
            end=value_start
            if wire[end]=='"':end=wire.index('"',end+1)+1
            else:
                while wire[end] not in ',}':end+=1
            duplicate=wire[:end]+','+wire[start:end]+wire[end:]
            self.assertEqual(self.parse_metadata(duplicate),0,field)

    def test_mixed_anonymous_nonce_retains_full_recipe_without_fabricated_owner_or_authority(self):
        obj=self.metadata();nonce=obj['reuse']['admission']['fragments'][-1]
        nonce['identity'].update(identityState='anonymous',owner=None,tags=[])
        nonce['authority']=[]
        self.assertEqual(self.parse_metadata(obj),1)
        for bad_field,value in (('owner','0'*64),('tags',['1'*64]),('identityState','personal')):
            bad=copy.deepcopy(obj);bad['reuse']['admission']['fragments'][-1]['identity'][bad_field]=value
            self.assertEqual(self.parse_metadata(bad),0)
        bad=copy.deepcopy(obj)
        bad['reuse']['admission']['fragments'][-1]['authority']=[dict(tag='1'*64,revision='2'*64,generation='3'*64)]
        self.assertEqual(self.parse_metadata(bad),0)
        bad=copy.deepcopy(obj);bad['reuse']['admission']['fragments'].pop()
        self.assertEqual(self.parse_metadata(bad),0,'Anonymous nonce is required, never silently omitted')

    def test_anonymous_content_dependencies_require_exact_authority_and_null_owner(self):
        obj=self.metadata()
        for row in obj['reuse']['admission']['fragments']:
            row['identity'].update(identityState='anonymous',owner=None)
        self.assertEqual(self.parse_metadata(obj),1,'All anonymous may depend on mutable content')
        for mutation in ('missing','extra','duplicate','malformed','owner'):
            bad=copy.deepcopy(obj);row=bad['reuse']['admission']['fragments'][0]
            if mutation=='missing':row['authority'].pop()
            elif mutation=='extra':row['authority'].append(dict(tag='9'*64,revision='3'*64,generation='4'*64))
            elif mutation=='duplicate':row['identity']['tags'].append(row['identity']['tags'][0])
            elif mutation=='malformed':row['authority'][0]['revision']='invalid'
            else:row['identity']['owner']='1'*64
            self.assertEqual(self.parse_metadata(bad),0,mutation)

    def test_content_dependency_admission_uses_a_new_object_namespace(self):
        self.lib.delivery_reuse_metadata_key.argtypes=[ctypes.POINTER(Context),ctypes.c_char_p,ctypes.c_void_p]
        fields=('siteId','canonicalHost','scope','epoch','nativePolicy','wordpressPolicy','reusePolicy','publicationDigest','representation','recipeDigest')
        values=self.metadata()['reuse']['context'];context=Context(*(values[n].encode() for n in fields))
        out=ctypes.create_string_buffer(65);binding=b'5'*64
        self.assertEqual(self.lib.delivery_reuse_metadata_key(ctypes.byref(context),binding,out),1)
        suffix=b''.join(lp(values[n]) for n in fields)+lp(binding)
        self.assertNotEqual(out.value.decode(),hashlib.sha256(lp('ultracache-private-admission-object-v1')+suffix).hexdigest())
        self.assertEqual(out.value.decode(),hashlib.sha256(lp('ultracache-private-admission-object-v2')+suffix).hexdigest())

if __name__=='__main__':unittest.main()
