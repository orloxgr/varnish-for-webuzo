"""Exact native-C/PHP parity; synthetic fixtures, never admission authority."""
import copy
import ctypes
import hashlib
import hmac
import json
import os
from pathlib import Path
import random
import shutil
import struct
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
VECTORS=json.loads((ROOT/'tests/fixtures/private_reuse_cookie_inputs_v1.json').read_text(encoding='utf-8'))
CC=shutil.which('cc') or shutil.which('gcc')
FIELDS=('siteId','canonicalHost','scope','epoch','nativePolicy','wordpressPolicy','reusePolicy',
        'publicationDigest','representation','recipeDigest')

class Inputs(ctypes.Structure):
    _fields_=[('names',ctypes.POINTER(ctypes.c_char_p)),('prefixes',ctypes.POINTER(ctypes.c_char_p)),
              ('name_count',ctypes.c_size_t),('prefix_count',ctypes.c_size_t),('php_max_input_vars',ctypes.c_uint32)]
class Descriptor(ctypes.Structure):pass
Descriptor._fields_=[('next',ctypes.POINTER(Descriptor)),('descriptor',ctypes.c_char*65),
                    ('url',ctypes.c_char_p),('provider',ctypes.c_char_p),('occurrences',ctypes.c_uint64)]
class Recipe(ctypes.Structure):
    _fields_=[('digest',ctypes.c_char*65),('inputs',ctypes.POINTER(Inputs)),
              ('fragments',ctypes.POINTER(Descriptor)),('occurrences',ctypes.c_uint64)]
class Context(ctypes.Structure):
    _fields_=[(name,ctypes.c_char_p) for name in FIELDS]

def lp(value):
    if isinstance(value,str):value=value.encode()
    return struct.pack('>I',len(value))+value

def declaration(names=(),prefixes=(),budget=1000):
    return dict(cookieNames=list(names),cookiePrefixes=list(prefixes),phpMaxInputVars=budget)

def descriptor_digest(url,provider):
    return hashlib.sha256(lp('ultracache-private-descriptor-v1')+lp(url)+lp(provider)).hexdigest()

def recipe_frame(recipe):
    inputs=recipe['inputs'];names=sorted(set(inputs['cookieNames']));prefixes=sorted(set(inputs['cookiePrefixes']))
    declaration_frame=(lp('ultracache-cookie-inputs-v1')+struct.pack('>I',inputs['phpMaxInputVars'])+
        struct.pack('>I',len(names))+b''.join(lp(v) for v in names)+
        struct.pack('>I',len(prefixes))+b''.join(lp(v) for v in prefixes)+struct.pack('>I',0))
    fragments=sorted(recipe['fragments'],key=lambda row:row['descriptor'])
    return (lp('ultracache-private-recipe-v1')+lp(declaration_frame)+struct.pack('>I',len(fragments))+
        b''.join(lp(row['descriptor'])+lp(row['url'])+lp(row['provider'])+struct.pack('>Q',row['occurrences']) for row in fragments))

def seal_recipe(recipe):
    for row in recipe['fragments']:row['descriptor']=descriptor_digest(row['url'],row['provider'])
    recipe['digest']=hashlib.sha256(recipe_frame(recipe)).hexdigest()
    return recipe

@unittest.skipUnless(CC,'Portable C compiler required; skipped does not qualify parity')
class ReuseCookieInputs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder=tempfile.TemporaryDirectory(prefix='owned-reuse-inputs-')
        library=Path(cls.folder.name)/('reuse.dll' if os.name=='nt' else 'reuse.so')
        command=[CC,'-std=c99','-Wall','-Wextra','-Werror','-O2','-shared']
        if os.name!='nt':command+=['-fPIC']
        result=subprocess.run(command+[str(ROOT/'shared/native/delivery_envelope.c'),'-o',str(library)],capture_output=True,text=True)
        if result.returncode:raise AssertionError(result.stdout+result.stderr)
        cls.lib=ctypes.CDLL(str(library))
        cls.lib.delivery_reuse_inputs_parse.argtypes=[ctypes.c_char_p,ctypes.c_size_t,ctypes.POINTER(ctypes.POINTER(Inputs))]
        cls.lib.delivery_reuse_inputs_free.argtypes=[ctypes.POINTER(Inputs)]
        cls.lib.delivery_reuse_input_projection.argtypes=[ctypes.POINTER(Inputs),ctypes.c_void_p,ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_void_p),ctypes.POINTER(ctypes.c_size_t)]
        cls.lib.delivery_reuse_frame_free.argtypes=[ctypes.c_void_p,ctypes.c_size_t]
        cls.lib.delivery_reuse_input_binding.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.POINTER(Context),
            ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p]
        cls.lib.delivery_reuse_identity_binding.argtypes=cls.lib.delivery_reuse_input_binding.argtypes
        cls.lib.delivery_reuse_key_derive.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p]
        cls.lib.delivery_reuse_input_mac.argtypes=[ctypes.c_void_p,ctypes.POINTER(Context),ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p]
        cls.lib.delivery_reuse_identity_mac.argtypes=cls.lib.delivery_reuse_input_mac.argtypes
        cls.lib.delivery_reuse_recipe_parse.argtypes=[ctypes.c_char_p,ctypes.c_size_t,ctypes.c_uint64,
            ctypes.POINTER(ctypes.POINTER(Recipe))]
        cls.lib.delivery_reuse_recipe_free.argtypes=[ctypes.POINTER(Recipe)]
        cls.lib.delivery_reuse_descriptor_digest.argtypes=[ctypes.c_char_p,ctypes.c_char_p,ctypes.c_void_p]
        cls.lib.delivery_reuse_recipe_digest.argtypes=[ctypes.POINTER(Recipe),ctypes.c_void_p]
    @classmethod
    def tearDownClass(cls):
        if os.name=='nt':
            import _ctypes
            _ctypes.FreeLibrary(cls.lib._handle);cls.lib=None
        cls.folder.cleanup()
    def inputs(self,value):
        raw=value.encode() if isinstance(value,str) else json.dumps(value).encode()
        out=ctypes.POINTER(Inputs)()
        result=self.lib.delivery_reuse_inputs_parse(raw,len(raw),ctypes.byref(out))
        return result,out
    def projection(self,declaration,cookie):
        result,inputs=self.inputs(declaration)
        self.assertEqual(result,1)
        wire=cookie.encode() if isinstance(cookie,str) else cookie
        output=ctypes.c_void_p();length=ctypes.c_size_t()
        try:
            result=self.lib.delivery_reuse_input_projection(inputs,wire,len(wire),ctypes.byref(output),ctypes.byref(length))
            return result,ctypes.string_at(output,length.value) if output else None
        finally:
            self.lib.delivery_reuse_frame_free(output,length)
            self.lib.delivery_reuse_inputs_free(inputs)
    def binding(self,context,frame,secret=None):
        if secret is None:secret=VECTORS['syntheticSecret'].encode()
        context=Context(*(context[k].encode() for k in FIELDS))
        output=ctypes.create_string_buffer(65)
        self.assertEqual(self.lib.delivery_reuse_input_binding(secret,len(secret),ctypes.byref(context),frame,len(frame),output),1)
        return output.value.decode()
    def vector(self,row):
        result,frame=self.projection(row['inputs'],row['cookieHeader'])
        if row['projection'].get('error'):
            expected={'ultracache_reuse_input_ambiguous':-4,'ultracache_reuse_input_budget':-5}
            self.assertIn(row['projection']['error'],expected)
            self.assertEqual(result,expected[row['projection']['error']]);self.assertIsNone(frame);return
        self.assertEqual(result,1)
        self.assertEqual(frame.hex(),row['projection']['frameHex'])
        native=self.binding(row['context'],frame)
        self.assertEqual(native,row['binding'],'C MAC must match actual PHP production helper')
        key=hmac.digest(VECTORS['syntheticSecret'].encode(),b'ultracache-delivery-reuse-key-v1','sha256')
        message=lp('ultracache-delivery-reuse-binding-v1')+b''.join(lp(row['context'][k]) for k in FIELDS)+lp(frame)
        self.assertEqual(native,hmac.new(key,message,hashlib.sha256).hexdigest())

    def identity_binding(self,context,frame,secret=None):
        if secret is None:secret=VECTORS['syntheticSecret'].encode()
        context=Context(*(context.get(k).encode() if context.get(k) is not None else None for k in FIELDS))
        output=ctypes.create_string_buffer(65)
        result=self.lib.delivery_reuse_identity_binding(secret,len(secret),ctypes.byref(context),frame,len(frame),output)
        return result,output.value.decode()

    def test_identity_binding_matches_independent_vectors_without_page_dimensions(self):
        vectors=json.loads((ROOT/'tests/fixtures/private_identity_binding_v1.json').read_text(encoding='utf-8'))
        key=hmac.digest(vectors['syntheticSecret'].encode(),b'ultracache-delivery-reuse-key-v1','sha256')
        for row in vectors['vectors']:
            with self.subTest(name=row['name']):
                source=next(v for v in VECTORS['vectors'] if v['name']==row['projectionSource'])
                result,projection=self.projection(source['inputs'],source['cookieHeader'])
                self.assertEqual(result,1)
                self.assertEqual(projection.hex(),row['projectionFrameHex'])
                message=lp('ultracache-private-identity-binding-v1')+b''.join(lp(row['context'][k]) for k in FIELDS[:7])+lp(projection)
                self.assertEqual(message.hex(),row['bindingFrameHex'])
                self.assertEqual(hmac.new(key,message,hashlib.sha256).hexdigest(),row['identityBinding'])
                self.assertEqual(self.identity_binding(row['context'],projection),(1,row['identityBinding']))

    def test_identity_binding_changes_with_native_scope_policies_or_identity_not_page(self):
        row=next(r for r in VECTORS['vectors'] if r['name']=='exact')
        frame=bytes.fromhex(row['projection']['frameHex']);context=dict(row['context'])
        result,baseline=self.identity_binding(context,frame)
        self.assertEqual(result,1)
        for field in FIELDS[:7]:
            changed=dict(context);changed[field]+='x'
            with self.subTest(field=field):
                self.assertNotEqual(self.identity_binding(changed,frame)[1],baseline)
                changed[field]=None
                self.assertEqual(self.identity_binding(changed,frame),(0,''))
        for field in FIELDS[7:]:
            for value in ('other-page',None,''):
                changed=dict(context);changed[field]=value
                self.assertEqual(self.identity_binding(changed,frame),(1,baseline))
        absent=next(r for r in VECTORS['vectors'] if r['name']=='absent')
        self.assertNotEqual(self.identity_binding(context,bytes.fromhex(absent['projection']['frameHex']))[1],baseline)
        self.assertNotEqual(self.identity_binding(context,frame,b'other-secret')[1],baseline)
        self.assertNotEqual(self.binding(context,frame),baseline,'Page-admission and identity domains must differ')

    def test_retained_purpose_key_produces_the_exact_original_php_bindings_without_double_derivation(self):
        secret=VECTORS['syntheticSecret'].encode();key=ctypes.create_string_buffer(32)
        self.assertEqual(self.lib.delivery_reuse_key_derive(secret,len(secret),key),1)
        self.assertEqual(key.raw,hmac.digest(secret,b'ultracache-delivery-reuse-key-v1','sha256'))
        for row in VECTORS['vectors']:
            if row['projection'].get('error'):continue
            frame=bytes.fromhex(row['projection']['frameHex']);context=Context(*(row['context'][k].encode() for k in FIELDS))
            page=ctypes.create_string_buffer(65);identity=ctypes.create_string_buffer(65)
            self.assertEqual(self.lib.delivery_reuse_input_mac(key,ctypes.byref(context),frame,len(frame),page),1)
            self.assertEqual(self.lib.delivery_reuse_identity_mac(key,ctypes.byref(context),frame,len(frame),identity),1)
            self.assertEqual(page.value.decode(),row['binding'])
            self.assertEqual(identity.value.decode(),self.identity_binding(row['context'],frame)[1])

    def test_all_accepted_context_dimensions_and_secret_change_mac(self):
        row=next(r for r in VECTORS['vectors'] if r['name']=='exact')
        frame=bytes.fromhex(row['projection']['frameHex']);baseline=self.binding(row['context'],frame)
        for field in FIELDS:
            changed=dict(row['context']);changed[field]+='x'
            with self.subTest(field=field):self.assertNotEqual(self.binding(changed,frame),baseline)
        self.assertNotEqual(self.binding(row['context'],frame,b'other-synthetic-secret'),baseline)
    def test_declarations_require_complete_runtime_metadata_and_strict_unambiguous_schema(self):
        bad=['{}','{"cookieNames":[]}','{"cookieNames":[],"cookiePrefixes":[]}',
             '{"cookieNames":[],"cookieNames":[],"cookiePrefixes":[],"phpMaxInputVars":1000}',
             '{"cookieNames":[],"cookiePrefixes":[],"phpMaxInputVars":1000,"phpMaxInputVars":1000}',
             json.dumps(dict(declaration(),other=0)),json.dumps(declaration(['owned input'])),
             json.dumps(declaration(['owned\x00input'])),json.dumps(declaration(prefixes=[''])),
             json.dumps(declaration())+' trailing']
        bad += [json.dumps(declaration(budget=value)) for value in (-1,True,'1000',2.5,2**32)]
        for raw in bad:
            with self.subTest(raw=raw):
                result,out=self.inputs(raw)
                try:self.assertEqual(result,-2);self.assertFalse(out)
                finally:self.lib.delivery_reuse_inputs_free(out)
    def test_cookie_control_bytes_fail_projection_not_cookie_policy(self):
        for value in (b'owned_input=one\x00two',b'unrelated=one\rtwo'):
            result,frame=self.projection(declaration(['owned_input']),value)
            self.assertEqual(result,-3);self.assertIsNone(frame)
    def test_unmatched_bracket_fallback_cannot_hide_consumed_exact_or_prefix_input(self):
        cases=[(declaration(['auth_session']),'auth[session=ownerB; auth_session=ownerA'),
               (declaration(prefixes=['wp_woocommerce_session_']),'wp[woocommerce[session_x=ownerB'),
               (declaration(['auth_session']),'auth[session')]
        for inputs,wire in cases:
            with self.subTest(wire=wire):
                result,frame=self.projection(inputs,wire)
                self.assertEqual(result,-4);self.assertIsNone(frame)
        inputs=declaration(['auth_session'])
        self.assertEqual(self.projection(inputs,'unrelated[session=not-consumed; auth_session=ownerA'),
                         self.projection(inputs,'auth_session=ownerA'))
        empty_base=declaration(['_auth_session'])
        self.assertEqual(self.projection(empty_base,'[auth_session=ignored'),self.projection(empty_base,''))
    def test_leading_tab_before_consumed_name_is_bound_like_php(self):
        cases=[(declaration(['auth_session']),'auth_session'),
               (declaration(prefixes=['wp_woocommerce_session_']),'wp_woocommerce_session_x')]
        for inputs,name in cases:
            with self.subTest(name=name):
                self.assertEqual(self.projection(inputs,'tracker=1;\t'+name+'=ownerB; '+name+'=ownerA'),
                                 self.projection(inputs,name+'=ownerB; '+name+'=ownerA'))
                self.assertNotEqual(self.projection(inputs,'tracker=1;\t'+name+'=ownerB; '+name+'=ownerA'),
                                    self.projection(inputs,name+'=ownerA'))
    def test_actual_parser_budget_counts_tokens_without_binding_unrelated_tail(self):
        inputs=declaration(['owned_input'],budget=1)
        expected=self.projection(inputs,'owned_input=one')
        self.assertEqual(self.projection(inputs,'; \t; =empty;owned_input=one;'+('n;'*2000)),expected)
        self.assertEqual(self.projection(inputs,'n;owned_input=one'),(-5,None))
        self.assertEqual(self.projection(inputs,'n;n;n;owned_input=one'),(-5,None))
        self.assertNotEqual(self.projection(declaration(['owned_input'],budget=2),'owned_input=one'),expected)
        self.assertEqual(self.projection(declaration(['owned_input'],budget=0),'owned_input=one'),(-5,None))
        self.assertEqual(self.projection(declaration(['owned_input'],budget=0),'')[0],1)
    def test_alias_prefix_and_unrelated_input_permutations_match_independent_frames(self):
        rng=random.Random(1006)
        inputs=declaration(['absent'],['owned.family.'])
        for n in range(100):
            values=[('owned.family.a','value+'+str(n)),('owned_family_b','%2B'+str(n))]
            rng.shuffle(values)
            wire='; '.join(k+'='+v for k,v in [values[0],('analytics','unconsumed-'+str(n)),values[1]])
            result,frame=self.projection(inputs,wire);self.assertEqual(result,1)
            expected=lp('ultracache-cookie-inputs-v1')+struct.pack('>II',1000,1)+lp('absent')+struct.pack('>I',1)+lp('owned.family.')+struct.pack('>I',2)
            for raw,value in sorted(values,key=lambda pair:pair[0].replace('.','_')):
                expected+=lp(raw.replace('.','_'))+struct.pack('>I',1)+lp(raw)+lp(value)
            self.assertEqual(frame,expected)

    def test_recipe_metadata_is_strict_and_binds_complete_occurrence_count(self):
        recipe=seal_recipe({'digest':'a'*64,'inputs':declaration(['owned_input','owned_input'],['new_']),
            'fragments':[{'descriptor':'b'*64,'url':'/shop/?ultracache_esi=first','provider':'native-cart','occurrences':2},
                         {'descriptor':'c'*64,'url':'/shop/?ultracache_esi=second','provider':'nonce','occurrences':1}]})
        def parse(value,count=3):
            raw=json.dumps(value).encode() if not isinstance(value,str) else value.encode()
            out=ctypes.POINTER(Recipe)()
            result=self.lib.delivery_reuse_recipe_parse(raw,len(raw),count,ctypes.byref(out))
            return result,out
        result,out=parse(recipe)
        try:
            self.assertEqual(result,1);self.assertEqual(out.contents.occurrences,3)
            self.assertEqual(out.contents.inputs.contents.name_count,1)
            self.assertEqual(out.contents.fragments.contents.provider,b'native-cart')
            self.assertEqual(out.contents.fragments.contents.next.contents.descriptor,recipe['fragments'][1]['descriptor'].encode())
        finally:self.lib.delivery_reuse_recipe_free(out)
        cases=[]
        for key in ('digest','inputs','fragments'):
            changed=copy.deepcopy(recipe);del changed[key];cases.append(changed)
        changed=copy.deepcopy(recipe);changed['fragments'][1]['descriptor']='b'*64;cases.append(changed)
        changed=copy.deepcopy(recipe);changed['fragments'][1]['url']=changed['fragments'][0]['url'];cases.append(changed)
        changed=copy.deepcopy(recipe);changed['fragments'][0]['url']='//outside.invalid/';cases.append(changed)
        changed=copy.deepcopy(recipe);changed['fragments'][0]['occurrences']=0;cases.append(changed)
        changed=copy.deepcopy(recipe);changed['fragments'][0]['occurrences']=2**64-1;cases.append(changed)
        changed=copy.deepcopy(recipe);changed['fragments'][0]['extra']=True;cases.append(changed)
        changed=copy.deepcopy(recipe);changed['extra']=True;cases.append(changed)
        changed=copy.deepcopy(recipe);changed['digest']='a'*64;cases.append(changed)
        changed=copy.deepcopy(recipe);changed['fragments'][0]['provider']='other-provider';cases.append(changed)
        cases.append(json.dumps(recipe).replace('"digest":','"digest":"'+('d'*64)+'","digest":',1))
        cases.append(json.dumps(recipe).replace('"provider":','"provider":"duplicate","provider":',1))
        for value in cases:
            with self.subTest(value=value):
                result,out=parse(value)
                try:self.assertEqual(result,0);self.assertFalse(out)
                finally:self.lib.delivery_reuse_recipe_free(out)
        result,out=parse(recipe,count=4)
        try:self.assertEqual(result,0);self.assertFalse(out)
        finally:self.lib.delivery_reuse_recipe_free(out)

    def test_canonical_recipe_vectors_and_native_digest_match_independent_frames(self):
        vectors=json.loads((ROOT/'tests/fixtures/private_reuse_recipe_v1.json').read_text(encoding='utf-8'))
        for row in vectors['vectors']:
            with self.subTest(name=row['name']):
                recipe=row['recipe'];frame=recipe_frame(recipe)
                self.assertEqual(frame.hex(),row['recipeFrameHex'])
                self.assertEqual(hashlib.sha256(frame).hexdigest(),recipe['digest'])
                for descriptor in recipe['fragments']:
                    output=ctypes.create_string_buffer(65)
                    self.assertEqual(self.lib.delivery_reuse_descriptor_digest(descriptor['url'].encode(),
                        descriptor['provider'].encode(),output),1)
                    self.assertEqual(output.value.decode(),descriptor_digest(descriptor['url'],descriptor['provider']))
                for candidate in (recipe,dict(recipe,fragments=list(reversed(recipe['fragments'])))):
                    raw=json.dumps(candidate).encode();out=ctypes.POINTER(Recipe)()
                    count=sum(d['occurrences'] for d in candidate['fragments'])
                    self.assertEqual(self.lib.delivery_reuse_recipe_parse(raw,len(raw),count,ctypes.byref(out)),1)
                    try:
                        digest=ctypes.create_string_buffer(65)
                        self.assertEqual(self.lib.delivery_reuse_recipe_digest(out,digest),1)
                        self.assertEqual(digest.value.decode(),recipe['digest'])
                    finally:self.lib.delivery_reuse_recipe_free(out)


for index,row in enumerate(VECTORS['vectors']):
    def vector_test(self,row=row):self.vector(row)
    setattr(ReuseCookieInputs,'test_php_vector_'+str(index).zfill(2)+'_'+row['name'].replace('-','_'),vector_test)

if __name__=='__main__':unittest.main()
