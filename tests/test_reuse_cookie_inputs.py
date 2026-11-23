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
        cls.lib.delivery_reuse_recipe_parse.argtypes=[ctypes.c_char_p,ctypes.c_size_t,ctypes.c_uint64,
            ctypes.POINTER(ctypes.POINTER(Recipe))]
        cls.lib.delivery_reuse_recipe_free.argtypes=[ctypes.POINTER(Recipe)]
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
        recipe={'digest':'a'*64,'inputs':declaration(['owned_input','owned_input'],['new_']),
            'fragments':[{'descriptor':'b'*64,'url':'/shop/?ultracache_esi=first','provider':'native-cart','occurrences':2},
                         {'descriptor':'c'*64,'url':'/shop/?ultracache_esi=second','provider':'nonce','occurrences':1}]}
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
            self.assertEqual(out.contents.fragments.contents.next.contents.descriptor,b'c'*64)
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


for index,row in enumerate(VECTORS['vectors']):
    def vector_test(self,row=row):self.vector(row)
    setattr(ReuseCookieInputs,'test_php_vector_'+str(index).zfill(2)+'_'+row['name'].replace('-','_'),vector_test)

if __name__=='__main__':unittest.main()
