"""Actual native owner/context joins; mock producer, no admission permission."""
import base64
import hashlib
import hmac
import json
import os
import shutil
import unittest

from test_cookie_delivery import proxy
from test_public_selection_runtime import control
from test_mutation_backend import actor_hooks,post,receipt,KEY
from test_mutation_wire import request_frame
from test_delivery_continuation import BODY,META,PARENT,MANIFEST,envelope
import test_reuse_authority as authority
from test_cold_public_selection import Application,choices

RECIPE=json.loads((__import__('pathlib').Path(__file__).parent/'fixtures/private_reuse_recipe_v1.json').read_text())['vectors'][1]['recipe']['digest']


def all_origin_hooks(source):
    return actor_hooks(source).replace('bereq.url ~ "/__owned_mutation"','bereq.method == "GET" || bereq.method == "POST"',1)


def canonical_origin_hooks(source):
    """Owned Lab vhost only: native canonical host vs actual origin home port."""
    source=all_origin_hooks(source)
    needle='call scp_backend_fetch; }'
    if source.count(needle)!=1:raise AssertionError('Expected one owned backend dispatch')
    source=source.replace(needle,'call scp_backend_fetch; set bereq.http.host = "127.0.0.1:38751"; }',1)
    return source.replace('set beresp.http.X-Cache-Object-Host = bereq.http.host;',
        'set beresp.http.X-Cache-Object-Host = regsub(bereq.http.host, ":[0-9]+$", "");',1)

def exact_authority_origin_hooks(source):
    """Strict owned Lab routing only; production panel hostname policy unchanged."""
    source=all_origin_hooks(source)
    normal='set req.http.host = std.tolower(regsub(req.http.host, ":[0-9]+$", ""));'
    if source.count(normal)!=1:raise AssertionError('Expected one production host normalization')
    source=source.replace(normal,'set req.http.host = std.tolower(req.http.host);',1)
    target='set req.http.X-WV-Ban-Host = regsub(regsub(req.http.X-WV-Ban-Host, ":[0-9]+$", ""), "[.]$", "");'
    if source.count(target)!=1:raise AssertionError('Expected one production invalidation host binding')
    source=source.replace(target,'set req.http.X-WV-Ban-Host = regsub(req.http.X-WV-Ban-Host, "[.]$", "");',1)
    if 'req.http.host == "127.0.0.1"' not in source:raise AssertionError('Expected explicit owned Lab site')
    return source.replace('req.http.host == "127.0.0.1"','req.http.host == "127.0.0.1:38751"')


def signed_context(test,headers,path,method):
    value=headers.get('X-UltraCache-Mutation-Context')
    test.assertTrue(value)
    context=json.loads(base64.b64decode(value,validate=True))
    test.assertEqual(context['proof'],hmac.new(KEY,request_frame(dict(context,method=method,url=path)),hashlib.sha256).hexdigest())
    return context


@unittest.skipUnless(shutil.which('varnishd') and os.environ.get('SCP_EXPERIMENTAL_REUSE_TEST')=='1',
                     'Explicit matching-source experimental native module required')
class NativeDeliveryReuseContext(unittest.TestCase):
    register=authority.NativeReuseAuthority.register
    call=authority.NativeReuseAuthority.call
    observe=authority.NativeReuseAuthority.observe

    def context(self,get,context,*,delivery_id=None,original=None,recipe=RECIPE,status=200,extra=None,scope='/'):
        headers={'X-UltraCache-Private-Request-Id':context['requestId'],
            'X-UltraCache-Private-Challenge':context['challenge'],'X-UltraCache-Delivery-Reuse-Recipe':recipe,
            'X-UltraCache-Private-Epoch':context['epoch'],'X-UltraCache-Private-Incarnation':context['incarnation']}
        if delivery_id is not None:headers['X-UltraCache-Delivery-Request']=delivery_id
        if original is not None:headers['X-UltraCache-Delivery-Original-URL']=original
        headers.update(extra or {})
        return self.call(get,'delivery-reuse-context',scope=scope,tag=None,extra=headers,expected_status=status)

    def test_live_backend_provisional_base_is_exact_and_never_guesses_a_parent(self):
        holder={};seen=[]
        def origin(path,headers):
            signed=signed_context(self,headers,path,'POST');seen.append(signed)
            context=self.context(holder['get'],signed)
            self.assertEqual(context['contextState'],'unqualified')
            self.assertEqual(context['parentIdentitySource'],'none')
            self.assertTrue(context['provisional'])
            self.assertEqual(context['recipeDigest'],RECIPE)
            self.assertNotIn('publicationDigest',context);self.assertNotIn('representation',context)
            self.assertNotIn('deliveryRequestId',context)
            self.assertEqual((context['requestId'],context['challenge']),(signed['requestId'],signed['challenge']))
            self.assertEqual(self.context(holder['get'],signed),context,'Same owned proposal retry is idempotent')
            self.context(holder['get'],signed,recipe='0'*64,status=409)
            self.context(holder['get'],signed,recipe='short',status=400)
            self.context(holder['get'],signed,status=409,extra={'X-UltraCache-Private-Challenge':'0'*64})
            self.context(holder['get'],signed,status=409,extra={'X-UltraCache-Private-Epoch':'0'*64})
            self.context(holder['get'],signed,delivery_id='made-up-owner',status=409)
            return 'actual response',[('Cache-Control','private, no-store'),
                ('X-UltraCache-Mutation-Receipt',receipt(signed,'none',()))]
        with proxy('ultracache',origin,transform=actor_hooks,allow_post=True) as get:
            holder['get']=get;self.register(get)
            self.assertEqual(post(get)[0],200)
            self.context(get,seen[0],status=409)
            self.assertEqual(self.observe(get)['scopeState'],'unbound')

    def test_hot_parent_provenance_uses_the_actual_selected_object_not_caller_headers(self):
        holder={};seen=[]
        def origin(path,headers):
            signed=signed_context(self,headers,path,'GET') if headers.get('X-UltraCache-Mutation-Context') else None
            if headers.get('X-UltraCache-Delivery-Phase')=='prepare':
                self.assertIsNotNone(signed)
                context=self.context(holder['get'],signed,delivery_id=headers['X-UltraCache-Delivery-Request'],
                    original=headers['X-UltraCache-Delivery-Original-URL'])
                self.assertEqual(context['contextState'],'parent-bound');self.assertTrue(context['provisional'])
                self.assertEqual(context['parentIdentitySource'],'native-selected-parent')
                self.assertEqual(context['publicationDigest'],hashlib.sha256(MANIFEST.encode()).hexdigest())
                self.assertRegex(context['representation'],r'\A[0-9a-f]{64}\Z')
                self.context(holder['get'],signed,delivery_id='999999999',status=409)
                self.context(holder['get'],signed,original='/wrong-route',status=409)
                seen.append(context)
                return envelope(headers,'actual-owner'),[('Cache-Control','private, no-store'),
                    ('X-UltraCache-Mutation-Receipt',receipt(signed,'none',()))]
            if path==PARENT:
                return BODY,META+[('Vary','Accept')]+([('X-UltraCache-Mutation-Receipt',receipt(signed,'none',()))] if signed else [])
            return 'ordinary child',[('Cache-Control','private, no-store')]+(
                [('X-UltraCache-Mutation-Receipt',receipt(signed,'none',()))] if signed else [])
        with proxy('ultracache',origin,transform=all_origin_hooks) as get:
            holder['get']=get
            self.assertEqual(get(PARENT)[0],200)
            self.assertEqual(get(PARENT,extra={'Accept':'text/html'})[0],200)
            self.register(get)
            self.assertEqual(get(PARENT,'_fbp=A')[0],200)
            self.assertEqual(len(seen),1)
            get(PARENT,'_fbp=B')
            self.assertEqual(seen[0]['representation'],seen[1]['representation'],'Shared cookie does not invent a representation split')
            self.assertEqual(get(PARENT,'_fbp=C',{'Accept':'text/html'})[0],200)
            self.assertNotEqual(seen[0]['representation'],seen[2]['representation'],'Actual native Vary is part of the selected representation')

    def test_cold_public_selection_exposes_only_real_seven_field_provenance(self):
        holder={};seen=[];application=Application(private=True)
        def origin(path,headers):
            signed=signed_context(self,headers,path,'GET')
            if headers.get('X-UltraCache-Delivery-Phase')=='public-select':
                context=self.context(holder['get'],signed,delivery_id=headers['X-UltraCache-Delivery-Request'],original=path)
                self.assertEqual(context['contextState'],'unqualified')
                self.assertNotIn('publicationDigest',context);self.assertNotIn('representation',context)
                seen.append(context)
            body,fields=application(path,headers)
            return body,fields+[('X-UltraCache-Mutation-Receipt',receipt(signed,'none',()))]
        config={'cookie_policies':choices(('cmp_group','variant'))}
        with proxy('ultracache',origin,configuration=config,transform=all_origin_hooks) as get:
            holder['get']=get
            status,_,_=control(get,enabled=True,names='cmp_group',extra={
                'X-UltraCache-Public-Selection-Reuse-Version':'1','X-UltraCache-Public-Selection-Reuse-Policy':'c'*64})
            self.assertEqual(status,200)
            self.assertEqual(get('/cold-context','cmp_group=A')[0],200)
            self.assertEqual(len(seen),1)
            self.assertEqual(seen[0]['scopeState'],'unbound')

    def test_separate_canonical_lab_vhost_preserves_origin_home_without_changing_native_identity(self):
        holder={};seen=[]
        def origin(path,headers):
            self.assertEqual(headers['Host'],'127.0.0.1:38751')
            self.assertEqual(headers['X-Forwarded-Proto'],'http')
            signed=signed_context(self,headers,path,'GET') if headers.get('X-UltraCache-Mutation-Context') else None
            if signed:self.assertEqual(signed['canonicalHost'],'127.0.0.1')
            if headers.get('X-UltraCache-Delivery-Phase')=='prepare':
                context=self.context(holder['get'],signed,delivery_id=headers['X-UltraCache-Delivery-Request'],original=path)
                self.assertEqual(context['canonicalHost'],'127.0.0.1')
                self.assertEqual(context['contextState'],'parent-bound')
                seen.append(context)
                return envelope(headers,'canonical-owner'),[('Cache-Control','private, no-store'),
                    ('X-UltraCache-Mutation-Receipt',receipt(signed,'none',()))]
            fields=[('X-UltraCache-Mutation-Receipt',receipt(signed,'none',()))] if signed else []
            return (BODY,META+fields) if path==PARENT else ('ordinary child',[('Cache-Control','private, no-store'),*fields])
        settings={'domain':'127.0.0.1','names':['127.0.0.1']}
        with proxy('ultracache',origin,transform=canonical_origin_hooks,site_settings=settings) as original:
            def get(path,cookie=None,extra=None):
                headers={'Host':'127.0.0.1:38751','X-Forwarded-Proto':'http'};headers.update(extra or {})
                return original(path,cookie,headers)
            get.endpoint=original.endpoint
            get.request_headers=dict(original.request_headers,Host='127.0.0.1:38751',**{'X-Forwarded-Proto':'http'})
            holder['get']=get
            self.assertEqual(get(PARENT)[0],200)
            self.register(get)
            status,_,body=get(PARENT,'_fbp=canonical')
            self.assertEqual(status,200)
            self.assertIn('private:canonical-owner',body)
            self.assertEqual(len(seen),1)

    def test_exact_lab_authority_matches_actual_home_without_site_origin_override(self):
        holder={};seen=[]
        def origin(path,headers):
            self.assertEqual(headers['Host'],'127.0.0.1:38751')
            self.assertEqual(headers['X-Forwarded-Proto'],'http')
            if headers.get('X-UltraCache-Delivery-Phase')=='prepare':
                signed=signed_context(self,headers,path,'GET')
                self.assertEqual(signed['canonicalHost'],'127.0.0.1:38751')
                context=self.context(holder['get'],signed,delivery_id=headers['X-UltraCache-Delivery-Request'],original=path)
                self.assertEqual(context['canonicalHost'],'127.0.0.1:38751');seen.append(context)
                return envelope(headers,'actual-authority'),[('Cache-Control','private, no-store')]
            return (BODY,META) if path==PARENT else ('ordinary',[('Cache-Control','private, no-store')])
        settings={'domain':'127.0.0.1','names':['127.0.0.1']}
        with proxy('ultracache',origin,transform=exact_authority_origin_hooks,site_settings=settings) as original:
            def get(path,cookie=None,extra=None):
                headers={'Host':'127.0.0.1:38751','X-Forwarded-Proto':'http'};headers.update(extra or {})
                return original(path,cookie,headers)
            get.endpoint=original.endpoint
            get.request_headers=dict(original.request_headers,Host='127.0.0.1:38751',**{'X-Forwarded-Proto':'http'})
            holder['get']=get;get(PARENT);self.register(get)
            status,_,body=get(PARENT,'_fbp=actual-authority')
            self.assertEqual(status,200);self.assertIn('private:actual-authority',body);self.assertEqual(len(seen),1)
            # The same strict test-only authority applies to the real warmup
            # invalidation transport. Another target port/host remains denied.
            for host,expected in (('127.0.0.1:38751',200),('127.0.0.1:38752',403),('other.test',403)):
                for operation,selector in (('exact-ban','obj.http.X-Cache-Object-URL ~ "^/warm$"'),
                    ('html-ban','obj.http.Content-Type ~ "^text/html"')):
                    reply=control(get,operation,extra={'X-UltraCache-Object-Expression':
                        'obj.http.X-Cache-Object-Host == "'+host+'" && '+selector})
                    self.assertEqual(reply[0],expected,(operation,host,reply))
            self.assertEqual(control(get,'exact-purge',path='/warm')[0],200)


if __name__=='__main__':unittest.main()
