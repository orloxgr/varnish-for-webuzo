"""Actual native HSH/finalization/full-HIT actors, with a MOCK trusted producer.

These assert engine ownership and zero origin/prepare calls on a complete HIT.
They do NOT prove WordPress/provider identity, drain or cookie-work semantics.
"""
import base64
import copy
import hashlib
import hmac
import json
import os
import shutil
import time
import unittest
import test_reuse_authority as authority
from test_cookie_delivery import proxy,cookies
from test_delivery_continuation import BODY,META,PARENT,PRIVATE,ADAPTIVE,envelope
from test_reuse_delivery_context import all_origin_hooks,signed_context
from test_reuse_cookie_inputs import declaration,seal_recipe,lp
from test_private_fragment_ttl import exchange

KEY=hmac.digest(('b'*64).encode(),b'ultracache-delivery-reuse-key-v1','sha256')
OWNER=authority.TAG
BASE_FIELDS=('siteId','canonicalHost','scope','epoch','nativePolicy','wordpressPolicy','reusePolicy')

def owner_frame(value):
    return lp('ultracache-cookie-inputs-v1')+(1000).to_bytes(4,'big')+(1).to_bytes(4,'big')+lp('owner')+\
        (0).to_bytes(4,'big')+(1).to_bytes(4,'big')+lp('owner')+(1).to_bytes(4,'big')+lp('owner')+lp(value)
def identity_mac(context,value):
    return hmac.new(KEY,lp('ultracache-private-identity-binding-v1')+
        b''.join(lp(context[n]) for n in BASE_FIELDS)+lp(owner_frame(value)),'sha256').hexdigest()

@unittest.skipUnless(shutil.which('varnishd') and os.environ.get('SCP_EXPERIMENTAL_REUSE_TEST')=='1',
    'Explicit matching-source native module required')
class NativeFullReuse(unittest.TestCase):
    register=authority.NativeReuseAuthority.register
    observe=authority.NativeReuseAuthority.observe
    call=authority.NativeReuseAuthority.call
    recover=authority.NativeReuseAuthority.recover
    publish=authority.NativeReuseAuthority.publish
    def test_metadata_and_all_private_bodies_compose_without_any_origin_then_missing_body_refills(self):
        holder={};calls=[];prepared={};generation=[1];records=[];armed=[]
        nonce_tag=lambda owner:hashlib.sha256(('mock-nonce-owner-'+owner).encode()).hexdigest()
        recipe=seal_recipe(dict(inputs=declaration(['owner']),fragments=[
            dict(url=PRIVATE,provider='cart',occurrences=2),dict(url=ADAPTIVE,provider='nonce',occurrences=1)]))
        def cache_key(url,owner):return hashlib.sha256((url+'|'+owner+'|'+str(generation[0])).encode()).hexdigest()
        def origin(path,headers):
            phase=headers.get('X-UltraCache-Delivery-Phase');calls.append((path,phase))
            if phase=='prepare':
                signed=signed_context(self,headers,path,'GET')
                context=self.call(holder['get'],'delivery-reuse-context',tag=None,extra={
                    'X-UltraCache-Private-Request-Id':signed['requestId'],'X-UltraCache-Private-Challenge':signed['challenge'],
                    'X-UltraCache-Private-Epoch':signed['epoch'],'X-UltraCache-Private-Incarnation':signed['incarnation'],
                    'X-UltraCache-Delivery-Reuse-Recipe':recipe['digest']})
                owner=headers['Cookie'].split('owner=',1)[1].split(';',1)[0]
                body=json.loads(envelope(headers,owner+'-generation'+str(generation[0])))
                for f in body['renderedFragments']:f['cache']=dict(key=cache_key(f['url'],owner),ttl=120,tags='owner product:123')
                body['reuseCandidate']=dict(version=1,requestId=signed['requestId'],challenge=signed['challenge'],
                    recipe=recipe,inputEvidence=identity_mac(context,owner))
                prepared[signed['requestId']]=(copy.deepcopy(body),owner)
                return json.dumps(body),[('Cache-Control','private, no-store')]
            if phase=='reuse-finalize':
                self.assertEqual(path,PARENT);self.assertIsNone(headers.get('Cookie'))
                self.assertIsNone(headers.get('X-UltraCache-Mutation-Context'))
                context=json.loads(base64.b64decode(headers['X-UltraCache-Delivery-Reuse-Context'],validate=True))
                old,owner=prepared[context['requestId']]
                current=self.observe(holder['get'])
                self.call(holder['get'],'private-execution-drained',current,tag=None,extra={
                    'X-UltraCache-Private-Request-Id':context['requestId'],'X-UltraCache-Private-Challenge':context['challenge'],
                    'X-UltraCache-Private-Drained':'1'})
                self.recover(holder['get'],self.observe(holder['get']))
                owner_tag=OWNER if owner=='A' else hashlib.sha256(('mock-owner-'+owner).encode()).hexdigest()
                observed=self.call(holder['get'],'private-authority-context',tag=owner_tag)
                ack=self.call(holder['get'],'private-generation-publish',observed,tag=owner_tag,
                    extra={'X-UltraCache-Private-Generation':hashlib.sha256(str(generation[0]).encode()).hexdigest()})
                c=dict(context['context'],scopeRevision=ack['scopeRevision'])
                deadline=int(time.time())+100
                rows=[]
                for descriptor in recipe['fragments']:
                    f=next(row for row in old['renderedFragments'] if row['url']==descriptor['url'])
                    dependency=owner_tag
                    if descriptor['provider']=='nonce':
                        dependency=nonce_tag(owner)
                        nonce_context=self.call(holder['get'],'private-authority-context',tag=dependency)
                        dependency_ack=self.call(holder['get'],'private-generation-publish',nonce_context,tag=dependency,
                            extra={'X-UltraCache-Private-Generation':hashlib.sha256(str(generation[0]).encode()).hexdigest()})
                    else:dependency_ack=ack
                    rows.append(dict(descriptor=descriptor['descriptor'],url=descriptor['url'],cache=f['cache'],bodyValidUntil=deadline+10,
                        identity=dict(identityState='personal',identityInputs=recipe['inputs'],identityBinding=identity_mac(c,owner),
                            owner=dependency,tags=[dependency],validUntil=deadline+20),
                        authority=[dict(tag=dependency,revision=dependency_ack['revision'],generation=dependency_ack['generation'])]))
                record=dict(schemaVersion=1,requestId=context['deliveryRequestId'],originalUrl=path,
                    reuse=dict(version=1,context=c,recipe=recipe,admission=dict(binding=context['binding'],validUntil=deadline,
                        cookieWork=dict(state='none',validUntil=deadline+20),fragments=rows)))
                records.append(record)
                return json.dumps(record),[('Content-Type','application/vnd.ultracache.reuse+json'),('Cache-Control','private, no-store'),
                    ('X-UltraCache-Delivery-Reuse-Outcome','finalized'),('X-UltraCache-Delivery-Reuse-Fresh-Remaining','99')]
            if path=='/__owned_mutation-map':
                signed=signed_context(self,headers,path,'GET')
                state=self.call(holder['get'],'private-authority-context',tag=nonce_tag('A'))
                armed.append((signed,state))
            return (BODY,META) if path==PARENT else ('cold',[('Cache-Control','private, no-store')])
        with proxy('ultracache',origin,transform=all_origin_hooks) as get:
            holder['get']=get;get(PARENT);calls.clear();self.register(get)
            status,headers,body=get(PARENT,'owner=A; _fbp=first')
            self.assertEqual(status,200);self.assertIn('private:A-generation1',body)
            self.assertEqual(calls,[(PARENT,'prepare'),(PARENT,'reuse-finalize')])
            self.assertEqual(len(records),1)
            calls.clear()
            status,headers,body2=get(PARENT,'owner=A; _fbp=second')
            self.assertEqual((status,body2),(200,body));self.assertEqual(cookies(headers),[])
            self.assertEqual(calls,[],'A complete native HIT must invoke no origin, prepare or finalizer')
            self.assertEqual(exchange(get,'PURGE',PRIVATE,cache_key(PRIVATE,'A'),'b'*64)[0],200)
            self.assertEqual(get(PARENT,'owner=A')[0],200)
            self.assertEqual(calls,[(PARENT,'prepare'),(PARENT,'reuse-finalize')],
                'One missing required private object must use ordinary fill, never partial admission')
            calls.clear();self.assertEqual(get(PARENT,'owner=A')[0],200);self.assertEqual(calls,[])
            generation[0]=2
            # Real native tag revocation immediately closes the old admission.
            prior=self.observe(get)
            dirty=self.call(get,'private-mutation-begin',prior,extra={'X-UltraCache-Private-Transaction':'8'*64})
            self.call(get,'private-mutation-commit',dirty,extra={'X-UltraCache-Private-Transaction':dirty['transaction'],
                'X-UltraCache-Private-Lease':dirty['lease']})
            status,_,body3=get(PARENT,'owner=A')
            self.assertEqual(status,200);self.assertIn('private:A-generation2',body3)
            self.assertEqual(calls,[(PARENT,'prepare'),(PARENT,'reuse-finalize')])
            calls.clear()
            status,_,other=get(PARENT,'owner=B')
            self.assertEqual(status,200);self.assertIn('private:B-generation2',other)
            self.assertNotIn('private:A-',other)
            self.assertEqual(calls,[(PARENT,'prepare'),(PARENT,'reuse-finalize')])
            calls.clear();self.assertEqual(get(PARENT,'owner=B; _fbp=changed')[2],other)
            self.assertEqual(calls,[],'The second independently bound owner also uses native-only composed HIT')
            status,_,again=get(PARENT,'owner=A')
            self.assertEqual(status,200);self.assertIn('private:A-generation2',again);self.assertNotIn('private:B-',again)
            # Two provider owners share the same input binding. Both mappings
            # coexist; a later cross-route backend prearms the nonce owner too.
            old_nonce=self.call(get,'private-authority-context',tag=nonce_tag('A'))
            other_nonce=self.call(get,'private-authority-context',tag=nonce_tag('B'))
            self.assertEqual(get('/__owned_mutation-map','owner=A; _fbp=unrelated')[0],200)
            signed,state=armed[-1]
            self.assertNotEqual(state['revision'],old_nonce['revision'])
            self.assertEqual(self.call(get,'private-authority-context',tag=nonce_tag('B'))['revision'],other_nonce['revision'])
            self.assertEqual(self.call(get,'private-tag-retire',state,tag=nonce_tag('A'),expected_status=409)['reason'],'execution-unsettled')
            ended=self.call(get,'private-authority-context',tag=nonce_tag('A'))
            self.assertEqual(self.call(get,'private-tag-retire',ended,tag=nonce_tag('A'),expected_status=409)['reason'],'execution-unsettled',
                'Backend response/fini must not retire the execution fence')
            self.call(get,'private-execution-drained',ended,tag=None,extra={
                'X-UltraCache-Private-Request-Id':signed['requestId'],'X-UltraCache-Private-Challenge':signed['challenge'],
                'X-UltraCache-Private-Drained':'1'})
            self.assertEqual(self.call(get,'private-tag-retire',ended,tag=nonce_tag('A'))['reason'],'tag-retired')
            self.assertEqual(self.observe(get)['scopeState'],'unbound','Revoke maps never imply whole actor coverage or CLEAN')

if __name__=='__main__':unittest.main()
