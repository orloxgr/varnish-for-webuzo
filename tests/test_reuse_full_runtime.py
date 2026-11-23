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
import threading
import unittest
import test_reuse_authority as authority
from test_cookie_delivery import proxy,cookies
from test_delivery_continuation import BODY,META,PARENT,PRIVATE,ADAPTIVE,envelope
from test_reuse_delivery_context import all_origin_hooks,signed_context
from test_reuse_cookie_inputs import declaration,seal_recipe,lp
from test_private_fragment_ttl import exchange
import test_mutation_coverage_runtime as coverage

KEY=hmac.digest(('b'*64).encode(),b'ultracache-delivery-reuse-key-v1','sha256')
OWNER=authority.TAG
BASE_FIELDS=('siteId','canonicalHost','scope','epoch','nativePolicy','wordpressPolicy','reusePolicy')

def input_frame(inputs,value):
    names=sorted(inputs['cookieNames']);prefixes=sorted(inputs['cookiePrefixes'])
    # Absent declared WP selectors have no fabricated present group.
    present='owner' in names
    return (lp('ultracache-cookie-inputs-v1')+inputs['phpMaxInputVars'].to_bytes(4,'big')+
        len(names).to_bytes(4,'big')+b''.join(lp(name) for name in names)+
        len(prefixes).to_bytes(4,'big')+b''.join(lp(prefix) for prefix in prefixes)+
        int(present).to_bytes(4,'big')+
        (lp('owner')+(1).to_bytes(4,'big')+lp('owner')+lp(value) if present else b''))

def identity_mac(context,value,inputs=None):
    return hmac.new(KEY,lp('ultracache-private-identity-binding-v1')+
        b''.join(lp(context[n]) for n in BASE_FIELDS)+lp(input_frame(inputs or declaration(['owner']),value)),'sha256').hexdigest()

@unittest.skipUnless(shutil.which('varnishd') and os.environ.get('SCP_EXPERIMENTAL_REUSE_TEST')=='1',
    'Explicit matching-source native module required')
class NativeFullReuse(unittest.TestCase):
    register=authority.NativeReuseAuthority.register
    observe=authority.NativeReuseAuthority.observe
    call=authority.NativeReuseAuthority.call
    recover=authority.NativeReuseAuthority.recover
    publish=authority.NativeReuseAuthority.publish
    def test_metadata_and_all_private_bodies_compose_without_any_origin_then_missing_body_refills(self):
        self.run_full_actor()

    def test_mixed_personal_cart_and_anonymous_nonce_compose_without_origin_or_fake_owner_map(self):
        self.run_full_actor(anonymous_nonce=True)

    def test_scope_writer_suspends_complete_mixed_hit_until_drained_and_fresh_finalized(self):
        self.run_full_actor(anonymous_nonce=True,scope_fence=True)

    def test_covered_unchanged_interleaved_owners_and_all_formats_reuse_without_origin(self):
        self.run_full_actor(anonymous_nonce=True,covered=True)

    def run_full_actor(self,anonymous_nonce=False,scope_fence=False,covered=False):
        holder={};calls=[];prepared={};generation=[1];records=[];armed=[]
        held_entered=threading.Event();held_release=threading.Event();held_original=[]
        nonce_tag=lambda owner:hashlib.sha256(('mock-nonce-owner-'+owner).encode()).hexdigest()
        nonce_inputs=declaration(['wordpress_logged_in_mock']) if anonymous_nonce else declaration(['owner'])
        recipe=seal_recipe(dict(inputs=declaration(['owner','wordpress_logged_in_mock'] if anonymous_nonce else ['owner']),fragments=[
            dict(url=PRIVATE,provider='cart',occurrences=2),dict(url=ADAPTIVE,provider='nonce',occurrences=1)]))
        def cache_key(url,owner):
            identity='uid0' if anonymous_nonce and url==ADAPTIVE else owner
            return hashlib.sha256((url+'|'+identity+'|'+str(generation[0])).encode()).hexdigest()
        accepts=('text/html', 'text/html,image/webp', 'text/html,image/avif,image/webp')
        def read_context(headers,path):
            return coverage.context(self,headers,'GET',path) if covered else signed_context(self,headers,path,'GET')
        def origin(path,headers):
            phase=headers.get('X-UltraCache-Delivery-Phase');calls.append((path,phase))
            if phase=='prepare':
                signed=read_context(headers,path)
                context=self.call(holder['get'],'delivery-reuse-context',tag=None,extra={
                    'X-UltraCache-Private-Request-Id':signed['requestId'],'X-UltraCache-Private-Challenge':signed['challenge'],
                    'X-UltraCache-Private-Epoch':signed['epoch'],'X-UltraCache-Private-Incarnation':signed['incarnation'],
                    'X-UltraCache-Delivery-Reuse-Recipe':recipe['digest']})
                owner=headers['Cookie'].split('owner=',1)[1].split(';',1)[0]
                body=json.loads(envelope(headers,owner+'-generation'+str(generation[0])))
                for f in body['renderedFragments']:
                    f['cache']=dict(key=cache_key(f['url'],owner),ttl=120,tags='owner product:123')
                    if anonymous_nonce and f['url']==ADAPTIVE:f['html']='nonce:uid0-generation'+str(generation[0])
                body['reuseCandidate']=dict(version=1,requestId=signed['requestId'],challenge=signed['challenge'],
                    recipe=recipe,inputEvidence=identity_mac(context,owner,recipe['inputs']))
                prepared[signed['requestId']]=(copy.deepcopy(body),owner,signed)
                return json.dumps(body),[('Cache-Control','private, no-store')]+([coverage.response_receipt(signed)] if covered else [])
            if phase=='reuse-finalize':
                self.assertEqual(path,PARENT);self.assertIsNone(headers.get('Cookie'))
                self.assertIsNone(headers.get('X-UltraCache-Mutation-Context'))
                context=json.loads(base64.b64decode(headers['X-UltraCache-Delivery-Reuse-Context'],validate=True))
                old,owner,original=prepared[context['requestId']]
                current=self.observe(holder['get'])
                self.call(holder['get'],'private-execution-drained',current,tag=None,extra={
                    'X-UltraCache-Private-Request-Id':context['requestId'],'X-UltraCache-Private-Challenge':context['challenge'],
                    'X-UltraCache-Private-Drained':'1',**(coverage.completion_headers(original) if covered else {})})
                if self.observe(holder['get'])['scopeMutations'] or self.observe(holder['get']).get('temporaryHolds'):
                    return 204,'',[('Cache-Control','private, no-store')]
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
                    if descriptor['provider']=='nonce' and not anonymous_nonce:
                        dependency=nonce_tag(owner)
                        nonce_context=self.call(holder['get'],'private-authority-context',tag=dependency)
                        dependency_ack=self.call(holder['get'],'private-generation-publish',nonce_context,tag=dependency,
                            extra={'X-UltraCache-Private-Generation':hashlib.sha256(str(generation[0]).encode()).hexdigest()})
                    else:dependency_ack=ack
                    anonymous=anonymous_nonce and descriptor['provider']=='nonce'
                    inputs=nonce_inputs if descriptor['provider']=='nonce' else declaration(['owner'])
                    rows.append(dict(descriptor=descriptor['descriptor'],url=descriptor['url'],cache=f['cache'],bodyValidUntil=deadline+10,
                        identity=dict(identityState='anonymous' if anonymous else 'personal',identityInputs=inputs,
                            identityBinding=identity_mac(c,owner,inputs),owner=None if anonymous else dependency,
                            tags=[] if anonymous else [dependency],validUntil=deadline+20),
                        authority=[] if anonymous else [dict(tag=dependency,revision=dependency_ack['revision'],generation=dependency_ack['generation'])]))
                record=dict(schemaVersion=1,requestId=context['deliveryRequestId'],originalUrl=path,
                    reuse=dict(version=1,context=c,recipe=recipe,admission=dict(binding=context['binding'],validUntil=deadline,
                        cookieWork=dict(state='none',validUntil=deadline+20),fragments=rows)))
                records.append(record)
                return json.dumps(record),[('Content-Type','application/vnd.ultracache.reuse+json'),('Cache-Control','private, no-store'),
                    ('X-UltraCache-Delivery-Reuse-Outcome','finalized'),('X-UltraCache-Delivery-Reuse-Fresh-Remaining','99')]
            if path=='/__owned_mutation-held':
                signed=read_context(headers,path);held_original.append(signed);held_entered.set()
                self.assertTrue(held_release.wait(10))
                return 'held actual response',[('Cache-Control','private, no-store'),coverage.response_receipt(signed)]
            if path=='/__owned_mutation-map':
                signed=read_context(headers,path)
                state=self.call(holder['get'],'private-authority-context',tag=nonce_tag('A'))
                armed.append((signed,state))
            return (BODY,META+([('Vary','Accept')] if covered else [])) if path==PARENT else ('cold',[('Cache-Control','private, no-store')])
        with proxy('ultracache',origin,transform=all_origin_hooks) as get:
            holder['get']=get;get(PARENT)
            if covered:
                for accept in accepts:get(PARENT,extra={'Accept':accept})
                coverage.register(self,get)
            else:self.register(get)
            calls.clear()
            status,headers,body=get(PARENT,'owner=A; _fbp=first')
            self.assertEqual(status,200);self.assertIn('private:A-generation1',body)
            self.assertEqual(calls,[(PARENT,'prepare'),(PARENT,'reuse-finalize')])
            self.assertEqual(len(records),1)
            calls.clear()
            status,headers,body2=get(PARENT,'owner=A; _fbp=second')
            self.assertEqual((status,body2),(200,body));self.assertEqual(cookies(headers),[])
            self.assertEqual(calls,[],'A complete native HIT must invoke no origin, prepare or finalizer')
            if scope_fence:
                current=self.observe(get)
                writer=self.call(get,'private-scope-mutation-begin',current,tag=None,
                    extra={'X-UltraCache-Private-Transaction':'7'*64})
                status,_,fresh=get(PARENT,'owner=A')
                self.assertEqual(status,200);self.assertIn('private:A-generation1',fresh)
                self.assertEqual(calls,[(PARENT,'prepare'),(PARENT,'reuse-finalize')],
                    'A retained scope writer must suspend otherwise-complete native admission')
                self.assertEqual(self.observe(get)['scopeState'],'unbound')
                done=self.call(get,'private-scope-mutation-commit',writer,tag=None,extra={
                    'X-UltraCache-Private-Transaction':writer['transaction'],
                    'X-UltraCache-Private-Lease':writer['lease'],'X-UltraCache-Private-Drained':'1'})
                self.call(get,'private-scope-mutation-ack',done,tag=None,extra={
                    'X-UltraCache-Private-Transaction':done['transaction'],'X-UltraCache-Private-Lease':done['lease']})
                calls.clear();self.assertEqual(get(PARENT,'owner=A')[0],200)
                self.assertEqual(calls,[(PARENT,'prepare'),(PARENT,'reuse-finalize')])
                calls.clear();self.assertEqual(get(PARENT,'owner=A')[0],200);self.assertEqual(calls,[])
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
            if covered:
                self.assertEqual(calls,[],'Filling B must preserve A admission without rebasing its authority')
                stable=self.observe(get)['scopeRevision']
                for owner in ('A','B'):
                    for accept in accepts:
                        get(PARENT,'owner='+owner,{'Accept':accept})
                        calls.clear()
                        status,_,html=get(PARENT,'owner='+owner,{'Accept':accept})
                        self.assertEqual(status,200);self.assertIn('private:'+owner+'-generation2',html)
                        self.assertEqual(calls,[],'Second request per owner/format must use complete native HIT')
                self.assertEqual(self.observe(get)['scopeRevision'],stable)
                for _ in range(2):
                    for accept in accepts:
                        for owner in ('A','B'):
                            status,_,html=get(PARENT,'owner='+owner+'; _fbp=interleaved',{'Accept':accept})
                            self.assertEqual(status,200);self.assertIn('private:'+owner+'-generation2',html)
                self.assertEqual(calls,[],'All 12 interleaved owner/format requests must be origin-free')
                self.assertEqual(self.observe(get)['scopeRevision'],stable)
                errors=[]
                def hold_request():
                    try:get('/__owned_mutation-held','owner=A')
                    except BaseException as error:errors.append(error)
                worker=threading.Thread(target=hold_request);worker.start()
                try:
                    self.assertTrue(held_entered.wait(10))
                    self.assertEqual(self.observe(get)['temporaryHolds'],1)
                    calls.clear()
                    status,_,during=get(PARENT,'owner=B',{'Accept':accepts[0]})
                    self.assertEqual(status,200);self.assertIn('private:B-generation2',during)
                    self.assertEqual(calls,[(PARENT,'prepare'),(PARENT,'reuse-finalize')])
                    self.assertEqual(self.observe(get)['temporaryHolds'],1,
                        'Reader completion must not clear another still-live hold')
                finally:held_release.set();worker.join(timeout=15)
                self.assertEqual(errors,[]);self.assertFalse(worker.is_alive())
                coverage.NativeCoverageHolds.ended(self,get)
                original=held_original[0]
                self.call(get,'private-execution-drained',self.observe(get),tag=None,extra={
                    'X-UltraCache-Private-Request-Id':original['requestId'],
                    'X-UltraCache-Private-Challenge':original['challenge'],'X-UltraCache-Private-Drained':'1',
                    **coverage.completion_headers(original)})
                self.assertEqual(self.observe(get)['scopeRevision'],stable)
                calls.clear()
                for accept in accepts:
                    for owner in ('A','B'):
                        self.assertEqual(get(PARENT,'owner='+owner,{'Accept':accept})[0],200)
                self.assertEqual(calls,[],
                    'Quiescent reader/writer holds must resume all existing admissions without a global refill storm')
            if anonymous_nonce:
                self.assertIn('nonce:uid0-generation2',other)
                self.assertIn('nonce:uid0-generation2',again)
                # This observation-only probe is not an anonymous owner map.
                probe=self.call(get,'private-authority-context',tag=nonce_tag('A'))
                personal=self.observe(get)
                self.assertEqual(get('/__owned_mutation-map','owner=A; _fbp=unrelated')[0],200)
                if covered:self.assertNotEqual(self.observe(get)['scopeRevision'],personal['scopeRevision'])
                else:self.assertNotEqual(self.observe(get)['revision'],personal['revision'])
                self.assertEqual(self.call(get,'private-authority-context',tag=nonce_tag('A'))['revision'],probe['revision'])
                self.assertEqual(self.observe(get)['scopeState'],'unbound')
                return
            # Two PERSONAL provider owners share the same input binding. Both
            # mappings coexist; a cross-route backend prearms the nonce too.
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
