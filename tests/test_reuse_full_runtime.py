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
import subprocess
import re
import test_reuse_authority as authority
from test_cookie_delivery import proxy,cookies
from test_delivery_continuation import BODY,META,PARENT,PRIVATE,ADAPTIVE,envelope
from test_reuse_delivery_context import all_origin_hooks,signed_context
from test_reuse_cookie_inputs import declaration,seal_recipe,lp
from test_private_fragment_ttl import exchange
from test_mutation_backend import receipt
from test_public_selection_runtime import control as native_control

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
    publish=authority.NativeReuseAuthority.publish
    def test_metadata_and_all_private_bodies_compose_without_any_origin_then_missing_body_refills(self):
        self.run_full_actor()

    def test_ack_only_preserves_an_already_complete_native_cached_plan(self):
        # ACK changes control CAS only, preserving complete content authority.
        from test_event_invalidation_runtime import NativeEventInvalidation
        actor = NativeEventInvalidation()
        with actor.actor() as (get, calls, _, bodies, _, _, _):
            begun = actor.begin(get, actor.observe(get), 'ack-only-completed-event')
            done = actor.commit(get, begun)
            calls.clear()
            self.assertEqual(get(PARENT, 'owner=A')[2], bodies['A'])
            self.assertEqual(calls, [(PARENT, 'prepare'), (PARENT, 'reuse-finalize')])
            calls.clear()
            self.assertEqual(get(PARENT, 'owner=A')[2], bodies['A']); self.assertEqual(calls, [])
            clean = actor.observe(get)
            acknowledged = actor.call(get, 'private-mutation-ack', clean, extra={
                'X-UltraCache-Private-Transaction': done['transaction'],
                'X-UltraCache-Private-Lease': done['lease']})
            self.assertNotEqual(acknowledged['revision'], clean['revision'])
            self.assertEqual((acknowledged['state'], acknowledged['generation']),
                (clean['state'], clean['generation']))
            self.assertEqual(acknowledged['contentRevision'], clean['contentRevision'])
            calls.clear()
            self.assertEqual(get(PARENT, 'owner=A')[2], bodies['A'])
            self.assertEqual(calls, [], 'ACK-only CAS cleanup must preserve the already complete native HIT')

    def test_ack_fences_delayed_begin_and_real_write_still_invalidates_content(self):
        from test_event_invalidation_runtime import NativeEventInvalidation
        actor = NativeEventInvalidation()
        with actor.actor() as (get, calls, versions, bodies, _, _, _):
            original = actor.observe(get)
            begun = actor.begin(get, original, 'real-write-then-ack')
            self.assertNotEqual(begun['revision'], original['revision'])
            self.assertNotEqual(begun['contentRevision'], original['contentRevision'])
            calls.clear(); self.assertEqual(get(PARENT, 'owner=B')[2], bodies['B']); self.assertEqual(calls, [])
            versions['A'] = 2
            done = actor.commit(get, begun)
            self.assertNotEqual(done['revision'], begun['revision'])
            self.assertNotEqual(done['contentRevision'], begun['contentRevision'])
            calls.clear(); status, _, updated = get(PARENT, 'owner=A')
            self.assertEqual(status, 200); self.assertIn('private:A-v2', updated)
            self.assertEqual(calls, [(PARENT, 'prepare'), (PARENT, 'reuse-finalize')])
            clean = actor.observe(get)
            self.assertEqual(clean['contentRevision'], done['contentRevision'])
            retry = actor.call(get, 'private-mutation-begin', clean, extra={
                'X-UltraCache-Private-Transaction': done['transaction']})
            self.assertFalse(retry['active'])
            acknowledged = actor.call(get, 'private-mutation-ack', clean, extra={
                'X-UltraCache-Private-Transaction': done['transaction'],
                'X-UltraCache-Private-Lease': done['lease']})
            self.assertNotEqual(acknowledged['revision'], retry['revision'])
            self.assertEqual(acknowledged['contentRevision'], done['contentRevision'])
            delayed = actor.call(get, 'private-mutation-begin', retry, expected_status=409, extra={
                'X-UltraCache-Private-Transaction': done['transaction']})
            self.assertEqual(delayed['reason'], 'revision-changed')
            self.assertEqual(actor.observe(get)['remainingMutations'], 0)
            calls.clear(); self.assertEqual(get(PARENT, 'owner=A')[2], updated); self.assertEqual(calls, [])
            self.assertEqual(get(PARENT, 'owner=B')[2], bodies['B']); self.assertEqual(calls, [])

    def test_mixed_personal_cart_and_anonymous_nonce_compose_without_origin_or_fake_owner_map(self):
        self.run_full_actor(anonymous_nonce=True)


    def test_unified_html_reuses_across_image_accepts_without_origin_or_owner_mixing(self):
        self.run_full_actor(anonymous_nonce=True,unified_html=True)

    def test_interleaved_owners_and_all_formats_reuse_without_origin(self):
        self.run_full_actor(anonymous_nonce=True,formats=True)


    def test_projected_resolver_registration_does_not_intercept_a_complete_native_hit(self):
        self.run_full_actor(projected=True)

    def test_anonymous_mutable_content_reuses_and_never_installs_a_visitor_revoke_map(self):
        self.run_full_actor(anonymous_nonce=True,anonymous_content=True,formats=True)

    def test_anonymous_content_dirty_authority_refuses_reuse_without_a_fake_owner(self):
        self.run_full_actor(anonymous_nonce=True,anonymous_content=True,content_failure='dirty')

    def test_anonymous_content_wrong_revision_refuses_admission(self):
        self.run_full_actor(anonymous_nonce=True,anonymous_content=True,content_failure='revision')

    def test_anonymous_content_wrong_generation_refuses_admission(self):
        self.run_full_actor(anonymous_nonce=True,anonymous_content=True,content_failure='generation')

    def test_later_absolute_deadline_is_capped_by_native_grants_without_another_approval_fetch(self):
        self.run_full_actor(anonymous_nonce=True,formats=True,ahead_absolute=True)

    def test_actual_native_body_expiry_still_requires_fresh_original_work(self):
        self.run_full_actor(anonymous_nonce=True,ahead_absolute=True,body_budget=2,verify_budget_expiry=True)

    def test_expired_natural_deadline_is_never_resurrected_by_native_budget_binding(self):
        self.run_full_actor(anonymous_nonce=True,anonymous_content=True,content_failure='natural-expired')

    def test_native_budget_binding_never_accepts_different_original_body_keys_or_tags(self):
        for field in ('cache-key','cache-tags'):
            with self.subTest(field=field):
                self.run_full_actor(anonymous_nonce=True,anonymous_content=True,content_failure=field)

    def test_value_free_reuse_stage_diagnostics_identify_actual_cold_metadata_and_complete_hits(self):
        self.run_full_actor(anonymous_nonce=True,diagnostic_only=True)

    def test_reuse_stage_diagnostics_are_masked_by_default_without_changing_cached_delivery(self):
        self.run_full_actor(anonymous_nonce=True,diagnostic_only=False)

    def test_known_pending_finalizer_retries_same_original_then_complete_hit_has_zero_origin(self):
        self.run_full_actor(anonymous_nonce=True,pending_case='settled')

    def test_pending_finalizer_exhaustion_preserves_original_without_publishing_metadata(self):
        self.run_full_actor(anonymous_nonce=True,pending_case='exhausted')

    def test_declined_finalizer_is_terminal_without_retry_or_admission(self):
        self.run_full_actor(anonymous_nonce=True,pending_case='declined')

    def test_pending_finalizer_with_cookie_is_terminal_without_cookie_replay(self):
        self.run_full_actor(anonymous_nonce=True,pending_case='cookie')

    def test_pending_finalizer_cannot_retry_past_actual_fragment_deadline(self):
        self.run_full_actor(anonymous_nonce=True,pending_case='expired',body_budget=1)

    def test_complete_plan_direct_reads_promote_private_bodies_and_metadata_in_native_lru(self):
        self.run_full_actor(anonymous_nonce=True,lru_case='moves')

    def test_hot_complete_plan_survives_cold_pressure_in_unchanged_native_cache(self):
        self.run_full_actor(anonymous_nonce=True,lru_case='pressure')

    def run_full_actor(self,anonymous_nonce=False,formats=False,projected=False,
                       anonymous_content=False,content_failure=None,ahead_absolute=False,body_budget=120,verify_budget_expiry=False,
                       diagnostic_only=None,pending_case=None,lru_case=None,unified_html=False):
        holder={};calls=[];prepared={};prepared_accepts={};generation=[1];records=[];armed=[]
        finalize_attempts={};finalize_headers={}
        cold_calls=[]
        nonce_tag=lambda owner:hashlib.sha256(('mock-nonce-owner-'+owner).encode()).hexdigest()
        content_tag=hashlib.sha256(b'mock-public-comments-content').hexdigest()
        nonce_inputs=declaration(['wordpress_logged_in_mock']) if anonymous_nonce else declaration(['owner'])
        recipe=seal_recipe(dict(inputs=declaration(['owner','wordpress_logged_in_mock'] if anonymous_nonce else ['owner']),fragments=[
            dict(url=PRIVATE,provider='cart',occurrences=2),dict(url=ADAPTIVE,provider='nonce',occurrences=1)]))
        def cache_key(url,owner):
            identity='uid0' if anonymous_nonce and url==ADAPTIVE else owner
            return hashlib.sha256((url+'|'+identity+'|'+str(generation[0])).encode()).hexdigest()
        accepts=('text/html', 'text/html,image/webp', 'text/html,image/avif,image/webp')
        def read_context(headers,path):
            return signed_context(self,headers,path,'GET')
        def origin(path,headers):
            if lru_case and path.startswith('/__owned_lru/'):
                # Ordinary Basic-site bytes share the fixture's unchanged
                # malloc16MB storage, without creating a private mutation owner.
                self.assertEqual(headers.get('Host'),'other.test')
                cold_calls.append(path)
                return b'x'*(512*1024),[('Content-Type','application/octet-stream'),('Cache-Control','public, max-age=120')]
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
                    f['cache']=dict(key=cache_key(f['url'],owner),ttl=body_budget,tags='owner product:123')
                    if anonymous_nonce and f['url']==ADAPTIVE:f['html']='nonce:uid0-generation'+str(generation[0])
                body['reuseCandidate']=dict(version=1,requestId=signed['requestId'],challenge=signed['challenge'],
                    recipe=recipe,inputEvidence=identity_mac(context,owner,recipe['inputs']))
                prepared[signed['requestId']]=(copy.deepcopy(body),owner,signed,context['scopeRevision'])
                prepared_accepts[signed['requestId']]=headers.get('Accept','')
                return json.dumps(body),[('Cache-Control','private, no-store'),('X-UltraCache-Mutation-Receipt',receipt(signed,'none',()))]
            if phase=='reuse-finalize':
                self.assertEqual(path,PARENT);self.assertIsNone(headers.get('Cookie'))
                self.assertIsNone(headers.get('X-UltraCache-Mutation-Context'))
                context=json.loads(base64.b64decode(headers['X-UltraCache-Delivery-Reuse-Context'],validate=True))
                original_id=context['requestId']
                exact=headers['X-UltraCache-Delivery-Reuse-Context']
                if original_id in finalize_headers:
                    self.assertEqual(exact,finalize_headers[original_id],
                        'A pending observer must retry the exact original signed finalization')
                finalize_headers[original_id]=exact
                finalize_attempts[original_id]=finalize_attempts.get(original_id,0)+1
                if pending_case and (pending_case!='settled' or finalize_attempts[original_id]<=2):
                    if pending_case=='expired':time.sleep(1.1)
                    diagnostic=[('Cache-Control','private, no-store'),
                        ('X-UltraCache-Delivery-Reuse-Outcome','declined' if pending_case=='declined' else 'pending')]
                    if pending_case=='cookie':diagnostic.append(('Set-Cookie','invalid-observer=never; HttpOnly; Path=/'))
                    return 204,'',diagnostic
                old,owner,original,source_namespace=prepared[context['requestId']]
                current=self.observe(holder['get'])
                if content_failure=='dirty' and holder.get('content_dirty'):
                    return 204,'',[('Cache-Control','private, no-store')]
                owner_tag=OWNER if owner=='A' else hashlib.sha256(('mock-owner-'+owner).encode()).hexdigest()
                observed=self.call(holder['get'],'private-authority-context',tag=owner_tag)
                ack=self.call(holder['get'],'private-generation-publish',observed,tag=owner_tag,
                    extra={'X-UltraCache-Private-Generation':hashlib.sha256(str(generation[0]).encode()).hexdigest()})
                self.assertEqual(ack['scopeRevision'],source_namespace,
                    'Finalization must retain the actual source policy namespace')
                c=dict(context['context'],scopeRevision=ack['scopeRevision'])
                deadline=int(time.time())+(5 if holder.get('arm_natural_deadline') else 100)
                if owner=='B' and prepared_accepts[context['requestId']]=='text/html':holder['natural_until']=deadline
                rows=[]
                for descriptor in recipe['fragments']:
                    f=next(row for row in old['renderedFragments'] if row['url']==descriptor['url'])
                    dependency=owner_tag
                    if descriptor['provider']=='nonce' and (not anonymous_nonce or anonymous_content):
                        dependency=content_tag if anonymous_content else nonce_tag(owner)
                        nonce_context=self.call(holder['get'],'private-authority-context',tag=dependency)
                        dependency_ack=self.call(holder['get'],'private-generation-publish',nonce_context,tag=dependency,
                            extra={'X-UltraCache-Private-Generation':hashlib.sha256(str(generation[0]).encode()).hexdigest()})
                    else:dependency_ack=ack
                    anonymous=anonymous_nonce and descriptor['provider']=='nonce'
                    inputs=nonce_inputs if descriptor['provider']=='nonce' else declaration(['owner'])
                    dependencies=not anonymous or anonymous_content
                    rows.append(dict(descriptor=descriptor['descriptor'],url=descriptor['url'],cache=f['cache'],bodyValidUntil=deadline+10,
                        identity=dict(identityState='anonymous' if anonymous else 'personal',identityInputs=inputs,
                            identityBinding=identity_mac(c,owner,inputs),owner=None if anonymous else dependency,
                            tags=[dependency] if dependencies else [],validUntil=deadline+20),
                        authority=[dict(tag=dependency,revision=dependency_ack['revision'],generation=dependency_ack['generation'])] if dependencies else []))
                    if anonymous and anonymous_content and content_failure in ('revision','generation'):
                        rows[-1]['authority'][0][content_failure]='0'*64
                    if anonymous and content_failure=='cache-key':rows[-1]['cache']=dict(f['cache'],key='0'*64)
                    if anonymous and content_failure=='cache-tags':rows[-1]['cache']=dict(f['cache'],tags='different-original-tags')
                record=dict(schemaVersion=1,requestId=context['deliveryRequestId'],originalUrl=path,
                    reuse=dict(version=1,context=c,recipe=recipe,admission=dict(binding=context['binding'],validUntil=deadline,
                        cookieWork=dict(state='none',validUntil=deadline+20),fragments=rows)))
                if ahead_absolute:
                    record['reuse']['admission']['validUntil']+=3600
                    record['reuse']['admission']['cookieWork']['validUntil']+=3600
                    for row in rows:
                        row['bodyValidUntil']+=3600;row['identity']['validUntil']+=3600
                if content_failure=='natural-expired':record['reuse']['admission']['validUntil']=int(time.time())-1
                records.append(record)
                return json.dumps(record),[('Content-Type','application/vnd.ultracache.reuse+json'),('Cache-Control','private, no-store'),
                    ('X-UltraCache-Delivery-Reuse-Outcome','finalized'),('X-UltraCache-Delivery-Reuse-Fresh-Remaining','99')]
            if path=='/__owned_mutation-map':
                signed=read_context(headers,path)
                state=self.call(holder['get'],'private-authority-context',tag=nonce_tag('A'))
                armed.append((signed,state))
                return 'ordinary unrelated request',[('Cache-Control','private, no-store'),
                    ('X-UltraCache-Mutation-Receipt',receipt(signed,'none',()))]
            return (BODY,META+([('Vary','Accept')] if formats else [])) if path==PARENT else ('cold',[('Cache-Control','private, no-store')])
        from test_cold_public_selection import choices
        policies = choices(('brandCurrency','variant')) if projected else None
        with proxy('ultracache',origin,transform=all_origin_hooks,policies=policies,
                   other_profile='basic' if lru_case else None,
                   management=bool(lru_case),
                   daemon_parameters=('vsl_mask=+Debug',) if diagnostic_only is not False else ()) as get:
            holder['get']=get;get(PARENT)
            if formats:
                for accept in accepts:get(PARENT,extra={'Accept':accept})
            self.register(get)
            calls.clear()
            status,headers,body=get(PARENT,'owner=A; _fbp=first')
            self.assertEqual(status,200);self.assertIn('private:A-generation1',body)
            if pending_case in ('exhausted','declined','cookie','expired'):
                self.assertEqual(calls.count((PARENT,'prepare')),1,'Retry is metadata only, never another provider execution')
                attempts=calls.count((PARENT,'reuse-finalize'))
                if pending_case=='exhausted':self.assertGreater(attempts,1)
                else:self.assertEqual(attempts,1)
                self.assertEqual(len(finalize_attempts),1,'One original execution owns every attempt')
                self.assertEqual(records,[],'Neither pending nor declined creates reusable metadata')
                self.assertNotIn('invalid-observer=',str(cookies(headers)))
                calls.clear()
                again=get(PARENT,'owner=A')
                self.assertEqual((again[0],again[2]),(200,body))
                self.assertEqual(calls.count((PARENT,'prepare')),1,'Failed optional metadata must not become an admitted HIT')
                return
            self.assertEqual(calls,[(PARENT,'prepare')]+[(PARENT,'reuse-finalize')]*(3 if pending_case=='settled' else 1))
            self.assertEqual(len(records),1)
            if content_failure in ('revision','generation','cache-key','cache-tags','natural-expired'):
                calls.clear()
                self.assertEqual(get(PARENT,'owner=A')[0],200)
                self.assertEqual(calls,[(PARENT,'prepare'),(PARENT,'reuse-finalize')],
                    'Invalid anonymous content authority must not publish reusable metadata')
                return
            if projected:
                from test_public_selection_runtime import control
                status,fields,_=control(get,enabled=True,names='brandCurrency',extra={
                    'X-UltraCache-Public-Selection-Public-Source-Version':'1',
                    'X-UltraCache-Public-Selection-Public-Source-Projection-Version':'1'})
                self.assertEqual(status,200)
                self.assertEqual(fields.get('X-UltraCache-VCL-Public-Selection-Public-Source-Projection-Version'),'1')
            calls.clear()
            status,headers,body2=get(PARENT,'owner=A; _fbp=second')
            self.assertEqual((status,body2),(200,body));self.assertEqual(cookies(headers),[])
            self.assertEqual(calls,[],'A complete native HIT must invoke no origin, prepare or finalizer')
            if pending_case=='settled':return
            if lru_case:
                def counters():
                    raw=json.loads(subprocess.check_output(
                        ['varnishstat','-n',str(get.instance),'-1','-j'],text=True))
                    rows=raw.get('counters',raw)
                    return {name:int(rows['MAIN.'+name]['value']) for name in ('n_lru_moved','n_lru_nuked')}
                interval_report=get.adm('param.show','lru_interval')
                match=re.search(r'Value is:\s*([0-9]+(?:\.[0-9]+)?)\s*\[seconds\]',interval_report)
                self.assertIsNotNone(match,interval_report)
                interval=float(match.group(1))
                self.assertLess(interval+1,body_budget,'Fixture must retain its existing grants beyond the native LRU interval')
                scope_before=self.observe(get)
                def cold(path):
                    result=get(path,extra={'Host':'other.test'})
                    self.assertEqual((result[0],len(result[2])),(200,512*1024))
                    return dict(result[1])['X-Cache']
                if lru_case=='pressure':
                    for i in range(24):self.assertEqual(cold('/__owned_lru/seed-'+str(i)),'MISS')
                # Read, never set, the engine's own interval. No cache/TTL or
                # daemon parameter change makes the test artificially pass.
                time.sleep(interval+0.15)
                before=counters()
                if lru_case=='pressure':
                    self.assertEqual(before['n_lru_nuked'],0,'Seed objects must fit before the controlled pressure starts')
                refreshed=get(PARENT,'owner=A; _fbp=lru')
                self.assertEqual((refreshed[0],refreshed[2]),(200,body))
                self.assertEqual(calls,[],'A touch must not call the original application')
                moved=counters()['n_lru_moved']-before['n_lru_moved']
                if lru_case=='moves':
                    # Parent normally touches itself. The additional three are
                    # the actual cached reuse metadata and two distinct bodies.
                    self.assertGreaterEqual(moved,4,'Parent-only LRU activity hides cold private dependencies')
                    self.assertEqual(get.adm('param.show','lru_interval'),interval_report)
                    return
                for i in range(16):self.assertEqual(cold('/__owned_lru/pressure-'+str(i)),'MISS')
                self.assertGreater(counters()['n_lru_nuked'],before['n_lru_nuked'],
                    'The unchanged16MB stevedore must actually evict objects')
                scope_after=self.observe(get)
                self.assertEqual(scope_after['scopeRevision'],scope_before['scopeRevision'])
                hot=get(PARENT,'owner=A; _fbp=after-pressure')
                self.assertEqual((hot[0],hot[2]),(200,body));self.assertEqual(cookies(hot[1]),[])
                self.assertEqual(calls,[],
                    'Hot parent, reuse metadata and bodies must survive cold pressure; native moved='+str(moved))
                previous=len(cold_calls)
                self.assertEqual(cold('/__owned_lru/seed-0'),'MISS','An actually cold object must remain evictable')
                self.assertEqual(len(cold_calls),previous+1)
                self.assertEqual(get.adm('param.show','lru_interval'),interval_report)
                return
            if diagnostic_only is not None:
                status,_,other=get(PARENT,'owner=B')
                self.assertEqual(status,200);self.assertIn('private:B-generation1',other)
                self.assertEqual(calls,[(PARENT,'prepare'),(PARENT,'reuse-finalize')])
                calls.clear()
                self.assertEqual(get(PARENT,'owner=B')[2],other)
                self.assertEqual(calls,[],'Diagnostics cannot add provider calls to a valid cached HIT')
                trace=subprocess.check_output(['varnishlog','-n',str(get.instance),'-d','-g','raw','-i','Debug'],text=True)
                # varnishlog escapes Debug's trailing NUL in its quoted format.
                messages=[line.split('uc-reuse',1)[1].removesuffix('%00"')
                          for line in trace.splitlines() if 'uc-reuse' in line]
                if diagnostic_only:
                    self.assertTrue(any('admission=miss reason=discovery-unavailable' in line for line in messages),messages)
                    self.assertTrue(any('admission=miss reason=metadata-object-unavailable' in line for line in messages))
                    self.assertTrue(any('lookup kind=metadata outcome=object-unavailable' in line for line in messages))
                    self.assertTrue(any('lookup kind=metadata outcome=hit' in line for line in messages))
                    self.assertTrue(any('admission=hit reason=complete-plan' in line for line in messages))
                    for message in messages:
                        self.assertRegex(message,r'^(?:-lookup )?[a-z0-9= .-]+$')
                        self.assertNotIn('owner=',message)
                        self.assertNotIn('PHPSESSID',message)
                        self.assertNotRegex(message,r'[0-9a-f]{32}')
                else:self.assertEqual(messages,[],'Native Debug diagnostics must remain off by default')
                return
            if verify_budget_expiry:
                time.sleep(body_budget+.2);generation[0]=2
                status,_,fresh=get(PARENT,'owner=A')
                self.assertEqual(status,200);self.assertIn('private:A-generation2',fresh)
                self.assertEqual(calls,[(PARENT,'prepare'),(PARENT,'reuse-finalize')],
                    'A later absolute provider clock may never extend the real native body grant')
                return
            if content_failure=='dirty':
                state=self.call(get,'private-authority-context',tag=content_tag)
                dirty=self.call(get,'private-mutation-begin',state,tag=content_tag,
                    extra={'X-UltraCache-Private-Transaction':'6'*64})
                holder['content_dirty']=True
                generation[0]=2;calls.clear()
                status,_,fresh=get(PARENT,'owner=A')
                self.assertEqual(status,200);self.assertIn('nonce:uid0-generation2',fresh)
                self.assertEqual(calls,[(PARENT,'prepare'),(PARENT,'reuse-finalize')])
                self.assertEqual(self.call(get,'private-authority-context',tag=content_tag)['remainingMutations'],1)
                return
            if anonymous_content:
                state=self.call(get,'private-authority-context',tag=content_tag)
                old_generation=state['generation'];old_revision=state['revision']
                writer=self.call(get,'private-mutation-begin',state,tag=content_tag,
                    extra={'X-UltraCache-Private-Transaction':'6'*64})
                self.assertNotEqual(writer['revision'],old_revision)
                done=self.call(get,'private-mutation-commit',writer,tag=content_tag,
                    extra={'X-UltraCache-Private-Transaction':writer['transaction'],'X-UltraCache-Private-Lease':writer['lease']})
                self.assertNotEqual(done['revision'],writer['revision'])
                published=self.call(get,'private-generation-publish',done,tag=content_tag,
                    extra={'X-UltraCache-Private-Generation':old_generation})
                self.assertNotEqual(published['revision'],old_revision)
                calls.clear();self.assertEqual(get(PARENT,'owner=A')[0],200)
                self.assertEqual(calls,[(PARENT,'prepare'),(PARENT,'reuse-finalize')],
                    'Same published content generation must not revive a pre-mutation admission')
                calls.clear();self.assertEqual(get(PARENT,'owner=A')[0],200);self.assertEqual(calls,[])
            if projected: return  # this case qualifies the registered full-HIT boundary only
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
            self.assertEqual(calls,[],'Filling B must preserve A admission without rebasing its authority')
            if formats or unified_html:
                stable=self.observe(get)['scopeRevision']
                for owner in ('A','B'):
                    for accept in accepts:
                        if not unified_html:
                            get(PARENT,'owner='+owner,{'Accept':accept})
                            calls.clear()
                        status,_,html=get(PARENT,'owner='+owner,{'Accept':accept})
                        self.assertEqual(status,200);self.assertIn('private:'+owner+'-generation2',html)
                        self.assertEqual(calls,[],'Second request per owner/format must use complete native HIT')
                for _ in range(2):
                    for accept in accepts:
                        for owner in ('A','B'):
                            status,_,html=get(PARENT,'owner='+owner+'; _fbp=interleaved',{'Accept':accept})
                            self.assertEqual(status,200);self.assertIn('private:'+owner+'-generation2',html)
                self.assertEqual(calls,[],'Interleaved owner/format requests must remain origin-free')
                self.assertEqual(self.observe(get)['scopeRevision'],stable)
            # An ordinary request, even with a valid receipt, is not a write.
            before=self.observe(get)
            old_nonce=self.call(get,'private-authority-context',tag=nonce_tag('A'))
            content_before=self.call(get,'private-authority-context',tag=content_tag) if anonymous_content else None
            self.assertEqual(get('/__owned_mutation-map','owner=A; _fbp=unrelated')[0],200)
            current=self.observe(get)
            self.assertEqual((current['contentRevision'],current['scopeRevision']),
                             (before['contentRevision'],before['scopeRevision']))
            self.assertEqual(self.call(get,'private-authority-context',tag=nonce_tag('A'))['revision'],old_nonce['revision'])
            if anonymous_nonce:
                self.assertIn('nonce:uid0-generation2',other)
                self.assertIn('nonce:uid0-generation2',again)
            if anonymous_content:
                self.assertEqual(self.call(get,'private-authority-context',tag=content_tag)['revision'],content_before['revision'])
            calls.clear();self.assertEqual(get(PARENT,'owner=A')[2],again);self.assertEqual(calls,[])

if __name__=='__main__':unittest.main()
