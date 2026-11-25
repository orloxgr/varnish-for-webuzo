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
import subprocess
import re
import http.client
import socket
import test_reuse_authority as authority
from test_cookie_delivery import proxy,cookies
from test_delivery_continuation import BODY,META,PARENT,PRIVATE,ADAPTIVE,envelope
from test_reuse_delivery_context import all_origin_hooks,signed_context
from test_reuse_cookie_inputs import declaration,seal_recipe,lp
from test_private_fragment_ttl import exchange
import test_mutation_coverage_runtime as coverage
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
    recover=authority.NativeReuseAuthority.recover
    publish=authority.NativeReuseAuthority.publish
    def test_metadata_and_all_private_bodies_compose_without_any_origin_then_missing_body_refills(self):
        self.run_full_actor()

    def test_ack_only_preserves_an_already_complete_native_cached_plan(self):
        # Reuse the current event-driven HSH actor. The older run_full_actor
        # cases below still describe removed execution-drain transport.
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

    def test_scope_writer_suspends_complete_mixed_hit_until_drained_and_fresh_finalized(self):
        self.run_full_actor(anonymous_nonce=True,scope_fence=True)

    def test_covered_unchanged_interleaved_owners_and_all_formats_reuse_without_origin(self):
        self.run_full_actor(anonymous_nonce=True,covered=True)

    def test_later_covered_reads_do_not_extend_the_pinned_admission_cut(self):
        self.run_full_actor(anonymous_nonce=True,covered=True,held_case='later-read')

    def test_actual_tag_write_after_pin_rejects_the_old_waiting_plan(self):
        self.run_full_actor(anonymous_nonce=True,covered=True,held_case='write')

    def test_postresponse_late_write_is_still_inside_the_original_blocker(self):
        self.run_full_actor(anonymous_nonce=True,covered=True,held_case='ended-late-write')

    def test_unknown_coverage_wakes_to_real_fallback_without_old_authority(self):
        self.run_full_actor(anonymous_nonce=True,covered=True,held_case='unknown')

    def test_actual_request_send_deadline_never_closes_a_lost_drain_as_clean(self):
        self.run_full_actor(anonymous_nonce=True,covered=True,held_case='deadline')

    def test_native_vcl_replacement_keeps_the_existing_wait_owner_alive_until_drain(self):
        self.run_full_actor(anonymous_nonce=True,covered=True,held_case='reload')

    def test_earlier_failed_fence_cannot_be_excluded_from_the_read_cut(self):
        self.run_full_actor(anonymous_nonce=True,covered=True,held_case='failed-fence')

    def test_disconnected_held_reader_releases_native_and_vcl_references(self):
        self.run_full_actor(anonymous_nonce=True,covered=True,held_case='cancel')

    def test_actual_provider_lifetime_withdraws_lost_drain_reservation_without_clean_grant(self):
        self.run_full_actor(anonymous_nonce=True,covered=True,held_case='body-deadline')

    def test_internal_observation_budget_never_waits_for_the_1500_second_send_budget(self):
        self.run_full_actor(anonymous_nonce=True,covered=True,held_case='lost-drain')

    def test_policy_replacement_invalidates_the_earlier_pinned_plan(self):
        self.run_full_actor(anonymous_nonce=True,covered=True,held_case='policy')

    def test_fresh_source_authority_namespace_survives_initial_and_postscope_recovery(self):
        self.run_full_actor(anonymous_nonce=True,scope_fence=True,covered=True,namespace_keys=True)

    def test_projected_resolver_registration_does_not_intercept_a_complete_native_hit(self):
        self.run_full_actor(projected=True)

    def test_anonymous_mutable_content_reuses_and_never_installs_a_visitor_revoke_map(self):
        self.run_full_actor(anonymous_nonce=True,anonymous_content=True,covered=True)

    def test_anonymous_content_dirty_authority_refuses_reuse_without_a_fake_owner(self):
        self.run_full_actor(anonymous_nonce=True,anonymous_content=True,content_failure='dirty')

    def test_anonymous_content_wrong_revision_refuses_admission(self):
        self.run_full_actor(anonymous_nonce=True,anonymous_content=True,content_failure='revision')

    def test_anonymous_content_wrong_generation_refuses_admission(self):
        self.run_full_actor(anonymous_nonce=True,anonymous_content=True,content_failure='generation')

    def test_later_absolute_deadline_is_capped_by_native_grants_without_another_approval_fetch(self):
        self.run_full_actor(anonymous_nonce=True,covered=True,ahead_absolute=True)

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

    def run_full_actor(self,anonymous_nonce=False,scope_fence=False,covered=False,namespace_keys=False,projected=False,
                       anonymous_content=False,content_failure=None,ahead_absolute=False,body_budget=120,verify_budget_expiry=False,
                       held_case='read',diagnostic_only=None,pending_case=None,lru_case=None):
        holder={};calls=[];prepared={};prepared_accepts={};generation=[1];records=[];armed=[]
        finalize_attempts={};finalize_headers={}
        cold_calls=[]
        held_entered=threading.Event();held_release=threading.Event();held_original=[]
        later_entered=threading.Event();later_release=threading.Event();later_original=[]
        if held_case=='ended-late-write':held_release.set()
        nonce_tag=lambda owner:hashlib.sha256(('mock-nonce-owner-'+owner).encode()).hexdigest()
        content_tag=hashlib.sha256(b'mock-public-comments-content').hexdigest()
        nonce_inputs=declaration(['wordpress_logged_in_mock']) if anonymous_nonce else declaration(['owner'])
        recipe=seal_recipe(dict(inputs=declaration(['owner','wordpress_logged_in_mock'] if anonymous_nonce else ['owner']),fragments=[
            dict(url=PRIVATE,provider='cart',occurrences=2),dict(url=ADAPTIVE,provider='nonce',occurrences=1)]))
        def cache_key(url,owner):
            identity='uid0' if anonymous_nonce and url==ADAPTIVE else owner
            namespace='|'+self.observe(holder['get'])['scopeRevision'] if namespace_keys else ''
            return hashlib.sha256((url+'|'+identity+'|'+str(generation[0])+namespace).encode()).hexdigest()
        accepts=('text/html', 'text/html,image/webp', 'text/html,image/avif,image/webp')
        def read_context(headers,path):
            return coverage.context(self,headers,'GET',path) if covered else signed_context(self,headers,path,'GET')
        def origin(path,headers):
            if lru_case and path.startswith('/__owned_lru/'):
                # Ordinary Basic-site bytes share the fixture's unchanged
                # malloc16MB storage, without creating a private mutation owner.
                self.assertEqual(headers.get('Host'),'other.test')
                cold_calls.append(path)
                return b'x'*(512*1024),[('Content-Type','application/octet-stream'),('Cache-Control','public, max-age=120')]
            phase=headers.get('X-UltraCache-Delivery-Phase');calls.append((path,phase))
            if phase=='prepare':
                if holder.get('waiting_reader_started') is not None and 'fallback_started' not in holder:
                    holder['fallback_started']=time.monotonic()
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
                return json.dumps(body),[('Cache-Control','private, no-store')]+([coverage.response_receipt(signed)] if covered else [])
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
                if covered and source_namespace!=current['scopeRevision']:
                    rejected=self.call(holder['get'],'private-execution-drained',current,tag=None,expected_status=409,extra={
                        'X-UltraCache-Private-Request-Id':context['requestId'],'X-UltraCache-Private-Challenge':context['challenge'],
                        'X-UltraCache-Private-Drained':'1',**coverage.completion_headers(original)})
                    self.assertIn(rejected['reason'],('coverage-scope-changed','coverage-unqualified'))
                    self.call(holder['get'],'private-execution-drained',self.observe(holder['get']),tag=None,extra={
                        'X-UltraCache-Private-Request-Id':context['requestId'],'X-UltraCache-Private-Challenge':context['challenge'],
                        'X-UltraCache-Private-Drained':'1',**coverage.completion_headers(original,'unknown')})
                    return 204,'',[('Cache-Control','private, no-store')]
                self.call(holder['get'],'private-execution-drained',current,tag=None,extra={
                    'X-UltraCache-Private-Request-Id':context['requestId'],'X-UltraCache-Private-Challenge':context['challenge'],
                    'X-UltraCache-Private-Drained':'1',**(coverage.completion_headers(original) if covered else {})})
                if (self.observe(holder['get'])['scopeMutations'] or self.observe(holder['get']).get('temporaryHolds') or
                        content_failure=='dirty' and holder.get('content_dirty')):
                    return 204,'',[('Cache-Control','private, no-store')]
                self.recover(holder['get'],self.observe(holder['get']))
                owner_tag=OWNER if owner=='A' else hashlib.sha256(('mock-owner-'+owner).encode()).hexdigest()
                observed=self.call(holder['get'],'private-authority-context',tag=owner_tag)
                ack=self.call(holder['get'],'private-generation-publish',observed,tag=owner_tag,
                    extra={'X-UltraCache-Private-Generation':hashlib.sha256(str(generation[0]).encode()).hexdigest()})
                if namespace_keys:self.assertEqual(ack['scopeRevision'],source_namespace,
                    'Recovery must not silently rebase a fresh original body claim into another namespace')
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
            if path=='/__owned_mutation-held':
                signed=read_context(headers,path);held_original.append(signed);held_entered.set()
                self.assertTrue(held_release.wait(10))
                return 'held actual response',[('Cache-Control','private, no-store'),
                    coverage.response_receipt(signed,result='unknown' if held_case=='unknown' else 'qualified')]
            if path=='/__owned_mutation-held-later':
                signed=read_context(headers,path);later_original.append(signed);later_entered.set()
                self.assertTrue(later_release.wait(10))
                return 'later actual response',[('Cache-Control','private, no-store'),coverage.response_receipt(signed)]
            if path=='/__owned_mutation-map':
                signed=read_context(headers,path)
                state=self.call(holder['get'],'private-authority-context',tag=nonce_tag('A'))
                armed.append((signed,state))
            return (BODY,META+([('Vary','Accept')] if covered else [])) if path==PARENT else ('cold',[('Cache-Control','private, no-store')])
        from test_cold_public_selection import choices
        policies = choices(('brandCurrency','variant')) if projected else None
        def actor_policy(source):
            source=all_origin_hooks(source)
            source=source.replace('sub vcl_synth {',
                'sub vcl_synth { set resp.http.X-Test-Held-Waiters = cookie_handoff.delivery_held_waiters(); '
                'set resp.http.X-Test-Pending = cookie_handoff.pending();',1)
            # Test-only actual session budget: the normal adapter intentionally
            # raises the daemon default to cover all origin phases.
            if held_case=='deadline':source=re.sub(r'set sess.send_timeout = [^;]+;', 'set sess.send_timeout = 0.2s;',source)
            return source
        with proxy('ultracache',origin,transform=actor_policy,policies=policies,
                   other_profile='basic' if lru_case else None,
                   management=bool(lru_case) or held_case in ('reload','cancel'),daemon_parameters=(
                       (('vsl_mask=+Debug',) if diagnostic_only is not False else ())+
                       (('send_timeout=1',) if held_case=='deadline' else
                        ('debug=+vclrel',) if held_case in ('reload','cancel') else ()))) as get:
            holder['get']=get;get(PARENT)
            if covered:
                for accept in accepts:get(PARENT,extra={'Accept':accept})
                coverage.register(self,get)
            else:self.register(get)
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
                    self.assertTrue(any('admission=miss reason=scope-not-ready' in line for line in messages),messages)
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
                if namespace_keys:
                    first_keys={f['cache']['key'] for f in records[0]['reuse']['admission']['fragments']}
                    current_keys={f['cache']['key'] for f in records[-1]['reuse']['admission']['fragments']}
                    self.assertTrue(first_keys.isdisjoint(current_keys),
                        'Actual scope invalidation must choose fresh HSH body keys even when session/body digest is unchanged')
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
                if held_case in ('reload','cancel'):get.adm('vcl.load','after',str(get.instance.parent/'policy.vcl'))
                if held_case=='body-deadline':
                    holder['arm_natural_deadline']=True
                    self.assertEqual(exchange(get,'PURGE',PRIVATE,cache_key(PRIVATE,'B'),'b'*64)[0],200)
                    self.assertEqual(get(PARENT,'owner=B',{'Accept':accepts[0]})[0],200)
                    until=holder['natural_until']
                    while time.time()<until-.3:time.sleep(.01)
                errors=[];reader_result=[];reader_done=threading.Event()
                def hold_request():
                    try:get('/__owned_mutation-held','owner=A')
                    except BaseException as error:errors.append(error)
                worker=threading.Thread(target=hold_request);worker.start()
                def read_parent():
                    try:
                        if held_case=='cancel':
                            client=http.client.HTTPConnection(*get.endpoint,timeout=10)
                            holder['cancel_client']=client
                            client.request('GET',PARENT,headers=dict(get.request_headers,Cookie='owner=B',Accept=accepts[0]))
                            response=client.getresponse();reader_result.append((response.status,response.read()))
                        else:reader_result.append(get(PARENT,'owner=B',{'Accept':accepts[0]}))
                    except BaseException as error:
                        if held_case=='cancel':holder['cancelled']=True
                        else:errors.append(error)
                    finally:reader_done.set()
                reader=None;later_worker=None
                try:
                    self.assertTrue(held_entered.wait(10))
                    if held_case=='ended-late-write':coverage.NativeCoverageHolds.ended(self,get)
                    self.assertEqual(self.observe(get)['temporaryHolds'],1)
                    def native_probe():
                        status,fields,_=native_control(get,'private-authority-context',extra={'X-UltraCache-Public-Selection-Scope':'/'})
                        self.assertEqual(status,200)
                        return fields
                    pending_before=int(native_probe()['X-Test-Pending']) if held_case=='cancel' else None
                    calls.clear()
                    started=time.monotonic()
                    holder['waiting_reader_started']=started
                    def actual_waiters():
                        return int(native_probe()['X-Test-Held-Waiters'])
                    reader=threading.Thread(target=read_parent);reader.start()
                    until=time.monotonic()+5
                    while not actual_waiters():
                        self.assertFalse(reader_done.is_set(),reader_result)
                        if time.monotonic()>=until:self.fail('Held read did not enter the actual engine waiting list')
                        time.sleep(.01)
                    self.assertEqual(calls,[],'A real held read must park without executing prepare/providers')
                    self.assertEqual(self.observe(get)['temporaryHolds'],1,
                        'Parking must not clear another still-live hold')
                    if held_case=='later-read':
                        def later_request():
                            try:get('/__owned_mutation-held-later','owner=A')
                            except BaseException as error:errors.append(error)
                        later_worker=threading.Thread(target=later_request);later_worker.start()
                        self.assertTrue(later_entered.wait(5))
                        self.assertEqual(self.observe(get)['temporaryHolds'],2)
                        calls.clear()
                    if held_case in ('reload','cancel'):
                        get.adm('vcl.use','after');get.adm('vcl.discard','boot')
                    if held_case=='cancel':
                        client=holder['cancel_client'];client.sock.shutdown(socket.SHUT_RDWR);client.close()
                        self.assertTrue(reader_done.wait(5));self.assertTrue(holder.get('cancelled'))
                        until=time.monotonic()+2
                        while int(native_probe()['X-Test-Pending'])!=pending_before:
                            if time.monotonic()>=until:self.fail('Closed reader retains its association until unrelated drain')
                            time.sleep(.01)
                        self.assertEqual(self.observe(get)['temporaryHolds'],1,
                            'Disconnect cleanup must happen while original application execution stays unresolved')
                        self.assertFalse(any(path==PARENT for path,_ in calls),'Closed reader must not invoke a fresh provider')
                        calls.clear()
                    if held_case in ('write','ended-late-write'):
                        generation[0]=3
                        tag=hashlib.sha256(b'mock-owner-B').hexdigest()
                        writer=self.call(get,'private-mutation-begin',self.call(get,'private-authority-context',tag=tag),
                            tag=tag,extra={'X-UltraCache-Private-Transaction':'4'*64})
                        self.call(get,'private-mutation-commit',writer,tag=tag,extra={
                            'X-UltraCache-Private-Transaction':writer['transaction'],'X-UltraCache-Private-Lease':writer['lease']})
                    if held_case=='policy':
                        generation[0]=3;coverage.register(self,get,policy='d'*64)
                    if held_case in ('write','ended-late-write','deadline','body-deadline','lost-drain','policy'):
                        self.assertTrue(reader_done.wait(10),'Real invalidation/deadline must withdraw the native reservation')
                        self.assertEqual(reader_result[0][0],200)
                        self.assertTrue(any(phase=='prepare' for _,phase in calls),'This must be actual original fallback')
                        if held_case not in ('deadline','body-deadline','lost-drain'):self.assertIn('private:B-generation3',reader_result[0][2])
                        if held_case in ('deadline','body-deadline','lost-drain'):
                            self.assertLess(holder['fallback_started']-started,2,
                                'The cache-only park, not real provider execution, must have bounded failure scheduling')
                            trace=subprocess.check_output(['varnishlog','-n',str(get.instance),'-d','-g','raw','-i','Debug'],text=True)
                            self.assertIn('parked deadline='+('observation' if held_case=='lost-drain' else 'natural'),trace)
                        self.assertEqual(self.observe(get)['temporaryHolds'],1,'No timeout or write signal may retire the old execution')
                    if held_case in ('unknown','failed-fence'):generation[0]=3
                    held_release.set();worker.join(timeout=15)
                    until=time.monotonic()+5
                    while any(e['requestId']==held_original[0]['requestId'] and e['live']
                              for e in self.observe(get).get('unsettledExecutions',[])):
                        if time.monotonic()>=until:self.fail('Original covered backend did not actually finish')
                        time.sleep(.01)
                    original=held_original[0]
                    if held_case=='failed-fence':
                        self.assertFalse(reader_done.is_set(),'A qualified response/fini cannot replace failed-prewrite drain proof')
                    self.call(get,'private-execution-drained',self.observe(get),tag=None,extra={
                        'X-UltraCache-Private-Request-Id':original['requestId'],
                        'X-UltraCache-Private-Challenge':original['challenge'],'X-UltraCache-Private-Drained':'1',
                        **coverage.completion_headers(original,'unknown' if held_case in ('unknown','failed-fence','policy') else 'qualified')})
                    self.assertTrue(reader_done.wait(10))
                    if held_case!='cancel':
                        status,_,during=reader_result[0]
                        self.assertEqual(status,200)
                    else:self.assertEqual(calls,[],'A closed native reader must not dispatch providers')
                    if held_case in ('read','later-read','reload'):
                        self.assertIn('private:B-generation2',during)
                        self.assertEqual(calls,[],'Exact drain must reselect the complete pinned cache with zero origin work')
                    if held_case=='later-read':
                        self.assertEqual(self.observe(get)['temporaryHolds'],1,
                            'A later real execution remains live yet cannot extend the earlier snapshot read')
                        later_release.set();later_worker.join(timeout=10)
                        coverage.NativeCoverageHolds.ended(self,get)
                        later=later_original[0]
                        self.call(get,'private-execution-drained',self.observe(get),tag=None,extra={
                            'X-UltraCache-Private-Request-Id':later['requestId'],'X-UltraCache-Private-Challenge':later['challenge'],
                            'X-UltraCache-Private-Drained':'1',**coverage.completion_headers(later)})
                    if held_case in ('reload','cancel'):
                        until=time.monotonic()+5
                        while True:
                            listing=get.adm('vcl.list');rows=[line.split() for line in listing.splitlines() if line.split() and line.split()[-1]=='boot']
                            # An idle discarded VCL may remain warm for the
                            # engine's real cooldown; its busy count must be zero.
                            if not rows or rows[0][-2]=='0':break
                            if time.monotonic()>=until:self.fail('Original VCL still busy after wait owners ended: '+listing)
                            time.sleep(.01)
                finally:
                    held_release.set();later_release.set();worker.join(timeout=15)
                    if reader:reader.join(timeout=15)
                    if later_worker:later_worker.join(timeout=15)
                self.assertEqual(errors,[]);self.assertFalse(worker.is_alive())
                if held_case in ('write','ended-late-write','unknown','failed-fence','deadline','body-deadline','lost-drain','cancel','policy'):return
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
                content_before=self.call(get,'private-authority-context',tag=content_tag) if anonymous_content else None
                personal=self.observe(get)
                self.assertEqual(get('/__owned_mutation-map','owner=A; _fbp=unrelated')[0],200)
                if covered:self.assertNotEqual(self.observe(get)['scopeRevision'],personal['scopeRevision'])
                else:self.assertNotEqual(self.observe(get)['revision'],personal['revision'])
                self.assertEqual(self.call(get,'private-authority-context',tag=nonce_tag('A'))['revision'],probe['revision'])
                if anonymous_content:
                    self.assertEqual(self.call(get,'private-authority-context',tag=content_tag)['revision'],content_before['revision'],
                        'An anonymous content tag must never become a visitor revoke-map dependency')
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
