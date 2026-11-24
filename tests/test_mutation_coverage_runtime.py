"""Actual native holds and tagged fences; MOCK trusted coverage/drain producer.

Real supported-handler and independent PHP/SQL drain acceptance belongs to Root.
These actors never infer complete application coverage from a NONE receipt.
"""
import base64
import hashlib
import hmac
import json
import os
import shutil
import threading
import unittest
import test_mutation_backend as backend
import test_reuse_authority as authority
from test_cookie_delivery import proxy
from test_public_selection_runtime import control
from test_mutation_coverage_wire import KEY,POLICY,request_frame,receipt,completion_headers


def register(test,get,policy=POLICY):
    status,headers,body=control(get,enabled=True,names='',extra={
        'X-UltraCache-Public-Selection-Reuse-Version':'1','X-UltraCache-Public-Selection-Reuse-Policy':authority.REUSE_POLICY,
        'X-UltraCache-Public-Selection-Coverage-Version':'1','X-UltraCache-Public-Selection-Coverage-Policy':policy})
    test.assertEqual(status,200,(status,body))
    test.assertEqual(headers.get('X-UltraCache-VCL-Public-Selection-Coverage-Version'),'1')
    test.assertEqual(headers.get('X-UltraCache-VCL-Public-Selection-Coverage-Policy'),policy)
    test.assertNotIn('X-UltraCache-VCL-Delivery-Reuse-Version',headers)

def context(test,headers,method,path):
    value=json.loads(base64.b64decode(headers['X-UltraCache-Mutation-Context'],validate=True))
    test.assertEqual(set(value),{'schemaVersion','proof','coverageVersion','coveragePolicy',
        'siteId','canonicalHost','scopeDigest','epoch','incarnation','nativePolicy','wordpressPolicy','reusePolicy','requestId','challenge'})
    test.assertEqual((value['schemaVersion'],value['coverageVersion']),(2,1))
    test.assertEqual(value['proof'],hmac.new(KEY,request_frame(dict(value,method=method,url=path)),'sha256').hexdigest())
    return value

def response_receipt(value,state='none',pairs=(),result='qualified'):
    return ('X-UltraCache-Mutation-Receipt',base64.b64encode(json.dumps(receipt(value,state,pairs,result),separators=(',',':')).encode()).decode())

@unittest.skipUnless(shutil.which('varnishd') and os.environ.get('SCP_EXPERIMENTAL_REUSE_TEST')=='1','Matching-source native required')
class NativeCoverageHolds(unittest.TestCase):
    call=authority.NativeReuseAuthority.call
    observe=authority.NativeReuseAuthority.observe
    recover=authority.NativeReuseAuthority.recover
    publish=authority.NativeReuseAuthority.publish
    ready=authority.NativeReuseAuthority.ready
    ended=backend.NativeMutationBackend.ended

    def drain(self,get,original,result='qualified',status=200,extra=None):
        headers={'X-UltraCache-Private-Request-Id':original['requestId'],
            'X-UltraCache-Private-Challenge':original['challenge'],'X-UltraCache-Private-Drained':'1',
            **completion_headers(original,result)}
        headers.update(extra or {})
        return self.call(get,'private-execution-drained',self.observe(get),tag=None,extra=headers,expected_status=status)
    def refused_recovery(self,get):
        return self.call(get,'private-authority-recover',self.observe(get),tag=None,
            extra={'X-UltraCache-Private-Drained':'1'},expected_status=409)

    def test_complete_execution_list_is_explicit_before_during_and_after_last_retirement(self):
        captured=[];entered=threading.Event();release=threading.Event();errors=[]
        def origin(path,headers):
            c=context(self,headers,'POST',path);captured.append(c);entered.set()
            self.assertTrue(release.wait(10))
            return 'actual',[('Cache-Control','private, no-store'),response_receipt(c)]
        with proxy('ultracache',origin,transform=backend.actor_hooks,allow_post=True) as get:
            register(self,get);old=self.ready(get)
            self.assertEqual(old['unsettledExecutions'],[])
            self.assertEqual(self.call(get,'private-authority-context',tag=None)['unsettledExecutions'],[])
            def request():
                try:self.assertEqual(backend.post(get)[0],200)
                except BaseException as error:errors.append(error)
            worker=threading.Thread(target=request);worker.start()
            try:
                self.assertTrue(entered.wait(10))
                active=self.observe(get)['unsettledExecutions']
                self.assertEqual(len(active),1)
                self.assertEqual((active[0]['requestId'],active[0]['challenge']),
                    (captured[0]['requestId'],captured[0]['challenge']))
                self.assertTrue(active[0]['live']);self.assertTrue(active[0]['awaitingReceipt'])
            finally:
                release.set();worker.join(timeout=15)
            self.assertFalse(worker.is_alive());self.assertEqual(errors,[])
            self.assertEqual(len(self.ended(get)['unsettledExecutions']),1)
            retired=self.drain(get,captured[0])
            self.assertEqual(retired['unsettledExecutions'],[])
            current=self.call(get,'private-authority-context',tag=None)
            self.assertEqual(current['unsettledExecutions'],[])
            self.assertEqual(current['scopeRevision'],old['scopeRevision'])
            stale=self.drain(get,captured[0],status=409)
            self.assertEqual(stale['reason'],'execution-unavailable')
            self.assertEqual(stale['unsettledExecutions'],[])

    def test_qualified_receipt_and_native_fini_do_not_close_hold_but_exact_drain_preserves_revision(self):
        captured=[]
        def origin(path,headers):
            c=context(self,headers,'POST',path);captured.append(c)
            return 'actual',[('Cache-Control','private, no-store'),response_receipt(c)]
        with proxy('ultracache',origin,transform=backend.actor_hooks,allow_post=True) as get:
            register(self,get);old=self.ready(get)
            self.assertEqual(backend.post(get)[0],200)
            pending=self.ended(get)
            self.assertEqual(pending['scopeRevision'],old['scopeRevision'])
            self.assertEqual((pending['temporaryHolds'],pending['scopeState']),(1,'unbound'))
            self.assertEqual(self.publish(get,pending,status=409)['reason'],'execution-held')
            self.assertEqual(self.refused_recovery(get)['reason'],'execution-unsettled')
            self.assertTrue(pending['unsettledExecutions'][0]['receiptQualified'])
            self.drain(get,captured[0])
            current=self.observe(get)
            self.assertEqual((current['scopeRevision'],current['revision'],current['generation']),
                (old['scopeRevision'],old['revision'],old['generation']))
            self.assertEqual(current['scopeState'],'ready')
            self.assertEqual(self.recover(get,current)['scopeRevision'],old['scopeRevision'])
            self.drain(get,captured[0],status=409)

    def test_overlapping_holds_and_live_execution_cannot_close_each_other(self):
        captured=[];lock=threading.Lock();entered=threading.Event();release=threading.Event();errors=[]
        def origin(path,headers):
            c=context(self,headers,'POST',path)
            with lock:
                captured.append(c)
                if len(captured)==2:entered.set()
            self.assertTrue(release.wait(10))
            return 'actual',[('Cache-Control','private, no-store'),response_receipt(c)]
        with proxy('ultracache',origin,transform=backend.actor_hooks,allow_post=True) as get:
            register(self,get);old=self.ready(get)
            def request():
                try:backend.post(get)
                except BaseException as error:errors.append(error)
            workers=[threading.Thread(target=request) for _ in range(2)]
            for worker in workers:worker.start()
            try:
                self.assertTrue(entered.wait(10))
                self.assertEqual(self.observe(get)['temporaryHolds'],2)
                self.assertEqual(self.drain(get,captured[0],status=409)['reason'],'execution-active')
            finally:
                release.set()
                for worker in workers:worker.join(timeout=15)
            self.assertEqual(errors,[]);self.assertTrue(all(not worker.is_alive() for worker in workers))
            self.ended(get);self.drain(get,captured[0])
            self.assertEqual(self.observe(get)['temporaryHolds'],1)
            self.assertEqual(self.observe(get)['scopeRevision'],old['scopeRevision'])
            self.drain(get,captured[1]);current=self.observe(get)
            self.assertEqual((current['scopeState'],current['scopeRevision'],current['generation']),('ready',old['scopeRevision'],old['generation']))

    def test_postresponse_real_tag_intent_revokes_only_that_owner_and_preserves_other_owner(self):
        captured=[];other=hashlib.sha256(b'other-covered-owner').hexdigest()
        def origin(path,headers):
            c=context(self,headers,'POST',path);captured.append(c)
            return 'early response',[('Cache-Control','private, no-store'),response_receipt(c)]
        with proxy('ultracache',origin,transform=backend.actor_hooks,allow_post=True) as get:
            register(self,get);old=self.ready(get)
            b=self.call(get,'private-authority-context',tag=other)
            b=self.call(get,'private-generation-publish',b,tag=other,extra={'X-UltraCache-Private-Generation':'e'*64})
            backend.post(get);self.ended(get)
            # Actual native prewrite/commit/ACK calls AFTER response/fini model
            # a late provider intent discovered by the independent SQL drain.
            a=self.observe(get)
            writer=self.call(get,'private-mutation-begin',a,extra={'X-UltraCache-Private-Transaction':'7'*64})
            done=self.call(get,'private-mutation-commit',writer,extra={
                'X-UltraCache-Private-Transaction':writer['transaction'],'X-UltraCache-Private-Lease':writer['lease']})
            self.call(get,'private-mutation-ack',done,extra={
                'X-UltraCache-Private-Transaction':done['transaction'],'X-UltraCache-Private-Lease':done['lease']})
            self.drain(get,captured[0]);current=self.observe(get)
            self.assertEqual((current['scopeRevision'],current['state']),(old['scopeRevision'],'unbound'))
            after_b=self.call(get,'private-authority-context',tag=other)
            self.assertEqual((after_b['revision'],after_b['generation']),(b['revision'],b['generation']))
            self.publish(get,current,'f'*64)

    def test_actual_prewrite_tag_lease_and_dirty_receipt_revoke_a_without_rebasing_b(self):
        captured=[];writers=[];holder={};other=hashlib.sha256(b'other-before-write-owner').hexdigest()
        def origin(path,headers):
            c=context(self,headers,'POST',path);captured.append(c)
            before=self.observe(holder['get'])
            writer=self.call(holder['get'],'private-mutation-begin',before,
                extra={'X-UltraCache-Private-Transaction':'6'*64})
            writers.append(writer)
            self.call(holder['get'],'private-mutation-commit',writer,extra={
                'X-UltraCache-Private-Transaction':writer['transaction'],'X-UltraCache-Private-Lease':writer['lease']})
            return 'business response',[('Cache-Control','private, no-store'),
                response_receipt(c,'dirty',[(authority.TAG,writer['transaction'])])]
        with proxy('ultracache',origin,transform=backend.actor_hooks,allow_post=True) as get:
            holder['get']=get;register(self,get);old=self.ready(get)
            b=self.call(get,'private-authority-context',tag=other)
            b=self.call(get,'private-generation-publish',b,tag=other,extra={'X-UltraCache-Private-Generation':'e'*64})
            self.assertEqual(backend.post(get)[0],200);self.ended(get)
            writer=writers[0]
            self.assertFalse(self.observe(get)['scopeMutations'])
            self.call(get,'private-mutation-ack',self.observe(get),extra={
                'X-UltraCache-Private-Transaction':writer['transaction'],'X-UltraCache-Private-Lease':writer['lease']})
            self.drain(get,captured[0]);a=self.observe(get)
            self.assertEqual((a['scopeRevision'],a['state']),(old['scopeRevision'],'unbound'))
            current_b=self.call(get,'private-authority-context',tag=other)
            self.assertEqual((current_b['state'],current_b['revision'],current_b['generation']),('clean',b['revision'],b['generation']))
            self.publish(get,a,'f'*64)

    def test_invalid_completion_or_missing_receipt_is_sticky_unknown_not_an_old_clean_restore(self):
        captured=[];mode=['qualified']
        def origin(path,headers):
            c=context(self,headers,'POST',path);captured.append(c)
            return 'actual',[('Cache-Control','private, no-store')]+([] if mode[0]=='missing' else [response_receipt(c,result='unknown' if mode[0]=='unknown' else 'qualified')])
        with proxy('ultracache',origin,transform=backend.actor_hooks,allow_post=True) as get:
            register(self,get)
            for variant in ('badcompletion','missing','unknown','missingcompletion'):
                mode[0]=variant;old=self.ready(get)
                backend.post(get);self.ended(get);c=captured[-1]
                if variant=='missingcompletion':
                    self.assertEqual(self.drain(get,c,status=400,extra={'X-UltraCache-Private-Coverage-Version':''})['reason'],'coverage-completion-invalid')
                if variant=='badcompletion':
                    self.assertEqual(self.drain(get,c,status=409,extra={'X-UltraCache-Private-Coverage-Proof':'0'*64})['reason'],'coverage-proof-mismatch')
                self.assertNotEqual(self.observe(get)['scopeRevision'],old['scopeRevision'])
                self.assertEqual(self.drain(get,c,status=409)['reason'],'coverage-unqualified')
                self.drain(get,c,'unknown')
                current=self.observe(get);self.assertEqual(current['scopeState'],'unbound');self.assertNotIn('generation',current)
                self.recover(get,current);self.assertEqual(self.observe(get)['state'],'unbound')

    def test_unknown_scope_writer_or_policy_replacement_invalidates_certified_hold(self):
        captured=[]
        def origin(path,headers):
            c=context(self,headers,'POST',path);captured.append(c)
            return 'actual',[('Cache-Control','private, no-store'),response_receipt(c)]
        with proxy('ultracache',origin,transform=backend.actor_hooks,allow_post=True) as get:
            register(self,get);old=self.ready(get);backend.post(get);self.ended(get);c=captured[-1]
            writer=self.call(get,'private-scope-mutation-begin',self.observe(get),tag=None,
                extra={'X-UltraCache-Private-Transaction':'8'*64})
            self.assertEqual(self.drain(get,c,status=409)['reason'],'coverage-scope-changed')
            self.drain(get,c,'unknown')
            self.assertEqual(len(self.observe(get)['scopeMutations']),1)
            self.assertEqual(self.refused_recovery(get)['reason'],'scope-mutation-unsettled')
            done=self.call(get,'private-scope-mutation-commit',writer,tag=None,extra={
                'X-UltraCache-Private-Transaction':writer['transaction'],'X-UltraCache-Private-Lease':writer['lease'],
                'X-UltraCache-Private-Drained':'1'})
            self.call(get,'private-scope-mutation-ack',done,tag=None,extra={
                'X-UltraCache-Private-Transaction':done['transaction'],'X-UltraCache-Private-Lease':done['lease']})
            self.recover(get,self.observe(get));self.publish(get,self.observe(get))
            backend.post(get);self.ended(get);c=captured[-1]
            register(self,get,policy='d'*64)
            self.assertEqual(self.drain(get,c,status=409)['reason'],'coverage-unqualified')
            self.drain(get,c,'unknown');self.assertEqual(self.observe(get)['scopeState'],'unbound')

    def test_new_epoch_cannot_accept_an_old_qualified_completion_or_restore_old_authority(self):
        captured=[]
        def origin(path,headers):
            c=context(self,headers,'POST',path);captured.append(c)
            return 'actual',[('Cache-Control','private, no-store'),response_receipt(c)]
        with proxy('ultracache',origin,transform=backend.actor_hooks,allow_post=True) as get:
            register(self,get);self.ready(get);backend.post(get);old=self.ended(get)
        with proxy('ultracache',lambda p,h:('ordinary',[])) as get:
            register(self,get);current=self.observe(get)
            self.assertNotEqual(current['epoch'],old['epoch'])
            c=captured[0]
            self.call(get,'private-execution-drained',old,tag=None,expected_status=409,extra={
                'X-UltraCache-Private-Request-Id':c['requestId'],'X-UltraCache-Private-Challenge':c['challenge'],
                'X-UltraCache-Private-Drained':'1',**completion_headers(c)})
            self.assertEqual(self.observe(get)['scopeState'],'unbound')
            self.assertNotIn('generation',self.observe(get))

    def test_negotiation_is_explicit_and_malformed_or_default_declarations_do_not_enable_coverage(self):
        with proxy('ultracache',lambda p,h:('ordinary',[])) as get:
            authority.NativeReuseAuthority.register(self,get)
            self.assertNotIn('X-UltraCache-VCL-Public-Selection-Coverage-Version',control(get)[1])
            for extra in ({'X-UltraCache-Public-Selection-Coverage-Version':'1'},
                {'X-UltraCache-Public-Selection-Coverage-Policy':POLICY},
                {'X-UltraCache-Public-Selection-Coverage-Version':'2','X-UltraCache-Public-Selection-Coverage-Policy':POLICY}):
                self.assertEqual(control(get,extra=extra)[0],400)
            self.assertNotIn('coverageVersion',self.observe(get))

if __name__=='__main__':unittest.main()
