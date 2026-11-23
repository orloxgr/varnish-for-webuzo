"""Actual native scope fencing; mock durable/drain attestations, not SQL proof.

Unsigned writes require an actual acknowledged scope fence before first SQL.
These actors do not claim coherence through a total control-channel outage.
"""
import hashlib
import os
import shutil
import threading
import unittest
from unittest import mock
import test_reuse_authority as authority
import test_mutation_backend as backend
from test_cookie_delivery import proxy
from test_public_selection_runtime import control

@unittest.skipUnless(shutil.which('varnishd') and os.environ.get('SCP_EXPERIMENTAL_REUSE_TEST')=='1',
    'Explicit matching-source experimental native module required')
class NativeScopeMutation(unittest.TestCase):
    register=authority.NativeReuseAuthority.register
    call=authority.NativeReuseAuthority.call
    observe=authority.NativeReuseAuthority.observe
    recover=authority.NativeReuseAuthority.recover
    publish=authority.NativeReuseAuthority.publish
    ready=authority.NativeReuseAuthority.ready
    ended=backend.NativeMutationBackend.ended
    drain=backend.NativeMutationBackend.drain

    def begin_scope(self,get,context,label,scope='/',status=200):
        return self.call(get,'private-scope-mutation-begin',context,scope=scope,tag=None,expected_status=status,
            extra={'X-UltraCache-Private-Transaction':hashlib.sha256(label.encode()).hexdigest()})
    def finish_scope(self,get,context,*,ack=False,scope='/',status=200,extra=None):
        headers={'X-UltraCache-Private-Transaction':context['transaction'],
            'X-UltraCache-Private-Lease':context['lease']}
        if not ack:headers['X-UltraCache-Private-Drained']='1'
        headers.update(extra or {})
        return self.call(get,'private-scope-mutation-ack' if ack else 'private-scope-mutation-commit',
            context,scope=scope,tag=None,expected_status=status,extra=headers)
    def recovery_refused(self,get,scope='/'):
        current=self.observe(get,scope)
        return self.call(get,'private-authority-recover',current,scope=scope,tag=None,expected_status=409,
            extra={'X-UltraCache-Private-Drained':'1'})

    def test_lost_begin_commit_ack_replies_never_reopen_or_grant_clean(self):
        with proxy('ultracache',lambda p,h:('ordinary',[])) as get:
            self.register(get);old=self.ready(get)
            self.assertEqual(old['scopeMutations'],[])
            begun=self.begin_scope(get,old,'unknown-raw-write')
            self.assertEqual(begun['transactionKind'],'scope');self.assertNotIn('tag',begun)
            self.assertNotEqual(begun['scopeRevision'],old['scopeRevision'])
            self.assertEqual((begun['scopeState'],begun['active']),('unbound',True))
            self.assertEqual(len(begun['scopeMutations']),1)
            self.call(get,'private-scope-mutation-begin',begun,tag=None,expected_status=400,extra={
                'X-UltraCache-Private-Transaction':begun['transaction'],'X-UltraCache-Private-Scope-Revision':''})
            replay=self.begin_scope(get,old,'unknown-raw-write')
            self.assertEqual((replay['lease'],replay['scopeRevision']),(begun['lease'],begun['scopeRevision']))
            self.assertEqual(self.recovery_refused(get)['reason'],'scope-mutation-unsettled')
            self.assertEqual(self.publish(get,self.observe(get),status=409)['reason'],'scope-unbound')
            self.assertEqual(self.finish_scope(get,begun,ack=True,status=409)['reason'],'mutation-active')
            self.finish_scope(get,begun,status=400,extra={'X-UltraCache-Private-Drained':'0'})
            self.finish_scope(get,begun,status=409,extra={'X-UltraCache-Private-Lease':'0'*64})
            done=self.finish_scope(get,begun)
            self.assertFalse(done['active']);self.assertEqual(done['scopeState'],'unbound')
            self.assertEqual(done['committedRevision'],done['scopeRevision'])
            self.assertEqual(self.finish_scope(get,begun)['scopeRevision'],done['scopeRevision'])
            retry=self.begin_scope(get,done,'unknown-raw-write')
            self.assertFalse(retry['active']);self.assertEqual(retry['scopeRevision'],done['scopeRevision'])
            self.assertEqual(self.recovery_refused(get)['reason'],'scope-mutation-unsettled')
            ack=self.finish_scope(get,done,ack=True)
            self.assertEqual(ack['scopeMutations'],[]);self.assertEqual(ack['scopeState'],'unbound')
            self.assertNotEqual(ack['scopeRevision'],retry['scopeRevision'])
            self.assertEqual(self.begin_scope(get,retry,'unknown-raw-write',status=409)['reason'],'scope-revision-changed')
            self.assertEqual(self.finish_scope(get,done,ack=True,status=409)['reason'],'unknown-lease')
            self.recover(get,self.observe(get));current=self.observe(get)
            self.assertEqual((current['scopeState'],current['state']),('ready','unbound'))
            self.assertNotIn('generation',current)
            fresh=self.publish(get,current,'e'*64)
            self.finish_scope(get,done,status=409)
            self.assertEqual(self.observe(get)['scopeRevision'],fresh['scopeRevision'])
            self.assertEqual(self.observe(get)['generation'],'e'*64)

    def test_overlapping_writers_cannot_recover_or_ack_each_other(self):
        with proxy('ultracache',lambda p,h:('ordinary',[])) as get:
            self.register(get);old=self.ready(get)
            a=self.begin_scope(get,old,'scope-A')
            self.begin_scope(get,old,'scope-B',status=409)
            b=self.begin_scope(get,self.observe(get),'scope-B')
            self.assertNotEqual(a['lease'],b['lease']);self.assertEqual(len(b['scopeMutations']),2)
            self.finish_scope(get,a,status=409,extra={'X-UltraCache-Private-Lease':b['lease']})
            # A's begin-time scope revision is now stale, but its real lease
            # still authorizes closing only A after independently proven drain.
            done_a=self.finish_scope(get,a)
            active=[w for w in done_a['scopeMutations'] if w['active']]
            self.assertEqual([w['transaction'] for w in active],[b['transaction']])
            self.finish_scope(get,done_a,ack=True)
            self.assertEqual(self.recovery_refused(get)['reason'],'scope-mutation-unsettled')
            done_b=self.finish_scope(get,b);self.finish_scope(get,done_b,ack=True)
            self.recover(get,self.observe(get))
            self.assertEqual(self.observe(get)['state'],'unbound')

    def test_tag_headers_bad_schema_foreign_scope_epoch_and_auth_are_rejected(self):
        with proxy('ultracache',lambda p,h:('ordinary',[])) as get:
            self.register(get,'/shop/');self.register(get,'/shop/sub/')
            old=self.ready(get,'/shop/');nested=self.ready(get,'/shop/sub/')
            tx='9'*64
            for operation in ('begin','commit','ack'):
                for tag in (authority.TAG,''):
                    self.call(get,'private-scope-mutation-'+operation,old,scope='/shop/',tag=tag,expected_status=400,
                        extra={'X-UltraCache-Private-Transaction':tx})
            for bad in ({},{'X-UltraCache-Private-Transaction':'invalid'}):
                self.call(get,'private-scope-mutation-begin',old,scope='/shop/',tag=None,expected_status=400,extra=bad)
            for field,reason in (('X-UltraCache-Private-Epoch','epoch-changed'),
                ('X-UltraCache-Private-Incarnation','incarnation-changed')):
                reply=self.call(get,'private-scope-mutation-begin',old,scope='/shop/',tag=None,expected_status=409,
                    extra={'X-UltraCache-Private-Transaction':tx,field:'0'*64})
                self.assertEqual(reply['reason'],reason)
            self.assertEqual(self.begin_scope(get,old,'foreign',scope='/shop/sub/',status=409)['reason'],'incarnation-changed')
            reply=control(get,'private-scope-mutation-begin',scope='/shop/',token=False,
                extra={'X-UltraCache-Private-Transaction':tx})
            self.assertEqual(reply[0],403)
            self.assertEqual(self.observe(get,'/shop/')['scopeRevision'],old['scopeRevision'])
            writer=self.begin_scope(get,old,'shop-only',scope='/shop/')
            self.assertEqual(self.observe(get,'/shop/sub/')['scopeRevision'],nested['scopeRevision'])
            self.assertEqual(self.observe(get,'/shop/sub/')['state'],'clean')
            self.finish_scope(get,writer,scope='/shop/sub/',status=409)
            done=self.finish_scope(get,writer,scope='/shop/');self.finish_scope(get,done,ack=True,scope='/shop/')

    def test_policy_disable_reenable_preserve_outstanding_scope_writers(self):
        with proxy('ultracache',lambda p,h:('ordinary',[])) as get:
            self.register(get);old=self.ready(get);writer=self.begin_scope(get,old,'old-policy')
            self.register(get,policy='f'*64)
            self.assertEqual(self.observe(get)['scopeMutations'][0]['lease'],writer['lease'])
            self.assertEqual(control(get,enabled=False)[0],200)
            self.register(get,policy='f'*64,wordpress_policy='e'*64)
            current=self.observe(get)
            self.assertEqual(current['incarnation'],writer['incarnation'])
            self.assertEqual(current['scopeMutations'][0]['transaction'],writer['transaction'])
            self.assertEqual(self.recovery_refused(get)['reason'],'scope-mutation-unsettled')
            done=self.finish_scope(get,writer);self.finish_scope(get,done,ack=True)
            self.recover(get,self.observe(get));self.assertEqual(self.observe(get)['state'],'unbound')

    def test_restart_has_new_unbound_epoch_and_refuses_old_scope_lease(self):
        with proxy('ultracache',lambda p,h:('ordinary',[])) as get:
            self.register(get);writer=self.begin_scope(get,self.ready(get),'retired-epoch')
        with proxy('ultracache',lambda p,h:('ordinary',[])) as get:
            self.register(get);new=self.observe(get)
            self.assertNotEqual(new['epoch'],writer['epoch']);self.assertEqual(new['scopeState'],'unbound')
            self.assertEqual(new['scopeMutations'],[])
            self.assertEqual(self.finish_scope(get,writer,status=409)['reason'],'epoch-changed')

    def test_scope_writer_cannot_clear_live_or_retained_signed_backend_execution(self):
        entered=threading.Event();release=threading.Event();errors=[]
        def origin(path,headers):
            context=backend.producer_context(self,headers,'POST',path)
            entered.set();self.assertTrue(release.wait(10))
            return 'actual response',[('Cache-Control','private, no-store'),
                ('X-UltraCache-Mutation-Receipt',backend.receipt(context,'none',()))]
        with proxy('ultracache',origin,transform=backend.actor_hooks,allow_post=True) as get:
            self.register(get);self.ready(get)
            def request():
                try:backend.post(get)
                except BaseException as error:errors.append(error)
            worker=threading.Thread(target=request);worker.start()
            try:
                self.assertTrue(entered.wait(10))
                writer=self.begin_scope(get,self.observe(get),'overlapping-CLI')
                self.assertEqual(self.recovery_refused(get)['reason'],'scope-mutation-unsettled')
                done=self.finish_scope(get,writer);self.finish_scope(get,done,ack=True)
                self.assertEqual(self.recovery_refused(get)['reason'],'execution-unsettled')
            finally:release.set();worker.join(timeout=15)
            self.assertFalse(worker.is_alive());self.assertEqual(errors,[])
            ended=self.ended(get);self.assertEqual(len(ended['unsettledExecutions']),1)
            self.assertEqual(self.recovery_refused(get)['reason'],'execution-unsettled')
            self.drain(get,ended,ended['unsettledExecutions'][0])
            self.recover(get,self.observe(get));self.assertEqual(self.observe(get)['state'],'unbound')

    def test_default_build_has_no_scope_mutation_authority(self):
        library=os.environ.get('SCP_TEST_COOKIE_DISABLED_MODULE')
        self.assertTrue(library,'Qualification must supply the actual default build')
        with mock.patch.dict(os.environ,{'SCP_TEST_COOKIE_MODULE':library}):
            with proxy('ultracache',lambda p,h:('ordinary',[])) as get:
                for operation in ('begin','commit','ack'):
                    self.assertEqual(control(get,'private-scope-mutation-'+operation)[0],501)

    def test_injected_constructor_or_identity_failure_leaves_scope_unbound_without_positive_ack(self):
        # The qualification harness separately compiles an OWNED altered source
        # copy. No production fault switch/header or product test hook exists.
        library=os.environ.get('SCP_TEST_SCOPE_FAULT_MODULE')
        self.assertTrue(library,'Explicit separately receipted fault build required')
        with mock.patch.dict(os.environ,{'SCP_TEST_COOKIE_MODULE':library}):
            with proxy('ultracache',lambda p,h:('ordinary',[])) as get:
                self.register(get)
                for transaction in ('f'*64,'e'*64):
                    old=self.ready(get)
                    failed=self.call(get,'private-scope-mutation-begin',old,tag=None,expected_status=503,
                        extra={'X-UltraCache-Private-Transaction':transaction})
                    self.assertFalse(failed['accepted']);self.assertEqual(failed['scopeMutations'],[])
                    current=self.observe(get)
                    self.assertEqual((current['state'],current['scopeState']),('unbound','unbound'))
                    self.assertNotEqual(current['scopeRevision'],old['scopeRevision'])
                    self.assertNotIn('generation',current)

if __name__=='__main__':unittest.main()
