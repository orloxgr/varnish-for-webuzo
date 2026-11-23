"""Actual native namespace/CAS recovery, with mock producer drain proofs."""
import os
import shutil
import unittest
from unittest import mock
import test_reuse_authority as authority
import test_scope_mutation as scope_actor
from test_cookie_delivery import proxy

@unittest.skipUnless(shutil.which('varnishd') and os.environ.get('SCP_EXPERIMENTAL_REUSE_TEST')=='1','Matching native source required')
class NativeRecoveryRevision(unittest.TestCase):
    register=authority.NativeReuseAuthority.register
    call=authority.NativeReuseAuthority.call
    observe=authority.NativeReuseAuthority.observe
    recover=authority.NativeReuseAuthority.recover
    publish=authority.NativeReuseAuthority.publish
    ready=authority.NativeReuseAuthority.ready
    begin_scope=scope_actor.NativeScopeMutation.begin_scope
    finish_scope=scope_actor.NativeScopeMutation.finish_scope

    def test_initial_recovery_preserves_observed_fresh_revision_without_granting_tag_generation(self):
        with proxy('ultracache',lambda p,h:('ordinary',[])) as get:
            self.register(get);fresh=self.observe(get)
            recovered=self.recover(get,fresh)
            self.assertEqual((recovered['scopeState'],recovered['scopeRevision']),('ready',fresh['scopeRevision']))
            self.assertEqual(self.observe(get)['state'],'unbound')
            self.assertNotIn('generation',self.observe(get))
            self.assertEqual(self.recover(get,fresh)['scopeRevision'],fresh['scopeRevision'])

    def test_completed_scope_fence_survives_recovery_and_stale_cas_replays_still_fail(self):
        with proxy('ultracache',lambda p,h:('ordinary',[])) as get:
            self.register(get);old=self.ready(get)
            writer=self.begin_scope(get,old,'namespace-write')
            done=self.finish_scope(get,writer)
            before_gc=self.begin_scope(get,done,'namespace-write')
            ack=self.finish_scope(get,done,ack=True)
            self.assertNotEqual(ack['scopeRevision'],before_gc['scopeRevision'])
            fresh=self.observe(get);self.assertNotEqual(fresh['scopeRevision'],old['scopeRevision'])
            self.assertEqual(self.recover(get,fresh)['scopeRevision'],fresh['scopeRevision'])
            current=self.observe(get)
            self.assertEqual((current['scopeState'],current['state']),('ready','unbound'))
            self.assertNotIn('generation',current)
            self.assertEqual(self.begin_scope(get,before_gc,'namespace-write',status=409)['reason'],'scope-revision-changed')
            self.assertEqual(self.publish(get,old,status=409)['reason'],'scope-revision-changed')
            self.assertEqual(self.call(get,'private-authority-recover',old,tag=None,expected_status=409,
                extra={'X-UltraCache-Private-Drained':'1'})['reason'],'scope-revision-changed')
            self.assertEqual(self.finish_scope(get,done,status=409)['reason'],'unknown-lease')
            self.publish(get,current,'e'*64)
            self.assertEqual(self.observe(get)['scopeRevision'],fresh['scopeRevision'])

    def test_failed_revision_never_exposes_old_namespace_and_successful_reobservation_only_repairs_fence(self):
        library=os.environ.get('SCP_TEST_SCOPE_FAULT_MODULE');self.assertTrue(library)
        with mock.patch.dict(os.environ,{'SCP_TEST_COOKIE_MODULE':library}):
            with proxy('ultracache',lambda p,h:('ordinary',[])) as get:
                self.register(get);old=self.ready(get)
                failed=self.call(get,'private-scope-mutation-begin',old,tag=None,expected_status=503,
                    extra={'X-UltraCache-Private-Transaction':'d'*64})
                self.assertEqual(failed['scopeState'],'unbound');self.assertEqual(failed['scopeRevision'],'')
                self.assertNotIn('generation',failed)
                still_unavailable=self.call(get,'private-authority-context',expected_status=503)
                self.assertEqual(still_unavailable['reason'],'scope-revision-unavailable')
                self.assertEqual(still_unavailable['scopeRevision'],'')
                repaired=self.observe(get)
                self.assertNotEqual(repaired['scopeRevision'],old['scopeRevision'])
                self.assertEqual((repaired['scopeState'],repaired['state']),('unbound','unbound'))
                self.assertNotIn('generation',repaired)
                self.assertEqual(self.recover(get,repaired)['scopeRevision'],repaired['scopeRevision'])
                self.assertEqual(self.observe(get)['state'],'unbound','RNG repair plus READY cannot resurrect old bound tags')

if __name__=='__main__':unittest.main()
