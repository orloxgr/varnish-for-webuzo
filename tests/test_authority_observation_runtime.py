"""Current identity observation preserves real event authority without a census."""
import json
import os
import shutil
import unittest
from test_cookie_delivery import proxy
from test_reuse_authority import NativeReuseAuthority

@unittest.skipUnless(shutil.which('varnishd') and os.environ.get('SCP_EXPERIMENTAL_REUSE_TEST')=='1', 'Matching-source native module required')
class NativeAuthorityObservation(unittest.TestCase):
    register=NativeReuseAuthority.register
    call=NativeReuseAuthority.call
    observe=NativeReuseAuthority.observe
    publish=NativeReuseAuthority.publish
    ready=NativeReuseAuthority.ready
    begin=NativeReuseAuthority.begin

    def test_identity_observation_preserves_pending_event_without_global_execution_domains(self):
        with proxy('ultracache',lambda p,h:('ordinary',[])) as get:
            self.register(get);before=self.ready(get)
            writer=self.begin(get,before,'actual-owner-event')
            identity=self.call(get,'private-authority-context',extra={'X-UltraCache-Private-Observation':'identity'})
            self.assertEqual(identity['observation'],'identity')
            self.assertEqual((identity['state'],identity['remainingMutations'],identity['contentRevision']),('dirty',1,writer['contentRevision']))
            self.assertEqual(identity['scopeRevision'],before['scopeRevision'])
            for field in ('unsettledExecutions','scopeMutations','temporaryHolds','coverageState'):
                self.assertNotIn(field,identity)
            self.assertLess(len(json.dumps(identity)),4096)
            for obsolete in ('execution','scope-transaction','quiescence'):
                with self.subTest(observation=obsolete):
                    rejected=self.call(get,'private-authority-context',expected_status=400,extra={'X-UltraCache-Private-Observation':obsolete})
                    self.assertEqual(rejected['reason'],'invalid-observation')
            self.assertEqual(self.observe(get)['remainingMutations'],1)

if __name__=='__main__':unittest.main()
