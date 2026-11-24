"""Actual native observation projections; mock producer, no SQL/admission claim."""
import hashlib
import json
import os
import shutil
import unittest

from test_cookie_delivery import proxy
from test_mutation_backend import NativeMutationBackend, actor_hooks, post, producer_context, receipt


@unittest.skipUnless(shutil.which('varnishd') and os.environ.get('SCP_EXPERIMENTAL_REUSE_TEST') == '1',
                     'Explicit matching-source native runtime required')
class NativeAuthorityObservation(unittest.TestCase):
    register = NativeMutationBackend.register
    call = NativeMutationBackend.call
    observe = NativeMutationBackend.observe
    recover = NativeMutationBackend.recover
    publish = NativeMutationBackend.publish
    ready = NativeMutationBackend.ready
    begin = NativeMutationBackend.begin
    commit = NativeMutationBackend.commit
    ended = NativeMutationBackend.ended

    def test_observation_domains_preserve_real_pending_authority(self):
        def origin(path, headers):
            context = producer_context(self, headers, 'POST', path)
            return 'actual response', [('Cache-Control', 'private, no-store'),
                                       ('X-UltraCache-Mutation-Receipt', receipt(context, 'none', ()))]

        with proxy('ultracache', origin, transform=actor_hooks, allow_post=True) as get:
            self.register(get)
            self.ready(get)
            self.assertEqual(post(get)[0], 200)
            self.assertEqual(post(get)[0], 200)
            full = self.ended(get)
            self.assertEqual(len(full['unsettledExecutions']), 2)
            transactions = [hashlib.sha256(label.encode()).hexdigest() for label in ('scope-A', 'scope-B')]
            first = self.call(get, 'private-scope-mutation-begin', full, tag=None,
                              extra={'X-UltraCache-Private-Transaction': transactions[0]})
            self.call(get, 'private-scope-mutation-begin', first, tag=None,
                      extra={'X-UltraCache-Private-Transaction': transactions[1]})

            identity = self.call(get, 'private-authority-context', tag=None,
                                 extra={'X-UltraCache-Private-Observation': 'identity'})
            self.assertEqual(identity['observation'], 'identity')
            self.assertNotIn('unsettledExecutions', identity)
            self.assertNotIn('scopeMutations', identity)
            self.assertEqual(identity['scopeState'], 'unbound')
            self.assertLess(len(json.dumps(identity)), 4096)

            marker = full['unsettledExecutions'][0]
            point = self.call(get, 'private-authority-context', tag=None, extra={
                'X-UltraCache-Private-Observation': 'execution',
                'X-UltraCache-Private-Request-Id': marker['requestId']})
            self.assertEqual(point['observationTarget'], marker['requestId'])
            self.assertEqual(point['unsettledExecutions'], [marker])
            self.assertNotIn('scopeMutations', point)
            missing = hashlib.sha256(b'absent-original').hexdigest()
            absent = self.call(get, 'private-authority-context', tag=None, extra={
                'X-UltraCache-Private-Observation': 'execution', 'X-UltraCache-Private-Request-Id': missing})
            self.assertEqual(absent['observationTarget'], missing)
            self.assertEqual(absent['unsettledExecutions'], [])
            self.assertEqual(absent['scopeState'], 'unbound')

            scope = self.call(get, 'private-authority-context', tag=None, extra={
                'X-UltraCache-Private-Observation': 'scope-transaction',
                'X-UltraCache-Private-Transaction': transactions[0]})
            self.assertEqual(scope['observationTarget'], transactions[0])
            self.assertEqual(len(scope['scopeMutations']), 1)
            self.assertEqual(scope['scopeMutations'][0]['transaction'], transactions[0])
            self.assertTrue(scope['scopeMutations'][0]['active'])
            self.assertNotIn('unsettledExecutions', scope)

            counted = self.call(get, 'private-authority-context', tag=None,
                                extra={'X-UltraCache-Private-Observation': 'quiescence'})
            self.assertEqual((counted['unsettledExecutionCount'], counted['scopeMutationCount'],
                              counted['activeScopeMutationCount']), (2, 2, 2))
            self.assertNotIn('unsettledExecutions', counted)
            self.assertNotIn('scopeMutations', counted)
            self.assertEqual(counted['scopeState'], 'unbound')

            self.call(get, 'private-authority-context', tag=None, expected_status=400,
                      extra={'X-UltraCache-Private-Observation': 'execution'})
            self.call(get, 'private-authority-context', tag=None, expected_status=400,
                      extra={'X-UltraCache-Private-Observation': 'invented'})
            current = self.observe(get)
            begun = self.call(get, 'private-mutation-begin', current, extra={
                'X-UltraCache-Private-Transaction': hashlib.sha256(b'compact-writer').hexdigest(),
                'X-UltraCache-Private-Observation': 'identity'})
            self.assertTrue(begun['active'])
            self.assertNotIn('unsettledExecutions', begun)
            self.assertNotIn('scopeMutations', begun)
            self.assertLess(len(json.dumps(begun)), 4096)
            unchanged = self.observe(get)
            self.assertEqual(len(unchanged['unsettledExecutions']), 2)
            self.assertEqual(len(unchanged['scopeMutations']), 2)
            self.assertEqual(unchanged['scopeState'], 'unbound')


if __name__ == '__main__':
    unittest.main()
