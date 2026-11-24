"""Real native transaction GC; mock signed V2 producer, no PHP/SQL drain claim."""
import os
import shutil
import threading
import unittest

import test_mutation_backend as backend
import test_mutation_coverage_runtime as coverage
from test_cookie_delivery import proxy
from test_reuse_authority import NativeReuseAuthority, TAG


@unittest.skipUnless(shutil.which('varnishd') and os.environ.get('SCP_EXPERIMENTAL_REUSE_TEST') == '1',
                     'Matching-source experimental native module required')
class NativeMutationReceiptOwners(unittest.TestCase):
    call = NativeReuseAuthority.call
    observe = NativeReuseAuthority.observe
    ready = NativeReuseAuthority.ready
    recover = NativeReuseAuthority.recover
    publish = NativeReuseAuthority.publish
    commit = NativeReuseAuthority.commit

    def begin_bound(self, get, origin):
        return self.call(get, 'private-mutation-begin', self.observe(get), extra={
            'X-UltraCache-Private-Transaction': '8' * 64,
            'X-UltraCache-Private-Request-Id': origin['requestId'],
            'X-UltraCache-Private-Challenge': origin['challenge']})

    def ack(self, get, done, status=200):
        return self.call(get, 'private-mutation-ack', self.observe(get), expected_status=status, extra={
            'X-UltraCache-Private-Transaction': done['transaction'],
            'X-UltraCache-Private-Lease': done['lease']})

    def request(self, get, path, result, errors):
        try:
            result.append(backend.post(get, path))
        except BaseException as error:
            errors.append(error)

    def test_exact_late_dirty_receipt_blocks_gc_and_cannot_reopen_completed_writer(self):
        entered = threading.Event(); release = threading.Event()
        originals = []; results = []; errors = []
        def origin(path, headers):
            original = coverage.context(self, headers, 'POST', path)
            originals.append(original); entered.set()
            self.assertTrue(release.wait(10))
            return 'actual business response', [('Cache-Control', 'private, no-store'),
                coverage.response_receipt(original, 'dirty', [(TAG, done['transaction'])])]
        with proxy('ultracache', origin, transform=backend.actor_hooks, allow_post=True) as get:
            coverage.register(self, get); self.ready(get)
            worker = threading.Thread(target=self.request, args=(get, '/__owned_mutation', results, errors))
            worker.start()
            try:
                self.assertTrue(entered.wait(10))
                begun = self.begin_bound(get, originals[0])
                self.assertEqual((begun['requestId'], begun['challenge']),
                                 (originals[0]['requestId'], originals[0]['challenge']))
                done = self.commit(get, begun)
                self.assertEqual(self.ack(get, done, 409)['reason'], 'receipt-outstanding')
            finally:
                release.set(); worker.join(timeout=15)
            self.assertFalse(worker.is_alive()); self.assertEqual(errors, [])
            self.assertEqual((results[0][0], results[0][2]), (200, b'actual business response'))
            self.assertEqual(dict(results[0][1]).get('X-Actor-Receipt-Verified'), '1')
            self.assertEqual(self.observe(get)['remainingMutations'], 0)
            self.assertEqual(self.ack(get, done)['reason'], 'mutation-acknowledged')
            self.assertEqual(self.observe(get)['remainingMutations'], 0)

    def test_unrelated_overlapping_v2_actor_does_not_block_gc_or_resurrect_retired_pair(self):
        entered = [threading.Event(), threading.Event()]
        release = [threading.Event(), threading.Event()]
        originals = {}; results = [[], []]; errors = []
        def origin(path, headers):
            actor = int(path.rsplit('/', 1)[1])
            original = coverage.context(self, headers, 'POST', path)
            originals[actor] = original; entered[actor].set()
            self.assertTrue(release[actor].wait(10))
            # Actor 1 deliberately sends a correctly signed stale DIRTY pair
            # after GC. It is no longer an admitted native transaction.
            return 'actual actor ' + str(actor), [('Cache-Control', 'private, no-store'),
                coverage.response_receipt(original, 'dirty', [(TAG, done['transaction'])])]
        with proxy('ultracache', origin, transform=backend.actor_hooks, allow_post=True) as get:
            coverage.register(self, get); self.ready(get)
            workers = [threading.Thread(target=self.request,
                args=(get, '/__owned_mutation/' + str(actor), results[actor], errors)) for actor in range(2)]
            workers[0].start()
            try:
                self.assertTrue(entered[0].wait(10))
                begun = self.begin_bound(get, originals[0]); done = self.commit(get, begun)
                workers[1].start(); self.assertTrue(entered[1].wait(10))
                self.assertEqual(self.ack(get, done, 409)['reason'], 'receipt-outstanding')
                release[0].set(); workers[0].join(timeout=15)
                self.assertFalse(workers[0].is_alive()); self.assertEqual(errors, [])
                self.assertEqual(dict(results[0][0][1]).get('X-Actor-Receipt-Verified'), '1')
                still_running = self.observe(get)
                self.assertTrue(any(row['requestId'] == originals[1]['requestId'] and row['live']
                                    and row['awaitingReceipt'] for row in still_running['unsettledExecutions']))
                self.assertEqual(self.ack(get, done)['reason'], 'mutation-acknowledged')
                self.assertEqual(self.observe(get)['remainingMutations'], 0)
                self.assertGreater(self.observe(get)['temporaryHolds'], 0, 'GC is not an execution-drain grant')
            finally:
                for gate in release: gate.set()
                for worker in workers:
                    if worker.ident is not None: worker.join(timeout=15)
            self.assertTrue(all(not worker.is_alive() for worker in workers)); self.assertEqual(errors, [])
            self.assertEqual((results[1][0][0], results[1][0][2]), (200, b'actual actor 1'))
            self.assertNotIn('X-Actor-Receipt-Verified', dict(results[1][0][1]))
            current = self.observe(get)
            self.assertEqual((current['remainingMutations'], current['scopeState']), (0, 'unbound'))
            self.assertTrue(any(row['requestId'] == originals[1]['requestId'] and row['unknown']
                                for row in current['unsettledExecutions']))


if __name__ == '__main__':
    unittest.main()
