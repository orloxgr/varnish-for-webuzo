"""Actual native HTTP diagnostics with the existing controlled signed producer."""
import os
import shutil
import subprocess
import unittest

from test_delivery_continuation import PARENT
from test_event_invalidation_runtime import NativeEventInvalidation


@unittest.skipUnless(shutil.which('varnishd') and os.environ.get('SCP_EXPERIMENTAL_REUSE_TEST') == '1',
                     'Matching-source native module required')
class NativeFinalizationDiagnostics(unittest.TestCase):
    def trace(self, get):
        raw = subprocess.check_output(['varnishlog', '-n', str(get.instance), '-d', '-g', 'raw', '-i', 'Debug'], text=True)
        messages = [line.split('uc-reuse', 1)[1].removesuffix('%00"')
                    for line in raw.splitlines() if 'uc-reuse finalization=' in line]
        for message in messages:
            self.assertRegex(message, r'^ finalization=(?:accepted|declined) reason=[a-z0-9-]+ status=[0-9]{3}$')
            self.assertNotIn('owner=', message)
            self.assertNotRegex(message, r'[0-9a-f]{32}')
        return messages

    def test_actual_declined_finalization_is_explained_and_recovery_still_reuses(self):
        declined = [False]
        def observer(path, headers):
            if declined[0] and headers.get('X-UltraCache-Delivery-Phase') == 'reuse-finalize':
                return 204, '', [('Cache-Control', 'private, no-store'),
                                 ('X-UltraCache-Delivery-Reuse-Outcome', 'declined')]
            return None
        actor = NativeEventInvalidation()
        with actor.actor(source_response=observer) as (get, calls, versions, _, _, _, _):
            writer = actor.begin(get, actor.observe(get), 'diagnostic-content-write')
            actor.commit(get, writer); versions['A'] = 2; declined[0] = True; calls.clear()
            status, _, original = get(PARENT, 'owner=A')
            self.assertEqual(status, 200); self.assertIn('private:A-v2', original)
            self.assertEqual(calls, [(PARENT, 'prepare'), (PARENT, 'reuse-finalize')])
            messages = self.trace(get)
            self.assertTrue(any('finalization=accepted reason=accepted status=200' in v for v in messages), messages)
            self.assertTrue(any('finalization=declined reason=' in v for v in messages), messages)
            declined[0] = False; calls.clear()
            self.assertEqual(get(PARENT, 'owner=A')[2], original)
            self.assertEqual(calls, [(PARENT, 'prepare'), (PARENT, 'reuse-finalize')],
                             'A declined publication must not become a reusable admission')
            calls.clear(); self.assertEqual(get(PARENT, 'owner=A')[2], original)
            self.assertEqual(calls, [], 'The recovered complete plan still reuses without origin')

    def test_diagnostics_remain_masked_by_default_with_complete_hits_unchanged(self):
        actor = NativeEventInvalidation()
        with actor.actor() as (get, calls, _, bodies, _, _, _):
            calls.clear(); self.assertEqual(get(PARENT, 'owner=A')[2], bodies['A'])
            self.assertEqual(calls, [])
            self.assertEqual(self.trace(get), [], 'No finalization Debug record under the normal default mask')
