"""Removed hold/drain controls cannot mutate current event authority."""
import os
import shutil
import unittest

from test_cookie_delivery import proxy
from test_public_selection_runtime import control
from test_reuse_authority import NativeReuseAuthority


@unittest.skipUnless(shutil.which('varnishd') and os.environ.get('SCP_EXPERIMENTAL_REUSE_TEST') == '1',
                     'Matching-source native module required')
class RetiredHoldContracts(unittest.TestCase):
    register = NativeReuseAuthority.register
    ready = NativeReuseAuthority.ready
    observe = NativeReuseAuthority.observe
    publish = NativeReuseAuthority.publish
    call = NativeReuseAuthority.call

    def test_removed_operations_cannot_restore_or_suspend_current_authority(self):
        calls = []
        with proxy('ultracache', lambda p, h: (calls.append(p) or 'ordinary', [])) as get:
            self.register(get); before = self.ready(get)
            for operation in ('private-authority-recover', 'private-execution-drained',
                              'private-scope-mutation-begin', 'private-scope-mutation-commit',
                              'private-scope-mutation-ack'):
                with self.subTest(operation=operation):
                    reply = control(get, operation, extra={
                        'X-UltraCache-Private-Drained': '1',
                        'X-UltraCache-Private-Epoch': before['epoch'],
                        'X-UltraCache-Private-Scope-Revision': before['scopeRevision'],
                        'X-UltraCache-Private-Transaction': 'd' * 64})
                    self.assertEqual(reply[0], 400)
            after = self.observe(get)
            self.assertEqual((after['scopeRevision'], after['contentRevision'], after['generation']),
                             (before['scopeRevision'], before['contentRevision'], before['generation']))
            self.assertEqual(calls, [], 'Retired control requests cannot execute the application')


if __name__ == '__main__': unittest.main()
