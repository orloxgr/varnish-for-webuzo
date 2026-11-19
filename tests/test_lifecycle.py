"""Native addon updates activate current policy without implicit fresh setup."""
import fcntl
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import engine
import lifecycle
import recognition
import repository
import service
import state
import cache_size


@unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid()==0,'Native Linux/root lifecycle')
class NativeActivation(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir='/var/lib',prefix='wvw-lifecycle-')
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.enterContext(patch.object(state,'ROOT',self.root/'state'))
        self.enterContext(patch.object(state,'RUN',self.root/'run'))
        self.enterContext(patch.object(lifecycle,'TMP',self.root/'tmp.conf'))
        state.mkdir(state.ROOT)
        self.enterContext(patch.object(cache_size,'recover'))
        self.modules=self.enterContext(patch.object(repository,'ensure_cookie_modules'))
        self.handoff=self.enterContext(patch.object(repository,'ensure_cookie_handoff'))
        self.features=self.enterContext(patch.object(service,'configure_esi'))
        self.recognition=self.enterContext(patch.object(recognition,'install'))
        self.retirement=self.enterContext(patch.object(lifecycle,'retire_cms_helper'))

    def test_fresh_activation_provisions_panel_without_installing_service(self):
        with patch.object(engine,'action') as action:lifecycle.install()
        action.assert_not_called();self.modules.assert_not_called();self.handoff.assert_not_called();self.features.assert_not_called()
        self.recognition.assert_called_once()
        self.retirement.assert_called_once()

    def test_existing_service_reconciles_after_provisioning_lock_is_released(self):
        state.save(state.ROOT/'settings.json',{'installed':True})
        def reconcile(request):
            self.assertEqual(request,dict(actor='root',admin=True,action='reconcile',refresh_cms=True))
            self.recognition.assert_called_once()
            with (state.ROOT/'operation.lock').open() as lock:
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                fcntl.flock(lock,fcntl.LOCK_UN)
        with patch.object(engine,'action',side_effect=reconcile) as action:lifecycle.install()
        action.assert_called_once();self.modules.assert_called_once();self.handoff.assert_called_once();self.features.assert_called_once()

    def test_failed_existing_policy_apply_is_reported_to_installer(self):
        state.save(state.ROOT/'settings.json',{'installed':True})
        before=(state.ROOT/'settings.json').read_bytes()
        with patch.object(engine,'action',side_effect=RuntimeError('Existing application policy is incompatible')):
            with self.assertRaisesRegex(RuntimeError,'application policy is incompatible'):lifecycle.install()
        self.assertEqual((state.ROOT/'settings.json').read_bytes(),before)
        self.retirement.assert_not_called()


if __name__=='__main__':unittest.main()
