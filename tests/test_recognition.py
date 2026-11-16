"""Recognition updates cannot reach cache transactions or arbitrary services."""
import copy
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import engine
import lifecycle
import recognition
import state


class RecognitionActions(unittest.TestCase):
    def test_real_isolated_entrypoint_imports_its_modules_before_rejecting_invalid_mode(self):
        entry = Path(__file__).resolve().parents[1] / 'src/recognition.py'
        result = subprocess.run([sys.executable, '-I', '-B', str(entry), '--mode', 'invalid'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, '')
        self.assertIn('Invalid recognition update mode', result.stdout)

    def test_admin_only_and_no_arbitrary_url_or_command_input(self):
        for action in ('recognition_status', 'recognition_configure', 'recognition_update'):
            with self.subTest(action=action), patch.object(recognition, 'start_update') as start:
                for request in ({'action': action}, {'actor': 'customer', 'admin': True, 'action': action},
                                {'actor': 'root', 'admin': False, 'action': action},
                                {'actor': 'root', 'admin': True, 'action': action, 'url': 'https://other.invalid'}):
                    with self.assertRaises(ValueError): engine.action(request)
                start.assert_not_called()

    def test_recognition_actions_never_enter_site_lock_or_inventory(self):
        actions = [('recognition_status', {}, 'status'),
                   ('recognition_configure', {'automatic': False}, 'configure'),
                   ('recognition_update', {}, 'start_update')]
        with (patch.object(engine, 'inventory', side_effect=AssertionError('inventory')),
             patch.object(state, 'locked', side_effect=AssertionError('cache lock')),
             patch.object(engine, 'apply', side_effect=AssertionError('cache transaction'))):
            for action, extra, function in actions:
                with self.subTest(action=action), patch.object(recognition, function, return_value={'automatic': False}) as run:
                    result = engine.action(dict(actor='root', admin=True, action=action, **extra))
                    self.assertEqual(result['cookie_recognition'], {'automatic': False})
                    run.assert_called_once_with(*([False] if function == 'configure' else []))


@unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid() == 0, 'Linux/root fixture')
class RecognitionSchedule(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir='/var/lib', prefix='wvw-recognition-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.directory = self.root / 'recognition'
        self.service = self.root / 'updater@.service'; self.timer = self.root / 'updater.timer'
        for target, name, value in ((state, 'ROOT', self.root), (recognition, 'DIRECTORY', self.directory),
                                    (recognition, 'SERVICE', self.service), (recognition, 'TIMER', self.timer)):
            self.enterContext(patch.object(target, name, value))
        self.data = {'automatic': True, 'records': 1, 'result': 'bundled'}
        self.enterContext(patch.object(recognition.cookie_recognition, 'status', side_effect=lambda *a: copy.deepcopy(self.data)))
        self.configure = self.enterContext(patch.object(recognition.cookie_recognition, 'configure', side_effect=self.save))
        self.run = self.enterContext(patch.object(recognition.native, 'run', side_effect=self.command))

    def save(self, directory, bundled, automatic):
        self.data['automatic'] = automatic

    def command(self, *args):
        if 'UnitFileState' in ' '.join(args): return 'enabled\n' if self.data['automatic'] else 'disabled\n'
        if 'show' in args: return 'ActiveState=inactive\nJob=0\nResult=success\nExecMainStatus=0\n'
        return ''

    def test_activation_uses_only_owned_daily_timer_and_no_download(self):
        with patch.object(recognition.cookie_recognition, 'update') as update:
            recognition.install()
        update.assert_not_called()
        self.assertIn('OnCalendar=daily', self.timer.read_text())
        self.assertIn('Persistent=true', self.timer.read_text())
        self.assertIn('--mode %i', self.service.read_text())
        self.assertIn('ProtectSystem=strict', self.service.read_text())
        self.assertEqual(self.timer.stat().st_mode & 0o777, 0o644)
        self.assertTrue(self.directory.is_dir())
        self.assertIn(('systemctl', 'enable', '--now', self.timer.name), [c.args for c in self.run.call_args_list])

    def test_disable_keeps_snapshot_and_manual_update_runs_async(self):
        recognition.install(); marker = self.directory / 'last-good'; marker.write_text('retained')
        result = recognition.configure(False); self.assertFalse(result['automatic'])
        result = recognition.start_update(); self.assertTrue(result['updating'])
        self.assertEqual(marker.read_text(), 'retained')
        self.assertIn(('systemctl', 'start', '--no-block', recognition.MANUAL), [c.args for c in self.run.call_args_list])

    def test_worker_forces_only_manual_updates_and_rejects_unknown_modes(self):
        for mode, forced in (('daily', False), ('manual', True)):
            with self.subTest(mode=mode), patch.object(recognition.cookie_recognition, 'update') as update:
                recognition.run(mode)
                update.assert_called_once_with(self.directory, recognition.BUNDLED, force=forced)
        with patch.object(recognition.cookie_recognition, 'update') as update, self.assertRaises(ValueError):
            recognition.run('unrelated')
        update.assert_not_called()

    def test_changed_unit_is_not_started_replaced_or_removed(self):
        self.timer.write_text('administrator configuration')
        for action in (recognition.install, recognition.start_update, recognition.remove):
            with self.subTest(action=action), self.assertRaises(ValueError): action()
        self.assertEqual(self.timer.read_text(), 'administrator configuration')
        self.run.assert_not_called()

    def test_schedule_failure_restores_previous_automatic_preference(self):
        with patch.object(recognition, 'install', side_effect=RuntimeError('systemd failed')):
            with self.assertRaises(RuntimeError): recognition.configure(False)
        self.assertTrue(self.data['automatic'])
        self.assertEqual([c.args[-1] for c in self.configure.call_args_list], [False, True])

    def test_uninstall_stops_only_owned_units_and_retains_last_good(self):
        recognition.install(); marker = self.directory / 'last-good'; marker.write_text('retained')
        recognition.remove()
        self.assertFalse(self.service.exists()); self.assertFalse(self.timer.exists())
        self.assertEqual(marker.read_text(), 'retained')
        self.assertIn(('systemctl', 'stop', recognition.DAILY, recognition.MANUAL), [c.args for c in self.run.call_args_list])

    def test_failed_worker_is_visible_and_newer_success_does_not_keep_stale_error(self):
        recognition.install()
        failed = dict(running=False, finished=10, result='exit-code', exit_status='1')
        succeeded = dict(running=False, finished=20, result='success', exit_status='0')
        with patch.object(recognition, 'worker_state', side_effect=[succeeded, failed]):
            self.assertEqual(recognition.status()['worker_error'], '')
        with patch.object(recognition, 'worker_state', side_effect=[failed, dict(succeeded, finished=0)]):
            self.assertIn('exit-code', recognition.status()['worker_error'])


if __name__ == '__main__': unittest.main()
