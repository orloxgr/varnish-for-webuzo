"""Bundled data and rules stay coupled; former updater routes perform no work."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import engine
import recognition
import state


class RecognitionActions(unittest.TestCase):
    def test_old_worker_entrypoint_returns_truthful_bundled_status(self):
        entry=Path(__file__).resolve().parents[1]/'src/recognition.py'
        for args in ([],['--mode','daily'],['--mode','manual']):
            result=subprocess.run([sys.executable,'-I','-B',str(entry),*args],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            data=json.loads(result.stdout)
            self.assertTrue(data['bundled']);self.assertFalse(data['automatic'])
            self.assertEqual(data['result'],'bundled');self.assertNotIn('updating',data)
            self.assertGreater(data['records'],2000);self.assertGreater(data['rules'],2000)

    def test_admin_boundary_and_database_routes_never_enter_cache_transactions(self):
        with patch.object(engine,'inventory',side_effect=AssertionError('inventory')),patch.object(state,'locked',side_effect=AssertionError('cache lock')):
            for action,extra in (('recognition_status',{}),('recognition_configure',{'automatic':True}),('recognition_update',{})):
                for request in ({'action':action},{'actor':'customer','admin':True,'action':action},{'actor':'root','admin':True,'action':action,'url':'https://other.invalid'}):
                    with self.assertRaises(ValueError):engine.action(request)
                result=engine.action(dict(actor='root',admin=True,action=action,**extra))
                self.assertEqual(result['cookie_recognition']['result'],'bundled')
                self.assertIn('Update the plugin',result['message'])


@unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid()==0,'Linux/root isolated ownership')
class RecognitionSchedule(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir='/var/lib',prefix='wvw-bundled-')
        self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.service=self.root/'updater@.service';self.timer=self.root/'updater.timer'
        self.enterContext(patch.object(recognition,'SERVICE',self.service))
        self.enterContext(patch.object(recognition,'TIMER',self.timer))
        self.run=self.enterContext(patch.object(recognition.native,'run',return_value=''))

    def test_fresh_activation_creates_no_schedule_or_download_state(self):
        recognition.install()
        self.assertEqual(list(self.root.iterdir()),[]);self.run.assert_not_called()

    def test_only_the_owned_retired_scheduler_is_removed(self):
        self.service.write_text('Description=Update cookie recognition data for Varnish for Webuzo\nExecStart=/usr/bin/python3 -I -B "'+str(recognition.ENTRY)+'" --mode %i\n')
        self.timer.write_text('Description=Daily cookie recognition update for Varnish for Webuzo\nUnit='+recognition.DAILY+'\n')
        retained=self.root/'old-snapshot.json';retained.write_text('{"records":[{"name":"unreviewed"}]}')
        recognition.install()
        self.assertFalse(self.service.exists());self.assertFalse(self.timer.exists())
        self.assertTrue(retained.exists())
        self.assertEqual([c.args for c in self.run.call_args_list],[('systemctl','disable','--now',self.timer.name),('systemctl','stop',recognition.DAILY,recognition.MANUAL),('systemctl','daemon-reload')])

    def test_changed_unit_is_not_stopped_or_deleted(self):
        self.timer.write_text('Administrator-owned unrelated unit')
        with self.assertRaises(ValueError):recognition.install()
        self.assertTrue(self.timer.exists());self.run.assert_not_called()

    def test_database_uses_bundled_data_without_reading_old_download_state(self):
        bundled=self.root/'bundled.json';bundled.write_text('{"revision":"reviewed","records":[{"name":"reviewed"}]}')
        (self.root/'snapshot.json').write_text('{"revision":"downloaded","records":[{"name":"not-reviewed"}]}')
        with patch.object(recognition,'BUNDLED',bundled):
            self.assertEqual(recognition.database(),{'revision':'reviewed','records':[{'name':'reviewed'}]})


if __name__=='__main__':unittest.main()
