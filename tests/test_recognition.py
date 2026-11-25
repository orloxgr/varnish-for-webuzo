"""Bundled descriptions remain available; only the owned old scheduler retires."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import recognition
import native_test_accounts


@unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid()==0,'Linux/root isolated ownership')
class RecognitionSchedule(unittest.TestCase):
    def setUp(self):
        native_test_accounts.install(self)
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
