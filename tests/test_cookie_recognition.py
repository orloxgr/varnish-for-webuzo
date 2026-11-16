"""Upstream metadata updates are independent from cache policy and service state."""
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'shared'))
import cookie_recognition as recognition

REVISION = 'a' * 40
LICENSE = b'Apache License\nVersion 2.0, January 2004\n'


def fixture(name='new_cookie', category='Functional'):
    output = io.StringIO(newline='')
    writer = csv.writer(output)
    writer.writerow(recognition.FIELDS)
    writer.writerow(['id', 'Provider', category, name, '', '90 days', '0'])
    return output.getvalue().encode()


class ParseRecognition(unittest.TestCase):
    def test_upstream_names_and_categories_remain_descriptive(self):
        entry = recognition.parse_csv(fixture('odd.storage*', 'New category'))[0]
        self.assertEqual(entry['name'], 'odd.storage*')
        self.assertEqual(entry['category'], 'New category')
        self.assertFalse(entry['wildcard'])

    def test_incomplete_empty_and_invalid_csv_are_rejected(self):
        for data in (b'bad,columns\n', ','.join(recognition.FIELDS).encode(), fixture().replace(b'90 days,0', b'90 days,unknown')):
            with self.assertRaises(ValueError):
                recognition.parse_csv(data)

    def test_real_empty_provider_and_unicode_are_retained(self):
        data = fixture('XSRF-TOKEN').replace(b'Provider', b'')
        self.assertEqual(recognition.parse_csv(data)[0]['provider'], '')
        self.assertEqual(recognition.parse_csv(fixture('δοκιμή'))[0]['name'], 'δοκιμή')

    def test_duplicate_columns_controls_bad_utf8_and_unclosed_quote_are_rejected(self):
        payloads = [fixture().replace(b'ID,Platform', b'ID,ID'), fixture().replace(b'Provider',b'Pro\x00vider'),
                    fixture().replace(b'Provider',b'\xff'), fixture() + b'"unclosed\n']
        for data in payloads:
            with self.assertRaises((ValueError,csv.Error)):
                recognition.parse_csv(data)

    def test_upstream_input_bounds_are_enforced(self):
        with patch.object(recognition,'MAX_CSV_BYTES',10), self.assertRaises(ValueError):
            recognition.parse_csv(fixture())
        with patch.object(recognition,'MAX_RECORDS',0), self.assertRaises(ValueError):
            recognition.parse_csv(fixture())
        with patch.object(recognition,'MAX_FIELD_CHARACTERS',100), self.assertRaises(csv.Error):
            recognition.parse_csv(fixture('x'*101))

    def test_redirect_and_unapproved_endpoint_are_refused(self):
        with self.assertRaises(ValueError):
            recognition.NoRedirect().redirect_request(None,None,302,'',{},'https://other.example/data')
        with patch.object(recognition.urllib.request,'build_opener') as opener:
            for url in ('http://api.github.com/', recognition.RAW+'master/open-cookie-database.csv', 'https://other.example/data'):
                with self.assertRaises(ValueError):
                    recognition.fetch(url)
            opener.assert_not_called()

    def test_streamed_byte_limit_does_not_trust_content_length(self):
        response = io.BytesIO(b'oversized')
        response.geturl = lambda: recognition.HEAD
        with patch.object(recognition,'MAX_METADATA_BYTES',4), \
             patch.object(recognition.urllib.request,'build_opener') as opener:
            opener.return_value.open.return_value = response
            with self.assertRaises(ValueError):
                recognition.fetch(recognition.HEAD)

    def test_column_amplification_is_rejected_before_row_arrays_exist(self):
        for data in (b',' * 128, fixture() + b'Unquoted"' + b',' * 128):
            with patch.object(recognition.csv,'DictReader') as reader:
                with self.assertRaisesRegex(ValueError,'128-column'):
                    recognition.parse_csv(data)
                reader.assert_not_called()

    def test_column_scan_preserves_quoted_commas_newlines_and_escaped_quotes(self):
        name = 'name,"quote"\n' + ',' * 256
        self.assertEqual(recognition.parse_csv(fixture(name))[0]['name'],name)
        output = io.StringIO(newline='')
        writer = csv.writer(output)
        extra = recognition.MAX_COLUMNS - len(recognition.FIELDS)
        writer.writerow([*recognition.FIELDS,*('extra'+str(i) for i in range(extra))])
        writer.writerow(['id','Provider','Functional','name','','90 days','0',*('' for _ in range(extra))])
        self.assertEqual(len(recognition.parse_csv(output.getvalue().encode())),1)


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0, 'Root-owned Linux updater state')
class RecognitionUpdates(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)/'state'
        self.bundled = ROOT/'shared/cookie-recognition/recognition.json'
        self.policy_hash = hashlib.sha256((ROOT/'shared/cookie-policies.json').read_bytes()).hexdigest()
        self.template_hash = hashlib.sha256((ROOT/'shared/cache-policy.vcl').read_bytes()).hexdigest()

    def download(self, url):
        if url == recognition.HEAD:
            return json.dumps({'sha': REVISION}).encode()
        if url == recognition.RAW + REVISION + '/LICENSE':
            return LICENSE
        self.assertEqual(url, recognition.RAW + REVISION + '/open-cookie-database.csv')
        return fixture()

    def update(self, **kwargs):
        with patch.object(recognition, 'fetch', side_effect=self.download):
            return recognition.update(self.directory, self.bundled, **kwargs)

    def test_bundled_snapshot_has_no_network_on_status(self):
        with patch.object(recognition, 'fetch') as fetch:
            status = recognition.status(self.directory, self.bundled)
        self.assertTrue(status['automatic'])
        self.assertTrue(status['bundled'])
        self.assertGreater(status['records'], 2000)
        fetch.assert_not_called()
        self.assertFalse(self.directory.exists())

    def test_valid_update_is_persistent_local_and_does_not_change_vcl(self):
        result = self.update()
        self.assertEqual(result['result'], 'updated')
        self.assertEqual(result['revision'], REVISION)
        self.assertEqual(result['records'], 1)
        self.assertEqual(result['sha256'], hashlib.sha256(fixture()).hexdigest())
        self.assertIsNotNone(result['last_success'])
        self.assertFalse(result['bundled'])
        data = recognition.database(self.directory, self.bundled)
        self.assertFalse(data['executable'])
        self.assertIn('Apache License', data['license_text'])
        self.assertEqual(data['records'][0]['name'], 'new_cookie')
        self.assertEqual(self.policy_hash, hashlib.sha256((ROOT/'shared/cookie-policies.json').read_bytes()).hexdigest())
        self.assertEqual(self.template_hash, hashlib.sha256((ROOT/'shared/cache-policy.vcl').read_bytes()).hexdigest())

    def test_unchanged_revision_avoids_redownloading_database(self):
        self.update()
        with patch.object(recognition, 'fetch', return_value=json.dumps({'sha':REVISION}).encode()) as fetch:
            result = recognition.update(self.directory, self.bundled)
        self.assertEqual(result['result'], 'unchanged')
        fetch.assert_called_once_with(recognition.HEAD)

    def test_daily_disabled_but_manual_update_available(self):
        recognition.configure(self.directory, self.bundled, False)
        with patch.object(recognition, 'fetch') as fetch:
            recognition.update(self.directory, self.bundled)
        fetch.assert_not_called()
        result = self.update(force=True)
        self.assertEqual(result['result'], 'updated')
        self.assertFalse(result['automatic'])
        recognition.configure(self.directory, self.bundled, True)
        self.assertEqual(recognition.status(self.directory,self.bundled)['revision'], REVISION)

    def test_failures_keep_last_good_data_and_success_timestamp(self):
        good = self.update()
        original = recognition.database(self.directory, self.bundled)
        failures = [urllib.error.HTTPError(recognition.HEAD,503,'Unavailable',{},None),
                    b'not-json', b'{"sha":"../../bad"}']
        for failure in failures:
            with patch.object(recognition,'fetch',side_effect=failure if isinstance(failure,Exception) else None,
                              return_value=failure if isinstance(failure,bytes) else None):
                result = recognition.update(self.directory,self.bundled,force=True)
            self.assertEqual(result['result'],'error')
            self.assertEqual(result['last_success'],good['last_success'])
            self.assertEqual(recognition.database(self.directory,self.bundled),original)

    def test_invalid_csv_and_changed_license_keep_bundled_data(self):
        for bad, stage in (([json.dumps({'sha':REVISION}).encode(),b'MIT'], 'check upstream license'),
                           ([json.dumps({'sha':REVISION}).encode(),LICENSE,b'empty'], 'validate recognition CSV')):
            with patch.object(recognition,'fetch',side_effect=bad):
                result = recognition.update(self.directory,self.bundled)
            self.assertEqual(result['result'],'error')
            self.assertIn(stage,result['error'])
            self.assertTrue(result['bundled'])

    def test_symlink_target_is_not_read_or_replaced(self):
        self.directory.mkdir(mode=0o700)
        target = Path(self.temp.name)/'unmanaged'
        target.write_text('keep')
        (self.directory/'recognition-state.json').symlink_to(target)
        with self.assertRaises(ValueError):
            self.update()
        self.assertEqual(target.read_text(),'keep')


if __name__ == '__main__':
    unittest.main()
