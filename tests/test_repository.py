"""Release matching, signed metadata, interrupted reconciliation and package safety."""
import base64
import hashlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import native
import repository as repo
import state


class Selection(unittest.TestCase):
    def test_release_detection_has_no_hardcoded_ubuntu_version(self):
        for codename in ('noble','resolute','futurelts'):
            with self.subTest(codename=codename),patch.object(repo.platform,'freedesktop_os_release',return_value=dict(ID='ubuntu',VERSION_CODENAME=codename)):
                self.assertEqual(repo.release(),codename)
        for data in (dict(ID='debian',VERSION_CODENAME='trixie'),dict(ID='ubuntu'),dict(ID='ubuntu',VERSION_CODENAME='noble;bad')):
            with patch.object(repo.platform,'freedesktop_os_release',return_value=data),self.assertRaises(ValueError):repo.release()

    def test_native_architecture_is_not_assumed(self):
        for arch in ('amd64','arm64'):
            with patch.object(native,'run',return_value=arch+'\n'):self.assertEqual(repo.architecture(),arch)
        with patch.object(native,'run',return_value='amd64;bad'),self.assertRaises(ValueError):repo.architecture()

    def test_candidate_must_come_from_current_suite_and_architecture(self):
        for suite in ('noble','resolute'):
            for arch in ('amd64','arm64'):
                version='10.2.0-1~'+suite
                listing='varnish | '+version+' | '+repo.BASE+' '+suite+'/main '+arch+' Packages\n'
                with patch.object(native,'run',side_effect=['  Candidate: '+version+'\n',listing]):
                    self.assertEqual(repo.candidate(suite,arch),version)
                for wrong in ('old/main '+arch,'resolute/main otherarch'):
                    with patch.object(native,'run',side_effect=['  Candidate: '+version+'\n',listing.replace(suite+'/main '+arch,wrong)]),self.assertRaises(ValueError):repo.candidate(suite,arch)
        with patch.object(native,'run',return_value='  Candidate: (none)\n'),self.assertRaises(ValueError):repo.candidate('noble','amd64')

    def test_modified_ownership_records_are_rejected(self):
        repo.owned_source(repo.source_text('noble'))
        repo.owned_source(repo.source_text('resolute','arm64'))
        for source in (repo.source_text('noble').replace(repo.BASE,'https://untrusted.test'),repo.source_text('noble')+'# changed\n'):
            with self.assertRaises(ValueError):repo.owned_source(source)


@unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid()==0,'Disposable Linux/root tests')
class Repository(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir='/var/lib',prefix='wvw-repository-');self.root=Path(self.temp.name)
        self.key=b'test-key'
        self.patches=[patch.object(state,'ROOT',self.root),patch.object(repo,'RECORD',self.root/'repository.json'),
            patch.object(repo,'KEY',self.root/'key.gpg'),patch.object(repo,'SOURCE',self.root/'source.list'),patch.object(repo,'PIN',self.root/'branch.pin'),
            patch.object(repo,'release',return_value='resolute'),patch.object(repo,'architecture',return_value='amd64')]
        for p in self.patches:p.start()
        self.record=dict(key=base64.b64encode(self.key).decode(),key_sha256=hashlib.sha256(self.key).hexdigest(),key_source_sha256=repo.KEY_SHA256,source=repo.source_text('noble'))
        state.save(repo.RECORD,self.record);repo.KEY.write_bytes(self.key);repo.SOURCE.write_text(self.record['source'])

    def tearDown(self):
        for p in reversed(self.patches):p.stop()
        self.temp.cleanup()

    def test_os_upgrade_reconciles_only_owned_source_and_retires_branch_pin(self):
        repo.PIN.write_text(repo.PIN_TEXT)
        with patch.object(repo,'existing_source',return_value=False),patch.object(repo,'verify_release') as verify,patch.object(repo.urllib.request,'urlopen') as download:
            repo.setup()
        verify.assert_called_once_with('resolute','amd64',self.key);download.assert_not_called()
        self.assertEqual(repo.SOURCE.read_text(),repo.source_text('resolute','amd64'))
        self.assertFalse(repo.PIN.exists());self.assertNotIn('pending_source',state.read(repo.RECORD))

    def test_explicit_refresh_reconciles_changed_owned_suite_only(self):
        with patch.object(repo,'setup') as setup:repo.reconcile_owned()
        setup.assert_called_once_with()
        self.record['source']=repo.source_text('resolute','amd64');state.save(repo.RECORD,self.record)
        with patch.object(repo,'setup') as setup:repo.reconcile_owned()
        setup.assert_not_called()
        self.record['source']=None;state.save(repo.RECORD,self.record)
        with patch.object(repo,'setup') as setup:repo.reconcile_owned()
        setup.assert_not_called()

    def test_independent_sources_must_match_suite_component_and_architecture(self):
        part=self.root/'external.list'
        with patch.object(Path,'glob',side_effect=lambda pattern:[part] if pattern=='*.list' else []):
            for options,component,expected in [('arch=amd64','main',True),('arch=arm64','main',False),('','other',False)]:
                part.write_text('deb ['+options+'] '+repo.BASE+' resolute '+component+'\n')
                self.assertEqual(repo.existing_source('resolute','amd64'),expected)
            part.write_text('deb '+repo.BASE+' noble main\n')
            self.assertFalse(repo.existing_source('resolute','amd64'))

    def test_compatible_native_binary_compiles_actual_policy(self):
        if not Path('/usr/sbin/varnishd').is_file():self.skipTest('Native Varnish required')
        self.assertTrue(repo.compatible())

    def test_unavailable_or_invalid_release_leaves_all_previous_files_untouched(self):
        repo.PIN.write_text(repo.PIN_TEXT)
        before={p:p.read_bytes() for p in (repo.RECORD,repo.KEY,repo.SOURCE,repo.PIN)}
        with patch.object(repo,'verify_release',side_effect=ValueError('Unavailable')),self.assertRaises(ValueError):repo.setup()
        self.assertEqual(before,{p:p.read_bytes() for p in before})

    def test_modified_files_are_not_overwritten_or_removed(self):
        for path in (repo.KEY,repo.SOURCE,repo.PIN):
            original=path.read_bytes() if path.exists() else None
            path.write_text('administrator change')
            with patch.object(repo,'verify_release') as verify,self.assertRaises(ValueError):repo.setup()
            verify.assert_not_called();self.assertEqual(path.read_text(),'administrator change')
            if original is None:path.unlink()
            else:path.write_bytes(original)

    def test_interrupted_source_change_resumes_after_source_was_replaced(self):
        actual_save=state.save
        def fail_final(path,value):
            if path==repo.RECORD and 'pending_source' not in value:raise OSError('Interrupted')
            actual_save(path,value)
        with patch.object(repo,'existing_source',return_value=False),patch.object(repo,'verify_release'),patch.object(state,'save',side_effect=fail_final):
            with self.assertRaises(OSError):repo.setup()
        self.assertEqual(state.read(repo.RECORD)['pending_source'],repo.SOURCE.read_text())
        with patch.object(repo,'existing_source',return_value=False),patch.object(repo,'verify_release'):repo.setup()
        self.assertEqual(state.read(repo.RECORD)['source'],repo.source_text('resolute','amd64'))
        self.assertNotIn('pending_source',state.read(repo.RECORD))

    def test_existing_independent_source_is_preserved(self):
        self.record['source']=None;state.save(repo.RECORD,self.record);repo.SOURCE.write_text('# independent\n')
        with patch.object(repo,'existing_source',return_value=True),patch.object(repo,'verify_release'):repo.setup()
        self.assertEqual(repo.SOURCE.read_text(),'# independent\n')

    def test_signed_release_must_match_requested_suite_and_have_architecture_index(self):
        for suite,arch,valid in [('resolute','amd64',True),('noble','amd64',False),('resolute','riscv64',False)]:
            body='Codename: '+suite+'\nOrigin: Varnish\nSHA256:\n '+'a'*64+' 123 main/binary-'+arch+'/Packages.gz\n'
            def verify(*args):Path(args[args.index('--output')+1]).write_text(body);return ''
            with self.subTest(suite=suite,arch=arch),patch.object(repo.urllib.request,'urlopen',return_value=io.BytesIO(b'signed')),patch.object(native,'run',side_effect=verify):
                if valid:repo.verify_release('resolute','amd64',self.key)
                else:
                    with self.assertRaises(ValueError):repo.verify_release('resolute','amd64',self.key)
        with patch.object(repo.urllib.request,'urlopen',return_value=io.BytesIO(b'tampered')),patch.object(native,'run',side_effect=RuntimeError('Bad signature')),self.assertRaises(RuntimeError):repo.verify_release('resolute','amd64',self.key)

    def test_adopting_compatible_independent_binary_does_not_reconfigure_apt(self):
        repo.RECORD.unlink()
        with patch.object(Path,'is_file',return_value=True),patch.object(repo,'compatible',return_value=True),patch.object(repo,'setup') as setup,patch.object(native,'run') as run:
            repo.ensure_package()
        setup.assert_not_called();run.assert_not_called()

    def test_incompatible_running_binary_is_not_replaced(self):
        with patch.object(Path,'is_file',return_value=True),patch.object(repo,'compatible',return_value=False),patch.object(subprocess,'run',return_value=subprocess.CompletedProcess([],0)),patch.object(repo,'setup') as setup,self.assertRaises(ValueError):repo.ensure_package()
        setup.assert_not_called()

    def test_fresh_install_uses_selected_candidate_and_does_not_remove_libraries_manually(self):
        calls=[]
        def run(*args):
            calls.append(tuple(map(str,args)))
            if args[:2]==('systemctl','show'):return 'not-found' if 'LoadState' in args[-2] else 'disabled'
            return ''
        with patch.object(Path,'is_file',return_value=False),patch.object(repo,'setup',return_value='resolute'),patch.object(repo,'candidate',return_value='10.2.0-1~resolute'),patch.object(repo,'compatible',return_value=True),patch.object(subprocess,'run',return_value=subprocess.CompletedProcess([],1)),patch.object(native,'run',side_effect=run):repo.ensure_package()
        self.assertIn(('env','DEBIAN_FRONTEND=noninteractive','apt-get','install','-y','varnish=10.2.0-1~resolute'),calls)
        self.assertFalse(any('remove' in call or 'libvarnishapi3' in call for call in calls))


if __name__=='__main__':unittest.main()
