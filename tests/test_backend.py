"""Security and transaction boundaries; run on a disposable Linux machine as root."""
import copy
import json
import os
from pathlib import Path
import pwd
import re
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import engine
import native
import policy
import routing
import service
import state
import transport
import subprocess
import repository
import connections
import base64
import hashlib
import io

def site():return dict(id='a'*32,domain='example.test',names=['example.test','www.example.test'],enabled=True,error='',token='b'*64,ttl=300,bypass=[])

@unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid()==0,'Disposable Linux/root tests')
class Boundaries(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir='/var/lib',prefix='wvw-tests-');self.base=Path(self.temp.name)
        self.root=self.base/'state';self.root.mkdir();self.config=self.base/'config';self.config.mkdir()
        self.custom=self.base/'native';self.custom.mkdir()
        self.patches=[patch.object(state,'ROOT',self.root),patch.object(engine,'SETTINGS',self.root/'settings.json'),
            patch.object(engine,'JOURNAL',self.root/'transaction.json'),patch.object(routing,'CONFIG',self.config),
            patch.object(native,'GLOBAL',self.custom/'global.conf'),patch.object(native,'CUSTOM',self.custom),
            patch.object(native,'APACHE_CUSTOM',self.base/'apache'),patch.object(service,'ACTIVE',self.config/'active.vcl')]
        self.patches += [patch.object(repository,'RECORD',self.root/'repository.json'),patch.object(repository,'KEY',self.config/'repo.gpg'),
            patch.object(repository,'SOURCE',self.config/'repo.list'),patch.object(repository,'PIN',self.config/'repo.pin')]
        self.patches += [patch.object(native,'proxy_timeouts',return_value=dict(connect=300000,read=300000,send=300000))]
        for p in self.patches:p.start()
    def tearDown(self):
        for p in reversed(self.patches):p.stop()
        self.temp.cleanup()
    def test_invalid_hosts_cannot_enter_vcl_or_nginx(self):
        for value in ('example.test;return 200','../example.test','*.test','a"b.test','x\ny.test','EXAMPLE.test'):
            with self.subTest(value=value),self.assertRaises(ValueError):native.hostname(value)
    def test_native_alias_with_a_separate_vhost_uses_the_same_site_scope(self):
        users=[dict(user='example',homedir='/home/example',status=0)]
        domains=[dict(user='example',domain='example.test',path='/home/example/public_html',type='primary'),dict(user='example',domain='alias.test',path='/home/example/public_html',type='alias',alias='example.test')]
        text='\n'.join('server { server_name '+name+' www.'+name+'; set $webuzoproxy http://127.0.0.1:8081; include '+str(native.CUSTOM/(name+'.conf'))+'; }' for name in ('example.test','alias.test'))
        with patch.object(native,'listing',side_effect=lambda kind:users if kind=='users' else domains),patch.object(native,'read',return_value=text.encode()),patch.object(pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=1001,pw_gid=1001,pw_dir='/home/example')):
            found=list(native.collect().values())
        self.assertEqual(len(found),1);self.assertEqual(set(found[0]['custom_domains']),{'example.test','alias.test'});self.assertIn('alias.test',found[0]['names'])
    def test_duplicate_host_cannot_cross_site_scope(self):
        a=site();b=site();b.update(id='c'*32,token='d'*64)
        with self.assertRaises(ValueError):policy.render({'a':a,'b':b},'e'*64,'f'*64)
    def test_no_arbitrary_vcl_or_expression_from_bypass(self):
        for value in ('/x\ny','relative','/x?query','/bad%Q0','/encoded%3fquery','/back\\slash'):
            a=site();a['bypass']=[value]
            with self.subTest(value=value),self.assertRaises(ValueError):policy.render({'a':a},'e'*64,'f'*64)
    def test_bypass_prefix_is_literal(self):
        a=site();a['bypass']=['/private.area/']
        self.assertIn('/private[.]area/',policy.render({'a':a},'e'*64,'f'*64))
        # Regular-expression characters and VCL punctuation become literal URL bytes.
        self.assertEqual(policy.paths(['/x.*','/x";return(synth(200));']),['/x.%2A','/x%22%3Breturn%28synth%28200%29%29%3B'])
    def test_encoded_and_unicode_bypass_share_a_canonical_path(self):
        self.assertEqual(policy.paths(['/ιδιωτικό/','/%CE%B9%CE%B4%CE%B9%CF%89%CF%84%CE%B9%CE%BA%CF%8C/']),['/%CE%B9%CE%B4%CE%B9%CF%89%CF%84%CE%B9%CE%BA%CF%8C/'])
    def test_invalid_tokens_and_ttl_rejected(self):
        for key,value in (('id','../x'),('token','short'),('ttl',True),('ttl',0),('ttl',2147483648)):
            a=site();a[key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):policy.render({'a':a},'e'*64,'f'*64)
    def test_purge_scope_does_not_use_caller_expression(self):
        with patch.object(service,'admin') as admin:service.purge(site())
        admin.assert_called_once_with('ban','obj.http.X-WV-Site','==','a'*32)
    def test_custom_pointer_preserves_independent_content(self):
        path=self.custom/'example.test.conf';original='# independent\nreturn 401;\n';path.write_text(original)
        target=self.config/'site.conf'
        change,entry=routing.pointer(path,target,{},True);routing.replace(change)
        manifest={str(path):dict(entry,target=str(target))}
        path.write_text(path.read_text()+'# later administrator edit\n')
        remove,_=routing.pointer(path,target,manifest,False);routing.replace(remove)
        self.assertEqual(path.read_text(),original+'# later administrator edit\n')
    def test_apache_pointer_uses_native_include_syntax(self):
        native.APACHE_CUSTOM.mkdir()
        change,_=routing.pointer(native.APACHE_CUSTOM/'example.test.conf',self.config/'ip.conf',{},True)
        self.assertIn('Include ',change['after']);self.assertNotIn(';',change['after'])
    def test_deleted_domain_custom_file_does_not_block_cleanup(self):
        path=self.custom/'example.test.conf';target=self.config/'site.conf'
        manifest={str(path):dict(created=True,separator='',target=str(target))}
        change,_=routing.pointer(path,target,manifest,False)
        self.assertIsNone(change['after']);routing.replace(change)
    def test_changed_owned_pointer_is_refused(self):
        path=self.custom/'example.test.conf';path.write_text(routing.BEGIN+'include /unrelated;\n'+routing.END)
        with self.assertRaises(ValueError):routing.pointer(path,self.config/'site.conf',{},True)
    def test_symlink_and_concurrent_edits_are_not_overwritten(self):
        other=self.base/'other';other.write_text('keep');path=self.custom/'example.test.conf';path.symlink_to(other)
        with self.assertRaises(OSError):routing.pointer(path,self.config/'site.conf',{},True)
        path.unlink();path.write_text('changed')
        with self.assertRaises(ValueError):routing.replace(dict(path=str(path),before='previous',after='next',mode=0o644))
        self.assertEqual(other.read_text(),'keep');self.assertEqual(path.read_text(),'changed')
    def test_root_state_refuses_links_and_untrusted_owners(self):
        path=self.root/'settings.json';other=self.base/'other';other.write_text('{}');path.symlink_to(other)
        with self.assertRaises(ValueError):state.read(path)
        path.unlink();path.write_text('{}');os.chown(path,pwd.getpwnam('nobody').pw_uid,0)
        with self.assertRaises(ValueError):state.read(path)
    def test_panel_ipc_rejects_hosting_user_and_consumes_once(self):
        panel=pwd.getpwnam('webuzo');run=self.base/'run';run.mkdir();run.chmod(0o730);os.chown(run,0,panel.pw_gid)
        identity='a'*64;path=run/(identity+'.json');path.write_text('{}');path.chmod(0o600)
        with patch.object(state,'RUN',run):
            os.chown(path,pwd.getpwnam('nobody').pw_uid,0)
            with self.assertRaises(ValueError):transport.request(identity)
            os.chown(path,panel.pw_uid,panel.pw_gid)
            self.assertEqual(transport.request(identity),{});self.assertFalse(path.exists())
            with self.assertRaises(FileNotFoundError):transport.request(identity)
    def test_non_admin_and_unknown_fields_rejected_before_operations(self):
        for request in (dict(actor='account',admin=True,action='install'),dict(actor='root',admin=False,action='status'),dict(actor='root',admin=True,action='shell'),dict(actor='root',admin=True,action='status',command='id')):
            with self.subTest(request=request),patch.object(native,'run') as run,self.assertRaises(ValueError):engine.action(request)
            run.assert_not_called()
    def test_package_installation_refuses_unknown_distribution(self):
        with patch.object(repository.platform,'freedesktop_os_release',return_value={'ID':'unsupported'}),patch.object(native,'run') as run:
            with self.assertRaises(ValueError):repository.release()
        run.assert_not_called()
    def test_package_installation_preserves_an_existing_independent_unit(self):
        with patch.object(repository,'release',return_value='noble'),patch.object(Path,'is_file',return_value=False),patch.object(repository.subprocess,'run',return_value=subprocess.CompletedProcess([],1)),patch.object(native,'run',return_value='loaded') as run,patch.object(repository,'setup') as setup:
            with self.assertRaises(ValueError):repository.ensure_package()
        self.assertEqual(run.call_count,2);setup.assert_not_called()
    def repository_record(self):
        key=b'fixture-dearmored-public-key'
        record=dict(key=base64.b64encode(key).decode(),source=None,key_source_sha256=repository.KEY_SHA256,key_sha256=hashlib.sha256(key).hexdigest())
        state.save(repository.RECORD,record)
        return key
    def test_unexpected_downloaded_signing_key_creates_no_repository(self):
        with patch.object(repository,'release',return_value='noble'),patch.object(repository.urllib.request,'urlopen',return_value=io.BytesIO(b'wrong-key')),patch.object(native,'run') as run:
            with self.assertRaises(ValueError):repository.setup()
        self.assertFalse(repository.RECORD.exists());self.assertFalse(repository.KEY.exists());run.assert_not_called()
    def test_changed_managed_repository_key_is_not_overwritten(self):
        self.repository_record();repository.KEY.write_bytes(b'administrator-change')
        with patch.object(repository,'release',return_value='noble'):
            with self.assertRaises(ValueError):repository.setup()
        self.assertEqual(repository.KEY.read_bytes(),b'administrator-change');self.assertFalse(repository.PIN.exists())
    def test_repository_resume_preserves_independent_source_and_avoids_download(self):
        key=self.repository_record();repository.SOURCE.write_text('# independent source\n')
        with patch.object(repository,'release',return_value='noble'),patch.object(repository.urllib.request,'urlopen') as download:repository.setup()
        download.assert_not_called();self.assertEqual(repository.KEY.read_bytes(),key)
        self.assertEqual(repository.SOURCE.read_text(),'# independent source\n');self.assertEqual(repository.PIN.read_text(),repository.PIN_TEXT)
    def test_nginx_failure_restores_previous_policy_and_files(self):
        path=self.custom/'global.conf';path.write_text('previous\n');service.ACTIVE.write_text('old VCL')
        previous=dict(installed=True,sites={},manifest={});desired=dict(previous,gateway='e'*64,origin='f'*64)
        change=dict(path=str(path),before='previous\n',after='next\n',mode=0o644)
        count=[0]
        def reload():
            count[0]+=1
            if count[0]==1:raise RuntimeError('Injected Nginx validation failure')
        with patch.object(engine,'plans',return_value=[change]),patch.object(service,'load',return_value=('old','new')),patch.object(service,'running',return_value=True),patch.object(service,'admin') as admin,patch.object(service,'write_vcl',side_effect=lambda p,c:p.write_text(c)),patch.object(engine,'reload_servers',side_effect=reload):
            with self.assertRaises(RuntimeError):engine.apply(previous,desired)
        self.assertEqual(path.read_text(),'previous\n');self.assertEqual(service.ACTIVE.read_text(),'old VCL')
        self.assertFalse(engine.JOURNAL.exists());self.assertEqual(engine.settings(),previous)
        admin.assert_any_call('vcl.use','old')
    def test_recovery_restores_journal_before_new_operations(self):
        path=self.custom/'global.conf';path.write_text('next')
        journal=dict(previous={'installed':True},changes=[dict(path=str(path),before='previous',after='next',mode=0o644)],active_before='old VCL',old_vcl='old')
        state.save(engine.JOURNAL,journal)
        with patch.object(service,'running',return_value=True),patch.object(service,'admin'),patch.object(service,'write_vcl'),patch.object(engine,'reload_servers'):
            engine.recover()
        self.assertEqual(path.read_text(),'previous');self.assertFalse(engine.JOURNAL.exists())
    def test_http_connection_readiness_failure_restores_previous_configuration(self):
        previous=dict(installed=True,sites={},gateway='e'*64,origin='f'*64)
        updated=dict(previous,control_port=82,control_marker='a'*32)
        service.ACTIVE.write_text('old VCL')
        with patch.object(engine,'plans',return_value=[]),patch.object(service,'load',return_value=('old','new')),\
             patch.object(service,'running',return_value=True),patch.object(service,'admin'),\
             patch.object(service,'write_vcl',side_effect=lambda p,c:p.write_text(c)),patch.object(engine,'reload_servers'),\
             patch.object(connections,'wait',side_effect=RuntimeError('Listener did not bind')):
            with self.assertRaisesRegex(RuntimeError,'did not bind'):engine.apply(previous,updated)
        self.assertEqual(engine.settings(),previous)
        self.assertEqual(service.ACTIVE.read_text(),'old VCL')
        self.assertFalse(engine.JOURNAL.exists())
    def test_timeout_refresh_keeps_existing_site_objects_and_persists_allowances(self):
        current=site();previous=dict(installed=True,sites={current['id']:current},manifest={},gateway='e'*64,origin='f'*64)
        desired=copy.deepcopy(previous);service.ACTIVE.write_text('old VCL')
        with patch.object(engine,'plans',return_value=[]),patch.object(service,'load',return_value=('old','new')),patch.object(service,'admin'),patch.object(service,'prune'),patch.object(service,'write_vcl',side_effect=lambda p,c:p.write_text(c)),patch.object(engine,'reload_servers'),patch.object(service,'purge') as purge:
            engine.apply(previous,desired)
        purge.assert_not_called()
        self.assertEqual(engine.settings()['proxy_timeouts'],dict(connect=300000,read=300000,send=300000))
        self.assertIn('.first_byte_timeout = 900s;',service.ACTIVE.read_text())
    def test_invalid_native_timeout_inspection_leaves_active_state_untouched(self):
        previous=dict(installed=True,sites={},manifest={},gateway='e'*64,origin='f'*64)
        state.save(engine.SETTINGS,previous);service.ACTIVE.write_text('old VCL')
        with patch.object(native,'proxy_timeouts',side_effect=ValueError('Native configuration unavailable')),patch.object(engine,'plans') as plans:
            with self.assertRaises(ValueError):engine.apply(previous,copy.deepcopy(previous))
        plans.assert_not_called();self.assertEqual(service.ACTIVE.read_text(),'old VCL')
        self.assertEqual(engine.settings(),previous);self.assertFalse(engine.JOURNAL.exists())
    def test_recovery_reloads_saved_policy_after_a_runtime_restart(self):
        journal=dict(previous={'installed':True},changes=[],active_before='old VCL',old_vcl='discarded_name')
        calls=[]
        def admin(*args):
            calls.append(args)
            if args==('vcl.use','discarded_name'):raise RuntimeError('Unknown VCL after restart')
        with patch.object(service,'running',return_value=True),patch.object(service,'admin',side_effect=admin),patch.object(service,'load',return_value=('boot','restored')) as load,patch.object(service,'write_vcl'),patch.object(engine,'reload_servers'):
            engine.restore(journal)
        load.assert_called_once_with('old VCL');self.assertIn(('vcl.use','restored'),calls)
    def test_account_helper_rejects_root_and_cannot_write_through_links(self):
        helper=Path(__file__).resolve().parents[1]/'src/account.py'
        root_run=subprocess.run(['/usr/bin/python3',str(helper),'save',str(self.base),'a'*32],capture_output=True)
        self.assertNotEqual(root_run.returncode,0)
        user=pwd.getpwnam('nobody');home=self.base/'home';home.mkdir();os.chown(home,user.pw_uid,user.pw_gid);self.base.chmod(0o711)
        other=self.base/'untouched';other.mkdir();(other/'data').write_text('keep')
        (home/'.varnish-for-webuzo').symlink_to(other,target_is_directory=True)
        result=subprocess.run(['/usr/bin/python3',str(helper),'save',str(home),'a'*32],input=json.dumps(dict(site='a'*32,names=['example.test'],token='b'*64)).encode(),user=user.pw_uid,group=user.pw_gid,extra_groups=[],capture_output=True)
        self.assertNotEqual(result.returncode,0);self.assertEqual((other/'data').read_text(),'keep');self.assertEqual(len(list(other.iterdir())),1)
    def test_account_credential_cannot_be_placed_inside_a_web_root(self):
        helper=Path(__file__).resolve().parents[1]/'src/account.py';user=pwd.getpwnam('nobody')
        home=self.base/'home';home.mkdir();os.chown(home,user.pw_uid,user.pw_gid);self.base.chmod(0o711)
        payload=dict(site='a'*32,names=['example.test'],token='b'*64,roots=[str(home)])
        def write():return subprocess.run(['/usr/bin/python3',str(helper),'save',str(home),'a'*32],input=json.dumps(payload).encode(),user=user.pw_uid,group=user.pw_gid,extra_groups=[],umask=0o077,capture_output=True)
        self.assertNotEqual(write().returncode,0);credential=home/'.varnish-for-webuzo'/('a'*32+'.json');self.assertFalse(credential.exists())
        payload['roots']=[str(home/'public_html')]
        self.assertEqual(write().returncode,0);self.assertEqual(credential.stat().st_mode&0o777,0o600)
        self.assertEqual(set(json.loads(credential.read_text())),{'site','names','token'})

if __name__=='__main__':unittest.main(verbosity=2)
