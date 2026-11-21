"""Runtime identity must work with policies larger than native CLI replies."""
import hashlib
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import native
import routing
import service
import vcl_cli
import native_test_accounts


@unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid()==0,'Linux/root managed files')
class RuntimeIdentity(unittest.TestCase):
    def setUp(self):
        native_test_accounts.install(self)
        self.temp=tempfile.TemporaryDirectory(dir='/var/lib',prefix='wvw-runtime-')
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        (self.root/'generations').mkdir()
        self.enterContext(patch.object(routing,'CONFIG',self.root))

    def test_unknown_and_legacy_generations_are_adopted_without_dumping_source(self):
        for name in ('boot','external','wvw_'+'a'*32,'../../etc/passwd'):
            with self.subTest(name=name),patch.object(service,'admin',return_value='active auto/warm 0 '+name) as admin:
                self.assertEqual(service.current_source(),(name,None))
                admin.assert_called_once_with('vcl.list')

    def test_only_matching_root_owned_generation_is_reused(self):
        source='vcl 4.1;\n# private-token\n'
        name='wvw_'+hashlib.sha256(source.encode()).hexdigest()+'_'+'b'*32
        path=self.root/'generations'/(name+'.vcl')
        with patch.object(service,'admin',return_value='active auto/warm 0 '+name):
            self.assertEqual(service.current_source(),(name,None))
            path.write_text(source)
            self.assertEqual(service.current_source(),(name,source))
            path.write_text(source+'# edited\n')
            self.assertEqual(service.current_source(),(name,None))
            path.chmod(0o666)
            with self.assertRaises(RuntimeError) as error:service.current_source()
            self.assertNotIn('private-token',str(error.exception))

    @unittest.skipUnless(shutil.which('varnishd') and shutil.which('varnishadm'),'Native Varnish required')
    def test_large_real_vcl_load_identity_and_repeat_apply_without_restart(self):
        import copy
        import engine
        import state
        import test_profiles
        source='vcl 4.1;\nbackend default { .host="127.0.0.1"; .port="9"; }\n'+'# source padding\n'*20000
        boot=self.root/'boot.vcl';boot.write_text(source)
        secret=self.root/'admin.secret';secret.write_text('test-only-secret')
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        process=subprocess.Popen(['varnishd','-j','none','-F','-a',str(self.root/'frontend.sock')+',mode=0600',
            '-T','127.0.0.1:'+str(port),'-S',str(secret),'-n',str(self.root/'cache'),'-f',str(boot)],
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        self.addCleanup(lambda:process.wait(timeout=10))
        self.addCleanup(process.terminate)
        def admin(*args):
            if args[0]=='vcl.load':return vcl_cli.load('127.0.0.1:'+str(port),secret,*args[1:])
            return native.run('/usr/bin/varnishadm','-T','127.0.0.1:'+str(port),'-S',secret,*args)
        deadline=time.monotonic()+10
        while True:
            try:
                if 'running' in admin('status'):break
            except RuntimeError:
                if process.poll() is not None or time.monotonic()>deadline:raise
            time.sleep(.05)
        # varnishadm accepts native 201 but returns a truncated source body.
        self.assertNotEqual(admin('vcl.show','boot').rstrip(),source.rstrip())
        # Reproduce the old timeout's late-registered, source-deleted candidate.
        orphan='wvw_'+'c'*64+'_'+'d'*32
        orphan_path=self.root/'generations'/(orphan+'.vcl')
        orphan_path.write_text(source+'# old timed-out generation\n')
        admin('vcl.load',orphan,str(orphan_path));orphan_path.unlink()
        site=test_profiles.site();site['enabled']=False
        config=dict(installed=True,sites={site['id']:site},gateway='e'*64,origin='f'*64)
        active=self.root/'active.vcl';active.write_text(source)
        with (patch.object(service,'admin',side_effect=admin) as calls,
              patch.object(service,'ACTIVE',active),patch.object(engine,'SETTINGS',self.root/'settings.json'),
              patch.object(engine,'JOURNAL',self.root/'transaction.json'),
              patch.object(native,'proxy_timeouts',return_value={}),
              patch.object(engine,'plans',return_value=[]),patch.object(engine.connections,'wait'),
              patch.object(engine.policy,'render',return_value=source)):
            self.assertEqual(service.current_source(),('boot',None))
            engine.apply(copy.deepcopy(config),copy.deepcopy(config))
            name,observed=service.current_source()
            self.assertEqual(observed,source)
            self.assertTrue(name.startswith('wvw_'+hashlib.sha256(source.encode()).hexdigest()+'_'))
            engine.apply(copy.deepcopy(config),copy.deepcopy(config))
            self.assertEqual(service.current_source(),(name,source))
            self.assertEqual(sum(call.args[0]=='vcl.load' for call in calls.call_args_list),1)
            self.assertEqual(sum(call.args[0]=='vcl.use' for call in calls.call_args_list),1)
            self.assertFalse(any(call.args[0]=='vcl.show' for call in calls.call_args_list))
            self.assertIsNone(process.poll())
            self.assertFalse(engine.JOURNAL.exists())
            self.assertNotIn(orphan,admin('vcl.list'))


if __name__=='__main__':unittest.main()
