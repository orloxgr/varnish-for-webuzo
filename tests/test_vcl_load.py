"""Real slow compilation, native frame validation and private failure diagnostics."""
import grp
import json
import os
from pathlib import Path
import shutil
import socket
import stat
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
import state
import vcl_cli

NAME='wvw_'+'a'*64+'_'+'b'*32
PATH=Path('/var/lib/owned "quoted" directory/generations')/(NAME+'.vcl')


def frame(status,body):
    return ('%-3d %-8d\n'%(status,len(body))).encode()+body


class NativeFrames(unittest.TestCase):
    def run_reply(self,stdout,stderr=b'',code=0):
        return patch.object(vcl_cli.subprocess,'run',return_value=subprocess.CompletedProcess([],code,stdout,stderr))

    def test_one_quoted_stdin_command_and_whole_byte_counted_reply(self):
        body='Compiled: café\n'.encode()
        with self.run_reply(frame(200,body)) as run:
            self.assertEqual(vcl_cli.load('127.0.0.1:9','/owned.secret',NAME,PATH),body.decode())
        args,kwargs=run.call_args
        self.assertEqual(args[0],['/usr/bin/varnishadm','-T','127.0.0.1:9','-S','/owned.secret','-t','10','-p'])
        self.assertEqual(kwargs['input'],('vcl.load '+NAME+' '+json.dumps(str(PATH),ensure_ascii=False)+'\n').encode())
        self.assertNotIn('timeout',kwargs)

    def test_exit_zero_does_not_hide_actual_rejection(self):
        with self.run_reply(frame(106,b'VCC error: private-value\n')):
            with self.assertRaises(vcl_cli.LoadFailure) as error:vcl_cli.load('127.0.0.1:9','/secret',NAME,PATH)
        self.assertTrue(error.exception.rejected)

    def test_incomplete_malformed_extra_and_non_success_frames_are_not_success(self):
        for value in (b'',b'200\nOK',b'200 3\nOK',b'200 2\nOKextra',frame(200,b'OK')+frame(200,b'OK'),
                      frame(201,b'truncated'),frame(400,b'communication error')):
            with self.subTest(reply=value),self.run_reply(value):
                with self.assertRaises(vcl_cli.LoadFailure):vcl_cli.load('127.0.0.1:9','/secret',NAME,PATH)

    def test_nonzero_exit_with_success_frame_is_uncertain_and_retains_both_streams(self):
        with self.run_reply(frame(200,b'OK'),b'connection lost',2):
            with self.assertRaises(vcl_cli.LoadFailure) as error:vcl_cli.load('127.0.0.1:9','/secret',NAME,PATH)
        self.assertFalse(error.exception.rejected)
        self.assertIn('connection lost',str(error.exception));self.assertIn('OK',str(error.exception))

    def test_arbitrary_names_paths_or_second_commands_never_reach_cli(self):
        for name,path in ((NAME+'\nvcl.use boot',PATH),(NAME,Path('/tmp/not-owned.vcl')),
                          (NAME,Path('/a/../generations')/(NAME+'.vcl'))):
            with self.subTest(name=name,path=path),patch.object(vcl_cli.subprocess,'run') as run:
                with self.assertRaises(ValueError):vcl_cli.load('127.0.0.1:9','/secret',name,path)
                run.assert_not_called()

    def test_other_admin_operations_keep_the_normal_bounded_argv_call(self):
        with patch.object(native,'run',return_value='active') as run,patch.object(vcl_cli,'load') as load:
            self.assertEqual(service.admin('vcl.list'),'active')
        self.assertIn('10',run.call_args.args);load.assert_not_called()


@unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid()==0,'Linux/root managed files')
class LoadState(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir='/var/lib',prefix='wvw-load-')
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);(self.root/'generations').mkdir()
        self.enterContext(patch.object(routing,'CONFIG',self.root))
        self.enterContext(patch.object(state,'ROOT',self.root))
        self.enterContext(patch.object(service,'DAEMON',grp.getgrgid(0).gr_name))
        self.active=self.root/'active.vcl';self.active.write_text('old active policy')
        self.enterContext(patch.object(service,'ACTIVE',self.active))
        self.source='vcl 4.1; # private-token-value\n'

    def test_actual_rejection_keeps_old_policy_and_writes_only_root_private_diagnostic(self):
        def admin(*args):
            if args[0]=='vcl.load':raise vcl_cli.LoadFailure('VCC error private-token-value',rejected=True)
            return 'active auto/warm 0 boot\n'
        with patch.object(service,'admin',side_effect=admin):
            with self.assertRaisesRegex(RuntimeError,'rejected') as error:service.load(self.source)
        self.assertNotIn('private-token-value',str(error.exception))
        self.assertEqual(self.active.read_text(),'old active policy')
        self.assertEqual(list((self.root/'generations').iterdir()),[])
        diagnostic=self.root/'last-vcl-error.json'
        self.assertEqual(stat.S_IMODE(diagnostic.stat().st_mode),0o600)
        self.assertEqual(diagnostic.stat().st_uid,0)
        self.assertIn('private-token-value',state.read(diagnostic)['diagnostic'])

    def test_lost_reply_recovers_only_the_exact_registered_candidate(self):
        seen=[]
        def admin(*args):
            seen.append(args)
            if args[0]=='vcl.load':raise vcl_cli.LoadFailure('CLI communication error')
            return 'active auto/warm 0 boot\navailable auto/cold 0 '+seen[0][1]+'\n'
        with patch.object(service,'admin',side_effect=admin):active,name=service.load(self.source)
        self.assertEqual(active,'boot');self.assertEqual(name,seen[0][1])
        self.assertEqual([args[0] for args in seen],['vcl.load','vcl.list'])
        self.assertTrue((self.root/'generations'/(name+'.vcl')).is_file())
        self.assertEqual(self.active.read_text(),'old active policy')

    def test_unavailable_verification_preserves_candidate_without_claiming_rejection(self):
        with patch.object(service,'admin',side_effect=vcl_cli.LoadFailure('lost reply private-token-value')):
            with self.assertRaisesRegex(RuntimeError,'could not be confirmed') as error:service.load(self.source)
        self.assertNotIn('private-token-value',str(error.exception));self.assertNotIn('rejected',str(error.exception))
        self.assertEqual(len(list((self.root/'generations').iterdir())),1)
        self.assertEqual(self.active.read_text(),'old active policy')

    def test_success_reply_without_exact_registration_does_not_allow_activation(self):
        with patch.object(service,'admin',side_effect=['VCL compiled.','active auto/warm 0 boot\n']):
            with self.assertRaisesRegex(RuntimeError,'could not be confirmed'):service.load(self.source)
        self.assertEqual(len(list((self.root/'generations').iterdir())),1)

    def test_success_reply_then_failed_listing_preserves_source_and_hides_diagnostic(self):
        with patch.object(service,'admin',side_effect=['VCL compiled.',RuntimeError('private-token-value')]):
            with self.assertRaisesRegex(RuntimeError,'could not be confirmed') as error:service.load(self.source)
        self.assertNotIn('private-token-value',str(error.exception))
        self.assertEqual(len(list((self.root/'generations').iterdir())),1)
        self.assertEqual(self.active.read_text(),'old active policy')

    def test_unused_registered_generation_with_missing_source_is_cleaned_without_failure(self):
        orphan='wvw_'+'c'*64+'_'+'d'*32
        current='wvw_'+'e'*64+'_'+'f'*32
        listing='active auto/warm 0 '+current+'\navailable auto/cold 0 '+orphan+'\n'
        with patch.object(service,'admin',side_effect=[listing,'']) as admin:service.prune()
        self.assertEqual(admin.call_args_list[-1].args,('vcl.discard',orphan))
        self.assertEqual(self.active.read_text(),'old active policy')

    def test_missing_source_cleanup_does_not_accept_symlinks_or_untrusted_files(self):
        orphan='wvw_'+'c'*64+'_'+'d'*32
        path=self.root/'generations'/(orphan+'.vcl')
        listing='available auto/cold 0 '+orphan+'\n'
        path.symlink_to(self.root/'missing')
        with patch.object(service,'admin',side_effect=[listing,'']):
            with self.assertRaises(ValueError):service.prune()
        self.assertTrue(path.is_symlink())
        path.unlink();path.write_text('untrusted');path.chmod(0o666)
        with patch.object(service,'admin',side_effect=[listing,'']):
            with self.assertRaises(ValueError):service.prune()
        self.assertTrue(path.exists())

    def test_absent_source_does_not_skip_untrusted_parent_checks(self):
        orphan='wvw_'+'c'*64+'_'+'d'*32
        (self.root/'generations').chmod(0o777)
        with patch.object(service,'admin',side_effect=['available auto/cold 0 '+orphan+'\n','']):
            with self.assertRaises(ValueError):service.prune()


@unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid()==0 and
                     shutil.which('varnishd') and shutil.which('varnishadm'),'Native Varnish/root required')
class ActualCompiler(unittest.TestCase):
    def setUp(self):
        LoadState.setUp(self)
        config=self.root/'quoted " config';config.mkdir();(config/'generations').mkdir()
        self.enterContext(patch.object(routing,'CONFIG',config))
        self.secret=self.root/'admin.secret';self.secret.write_text('owned-test-secret');self.secret.chmod(0o600)
        self.boot=self.root/'boot.vcl'
        self.source='vcl 4.1; backend default { .host="127.0.0.1"; .port="9"; } sub vcl_recv { return(synth(200)); }\n'
        self.boot.write_text(self.source)
        with socket.socket() as sock:sock.bind(('127.0.0.1',0));self.address='127.0.0.1:'+str(sock.getsockname()[1])
        self.process=subprocess.Popen(['varnishd','-F','-j','none','-n',str(self.root/'instance'),'-f',str(self.boot),
            '-a',str(self.root/'frontend.sock')+',mode=0600','-T',self.address,'-S',str(self.secret),'-s','malloc,16m'],
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        self.addCleanup(lambda:self.process.wait(timeout=15));self.addCleanup(self.process.terminate)
        deadline=time.monotonic()+15
        while True:
            try:
                if 'running' in self.admin('status'):break
            except RuntimeError:
                if self.process.poll() is not None or time.monotonic()>deadline:raise
            time.sleep(.05)

    def admin(self,*args):
        if args[0]=='vcl.load':return vcl_cli.load(self.address,self.secret,*args[1:])
        return native.run('/usr/bin/varnishadm','-T',self.address,'-S',self.secret,'-t','10',*args)

    def test_compilation_over_ten_seconds_is_not_rejected_and_does_not_activate_itself(self):
        compiler=self.root/'delayed-cc';compiler.write_text('#!/bin/sh\nsleep 11\nexec /usr/bin/cc "$@"\n');compiler.chmod(0o700)
        self.admin('param.set','cc_command',json.dumps('exec '+str(compiler)+' %w -pthread -fpic -shared -Wl,-x -o %o %s'))
        start=time.monotonic()
        with patch.object(service,'admin',side_effect=self.admin):active,name=service.load(self.source+'# delayed\n')
        self.assertGreaterEqual(time.monotonic()-start,11)
        self.assertEqual(active,'boot');self.assertIsNone(self.process.poll())
        self.assertIn(name,self.admin('vcl.list'))
        self.assertTrue(any(line.startswith('active') and line.split()[-1]=='boot' for line in self.admin('vcl.list').splitlines()))
        self.assertEqual(self.active.read_text(),'old active policy')
        self.admin('vcl.use',name)
        self.assertTrue(any(line.startswith('active') and line.split()[-1]==name for line in self.admin('vcl.list').splitlines()))

    def test_real_vcc_rejection_is_safe_and_previous_generation_remains_active(self):
        with patch.object(service,'admin',side_effect=self.admin):
            with self.assertRaisesRegex(RuntimeError,'rejected') as error:
                service.load('vcl 4.1; private_token_value;\n')
        self.assertNotIn('private_token_value',str(error.exception))
        self.assertIn('private_token_value',state.read(self.root/'last-vcl-error.json')['diagnostic'])
        self.assertTrue(any(line.startswith('active') and line.split()[-1]=='boot' for line in self.admin('vcl.list').splitlines()))


if __name__=='__main__':unittest.main()
