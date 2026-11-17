"""A C-only update must load new native code while the previous VCL can roll back."""
import http.client
import importlib.util
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform.startswith('linux') and shutil.which('varnishd') and shutil.which('pkg-config'),'Native Varnish build tools required')
class NativeModuleUpgrade(unittest.TestCase):
    def test_c_only_update_loads_new_code_and_retains_previous_vcl_mapping(self):
        with tempfile.TemporaryDirectory(prefix='wvw-native-build-') as temporary:
            root=Path(temporary);source=root/'source';source.mkdir()
            shutil.copytree(ROOT/'shared/native',source/'native')
            shutil.copyfile(ROOT/'shared/native_build.py',source/'native_build.py')
            target=root/'vmods';target.mkdir()
            spec=importlib.util.spec_from_file_location('private_native_builder',source/'native_build.py')
            builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
            command=builder.command
            def build_command(*args,**kwargs):
                return str(target) if args==('pkg-config','--variable=vmoddir','varnishapi') else command(*args,**kwargs)
            with patch.object(builder,'command',side_effect=build_command):
                library=builder.build()
                before=json.loads((target/'cookie_handoff.build.json').read_text())['signature']
                program='''vcl 4.1;
import cookie_handoff from '''+json.dumps(str(library))+''';
backend default { .host = "127.0.0.1"; .port = "9"; }
sub vcl_recv { return (synth(200)); }
sub vcl_synth { set resp.http.X-Native-Code = cookie_handoff.pending(); return (deliver); }
'''
                active=root/'active.vcl';active.write_text(program)
                secret=root/'secret';secret.write_text('private-test-secret')
                def free_port():
                    with socket.socket() as reservation:
                        reservation.bind(('127.0.0.1',0));return reservation.getsockname()[1]
                port,admin_port=free_port(),free_port()
                with (root/'varnish.log').open('w+') as log:
                    process=subprocess.Popen(['varnishd','-F','-j','none','-a','127.0.0.1:'+str(port),'-T','127.0.0.1:'+str(admin_port),
                        '-S',str(secret),'-n',str(root/'instance'),'-f',str(active),'-s','malloc,16m'],stdout=log,stderr=log)
                    try:
                        def admin(*args):
                            return subprocess.run(['varnishadm','-T','127.0.0.1:'+str(admin_port),'-S',str(secret),*args],capture_output=True,text=True,check=True).stdout
                        deadline=time.monotonic()+15
                        while True:
                            try:
                                if 'running' in admin('status'):break
                            except subprocess.CalledProcessError:
                                if process.poll() is not None or time.monotonic()>deadline:
                                    log.seek(0);self.fail(log.read())
                            time.sleep(.05)
                        def code():
                            connection=http.client.HTTPConnection('127.0.0.1',port,timeout=5)
                            try:
                                connection.request('GET','/');response=connection.getresponse();response.read()
                                return response.getheader('X-Native-Code')
                            finally:connection.close()
                        self.assertEqual(code(),'0')
                        native=source/'native/cookie_handoff.c';original=native.read_text()
                        changed=original.replace('return count;','return count + 1000;')
                        self.assertNotEqual(changed,original);native.write_text(changed)
                        self.assertEqual(builder.build(),library)
                        self.assertNotEqual(before,json.loads((target/'cookie_handoff.build.json').read_text())['signature'])
                        updated=root/'updated.vcl';updated.write_text('# Changed C implementation\n'+program)
                        admin('vcl.load','changed_c',str(updated));admin('vcl.use','changed_c')
                        self.assertEqual(code(),'1000','The new VCL reused the old VMOD implementation')
                        admin('vcl.use','boot');self.assertEqual(code(),'0')
                    finally:
                        process.terminate();process.wait(timeout=10)


if __name__=='__main__':unittest.main()
