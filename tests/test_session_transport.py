"""Native request-time CMS resolver protocol; no session result cache."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid()==0 and shutil.which('varnishtest'),'Native Linux/root Varnish required')
class SessionTransport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory(prefix='cms-session-transport-')
        cls.folder=Path(cls.temporary.name);cls.folder.chmod(0o755)
        cls.target=cls.folder/'vmods';cls.target.mkdir(mode=0o755)
        spec=importlib.util.spec_from_file_location('session_native_builder',ROOT/'shared/native_build.py')
        builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
        command=builder.command
        def redirected(*args,**kwargs):
            return str(cls.target) if args==('pkg-config','--variable=vmoddir','varnishapi') else command(*args,**kwargs)
        with patch.object(builder,'command',side_effect=redirected):cls.library=builder.build()

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def execute(self,responses,cookies,expectations):
        pathname=self.folder/('resolver-'+str(time.monotonic_ns())+'.sock')
        listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        listener.bind(str(pathname));pathname.chmod(0o666);listener.listen();listener.settimeout(10)
        received=[];errors=[]
        def server():
            try:
                for response in responses:
                    connection,_=listener.accept()
                    with connection:
                        request=connection.makefile('rb').readline()
                        received.append(json.loads(request))
                        connection.sendall(response.encode())
            except Exception as error:errors.append(error)
            finally:listener.close()
        worker=threading.Thread(target=server,daemon=True);worker.start()
        vcl='''vcl 4.1;
import cookie_handoff from LIBRARY;
backend default { .host="127.0.0.1"; .port="9"; }
sub vcl_recv {
set req.http.X-Test-Session = cookie_handoff.session_state(SOCKET, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", req.url, req.http.Cookie, 10s);
return(synth(200));
}
sub vcl_synth { set resp.http.X-Test-Session = req.http.X-Test-Session; return(deliver); }
'''.replace('LIBRARY',json.dumps(str(self.library))).replace('SOCKET',json.dumps(str(pathname)))
        requests=[]
        for cookie,expected in zip(cookies,expectations):
            requests.extend(['txreq -url "/page?utm_source=A" -hdr "Cookie: '+cookie+'"','rxresp','expect resp.status == 200',
                             'expect resp.http.X-Test-Session ~ {'+expected+'}'])
        content='varnishtest "Native CMS session protocol"\nvarnish v1 -vcl {\n'+vcl+'\n} -start\nclient c1 {\n'+'\n'.join(requests)+'\n} -run\n'
        script=self.folder/'session.vtc';script.write_text(content)
        result=subprocess.run(['varnishtest','-t','20',str(script)],capture_output=True,text=True,timeout=30)
        worker.join(timeout=10)
        self.assertEqual(result.returncode,0,'\n'.join(line for line in (result.stdout+result.stderr).splitlines() if line.startswith('----')))
        self.assertFalse(errors,str(errors));self.assertFalse(worker.is_alive())
        return received

    def test_fresh_guest_auth_state_each_request_and_original_cookie_url(self):
        received=self.execute(['guest\tjoomla-guest-session\n','private\tjoomla-authenticated-session\n'],
                              ['session=same-id; _ga=A','session=same-id; _ga=B'],
                              ['^guest[[:blank:]]joomla-guest-session$','^private[[:blank:]]joomla-authenticated-session$'])
        self.assertEqual([r['schema'] for r in received],[1,1])
        self.assertEqual([r['path'] for r in received],['/page?utm_source=A']*2)
        self.assertEqual([r['cookie'] for r in received],['session=same-id; _ga=A','session=same-id; _ga=B'])
        self.assertTrue(all(r['site']=='a'*32 for r in received))

    def test_protocol_does_not_reflect_untrusted_values_as_reason(self):
        self.execute(['guest\tsecret=value\n'],['session=id'],['^unresolved[[:blank:]]cms-session-protocol$'])


if __name__=='__main__':unittest.main()
