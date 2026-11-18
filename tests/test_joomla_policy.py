"""A warm public object must never bypass a fresh opaque-session auth check."""
import json
import os
from pathlib import Path
import shutil
import socket
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import test_profiles as http
import cms_resolver

COOKIE='0123456789abcdef0123456789abcdef'


@unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid()==0 and shutil.which('varnishtest'),'Native Linux/root Varnish required')
class JoomlaPolicy(unittest.TestCase):
    run_policy=http.NativeProfiles.run_policy

    def broker(self,profile,answers,responses,requests,private=False):
        with tempfile.TemporaryDirectory(prefix='cms-broker-policy-') as temporary:
            folder=Path(temporary);folder.chmod(0o755);path=folder/'sessions.sock'
            listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            listener.bind(str(path));path.chmod(0o666);listener.listen();listener.settimeout(10)
            received=[];errors=[]
            def serve():
                try:
                    for answer in answers:
                        connection,_=listener.accept()
                        with connection:
                            received.append(json.loads(connection.makefile('rb').readline()))
                            connection.sendall(answer.encode())
                except Exception as error:errors.append(error)
                finally:listener.close()
            worker=threading.Thread(target=serve,daemon=True);worker.start()
            original=http.site
            def selected(*args,**kwargs):
                row=original(*args,**kwargs)
                if row['domain']=='example.test':
                    row.update(aggressive=True,aggressive_ttl=86400,cms_installations=[dict(cms='joomla',base='/')],
                               cms_sessions=[dict(cms='joomla',base='/',cookie_name=COOKIE,supported=True)])
                    if private:row['cookie_policies']=dict(schemaVersion=1,rules=[dict(id='keep-private',match=dict(kind='exact',value=COOKIE),description='Explicit Private',action='private')])
                return row
            try:
                with patch.object(http,'site',side_effect=selected),patch.object(cms_resolver,'SOCKET',str(path)):
                    self.run_policy(profile,responses,requests)
            finally:
                worker.join(timeout=10)
            self.assertFalse(errors,str(errors));self.assertFalse(worker.is_alive())
            return received

    def test_same_cookie_guest_to_authenticated_cannot_reuse_warm_public_html(self):
        for profile in ('basic','ultracache'):
            first=http.origin('/page','public',['Set-Cookie: '+COOKIE+'=session-A; Path=/','Vary: Cookie'],cache='no-store')
            private=http.origin('/page','private',cache='private, no-store')
            requests=[http.get('/page','public',cache='MISS'),'expect resp.http.Set-Cookie == "'+COOKIE+'=session-A; Path=/"',
                      http.get('/page','public',['Cookie: '+COOKIE+'=session-A'],cache='HIT'),'expect resp.http.Set-Cookie == <undef>',
                      http.get('/page','private',['Cookie: '+COOKIE+'=session-A'],cache='PASS'),
                      'expect resp.http.X-Webuzo-Varnish-Reason == "joomla-authenticated-session"',
                      http.get('/page','public',['Cookie: '+COOKIE+'=session-B'],cache='HIT'),'expect resp.http.Set-Cookie == <undef>']
            received=self.broker(profile,['guest\tjoomla-guest-session\n','private\tjoomla-authenticated-session\n','guest\tjoomla-guest-session\n'],[first,private],requests)
            self.assertEqual([r['cookie'] for r in received],[COOKIE+'=session-A',COOKIE+'=session-A',COOKIE+'=session-B'])

    def test_explicit_private_cookie_choice_wins_over_verified_guest_default(self):
        for profile in ('basic','ultracache'):
            self.broker(profile,['guest\tjoomla-guest-session\n'],[http.origin('/page','private',cache='no-store')],
                [http.get('/page','private',['Cookie: '+COOKIE+'=session-A'],cache='PASS'),
                 'expect resp.http.X-Cache-Cookie-Action == "private"'],private=True)


if __name__=='__main__':unittest.main()
