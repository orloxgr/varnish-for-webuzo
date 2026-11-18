"""Actual Joomla session-token bodies stay private; ordinary forms still HIT."""
import shutil
import base64
import json
import socket
import tempfile
import threading
from pathlib import Path
import unittest
from unittest.mock import patch
import test_profiles as http
import cms_resolver

TOKEN_A='0123456789abcdef0123456789abcdef'
TOKEN_B='fedcba9876543210fedcba9876543210'


@unittest.skipUnless(shutil.which('varnishtest'),'Native Varnish required')
class JoomlaForms(unittest.TestCase):
    run_policy=http.NativeProfiles.run_policy

    def run_joomla(self,profile,responses,requests):
        original=http.site
        def selected(*args,**kwargs):
            row=original(*args,**kwargs)
            if row['domain']=='example.test':row.update(aggressive=True,cms_installations=[dict(cms='joomla',base='/')])
            return row
        with patch.object(http,'site',side_effect=selected):self.run_policy(profile,responses,requests)

    def test_distinct_session_form_tokens_are_not_shared_between_anonymous_visitors(self):
        for profile in ('basic','ultracache'):
            bodies=['<form method="post"><input type="hidden" name="'+token+'" value="1" /></form>' for token in (TOKEN_A,TOKEN_B)]
            responses=[http.origin('/page',body,cache='no-store') for body in bodies]
            requests=[]
            for body in bodies:requests.extend([http.get('/page',body,cache='PASS'),'expect resp.http.X-Webuzo-Varnish-Reason == "joomla-session-form"'])
            self.run_joomla(profile,responses,requests)

    def token_broker(self,answers,callback):
        with tempfile.TemporaryDirectory(prefix='wvw-token-') as folder:
            Path(folder).chmod(0o755);path=Path(folder)/'token.sock'
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
            try:
                with patch.object(cms_resolver,'SOCKET',str(path)):callback()
            finally:worker.join(timeout=10)
            self.assertFalse(errors,str(errors));self.assertFalse(worker.is_alive())
            return received

    def test_script_options_csrf_token_is_private_while_public_parent_hits(self):
        for profile in ('basic','ultracache'):
            for gzip in (False,True):
                bodies=['<script type="application/json" class="joomla-script-options new">{"csrf.token":"'+token+'"}</script>' for token in (TOKEN_A,TOKEN_B)]
                fields=base64.b64encode(b'Set-Cookie: PHPSESSID=session-B; Path=/; Secure; HttpOnly\nSet-Cookie: preferences='+b'x'*300+b'; Expires=Wed, 18 Nov 2027 00:00:00 GMT; SameSite=Lax').decode()
                origin=http.origin('/page',bodies[0],['Set-Cookie: PHPSESSID=session-A; Path=/; Secure; HttpOnly','ETag: "private-A"'],cache='no-store')
                if gzip:origin=origin.replace('-body {','-gzipbody {')
                requests=[http.get('/page',bodies[0],cache='MISS'),'expect resp.http.Set-Cookie == "PHPSESSID=session-A; Path=/; Secure; HttpOnly"',
                          'expect resp.http.ETag == <undef>',
                          http.get('/page',bodies[1],['Accept-Language: el-GR,en;q=0.8'],cache='HIT'),'expect resp.http.Set-Cookie == "PHPSESSID=session-B; Path=/; Secure; HttpOnly"',
                          'expect resp.http.ETag == <undef>',
                          http.get('/page',bodies[0],['Cookie: PHPSESSID=session-A'],cache='HIT'),'expect resp.http.Set-Cookie == <undef>',
                          http.get('/.__varnish_cms_token/v1',None,status=403)]
                with self.subTest(profile=profile,gzip=gzip):
                    received=self.token_broker(['token\t'+TOKEN_B+'\t'+fields+'\n','token\t'+TOKEN_A+'\t\n'],
                        lambda:self.run_joomla(profile,[origin],requests))
                    self.assertEqual([r['op'] for r in received],['token','token'])
                    self.assertEqual(received[0]['accept_language'],'el-GR,en;q=0.8')
                    self.assertEqual(received[1]['cookie'],'PHPSESSID=session-A')

    def test_token_provider_failure_uses_original_origin_html_without_placeholder(self):
        for profile in ('basic','ultracache'):
            bodies=['<script type="application/json">{"csrf.token":"'+token+'"}</script>' for token in (TOKEN_A,TOKEN_B)]
            self.token_broker(['unresolved\tjoomla-token-unavailable\n'],lambda:self.run_joomla(profile,
                [http.origin('/page',body,cache='no-store') for body in bodies],
                [http.get('/page',bodies[0],cache='MISS'),http.get('/page',bodies[1],cache='PASS'),
                 'expect resp.http.X-Webuzo-Varnish-Reason == "joomla-token-unavailable"']))

    def test_ordinary_forms_script_examples_and_comments_remain_cacheable(self):
        bodies=['<form><input name="email" type="email"><button>Newsletter</button></form>',
                '<!-- <form><input type="hidden" name="'+TOKEN_A+'" value="1"></form> -->Public',
                '<script>let example=\'<form><input type="hidden" name="'+TOKEN_A+'" value="1"></form>\';</script>Public',
                '<textarea><form><input type="hidden" name="'+TOKEN_A+'" value="1"></form></textarea>Public',
                '<!-- <script type="application/json">{"csrf.token":"'+TOKEN_A+'"}</script> -->Public',
                '<textarea><script type="application/json">{"csrf.token":"'+TOKEN_A+'"}</script></textarea>Public']
        for profile in ('basic','ultracache'):
            responses=[];requests=[]
            for i,body in enumerate(bodies):
                url='/public-'+str(i)
                responses.append(http.origin(url,body,cache='no-store'))
                requests.extend([http.get(url,body,cache='MISS'),http.get(url,body,cache='HIT')])
            self.run_joomla(profile,responses,requests)

    def test_gzip_html_is_delivered_unchanged_and_still_detects_private_tokens(self):
        for profile in ('basic','ultracache'):
            public='<html>public page</html>'
            private='<form><input value="1" name="'+TOKEN_A+'" type="hidden"></form>'
            responses=[http.origin('/public',public,cache='no-store').replace('-body {','-gzipbody {'),
                       http.origin('/private',private,cache='no-store').replace('-body {','-gzipbody {')]
            self.run_joomla(profile,responses,[http.get('/public',public,cache='MISS'),http.get('/public',public,cache='HIT'),http.get('/private',private,cache='PASS')])

    def test_large_html_and_token_at_end_have_no_scanning_cutoff(self):
        for profile in ('basic','ultracache'):
            body='<html>'+('public content '*20000)+'<form><input value="1" type="hidden" name="'+TOKEN_A+'"></form></html>'
            self.run_joomla(profile,[http.origin('/large',body,cache='no-store')],[http.get('/large',body,cache='PASS')])


if __name__=='__main__':unittest.main()
