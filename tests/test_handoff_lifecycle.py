"""Discarded fetches and disconnected clients must not retain cookie fields."""
import shutil
import socket
import threading
import time
import unittest

from test_cookie_delivery import proxy,cookies


def pending(source):
    return source.replace(' call scp_deliver;',
        ' call scp_deliver; set resp.http.X-Test-Pending = cookie_handoff.pending();')


@unittest.skipUnless(shutil.which('varnishd'),'Native Varnish required')
class HandoffLifecycle(unittest.TestCase):
    def test_failed_body_fetch_discards_headers_from_the_failed_response(self):
        def origin(path,headers):
            if path=='/broken':
                return 'short',[('Cache-Control','public, max-age=120'),('Content-Length','100'),('Set-Cookie','_fbp=failed-body; Path=/')]
            return 'probe',[('Cache-Control','public, max-age=120')]
        def complete_fetch(source):
            return pending(source).replace('sub vcl_backend_response {',
                'sub vcl_backend_response { set beresp.do_stream = false;')
        for profile in ('basic','ultracache'):
            with self.subTest(profile=profile),proxy(profile,origin,transform=complete_fetch) as get:
                get('/probe')
                status,fields,_=get('/broken')
                self.assertEqual(status,503);self.assertEqual(cookies(fields),[])
                _,fields,_=get('/probe');self.assertEqual(dict(fields)['X-Test-Pending'],'0')

    def test_background_refill_does_not_replay_its_cookies_or_leave_entries(self):
        for profile in ('basic','ultracache'):
            calls=[];refill=threading.Event()
            def origin(path,headers):
                calls.append(path)
                number=len(calls)
                if number==2:refill.set()
                return 'version-'+str(number),[('Cache-Control','public, max-age=1'),('Set-Cookie','_fbp=origin-'+str(number)+'; Path=/')]
            def grace(source):
                return pending(source).replace('sub vcl_backend_response {',
                    'sub vcl_backend_response { set beresp.grace = 60s;')
            with self.subTest(profile=profile),proxy(profile,origin,transform=grace) as get:
                _,fields,body=get('/background')
                self.assertEqual(body,'version-1');self.assertEqual(cookies(fields),['_fbp=origin-1; Path=/'])
                time.sleep(1.1)
                _,fields,_=get('/background')
                self.assertEqual(dict(fields)['X-Cache'],'HIT');self.assertEqual(cookies(fields),[])
                self.assertTrue(refill.wait(5))
                for _ in range(100):
                    _,fields,body=get('/background')
                    self.assertEqual(cookies(fields),[])
                    if body=='version-2':break
                    time.sleep(.01)
                self.assertEqual(body,'version-2');self.assertEqual(dict(fields)['X-Test-Pending'],'0')
                self.assertEqual(len(calls),2)

    def test_client_restart_to_a_warmed_hit_discards_the_old_response_cookies(self):
        for profile in ('basic','ultracache'):
            def origin(path,headers):
                return path,[('Cache-Control','public, max-age=120')]+(
                    [('Set-Cookie','_fbp=discarded; Path=/')] if path=='/discard' else [])
            def restart(source):
                return pending(source).replace('sub vcl_deliver {','''sub vcl_deliver {
 if (req.url == "/discard" && req.restarts == 0) {
   set req.url = "/prime";
   set req.http.X-WV-Gateway = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
   return (restart);
 }
''')
            with self.subTest(profile=profile),proxy(profile,origin,transform=restart) as get:
                get('/prime')
                _,fields,body=get('/discard')
                self.assertEqual(body,'/prime');self.assertEqual(dict(fields)['X-Cache'],'HIT')
                self.assertEqual(cookies(fields),[])
                _,fields,_=get('/prime');self.assertEqual(dict(fields)['X-Test-Pending'],'0')

    def test_backend_retry_does_not_deliver_the_discarded_attempts_cookie(self):
        for profile in ('basic','ultracache'):
            calls=[]
            def origin(path,headers):
                calls.append(path)
                return 'final',[('Cache-Control','public, max-age=120')]+(
                    [('Set-Cookie','_fbp=discarded; Path=/')] if len(calls)==1 else [])
            def retry(source):
                return pending(source).replace('sub vcl_backend_response {','''sub vcl_backend_response {
 if (bereq.url == "/retry" && bereq.retries == 0) {
   call scp_backend_response; return (retry);
 }
''')
            with self.subTest(profile=profile),proxy(profile,origin,transform=retry) as get:
                _,fields,body=get('/retry')
                self.assertEqual(body,'final');self.assertEqual(calls,['/retry','/retry'])
                self.assertEqual(cookies(fields),[])
                _,fields,_=get('/retry');self.assertEqual(dict(fields)['X-Cache'],'HIT')
                self.assertEqual(dict(fields)['X-Test-Pending'],'0')

    def test_disconnect_before_origin_response_releases_the_client_owned_entry(self):
        started=threading.Event();finish=threading.Event();completed=threading.Event()
        def origin(path,headers):
            if path=='/abort':
                started.set();finish.wait(5);completed.set()
                return 'aborted',[('Cache-Control','public, max-age=120'),('Set-Cookie','_fbp=aborted-client; Path=/')]
            return 'probe',[('Cache-Control','public, max-age=120')]
        with proxy('basic',origin,transform=pending) as get:
            get('/probe')
            with socket.create_connection(get.endpoint) as connection:
                connection.sendall(b'GET /abort HTTP/1.1\r\nHost: example.test\r\nX-WV-Gateway: '+b'e'*64+b'\r\nConnection: close\r\n\r\n')
                self.assertTrue(started.wait(5))
            finish.set();self.assertTrue(completed.wait(5))
            for _ in range(100):
                _,fields,_=get('/probe')
                self.assertEqual(cookies(fields),[])
                if dict(fields)['X-Test-Pending']=='0':break
                time.sleep(.02)
            self.assertEqual(dict(fields)['X-Test-Pending'],'0')


if __name__=='__main__':unittest.main()
