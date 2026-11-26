"""Read real HTTP header fields: cookie commas are not header separators."""
import contextlib
import http.client
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest

from test_profiles import program


def policy_for_choices(profile,choices):
    return program(profile,config={'cookie_policies':choices},other_profile=profile)


@contextlib.contextmanager
def proxy(profile, respond, transform=None, configuration=None,policies=None,site_settings=None,other_profile=None,management=False,daemon_parameters=(),allow_post=False,request_body=False,coalesce_response=False):
    """An isolated origin and daemon; never load/restart the installed service."""
    class Origin(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def do_GET(self):
            if request_body:
                body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
                result = respond(self.path, self.headers, body)
            else:
                result = respond(self.path, self.headers)
            if result is None:
                self.close_connection = True # owned upstream EOF/fetch-error fixture
                return
            status, body, headers = result if len(result)==3 else (200,*result)
            if isinstance(body,str):body = body.encode()
            streaming = not isinstance(body,bytes)
            self.send_response(status)
            if not any(name.lower() == 'content-type' for name, _ in headers):
                self.send_header('Content-Type', 'text/html')
            if not streaming and not any(name.lower() == 'content-length' for name, _ in headers):
                self.send_header('Content-Length', str(len(body)))
            self.send_header('Connection', 'close')
            for name, value in headers:
                self.send_header(name, value)
            combined = coalesce_response and not streaming
            if combined:
                self._headers_buffer.append(b'\r\n')
            else:
                self.end_headers()
            try:
                if combined:
                    self.wfile.write(b''.join(self._headers_buffer)+body)
                    self._headers_buffer = []
                elif streaming:
                    for chunk in body:
                        self.wfile.write(chunk);self.wfile.flush()
                else:self.wfile.write(body)
            except (BrokenPipeError,ConnectionResetError):
                pass # abandoned client streaming fixture
            finally:
                if streaming and hasattr(body,'close'):body.close()

        def log_message(self, *args):
            pass

    if allow_post:Origin.do_POST=Origin.do_GET
    origin = ThreadingHTTPServer(('127.0.0.1', 0), Origin)
    thread = threading.Thread(target=origin.serve_forever, daemon=True)
    thread.start()
    daemon = None
    try:
        with tempfile.TemporaryDirectory(prefix='wvw-cookie-http-') as folder:
            root = Path(folder)
            selected=dict(configuration or {})
            if policies is not None:selected['cookie_policies']=policies
            source = program(profile, config=selected,site_settings=site_settings,other_profile=other_profile).replace('${s1_port}', str(origin.server_port))
            module = os.environ.get('SCP_TEST_COOKIE_MODULE')
            if module:
                source = source.replace('import cookie_handoff;', 'import cookie_handoff from "'+module+'";')
            if transform is not None:
                source = transform(source)
            (root / 'policy.vcl').write_text(source)
            with socket.socket() as reservation:
                reservation.bind(('127.0.0.1', 0))
                port = reservation.getsockname()[1]
            admin_args=['-T','none']
            if management:
                with socket.socket() as reservation:
                    reservation.bind(('127.0.0.1',0));admin_port=reservation.getsockname()[1]
                secret=root/'admin.secret';secret.write_text('owned-test-only');secret.chmod(0o600)
                admin_args=['-T','127.0.0.1:'+str(admin_port),'-S',str(secret)]
            with (root / 'daemon.log').open('w+') as log:
                daemon = subprocess.Popen([
                    'varnishd', '-F', '-j', 'none', '-n', str(root / 'instance'),
                    '-f', str(root / 'policy.vcl'), '-a', '127.0.0.1:' + str(port),
                    *admin_args, '-s', 'malloc,16m',
                    '-p', 'feature=+esi_ignore_other_elements',
                    *[arg for value in daemon_parameters for arg in ('-p',value)]], stdout=log, stderr=log)
                # VM startup/compilation allowance for this disposable actor,
                # not an origin/application timeout or a cache policy limit.
                deadline = time.monotonic() + 45
                while True:
                    if daemon.poll() is not None:
                        log.seek(0)
                        raise AssertionError('Isolated Varnish failed: ' + log.read())
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.2):
                            break
                    except OSError:
                        if time.monotonic() >= deadline:
                            log.seek(0)
                            raise AssertionError('Isolated Varnish did not start: ' + log.read())
                        time.sleep(.05)

                def get(path, cookie=None, extra=None):
                    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
                    try:
                        headers = {'Host': 'example.test', 'X-WV-Gateway': 'e' * 64, 'X-Forwarded-Proto': 'https'}
                        if cookie is not None:
                            headers['Cookie'] = cookie
                        if extra is not None:
                            headers.update(extra)
                        connection.request('GET', path, headers=headers)
                        response = connection.getresponse()
                        fields = response.getheaders()
                        body = response.read().decode()
                        return response.status, fields, body
                    finally:
                        connection.close()

                get.endpoint=('127.0.0.1',port)
                # Raw HTTP regressions must use the same adapter entry headers.
                get.request_headers = {'Host': 'example.test', 'X-WV-Gateway': 'e' * 64, 'X-Forwarded-Proto': 'https'}
                def stop_origin():
                    origin.shutdown();origin.server_close();thread.join(timeout=5)
                get.stop_origin=stop_origin
                get.origin_endpoint=('127.0.0.1',origin.server_port)
                get.source=source
                get.instance=root/'instance'
                if management:
                    def adm(*args):
                        # Disposable VM compilation allowance, not an origin
                        # timeout or a product cache lifetime.
                        result=subprocess.run(['varnishadm','-t','30','-T','127.0.0.1:'+str(admin_port),'-S',str(secret),*args],capture_output=True,text=True)
                        if result.returncode:raise AssertionError(result.stdout+result.stderr)
                        return result.stdout
                    def activate(name,content):
                        path=root/(name+'.vcl');path.write_text(content)
                        adm('vcl.load',name,str(path));adm('vcl.use',name)
                    get.adm=adm;get.activate=activate
                try:
                    yield get
                finally:
                    daemon.terminate()
                    daemon.wait(timeout=10)
                    daemon = None
    finally:
        if daemon is not None:
            daemon.terminate()
            daemon.wait(timeout=10)
        origin.shutdown()
        origin.server_close()
        thread.join(timeout=5)


def cookies(fields):
    return [value for name, value in fields if name.lower() == 'set-cookie']


@unittest.skipUnless(shutil.which('varnishd'), 'Native varnishd required')
class NativeCookieDelivery(unittest.TestCase):
    def test_multiple_set_cookie_refresh_and_deletion_are_preserved_per_response(self):
        for profile in ('basic', 'ultracache'):
            calls = []

            def origin(path, headers):
                calls.append(headers.get('Cookie'))
                visitor = str(len(calls))
                fields = [
                    ('Cache-Control', 'public, max-age=120'),
                    ('Set-Cookie', '_fbp=provider-' + visitor + '; Path=/; Max-Age=7776000; SameSite=Lax; Secure'),
                    ('Set-Cookie', 'private_id=visitor-' + visitor + '; Path=/account; HttpOnly; Secure; SameSite=Strict'),
                    ('Set-Cookie', 'obsolete=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; Domain=example.test; Path=/'),
                    ('Set-Cookie', 'locale=el; Path=/shop; SameSite=Lax')]
                return 'origin-' + visitor, fields

            with self.subTest(profile=profile), proxy(profile, origin) as get:
                for visitor in ('1', '2'):
                    status, fields, body = get('/cookies', '_fbp=existing' if visitor == '2' else None)
                    self.assertEqual((status, body), (200, 'origin-' + visitor))
                    self.assertEqual(dict(fields)['X-Webuzo-Varnish'], 'PASS')
                    self.assertEqual(cookies(fields), [value for name, value in [
                        ('Set-Cookie', '_fbp=provider-' + visitor + '; Path=/; Max-Age=7776000; SameSite=Lax; Secure'),
                        ('Set-Cookie', 'private_id=visitor-' + visitor + '; Path=/account; HttpOnly; Secure; SameSite=Strict'),
                        ('Set-Cookie', 'obsolete=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; Domain=example.test; Path=/'),
                        ('Set-Cookie', 'locale=el; Path=/shop; SameSite=Lax')]])
                self.assertEqual(calls, [None, '_fbp=existing'])

    def test_private_esi_children_do_not_overwrite_parent_cookie_fields(self):
        calls = []
        parent_cookies = [
            '_fbp=origin-value; Path=/; Max-Age=7776000; SameSite=Lax',
            'obsolete=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; Path=/',
            'private_id=origin-session; HttpOnly; Path=/']

        def origin(path, headers):
            calls.append(path)
            if path.startswith('/?ultracache_esi='):
                return 'private-fragment', [('Cache-Control', 'private, no-store'),
                    ('Set-Cookie', 'child_id=must-not-escape; HttpOnly; Path=/'),
                    ('Set-Cookie', 'another_child=must-not-escape; Path=/')]
            return '<html><esi:include src="/?ultracache_esi=cart&amp;esi_scope=private"/></html>', [
                ('Cache-Control', 'private, no-store'),
                ('Surrogate-Control', 'content=ESI/1.0, no-store'),
                *[('Set-Cookie', value) for value in parent_cookies]]

        with proxy('ultracache', origin) as get:
            status, fields, body = get('/parent')
            self.assertEqual((status, body), (200, '<html>private-fragment</html>'))
            self.assertEqual(cookies(fields), parent_cookies)
            self.assertEqual(dict(fields)['X-Webuzo-Varnish'], 'PASS')
            self.assertEqual(calls, ['/parent', '/?ultracache_esi=cart&esi_scope=private'])


@unittest.skipUnless(shutil.which('varnishd') and Path('/usr/lib/varnish/vmods/libvmod_header.so').is_file(),
                     'Official native header VMOD required')
class NativeHeaderPrimitive(unittest.TestCase):
    """Test the VMOD transport primitive, not a provider/consent integration."""

    def test_append_and_targeted_removal_preserve_other_cookies_and_deletions(self):
        kept = ['private_id=origin-session; Path=/account; Secure; HttpOnly; SameSite=Strict',
                'obsolete=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; Path=/']

        def origin(path, headers):
            return 'public-body', [('Cache-Control', 'public, max-age=120'),
                ('Set-Cookie', '_fbp=original; Path=/; Secure'),
                *[('Set-Cookie', value) for value in kept]]

        def transform(source):
            return source.replace(
                ' call scp_backend_response;',
                ' header.remove(beresp.http.Set-Cookie, "^_fbp=");\n call scp_backend_response;').replace(
                ' call scp_deliver;',
                ' header.append(resp.http.Set-Cookie, "fixture=independent; Path=/; Secure");\n call scp_deliver;')

        with proxy('basic', origin, transform) as get:
            status, fields, body = get('/primitive')
            self.assertEqual((status, body), (200, 'public-body'))
            self.assertEqual(cookies(fields), kept + ['fixture=independent; Path=/; Secure'])
            self.assertEqual(dict(fields)['X-Webuzo-Varnish'], 'PASS')

    def test_per_delivery_values_never_enter_the_cached_object(self):
        calls = []

        def origin(path, headers):
            calls.append(path)
            return 'same-public-html', [('Cache-Control', 'public, max-age=120')]

        def transform(source):
            return source.replace(
                ' call scp_deliver;',
                ' header.append(resp.http.Set-Cookie, "fixture=" + req.http.X-Fixture-Visitor + "; Path=/");\n call scp_deliver;')

        with proxy('basic', origin, transform) as get:
            for visitor, result in (('A', 'MISS'), ('B', 'HIT'), ('C', 'HIT')):
                status, fields, body = get('/shared', extra={'X-Fixture-Visitor': visitor})
                self.assertEqual((status, body), (200, 'same-public-html'))
                self.assertEqual(cookies(fields), ['fixture=' + visitor + '; Path=/'])
                self.assertEqual(dict(fields)['X-Webuzo-Varnish'], result)
            self.assertEqual(calls, ['/shared'])


if __name__ == '__main__':
    unittest.main()
