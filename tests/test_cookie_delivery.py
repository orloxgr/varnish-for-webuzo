"""Read real HTTP header fields: cookie commas are not header separators."""
import contextlib
import http.client
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


@contextlib.contextmanager
def proxy(profile, respond):
    """An isolated origin and daemon; never load/restart the installed service."""
    class Origin(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def do_GET(self):
            body, headers = respond(self.path, self.headers)
            body = body.encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Connection', 'close')
            for name, value in headers:
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    origin = ThreadingHTTPServer(('127.0.0.1', 0), Origin)
    thread = threading.Thread(target=origin.serve_forever, daemon=True)
    thread.start()
    daemon = None
    try:
        with tempfile.TemporaryDirectory(prefix='wvw-cookie-http-') as folder:
            root = Path(folder)
            source = program(profile).replace('${s1_port}', str(origin.server_port))
            (root / 'policy.vcl').write_text(source)
            with socket.socket() as reservation:
                reservation.bind(('127.0.0.1', 0))
                port = reservation.getsockname()[1]
            with (root / 'daemon.log').open('w+') as log:
                daemon = subprocess.Popen([
                    'varnishd', '-F', '-j', 'none', '-n', str(root / 'instance'),
                    '-f', str(root / 'policy.vcl'), '-a', '127.0.0.1:' + str(port),
                    '-T', 'none', '-s', 'malloc,16m',
                    '-p', 'feature=+esi_ignore_other_elements'], stdout=log, stderr=log)
                deadline = time.monotonic() + 15
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

                def get(path, cookie=None):
                    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
                    try:
                        headers = {'Host': 'example.test', 'X-WV-Gateway': 'e' * 64}
                        if cookie is not None:
                            headers['Cookie'] = cookie
                        connection.request('GET', path, headers=headers)
                        response = connection.getresponse()
                        fields = response.getheaders()
                        body = response.read().decode()
                        return response.status, fields, body
                    finally:
                        connection.close()

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


if __name__ == '__main__':
    unittest.main()
