"""Actual generated Nginx file boundary; explicit mock application/Varnish upstream."""
from contextlib import contextmanager
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import browser_cache
import native
import routing


@contextmanager
def gateway(test):
    seen = []
    class Application(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.path)
            body = b'dynamic application result'
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Cache-Control', 'private, no-store')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers(); self.wfile.write(body)
        def log_message(self, *args): pass
    origin = ThreadingHTTPServer(('127.0.0.1', 0), Application)
    thread = threading.Thread(target=origin.serve_forever, daemon=True); thread.start()
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix='wvw-source-map-') as folder:
            root = Path(folder); (root / 'assets').mkdir()
            payload = b'{"version":3,"sources":["style.scss"]}'
            (root / 'assets/style.css.map').write_bytes(payload)
            site = dict(id='a' * 32, names=['example.test'], enabled=True, error='', bypass=[])
            with socket.socket() as reservation:
                reservation.bind(('127.0.0.1', 0)); port = reservation.getsockname()[1]
            target = 'http://127.0.0.1:' + str(origin.server_port)
            locations = routing.domain(site, 'e' * 64).replace(
                'http://unix:/run/varnish-for-webuzo-cache/frontend.sock:', target).replace('http://127.0.0.1:8081', target)
            config = ('worker_processes 1;\n' + ('user root;\n' if os.geteuid() == 0 else '')
                + 'pid ' + str(root / 'nginx.pid') + ';\nerror_log ' + str(root / 'nginx.log')
                + ';\nevents {}\nhttp { access_log off;\n' + browser_cache.maps({site['id']: site}, {})
                + 'server { listen 127.0.0.1:' + str(port) + '; server_name example.test; root '
                + str(root) + ';\n' + locations + '\n}\n}')
            path = root / 'nginx.conf'; path.write_text(config)
            command = [str(native.NGINX), '-p', str(root), '-c', str(path)]
            checked = subprocess.run(command + ['-t'], capture_output=True, text=True)
            test.assertEqual(checked.returncode, 0, checked.stderr)
            with (root / 'process.log').open('w+') as log:
                process = subprocess.Popen(command + ['-g', 'daemon off;'], stdout=log, stderr=subprocess.STDOUT)
                deadline = time.monotonic() + 10
                while True:
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.2): break
                    except OSError:
                        if process.poll() is not None or time.monotonic() >= deadline:
                            log.seek(0); test.fail('Isolated Nginx did not start: ' + log.read())
                        time.sleep(.02)
                def request(url):
                    client = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
                    try:
                        client.request('GET', url, headers={'Host': 'example.test'})
                        response = client.getresponse()
                        return response.status, {k.lower(): v for k, v in response.getheaders()}, response.read()
                    finally: client.close()
                try: yield request, seen, payload
                finally:
                    process.terminate(); process.wait(timeout=10); process = None
    finally:
        if process is not None: process.terminate(); process.wait(timeout=10)
        origin.shutdown(); origin.server_close(); thread.join()


@unittest.skipUnless(sys.platform.startswith('linux') and native.NGINX.is_file(), 'Native Webuzo Nginx required')
class NativeSourceMapBoundary(unittest.TestCase):
    def test_existing_source_map_is_served_before_the_dynamic_boundary(self):
        with gateway(self) as (request, seen, payload):
            status, headers, body = request('/assets/style.css.map')
            self.assertEqual((status, body), (200, payload))
            self.assertEqual(headers.get('content-type'), 'application/json')
            self.assertEqual(headers.get('x-webuzo-varnish'), 'STATIC')
            self.assertEqual(seen, [], 'Existing public file must not execute the dynamic upstream')

    def test_missing_source_map_keeps_the_original_dynamic_fallback(self):
        with gateway(self) as (request, seen, _):
            url = '/assets/missing.css.map?ver=7'
            status, headers, body = request(url)
            self.assertEqual((status, body), (200, b'dynamic application result'))
            self.assertEqual(headers.get('cache-control'), 'private, no-store')
            self.assertNotIn('x-webuzo-varnish', headers)
            self.assertEqual(seen, [url], 'Missing file must retain its original URL and query')


if __name__ == '__main__': unittest.main()
