"""Root-owned local transport, with all customer reads/queries under their UID.

No session values are logged or retained. The server does not cache guest state.
Site identifiers select private root-owned descriptors, never request file paths.
"""
import argparse
import json
import os
from pathlib import Path
import pwd
import re
import socket
import socketserver
import stat
import struct
import subprocess
import sys
from urllib.parse import unquote, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cms_sessions

UNAVAILABLE = 'unresolved\tcms-session-unavailable\n'


def configuration(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor) as stream:
        info = os.fstat(stream.fileno())
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o077 or not stat.S_ISREG(info.st_mode):
            raise ValueError('Resolver configuration must be root private')
        value = json.load(stream)
    if value.get('schema') != 1 or not isinstance(value.get('sites'), dict):
        raise ValueError('Invalid resolver configuration')
    return value


def select_installation(site, path):
    pathname = unquote(urlsplit(path).path)
    if not pathname.startswith('/') or '\x00' in pathname:
        raise ValueError('Invalid request path')
    matching = [row for row in site['installations'] if row['cms'] == 'joomla' and
                (row['base'] == '/' or pathname == row['base'].rstrip('/') or
                 pathname.startswith(row['base'].rstrip('/') + '/'))]
    return max(matching, key=lambda row: len(row['base'])) if matching else None


def resolve(config, request):
    if (request.get('schema') != 1 or not re.fullmatch('[a-f0-9]{32}', request.get('site', '')) or
            not isinstance(request.get('path'), str) or not isinstance(request.get('cookie'), str)):
        return 'unresolved\tcms-session-protocol\n'
    site = config['sites'].get(request['site'])
    if site is None:
        return 'unresolved\tcms-session-site\n'
    row = select_installation(site, request['path'])
    if row is None:
        return 'unresolved\tcms-session-site\n'
    uid, gid = site['uid'], site['gid']
    identity = pwd.getpwuid(uid)
    if uid == 0 or identity.pw_gid != gid or identity.pw_dir != site['home']:
        return 'unresolved\tcms-session-identity\n'
    payload = {'root': row['root'], 'cookie': request['cookie'], 'timeout': config.get('query_timeout'),
               'mysql_socket': config.get('mysql_socket')}
    # Python -I ignores customer PYTHONPATH; -B avoids writing tenant bytecode.
    result = subprocess.run([sys.executable, '-I', '-B', str(Path(__file__).resolve()), '--worker'],
                            input=json.dumps(payload), capture_output=True, text=True,
                            user=uid, group=gid, extra_groups=[], umask=0o077,
                            cwd='/', env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': site['home']},
                            timeout=config.get('query_timeout'))
    if result.returncode or not re.fullmatch(r'(?:guest|private|unresolved)\t[a-z0-9-]+\n', result.stdout):
        return UNAVAILABLE
    return result.stdout


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            config = configuration(self.server.config_path)
            _, uid, _ = struct.unpack('3i', self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid not in [0, *config['allowed_uids']]:
                return
            # Bound the IPC envelope to native request/header allowances supplied
            # by the adapter. This never truncates an accepted site request.
            maximum = config['max_frame_bytes']
            if type(maximum) is not int or maximum <= 0:
                raise ValueError('Invalid transport allowance')
            self.request.settimeout(config.get('query_timeout'))
            data = self.rfile.readline(maximum + 1)
            if len(data) > maximum or not data.endswith(b'\n'):
                answer = 'unresolved\tcms-session-protocol\n'
            else:
                answer = resolve(config, json.loads(data))
            self.wfile.write(answer.encode('ascii'))
        except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
            try:
                self.wfile.write(UNAVAILABLE.encode('ascii'))
            except OSError:
                pass


class Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True


def serve(path):
    config = configuration(path)
    target = Path(config['socket'])
    parent = target.parent.stat()
    if parent.st_uid != 0 or stat.S_IMODE(parent.st_mode) & 0o022:
        raise ValueError('Resolver socket directory must be root owned')
    if target.exists():
        if not target.is_socket() or target.lstat().st_uid != 0:
            raise ValueError('Unexpected resolver socket path')
        target.unlink()
    with Server(str(target), Handler) as server:
        server.config_path = path
        # Peer credentials are checked before reading or spawning a worker.
        if config.get('socket_gid') is not None:
            os.chown(target, 0, config['socket_gid'])
            target.chmod(0o660)
        else:
            target.chmod(0o666)
        server.serve_forever()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--config')
    parser.add_argument('--worker', action='store_true')
    args = parser.parse_args()
    if args.worker:
        if os.geteuid() == 0:
            raise SystemExit(1)
        try:
            payload = json.load(sys.stdin)
            def query(connection, session):
                if payload.get('mysql_socket') and connection['host'] == 'localhost' and not connection.get('socket'):
                    connection = dict(connection, socket=payload['mysql_socket'])
                return cms_sessions.mysql_session(connection, session, timeout=payload.get('timeout'))
            state, reason = cms_sessions.classify(payload['root'], payload['cookie'], query)
            sys.stdout.write(state + '\t' + reason + '\n')
        except (OSError, ValueError, KeyError, TypeError):
            sys.stdout.write(UNAVAILABLE)
    else:
        if os.geteuid() != 0 or not args.config:
            raise SystemExit(1)
        serve(args.config)
