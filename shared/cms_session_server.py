"""Root-owned local transport, with all customer reads/queries under their UID.

No session values are logged or retained. The server does not cache guest state.
Site identifiers select private root-owned descriptors, never request file paths.
"""
import argparse
import base64
import gzip
import http.client
import ipaddress
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
import time
from urllib.parse import unquote, urlsplit, urljoin, parse_qs, urlencode

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cms_sessions

UNAVAILABLE = 'unresolved\tcms-session-unavailable\n'


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self,path,timeout):
        super().__init__('localhost',timeout=timeout);self.path=path

    def connect(self):
        self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout);self.sock.connect(self.path)


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
                (row['base'] == '/' or pathname == unquote(row['base']).rstrip('/') or
                 pathname.startswith(unquote(row['base']).rstrip('/') + '/'))]
    return max(matching, key=lambda row: len(unquote(row['base']))) if matching else None


def resolve(config, request):
    if (not isinstance(request,dict) or request.get('schema') != 1 or not re.fullmatch('[a-f0-9]{32}', request.get('site', '')) or
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


def merge_cookies(header,fields):
    """Keep application-issued values intact; cookie attributes stay on wire."""
    jar=cms_sessions.cookies(header)
    for value in fields:
        pair=value.split(';',1)[0]
        name,separator,value=pair.partition('=')
        name=name.strip()
        if not separator or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+",name):
            raise ValueError('Invalid origin session cookie')
        jar[name]=value.strip()
    return '; '.join(name+'='+value for name,value in jar.items())


def native_host(host,names):
    if not isinstance(host,str):raise ValueError('Invalid visitor host')
    host=host.lower().rstrip('.')
    if not re.fullmatch(r'[a-z0-9.-]+',host) or '..' in host:raise ValueError('Invalid visitor host')
    if not any(host==name.lower() or name.startswith('*.') and host.endswith(name[1:].lower()) and host!=name[2:].lower() for name in names):
        raise ValueError('Host does not belong to this native site')
    return host


def resolve_token(config,request,fetch=None):
    """Obtain a real Joomla token through its core component, not DB writes.

    Only root-owned native destinations are accepted. Caller controls visitor
    context, never Host, gateway credentials or backend/socket destinations.
    The complete response is owned by this one visitor and is never cached.
    """
    state=resolve(config,request)
    if not state.startswith('guest\t'):return state
    try:
        site=config['sites'][request['site']]
        row=select_installation(site,request['path'])
        if row is None:return 'unresolved\tcms-session-site\n'
        scheme=request.get('scheme','https')
        if scheme not in ('http','https'):raise ValueError('Invalid visitor scheme')
        agent=request.get('user_agent','')
        ip=request.get('client_ip','')
        if not isinstance(agent,str) or any(c in agent for c in '\r\n\x00'):raise ValueError('Invalid visitor agent')
        if ip:ip=str(ipaddress.ip_address(ip))
        default_origin=site.get('origin',{})
        names=site.get('names',[default_origin.get('host','')])
        host=native_host(request.get('host',default_origin.get('host')),names)
        origin=site.get('origins',{}).get(scheme,default_origin)
        timeout=config.get('token_timeout',config.get('query_timeout'))
        deadline=time.monotonic()+timeout if timeout is not None else None
        base=row['base'].rstrip('/')
        path=origin.get('init_path',base+'/index.php?option=com_users&view=login&tmpl=component')
        if 'init_path' not in origin:
            source=urlsplit(request['path'])
            language=parse_qs(source.query).get('lang',[''])[0]
            relative=unquote(source.path)[len(unquote(base)):].lstrip('/')
            first=relative.split('/',1)[0]
            if not language and re.fullmatch(r'[a-zA-Z]{2,3}(?:-[a-zA-Z0-9]{2,8})?',first):language=first
            if language and re.fullmatch(r'[a-zA-Z]{2,3}(?:-[a-zA-Z0-9]{2,8})?',language):path+='&'+urlencode({'lang':language})
        if not path.startswith('/') or path.startswith('//') or any(c in path for c in '\r\n\x00'):
            raise ValueError('Invalid core component route')
        cookie=request['cookie'];issued=[];seen=set()
        while True:
            location_key=(scheme,host,path)
            if location_key in seen:raise ValueError('Origin component redirect loop')
            seen.add(location_key)
            remaining=max(.001,deadline-time.monotonic()) if deadline is not None else None
            if deadline is not None and time.monotonic()>=deadline:raise TimeoutError('Native origin allowance elapsed')
            headers={'Host':host,'Accept':'text/html','Accept-Encoding':'identity','Connection':'close',
                     'X-Forwarded-Proto':scheme,'X-Forwarded-Port':'443' if scheme=='https' else '80',
                     'User-Agent':agent,'Cookie':cookie}
            language=request.get('accept_language','')
            if not isinstance(language,str) or any(c in language for c in '\r\n\x00'):raise ValueError('Invalid visitor language')
            if language:headers['Accept-Language']=language
            if ip:headers.update({'X-Real-IP':ip,'X-Forwarded-For':ip})
            for name,value in origin.get('headers',{}).items():
                if not isinstance(name,str) or not isinstance(value,str) or any(c in name+value for c in '\r\n\x00'):
                    raise ValueError('Invalid native gateway header')
                headers[name]=value
            if fetch is not None:
                status,fields,body=fetch(origin,path,headers,remaining,scheme)
            else:
                if origin['type']=='tcp':
                    address=str(ipaddress.ip_address(origin['address']))
                    port=origin['port']
                    if type(port) is not int or not 1<=port<=65535:raise ValueError('Invalid native origin port')
                    connection=http.client.HTTPConnection(address,port,timeout=remaining)
                elif origin['type']=='unix':
                    connection=UnixHTTP(origin.get('path',origin.get(scheme+'_socket',origin.get('socket'))),remaining)
                else:raise ValueError('Unsupported native origin transport')
                try:
                    connection.request('GET',path,headers=headers)
                    response=connection.getresponse();status=response.status;fields=response.getheaders();body=response.read()
                finally:connection.close()
            updates=[value for name,value in fields if name.lower()=='set-cookie']
            if any('\r' in value or '\n' in value or '\x00' in value for value in updates):raise ValueError('Invalid origin cookie field')
            issued.extend(updates);cookie=merge_cookies(cookie,updates)
            if status in (301,302,303,307,308):
                location=next((value for name,value in fields if name.lower()=='location'),None)
                if not location:raise ValueError('Missing component redirect')
                target=urlsplit(urljoin(scheme+'://'+host+path,location))
                new_host=native_host(target.hostname,names)
                new_scheme=target.scheme
                if (new_scheme!=scheme and (scheme,new_scheme)!=('http','https')) or target.username or target.password or target.port not in (None,443 if new_scheme=='https' else 80):
                    raise ValueError('Component redirect leaves its native website')
                target_path=unquote(target.path);base_path=unquote(base)
                if any(part in ('.','..') for part in target_path.split('/')):
                    raise ValueError('Component redirect is not canonical')
                if base_path and target_path!=base_path and not target_path.startswith(base_path+'/'):
                    raise ValueError('Component redirect leaves its CMS installation')
                host=new_host;scheme=new_scheme
                origin=site.get('origins',{}).get(scheme,default_origin)
                path=target.path+('?'+target.query if target.query else '')
                continue
            if status!=200:raise ValueError('Core component did not respond successfully')
            encoding=next((value.lower() for name,value in fields if name.lower()=='content-encoding'),'identity')
            if encoding=='gzip':body=gzip.decompress(body)
            elif encoding!='identity':raise ValueError('Unsupported core component encoding')
            token=cms_sessions.token_from_html(body.decode('latin-1'))
            refreshed=resolve(config,dict(request,cookie=cookie))
            if not refreshed.startswith('guest\t'):return refreshed
            wire=base64.b64encode('\n'.join('Set-Cookie: '+value for value in issued).encode('latin-1')).decode('ascii')
            return 'token\t'+token+'\t'+wire+'\n'
    except (OSError,ValueError,KeyError,TypeError,http.client.HTTPException,subprocess.SubprocessError):
        return 'unresolved\tjoomla-token-unavailable\n'


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
                request=json.loads(data)
                answer = resolve_token(config,request) if isinstance(request,dict) and request.get('op')=='token' else resolve(config,request)
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
