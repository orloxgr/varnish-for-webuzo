"""Own a local CMS authentication helper; never change application or panel files."""
import hashlib
from pathlib import Path
import pwd
import re
import socket
import stat
import struct
import time
from urllib.parse import unquote

import native
import service
import state
import timeouts

UNIT=Path('/etc/systemd/system/varnish-for-webuzo-cms.service')
SOCKET='/run/varnish-for-webuzo-cms/sessions.sock'
NAME='varnish-for-webuzo-cms'


def selected(config):
    return {sid:site for sid,site in config.get('sites',{}).items()
            if config.get('installed') and site.get('enabled') and site.get('aggressive') and
            not site.get('error') and any(row['cms']=='joomla' for row in site.get('cms_installations',[]))}


def unit():
    return '''[Unit]
Description=Varnish for Webuzo CMS session resolver
After=network.target
[Service]
Type=simple
User=root
Group=root
RuntimeDirectory=varnish-for-webuzo-cms
RuntimeDirectoryMode=0755
ExecStart=/usr/bin/python3 -I -B /usr/local/webuzo/plugins/varnish-for-webuzo/shared/cms_session_server.py --config /var/lib/varnish-for-webuzo/cms-sessions.json
TimeoutStartSec=infinity
Restart=on-failure
RestartSec=2
UMask=0077
NoNewPrivileges=true
CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_CHOWN
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
[Install]
WantedBy=multi-user.target
'''


def snapshot():
    if UNIT.exists() and native.read(UNIT).decode()!=unit():
        raise ValueError('An independent unit already uses the CMS resolver name')
    return dict(configuration=state.read(state.ROOT/'cms-sessions.json'),
                unit=native.read(UNIT).decode() if UNIT.exists() else None,
                running=UNIT.exists() and native.run('systemctl','show',NAME,'--property=ActiveState','--value').strip()=='active')


def frame_bytes():
    value=service.admin('param.show','http_req_size')
    match=re.search(r'Value is:\s*([0-9]+(?:[.][0-9]+)?)([kmg]?)\s*\[bytes\]',value,re.I)
    if not match:raise ValueError('Cannot read the native HTTP request allowance for the CMS transport')
    size=int(float(match[1])*{'':1,'k':1024,'m':1024**2,'g':1024**3}[match[2].lower()])
    return size*6+128


def configuration(config):
    daemon=pwd.getpwnam(service.DAEMON)
    sites={}
    for sid,site in selected(config).items():
        roots=[dict(cms=row['cms'],base=row['base'],root=str(Path(site['path'])/unquote(row['base']).lstrip('/')))
               for row in site['cms_installations'] if row['cms']=='joomla']
        sites[sid]=dict(uid=site['uid'],gid=site['gid'],home=site['home'],installations=roots,
            names=site['names'],origins={scheme:dict(type='unix',
                path='/run/varnish-for-webuzo-origin-'+scheme+'.sock',
                headers={'X-WV-Origin':config['origin']}) for scheme in ('http','https')})
    root=Path(__file__).resolve().parents[1]/'shared'
    source_identity=hashlib.sha256(b''.join((root/name).read_bytes() for name in
        ('cms_sessions.py','cms_session_server.py','cms_metadata.py','cms_discovery.py','cms_routes.py'))).hexdigest()
    return dict(schema=1,socket=SOCKET,allowed_uids=[daemon.pw_uid],socket_gid=daemon.pw_gid,
                max_frame_bytes=frame_bytes(),query_timeout=timeouts.settings(config)['connect']/1000,
                token_timeout=timeouts.frontend(timeouts.settings(config))['read']/1000,
                mysql_socket='/var/lib/mysql/mysql.sock',sites=sites,source_identity=source_identity)


def prepare(config):
    if not selected(config):return
    previous=snapshot()
    following=configuration(config)
    state.save(state.ROOT/'cms-sessions.json',following)
    if previous['unit'] is None:
        state.write(UNIT,unit().encode());UNIT.chmod(0o644)
        native.run('systemctl','daemon-reload')
    if previous['running'] and previous['configuration'] and previous['configuration'].get('source_identity')!=following['source_identity']:
        native.run('systemctl','restart',NAME)
    else:native.run('systemctl','enable','--now',NAME)
    wait(following)


def wait(config):
    deadline=time.monotonic()+config['query_timeout']
    while True:
        try:
            info=Path(config['socket']).lstat()
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid!=0 or info.st_gid!=config['socket_gid']:
                raise ValueError('Unexpected CMS resolver socket ownership')
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
                connection.settimeout(max(.001,deadline-time.monotonic()))
                connection.connect(config['socket'])
                _,uid,_=struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                if uid!=0:raise ValueError('Unexpected CMS resolver peer identity')
                return
        except (FileNotFoundError,ConnectionRefusedError,socket.timeout):
            if time.monotonic()>=deadline:raise RuntimeError('The CMS session resolver did not become ready') from None
            time.sleep(.05)


def restore(before):
    if before['configuration'] is None:
        path=state.ROOT/'cms-sessions.json'
        if path.exists():state.trusted(path);path.unlink()
    else:state.save(state.ROOT/'cms-sessions.json',before['configuration'])
    if before['unit'] is None:
        if UNIT.exists():
            if native.read(UNIT).decode()!=unit():raise ValueError('The owned CMS resolver unit was changed')
            native.run('systemctl','disable','--now',NAME)
            UNIT.unlink();native.run('systemctl','daemon-reload')
    else:
        if not UNIT.exists():
            state.write(UNIT,before['unit'].encode());UNIT.chmod(0o644);native.run('systemctl','daemon-reload')
        if before['running']:native.run('systemctl','enable','--now',NAME)
        else:native.run('systemctl','stop',NAME)


def finish(config):
    if selected(config) or not UNIT.exists():return
    if native.read(UNIT).decode()!=unit():raise ValueError('The owned CMS resolver unit was changed')
    native.run('systemctl','disable','--now',NAME)
    path=state.ROOT/'cms-sessions.json'
    if path.exists():state.trusted(path);path.unlink()
    UNIT.unlink();native.run('systemctl','daemon-reload')
