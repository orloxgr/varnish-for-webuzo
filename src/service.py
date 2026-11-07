"""Own a separate systemd instance; never alter Webuzo or vendor service units."""
from pathlib import Path
import grp
import json
import os
import secrets
import socket
import time
import pwd
import stat
import repository
import native
import routing
import state

UNIT=Path('/etc/systemd/system/varnish-for-webuzo.service')
ADMIN_SECRET=routing.CONFIG/'admin.secret'
ACTIVE=routing.CONFIG/'active.vcl'
DAEMON='webuzo-varnish'
CACHE=Path('/var/lib/varnish-for-webuzo-cache')

def installed():return Path('/usr/sbin/varnishd').is_file()
def running():
    return native.run('systemctl','show','varnish-for-webuzo','--property=ActiveState','--value').strip()=='active'

def admin(*args):return native.run('/usr/bin/varnishadm','-T','127.0.0.1:6086','-S',ADMIN_SECRET,'-t','10',*args)

def wait():
    deadline=time.monotonic()+15
    while time.monotonic()<deadline:
        try:
            if 'running' in admin('status'):return
        except RuntimeError:pass
        time.sleep(.1)
    raise RuntimeError('The Varnish child did not become ready')

def unit():
    return '''[Unit]
Description=Varnish for Webuzo
After=network.target nginx.service
[Service]
Type=simple
User=webuzo-varnish
Group=webuzo-varnish
StateDirectory=varnish-for-webuzo-cache
StateDirectoryMode=0700
RuntimeDirectory=varnish-for-webuzo-cache
RuntimeDirectoryMode=0755
ExecStart=/usr/sbin/varnishd -j none -F -a public=/run/varnish-for-webuzo-cache/frontend.sock,mode=0666 -T 127.0.0.1:6086 -S /etc/varnish-for-webuzo/admin.secret -f /etc/varnish-for-webuzo/active.vcl -n /var/lib/varnish-for-webuzo-cache -s malloc,256m
Restart=on-failure
RestartSec=2
LimitNOFILE=131072
NoNewPrivileges=true
CapabilityBoundingSet=
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ReadWritePaths=/var/lib/varnish-for-webuzo-cache
[Install]
WantedBy=multi-user.target
'''

def prepare():
    for port in (6086,):
        with socket.socket() as sock:
            sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            try:sock.bind(('127.0.0.1',port))
            except OSError:raise ValueError('Required local port is already in use: '+str(port)) from None
    if UNIT.exists() and native.read(UNIT).decode()!=unit():raise ValueError('An independent unit already uses this service name')
    repository.ensure_package()
    try:daemon=pwd.getpwnam(DAEMON)
    except KeyError:
        native.run('useradd','--system','--user-group','--no-create-home','--home-dir','/nonexistent','--shell','/usr/sbin/nologin',DAEMON)
        daemon=pwd.getpwnam(DAEMON)
    group=grp.getgrnam(DAEMON)
    if (not 0<daemon.pw_uid<1000 or daemon.pw_gid!=group.gr_gid or group.gr_gid==0 or daemon.pw_dir!='/nonexistent' or daemon.pw_shell!='/usr/sbin/nologin' or
        {p.pw_name for p in pwd.getpwall() if p.pw_gid==group.gr_gid}-{DAEMON} or set(group.gr_mem)-{DAEMON,'root'}):
        raise ValueError('The dedicated Varnish system identity is unsafe')
    if CACHE.exists() or CACHE.is_symlink():
        info=CACHE.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=daemon.pw_uid or info.st_gid!=group.gr_gid or stat.S_IMODE(info.st_mode)!=0o700:
            raise ValueError('Untrusted Varnish runtime directory')
    state.mkdir(routing.CONFIG,0o750);os.chown(routing.CONFIG,0,group.gr_gid)
    state.mkdir(routing.CONFIG/'generations',0o750);os.chown(routing.CONFIG/'generations',0,group.gr_gid)
    if not ADMIN_SECRET.exists():state.write(ADMIN_SECRET,secrets.token_hex(32).encode())
    state.trusted(ADMIN_SECRET);os.chown(ADMIN_SECRET,0,group.gr_gid);ADMIN_SECRET.chmod(0o640)
    state.write(UNIT,unit().encode());UNIT.chmod(0o644)
    native.run('systemctl','daemon-reload')

def write_vcl(path,content):
    state.write(path,content.encode());os.chown(path,0,grp.getgrnam(DAEMON).gr_gid);path.chmod(0o640)

def load(content):
    name='wvw_'+secrets.token_hex(16)
    path=routing.CONFIG/'generations'/(name+'.vcl');write_vcl(path,content)
    try:admin('vcl.load',name,str(path))
    except Exception:
        path.unlink();raise RuntimeError('Varnish rejected the candidate policy; existing policy retained') from None
    active=next(line.split()[-1] for line in admin('vcl.list').splitlines() if line.strip().startswith('active'))
    return active,name

def prune():
    # Discard only our unused generations, and preserve busy VCLs until later.
    for line in admin('vcl.list').splitlines():
        parts=line.split()
        if not parts or parts[0]=='active' or not parts[-1].startswith('wvw_'):continue
        try:admin('vcl.discard',parts[-1])
        except RuntimeError:continue
        path=routing.CONFIG/'generations'/(parts[-1]+'.vcl')
        state.trusted(path);path.unlink()

def purge(site):
    state.identity(site['id'])
    admin('ban','obj.http.X-WV-Site','==',site['id'])

def stop():
    if UNIT.exists():
        if native.read(UNIT).decode()!=unit():raise ValueError('The owned service unit was changed')
        native.run('systemctl','disable','--now','varnish-for-webuzo')
        # Varnish may report exit status 64 when systemd terminates its child.
        # Clear that stopped unit's failure state before systemd cleans its state.
        native.run('systemctl','reset-failed','varnish-for-webuzo')
        native.run('systemctl','clean','--what=state','varnish-for-webuzo')
        UNIT.unlink();native.run('systemctl','daemon-reload')
