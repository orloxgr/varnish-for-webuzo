"""Start the generated helper unit on an explicitly disposable Linux lab."""
import argparse
import json
import os
from pathlib import Path
import pwd
import socket
import stat
import subprocess
import sys
import tempfile
import time

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--disposable',action='store_true',required=True)
args=parser.parse_args()
if os.geteuid()!=0:parser.error('Root is required on the disposable lab')
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import cms_resolver
import service

name='wvw-cms-resolver-runtime-test'
unit_path=Path('/etc/systemd/system')/(name+'.service')
if unit_path.exists() or unit_path.is_symlink():raise RuntimeError('Test unit name is already occupied')
account=pwd.getpwnam('cachelab1')
daemon=pwd.getpwnam(service.DAEMON)
source=Path(__file__).resolve().parents[1]/'shared/cms_session_server.py'

with tempfile.TemporaryDirectory(prefix='wvw-cms-unit-',dir='/var/lib') as temporary:
    # Match panel-owned /home: the worker may traverse this directory without
    # being able to list it, and must still read the known Joomla files.
    root=Path(temporary);root.chmod(0o711)
    version=root/'libraries/src/Version.php';version.parent.mkdir(parents=True)
    version.write_text('<?php const MAJOR_VERSION = 3;')
    (root/'configuration.php').write_text("<?php class JConfig { public $secret='runtime-test'; public $session_handler='database'; public $host='localhost'; public $user='unused'; public $password='unused'; public $db='unused'; public $dbprefix='j_'; }")
    socket_path='/run/'+name+'/sessions.sock'
    configuration=dict(schema=1,socket=socket_path,socket_gid=daemon.pw_gid,allowed_uids=[daemon.pw_uid],
        max_frame_bytes=cms_resolver.frame_bytes(),query_timeout=60,mysql_socket='/var/lib/mysql/mysql.sock',
        sites={'a'*32:dict(uid=account.pw_uid,gid=account.pw_gid,home=account.pw_dir,
                         installations=[dict(cms='joomla',root=str(root),base='/')])})
    config=root/'cms-sessions.json';config.write_text(json.dumps(configuration));config.chmod(0o600)
    content=cms_resolver.unit().replace('RuntimeDirectory=varnish-for-webuzo-cms','RuntimeDirectory='+name).replace(
        '/usr/local/webuzo/plugins/varnish-for-webuzo/shared/cms_session_server.py',str(source)).replace(
        '/var/lib/varnish-for-webuzo/cms-sessions.json',str(config))
    fd=os.open(unit_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
    with os.fdopen(fd,'w') as output:output.write(content)
    def systemctl(*arguments):
        return subprocess.run(['systemctl',*arguments],capture_output=True,text=True,check=True).stdout
    try:
        systemctl('daemon-reload');systemctl('start',name)
        deadline=time.monotonic()+15
        while not Path(socket_path).exists():
            if time.monotonic()>deadline:
                raise RuntimeError('Runtime helper did not create its socket: '+systemctl('status',name,'--no-pager'))
            time.sleep(.05)
        info=Path(socket_path).stat()
        assert info.st_uid==0 and info.st_gid==daemon.pw_gid and stat.S_IMODE(info.st_mode)==0o660
        code='''import json,socket,sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.connect(sys.argv[1])
s.sendall((json.dumps(dict(schema=1,site='a'*32,path='/page',cookie='_ga=anonymous'))+'\\n').encode())
print(s.makefile('rb').readline().decode().strip());s.close()
'''
        result=subprocess.run([sys.executable,'-c',code,socket_path],capture_output=True,text=True,
                              user=daemon.pw_uid,group=daemon.pw_gid,extra_groups=[])
        assert result.returncode==0,result.stderr
        assert result.stdout.strip()=='guest\tjoomla-no-session',result.stdout
        capabilities=systemctl('show',name,'--property=CapabilityBoundingSet','--value')
        assert all(value in capabilities.lower() for value in ('cap_chown','cap_setuid','cap_setgid'))
        print(json.dumps(dict(systemd_start='passed',socket_mode='0660',socket_group=daemon.pw_gid,
                              varnish_peer_uid=daemon.pw_uid,hosting_worker_uid=account.pw_uid,
                              response='guest/joomla-no-session',capabilities=capabilities.strip())))
    finally:
        subprocess.run(['systemctl','stop',name],capture_output=True)
        if unit_path.read_text()!=content:raise RuntimeError('Test unit changed during cleanup')
        unit_path.unlink();systemctl('daemon-reload')
