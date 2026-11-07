"""Provision one scoped capability through an unprivileged, fixed helper."""
import json
from pathlib import Path
import pwd
import subprocess

def change(site,enabled):
    user=pwd.getpwnam(site['owner'])
    if user.pw_uid==0 or user.pw_uid!=site['uid'] or user.pw_gid!=site['gid'] or user.pw_dir!=site['home']:raise ValueError('Hosting identity changed')
    payload=json.dumps(dict(site=site['id'],names=site['names'],token=site['token'],roots=site['credential_roots'])).encode() if enabled else b''
    result=subprocess.run(['/usr/bin/python3','-I','-B',str(Path(__file__).with_name('account.py')),'save' if enabled else 'remove',user.pw_dir,site['id']],
        input=payload,capture_output=True,timeout=15,user=user.pw_uid,group=user.pw_gid,extra_groups=[],umask=0o077,
        env={'PATH':'/usr/bin:/bin','HOME':user.pw_dir,'LANG':'C.UTF-8'})
    if result.returncode:
        try:detail=json.loads(result.stdout).get('error','Account credential helper failed')
        except (ValueError,AttributeError):detail='Account credential helper failed'
        raise RuntimeError('Could not provision the site purge credential for '+site['domain']+': '+str(detail)[:500])
