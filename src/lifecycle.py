"""Native plugin activation creates IPC; service setup is an explicit panel action."""
import grp
import json
import os
from pathlib import Path
import pwd
import stat
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import state

TMP=Path('/etc/tmpfiles.d/varnish-for-webuzo.conf')
CONTENT=b'd /run/varnish-for-webuzo 0730 root webuzo -\n'

def install():
    panel=pwd.getpwnam('webuzo')
    members=set(grp.getgrgid(panel.pw_gid).gr_mem)|{p.pw_name for p in pwd.getpwall() if p.pw_gid==panel.pw_gid}
    if panel.pw_uid==0 or panel.pw_gid==0 or members-{'root','webuzo'}:raise ValueError('Unsafe native panel identity')
    state.mkdir(state.ROOT)
    if not state.RUN.exists():
        state.RUN.mkdir(mode=0o730);os.chown(state.RUN,0,panel.pw_gid);state.RUN.chmod(0o730)
    info=state.RUN.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_gid!=panel.pw_gid or stat.S_IMODE(info.st_mode)!=0o730:raise ValueError('Unsafe IPC directory')
    if TMP.exists() and native_read_tmp()!=CONTENT:raise ValueError('An unrelated tmpfiles configuration exists')
    state.write(TMP,CONTENT);TMP.chmod(0o644)

def native_read_tmp():
    state.trusted(TMP);return TMP.read_bytes()

def remove():
    import engine
    engine.remove()
    if TMP.exists():
        if native_read_tmp()!=CONTENT:raise ValueError('The owned tmpfiles entry changed')
        TMP.unlink()

if __name__=='__main__':
    try:
        if os.geteuid()!=0 or len(sys.argv)!=2 or sys.argv[1] not in ('install','remove'):raise ValueError('Invalid lifecycle action')
        (install if sys.argv[1]=='install' else remove)();print(json.dumps(dict(ok=True)))
    except Exception as error:print(json.dumps(dict(ok=False,error=str(error))));raise SystemExit(1)
