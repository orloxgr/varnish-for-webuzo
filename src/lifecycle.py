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


def retire_cms_helper(*, unit=None, source=None):
    """Retire only addon-owned resources after the helper-free VCL is active."""
    unit=unit or Path('/etc/systemd/system/varnish-for-webuzo-cms.service')
    config=state.ROOT/'cms-sessions.json'
    source=source or Path(__file__).resolve().parents[1]
    obsolete=[source/name for name in ('src/cms_resolver.py','shared/cms_sessions.py',
                                      'shared/cms_session_server.py','shared/native/joomla_forms.h')]
    if unit.exists() or unit.is_symlink():
        state.trusted(unit)
        content=unit.read_text()
        owned='ExecStart=/usr/bin/python3 -I -B /usr/local/webuzo/plugins/varnish-for-webuzo/shared/cms_session_server.py --config /var/lib/varnish-for-webuzo/cms-sessions.json'
        if owned not in content.splitlines() or 'Description=Varnish for Webuzo CMS session resolver' not in content.splitlines():
            raise ValueError('An independent service uses the former CMS helper name')
        import native
        native.run('systemctl','disable','--now','varnish-for-webuzo-cms')
        unit.unlink();native.run('systemctl','daemon-reload')
    if config.exists() or config.is_symlink():state.trusted(config);config.unlink()
    for path in obsolete:
        if path.exists() or path.is_symlink():state.trusted(path);path.unlink()
    # Bytecode belongs to the same removed source modules, never tenant code.
    for folder,names in ((source/'src/__pycache__',('cms_resolver',)),
                         (source/'shared/__pycache__',('cms_sessions','cms_session_server'))):
        if not folder.exists():continue
        state.trusted(folder,True)
        for name in names:
            for path in folder.glob(name+'.*.pyc'):state.trusted(path);path.unlink()

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
    with state.locked():
        settings=state.read(state.ROOT/'settings.json',{})
        if settings.get('installed'):
            import cache_size
            import service
            import repository
            cache_size.recover(state.ROOT/'settings.json')
            repository.ensure_cookie_modules()
            repository.ensure_cookie_handoff()
            service.configure_esi()
    import recognition
    recognition.install()
    if settings.get('installed'):
        # An update must activate the shipped policy for existing sites. Run
        # the normal recoverable apply after releasing the provisioning lock.
        import engine
        engine.action(dict(actor='root',admin=True,action='reconcile'))
    retire_cms_helper()

def native_read_tmp():
    state.trusted(TMP);return TMP.read_bytes()

def remove():
    import engine
    engine.remove()
    retire_cms_helper()
    import recognition
    recognition.remove()
    if TMP.exists():
        if native_read_tmp()!=CONTENT:raise ValueError('The owned tmpfiles entry changed')
        TMP.unlink()

if __name__=='__main__':
    try:
        if os.geteuid()!=0 or len(sys.argv)!=2 or sys.argv[1] not in ('install','remove'):raise ValueError('Invalid lifecycle action')
        (install if sys.argv[1]=='install' else remove)();print(json.dumps(dict(ok=True)))
    except Exception as error:print(json.dumps(dict(ok=False,error=str(error))));raise SystemExit(1)
