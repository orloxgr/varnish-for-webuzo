"""Manage the shared recognition snapshot without touching cache policy or sites."""
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import native
import state

SHARED = Path(__file__).resolve().parents[1] / 'shared'
sys.path.insert(0, str(SHARED))
import cookie_recognition

BUNDLED = SHARED / 'cookie-recognition/recognition.json'
DIRECTORY = state.ROOT / 'cookie-recognition'
ENTRY = Path(__file__).resolve()
SERVICE = Path('/etc/systemd/system/varnish-for-webuzo-cookie-recognition@.service')
TIMER = Path('/etc/systemd/system/varnish-for-webuzo-cookie-recognition.timer')
DAILY = 'varnish-for-webuzo-cookie-recognition@daily.service'
MANUAL = 'varnish-for-webuzo-cookie-recognition@manual.service'


def unit_files():
    return {
        SERVICE: '''[Unit]
Description=Update cookie recognition data for Varnish for Webuzo
Wants=network-online.target
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -I -B "''' + str(ENTRY) + '''" --mode %i
User=root
Group=root
UMask=0077
NoNewPrivileges=true
CapabilityBoundingSet=
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ReadWritePaths=''' + str(DIRECTORY) + '''
''',
        TIMER: '''[Unit]
Description=Daily cookie recognition update for Varnish for Webuzo
[Timer]
OnCalendar=daily
RandomizedDelaySec=30m
Persistent=true
Unit=''' + DAILY + '''
[Install]
WantedBy=timers.target
''',
    }


def check_units():
    for path, content in unit_files().items():
        if path.exists() or path.is_symlink():
            if native.read(path) != content.encode():
                raise ValueError('The cookie recognition unit was changed: ' + path.name)


def install():
    state.mkdir(DIRECTORY)
    check_units()
    changed = False
    for path, content in unit_files().items():
        if not path.exists():
            state.write(path, content.encode()); path.chmod(0o644); changed = True
    if changed:
        native.run('systemctl', 'daemon-reload')
    automatic = cookie_recognition.status(DIRECTORY, BUNDLED)['automatic']
    native.run('systemctl', 'enable' if automatic else 'disable', '--now', TIMER.name)


def remove():
    check_units()
    if TIMER.exists():
        native.run('systemctl', 'disable', '--now', TIMER.name)
    if SERVICE.exists():
        native.run('systemctl', 'stop', DAILY, MANUAL)
    changed = False
    for path in unit_files():
        if path.exists():
            path.unlink(); changed = True
    if changed:
        native.run('systemctl', 'daemon-reload')
    # Keep the last valid snapshot and preferences across reactivation.


def worker_state(name):
    values = {}
    output = native.run('systemctl', 'show', name,
                        '--property=ActiveState,SubState,Result,ExecMainStatus,ExecMainExitTimestampMonotonic,Job')
    for line in output.splitlines():
        if '=' in line:
            key, value = line.split('=', 1); values[key] = value
    job = values.get('Job', '0').split()
    pending = bool(job and job[0] != '0')
    return dict(running=pending or values.get('ActiveState') in ('active', 'activating'),
                result=values.get('Result', ''), exit_status=values.get('ExecMainStatus', ''),
                finished=int(values.get('ExecMainExitTimestampMonotonic', '0') or '0'))


def status():
    result = dict(cookie_recognition.status(DIRECTORY, BUNDLED))
    result.update(updating=False, scheduled=False, schedule_error='', worker_error='')
    try:
        check_units()
        if TIMER.exists() and SERVICE.exists():
            result['scheduled'] = native.run('systemctl', 'show', TIMER.name,
                '--property=UnitFileState', '--value').strip() == 'enabled'
            workers = [worker_state(name) for name in (DAILY, MANUAL)]
            result['updating'] = any(worker['running'] for worker in workers)
            latest = max(workers, key=lambda worker: worker['finished'])
            if not result['updating'] and latest['finished'] and latest['result'] not in ('', 'success'):
                result['worker_error'] = 'The last database update worker failed (' + latest['result'] + ').'
    except (ValueError, RuntimeError) as error:
        result['schedule_error'] = str(error)
    return result


def configure(automatic):
    if type(automatic) is not bool:
        raise ValueError('Automatic recognition updates must be enabled or disabled')
    state.mkdir(DIRECTORY)
    check_units()
    previous = cookie_recognition.status(DIRECTORY, BUNDLED)['automatic']
    cookie_recognition.configure(DIRECTORY, BUNDLED, automatic)
    try:
        install()
    except Exception:
        cookie_recognition.configure(DIRECTORY, BUNDLED, previous)
        raise
    return status()


def start_update():
    install()
    native.run('systemctl', 'start', '--no-block', MANUAL)
    result = status(); result['updating'] = True
    return result


def run(mode):
    if mode not in ('daily', 'manual'):
        raise ValueError('Invalid recognition update mode')
    state.trusted(state.ROOT, True)
    state.mkdir(DIRECTORY)
    return cookie_recognition.update(DIRECTORY, BUNDLED, force=mode == 'manual')


if __name__ == '__main__':
    try:
        if os.geteuid() != 0 or len(sys.argv) != 3 or sys.argv[1] != '--mode':
            raise ValueError('Use the administrator panel or the owned daily timer')
        print(json.dumps(run(sys.argv[2]), ensure_ascii=True))
    except Exception as error:
        print(json.dumps({'error': str(error)}, ensure_ascii=True)); raise SystemExit(1)
