"""Load bundled cookie descriptions and retire only the owned old scheduler."""
import json
from pathlib import Path
import sys

SHARED=Path(__file__).resolve().parents[1]/'shared'
sys.path[:0]=[str(Path(__file__).resolve().parent),str(SHARED)]
import native

BUNDLED=SHARED/'cookie-recognition/recognition.json'
ENTRY=Path(__file__).resolve()
SERVICE=Path('/etc/systemd/system/varnish-for-webuzo-cookie-recognition@.service')
TIMER=Path('/etc/systemd/system/varnish-for-webuzo-cookie-recognition.timer')
DAILY='varnish-for-webuzo-cookie-recognition@daily.service'
MANUAL='varnish-for-webuzo-cookie-recognition@manual.service'


def database():
    return json.loads(BUNDLED.read_text(encoding='utf-8'))


def remove():
    # Reconcile only this addon's retired scheduler, without a state migration.
    expected={SERVICE:('Description=Update cookie recognition data for Varnish for Webuzo',
        'ExecStart=/usr/bin/python3 -I -B "'+str(ENTRY)+'" --mode %i'),
        TIMER:('Description=Daily cookie recognition update for Varnish for Webuzo','Unit='+DAILY)}
    present=[]
    for path,markers in expected.items():
        if path.exists() or path.is_symlink():
            lines=native.read(path).decode().splitlines()
            if not all(marker in lines for marker in markers):
                raise ValueError('The retired cookie recognition unit was changed: '+path.name)
            present.append(path)
    if TIMER in present:native.run('systemctl','disable','--now',TIMER.name)
    if SERVICE in present:native.run('systemctl','stop',DAILY,MANUAL)
    for path in present:path.unlink()
    if present:native.run('systemctl','daemon-reload')


def install():
    remove()
