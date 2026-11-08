"""Addon-owned, Signed-By-scoped upstream repository for the Varnish 9.1 LTS branch."""
import base64
import hashlib
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
import urllib.request
import native
import state

BASE='https://packages.varnish-software.com/varnish/ubuntu'
KEY_URL='https://packages.varnish-software.com/varnish/varnish.pub.asc'
KEY_SHA256='eea1110e5aa0afc0e8cfe872f0f5bbf0778d95e811227e19835c02378dd03ff2'
KEY=Path('/etc/apt/keyrings/varnish-for-webuzo.gpg')
SOURCE=Path('/etc/apt/sources.list.d/varnish-for-webuzo.list')
PIN=Path('/etc/apt/preferences.d/varnish-for-webuzo')
RECORD=state.ROOT/'repository.json'
PIN_TEXT='Package: varnish\nPin: version 9.1.*\nPin-Priority: 990\n'

def release():
    data=platform.freedesktop_os_release()
    if data.get('ID')!='ubuntu' or data.get('VERSION_CODENAME')!='noble':
        raise ValueError('Automatic Varnish 9.1 LTS setup currently supports Ubuntu 24.04')
    return 'noble'

def existing_source(codename):
    files=[Path('/etc/apt/sources.list'),*Path('/etc/apt/sources.list.d').glob('*.list'),*Path('/etc/apt/sources.list.d').glob('*.sources')]
    for path in files:
        if path==SOURCE or not path.exists():continue
        state.trusted(path);text=path.read_text()
        if path.suffix=='.sources':
            for section in text.split('\n\n'):
                fields={line.split(':',1)[0].strip().lower():line.split(':',1)[1].strip() for line in section.splitlines() if ':' in line and not line.startswith('#')}
                if fields.get('enabled','yes')!='no' and BASE in fields.get('uris','').split() and codename in fields.get('suites','').split():return True
        elif any(line.strip().startswith('deb ') and BASE in line.split() and codename in line.split() for line in text.splitlines()):return True
    return False

def setup():
    codename=release();record=state.read(RECORD)
    source='# Managed by varnish-for-webuzo\ndeb [signed-by='+str(KEY)+'] '+BASE+' '+codename+' main\n'
    if record is None:
        for path in (KEY,SOURCE,PIN):
            if path.exists() or path.is_symlink():raise ValueError('An unmanaged repository file uses the plugin path: '+str(path))
        with urllib.request.urlopen(KEY_URL,timeout=30) as response:data=response.read(65537)
        if hashlib.sha256(data).hexdigest()!=KEY_SHA256:raise ValueError('The upstream signing key differs from the verified key')
        if not shutil.which('gpg'):
            native.run('apt-get','update','-o','APT::Update::Error-Mode=any')
            native.run('env','DEBIAN_FRONTEND=noninteractive','apt-get','install','-y','gnupg')
        with tempfile.TemporaryDirectory(dir=state.ROOT) as home:
            result=subprocess.run(['/usr/bin/gpg','--homedir',home,'--batch','--no-options','--dearmor'],input=data,capture_output=True,check=True,timeout=30)
        record=dict(key=base64.b64encode(result.stdout).decode(),source=None if existing_source(codename) else source,key_source_sha256=KEY_SHA256,key_sha256=hashlib.sha256(result.stdout).hexdigest())
        # Record before writing public files so an interrupted setup is resumable.
        state.save(RECORD,record)
    if record.get('key_source_sha256')!=KEY_SHA256 or record.get('source') not in (None,source):raise ValueError('Unsupported repository record')
    key=base64.b64decode(record['key'],validate=True)
    if hashlib.sha256(key).hexdigest()!=record.get('key_sha256'):raise ValueError('Damaged repository key record')
    expected={KEY:key,PIN:PIN_TEXT.encode()}
    if record['source'] is not None:expected[SOURCE]=record['source'].encode()
    for path,raw in expected.items():
        if path.exists() or path.is_symlink():
            state.trusted(path)
            if path.read_bytes()!=raw:raise ValueError('The managed repository configuration was changed: '+str(path))
        if not path.parent.exists():state.mkdir(path.parent,0o755)
        state.write(path,raw);path.chmod(0o644)

def ensure_package():
    release()
    installed=Path('/usr/sbin/varnishd').is_file()
    if installed:
        result=subprocess.run(['/usr/sbin/varnishd','-V'],capture_output=True,text=True,check=True)
        if re.search(r'varnish-9[.]1[.]\d+',result.stdout+result.stderr):setup();return
    # Upgrading a binary used by another instance must be an administrator's choice.
    if subprocess.run(['/usr/bin/pgrep','-x','varnishd'],capture_output=True).returncode==0:
        raise ValueError('Another Varnish instance is running. Stop it before upgrading the shared Varnish package.')
    before={key:native.run('systemctl','show','varnish','--property='+key,'--value').strip() for key in ('LoadState','UnitFileState')}
    if not installed and before['LoadState']!='not-found':raise ValueError('An independent Varnish unit exists without the distribution binary')
    setup()
    native.run('apt-get','update','-o','APT::Update::Error-Mode=any')
    versions=[]
    for line in native.run('apt-cache','madison','varnish').splitlines():
        parts=[part.strip() for part in line.split('|')]
        if len(parts)==3 and re.fullmatch(r'9[.]1[.]\d+[-+~.A-Za-z0-9]*~noble',parts[1]) and BASE in parts[2]:versions.append(parts[1])
    if not versions:raise ValueError('No signed Varnish 9.1 LTS package was found for Ubuntu 24.04')
    version=versions[0]
    for candidate in versions[1:]:
        if subprocess.run(['/usr/bin/dpkg','--compare-versions',candidate,'gt',version]).returncode==0:version=candidate
    simulation=native.run('apt-get','-s','install','varnish='+version)
    removals=[line.split()[1] for line in simulation.splitlines() if line.startswith('Remv ')]
    if set(removals)-{'libvarnishapi1','libvarnishapi2','libvarnishapi3'}:raise ValueError('Varnish installation would remove another service')
    native.run('env','DEBIAN_FRONTEND=noninteractive','apt-get','install','-y','varnish='+version)
    # Package scripts may start the vendor instance. Preserve its previous inactive
    # state; only a newly installed vendor unit is disabled by this setup.
    native.run('systemctl','stop','varnish')
    if before['UnitFileState']!='enabled':native.run('systemctl','disable','varnish')
    # Older distribution libraries can shadow the library bundled upstream.
    previous=subprocess.run(['dpkg-query','-W','-f=${db:Status-Status}','libvarnishapi3'],capture_output=True,text=True)
    if previous.stdout.strip()=='installed':
        plan=native.run('apt-get','-s','remove','libvarnishapi3')
        if [line.split()[1] for line in plan.splitlines() if line.startswith('Remv ')]!=['libvarnishapi3']:raise ValueError('Removing an obsolete Varnish library would affect another package')
        native.run('env','DEBIAN_FRONTEND=noninteractive','apt-get','remove','-y','libvarnishapi3');native.run('ldconfig')
