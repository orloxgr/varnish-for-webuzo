"""Match the official signed APT repository to the installed Ubuntu release."""
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
    codename=data.get('VERSION_CODENAME','')
    if data.get('ID')!='ubuntu' or not re.fullmatch('[a-z][a-z0-9]*',codename):
        raise ValueError('Automatic package setup requires Ubuntu with a valid release codename')
    return codename

def existing_source(codename,arch):
    files=[Path('/etc/apt/sources.list'),*Path('/etc/apt/sources.list.d').glob('*.list'),*Path('/etc/apt/sources.list.d').glob('*.sources')]
    for path in files:
        if path==SOURCE or not path.exists():continue
        state.trusted(path);text=path.read_text()
        if path.suffix=='.sources':
            for section in text.split('\n\n'):
                fields={line.split(':',1)[0].strip().lower():line.split(':',1)[1].strip() for line in section.splitlines() if ':' in line and not line.startswith('#')}
                if (fields.get('enabled','yes')!='no' and 'deb' in fields.get('types','').split()
                    and BASE in [uri.rstrip('/') for uri in fields.get('uris','').split()] and codename in fields.get('suites','').split()
                    and 'main' in fields.get('components','').split()
                    and ('architectures' not in fields or arch in fields['architectures'].split())):return True
        else:
            for line in text.splitlines():
                match=re.fullmatch(r'\s*deb\s+(?:\[([^\]]+)\]\s+)?(\S+)\s+(\S+)\s+(.+)',line)
                if not match or match[2].rstrip('/')!=BASE or match[3]!=codename or 'main' not in match[4].split('#',1)[0].split():continue
                arches=re.search(r'(?:^|\s)arch=([^\s]+)',match[1] or '')
                if not arches or arch in arches[1].split(','):return True
    return False

def architecture():
    value=native.run('/usr/bin/dpkg','--print-architecture').strip()
    if not re.fullmatch('[a-z0-9][a-z0-9-]*',value):raise ValueError('Invalid native package architecture')
    return value


def source_text(codename,arch=None):
    options=('arch='+arch+' ' if arch else '')+'signed-by='+str(KEY)
    return '# Managed by varnish-for-webuzo\ndeb ['+options+'] '+BASE+' '+codename+' main\n'


def owned_source(value):
    if value is None:return
    # Recognize only our own generated source syntax, including its current
    # suite. Reconciliation can then follow an OS upgrade without rewriting
    # an administrator's independent source or silently choosing another suite.
    expression=(r'\# Managed by varnish-for-webuzo\ndeb \[(?:arch=([a-z0-9-]+) )?signed-by='
        +re.escape(str(KEY))+r'\] '+re.escape(BASE)+r' ([a-z][a-z0-9]*) main\n')
    if not isinstance(value,str) or not re.fullmatch(expression,value):raise ValueError('Unsupported repository source record')


def verify_release(codename,arch,key):
    """Verify signed metadata before changing any persistent repository files."""
    try:
        with urllib.request.urlopen(BASE+'/dists/'+codename+'/InRelease',timeout=30) as response:metadata=response.read()
    except OSError as error:
        raise ValueError('The official Varnish repository is unavailable for Ubuntu '+codename+': '+str(error)) from error
    with tempfile.TemporaryDirectory(dir=state.ROOT) as folder:
        folder=Path(folder);keyfile=folder/'key.gpg';signed=folder/'InRelease';plain=folder/'Release'
        keyfile.write_bytes(key);signed.write_bytes(metadata)
        native.run('/usr/bin/gpgv','--homedir',folder,'--keyring',keyfile,'--output',plain,signed)
        text=plain.read_text()
    fields={};name=None
    for line in text.splitlines():
        if line[:1].isspace() and name:fields[name]+='\n'+line.strip()
        elif ':' in line:name,value=line.split(':',1);fields[name]=value.strip()
    if fields.get('Codename')!=codename or fields.get('Origin')!='Varnish':
        raise ValueError('The signed Varnish repository does not match Ubuntu '+codename)
    indexes=[line.split() for line in fields.get('SHA256','').splitlines()]
    if not any(len(row)==3 and re.fullmatch('[0-9a-fA-F]{64}',row[0]) and row[1].isdigit()
        and row[2] in ('main/binary-'+arch+'/Packages','main/binary-'+arch+'/Packages.gz','main/binary-'+arch+'/Packages.xz') for row in indexes):
        raise ValueError('The signed Varnish repository has no package index for '+arch+' on '+codename)


def setup():
    codename=release();arch=architecture();record=state.read(RECORD)
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
        record=dict(key=base64.b64encode(result.stdout).decode(),source=None,key_source_sha256=KEY_SHA256,key_sha256=hashlib.sha256(result.stdout).hexdigest())
    if record.get('key_source_sha256')!=KEY_SHA256:raise ValueError('Unsupported repository key record')
    owned_source(record.get('source'));owned_source(record.get('pending_source'))
    key=base64.b64decode(record['key'],validate=True)
    if not key or hashlib.sha256(key).hexdigest()!=record.get('key_sha256'):raise ValueError('Damaged repository key record')
    if KEY.exists() or KEY.is_symlink():
        state.trusted(KEY)
        if KEY.read_bytes()!=key:raise ValueError('The managed repository key was changed')
    allowed={value.encode() for value in (record.get('source'),record.get('pending_source')) if value is not None}
    if SOURCE.exists() or SOURCE.is_symlink():
        state.trusted(SOURCE)
        # A record with no owned source leaves independent files untouched.
        if allowed and SOURCE.read_bytes() not in allowed:raise ValueError('The managed repository source was changed')
    if PIN.exists() or PIN.is_symlink():
        state.trusted(PIN)
        if PIN.read_text()!=PIN_TEXT:raise ValueError('The managed repository preference was changed')
    verify_release(codename,arch,key)
    desired=None if existing_source(codename,arch) else source_text(codename,arch)
    if desired is not None and not allowed and (SOURCE.exists() or SOURCE.is_symlink()):
        raise ValueError('An unmanaged repository file uses the plugin path: '+str(SOURCE))
    # Write-ahead intent makes interruption during a suite change resumable.
    # There is no conversion of site settings or background OS-upgrade watcher.
    record['pending_source']=desired;state.save(RECORD,record)
    if not KEY.parent.exists():state.mkdir(KEY.parent,0o755)
    state.write(KEY,key);KEY.chmod(0o644)
    if desired is not None:
        state.write(SOURCE,desired.encode());SOURCE.chmod(0o644)
    elif allowed and SOURCE.exists():SOURCE.unlink()
    if PIN.exists():PIN.unlink()  # Retire only the exact branch pin we own.
    record['source']=desired;record.pop('pending_source',None);state.save(RECORD,record)
    return codename


def compatible():
    """Test the actual policy language/modules instead of imposing a version."""
    import policy
    with tempfile.TemporaryDirectory(dir=state.ROOT) as folder:
        candidate=Path(folder)/'probe.vcl'
        site=dict(id='a'*32,token='b'*64,names=['probe.invalid'],enabled=True,profile='basic',bypass=[])
        candidate.write_text(policy.render({site['id']:site},'a'*64,'b'*64),encoding='utf-8')
        try:native.run('/usr/sbin/varnishd','-C','-j','none','-f',candidate)
        except RuntimeError:return False
    return True


def reconcile_owned():
    """Refresh only addon-owned repository settings during an explicit refresh."""
    record=state.read(RECORD)
    if record is None:return
    owned_source(record.get('source'))
    # Independent sources are maintained by their administrator.
    if record.get('source') is None and 'pending_source' not in record and not PIN.exists():return
    if record.get('source')!=source_text(release(),architecture()) or 'pending_source' in record or PIN.exists():setup()


def candidate(codename,arch):
    policy=native.run('apt-cache','policy','varnish')
    found=re.search(r'^\s*Candidate:\s*(\S+)\s*$',policy,re.M)
    if not found or found[1]=='(none)':raise ValueError('APT has no Varnish candidate for Ubuntu '+codename)
    version=found[1]
    for line in native.run('apt-cache','madison','varnish').splitlines():
        parts=[part.strip() for part in line.split('|')]
        if len(parts)==3 and parts[0]=='varnish' and parts[1]==version and parts[2].split()==[BASE,codename+'/main',arch,'Packages']:
            return version
    raise ValueError('The APT Varnish candidate is not from the matching official repository; review the administrator package preferences')


def ensure_package():
    installed=Path('/usr/sbin/varnishd').is_file()
    if installed and compatible():
        # Do not replace a compatible existing binary or add a repository to an
        # independent install. Reconcile only sources already owned by the addon.
        if RECORD.exists():setup()
        return
    # Upgrading a binary used by another instance must be an administrator's choice.
    if subprocess.run(['/usr/bin/pgrep','-x','varnishd'],capture_output=True).returncode==0:
        raise ValueError('Another Varnish instance is running. Stop it before upgrading the shared Varnish package.')
    before={key:native.run('systemctl','show','varnish','--property='+key,'--value').strip() for key in ('LoadState','UnitFileState')}
    if not installed and before['LoadState']!='not-found':raise ValueError('An independent Varnish unit exists without the distribution binary')
    codename=setup();arch=architecture()
    native.run('apt-get','update','-o','APT::Update::Error-Mode=any')
    version=candidate(codename,arch)
    simulation=native.run('apt-get','-s','install','varnish='+version)
    removals=[line.split()[1] for line in simulation.splitlines() if line.startswith('Remv ')]
    if set(removals)-{'libvarnishapi1','libvarnishapi2','libvarnishapi3'}:raise ValueError('Varnish installation would remove another service')
    native.run('env','DEBIAN_FRONTEND=noninteractive','apt-get','install','-y','varnish='+version)
    native.run('systemctl','stop','varnish')
    if before['UnitFileState']!='enabled':native.run('systemctl','disable','varnish')
    if not compatible():raise ValueError('The installed Varnish package cannot compile the addon policy')
