"""Build the handoff against the installed native engine, never a bundled ABI."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def command(*args, cwd=None):
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError('Native cookie module build failed: '+result.stderr.strip())
    return result.stdout.strip()


def build():
    source = Path(__file__).with_name('native')
    include = Path(command('pkg-config','--variable=includedir','varnishapi')) / 'varnish'
    tool = command('pkg-config','--variable=vmodtool','varnishapi')
    target = Path(command('pkg-config','--variable=vmoddir','varnishapi'))
    if not tool or not target.is_absolute() or not target.is_dir():
        raise RuntimeError('Install the development package matching the native Varnish engine')
    inputs = {name:(source/name).read_bytes() for name in ('cookie_handoff.c','cookie_handoff.vcc','delivery_continuation.c')}
    inputs['abi'] = (include/'vmod_abi.h').read_bytes()
    inputs['builder'] = Path(__file__).read_bytes()
    signature = hashlib.sha256(b'cookie-handoff-build-1\0'+b''.join(inputs.values())).hexdigest()
    library = target/'libvmod_cookie_handoff.so'
    receipt = target/'cookie_handoff.build.json'
    with (target/'.cookie_handoff.build.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if receipt.is_file() and library.is_file():
            old = json.loads(receipt.read_text())
            if old.get('signature')==signature and old.get('library')==hashlib.sha256(library.read_bytes()).hexdigest():
                return library
        with tempfile.TemporaryDirectory(prefix='.cookie-handoff-',dir=target) as temporary:
            folder=Path(temporary)
            (folder/'cookie_handoff.c').write_bytes(inputs['cookie_handoff.c'])
            (folder/'delivery_continuation.c').write_bytes(inputs['delivery_continuation.c'])
            # vmodtool hashes directives, not their documentation. Put the
            # source/ABI identity in $Module so a C-only update gets a new DSO
            # identity even while an earlier VCL still holds the old module.
            vcc,count=re.subn(r'^(\$Module\s+cookie_handoff\s+\d+\s+"[^"]*)(".*)$',
                r'\g<1> build '+signature+r'\2',inputs['cookie_handoff.vcc'].decode('utf-8'),flags=re.M)
            if count!=1:raise RuntimeError('Native cookie module needs one module declaration')
            (folder/'cookie_handoff.vcc').write_text(vcc,encoding='utf-8')
            (folder/'vmod_vcs_version.txt').write_text(signature+'\n')
            (folder/'config.h').write_text('#define PACKAGE_VERSION "'+signature+'"\n')
            command('python3',tool,'cookie_handoff.vcc',cwd=folder)
            command('cc','-Wall','-Wextra','-Werror','-fPIC','-shared','-pthread',
                    '-I'+str(include),'-I.','cookie_handoff.c','vcc_if.c',
                    '-o','libvmod_cookie_handoff.so',cwd=folder)
            output=folder/'libvmod_cookie_handoff.so'
            metadata={'signature':signature,'library':hashlib.sha256(output.read_bytes()).hexdigest()}
            output.chmod(0o644)
            os.replace(output,library)
            record=folder/'receipt.json';record.write_text(json.dumps(metadata)+'\n');record.chmod(0o644)
            os.replace(record,receipt)
    return library
