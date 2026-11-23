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


def experimental_reuse_source(include):
    """Explicit internal-engine dependency for the isolated resolver candidate.

    No network download or guessed prototypes. A source receipt must match the
    installed strict ABI AND actual installed cache layouts. Default is off.
    """
    value = os.environ.get('SCP_EXPERIMENTAL_REUSE_ENGINE_SOURCE')
    if not value:
        return None
    root = Path(value)
    if not root.is_absolute():
        raise RuntimeError('Experimental reuse needs an absolute engine source receipt directory')
    record = json.loads((root/'engine.json').read_text())
    revision = record.get('revision','')
    if not re.fullmatch('[0-9a-f]{40}',revision) or revision not in (include/'vmod_abi.h').read_text():
        raise RuntimeError('Experimental reuse source revision differs from the installed engine ABI')
    header = (root/'cache_objhead.h').read_bytes()
    if hashlib.sha256(header).hexdigest() != record.get('objheadSha256'):
        raise RuntimeError('Experimental reuse private header differs from its source receipt')
    for name in ('cache/cache.h','cache/cache_int.h'):
        expected = record.get('installedHeaders',{}).get(name)
        if hashlib.sha256((include/name).read_bytes()).hexdigest() != expected:
            raise RuntimeError('Experimental reuse installed layout differs from its source receipt: '+name)
    return header,record


def build():
    source = Path(__file__).with_name('native')
    include = Path(command('pkg-config','--variable=includedir','varnishapi')) / 'varnish'
    tool = command('pkg-config','--variable=vmodtool','varnishapi')
    target = Path(command('pkg-config','--variable=vmoddir','varnishapi'))
    if not tool or not target.is_absolute() or not target.is_dir():
        raise RuntimeError('Install the development package matching the native Varnish engine')
    inputs = {name:(source/name).read_bytes() for name in
              ('cookie_handoff.c','cookie_handoff.vcc','delivery_continuation.c',
               'delivery_envelope.c','delivery_envelope.h','delivery_selection.c',
               'public_selection_registry.c','selection_digest.c','delivery_snapshot_backend.c','delivery_reuse.c',
               'delivery_reuse_inputs.c','delivery_reuse_inputs.h','reuse_authority.c')}
    inputs['abi'] = (include/'vmod_abi.h').read_bytes()
    # The virtual fetch uses the installed internal http_conn layout. Strict
    # VRT ABI alone is insufficient as a build receipt for internal headers.
    for header in ('cache/cache_int.h','cache/cache.h','cache/cache_filter.h','vrt.h','vrt_obj.h'):
        inputs['installed:'+header] = (include/header).read_bytes()
    inputs['builder'] = Path(__file__).read_bytes()
    experimental = experimental_reuse_source(include)
    if experimental:
        inputs['engine-private-header'] = experimental[0]
        inputs['engine-private-receipt'] = json.dumps(experimental[1],sort_keys=True).encode()
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
            for name in ('delivery_envelope.c','delivery_envelope.h','delivery_selection.c',
                         'public_selection_registry.c','selection_digest.c','delivery_snapshot_backend.c','delivery_reuse.c',
                         'delivery_reuse_inputs.c','delivery_reuse_inputs.h','reuse_authority.c'):
                (folder/name).write_bytes(inputs[name])
            # vmodtool hashes directives, not their documentation. Put the
            # source/ABI identity in $Module so a C-only update gets a new DSO
            # identity even while an earlier VCL still holds the old module.
            vcc,count=re.subn(r'^(\$Module\s+cookie_handoff\s+\d+\s+"[^"]*)(".*)$',
                r'\g<1> build '+signature+r'\2',inputs['cookie_handoff.vcc'].decode('utf-8'),flags=re.M)
            if count!=1:raise RuntimeError('Native cookie module needs one module declaration')
            (folder/'cookie_handoff.vcc').write_text(vcc,encoding='utf-8')
            (folder/'vmod_vcs_version.txt').write_text(signature+'\n')
            (folder/'config.h').write_text('#define PACKAGE_VERSION "'+signature+'"\n'+
                ('#define UC_EXPERIMENTAL_PRIVATE_REUSE 1\n' if experimental else ''))
            if experimental:
                (folder/'uc_engine_objhead.h').write_bytes(experimental[0])
            command('python3',tool,'cookie_handoff.vcc',cwd=folder)
            command('cc','-Wall','-Wextra','-Werror','-fPIC','-shared','-pthread',
                    '-I'+str(include),'-I.','cookie_handoff.c','delivery_envelope.c','vcc_if.c',
                    '-o','libvmod_cookie_handoff.so','-lm',cwd=folder)
            output=folder/'libvmod_cookie_handoff.so'
            metadata={'signature':signature,'library':hashlib.sha256(output.read_bytes()).hexdigest()}
            if experimental:
                metadata['experimentalReuseEngine']=experimental[1]
            output.chmod(0o644)
            os.replace(output,library)
            record=folder/'receipt.json';record.write_text(json.dumps(metadata)+'\n');record.chmod(0o644)
            os.replace(record,receipt)
    return library
