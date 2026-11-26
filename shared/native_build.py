"""Build against the installed engine and its verified upstream interface."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


ENGINE_INTERFACES=Path(__file__).with_name('native')/'engine'

def command(*args, cwd=None):
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError('Native cookie module build failed: '+result.stderr.strip())
    return result.stdout.strip()


def native_reuse_source(include):
    """Automatically select a proven upstream interface for the installed ABI.

    No user flag, guessed prototypes or build-time network fetch. Unknown engine
    interfaces retain the existing compatible producer path. A bundled interface
    that has been altered is an install error, never silently trusted.
    """
    abi=(include/'vmod_abi.h').read_text()
    declaration=re.search(r'^\s*#define\s+VMOD_ABI_Version\s+"([^"\r\n]+)"\s*$',abi,re.M)
    installed=re.search(r'(?:^| )([0-9a-f]{40})$',declaration[1]) if declaration else None
    if not installed:return None
    root=ENGINE_INTERFACES
    for receipt in sorted(root.glob('*/engine.json')):
        record=json.loads(receipt.read_text())
        revision=record.get('revision','')
        if not re.fullmatch('[0-9a-f]{40}',revision) or receipt.parent.name!=revision:
            raise RuntimeError('Invalid bundled native engine source receipt')
        header=(receipt.parent/'cache_objhead.h').read_bytes()
        if hashlib.sha256(header).hexdigest()!=record.get('objheadSha256'):
            raise RuntimeError('Bundled native engine interface differs from verified source')
        pool=(receipt.parent/'cache_pool.h').read_bytes()
        if hashlib.sha256(pool).hexdigest()!=record.get('poolHeader',{}).get('sha256'):
            raise RuntimeError('Bundled native engine pool differs from verified source')
        counters=(receipt.parent/'VSC_main.h').read_bytes()
        if hashlib.sha256(counters).hexdigest()!=record.get('counterHeader',{}).get('sha256'):
            raise RuntimeError('Bundled native counters differ from verified source')
        transport=(receipt.parent/'cache_transport.h').read_bytes()
        if hashlib.sha256(transport).hexdigest()!=record.get('transportHeader',{}).get('sha256'):
            raise RuntimeError('Bundled native transport differs from verified source')
        if revision!=installed[1]:continue
        layouts=record.get('installedHeaders',{})
        if set(layouts)!={'cache/cache.h','cache/cache_int.h','waiter/waiter.h'}:
            raise RuntimeError('Incomplete bundled native engine layout receipt')
        if any(hashlib.sha256((include/name).read_bytes()).hexdigest()!=expected for name,expected in layouts.items()):
            continue
        return header,record,pool,counters,transport
    return None


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
               'delivery_reuse_inputs.c','delivery_reuse_inputs.h','reuse_authority.c',
               'delivery_mutation_wire.c','delivery_mutation_wire.h','delivery_public_projection_wire.c','mutation_backend.c',
               'delivery_reuse_wire.c','delivery_reuse_wire.h','delivery_reuse_metadata.c','delivery_reuse_runtime.c',
               'delivery_fragments_wire.c','delivery_fragments_wire.h','delivery_fragments_runtime.c')}
    inputs['abi'] = (include/'vmod_abi.h').read_bytes()
    # The virtual fetch uses the installed internal http_conn layout. Strict
    # VRT ABI alone is insufficient as a build receipt for internal headers.
    for header in ('cache/cache_int.h','cache/cache.h','cache/cache_filter.h','vrt.h','vrt_obj.h'):
        inputs['installed:'+header] = (include/header).read_bytes()
    inputs['builder'] = Path(__file__).read_bytes()
    private_reuse = native_reuse_source(include)
    if private_reuse:
        inputs['engine-private-header'] = private_reuse[0]
        inputs['engine-pool-header'] = private_reuse[2]
        inputs['engine-counter-header'] = private_reuse[3]
        inputs['engine-transport-header'] = private_reuse[4]
        inputs['engine-private-receipt'] = json.dumps(private_reuse[1],sort_keys=True).encode()
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
                         'delivery_reuse_inputs.c','delivery_reuse_inputs.h','reuse_authority.c',
                         'delivery_mutation_wire.c','delivery_mutation_wire.h','delivery_public_projection_wire.c','mutation_backend.c',
               'delivery_reuse_wire.c','delivery_reuse_wire.h','delivery_reuse_metadata.c','delivery_reuse_runtime.c',
               'delivery_fragments_wire.c','delivery_fragments_wire.h','delivery_fragments_runtime.c'):
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
                ('#define UC_NATIVE_PRIVATE_REUSE 1\n' if private_reuse else ''))
            if private_reuse:
                (folder/'uc_engine_objhead.h').write_bytes(private_reuse[0])
                (folder/'uc_engine_pool.h').write_bytes(private_reuse[2])
                (folder/'uc_engine_counters.h').write_bytes(private_reuse[3])
                (folder/'uc_engine_transport.h').write_bytes(private_reuse[4])
            command('python3',tool,'cookie_handoff.vcc',cwd=folder)
            command('cc','-Wall','-Wextra','-Werror','-fPIC','-shared','-pthread',
                    '-I'+str(include),'-I.','cookie_handoff.c','delivery_envelope.c','vcc_if.c',
                    '-o','libvmod_cookie_handoff.so','-lm',cwd=folder)
            output=folder/'libvmod_cookie_handoff.so'
            metadata={'signature':signature,'library':hashlib.sha256(output.read_bytes()).hexdigest()}
            if private_reuse:
                metadata['privateReuseEngine']=private_reuse[1]
            output.chmod(0o644)
            os.replace(output,library)
            record=folder/'receipt.json';record.write_text(json.dumps(metadata)+'\n');record.chmod(0o644)
            os.replace(record,receipt)
    return library
