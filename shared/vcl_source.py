"""Compose owned VCL source modules before native compilation.

The published runtime program is self-contained. Its digest covers every module
byte and it can be booted/restored without the source checkout. This loader only
handles explicit local includes in our coordinator, never visitor metadata.
"""
from pathlib import Path
import hashlib
import re

INCLUDE = re.compile(r'^include "(vcl/[a-z][a-z-]*[.]vcl)";[ \t]*$', re.MULTILINE)


def manifest(root=None):
    root = Path(root) if root is not None else Path(__file__).resolve().parent
    source = (root / 'cache-policy.vcl').read_text(encoding='utf-8')
    expand(source, root)  # Verify the same owned paths as the real generator.
    names = ['cache-policy.vcl', *(match[1] for match in INCLUDE.finditer(source))]
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in names}


def expand(source, root=None):
    root = Path(root) if root is not None else Path(__file__).resolve().parent
    def replace(match):
        relative = match[1]
        path = root / relative
        # Do not let a source module redirect the root-side compiler outside its
        # installed, owned code generation. Runtime rules never choose this path.
        if root.is_symlink() or path.parent.is_symlink() or path.is_symlink():
            raise ValueError('VCL source modules must be owned regular files')
        if path.resolve().parent != (root / 'vcl').resolve():
            raise ValueError('Invalid VCL source module location')
        content = path.read_text(encoding='utf-8')
        if re.search(r'^\s*include\b', content, re.MULTILINE):
            raise ValueError('List VCL source modules explicitly in the coordinator')
        return '# Begin ' + relative + '\n' + content.rstrip() + '\n# End ' + relative
    result = INCLUDE.sub(replace, source)
    if re.search(r'^\s*include\b', result, re.MULTILINE):
        raise ValueError('Only explicit owned VCL source modules are supported')
    return result
