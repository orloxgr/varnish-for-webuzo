"""One native VCLI load, waiting for the compiler rather than a client deadline."""
import json
from pathlib import Path
import re
import subprocess

import native


class LoadFailure(RuntimeError):
    """The diagnostic is private; callers must not expose it in panel errors."""
    def __init__(self, diagnostic, rejected=False, status=None, kind='cli-communication'):
        super().__init__(diagnostic)
        self.rejected = rejected
        self.status = status
        self.kind = kind


def load(address, secret, name, path):
    path = Path(path)
    if (not re.fullmatch(r'wvw_[0-9a-f]{64}_[0-9a-f]{32}', name) or
            not path.is_absolute() or '..' in path.parts or
            path.parent.name != 'generations' or path.name != name + '.vcl'):
        raise ValueError('Invalid owned VCL generation')
    # Pass mode polls indefinitely before a reply starts. -t still bounds reads
    # once reply bytes arrive. Argv command mode instead times out during CC.
    # Only this generated load command uses stdin; JSON quotes VCLI strings.
    command = 'vcl.load ' + name + ' ' + json.dumps(str(path), ensure_ascii=False) + '\n'
    result = subprocess.run(['/usr/bin/varnishadm', '-T', address, '-S', str(secret),
        '-t', '10', '-p'], input=command.encode(), capture_output=True, env=native.ENV)
    diagnostic = (result.stderr + b'\n' + result.stdout).decode('utf-8', errors='replace')
    if result.returncode:
        raise LoadFailure(diagnostic)
    # Pass mode can exit zero on a rejected command. Require exactly one whole
    # native frame, not just exit zero or a success-looking substring.
    header, separator, body = result.stdout.partition(b'\n')
    match = re.fullmatch(rb'([0-9]{3}) +([0-9]+) *', header)
    if not separator or not match or len(body) != int(match[2]):
        raise LoadFailure('Invalid or incomplete VCLI load reply\n' + diagnostic, kind='invalid-cli-reply')
    status = int(match[1])
    if status != 200:
        raise LoadFailure(diagnostic, rejected=status in (100, 101, 102, 104, 105, 106, 107, 300),
                          status=status, kind='native-cli-status')
    return body.decode('utf-8', errors='replace')
