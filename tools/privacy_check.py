"""Check tracked source and package inputs without printing private values.

Deployment details belong in local configuration. This complements Gitleaks;
provider descriptions and intentional public author attribution remain licensed
product data, rather than customer deployment examples.
"""
import argparse
import ipaddress
from pathlib import Path
import re
import subprocess
from urllib.parse import urlsplit
import zipfile

ROOT = Path(__file__).resolve().parents[1]
WINDOWS_HOME = re.compile(r"(?i)\b[a-z]:[\\/]+Users[\\/]+(?!Public\b|Default\b)[^\\/\s\"'<>]+")
PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")
URL = re.compile(r"https?://[^\s<>\"')\\]+", re.I)
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
PRIVATE_NETWORKS = tuple(ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
PUBLIC_REFERENCES = frozenset((
    'github.com', 'api.github.com', 'raw.githubusercontent.com',
    'docs.varnish-software.com', 'aelia.freshdesk.com', 'www.iniotakis.com',
))


def fixture_host(host):
    if host in ('localhost', 'unix', 'example.com', 'example.org', 'example.net'):
        return True
    if host.endswith(('.test', '.example', '.invalid')):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return '.' not in host and ':' not in host  # synthetic single-label fixtures
    return address.is_loopback or any(address in network for network in (
        ipaddress.ip_network('192.0.2.0/24'), ipaddress.ip_network('198.51.100.0/24'),
        ipaddress.ip_network('203.0.113.0/24'), ipaddress.ip_network('2001:db8::/32'),
    ) if network.version == address.version)


def inspect_text(name, text):
    """Return only file/line/category, never the matching content or secret."""
    findings = set()
    examples = name.startswith(('docs/', 'tests/')) or name == 'README.md'
    for number, line in enumerate(text.splitlines(), 1):
        if WINDOWS_HOME.search(line):
            findings.add((name, number, 'personal-windows-path'))
        if PRIVATE_KEY.search(line):
            findings.add((name, number, 'private-key-material'))
        for match in IPV4.finditer(line):
            try:
                address = ipaddress.ip_address(match[0])
            except ValueError:
                continue
            if any(address == network.network_address and
                   line[match.end():].startswith('/' + str(network.prefixlen))
                   for network in PRIVATE_NETWORKS):
                continue  # Standard RFC1918 range definitions are not a deployment.
            if any(address in network for network in PRIVATE_NETWORKS):
                findings.add((name, number, 'private-deployment-ip'))
        for match in URL.finditer(line):
            try:
                url = urlsplit(match[0])
                host = (url.hostname or '').lower().rstrip('.')
            except ValueError:
                continue  # partial URL grammar in tests is not a deployment
            if not host:
                continue
            synthetic = fixture_host(host)
            if (url.username is not None or url.password is not None) and not synthetic:
                findings.add((name, number, 'credentials-in-url'))
            if examples and not synthetic and host not in PUBLIC_REFERENCES:
                findings.add((name, number, 'unreviewed-public-host-in-example'))
    return sorted(findings)


def inspect_paths(paths, root=ROOT):
    findings = []
    for path in paths:
        name = path.relative_to(root).as_posix()
        if path.is_symlink():
            findings.append((name, 1, 'source-symlink'))
        elif path.is_file():
            findings.extend(inspect_text(name, path.read_bytes().decode('utf-8', 'replace')))
    return findings


def assert_clean(paths, root=ROOT):
    findings = inspect_paths(paths, root)
    if findings:
        locations = '\n'.join('{}:{}: {}'.format(*row) for row in findings)
        raise ValueError('Privacy check failed (matched values withheld):\n' + locations)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, help='Inspect an existing release ZIP')
    args = parser.parse_args(argv)
    if args.archive:
        with zipfile.ZipFile(args.archive) as archive:
            findings = []
            for member in archive.infolist():
                name = member.filename.split('/', 1)[-1]
                findings.extend(inspect_text(name, archive.read(member).decode('utf-8', 'replace')))
    else:
        files = subprocess.check_output(['git', '-C', str(ROOT), 'ls-files', '-z']).decode('utf-8').split('\0')
        findings = inspect_paths([ROOT / name for name in files if name])
    for row in sorted(set(findings)):
        print('{}:{}: {}'.format(*row))
    if findings:
        print('Privacy check failed; matched values are withheld.')
        return 1
    print('Privacy check passed.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
