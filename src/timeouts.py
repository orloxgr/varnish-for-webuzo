"""Derive proxy allowances from the hosting configuration, not addon constants."""
import re

KEYS = ('connect', 'read', 'send')
NGINX_DEFAULT_MS = 60000


def duration(value):
    """Parse Nginx millisecond-resolution time syntax without accepting code."""
    value = value.strip().strip('"\'')
    value = re.sub(r'\s+', '', value)
    if value.isdecimal():
        return int(value) * 1000
    parts = list(re.finditer(r'([0-9]+)(ms|s|m|h|d|w|M|y)', value))
    if not parts or ''.join(p.group() for p in parts) != value:
        raise ValueError('Unsupported native proxy timeout: ' + value)
    units = dict(ms=1, s=1000, m=60000, h=3600000, d=86400000, w=604800000, M=2592000000, y=31536000000)
    return sum(int(p[1]) * units[p[2]] for p in parts)


def discover(dump):
    """Keep the widest native allowance; exclude our generated proxy snippets.

    nginx -T enumerates the configuration files it actually loaded. Taking the
    maximum also preserves longer per-domain overrides on a shared instance.
    A missing directive retains the documented Nginx default, not a new limit.
    """
    found = {key: [] for key in KEYS}
    source = None
    for line in dump.splitlines():
        header = re.fullmatch(r'# configuration file (/.+):', line)
        if header:
            source = header[1]
            continue
        if source is None or source.startswith('/etc/varnish-for-webuzo/'):
            continue
        match = re.fullmatch(r'\s*proxy_(connect|read|send)_timeout\s+([^;]+);\s*(?:#.*)?', line)
        if match:
            found[match[1]].append(duration(match[2]))
    if source is None:
        raise ValueError('The native Nginx configuration could not be inspected')
    result = {key: max(values) if values else NGINX_DEFAULT_MS for key, values in found.items()}
    return validate(result)


def validate(values):
    if not isinstance(values, dict) or set(values) != set(KEYS):
        raise ValueError('Invalid proxy timeout settings')
    if any(type(value) is not int or value <= 0 for value in values.values()):
        raise ValueError('Native proxy timeouts must be positive millisecond values')
    return dict(values)


def settings(config=None):
    return validate((config or {}).get('proxy_timeouts', {key: NGINX_DEFAULT_MS for key in KEYS}))


def seconds(milliseconds):
    return str(milliseconds // 1000) + ('.' + str(milliseconds % 1000).zfill(3).rstrip('0') if milliseconds % 1000 else '') + 's'


def first_byte(values):
    # The origin bridge may spend separate intervals connecting, sending the
    # request and waiting for Apache. Do not cut it off with a shorter timer.
    return sum(values.values())


def frontend(values):
    # The outer proxy must also allow the Varnish-to-bridge exchange to start.
    return dict(values, read=values['connect'] + values['send'] + first_byte(values))
