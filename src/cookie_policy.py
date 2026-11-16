"""Owner cookie exclusions; built-in HTTP policy lives in the shared VCL."""
import re
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'shared'))
from cookie_catalogue import load_catalogue, render_policy
from cookie_delivery import normalize_delivery, recv_configuration

# Built-in roles come from the shared reviewed catalogue, not recognition categories.
RULE = re.compile(r"[!#$%&'+.^_`|~0-9A-Za-z-]+\*?")


def normalize(value):
    if isinstance(value, str):
        value = value.splitlines()
    if not isinstance(value, list):
        raise ValueError('Use cookie names or trailing-star prefixes')
    result = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError('Cookie rules must be names, one per line')
        item = item.strip()
        if not item:
            continue
        if not RULE.fullmatch(item):
            raise ValueError('Use valid HTTP cookie names; only a trailing * is interpreted as a prefix wildcard')
        if item not in result:
            result.append(item)
    return result


def pattern(rules):
    names = []
    for rule in normalize(list(rules)):
        name = re.escape(rule.removesuffix('*'))
        if rule.endswith('*'):
            name += '[^=;[:blank:]]*'
        names.append(name)
    if not names:
        raise ValueError('An empty cookie rule list has no match pattern')
    return '(^|;[[:blank:]]*)(' + '|'.join(names) + ')='


def vcl_pattern(rules):
    # Native long strings preserve PCRE escapes. Cookie names cannot contain
    # quotes/braces, so they cannot terminate this generated VCL literal.
    return '{"' + pattern(rules) + '"}'


def shared_policy():
    source = Path(__file__).resolve().parents[1] / "shared/cache-policy.vcl"
    return render_policy(source.read_text(encoding="utf-8"), load_catalogue())


def owned_domains(site, sites):
    return {name for row in sites.values() if row.get('owner') == site.get('owner')
            for name in row.get('names', [row['domain']])}


def delivery_settings(value, site, sites):
    return normalize_delivery(value, site['domain'], owned_domains(site, sites))


def delivery_configuration(site, sites):
    value = delivery_settings(site.get('cookie_delivery'), site, sites)
    domain = value['fbp']['domain']
    lines = []
    for hostname in site['names']:
        # An explicit cookie domain does not apply to an unrelated alias.
        # That alias keeps ordinary caching and its existing provider cookies.
        if domain and hostname != domain and not hostname.endswith('.' + domain):
            continue
        source = recv_configuration(value, hostname, owned_domains(site, sites))
        if source:
            lines.append('if (req.http.host == "' + hostname + '") {\n' + source + '\n}')
    return '\n'.join(lines)
