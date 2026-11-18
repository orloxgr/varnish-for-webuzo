"""Compile reviewed local cookie policies. Recognition metadata is not executable.

This module is distributed unchanged by both panel integrations. It has no panel,
network, or WordPress dependency. Loading happens when generating VCL, not on an
HTTP request. Cookie values never enter this API.
"""
import json
import hashlib
from pathlib import Path
import re
from vcl_source import expand

CONSUMERS = ('varnishPrivate', 'varnishCart', 'varnishTrackingIgnore')
NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
VALUE = re.compile(r'[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]*')
MARKER = re.compile(r'@@COOKIE_PATTERN_([A-Za-z]+)@@')


def validate(catalogue):
    if not isinstance(catalogue, dict) or catalogue.get('schemaVersion') != 1:
        raise ValueError('Unsupported cookie policy catalogue schema')
    if not isinstance(catalogue.get('version'), str) or not catalogue['version']:
        raise ValueError('Cookie policy catalogue needs a version')
    if catalogue.get('unknownCookies') != 'preserve-existing-policy':
        raise ValueError('Cookie recognition must not change unknown-cookie behavior')
    if not isinstance(catalogue.get('policies'), list):
        raise ValueError('Cookie policy catalogue needs reviewed policies')
    identities, matches = set(), set()
    for policy in catalogue['policies']:
        if not isinstance(policy, dict):
            raise ValueError('Invalid cookie policy')
        identity = policy.get('id')
        if not isinstance(identity, str) or not identity or identity in identities:
            raise ValueError('Cookie policy identifiers must be unique')
        identities.add(identity)
        match = policy.get('match', {})
        name, kind = match.get('value'), match.get('kind')
        if kind not in ('exact', 'prefix') or not isinstance(name, str) or not NAME.fullmatch(name):
            raise ValueError('Use a literal cookie name or prefix in the catalogue')
        if (kind, name) in matches:
            raise ValueError('Duplicate cookie policy match')
        matches.add((kind, name))
        consumers = policy.get('consumers', {})
        if not isinstance(consumers, dict) or any(type(consumers.get(key)) is not bool for key in CONSUMERS):
            raise ValueError('Cookie policies need explicit Varnish consumer flags')
        if consumers['varnishTrackingIgnore'] and (policy.get('htmlEffect') != 'none' or policy.get('cacheKey') != 'ignore'):
            raise ValueError('Only reviewed HTML-independent cookies can omit their cache variation')
        if consumers['varnishTrackingIgnore'] and (consumers['varnishPrivate'] or consumers['varnishCart']):
            raise ValueError('Private cookies cannot be classified as shared tracking cookies')
        if consumers['varnishPrivate'] and policy.get('htmlEffect') != 'private':
            raise ValueError('Private cookie policy must describe private HTML')
        if consumers['varnishCart'] and policy.get('htmlEffect') != 'private-fragment':
            raise ValueError('Cart cookie policy must describe its private fragment')
        for key in ('delivery', 'consent', 'attributes'):
            if not isinstance(policy.get(key), dict):
                raise ValueError('Cookie policy is missing ' + key)
        # supported belongs to independent delivery, not request lookup. A known
        # cookie remains usable under its existing policy before an issuer exists.
        if type(policy['delivery'].get('supported')) is not bool:
            raise ValueError('Cookie delivery needs an explicit support decision')
    return catalogue


def load_catalogue(path=None):
    source = Path(path) if path is not None else Path(__file__).with_name('cookie-policies.json')
    return validate(json.loads(source.read_text(encoding='utf-8')))


def cookie_pattern(catalogue, consumer):
    if consumer not in CONSUMERS:
        raise ValueError('Unknown cookie policy consumer')
    names = []
    for policy in validate(catalogue)['policies']:
        if policy['consumers'][consumer]:
            match = policy['match']
            name = re.escape(match['value'])
            if match['kind'] == 'prefix':
                name += '[^=;[:blank:]]*'
            names.append(name)
    if not names:
        return '(?!)'  # An empty reviewed group matches no cookies.
    return '(^|;[[:blank:]]*)(' + '|'.join(names) + ')='


def render_policy(source, catalogue, admin_rules='', response_rules='', cms_rules=''):
    """Expand only reviewed names; output remains a standalone native VCL."""
    validate(catalogue)
    source = expand(source)
    def replace(match):
        return cookie_pattern(catalogue, match.group(1))
    # A version is a literal VCL string, not user-provided source code.
    version = json.dumps(catalogue['version'], ensure_ascii=True)[1:-1]
    rendered = MARKER.sub(replace, source).replace('@@COOKIE_POLICY_VERSION@@', version)
    rendered = rendered.replace('@@COOKIE_ADMIN_RULES@@', admin_rules)
    rendered = rendered.replace('@@COOKIE_RESPONSE_RULES@@', response_rules)
    import cms_routes
    rendered = rendered.replace('@@CMS_ROUTE_RULES@@', cms_rules)
    rendered = rendered.replace('@@CMS_NORMALIZATION@@', cms_routes.normalization_vcl())
    # Native-helper-only updates must also activate a newly loaded VCL/VMOD.
    # This contains source identity, never visitor state or an engine ABI guess.
    root=Path(__file__).parent
    identity=hashlib.sha256(b''.join((root/name).read_bytes() for name in
        ('native/cookie_handoff.c','native/cookie_handoff.vcc','native/joomla_forms.h','native_build.py'))).hexdigest()
    return '# Native cookie handoff sources: '+identity+'\n'+rendered
