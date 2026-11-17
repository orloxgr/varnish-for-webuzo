"""Compile reviewed local cookie policies. Recognition metadata is not executable.

This module is distributed unchanged by both panel integrations. It has no panel,
network, or WordPress dependency. Loading happens when generating VCL, not on an
HTTP request. Cookie values never enter this API.
"""
import json
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


def render_policy(source, catalogue, admin_rules=''):
    """Expand only reviewed names; output remains a standalone native VCL."""
    validate(catalogue)
    source = expand(source)
    def replace(match):
        return cookie_pattern(catalogue, match.group(1))
    # A version is a literal VCL string, not user-provided source code.
    version = json.dumps(catalogue['version'], ensure_ascii=True)[1:-1]
    rendered = MARKER.sub(replace, source).replace('@@COOKIE_POLICY_VERSION@@', version)
    rendered = rendered.replace('@@COOKIE_ADMIN_RULES@@', admin_rules)
    if '@@FBP_' not in rendered:
        return rendered
    fbp = next(policy for policy in catalogue['policies'] if policy['id'] == 'fbp')
    held = []
    conditions = fbp['delivery'].get('transports', {}).get('proxy-fbp', {}).get('holdWhen', [])
    if not isinstance(conditions,list) or any(not isinstance(item,dict) for item in conditions):
        raise ValueError('Provider hold policy needs a list of conditions')
    for condition in conditions:
        name, expected = condition.get('cookie'), condition.get('value')
        if not isinstance(name,str) or not NAME.fullmatch(name) or not isinstance(expected,str) or not VALUE.fullmatch(expected):
            raise ValueError('Provider hold policy needs an exact cookie name/value')
        expression = '(^|;[[:blank:]]*)' + re.escape(name) + '=' + re.escape(expected) + '(;|$)'
        held.append('if (req.http.Cookie ~ {"' + expression + '"}) {\n' +
            '        set req.http.X-SCP-Cookie-Name = ' + json.dumps(name) + ';\n' +
            '        set req.http.X-SCP-Cookie-Role = "provider-consent";\n' +
            '        set resp.http.X-Cache-Cookie-Delivery = "fbp:provider-held";\n' +
            '        return;\n    }')
    rendered = rendered.replace('@@FBP_PROVIDER_HOLD@@', '\n    '.join(held))
    attributes = fbp['attributes']
    age, path, same_site = (attributes.get(key) for key in ('maxAgeSeconds','path','sameSite'))
    if type(age) is not int or age <= 0:
        raise ValueError('Native Meta cookie policy needs a positive Max-Age')
    if not isinstance(path, str) or not path.startswith('/') or re.search(r'[\x00-\x20\x7f;"\\]', path):
        raise ValueError('Native Meta cookie policy needs a literal cookie path')
    if same_site not in ('Lax','Strict','None') or type(attributes.get('httpOnly')) is not bool:
        raise ValueError('Native Meta cookie policy needs explicit SameSite and HttpOnly attributes')
    secure = attributes.get('secure')
    if secure == 'site-scheme':
        secure_vcl = '''if (req.http.X-Forwarded-Proto ~ "(?i)^https$") {
        set req.http.X-SCP-Fbp-New = req.http.X-SCP-Fbp-New + "; Secure";
    }'''
    elif secure is True:
        secure_vcl = 'set req.http.X-SCP-Fbp-New = req.http.X-SCP-Fbp-New + "; Secure";'
    elif secure is False:
        secure_vcl = ''
    else:
        raise ValueError('Native Meta cookie policy needs a known Secure attribute policy')
    for marker, value in {'MAX_AGE':str(age), 'PATH':path, 'SAME_SITE':same_site,
                           'HTTP_ONLY':'; HttpOnly' if attributes['httpOnly'] else '',
                           'SECURE_VCL':secure_vcl}.items():
        rendered = rendered.replace('@@FBP_' + marker + '@@', value)
    return rendered
