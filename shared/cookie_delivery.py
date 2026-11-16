"""Shared site configuration and native delivery code; never issues cookies in Python."""
import re
from cookie_catalogue import NAME, VALUE
DEFAULT = {'fbp': {'enabled': False, 'consent_cookie': 'cmplz_marketing',
                   'consent_value': 'allow', 'domain': ''}}


def normalize_delivery(value, hostname, owned_domains=()):
    if value is None:
        value = {}
    if not isinstance(value, dict) or set(value) - {'fbp'}:
        raise ValueError('Use the supported cookie delivery provider settings')
    selected = value.get('fbp', {})
    if not isinstance(selected, dict) or set(selected) - set(DEFAULT['fbp']):
        raise ValueError('Invalid Meta cookie delivery settings')
    settings = {**DEFAULT['fbp'], **selected}
    if type(settings['enabled']) is not bool:
        raise ValueError('Cookie delivery enabled must be a boolean')
    name, expected, domain = (settings[key] for key in ('consent_cookie','consent_value','domain'))
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise ValueError('Use the exact consent cookie name')
    if not isinstance(expected, str) or not VALUE.fullmatch(expected):
        raise ValueError('Use the exact consent cookie value without header separators')
    if not isinstance(domain, str):
        raise ValueError('Invalid cookie domain')
    domain = domain.lower().removeprefix('.')
    hostname = hostname.lower()
    if domain and (domain != hostname and
                   (not hostname.endswith('.' + domain) or domain not in owned_domains)):
        raise ValueError('Cookie domain must be this hostname or a parent domain owned by this account')
    settings['domain'] = domain
    return {'fbp': settings}


def recv_configuration(value, hostname, owned_domains=()):
    """VCL inside the adapter's authenticated site/host branch, after scp_init."""
    config = normalize_delivery(value, hostname, owned_domains)['fbp']
    if not config['enabled']:
        return ''
    consent = '(^|;[[:blank:]]*)' + re.escape(config['consent_cookie']) + '=' + re.escape(config['consent_value']) + '(;|$)'
    domain = config['domain']
    index = ('"' + str(domain.count('.')) + '"' if domain else
             'blob.length(blob.decode(decoding=IDENTITY, encoded=regsuball(req.http.host, "[^.]", "")))')
    return '\n'.join([
        'set req.http.X-SCP-Fbp-Enabled = "1";',
        'set req.http.X-SCP-Fbp-Domain = "' + domain + '";',
        'set req.http.X-SCP-Fbp-Index = ' + index + ';',
        'if (req.http.Cookie ~ {"' + consent + '"}) { set req.http.X-SCP-Fbp-Consent = "1"; }',
    ])
