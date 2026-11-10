"""Browser caching for existing public assets, independent of HTML/Varnish TTLs."""
import copy
import json
import re

DEFAULTS=dict(enabled=True,static_seconds=2592000,versioned_seconds=31536000,versioned_paths=[])
PROFILE_PATHS={'ultracache':['/wp-content/uploads/ultracache/css-bundles/bundle-*-{hash}.css']}
TYPES={
    'text/css':'css', 'application/javascript':'js mjs',
    'image/jpeg':'jpg jpeg', 'image/png':'png', 'image/gif':'gif',
    'image/webp':'webp', 'image/avif':'avif', 'image/avif-sequence':'avifs',
    'image/x-icon':'ico', 'image/svg+xml':'svg',
    'font/woff':'woff', 'font/woff2':'woff2', 'font/ttf':'ttf', 'font/otf':'otf',
    'application/vnd.ms-fontobject':'eot', 'application/manifest+json':'webmanifest',
    'application/wasm':'wasm', 'video/mp4':'mp4 m4v', 'video/webm':'webm',
    'video/ogg':'ogv', 'audio/mpeg':'mp3', 'audio/ogg':'ogg',
    'audio/mp4':'m4a', 'audio/wav':'wav',
}
EXTENSIONS='|'.join(ext for names in TYPES.values() for ext in names.split())


def pattern(value):
    # This is a small URL-pattern language, never arbitrary Nginx/PCRE source.
    # The administrator declares that these names change with their content;
    # a hexadecimal-looking filename or version query alone proves nothing.
    if not isinstance(value,str) or not value.startswith('/') or '{hash}' not in value:
        raise ValueError('Versioned asset paths must start with / and contain {hash}')
    if not re.fullmatch(r'[A-Za-z0-9/_.{}*\-]+',value) or any(p in ('.','..') for p in value.split('/')):
        raise ValueError('Use literal URL paths, * within one path segment, and {hash}; no query strings or Nginx syntax')
    if '{' in value.replace('{hash}','') or '}' in value.replace('{hash}','') or '**' in value:
        raise ValueError('Use * within one path segment and {hash} for a hexadecimal fingerprint')
    if value.rsplit('.',1)[-1].lower() not in EXTENSIONS.split('|'):
        raise ValueError('Versioned asset paths must end in a supported public asset extension')
    return re.escape(value).replace(r'\*','[^/]*').replace(r'\{hash\}','[0-9a-fA-F]{16,128}')


def validate(value):
    if not isinstance(value,dict) or set(value)!=set(DEFAULTS):raise ValueError('Invalid browser cache settings')
    if type(value['enabled']) is not bool:raise ValueError('Invalid browser cache enabled value')
    for key in ('static_seconds','versioned_seconds'):
        if type(value[key]) is not int or not 0<=value[key]<=2147483647:
            raise ValueError('Browser cache lifetimes must be whole seconds from 0 to 2147483647')
    if not isinstance(value['versioned_paths'],list):raise ValueError('Versioned asset paths must be a list')
    for path in value['versioned_paths']:pattern(path)
    result=copy.deepcopy(value);result['versioned_paths']=list(dict.fromkeys(result['versioned_paths']))
    return result


def defaults(config):return validate(config.get('browser_cache',copy.deepcopy(DEFAULTS)))


def selected(site,config):
    value=site.get('browser_cache')
    choice=defaults(config) if value is None else validate(value)
    choice['versioned_paths']=list(dict.fromkeys(choice['versioned_paths']+PROFILE_PATHS.get(site.get('profile'),[])))
    return choice


def variable(site):
    if not re.fullmatch('[0-9a-f]{32}',site['id']):raise ValueError('Invalid site identity')
    return '$wvb_'+site['id']


def control(seconds,immutable=False):
    if not seconds:return 'no-cache'
    return 'public, max-age='+str(seconds)+(', immutable' if immutable else '')


def maps(sites,config):
    lines=[]
    for site in sites.values():
        if not site.get('enabled') or site.get('error'):continue
        choice=selected(site,config)
        lines += ['map "$request_method:$status:$uri" '+variable(site)+' {',' default "";']
        if choice['enabled']:
            prefix='~^(?:GET|HEAD):(?:200|206|304):'
            for path in choice['versioned_paths']:
                lines.append(' '+json.dumps(prefix+pattern(path)+'$')+' '+json.dumps(control(choice['versioned_seconds'],True))+';')
            lines.append(' '+json.dumps(prefix)+' '+json.dumps(control(choice['static_seconds']))+';')
        lines.append('}')
    return '\n'.join(lines)+'\n' if lines else ''


def directives(site):
    # Explicitly retain the native validators. One Cache-Control field is added
    # only for successful GET/HEAD asset responses; dynamic fallbacks keep theirs.
    return '\n    '.join(['expires off;','etag on;','if_modified_since exact;',
        'add_header Cache-Control '+variable(site)+';',
        'types {',*('    '+mime+' '+ext+';' for mime,ext in TYPES.items()),'}'])
