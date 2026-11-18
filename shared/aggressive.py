"""Explicit per-site shared-cache override; no settings migration or old TTL cap."""
import re
DEFAULT_TTL = 86400
GENERIC_COOKIES = frozenset(('PHPSESSID', '__Secure-PHPSESSID'))


def settings(site):
    enabled = site.get('aggressive', False)
    ttl = site.get('aggressive_ttl', DEFAULT_TTL)
    if type(enabled) is not bool:
        raise ValueError('Aggressive caching must be a checkbox value')
    if type(ttl) is not int or ttl <= 0:
        raise ValueError('Aggressive cache duration must be a positive number of seconds')
    return dict(aggressive=enabled, aggressive_ttl=ttl)


def session_names(site):
    if not settings(site)['aggressive']:return []
    rows=site.get('cms_sessions',[])
    if not isinstance(rows,list):raise ValueError('Invalid CMS session descriptors')
    names=[]
    for row in rows:
        if not isinstance(row,dict) or row.get('cms')!='joomla':raise ValueError('Invalid CMS session descriptor')
        if row.get('supported') is not True:continue
        name=row.get('cookie_name')
        if not isinstance(name,str) or not re.fullmatch('[0-9a-f]{32}',name):raise ValueError('Invalid Joomla session cookie name')
        if name not in names:names.append(name)
    return sorted(names)
