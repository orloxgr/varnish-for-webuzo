"""Four named, addon-owned policies and central site-template additions."""
from pathlib import Path
import fragments

ROOT=Path(__file__).resolve().parents[1]/'profiles'
NAMES=('basic','wordpress','woocommerce','ultracache')
LABELS={'basic':'Basic','wordpress':'WordPress','woocommerce':'WooCommerce','ultracache':'UltraCache'}
DESCRIPTIONS={
    'basic':'General public HTTP cache. Unknown cookies reach the origin and query strings remain in the cache key. Authentication, private sessions and origin privacy instructions bypass shared caching.',
    'wordpress':'WordPress public pages with login, dashboard, API, preview and session exclusions. Unrelated cookies do not bypass public pages.',
    'woocommerce':'WordPress rules plus cart, checkout, customer-account and WooCommerce action exclusions. Cart and session cookies bypass cache.',
    'ultracache':'WordPress/WooCommerce policy with marketing-parameter normalization and origin-approved ESI or warmed async-cart parents. Private cart requests require opt-in and an approved shared object; cold misses remain uncached unless the ESI response handshake approves them.'}

def name(value):
    if not isinstance(value,str) or value not in NAMES:raise ValueError('Choose Basic, WordPress, WooCommerce or UltraCache')
    return value

def default(config):return name(config.get('default_profile','basic'))

def selected(site):return name(site.get('profile','basic'))

def rules(config,profile):
    name(profile)
    row=config.get('profile_rules',{}).get(profile,{})
    if not isinstance(row,dict) or set(row)-{'recv_vcl','backend_vcl'}:raise ValueError('Invalid central profile rules')
    result=dict(recv_vcl=row.get('recv_vcl',''),backend_vcl=row.get('backend_vcl',''))
    fragments.validate(result['recv_vcl'],'recv');fragments.validate(result['backend_vcl'],'backend_response')
    return result

def catalog(config):
    return [dict(name=value,label=LABELS[value],description=DESCRIPTIONS[value],source=(ROOT/(value+'.vcl')).read_text(),**rules(config,value)) for value in NAMES]

def program():return '\n'.join((ROOT/(value+'.vcl')).read_text() for value in (*NAMES,'control'))
