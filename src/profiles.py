"""Two presets over one application policy and central site-template additions."""
from pathlib import Path
import fragments
import cookie_policy

ROOT=Path(__file__).resolve().parents[1]/'profiles'
SHARED=ROOT.parent/'shared/cache-policy.vcl'
NAMES=('basic','ultracache')
LABELS={'basic':'Basic','ultracache':'UltraCache'}
DESCRIPTIONS={
    'basic':'WordPress and WooCommerce caching, with best-effort support for other sites. Public pages, searches, REST and AJAX GET responses can be cached. Login, checkout, cart actions and private sessions remain protected.',
    'ultracache':'The Basic policy plus UltraCache ESI and async-cart integration. Approved shared HTML can be reused while personal fragments are fetched separately.'}

def name(value):
    if not isinstance(value,str) or value not in NAMES:raise ValueError('Choose Basic or UltraCache')
    return value

def default(config):return selected({'profile':config.get('default_profile')})

def selected(site):
    # Missing/unavailable saved choices use Basic without rewriting state.
    # Submitted administrator input is still validated strictly by name().
    value=site.get('profile')
    return value if isinstance(value,str) and value in NAMES else 'basic'

def rules(config,profile):
    name(profile)
    row=config.get('profile_rules',{}).get(profile,{})
    if not isinstance(row,dict) or set(row)-{'recv_vcl','backend_vcl'}:raise ValueError('Invalid central profile rules')
    result=dict(recv_vcl=row.get('recv_vcl',''),backend_vcl=row.get('backend_vcl',''))
    fragments.validate(result['recv_vcl'],'recv');fragments.validate(result['backend_vcl'],'backend_response')
    return result

def catalog(config):
    return [dict(name=value,label=LABELS[value],description=DESCRIPTIONS[value],source=cookie_policy.shared_policy(),**rules(config,value)) for value in NAMES]

def program(admin_rules=''):return cookie_policy.shared_policy(admin_rules)+'\n'+(ROOT/'control.vcl').read_text(encoding='utf-8')
