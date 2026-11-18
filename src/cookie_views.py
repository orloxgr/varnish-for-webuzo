"""Native Webuzo scopes and persistence for the shared cookie-policy compiler."""
import copy
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'shared'))
import cookie_admin
import cookie_defaults
from cookie_catalogue import load_catalogue
import recognition
import state
import cookie_bridge
import aggressive

EMPTY = {'schemaVersion': 1, 'rules': []}


def normalize(value):
    return cookie_admin.normalize(EMPTY if value is None else value)


def default_version():
    return cookie_defaults.bundle()[1]['version']


def default_digest():
    return cookie_defaults.fingerprint()


def administrator(request):
    return request.get('actor') == 'root' and request.get('admin') is True


def allowed(request):
    if administrator(request):
        return
    actor = request.get('actor')
    if (not isinstance(actor, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]*', actor)
            or actor == 'root' or request.get('admin') is not False):
        raise ValueError('A native Webuzo hosting account session is required')


def scope(request, sites, saving=False):
    allowed(request)
    admin = administrator(request)
    visible = {sid: site for sid, site in sites.items() if admin or site['owner'] == request['actor']}
    identity = request.get('id')
    if identity is None:
        if admin:
            return None, visible
        if saving:
            raise ValueError('Choose one of your own sites before saving cookie policies')
        return next(iter(visible), None), visible
    identity = state.identity(identity)
    if identity not in visible:
        raise ValueError('This site is not available to the current Webuzo account')
    return identity, visible


def rules(config, site=None):
    return cookie_admin.active(normalize(config.get('cookie_policies')),
                                normalize(site.get('cookie_policies')) if site else None)


def executable(config, site):
    # Labels/row IDs are metadata; only the resolved match/action changes cache behavior.
    return cookie_admin.executable(normalize(config.get('cookie_policies')),
                                   normalize(site.get('cookie_policies')))


def compile_recv(config, site):
    return cookie_admin.compile_vcl(normalize(config.get('cookie_policies')),
                                    normalize(site.get('cookie_policies')),chain_defaults=True,automatic_shared=aggressive.session_names(site))


def defaults_vcl():
    return cookie_admin.defaults_vcl()


def explain_cart_precedence(metadata, match, profile, catalogue, selected_action=None):
    cart=next((entry for entry in catalogue['policies'] if entry['consumers']['varnishCart']
               and cookie_admin._matches(entry['match'],match)),None)
    if not cart:return
    metadata['core_precedence']='WooCommerce cart/session protection takes precedence over the table choice. '
    if profile=='basic':
        metadata['effective_action']='private'
        metadata['core_precedence']+='Basic passes this cart/session request to the application.'
        metadata['policy_behavior']='Basic sends requests carrying this WooCommerce cart/session cookie to the application (PASS).'
    elif selected_action=='private':
        metadata['effective_action']='private'
        metadata['core_precedence']='The explicit Private choice passes the entire request before optional UltraCache ESI sharing.'
        metadata['policy_behavior']='The explicit Private choice sends the entire request, including its HTML, to the application (PASS).'
    else:
        metadata['effective_action']='application-contract'
        metadata['core_precedence']+='Basic passes this cart/session request. UltraCache shares only an approved ESI parent with private fragments; without that application contract it also passes.'
        metadata['policy_behavior']='Basic uses PASS. UltraCache shares the HTML only with a verified private-fragment contract; otherwise it also uses PASS.'


def view(config, sites, request):
    identity, visible = scope(request, sites)
    site = visible[identity] if identity is not None else None
    central = normalize(config.get('cookie_policies'))
    local = normalize(site.get('cookie_policies')) if site else None
    admin = administrator(request)
    database = recognition.database()
    catalogue=load_catalogue();profile=site.get('profile','basic') if site else None
    rows = cookie_admin.table(database, catalogue, central, local)
    inherited = cookie_admin.table(database, catalogue, central if site else None, None)
    for row in rows+inherited:
        if site and aggressive.settings(site)['aggressive']:
            explanation='Aggressive mode shares this generic anonymous session cookie. Known authentication, private routes and explicit Private choices still select PASS.'
            for metadata in (row,row['reset_metadata']):
                metadata['core_precedence']=metadata.get('core_precedence','').replace(
                    'and origin private/no-store remain authoritative.',
                    'take precedence. Aggressive mode can override generic origin privacy for anonymous public HTML.')
            if row['match']['kind']=='exact' and row['match']['value'] in aggressive.GENERIC_COOKIES:
                if not row.get('override'):
                    row.update(action='shared',effective_action='shared',mode_default_action='shared',
                               core_precedence=explanation,policy_behavior='Shares anonymous public HTML without storing or replaying personal cookie values.')
                if row['inherited_scope']=='bundled':row['inherited_action']='shared'
            if row['reset_match']['kind']=='exact' and row['reset_match']['value'] in aggressive.GENERIC_COOKIES and row['inherited_scope']=='bundled':
                row['reset_metadata'].update(effective_action='shared',mode_default_action='shared',core_precedence=explanation)
        explain_cart_precedence(row,row['match'],profile,catalogue,row.get('action') if row.get('override') else None)
        explain_cart_precedence(row['reset_metadata'],row['reset_match'],profile,catalogue,
                                row['inherited_action'] if row['inherited_scope']=='central' else None)
    inherited_by_id = {row['id']: row for row in inherited}
    for row in rows:
        fallback = inherited_by_id.get(row['id'])
        row['inherited'] = (dict(rule_id=fallback.get('rule_id'),**{key: copy.deepcopy(fallback[key]) for key in ('match','description','action','scope','override','provider','category','proposal','htmlEffect','confidence','reason','sources','core_precedence','effective_action','valid_match','default_version','policy_behavior','active_rule','mode_default_action') if key in fallback})
                            if fallback else None)
    integration=None; integration_error=site.get('cookie_integration_notice','') if site else ''
    precedence=[]
    if site:
        try:integration=cookie_bridge.configuration(site.get('cookie_integration'),site)
        except ValueError:
            integration=cookie_bridge.configuration(None,site)
            integration_error='The saved WordPress connection is no longer valid for this site. Choose a current site hostname before saving.'
        for path in site.get('bypass',[]):precedence.append('Site bypass path '+path+' selects PASS before cookie rules (site-bypass-path).')
        if site.get('recv_vcl'):precedence.append('Additional site request VCL runs before cookie rules; matching PASS decisions report site-request-vcl.')
        if config.get('profile_rules',{}).get(site.get('profile','basic'),{}).get('recv_vcl'):
            precedence.append('Central '+site.get('profile','basic')+' request VCL runs before cookie rules; matching PASS decisions report central-profile-vcl.')
    return dict(cookie_policies=dict(
        administrator=admin, id=identity, scope='central' if identity is None and admin else 'site',
        sites=[{key: row[key] for key in ('id', 'domain', 'owner', 'enabled', 'profile', 'error')}
               for row in visible.values()],
        settings=cookie_admin.concrete(central if identity is None and admin else local or EMPTY),
        rows=rows if site is not None or admin else [],
        enabled=bool(config.get('installed')) and (bool(site.get('enabled')) if site else admin),
        profile=site.get('profile') if site else None,
        aggressive=aggressive.settings(site)['aggressive'] if site else False,
        integration=integration,integration_error=integration_error,
        precedence_notes=precedence,
        database_revision=database.get('revision', '')))
