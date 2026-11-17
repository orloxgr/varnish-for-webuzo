"""Native Webuzo scopes and persistence for the shared cookie-policy compiler."""
import copy
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'shared'))
import cookie_admin
from cookie_catalogue import load_catalogue
import recognition
import state
import cookie_bridge

EMPTY = {'schemaVersion': 1, 'rules': []}


def normalize(value):
    return cookie_admin.normalize(EMPTY if value is None else value)


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
    return cookie_admin.resolve(normalize(config.get('cookie_policies')),
                                normalize(site.get('cookie_policies')) if site else None)


def executable(config, site):
    # Labels/row IDs are metadata; only the resolved match/action changes cache behavior.
    return cookie_admin.executable(normalize(config.get('cookie_policies')),
                                   normalize(site.get('cookie_policies')))


def compile_recv(config, site):
    return cookie_admin.compile_vcl(normalize(config.get('cookie_policies')),
                                    normalize(site.get('cookie_policies')))


def view(config, sites, request):
    identity, visible = scope(request, sites)
    site = visible[identity] if identity is not None else None
    central = normalize(config.get('cookie_policies'))
    local = normalize(site.get('cookie_policies')) if site else None
    admin = administrator(request)
    database = recognition.cookie_recognition.database(recognition.DIRECTORY, recognition.BUNDLED)
    rows = cookie_admin.table(database, load_catalogue(), central, local)
    inherited = cookie_admin.table(database, load_catalogue(), central if site else None, None)
    inherited_by_id = {row['id']: row for row in inherited}
    for row in rows:
        fallback = inherited_by_id.get(row['id'])
        row['inherited'] = (dict(rule_id=fallback.get('rule_id'),**{key: copy.deepcopy(fallback[key]) for key in ('match','description','action','scope','override','provider','category','proposal','htmlEffect','confidence','reason','sources','core_precedence','effective_action','valid_match') if key in fallback})
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
        settings=copy.deepcopy(central if identity is None and admin else local or EMPTY),
        rows=rows if site is not None or admin else [],
        enabled=bool(config.get('installed')) and (bool(site.get('enabled')) if site else admin),
        profile=site.get('profile') if site else None,
        integration=integration,integration_error=integration_error,
        precedence_notes=precedence,
        database_revision=database.get('revision', '')))
