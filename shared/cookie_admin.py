"""Versioned cookie choices shared by native panel adapters.

Only explicit, literal match snapshots become rules. Recognition remains local
metadata and never grants public-cache or cookie-issuance permission by itself.
"""
import copy
import json
from pathlib import Path
import re

from cookie_catalogue import NAME, validate

ACTIONS = ('automatic', 'shared', 'variant', 'private')
IDENTITY = re.compile(r'[A-Za-z0-9][A-Za-z0-9:._-]*')


class CookieChoiceError(ValueError):
    """A safe fixed-message validation error for the native panel."""
    pass


def normalize(value):
    if value is None:
        return {'schemaVersion': 1, 'rules': []}
    if (not isinstance(value, dict) or type(value.get('schemaVersion')) is not int or
            value['schemaVersion'] != 1 or set(value) != {'schemaVersion', 'rules'}):
        raise CookieChoiceError('Unsupported cookie choices schema')
    if not isinstance(value['rules'], list):
        raise CookieChoiceError('Cookie choices need a list of rules')
    result, identities, matches = [], set(), {}
    for raw in value['rules']:
        if not isinstance(raw, dict) or set(raw) != {'id', 'match', 'description', 'action'}:
            raise CookieChoiceError('Cookie rules need id, literal match, description and action')
        identity, match, action = raw['id'], raw['match'], raw['action']
        if not isinstance(identity, str) or not IDENTITY.fullmatch(identity) or identity in identities:
            raise CookieChoiceError('Cookie rule identifiers must be unique literal identifiers')
        identities.add(identity)
        if not isinstance(match, dict) or set(match) != {'kind', 'value'}:
            raise CookieChoiceError('A cookie match needs kind and value')
        kind, name = match['kind'], match['value']
        if kind not in ('exact', 'prefix') or not isinstance(name, str) or not NAME.fullmatch(name):
            raise CookieChoiceError('Use a literal cookie name or prefix')
        description = raw['description']
        if not isinstance(description, str) or re.search(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', description):
            raise CookieChoiceError('Cookie description must be plain text')
        if action not in ACTIONS:
            raise CookieChoiceError('Unknown cookie action')
        key = (kind, name)
        if key in matches and matches[key] != action:
            raise CookieChoiceError('The same cookie match has conflicting actions in this scope')
        matches[key] = action
        result.append({'id': identity, 'match': {'kind': kind, 'value': name},
                       'description': description, 'action': action})
    return {'schemaVersion': 1, 'rules': sorted(result, key=lambda row: row['id'])}


def resolve(central=None, site=None):
    """Site choices precede central choices; exact then longest literal prefix."""
    result = []
    for scope, settings in (('site', site), ('central', central)):
        rows = normalize(settings)['rules']
        rows.sort(key=lambda row: (row['match']['kind'] != 'exact', -len(row['match']['value']),
                                   row['match']['value'], row['id']))
        seen = set()
        for row in rows:
            key = (row['match']['kind'], row['match']['value'])
            if key not in seen and not any(_matches(prior['match'], row['match']) for prior in result):
                result.append(dict(row, scope=scope))
                seen.add(key)
    return result


def executable(central=None, site=None):
    """Projection used for targeted invalidation; descriptions/IDs are metadata."""
    return [(row['scope'], row['match']['kind'], row['match']['value'], row['action'])
            for row in resolve(central, site)]


def _recognition_match(row):
    name = row.get('name', '')
    kind = 'prefix' if row.get('wildcard') else 'exact'
    if kind == 'prefix':
        name = name.removesuffix('*')
    return {'kind': kind, 'value': name}


def _matches(pattern, match):
    return (pattern == match or pattern['kind'] == 'prefix' and
            match['value'].startswith(pattern['value']))


def _proposal(match, catalogue):
    candidates = [row for row in catalogue['policies'] if _matches(row['match'], match)]
    candidates.sort(key=lambda row: (row['match']['kind'] != 'exact', -len(row['match']['value'])))
    if not candidates:
        return None
    entry = candidates[0]
    consumers = entry['consumers']
    action = ('private' if consumers['varnishPrivate'] else
              'shared' if consumers['varnishTrackingIgnore'] else 'automatic')
    return dict(proposal=action, htmlEffect=entry['htmlEffect'], confidence='reviewed',
                reason='Reviewed policy ' + entry['id'] + '; private cart/ESI behavior retains its application contract.'
                       if consumers['varnishCart'] else 'Reviewed policy ' + entry['id'],
                sources=entry.get('sources', []))


def table(database, catalogue, central=None, site=None):
    """The database has a real admin consumer; values never enter this API."""
    validate(catalogue)
    assessment_path = Path(__file__).with_name('cookie-assessments.json')
    assessments = json.loads(assessment_path.read_text(encoding='utf-8'))['records'] if assessment_path.exists() else {}
    rows = []
    for entry in database.get('records', []):
        match = _recognition_match(entry)
        assessment = assessments.get(entry['id'], {})
        if assessment and (any(assessment.get(key, '') != entry.get(key, '') for key in ('name', 'provider', 'domain')) or
                           'description' in entry and entry['description'] != assessment.get('description', '')):
            assessment = {}
        row = dict(id='ocd:' + entry['id'], match=match,
                   name=match['value'] + ('*' if match['kind'] == 'prefix' else ''),
                   description=entry.get('description') or assessment.get('description', ''),
                   provider=entry.get('provider', ''), category=entry.get('category', ''),
                   proposal='automatic', action='automatic', scope='existing-policy', override=False,
                   htmlEffect='unknown', confidence='unassessed',
                   reason='No reviewed execution policy; existing behavior is retained.', sources=[])
        row.update({k: assessment[k] for k in ('proposal', 'htmlEffect', 'confidence', 'reason', 'sources') if k in assessment})
        reviewed = _proposal(match, catalogue)
        if reviewed:
            row.update(reviewed)
            row['action'] = reviewed['proposal']
        rows.append(row)
    existing = {(row['match']['kind'], row['match']['value']) for row in rows}
    for policy in catalogue['policies']:
        match = policy['match']
        if (match['kind'], match['value']) not in existing:
            rows.append(dict(id='policy:' + policy['id'], match=copy.deepcopy(match),
                             name=match['value'] + ('*' if match['kind'] == 'prefix' else ''),
                             description=policy.get('description', ''), provider=policy.get('provider', ''),
                             category='Reviewed policy', scope='existing-policy', override=False,
                             action=_proposal(match, catalogue)['proposal'], **_proposal(match, catalogue)))
    by_id = {row['id']: row for row in rows}
    # Apply central then site for display. The compiled per-cookie resolution also
    # handles overlapping patterns; table rows expose that winner, not just ID.
    explicit = resolve(central, site)
    for choice in reversed(explicit):
        if choice['id'] not in by_id:
            row = dict(id=choice['id'], match=copy.deepcopy(choice['match']),
                       name=choice['match']['value'] + ('*' if choice['match']['kind'] == 'prefix' else ''),
                       description=choice['description'], provider='', category='Custom rule',
                       proposal='automatic', action='automatic', scope='existing-policy', override=False,
                       htmlEffect='site-dependent', confidence='user-choice', reason='Explicit local choice.', sources=[])
            rows.append(row)
            by_id[row['id']] = row
    inherited = resolve(central) if site is not None else []
    selected_rules = normalize(site if site is not None else central)['rules']
    for row in rows:
        baseline = _proposal(row['match'], catalogue)
        inherited_winner = next((rule for rule in inherited if _matches(rule['match'], row['match'])), None)
        row['inherited_action'] = inherited_winner['action'] if inherited_winner else baseline['proposal'] if baseline else 'automatic'
        row['inherited_scope'] = 'central' if inherited_winner else 'existing-policy'
        row['inherited_exists'] = (not row['id'].startswith('custom:') or
                                   any(rule['id'] == row['id'] for rule in inherited))
        row['local_choice'] = next((copy.deepcopy(rule) for rule in selected_rules if rule['id'] == row['id']), None)
        reset = next((rule for rule in inherited if rule['id'] == row['id']), None)
        row['reset_match'] = copy.deepcopy(reset['match'] if reset else row['match'])
        row['reset_name'] = row['reset_match']['value'] + ('*' if row['reset_match']['kind'] == 'prefix' else '')
        row['reset_description'] = reset['description'] if reset else row['description']
        row['reset_proposal'] = row['proposal']
        row['reset_provider'] = row['provider']
        reset_metadata = {key: copy.deepcopy(row[key]) for key in
                          ('provider','category','proposal','htmlEffect','confidence','reason','sources')}
        if reset and reset['match'] != row['match']:
            reset_metadata.update(provider='',category='Renamed inherited snapshot',proposal='automatic',
                                  htmlEffect='site-dependent',confidence='user-choice',sources=[],
                                  reason='This inherited match was renamed; original database metadata does not describe it.')
        reset_reviewed = _proposal(row['reset_match'],catalogue)
        if reset_reviewed:
            reset_metadata.update(reset_reviewed)
        reset_metadata['core_precedence'] = 'Authentication, private sessions/cart contracts and origin private/no-store remain authoritative.'
        reset_metadata['effective_action'] = row['inherited_action']
        if reset_reviewed and reset_reviewed['proposal']=='private':
            reset_metadata['effective_action']='private'
            reset_metadata['core_precedence']=reset_reviewed['reason']+' requires private handling even if a local choice says shared/variant.'
        row['reset_metadata']=reset_metadata
        row['reset_proposal']=reset_metadata['proposal']
        row['reset_provider']=reset_metadata['provider']
        own = next((rule for rule in explicit if rule['id'] == row['id']), None)
        if own:
            renamed = own['match'] != row['match']
            row.update(match=copy.deepcopy(own['match']), description=own['description'])
            row['name'] = own['match']['value'] + ('*' if own['match']['kind'] == 'prefix' else '')
            if renamed:
                row.update(provider='', category='Renamed local snapshot', proposal='automatic',
                           htmlEffect='site-dependent', confidence='user-choice', sources=[],
                           reason='This local match was renamed; the original database provider and HTML assessment do not describe it.')
                reviewed = _proposal(row['match'], catalogue)
                if reviewed:
                    row.update(reviewed)
        winner = next((rule for rule in explicit if _matches(rule['match'], row['match'])), None)
        if winner:
            row.update(action=winner['action'], scope=winner['scope'], override=True,
                       rule_id=winner['id'])
            if winner['id'] == row['id']:
                row.update(match=copy.deepcopy(winner['match']), description=winner['description'])
                row['name'] = winner['match']['value'] + ('*' if winner['match']['kind'] == 'prefix' else '')
        # UI editing a snapshot does not need to guess whether this name is a
        # valid HTTP token. Invalid upstream notation remains visible metadata.
        row['valid_match'] = bool(NAME.fullmatch(row['match']['value']))
        row['core_precedence'] = 'Authentication, private sessions/cart contracts and origin private/no-store remain authoritative.'
        baseline = _proposal(row['match'], catalogue)
        if baseline and baseline['proposal'] == 'private':
            row['core_precedence'] = baseline['reason'] + ' requires private handling even if a local choice says shared/variant.'
            row['effective_action'] = 'private'
        else:
            row['effective_action'] = row['action']
    return sorted(rows, key=lambda row: (row['name'].casefold(), row['id']))


def _pattern(match):
    name = re.escape(match['value'])
    if match['kind'] == 'prefix':
        name += '[^=;[:blank:]]*'
    return name


def _tidy(header):
    return ('set req.http.' + header + ' = regsuball(req.http.' + header + ', "^[;[:blank:]]+|[;[:blank:]]+$", "");\n'
            'set req.http.' + header + ' = regsuball(req.http.' + header + ', ";[[:blank:]]*", "; ");')


def compile_vcl(central=None, site=None):
    """Body for scp_admin_cookie_rules, called after core privacy checks.

    Remove already handled pairs from a working copy so a lower-priority prefix
    cannot undo an exact/site decision. Keep the real origin Cookie unchanged.
    """
    rules = resolve(central, site)
    if not rules:
        return ''
    code = ['set req.http.X-SCP-Admin-Remaining = req.http.Cookie;', 'unset req.http.X-SCP-Admin-Keep;']
    # Public responses also need downstream variation when an absent cookie
    # would turn the same URL into a private request. Otherwise an outer cache
    # can answer before the request reaches our private guard.
    if any(rule['action'] in ('variant','private') for rule in rules):
        code.append('set req.http.X-SCP-Admin-Has-Variant = "1";')
    for rule in rules:
        name = _pattern(rule['match'])
        pattern = '(^|;[[:blank:]]*)(' + name + ')='
        diagnostic = '!req.http.X-SCP-Admin-Rule'
        if rule['action'] == 'variant':
            diagnostic += ' || req.http.X-SCP-Admin-Action != "variant"'
        elif rule['action'] == 'shared':
            diagnostic += ' || req.http.X-SCP-Admin-Action == "automatic"'
        code.extend(['if (req.http.X-SCP-Admin-Remaining ~ {"' + pattern + '"}) {',
                     'if (' + diagnostic + ') {',
                     'set req.http.X-SCP-Admin-Rule = ' + json.dumps(rule['id']) + ';',
                     'set req.http.X-SCP-Admin-Scope = ' + json.dumps(rule['scope']) + ';',
                     'set req.http.X-SCP-Admin-Action = ' + json.dumps(rule['action']) + ';',
                     'set req.http.X-SCP-Cookie-Name = regsub(req.http.X-SCP-Admin-Remaining, {"^.*?' + pattern + '.*$"}, "\\2");',
                     'set req.http.X-SCP-Cookie-Role = ' + json.dumps(rule['action']) + ';', '}'])
        if rule['action'] == 'private':
            code.extend(['set req.http.X-SCP-Admin-Rule = ' + json.dumps(rule['id']) + ';',
                         'set req.http.X-SCP-Admin-Scope = ' + json.dumps(rule['scope']) + ';',
                         'set req.http.X-SCP-Admin-Action = "private";',
                         'set req.http.X-SCP-Cookie-Name = regsub(req.http.X-SCP-Admin-Remaining, {"^.*?' + pattern + '.*$"}, "\\2");',
                         'set req.http.X-SCP-Cookie-Role = "private";',
                         'set req.http.X-SCP-Reason = "cookie-policy-private";', 'return (pass);'])
        if rule['action'] in ('variant', 'automatic'):
            # Check optional whitespace inside the lookahead. Putting it before
            # a negative lookahead lets PCRE backtrack and drop wanted pairs.
            inverse = '(^|;)(?![[:blank:]]*(?:' + name + ')=)[^;]*'
            code.extend(['set req.http.X-SCP-Admin-Matched = regsuball(req.http.X-SCP-Admin-Remaining, {"' + inverse + '"}, "");',
                         _tidy('X-SCP-Admin-Matched'),
                         'set req.http.X-SCP-Admin-Keep = req.http.X-SCP-Admin-Keep + "; " + req.http.X-SCP-Admin-Matched;'])
            if rule['action'] == 'variant':
                code.append('set req.http.X-SCP-Admin-Variant = req.http.X-SCP-Admin-Variant + "; " + req.http.X-SCP-Admin-Matched;')
                code.extend(['if (req.http.X-SCP-Admin-Rule == ' + json.dumps(rule['id']) + ') {',
                             'set req.http.X-SCP-Cookie-Name = regsuball(req.http.X-SCP-Admin-Matched, "=[^;]*", "");',
                             'set req.http.X-SCP-Cookie-Name = regsuball(req.http.X-SCP-Cookie-Name, ";[[:blank:]]*", ", ");', '}'])
        code.extend(['set req.http.X-SCP-Admin-Remaining = regsuball(req.http.X-SCP-Admin-Remaining, {"' + pattern + '[^;]*"}, "");',
                     _tidy('X-SCP-Admin-Remaining'), '}'])
    code.extend(['set req.http.X-SCP-Admin-Filtered = req.http.X-SCP-Admin-Keep + "; " + req.http.X-SCP-Admin-Remaining;',
                 _tidy('X-SCP-Admin-Filtered'), _tidy('X-SCP-Admin-Variant')])
    return '\n'.join(code)
