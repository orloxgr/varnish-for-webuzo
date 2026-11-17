"""Versioned cookie choices shared by native panel adapters.

Versioned editorial defaults and explicit literal choices become rules.
Downloaded recognition labels never grant cache or cookie-issuance permission.
"""
import copy
import json
from pathlib import Path
import re

from cookie_catalogue import validate
from cookie_defaults import NAME, valid_name, defaults, assessment, bundle, rule_for

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
        if kind not in ('exact', 'prefix') or not valid_name(name):
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
    result, exact, prefixes = [], set(), {}
    for scope, settings in (('site', site), ('central', central)):
        rows = normalize(settings)['rules']
        rows.sort(key=lambda row: (row['match']['kind'] != 'exact', -len(row['match']['value'].encode('utf-8')),
                                   row['match']['value'], row['id']))
        seen = set()
        for row in rows:
            key = (row['match']['kind'], row['match']['value'])
            cursor=prefixes
            covered=False
            for char in row['match']['value']:
                if '' in cursor:
                    covered=True
                    break
                cursor=cursor.get(char,{})
            covered=covered or '' in cursor
            if key not in seen and not covered and not (row['match']['kind']=='exact' and row['match']['value'] in exact):
                result.append(dict(row, scope=scope))
                seen.add(key)
                if row['match']['kind']=='exact':exact.add(row['match']['value'])
                else:
                    cursor=prefixes
                    for char in row['match']['value']:cursor=cursor.setdefault(char,{})
                    cursor['']=True
    return result


def concrete(value):
    """Read old Automatic choices reproducibly, without retaining indecision.

    A prefix never borrows the decision of its first child. Only an identical
    or covering bundled match qualifies; otherwise use an explicit variant.
    Keep the raw stored snapshot intact for rollback to earlier software.
    """
    result=normalize(value)
    for row in result['rules']:
        if row['action']=='automatic':row['action']=assessment(row['match'])
    return result


def materialize(central=None):
    """Flatten our defaults below admin choices into the existing wire schema."""
    return normalize({'schemaVersion':1,'rules':[
        {key:row[key] for key in ('id','match','description','action')}
        for row in resolve(defaults(),concrete(central))]})


def active(central=None,site=None):
    return resolve(materialize(central),concrete(site))


def executable(central=None, site=None):
    """Projection used for targeted invalidation; descriptions/IDs are metadata."""
    return [(row['scope'], row['match']['kind'], row['match']['value'], row['action'])
            for row in active(central, site)]


def _recognition_match(row):
    name = row.get('name', '').strip()
    kind = 'prefix' if row.get('wildcard') else 'exact'
    if kind == 'prefix':
        name = name.removesuffix('*')
    return {'kind': kind, 'value': name}


def _matches(pattern, match):
    return (pattern == match or pattern['kind'] == 'prefix' and
            match['value'].startswith(pattern['value']))


def _proposal(match, catalogue):
    candidates = [row for row in catalogue['policies'] if _matches(row['match'], match)]
    candidates.sort(key=lambda row: (row['match']['kind'] != 'exact', -len(row['match']['value'].encode('utf-8'))))
    if not candidates:
        return None
    entry = candidates[0]
    consumers = entry['consumers']
    action = ('private' if consumers['varnishPrivate'] else
              'shared')
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
    # Preserve every executable bundled row even if upstream deletes or renames
    # a record. Newly downloaded names remain visible, with truthful provenance:
    # a proposed action is not an already compiled default.
    entries=[]
    current={row['id']:row for row in database.get('records',[])}
    for identity,editorial in assessments.items():
        entry=dict(editorial,id=identity,category='Bundled source')
        incoming=current.get(identity)
        if incoming and _recognition_match(incoming)==_recognition_match(entry):
            current.pop(identity)
            entry.update({key:incoming[key] for key in ('description','category') if key in incoming})
        entries.append(entry)
    for identity,entry in current.items():
        entries.append(dict(entry,id='recognition:'+identity if identity in assessments else identity))
    for entry in entries:
        match = _recognition_match(entry)
        editorial = assessments.get(entry['id'], {})
        if editorial and (any(editorial.get(key, '') != entry.get(key, '') for key in ('name', 'provider', 'domain')) or
                           'description' in entry and entry['description'] != editorial.get('description', '')):
            editorial = {}
        row = dict(id='ocd:' + entry['id'], match=match,
                   name=match['value'] + ('*' if match['kind'] == 'prefix' else ''),
                   description=entry.get('description') or editorial.get('description', ''),
                   provider=entry.get('provider', ''), category=entry.get('category', ''),
                   proposal=assessment(match), action=assessment(match), scope='bundled', override=False,
                   htmlEffect='unknown', confidence='unassessed',
                   reason='Our default separates public objects by cookie value unless a concrete reviewed rule applies.', sources=[])
        row.update({k: editorial[k] for k in ('proposal', 'htmlEffect', 'confidence', 'reason', 'sources') if k in editorial})
        reviewed = _proposal(match, catalogue)
        if reviewed:
            row.update(reviewed)
        row['action'] = assessment(match)
        row['proposal'] = assessment(match)
        if not rule_for(match):row['scope']='recognition'
        rows.append(row)
    existing = {(row['match']['kind'], row['match']['value']) for row in rows}
    for policy in catalogue['policies']:
        match = policy['match']
        if (match['kind'], match['value']) not in existing:
            rows.append(dict(id='policy:' + policy['id'], match=copy.deepcopy(match),
                             name=match['value'] + ('*' if match['kind'] == 'prefix' else ''),
                             description=policy.get('description', ''), provider=policy.get('provider', ''),
                             category='Reviewed policy', scope='bundled', override=False,
                             action=_proposal(match, catalogue)['proposal'], **_proposal(match, catalogue)))
    by_id = {row['id']: row for row in rows}
    # Apply central then site for display. The compiled per-cookie resolution also
    # handles overlapping patterns; table rows expose that winner, not just ID.
    explicit = resolve(concrete(central), concrete(site))
    for choice in reversed(explicit):
        if choice['id'] not in by_id:
            # Old editors created policy:<id> rows when recognition lacked that
            # entry. Retain their original reset identity even when today's
            # bundled database also supplies the equivalent ocd:<id> row.
            original=next((p for p in catalogue['policies'] if choice['id']=='policy:'+p['id']),None)
            match=original['match'] if original else choice['match']
            row = dict(id=choice['id'], match=copy.deepcopy(match),
                       name=match['value'] + ('*' if match['kind'] == 'prefix' else ''),
                       description=original.get('description','') if original else choice['description'],
                       provider=original.get('provider','') if original else '', category='Custom rule',
                       proposal=assessment(match), action=assessment(match), scope='bundled', override=False,
                       htmlEffect='site-dependent', confidence='user-choice', reason='Explicit local choice.', sources=[])
            rows.append(row)
            by_id[row['id']] = row
    inherited = resolve(materialize(central) if site is not None else defaults())
    selected_rules = normalize(site if site is not None else central)['rules']
    for row in rows:
        baseline = _proposal(row['match'], catalogue)
        inherited_winner = next((rule for rule in inherited if _matches(rule['match'], row['match'])), None)
        row['inherited_action'] = inherited_winner['action'] if inherited_winner else baseline['proposal'] if baseline else assessment(row['match'])
        row['inherited_scope'] = ('bundled' if inherited_winner['id'].startswith('bundled:') else 'central') if inherited_winner else 'recognition'
        row['inherited_active_rule'] = bool(inherited_winner)
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
            reset_metadata.update(provider='',category='Renamed inherited snapshot',proposal=assessment(row['reset_match']),
                                  htmlEffect='site-dependent',confidence='user-choice',sources=[],
                                  reason='This inherited match was renamed; original database metadata does not describe it.')
        reset_reviewed = _proposal(row['reset_match'],catalogue)
        if reset_reviewed:
            reset_metadata.update(reset_reviewed)
        reset_metadata['core_precedence'] = 'Authentication, private sessions/cart contracts and origin private/no-store remain authoritative.'
        reset_metadata['effective_action'] = row['inherited_action']
        reset_metadata['active_rule'] = row['inherited_active_rule']
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
                row.update(provider='', category='Renamed local snapshot', proposal=assessment(row['match']),
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
        row['valid_match'] = valid_name(row['match']['value'])
        row['active_rule'] = bool(winner or rule_for(row['match']))
        row['default_version'] = bundle()[1]['version']
        row['policy_behavior'] = {'shared':'Shares HTML across these cookie values; the original cookie still reaches the application.', 'variant':'Caches a separate public representation for each cookie value, including absence.', 'private':'Passes matching requests to the application without sharing their response.'}[row['action']]
        row['core_precedence'] = 'Authentication, private sessions/cart contracts and origin private/no-store remain authoritative.'
        baseline = _proposal(row['match'], catalogue)
        if baseline and baseline['proposal'] == 'private':
            row['core_precedence'] = baseline['reason'] + ' requires private handling even if a local choice says shared/variant.'
            row['effective_action'] = 'private'
        else:
            row['effective_action'] = row['action'] if row['active_rule'] else 'existing-policy'
    return sorted(rows, key=lambda row: (row['name'].casefold(), row['id']))


def _pattern(match):
    name = re.escape(match['value'])
    if match['kind'] == 'prefix':
        name += '[^=;[:blank:]]*'
    return name


def _tidy(header):
    return ('set req.http.' + header + ' = regsuball(req.http.' + header + ', "^[;[:blank:]]+|[;[:blank:]]+$", "");\n'
            'set req.http.' + header + ' = regsuball(req.http.' + header + ', ";[[:blank:]]*", "; ");\n'
            'if (req.http.' + header + ' == "") { unset req.http.' + header + '; }')


def compile_vcl(central=None, site=None, *, chain_defaults=False):
    """Body for scp_admin_cookie_rules, called after core privacy checks.

    Remove already handled pairs from a working copy so a lower-priority prefix
    cannot undo an exact/site decision. Keep the real origin Cookie unchanged.
    """
    rules = resolve(concrete(central),concrete(site)) if chain_defaults else active(central, site)
    return _compile_rules(rules,chain_defaults=chain_defaults)


def defaults_vcl():
    """Emit once per program; explicit site rules consume their pairs first."""
    return 'sub scp_bundled_cookie_rules {\n'+_compile_rules(resolve(defaults()),initialize=False,finish=False)+'\n}'


def _compile_rules(rules, *, initialize=True, finish=True, chain_defaults=False):
    if not rules and not chain_defaults:
        return ''
    code = ['set req.http.X-SCP-Admin-Remaining = req.http.Cookie;', 'unset req.http.X-SCP-Admin-Keep;'] if initialize else []
    # Public responses also need downstream variation when an absent cookie
    # would turn the same URL into a private request. Otherwise an outer cache
    # can answer before the request reaches our private guard.
    if any(rule['action'] in ('variant','private') for rule in rules):
        code.append('set req.http.X-SCP-Admin-Has-Variant = "1";')
    # Compile bundled exact names and prefixes as disjoint action groups.
    # A broader prefix excludes more-specific selectors with another action;
    # this retains precedence without hundreds of repeated VCL blocks.
    # Explicit rules keep their individual diagnostics and priority.
    grouped=[]
    for rule in rules:
        if rule['id'].startswith('bundled:'):
            key=(rule['scope'],rule['action'],rule['match']['kind'])
            pattern=_pattern(rule['match'])
            if rule['match']['kind']=='prefix':
                base=rule['match']['value']
                children=[child['match']['value'][len(base):] for child in rules if
                    child['match']['kind']=='prefix' and child['action']!=rule['action'] and
                    child['match']['value']!=base and child['match']['value'].startswith(base)]
                if children:
                    pattern=re.escape(base)+'(?!'+'|'.join(re.escape(value) for value in sorted(set(children)))+')[^=;[:blank:]]*'
            target=next((item for item in grouped if item.get('_key')==key),None)
            if target:target['_patterns'].append(pattern)
            else:grouped.append(dict(rule,id='bundled:'+rule['action'],_key=key,_patterns=[pattern]))
        else:grouped.append(rule)
    for rule in grouped:
        name = '(?:'+'|'.join(rule['_patterns'])+')' if '_patterns' in rule else _pattern(rule['match'])
        scope='bundled' if rule['id'].startswith('bundled:') else rule['scope']
        pattern = '(^|;[[:blank:]]*)(' + name + ')='
        diagnostic = '!req.http.X-SCP-Admin-Rule'
        if rule['action'] == 'variant':
            diagnostic += ' || req.http.X-SCP-Admin-Action != "variant"'
        elif rule['action'] == 'shared':
            diagnostic += ' || req.http.X-SCP-Admin-Action == "automatic"'
        code.extend(['if (req.http.X-SCP-Admin-Remaining ~ {"' + pattern + '"}) {',
                     'if (' + diagnostic + ') {',
                     'set req.http.X-SCP-Admin-Rule = ' + json.dumps(rule['id']) + ';',
                     'set req.http.X-SCP-Admin-Scope = ' + json.dumps(scope) + ';',
                     'set req.http.X-SCP-Admin-Action = ' + json.dumps(rule['action']) + ';',
                     'set req.http.X-SCP-Cookie-Name = regsub(req.http.X-SCP-Admin-Remaining, {"^.*?' + pattern + '.*$"}, "\\2");',
                     'set req.http.X-SCP-Cookie-Role = ' + json.dumps(rule['action']) + ';', '}'])
        if rule['action'] == 'private':
            code.extend(['set req.http.X-SCP-Admin-Rule = ' + json.dumps(rule['id']) + ';',
                         'set req.http.X-SCP-Admin-Scope = ' + json.dumps(scope) + ';',
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
    if chain_defaults:code.append('call scp_bundled_cookie_rules;')
    if finish:
        code.extend(['set req.http.X-SCP-Admin-Filtered = req.http.X-SCP-Admin-Keep + "; " + req.http.X-SCP-Admin-Remaining;',
                     _tidy('X-SCP-Admin-Filtered'), _tidy('X-SCP-Admin-Variant')])
    return '\n'.join(code)
