"""Fresh CMS authentication classification; never bootstrap customer PHP.

Guest authentication state alone does not prove that session-bound form tokens
inside the response are shareable. The adapter must keep that separate contract.
"""
import hashlib
import json
import os
import re
import subprocess

from cms_discovery import read_literal
import cms_metadata


def cookies(header):
    result = {}
    for field in header.split(';'):
        name, separator, value = field.strip().partition('=')
        if not separator or not name:
            continue
        if name in result:
            raise ValueError('Ambiguous cookie name')
        result[name] = value
    return result


def joomla_settings(root):
    """Verified Joomla 3–6 default site application + database session handler.

    CMSApplication hashes secret+site; Session::setOptions hashes that name
    again. Do not mistake an arbitrary 32-hex tracking cookie for this session.
    """
    version = read_literal(root, 'libraries/cms/version/version.php') if _legacy(root) else read_literal(root, 'libraries/src/Version.php')
    release = re.search(r"\b(?:const\s+RELEASE|\$RELEASE)\s*=\s*['\"]([3-6])\.[0-9]+['\"]\s*;", version)
    major = re.search(r'\bconst\s+MAJOR_VERSION\s*=\s*([3-6])\s*;', version)
    if not (release or major):
        raise cms_metadata.MetadataUnavailable('Unsupported Joomla session naming')
    major = int(major[1] if major else release[1])
    text = read_literal(root, 'configuration.php')
    tokens = [token for token in cms_metadata.TOKEN.findall(text) if not token.startswith(('//','/*','#'))]
    _, values, _ = cms_metadata.settings(text)
    for name in ('secret','session_handler','session_name'):
        occurrences = [i for i,t in enumerate(tokens[:-1]) if t=='$' and tokens[i+1]==name]
        if occurrences and (len(occurrences)!=1 or name not in values):
            raise cms_metadata.MetadataUnavailable('Dynamic session settings are not evaluated')
    for name in ('shared_session','session_metadata'):
        occurrences = [i for i,t in enumerate(tokens[:-1]) if t=='$' and tokens[i+1]==name]
        if occurrences:
            i=occurrences[0]
            acceptable = ('0','false',"'0'",'"0"') if name=='shared_session' else ('1','true',"'1'",'"1"')
            if len(occurrences)!=1 or tokens[i+2:i+5] not in [['=',value,';'] for value in acceptable]:
                raise cms_metadata.MetadataUnavailable('Unsupported session metadata configuration')
    if values.get('session_handler') != 'database' or not values.get('secret'):
        raise cms_metadata.MetadataUnavailable('Unsupported Joomla session configuration')
    seed = values.get('session_name', 'site' if major == 3 else r'Joomla\CMS\Application\SiteApplication')
    first = hashlib.md5((values['secret'] + seed).encode()).hexdigest()
    return hashlib.md5(first.encode()).hexdigest()


def _legacy(root):
    try:
        read_literal(root, 'libraries/src/Version.php')
        return False
    except FileNotFoundError:
        return True


def classify(root, header, query):
    """query(connection, exact_session_id) returns current guest/userid rows.

    No result cache: a guest-to-authenticated transition must be observed before
    a warm cache lookup, even when the client removes its user-state marker.
    """
    try:
        supplied = cookies(header)
        if supplied.get('joomla_user_state') == 'logged_in':
            return 'private', 'joomla-authenticated-session'
        if any(name.startswith('joomla_remember_me_') and value for name,value in supplied.items()):
            return 'private', 'joomla-remember-session'
        name = joomla_settings(root)
        # Joomla 3 accepts a pre-3.6 remember-me cookie under a bare hash name.
        # Its token.series shape is not an unrelated numeric analytics cookie.
        if any(other!=name and re.fullmatch('[a-f0-9]{32}',other) and '.' in value
               for other,value in supplied.items()):
            return 'unresolved', 'joomla-legacy-remember'
        if name not in supplied:
            return 'guest', 'joomla-no-session'
        session = supplied[name]
        if not re.fullmatch(r'[A-Za-z0-9,-]+', session):
            return 'unresolved', 'joomla-session-invalid'
        connection = cms_metadata.connection('joomla', root)
        records = query(connection, session)
        if not records:
            return 'guest', 'joomla-expired-session'
        if len(records) != 1:
            return 'unresolved', 'joomla-session-not-found'
        guest, user = records[0]['guest'], records[0]['userid']
        if str(guest) == '0' or (str(user).isdigit() and int(user) > 0):
            return 'private', 'joomla-authenticated-session'
        if str(guest) == '1' and str(user) == '0':
            return 'guest', 'joomla-guest-session'
        return 'unresolved', 'joomla-session-invalid'
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        return 'unresolved', 'joomla-session-unavailable'


def mysql_session(connection, session, *, timeout=None, executable='/usr/bin/mysql'):
    """Run as the hosting UID. Values bind through a server prepared SELECT.

    Credentials stay out of argv, stdout, panel diagnostics and root state. The
    query is readonly and the session ID is an encoded prepared parameter.
    """
    if os.geteuid() == 0:
        raise ValueError('CMS database queries must run as the hosting account')
    prefix = connection['prefix']
    if not re.fullmatch(r'[A-Za-z0-9_]*', prefix):
        raise ValueError('Invalid table prefix')
    command = [executable, '--no-defaults', '--batch', '--raw', '--skip-column-names',
               '--default-character-set=utf8mb4', '--host=' + connection['host'],
               '--user=' + connection['user'], '--database=' + connection['database']]
    if connection.get('port') is not None:
        command.append('--port=' + str(connection['port']))
    if connection.get('socket'):
        command.append('--socket=' + connection['socket'])
    prepared = "SELECT JSON_OBJECT('guest',guest,'userid',userid) FROM `" + prefix + "session` WHERE session_id=? AND client_id=0"
    statement = ("START TRANSACTION READ ONLY; SET @cms_session=CONVERT(UNHEX('" + session.encode().hex() + "') USING utf8mb4); "
                 "SET @cms_query=CONVERT(UNHEX('" + prepared.encode().hex() + "') USING utf8mb4); "
                 "PREPARE cms_lookup FROM @cms_query; EXECUTE cms_lookup USING @cms_session; "
                 "DEALLOCATE PREPARE cms_lookup; ROLLBACK;")
    result = subprocess.run(command, input=statement, capture_output=True, text=True, timeout=timeout,
                            env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'MYSQL_PWD': connection['password']})
    if result.returncode:
        raise cms_metadata.MetadataUnavailable('CMS session query failed')
    return [json.loads(line) for line in result.stdout.splitlines() if line]
