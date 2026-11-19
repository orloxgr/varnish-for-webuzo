"""Native Webuzo document roots and unprivileged read-only route metadata."""
import copy
import json
from pathlib import Path
import pwd
import subprocess
import sys
from urllib.parse import unquote

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'shared'))
import cms_discovery
import cms_metadata
import cms_cookies


def query(connection, site, statement):
    if not statement.startswith('SELECT '):
        raise ValueError('CMS metadata permits SELECT statements only')
    user = pwd.getpwnam(site['owner'])
    if user.pw_uid == 0 or user.pw_uid != site['uid'] or user.pw_gid != site['gid'] or user.pw_dir != site['home']:
        raise ValueError('Hosting identity changed during CMS discovery')
    command = ['/usr/bin/mysql', '--no-defaults', '--batch', '--raw', '--skip-column-names',
               '--default-character-set=utf8mb4', '--host='+connection['host'],
               '--user='+connection['user'], '--database='+connection['database']]
    if connection.get('port') is not None:command.append('--port='+str(connection['port']))
    socket = connection.get('socket')
    if not socket and connection['host'] == 'localhost':socket = '/var/lib/mysql/mysql.sock'
    if socket:command.append('--socket='+socket)
    command.append('--execute=START TRANSACTION READ ONLY; '+statement+'; ROLLBACK;')
    # A customer-owned DB_HOST/DB_USER must never inherit root unix_socket auth.
    result = subprocess.run(command, capture_output=True, text=True, user=user.pw_uid,
                            group=user.pw_gid, extra_groups=[], umask=0o077,
                            env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','HOME':user.pw_dir,
                                 'MYSQL_PWD':connection['password']})
    if result.returncode:
        raise cms_metadata.MetadataUnavailable('Read-only CMS route query failed')
    try:return [json.loads(line) for line in result.stdout.splitlines() if line]
    except (ValueError, TypeError):raise cms_metadata.MetadataUnavailable('Unexpected CMS route metadata') from None


def discover(site, previous=None):
    excluded = cms_discovery.exclusions(site.get('cms_excluded_directories', []))
    records = cms_discovery.discover(site['path'], excluded)
    notices = []
    sessions = []
    for index, record in enumerate(records):
        if record['cms'] not in ('wordpress','joomla','prestashop'):continue
        root = Path(site['path']) / unquote(record['base']).lstrip('/')
        if record['cms']=='joomla':
            try:sessions.append(dict(cms='joomla',base=record['base'],cookie_name=cms_cookies.joomla_name(root),supported=True))
            except (OSError,ValueError):
                sessions.append(dict(cms='joomla',base=record['base'],supported=False))
                notices.append('joomla at '+record['base']+': Session cookie name could not be read; use an explicit cookie rule if needed.')
        try:
            connection = cms_metadata.connection(record['cms'], root)
            records[index] = cms_metadata.aliases(record, lambda statement:query(connection,site,statement), connection['prefix'], site['names'])
        except (OSError, ValueError, KeyError, TypeError):
            retained=next((old for old in (previous or {}).get('cms_installations',[])
                           if old['cms']==record['cms'] and old['base']==record['base']),None)
            if retained and not cms_discovery.excluded(retained['base'], excluded) and \
                    str(Path((previous or {}).get('path',''))) == str(Path(site['path'])):
                records[index]=retained
                notices.append(record['cms']+' at '+record['base']+': Configured route metadata unavailable; last discovered routes remain active.')
            else:notices.append(record['cms']+' at '+record['base']+': Configured route metadata unavailable; standard CMS routes remain active.')
    return records, notices, sessions


def retain(site, previous):
    """Explicit exclusions also prune last-valid metadata before any refresh."""
    excluded = cms_discovery.exclusions(site.get('cms_excluded_directories', []))
    for field in ('cms_installations', 'cms_cookies'):
        site[field] = [copy.deepcopy(row) for row in previous.get(field, [])
                       if not cms_discovery.excluded(row['base'], excluded)]
    site['cms_discovery_notices'] = copy.deepcopy(previous.get('cms_discovery_notices', []))
    marker = previous.get('cms_discovery_root')
    if not marker and 'cms_installations' in previous:
        marker = previous.get('path')
    if marker:
        site['cms_discovery_root'] = str(Path(marker))


def root_changed(site):
    return bool(site.get('path')) and str(Path(site['path'])) != site.get('cms_discovery_root')


def refresh(site, previous):
    retain(site, previous)
    try:
        records, notices, cookies = discover(site, previous)
        site.update(cms_installations=records, cms_discovery_notices=notices, cms_cookies=cookies)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        # retain() already removed excluded metadata. Do not restore it on an
        # unsuccessful explicit refresh or retry dead credentials every minute.
        site['cms_discovery_notices'] = ['CMS discovery unavailable. Last known non-excluded routes remain active. Refresh after checking the native document root and hosting account.']
    site['cms_discovery_root'] = str(Path(site['path']))
