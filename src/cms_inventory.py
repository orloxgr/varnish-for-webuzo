"""Native Webuzo document roots and unprivileged read-only route metadata."""
import json
from pathlib import Path
import pwd
import subprocess
import sys
from urllib.parse import unquote

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'shared'))
import cms_discovery
import cms_metadata
import cms_sessions


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
    records = cms_discovery.discover(site['path'])
    notices = []
    sessions = []
    for index, record in enumerate(records):
        if record['cms'] not in ('wordpress','joomla','prestashop'):continue
        root = Path(site['path']) / unquote(record['base']).lstrip('/')
        if record['cms']=='joomla':
            try:sessions.append(dict(cms='joomla',base=record['base'],cookie_name=cms_sessions.joomla_settings(root),supported=True))
            except (OSError,ValueError):
                sessions.append(dict(cms='joomla',base=record['base'],supported=False))
                notices.append('joomla at '+record['base']+': Session configuration requires resolver support before its opaque session can share anonymous HTML.')
        try:
            connection = cms_metadata.connection(record['cms'], root)
            records[index] = cms_metadata.aliases(record, lambda statement:query(connection,site,statement), connection['prefix'], site['names'])
        except (OSError, ValueError, KeyError, TypeError):
            retained=next((old for old in (previous or {}).get('cms_installations',[])
                           if old['cms']==record['cms'] and old['base']==record['base']),None)
            if retained and (previous or {}).get('path')==site['path']:
                records[index]=retained
                notices.append(record['cms']+' at '+record['base']+': Configured route metadata unavailable; last discovered routes remain active.')
            else:notices.append(record['cms']+' at '+record['base']+': Configured route metadata unavailable; standard CMS routes remain active.')
    return records, notices, sessions
