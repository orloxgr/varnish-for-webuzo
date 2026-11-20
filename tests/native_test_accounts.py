"""Process-local product identities for isolated Linux/root filesystem tests.

No passwd/group entries or services are created. Only the two product lookups
are substituted; filesystem ownership, modes, secure opens and IPC checks stay
real. Hosting-user lookups (including nobody) retain the host's actual records.
"""
import grp
import pwd
from unittest.mock import patch


def install(test):
    passwd_lookup, group_lookup = pwd.getpwnam, grp.getgrnam
    used_uids = {entry.pw_uid for entry in pwd.getpwall()}
    used_gids = {entry.gr_gid for entry in grp.getgrall()}
    panel_uid = next(value for value in range(60000, 65000) if value not in used_uids)
    panel_gid = next(value for value in range(60000, 65000) if value not in used_gids)
    daemon_gid = next(value for value in range(panel_gid + 1, 65000) if value not in used_gids)
    panel = pwd.struct_passwd(('webuzo', 'x', panel_uid, panel_gid,
                               'Isolated test panel', '/nonexistent', '/usr/sbin/nologin'))
    daemon = grp.struct_group(('webuzo-varnish', 'x', daemon_gid, []))
    test.enterContext(patch.object(pwd, 'getpwnam', side_effect=lambda name:
        panel if name == 'webuzo' else passwd_lookup(name)))
    test.enterContext(patch.object(grp, 'getgrnam', side_effect=lambda name:
        daemon if name == 'webuzo-varnish' else group_lookup(name)))
    return panel, daemon
