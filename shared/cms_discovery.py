"""Read CMS markers and literal configuration under panel-owned document roots.

No application bootstrap, shell command or executable configuration is evaluated.
Database-derived routes are supplied by the panel adapter as private_paths.
"""
import os
from pathlib import Path
import re
import stat
from urllib.parse import quote

from cms_routes import normalize, path


def exclusions(value):
    """Literal URL-relative directory roots, never regexes or filesystem escapes."""
    if not isinstance(value, list):
        raise ValueError('Excluded CMS directories must be a list')
    return sorted(set('/' + '/'.join(part for part in path(item).split('/') if part) for item in value))


def excluded(base, roots):
    return any(root == '/' or base == root or base.startswith(root + '/') for root in roots)


SKIP = frozenset(('.git', '.svn', 'node_modules', 'vendor', 'cache', 'tmp', 'logs',
                  'wp-content', 'wp-includes', 'wp-admin', 'administrator', 'libraries',
                  'components', 'modules', 'plugins', 'templates', 'media', 'images',
                  'sites', 'core', 'app', 'var', 'pub', 'generated', 'classes', 'controllers'))


def read_literal(root, relative):
    """No symlink traversal, including ancestors; return a regular file only."""
    root = Path(root)
    relative = Path(relative)
    if not root.is_absolute() or '..' in root.parts or relative.is_absolute() or '..' in relative.parts:
        raise ValueError('Invalid CMS discovery path')
    # A known path needs search permission on its parents, not permission to
    # list them. Hosting panels commonly use 0711 on /home. O_PATH keeps each
    # ancestor pinned without following links or requiring directory reads.
    parent_flags = os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(root.anchor, parent_flags)
    parts = [*root.parts[1:], *relative.parts]
    try:
        for index, part in enumerate(parts):
            last = index == len(parts) - 1
            next_fd = os.open(part, (os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                              if last else parent_flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError('CMS configuration must be a regular file')
        with os.fdopen(fd, 'r', encoding='utf-8', errors='replace') as stream:
            fd = None
            return stream.read()
    finally:
        if fd is not None:
            os.close(fd)


def _exists(root, name):
    try:
        read_literal(root, name)
        return True
    except (OSError, ValueError):
        return False


def _magento_admin(root):
    try:
        text = read_literal(root, 'app/etc/env.php')
    except (OSError, ValueError):
        return None
    # The literal reader ignores PHP comments and conflicting values.
    from cms_metadata import settings
    value=settings(text)[2].get('frontName')
    return value if isinstance(value,str) and re.fullmatch('[A-Za-z0-9_-]+',value) else None


def _prestashop_admin(root, directories):
    # PrestaShop intentionally renames admin-dev on installation. Identify its
    # real entrypoint, never guess by prefix or execute the tenant PHP file.
    from cms_metadata import TOKEN
    found=[]
    for name in directories:
        try:text=read_literal(root,name+'/index.php')
        except (OSError,ValueError):continue
        tokens=[t for t in TOKEN.findall(text) if not t.startswith(('//','/*','#'))]
        if any(tokens[i:i+4]==['define','(',"'_PS_ADMIN_DIR_'",','] or tokens[i:i+4]==['define','(','"_PS_ADMIN_DIR_"',','] for i in range(len(tokens))):
            found.append(name)
    return found


def discover(document_root, excluded_directories=None):
    excluded_roots = exclusions([] if excluded_directories is None else excluded_directories)
    root = Path(document_root)
    if not root.is_absolute() or '..' in root.parts or root.is_symlink() or not root.is_dir():
        return []
    if excluded('/', excluded_roots):
        return []
    found = []
    # Magento's recommended public root is pub/, beside its app/etc metadata.
    if root.name=='pub' and _exists(root,'index.php') and _exists(root.parent,'app/etc/env.php') and _exists(root.parent,'bin/magento'):
        admin=_magento_admin(root.parent)
        found.append(dict(cms='magento',base='/',private_paths=['/'+admin] if admin else []))
    for folder, directories, _ in os.walk(root, followlinks=False):
        folder = Path(folder)
        relative = folder.relative_to(root).as_posix()
        base = '/' if relative == '.' else '/' + quote(relative, safe='/-._~')
        directories[:] = [name for name in directories if not excluded(
            base.rstrip('/') + '/' + quote(name, safe='-._~'), excluded_roots)]
        children=list(directories)
        directories[:] = sorted(name for name in directories if name not in SKIP and
                                not name.startswith('.') and not (folder / name).is_symlink())
        cms = None
        if _exists(folder, 'wp-settings.php') and _exists(folder, 'wp-includes/version.php'):
            cms = 'wordpress'
        elif _exists(folder, 'configuration.php') and (_exists(folder, 'libraries/src/Version.php') or _exists(folder, 'libraries/cms/version/version.php')):
            cms = 'joomla'
        elif _exists(folder, 'core/lib/Drupal.php') and _exists(folder, 'sites/default/default.settings.php'):
            cms = 'drupal'
        elif _exists(folder, 'includes/bootstrap.inc') and _exists(folder, 'modules/system/system.module'):
            cms = 'drupal'
        elif _exists(folder, 'app/etc/env.php') and _exists(folder, 'bin/magento'):
            cms = 'magento'
        elif (_exists(folder, 'config/settings.inc.php') or _exists(folder, 'app/config/parameters.php')) and _exists(folder, 'classes/Dispatcher.php'):
            cms = 'prestashop'
        if cms:
            private = []
            admin = _magento_admin(folder) if cms == 'magento' else None
            if admin:
                private.append(base.rstrip('/') + '/' + admin)
            if cms=='prestashop':
                private.extend(base.rstrip('/')+'/'+quote(name,safe='-._~') for name in _prestashop_admin(folder,children))
            found.append(dict(cms=cms, base=base, private_paths=private))
    return normalize(found)
