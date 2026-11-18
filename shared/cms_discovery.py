"""Read CMS markers and literal configuration under panel-owned document roots.

No application bootstrap, shell command or executable configuration is evaluated.
Database-derived routes are supplied by the panel adapter as private_paths.
"""
import os
from pathlib import Path
import re
import stat
from urllib.parse import quote

from cms_routes import normalize

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
    fd = os.open(root.anchor, os.O_RDONLY | os.O_DIRECTORY)
    parts = [*root.parts[1:], *relative.parts]
    try:
        for index, part in enumerate(parts):
            last = index == len(parts) - 1
            next_fd = os.open(part, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                              (0 if last else os.O_DIRECTORY), dir_fd=fd)
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
    # A literal entry only, never include/eval the PHP return value.
    match = re.search(r"['\"]backend['\"]\s*=>\s*\[\s*['\"]frontName['\"]\s*=>\s*(['\"])([A-Za-z0-9_-]+)\1", text)
    return match[2] if match else None


def discover(document_root):
    root = Path(document_root)
    if not root.is_absolute() or '..' in root.parts or root.is_symlink() or not root.is_dir():
        return []
    found = []
    for folder, directories, _ in os.walk(root, followlinks=False):
        folder = Path(folder)
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
            relative = folder.relative_to(root).as_posix()
            base = '/' if relative == '.' else '/' + quote(relative, safe='/-._~')
            private = []
            admin = _magento_admin(folder) if cms == 'magento' else None
            if admin:
                private.append(base.rstrip('/') + '/' + admin)
            found.append(dict(cms=cms, base=base, private_paths=private))
    return normalize(found)
