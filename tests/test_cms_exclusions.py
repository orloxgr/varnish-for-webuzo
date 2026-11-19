"""Explicit discovery exclusions and native background reconciliation scope."""
import contextlib
import copy
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path[:0] = [str(Path(__file__).resolve().parents[1] / 'src'), str(Path(__file__).resolve().parents[1] / 'shared')]
import cms_discovery
import cms_inventory
import engine


def fixture(root='/fixture/site'):
    return dict(id='a'*32, domain='example.test', names=['example.test'], path=root, error='',
                enabled=True, token='b'*64, profile='basic', bypass=[], recv_vcl='', backend_vcl='',
                cms_installations=[], cms_cookies=[])


class ExclusionSettings(unittest.TestCase):
    def test_literal_paths_are_canonical_and_boundaries_are_exact(self):
        roots = cms_discovery.exclusions(['/old//site/', '/old/site', '/παλιό'])
        self.assertEqual(roots, ['/%CF%80%CE%B1%CE%BB%CE%B9%CF%8C', '/old/site'])
        self.assertTrue(cms_discovery.excluded('/old/site/child', roots))
        self.assertFalse(cms_discovery.excluded('/old/site2', roots))
        for value in (False, 'relative', ['relative'], ['/../outside'], ['/x/%2e%2e/y'], ['/bad?query'], ['/bad\\path']):
            with self.subTest(value=value), self.assertRaises(ValueError):
                cms_discovery.exclusions(value)

    def test_failed_refresh_cannot_restore_excluded_metadata(self):
        keep = dict(cms='wordpress', base='/', private_paths=['/checkout'])
        retired = dict(cms='joomla', base='/old/site', private_paths=['/old/site/login'])
        previous = dict(fixture(), cms_installations=[keep, retired], cms_cookies=[dict(cms='joomla', base='/old/site')])
        site = dict(previous, cms_excluded_directories=['/old'])
        with patch.object(cms_inventory, 'discover', side_effect=OSError):
            cms_inventory.refresh(site, previous)
        self.assertEqual(site['cms_installations'], [keep])
        self.assertEqual(site['cms_cookies'], [])
        self.assertEqual(site['cms_discovery_root'], '/fixture/site')


class Reconciliation(unittest.TestCase):
    def setUp(self):
        self.previous = fixture()
        self.current = fixture('/fixture/site/')
        self.config = dict(installed=True, sites={self.previous['id']: self.previous})
        self.enterContext(patch.object(engine.native, 'collect', side_effect=lambda: {self.current['id']: copy.deepcopy(self.current)}))
        self.enterContext(patch.object(engine.state, 'locked', side_effect=contextlib.nullcontext))
        self.enterContext(patch.object(engine, 'recover'))
        self.enterContext(patch.object(engine, 'settings', side_effect=lambda: copy.deepcopy(self.config)))
        self.enterContext(patch.object(engine, 'status', return_value={}))
        self.enterContext(patch.object(engine.repository, 'reconcile_owned'))
        self.enterContext(patch.object(engine.repository, 'ensure_cookie_modules'))
        self.enterContext(patch.object(engine.repository, 'ensure_cookie_handoff'))
        self.enterContext(patch.object(engine.service, 'configure_esi'))
        self.enterContext(patch.object(engine.connections, 'prepare'))
        self.enterContext(patch.object(engine.credentials, 'change'))
        def save(before, after): self.config = copy.deepcopy(after)
        self.saved = self.enterContext(patch.object(engine, 'apply', side_effect=save))

    def action(self, action='reconcile', **values):
        return engine.action(dict(actor='root', admin=True, action=action, **values))

    def test_three_native_reconciles_do_not_refresh_unchanged_normalized_roots(self):
        self.current['path'] = '/fixture//site/./'
        with patch.object(cms_inventory, 'discover') as discover:
            for _ in range(3): self.action()
        discover.assert_not_called()

    def test_changed_root_is_attempted_once_even_when_discovery_fails(self):
        self.current['path'] = '/fixture/new-site/'
        with patch.object(cms_inventory, 'discover', side_effect=OSError) as discover:
            for _ in range(3): self.action()
        self.assertEqual(discover.call_count, 1)
        self.assertEqual(self.config['sites'][self.current['id']]['cms_discovery_root'], '/fixture/new-site')

    def test_explicit_refresh_retries_the_selected_attempted_root(self):
        with patch.object(cms_inventory, 'discover', return_value=([], [], [])) as discover:
            self.action(refresh_cms=True)
        discover.assert_called_once()

    def test_new_native_site_is_discovered_once(self):
        self.config['sites'] = {}
        with patch.object(cms_inventory, 'discover', return_value=([], [], [])) as discover:
            for _ in range(3): self.action()
        discover.assert_called_once()

    def test_configure_applies_exclusions_before_its_only_discovery_and_preserves_them(self):
        seen = []
        other = dict(fixture(), id='c'*32, domain='other.test', names=['other.test'])
        self.config['sites'][other['id']] = other
        self.enterContext(patch.object(engine.native, 'collect', return_value={self.current['id']: self.current, other['id']: copy.deepcopy(other)}))
        def discover(site, previous):
            seen.append((site['id'], copy.deepcopy(site['cms_excluded_directories'])))
            return [], [], []
        with patch.object(cms_inventory, 'discover', side_effect=discover):
            self.action('configure', id=self.current['id'], enabled=True, cms_excluded_directories=['/retired/site/'])
            self.action('configure', id=self.current['id'], enabled=True)
        self.assertEqual(seen, [(self.current['id'], ['/retired/site'])]*2)
        self.assertEqual(self.config['sites'][other['id']].get('cms_excluded_directories'), [])

    def test_invalid_exclusions_do_not_scan_or_save(self):
        with patch.object(cms_inventory, 'discover') as discover, self.assertRaises(ValueError):
            self.action('configure', id=self.current['id'], enabled=True, cms_excluded_directories=['/../outside'])
        discover.assert_not_called()
        self.saved.assert_not_called()


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux no-follow reader')
class DiscoveryExclusions(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.write('wp-settings.php', '<?php')
        self.write('wp-includes/version.php', '<?php')
        self.write('wp-config.php', "<?php define('DB_HOST','localhost');define('DB_USER','active');define('DB_PASSWORD','fixture');define('DB_NAME','active');$table_prefix='wp_';")
        for base in ('old/site', 'old/site/child', 'old/site2', 'παλιό'):
            self.write(base+'/configuration.php', "<?php class JConfig{public $host='localhost';public $user='retired';public $password='fixture';public $db='retired';public $dbprefix='j_';}")
            self.write(base+'/libraries/src/Version.php', '<?php')

    def write(self, relative, content):
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)

    def test_excluded_subtrees_are_not_read_and_same_prefix_sibling_is_retained(self):
        read = cms_discovery.read_literal
        def guarded(root, name):
            self.assertFalse(Path(root).is_relative_to(self.root/'old/site'))
            self.assertFalse(Path(root).is_relative_to(self.root/'παλιό'))
            return read(root, name)
        with patch.object(cms_discovery, 'read_literal', side_effect=guarded):
            records = cms_discovery.discover(str(self.root), ['/old/site/', '/παλιό'])
        self.assertEqual({(r['cms'], r['base']) for r in records}, {('wordpress', '/'), ('joomla', '/old/site2')})

    def test_root_exclusion_prevents_every_marker_read(self):
        with patch.object(cms_discovery, 'read_literal', side_effect=AssertionError('Excluded read')):
            self.assertEqual(cms_discovery.discover(str(self.root), ['/']), [])

    def test_active_wordpress_queries_continue_without_reading_retired_joomla_credentials(self):
        site = dict(fixture(str(self.root)), cms_excluded_directories=['/old', '/παλιό'])
        databases = []
        def query(connection, site, statement):
            databases.append(connection['database'])
            self.assertTrue(statement.startswith('SELECT '))
            return [dict(name='home', value='https://example.test')]
        with patch.object(cms_inventory, 'query', side_effect=query):
            records, notices, cookies = cms_inventory.discover(site)
        self.assertEqual(databases, ['active'])
        self.assertEqual([(r['cms'], r['base']) for r in records], [('wordpress', '/')])
        self.assertEqual(notices, [])
        self.assertEqual(cookies, [])

    def test_excluded_prestashop_admin_child_is_not_read(self):
        self.write('store/config/settings.inc.php', '<?php')
        self.write('store/classes/Dispatcher.php', '<?php')
        self.write('store/admin-private/index.php', "<?php define('_PS_ADMIN_DIR_', __DIR__);")
        read = cms_discovery.read_literal
        def guarded(root, name):
            self.assertFalse(str(name).startswith('admin-private/'))
            return read(root, name)
        with patch.object(cms_discovery, 'read_literal', side_effect=guarded):
            rows = cms_discovery.discover(str(self.root), ['/old', '/παλιό', '/store/admin-private'])
        self.assertEqual(next(row for row in rows if row['cms']=='prestashop')['private_paths'], [])


if __name__ == '__main__': unittest.main()
