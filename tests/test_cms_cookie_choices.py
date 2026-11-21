"""Selected cookie actions govern CMS cookies; private routes remain separate."""
import os
import hashlib
import json
from pathlib import Path
import shutil
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'shared'))
import cookie_admin
import cookie_control
import cookie_defaults
from cookie_catalogue import load_catalogue
from test_cookie_delivery import proxy


def selected_rules(shared, variant):
    return {'schemaVersion': 2, 'rules': [
        dict(id='custom:cms-shared', match=shared, description='Selected shared CMS cookie',
             actions=dict(basic='shared', ultracache='shared')),
        dict(id='custom:cms-variant', match=variant, description='Selected CMS variant',
             actions=dict(basic='variant', ultracache='variant'))]}


def owned_module(source):
    module = os.environ.get('SCP_TEST_COOKIE_MODULE')
    if module:
        source = source.replace('import cookie_handoff;', 'import cookie_handoff from "'+module+'";')
    return source


def cache(fields):
    values = {key.lower(): value for key, value in fields}
    return values.get('x-hestia-varnish', values.get('x-webuzo-varnish'))


class CMSCookieDefaults(unittest.TestCase):
    def test_only_the_visible_cms_defaults_change_each_existing_profile_identity(self):
        prior = json.loads((Path(__file__).parent/'fixtures/cookie-defaults-2026.11.20.11.json').read_text())
        added = {'SSESS', 'SESS', 'PrestaShop-', 'joomla_user_state', 'joomla_remember_me_'}
        remaining = [row for row in cookie_defaults.defaults()['rules'] if row['match']['value'] not in added]
        for profile in ('basic', 'ultracache'):
            projection = sorted((row['match']['kind'], row['match']['value'], row['actions'][profile]) for row in remaining)
            digest = hashlib.sha256(json.dumps(projection, ensure_ascii=True, separators=(',', ':')).encode()).hexdigest()
            self.assertEqual(digest, prior['saved']['cookie_defaults_profile_digests'][profile])
            self.assertNotEqual(digest, cookie_defaults.fingerprint(profile))

    def test_visible_defaults_and_signed_materialization_use_the_same_private_actions(self):
        matches = [('prefix', name) for name in ('SSESS', 'SESS', 'PrestaShop-', 'joomla_remember_me_')]
        matches.append(('exact', 'joomla_user_state'))
        catalogue = load_catalogue()
        for profile in ('basic', 'ultracache'):
            snapshot = cookie_control.materialized_snapshot(profile=profile)
            for kind, name in matches:
                match = dict(kind=kind, value=name)
                rows = [rule for rule in catalogue['policies'] if rule['match'] == match]
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]['actions'], dict(basic='private', ultracache='private'))
                self.assertTrue(rows[0]['sources'])
                materialized = [rule for rule in snapshot['central']['rules'] if rule['match'] == match]
                self.assertEqual(len(materialized), 1)
                self.assertEqual(materialized[0]['action'], 'private')

    def test_independent_override_and_reset_are_not_another_cms_classifier(self):
        match = dict(kind='prefix', value='SSESS')
        choice = selected_rules(match, dict(kind='exact', value='shop_currency'))
        choice['rules'][0]['actions'] = dict(basic='shared', ultracache='variant')
        for profile, expected in (('basic', 'shared'), ('ultracache', 'variant')):
            active = cookie_admin.active(site=choice, profile=profile)
            row = next(row for row in active if row['match'] == match)
            self.assertEqual(row['action'], expected)
            choice['rules'][0]['actions'][profile] = None
            reset = cookie_admin.active(site=choice, profile=profile)
            self.assertEqual(next(row for row in reset if row['match'] == match)['action'], 'private')
            choice['rules'][0]['actions'][profile] = expected


@unittest.skipUnless(shutil.which('varnishd'), 'Native varnishd required')
class CMSCookieChoices(unittest.TestCase):
    def test_visible_private_defaults_exclude_sessions_without_an_early_cms_veto(self):
        names = ['SSESSabcdef123456', 'SESSabcdef123456', 'PrestaShop-'+'a'*32,
                 'joomla_user_state', 'joomla_remember_me_example']
        for profile in ('basic', 'ultracache'):
            def origin(path, headers):
                return 'public', [('Cache-Control', 'public, max-age=120')]
            with self.subTest(profile=profile), proxy(profile, origin, transform=owned_module) as get:
                for name in names:
                    for _ in range(2):
                        status, fields, _ = get('/article', name+'=logged_in')
                        self.assertEqual((status, cache(fields)), (200, 'PASS'))
                        self.assertEqual(dict(fields).get('X-Cache-Cookie-Action'), 'private')
                self.assertEqual(cache(get('/article')[1]), 'MISS')
                self.assertEqual(cache(get('/article')[1]), 'HIT')

    def verify(self, cms, shared_name, shared_match, variant_name, variant_match, private_path):
        for profile in ('basic', 'ultracache'):
            calls = []
            def origin(path, headers):
                calls.append((path, headers.get('Cookie')))
                return 'origin-'+str(len(calls)), [('Cache-Control', 'public, max-age=120')]
            with self.subTest(profile=profile), proxy(profile, origin, transform=owned_module,
                    policies=selected_rules(shared_match, variant_match),
                    site_settings={'cms_installations': [dict(cms=cms, base='/') ]}) as get:
                # A saved Shared choice must omit the cookie value from selection.
                for value, expected, body in [('logged_in', 'MISS', 'origin-1'), ('other', 'HIT', 'origin-1')]:
                    status, fields, content = get('/article/shared', shared_name+'='+value)
                    self.assertEqual((status, cache(fields), content), (200, expected, body))
                self.assertEqual(calls, [('/article/shared', shared_name+'=logged_in')])
                # A saved Public variant creates independently reusable objects.
                for value, expected, body in [('first', 'MISS', 'origin-2'), ('second', 'MISS', 'origin-3'),
                                             ('first', 'HIT', 'origin-2')]:
                    status, fields, content = get('/article/variant', variant_name+'='+value)
                    self.assertEqual((status, cache(fields), content), (200, expected, body))
                self.assertEqual(calls[1:], [('/article/variant', variant_name+'=first'),
                                            ('/article/variant', variant_name+'=second')])
                # URL/action privacy is independent of the selected cookie action.
                for _ in range(2):
                    status, fields, _ = get(private_path, shared_name+'=logged_in')
                    self.assertEqual((status, cache(fields)), (200, 'PASS'))
                # A more specific, ordinary Private override still excludes HTML.
            private = selected_rules(shared_match, variant_match)
            private['rules'][0]['actions'] = dict(basic='private', ultracache='private')
            with self.subTest(profile=profile, action='private'), proxy(profile, origin, transform=owned_module,
                    policies=private, site_settings={'cms_installations': [dict(cms=cms, base='/')]}) as get:
                for _ in range(2):
                    status, fields, _ = get('/article/private', shared_name+'=logged_in')
                    self.assertEqual((status, cache(fields)), (200, 'PASS'))
                    self.assertEqual(dict(fields).get('X-Cache-Cookie-Action'), 'private')

    def test_drupal_selected_cookie_actions_and_private_route(self):
        self.verify('drupal', 'SSESSabcdef123456', dict(kind='prefix', value='SSESS'),
                    'SESSabcdef123456', dict(kind='prefix', value='SESS'), '/user/login')

    def test_joomla_selected_cookie_actions_and_private_route(self):
        self.verify('joomla', 'joomla_user_state', dict(kind='exact', value='joomla_user_state'),
                    'joomla_remember_me_example', dict(kind='prefix', value='joomla_remember_me_'), '/administrator/')

    def test_prestashop_selected_cookie_actions_and_private_route(self):
        self.verify('prestashop', 'PrestaShop-'+'a'*32, dict(kind='prefix', value='PrestaShop-'),
                    'shop_currency', dict(kind='exact', value='shop_currency'), '/my-account')


if __name__ == '__main__':
    unittest.main()
