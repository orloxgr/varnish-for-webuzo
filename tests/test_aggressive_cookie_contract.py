"""Aggressive HTTP policy must not rewrite selected cookie actions."""
import shutil
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'shared'))
import aggressive
import cookie_control

from test_cookie_delivery import proxy
from test_cms_cookie_choices import cache

OPAQUE = 'a'*32
SITE = dict(aggressive=True, cms_installations=[dict(cms='joomla', base='/')],
            cms_cookies=[dict(cms='joomla', cookie_name=OPAQUE, supported=True)])


class AggressiveCookieSettings(unittest.TestCase):
    def test_materialized_application_policy_has_the_same_private_session_defaults(self):
        for profile in ('basic', 'ultracache'):
            snapshot = cookie_control.materialized_snapshot(profile=profile)
            for name in ('PHPSESSID', '__Secure-PHPSESSID'):
                row = next(row for row in snapshot['central']['rules'] if row['match'] == dict(kind='exact', value=name))
                self.assertEqual(row['action'], 'private')

    def test_only_old_aggressive_replicas_require_the_cookie_revision_invalidation(self):
        revised = dict(aggressive=True, cookie_rules_revision=aggressive.COOKIE_RULE_REVISION)
        self.assertTrue(aggressive.cookie_rules_changed(dict(aggressive=True), revised))
        self.assertFalse(aggressive.cookie_rules_changed(revised, dict(revised)))
        self.assertFalse(aggressive.cookie_rules_changed({}, dict(cookie_rules_revision=aggressive.COOKIE_RULE_REVISION)))


@unittest.skipUnless(shutil.which('varnishd'), 'Native Varnish required')
class AggressiveCookieContract(unittest.TestCase):
    def test_aggressive_keeps_bundled_private_sessions(self):
        def origin(path, headers):
            return 'origin', [('Cache-Control', 'public, max-age=120'), ('Vary', 'Cookie')]
        for profile in ('basic', 'ultracache'):
            with self.subTest(profile=profile), proxy(profile, origin, site_settings=SITE) as get:
                for name in ('PHPSESSID', '__Secure-PHPSESSID'):
                    for value in ('first', 'second'):
                        status, fields, _ = get('/private-default', name+'='+value)
                        self.assertEqual((status, cache(fields), dict(fields).get('X-Cache-Cookie-Action')),
                                         (200, 'PASS', 'private'))

    def test_unselected_opaque_cms_session_keeps_normal_functional_vary(self):
        def origin(path, headers):
            return headers.get('Cookie', 'none'), [('Cache-Control', 'public, max-age=120'), ('Vary', 'Cookie')]
        for profile in ('basic', 'ultracache'):
            with self.subTest(profile=profile), proxy(profile, origin, site_settings=SITE) as get:
                for value, wanted in (('first', 'MISS'), ('second', 'MISS'), ('first', 'HIT')):
                    status, fields, body = get('/opaque', OPAQUE+'='+value)
                    self.assertEqual((status, cache(fields), body), (200, wanted, OPAQUE+'='+value))

    def test_saved_shared_variant_and_private_remain_the_only_decisions(self):
        choices = {'schemaVersion': 2, 'rules': [
            dict(id='custom:'+name, match=dict(kind='exact', value=name), description='',
                 actions=dict(basic=basic, ultracache=ultracache))
            for name, basic, ultracache in [('PHPSESSID', 'shared', 'variant'),
                ('__Secure-PHPSESSID', 'variant', 'private'), (OPAQUE, 'private', 'shared')]]}
        def origin(path, headers):
            return 'public', [('Cache-Control', 'public, max-age=120'), ('Vary', 'Cookie')]
        for profile in ('basic', 'ultracache'):
            with self.subTest(profile=profile), proxy(profile, origin, site_settings=SITE, policies=choices) as get:
                for row in choices['rules']:
                    action = row['actions'][profile]
                    wanted = {'shared': ['MISS', 'HIT', 'HIT'], 'variant': ['MISS', 'MISS', 'HIT'],
                              'private': ['PASS', 'PASS', 'PASS']}[action]
                    for value, expected in zip(('first', 'second', 'first'), wanted):
                        status, fields, _ = get('/selected-'+row['match']['value'], row['match']['value']+'='+value)
                        self.assertEqual((status, cache(fields)), (200, expected))

    def test_http_origin_override_still_works_without_cookie_reclassification(self):
        def origin(path, headers):
            return '<html>public</html>', [('Cache-Control', 'private, no-store')]
        for profile in ('basic', 'ultracache'):
            with self.subTest(profile=profile), proxy(profile, origin, site_settings=SITE) as get:
                self.assertEqual(cache(get('/public')[1]), 'MISS')
                self.assertEqual(cache(get('/public')[1]), 'HIT')
                self.assertEqual(cache(get('/public', 'PHPSESSID=private')[1]), 'PASS')


if __name__ == '__main__':
    unittest.main()
