"""Native inventory ownership and per-host cookie-delivery configuration."""
import copy
import shutil
import unittest
from unittest.mock import patch

import test_profiles as http
import cookie_policy
import engine


def account(identity='a', domain='example.test', owner='account-a', names=None):
    return dict(http.site(identity, domain), owner=owner, names=names or [domain])


class CookieSettings(unittest.TestCase):
    def test_inventory_defaults_are_disabled_and_saved_settings_are_preserved(self):
        first = account()
        second = account('c', 'other.test', 'account-b')
        saved = {'fbp': {'enabled': True, 'consent_cookie': 'marketing_ok',
                         'consent_value': 'yes', 'domain': 'example.test'}}
        config = {'sites': {first['id']: {'cookie_delivery': saved}}}
        before = copy.deepcopy(config)
        with patch.object(engine.native, 'collect', return_value={s['id']: s for s in (first, second)}):
            found = engine.inventory(config)
        self.assertEqual(config, before)
        self.assertEqual(found[first['id']]['cookie_delivery'], saved)
        self.assertFalse(found[second['id']]['cookie_delivery']['fbp']['enabled'])

    def test_parent_cookie_domain_requires_native_account_ownership(self):
        child = account(domain='shop.example.test')
        parent = account('c', 'example.test', 'account-b')
        sites = {s['id']: s for s in (child, parent)}
        choice = {'fbp': {'enabled': True, 'domain': '.example.test'}}
        with self.assertRaises(ValueError):
            cookie_policy.delivery_settings(choice, child, sites)
        parent['owner'] = child['owner']
        self.assertEqual(cookie_policy.delivery_settings(choice, child, sites)['fbp']['domain'], 'example.test')

    def test_domain_index_uses_each_alias_without_issuing_for_unrelated_aliases(self):
        target = account(names=['example.test', 'www.example.test', 'other-alias.test'])
        sites = {target['id']: target}
        target['cookie_delivery'] = {'fbp': {'enabled': True}}
        source = cookie_policy.delivery_configuration(target, sites)
        self.assertIn('if (req.http.host == "www.example.test")', source)
        self.assertIn('set req.http.X-SCP-Fbp-Index = "2";', source)
        self.assertIn('if (req.http.host == "other-alias.test")', source)
        target['cookie_delivery']['fbp']['domain'] = 'example.test'
        source = cookie_policy.delivery_configuration(target, sites)
        self.assertNotIn('other-alias.test', source)
        self.assertIn('set req.http.X-SCP-Fbp-Index = "1";', source)

    def test_disabled_settings_add_no_cookie_issuance_configuration(self):
        target = account()
        self.assertEqual(cookie_policy.delivery_configuration(target, {target['id']: target}), '')


@unittest.skipUnless(shutil.which('varnishtest'), 'Native varnishtest required')
class NativeCookieSettings(unittest.TestCase):
    run_policy = http.NativeProfiles.run_policy
    def test_configured_consent_headers_compile_with_real_native_varnish(self):
        import test_profiles
        original = test_profiles.site

        def configured(*args, **kwargs):
            row = original(*args, **kwargs)
            row['cookie_delivery'] = {'fbp': {'enabled': True, 'consent_cookie': 'site.marketing+ok',
                                            'consent_value': 'yes', 'domain': ''}}
            return row

        with patch.object(test_profiles, 'site', side_effect=configured):
            self.run_policy('basic', [http.origin('/page', 'public')],
                            [http.get('/page', 'public', cache='MISS'), http.get('/page', 'public', cache='HIT')])


if __name__ == '__main__':
    unittest.main()
