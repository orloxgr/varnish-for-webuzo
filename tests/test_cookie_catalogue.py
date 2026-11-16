"""Reviewed policy roles and literal matching, independent of recognition labels."""
import copy
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
import cookie_policy
from cookie_catalogue import cookie_pattern, load_catalogue, render_policy, validate


def matches(catalogue, consumer, cookies):
    # Python lacks POSIX character classes; the native PCRE tests cover those.
    return bool(re.search(cookie_pattern(catalogue, consumer).replace('[:blank:]', ' \\t'), cookies))


class CookieCatalogue(unittest.TestCase):
    def setUp(self):
        self.catalogue = load_catalogue(ROOT/'shared/cookie-policies.json')

    def test_literals_case_and_cookie_boundaries(self):
        for cookie in ('wordpress_logged_in_a=secret', 'tracking=one;\tPHPSESSID=two', 'wp-postpass_x=private'):
            self.assertTrue(matches(self.catalogue, 'varnishPrivate', cookie))
        for cookie in ('myprefixPHPSESSID=one', 'phpsessid=two', 'custom=PHPSESSID=three', 'PHPSESSID_extra=four'):
            self.assertFalse(matches(self.catalogue, 'varnishPrivate', cookie))
        changed = copy.deepcopy(self.catalogue)
        changed['policies'][0]['match']['value'] = 'plugin.cookie+id'
        self.assertTrue(matches(changed, 'varnishTrackingIgnore', 'plugin.cookie+id=a'))
        self.assertFalse(matches(changed, 'varnishTrackingIgnore', 'pluginXcookieid=a'))

    def test_roles_keep_cart_separate_from_private_and_tracking(self):
        for consumer, cookie in [('varnishCart','wp_woocommerce_session_shop=cart'),
                                 ('varnishTrackingIgnore','_ga_property=visitor')]:
            self.assertTrue(matches(self.catalogue, consumer, cookie))
            self.assertFalse(matches(self.catalogue, 'varnishPrivate', cookie))
        for cookie in ('consent=yes', 'currency=EUR', 'custom_session=value'):
            for consumer in ('varnishPrivate', 'varnishCart', 'varnishTrackingIgnore'):
                self.assertFalse(matches(self.catalogue, consumer, cookie))

    def test_delivery_support_does_not_become_a_request_blocker(self):
        entry = self.catalogue['policies'][0]
        self.assertEqual(entry['id'], 'fbp')
        entry['delivery']['supported'] = False
        self.assertTrue(matches(self.catalogue, 'varnishTrackingIgnore', '_fbp=existing'))
        entry['delivery']['supported'] = True
        self.assertTrue(matches(self.catalogue, 'varnishTrackingIgnore', '_fbp=existing'))

    def test_generation_consumes_local_reviewed_catalogue_only(self):
        source = (ROOT/'shared/cache-policy.vcl').read_text(encoding='utf-8')
        result = render_policy(source, self.catalogue)
        self.assertNotIn('@@COOKIE_PATTERN_', result)
        self.assertEqual(result, cookie_policy.shared_policy())
        self.catalogue['policies'][0]['match']['value'] = '_reviewed_fixture'
        result = render_policy(source, self.catalogue)
        self.assertIn('_reviewed_fixture', result)
        self.assertNotIn('|_fbp|', result)

    def test_native_attributes_are_generated_from_the_reviewed_provider_policy(self):
        source = (ROOT/'shared/cache-policy.vcl').read_text(encoding='utf-8')
        attributes = self.catalogue['policies'][0]['attributes']
        attributes.update(maxAgeSeconds=3600,path='/shop',sameSite='Strict',httpOnly=True,secure=True)
        result = render_policy(source,self.catalogue)
        self.assertIn('; Max-Age=3600; Path=/shop; SameSite=Strict; HttpOnly',result)
        self.assertNotIn('@@FBP_',result)
        attributes['path'] = '/; other=cookie'
        with self.assertRaises(ValueError):
            render_policy(source,self.catalogue)

    def test_provider_hold_uses_reviewed_exact_cookie_condition_and_name_only_diagnostics(self):
        source = (ROOT/'shared/cache-policy.vcl').read_text(encoding='utf-8')
        transport = self.catalogue['policies'][0]['delivery'].setdefault('transports',{}).setdefault('proxy-fbp',{})
        transport['holdWhen'] = [{'cookie':'provider_state','value':'held'}]
        result = render_policy(source,self.catalogue)
        self.assertIn('provider_state=held(;|$)',result)
        self.assertIn('X-SCP-Cookie-Name = "provider_state"',result)
        self.assertIn('X-Cache-Cookie-Delivery = "fbp:provider-held"',result)
        transport['holdWhen'][0]['value'] = 'held; other=1'
        with self.assertRaises(ValueError):
            render_policy(source,self.catalogue)

    def test_malformed_or_contradictory_catalogue_is_not_generated(self):
        changes = [lambda c: c.update(schemaVersion=2),
                   lambda c: c.update(unknownCookies='pass'),
                   lambda c: c['policies'].append(copy.deepcopy(c['policies'][0])),
                   lambda c: c['policies'][0]['match'].update(value='x"}; return(pass); #'),
                   lambda c: c['policies'][0].update(htmlEffect='private'),
                   lambda c: c['policies'][0]['consumers'].update(varnishTrackingIgnore='true'),
                   lambda c: c['policies'][0]['consumers'].update(varnishPrivate=True)]
        for change in changes:
            candidate = copy.deepcopy(self.catalogue)
            change(candidate)
            with self.assertRaises(ValueError):
                validate(candidate)


if __name__ == '__main__':
    unittest.main()
