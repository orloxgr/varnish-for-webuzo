"""Native transport for the five reviewed defaults; no CMS-render claim."""
import copy
import shutil
import unittest

from test_cookie_delivery import proxy, cookies
from test_cms_cookie_choices import cache

SELECTORS = (('prefix', 'wp-settings-'), ('prefix', 'wp-settings-time-'),
    ('exact', 'wp_lang'), ('exact', 'cmplz_saved_categories'), ('exact', 'cmplz_saved_services'))


def cookie_values(owner):
    return '; '.join((
        'wp-settings-17=editor-'+owner,
        'wp-settings-time-17='+('101' if owner=='A' else '202'),
        'wp_lang='+('en_US' if owner=='A' else 'el'),
        'cmplz_saved_categories=categories-'+owner,
        'cmplz_saved_services=services-'+owner))


def saved(action):
    return dict(schemaVersion=2, rules=[dict(id='custom:reviewed-'+str(index),
        match=dict(kind=kind, value=name), description='Explicit fixture choice',
        actions=dict(basic=action, ultracache=action)) for index, (kind, name) in enumerate(SELECTORS)])


@unittest.skipUnless(shutil.which('varnishd'), 'Native Varnish required; skip is not acceptance')
class ReviewedDefaultsRuntime(unittest.TestCase):
    def test_shared_defaults_reuse_public_vary_object_and_keep_original_cookie_fields(self):
        for profile in ('basic', 'ultracache'):
            calls = []
            def origin(path, headers):
                raw = headers.get('Cookie'); calls.append(raw)
                return 'public document', [('Cache-Control', 'public, max-age=120'), ('Vary', 'Cookie'),
                    *[('Set-Cookie', pair+'; Path=/; SameSite=Lax') for pair in cookie_values('A').split('; ')]]
            with self.subTest(profile=profile), proxy(profile, origin) as get:
                for raw, expected in ((cookie_values('A'), 'MISS'), (cookie_values('B'), 'HIT'), (None, 'HIT')):
                    status, fields, body = get('/reviewed-public', raw)
                    self.assertEqual((status, cache(fields), body), (200, expected, 'public document'))
                    self.assertEqual(cookies(fields),
                        [pair+'; Path=/; SameSite=Lax' for pair in cookie_values('A').split('; ')] if expected=='MISS' else [])
                self.assertEqual(calls, [cookie_values('A')])

    def test_manual_site_variant_and_private_override_central_choices_in_both_profiles(self):
        for profile in ('basic', 'ultracache'):
            for action in ('variant', 'private'):
                calls = []
                def origin(path, headers):
                    raw = headers.get('Cookie'); calls.append(raw)
                    return raw, [('Cache-Control', 'public, max-age=120'), ('Vary', 'Cookie')]
                central = saved('private' if action=='variant' else 'variant'); site = saved(action)
                before = copy.deepcopy((central, site))
                with self.subTest(profile=profile, action=action), proxy(profile, origin,
                        policies=central, site_settings={'cookie_policies':site}) as get:
                    outcomes = ('MISS', 'MISS', 'HIT') if action=='variant' else ('PASS', 'PASS', 'PASS')
                    for owner, expected in zip(('A', 'B', 'A'), outcomes):
                        status, fields, body = get('/manual-choice', cookie_values(owner))
                        self.assertEqual((status, cache(fields), body), (200, expected, cookie_values(owner)))
                    self.assertEqual(len(calls), 2 if action=='variant' else 3)
                self.assertEqual((central, site), before)


if __name__ == '__main__':
    unittest.main()
