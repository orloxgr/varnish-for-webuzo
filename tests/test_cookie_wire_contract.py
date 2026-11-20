"""Offline compiler qualification; native HTTP acceptance is a separate gate."""
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'shared'))
import cookie_admin as admin
from cookie_catalogue import load_catalogue


def choices(*rows):
    return {'schemaVersion': 1, 'rules': [dict(id='custom:' + str(index),
        match=dict(kind=kind, value=name), description='', action=action)
        for index, (kind, name, action) in enumerate(rows)]}


def native_pattern(value):
    # These compiler predicates use only the shared Python/PCRE subset plus
    # POSIX blank classes. This checks generated selectors, not VCL execution.
    return re.compile(value.replace('[:blank:]', ' \\t'))


def compiled_selectors(source):
    expression = (r'if \(req.http.X-SCP-Admin-Remaining ~ \{"([^"\n]*)"\}\) \{\n'
                  r'if \([^\n]*\) \{\n'
                  r'set req.http.X-SCP-Admin-Rule = [^\n]*;\n'
                  r'set req.http.X-SCP-Admin-Scope = [^\n]*;\n'
                  r'set req.http.X-SCP-Admin-Action = "([a-z]+)";')
    return [(native_pattern(pattern), action) for pattern, action in re.findall(expression, source)]


def selected_action(selectors, name):
    return next((action for pattern, action in selectors if pattern.search(name + '=fixture')), None)


def response_action(wire, name):
    for line in wire.splitlines():
        action, kind, value = line.split('\t')
        if name == value or kind == 'prefix' and name.startswith(value):
            return action
    return None


class CookieWireContract(unittest.TestCase):
    def test_saved_choices_override_former_mandatory_roles_in_both_directions(self):
        for name in ('wordpress_logged_in_demo', 'PHPSESSID', 'wp_woocommerce_session_shop',
                     'woocommerce_items_in_cart', '_ga', '_fbp', 'esi_session', 'ultracache_esi_optin'):
            for action in ('shared', 'variant', 'private'):
                policy = choices(('exact', name, action))
                with self.subTest(name=name, action=action):
                    selectors = compiled_selectors(admin.compile_vcl(site=policy))
                    self.assertEqual(selected_action(selectors, name), action)
                    self.assertEqual(response_action(admin.response_rules(site=policy), name), action)

    def test_scopes_exact_and_nested_prefixes_have_identical_winners(self):
        central = choices(('prefix', 'vendor_', 'private'),
                          ('prefix', 'vendor_public_', 'shared'),
                          ('exact', 'vendor_public_currency', 'variant'))
        site = choices(('prefix', 'vendor_public_', 'variant'),
                       ('prefix', 'vendor_public_measure_', 'shared'),
                       ('exact', 'vendor_public_measure_private', 'private'),
                       ('exact', 'vendor_secret', 'shared'))
        expected = {'vendor_id': 'private', 'vendor_public_id': 'variant',
                    'vendor_public_currency': 'variant', 'vendor_public_measure_id': 'shared',
                    'vendor_public_measure_private': 'private', 'vendor_secret': 'shared'}
        selectors = compiled_selectors(admin.compile_vcl(central, site))
        wire = admin.response_rules(central, site)
        # Exercise the adapter's shared-default call path as well as the flat
        # compiler; chosen names have no generic aggressive-session branch.
        chained = compiled_selectors(admin.compile_vcl(central, site, chain_defaults=True))
        for name, action in expected.items():
            with self.subTest(name=name):
                self.assertEqual(selected_action(selectors, name), action)
                self.assertEqual(selected_action(chained, name), action)
                self.assertEqual(response_action(wire, name), action)

    def test_local_prefix_precedes_inherited_exact_and_case_stays_literal(self):
        central = choices(('exact', 'vendor_account', 'private'))
        site = choices(('prefix', 'vendor_', 'shared'))
        selectors = compiled_selectors(admin.compile_vcl(central, site))
        self.assertEqual(selected_action(selectors, 'vendor_account'), 'shared')
        self.assertEqual(response_action(admin.response_rules(central, site), 'vendor_account'), 'shared')
        self.assertNotEqual(selected_action(selectors, 'Vendor_account'), 'shared')

    def test_table_and_reset_no_longer_claim_a_hidden_cookie_override(self):
        catalogue = load_catalogue()
        policy = choices(('prefix', 'wordpress_logged_in_', 'shared'))
        row = next(row for row in admin.table({'records': []}, catalogue, site=policy)
                   if row['id'] == 'custom:0')
        self.assertEqual(row['effective_action'], 'shared')
        self.assertNotIn('even if a local choice', row['core_precedence'])
        self.assertNotIn('even if a local choice', row['reset_metadata']['core_precedence'])

    def test_private_carrier_preserves_history_auth_and_excludes_other_names(self):
        source = (ROOT / 'shared/vcl/ultracache-esi.vcl').read_text()
        expression = re.search(r'set req.http.X-ESI-Original-Cookie = regsuball\(req.http.Cookie,\s*\{"([^"\n]+)"\}', source)
        self.assertIsNotNone(expression)
        pattern = native_pattern(expression.group(1))
        incoming = ('_ga=tracking; wordpress_logged_in_shop=raw%7Csignature; unrelated=secret; '
                    'woocommerce_recently_viewed=10%7C20;\twp_woocommerce_session_shop=session; '
                    'woocommerce_items_in_cart=1; xwordpress_logged_in_shop=no; '
                    'WooCommerce_recently_viewed=wrong-case; wordpress_logged_in_other=other')
        selected = pattern.sub('', incoming).strip('; \t')
        selected = re.sub(r';[ \t]*', '; ', selected)
        self.assertEqual(selected, 'wordpress_logged_in_shop=raw%7Csignature; '
                         'woocommerce_recently_viewed=10%7C20; wp_woocommerce_session_shop=session; '
                         'woocommerce_items_in_cart=1; wordpress_logged_in_other=other')


if __name__ == '__main__':
    unittest.main()
