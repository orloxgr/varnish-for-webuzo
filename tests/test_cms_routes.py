"""CMS selection, URL matching and unchanged forwarding with native Varnish."""
import copy
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'shared'))
import cms_discovery
import cms_routes
import test_profiles as http


class Descriptors(unittest.TestCase):
    def test_paths_are_data_not_vcl_and_parent_traversal_is_rejected(self):
        for value in ('relative', '/../private', '/%2e%2e/x', '/x?task=login', '/x\n', '/bad%GG'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                cms_routes.normalize([dict(cms='joomla', base=value)])
        row = dict(cms='joomla', base='/cms', private_paths=['/cms/customer.area', '/cms/customer.area/'])
        before = copy.deepcopy(row)
        self.assertEqual(cms_routes.normalize([row])[0]['private_paths'], ['/cms/customer.area'])
        self.assertEqual(before, row)
        self.assertIn('customer\\.area', cms_routes.compile_recv([row]))

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Native no-follow filesystem')
    def test_discovery_finds_subfolders_and_literal_magento_admin_without_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            markers = {'blog/wp-settings.php': '', 'blog/wp-includes/version.php': '',
                       'cms/configuration.php': '<?php throw new Exception("must not execute");',
                       'cms/libraries/src/Version.php': '',
                       'shop/bin/magento': '', 'shop/app/etc/env.php': "<?php return ['backend'=>['frontName'=>'secret_admin']];"}
            for name, value in markers.items():
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(value)
            (root / 'external').symlink_to(root / 'cms', target_is_directory=True)
            rows = cms_discovery.discover(root)
            self.assertEqual({(r['cms'], r['base']) for r in rows}, {('wordpress', '/blog'), ('joomla', '/cms'), ('magento', '/shop')})
            self.assertEqual(next(r for r in rows if r['cms'] == 'magento')['private_paths'], ['/shop/secret_admin'])


@unittest.skipUnless(shutil.which('varnishtest'), 'Native Varnish required')
class NativeCMS(unittest.TestCase):
    run_policy = http.NativeProfiles.run_policy

    def run_cms(self, cms, responses, requests, *, profile='basic', base='/', private_paths=()):
        original = http.site
        def configured(*args, **kwargs):
            value = original(*args, **kwargs)
            if value['domain'] == 'example.test':
                value['cms_installations'] = [dict(cms=cms, base=base, private_paths=list(private_paths))]
            return value
        with patch.object(http, 'site', side_effect=configured):
            self.run_policy(profile, responses, requests)

    def test_public_cms_pages_hit_in_both_profiles(self):
        for cms in cms_routes.NAMES:
            for profile in ('basic', 'ultracache'):
                with self.subTest(cms=cms, profile=profile):
                    self.run_cms(cms, [http.origin('/el/article', 'public')],
                                 [http.get('/el/article', 'public', cache='MISS'), http.get('/el/article', 'public', cache='HIT')], profile=profile)

    def test_known_private_paths_queries_and_encoded_actions_pass(self):
        cases = {
            'joomla': ['/administrator/', '/el/component/users/login', '/index.php?option=com_users&view=profile', '/?task=user.logout', '/?option=com_content&task=article.edit', '/%61dministrator/', '/?option=com_users&view=reset'],
            'drupal': ['/admin/config', '/el/user/login', '/user', '/user/7/edit', '/node/2/edit', '/?q=user/password'],
            'magento': ['/customer/account', '/checkout/cart', '/sales/order/view', '/paypal/express/start', '/customer/section/load'],
            'prestashop': ['/my-account', '/el/order-confirmation', '/?controller=order', '/?controller=authentication', '/?controller=cart&add=1'],
        }
        for cms, paths in cases.items():
            for profile in ('basic', 'ultracache'):
                responses, requests = [], []
                for path in paths:
                    for visitor in ('A', 'B'):
                        responses.append(http.origin(path, visitor))
                        requests.extend([http.get(path, visitor, cache='PASS'), 'expect resp.http.X-Webuzo-Varnish-Reason == "' + cms + '-private-route"'])
                with self.subTest(cms=cms, profile=profile):
                    self.run_cms(cms, responses, requests, profile=profile)

    def test_configured_paths_base_scope_and_origin_forwarding(self):
        paths = ['/cms/el/customer-area', '/cms/secret-admin']
        responses = [http.origin(p, 'private') for p in paths]
        requests = [http.get(p, 'private', cache='PASS') for p in paths]
        # The same spelling outside this installation and an ordinary referral
        # inside it remain public. Full original URL/cookies reach the origin.
        for path in ['/administrator/', '/cms/article?ref=partner']:
            responses.append(http.origin(path, 'public', expect=['expect req.url == ' + json.dumps(path), 'expect req.http.Cookie == "_ga=client"']))
            requests.extend([http.get(path, 'public', ['Cookie: _ga=client'], cache='MISS'), http.get(path, 'public', ['Cookie: _ga=other'], cache='HIT')])
        self.run_cms('joomla', responses, requests, base='/cms', private_paths=paths)

    def test_cms_rules_do_not_apply_to_another_site_or_similar_words(self):
        responses, requests = [], []
        for path in ['/cartoon', '/accounting', '/administrator-info', '/component/content/article', '/?option=com_content&view=article', '/?return=foo%26option%3Dcom_users']:
            responses.append(http.origin(path, 'public'))
            requests.extend([http.get(path, 'public', cache='MISS'), http.get(path, 'public', cache='HIT')])
        self.run_cms('joomla', responses, requests)

    def test_greek_configured_alias_and_plain_private_page_id(self):
        paths = ['/el/%CE%BA%CE%B1%CE%BB%CE%AC%CE%B8%CE%B9/', '/el/%ce%ba%ce%b1%ce%bb%ce%ac%ce%b8%ce%b9/', '/?page_id=123']
        original=http.site
        def selected(*args,**kwargs):
            row=original(*args,**kwargs)
            if row['domain']=='example.test':
                row['cms_installations']=[dict(cms='wordpress',base='/wordpress',private_paths=['/el/καλάθι'],private_queries=[dict(name='page_id',value='123')])]
            return row
        with patch.object(http,'site',side_effect=selected):
            self.run_policy('basic',[http.origin(p,'private') for p in paths],
                            [http.get(p,'private',cache='PASS') for p in paths])

    def test_drupal_authenticated_cookie_does_not_reuse_anonymous_hit(self):
        self.run_cms('drupal', [http.origin('/article', 'public'), http.origin('/article', 'private')],
                     [http.get('/article', 'public', cache='MISS'),
                      http.get('/article', 'private', ['Cookie: SSESSabcdef123456=alice'], cache='PASS'),
                      'expect resp.http.X-Webuzo-Varnish-Reason == "drupal-authenticated-session"',
                      http.get('/article', 'public', cache='HIT')])


if __name__ == '__main__':
    unittest.main()
