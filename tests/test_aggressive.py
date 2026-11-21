"""Opt-in HTML cache lifetime, original browser policy and request-owned cookies."""
import copy
import shutil
import unittest
from unittest.mock import patch
import test_profiles as http
import aggressive


class Settings(unittest.TestCase):
    def test_no_migration_old_ttl_or_implicit_enable(self):
        site={'ttl':300}
        before=copy.deepcopy(site)
        self.assertEqual(aggressive.settings(site),dict(aggressive=False,aggressive_ttl=86400))
        self.assertEqual(site,before)
        self.assertEqual(aggressive.settings(dict(aggressive=True,aggressive_ttl=31536000))['aggressive_ttl'],31536000)
        for value in (dict(aggressive=1),dict(aggressive_ttl=True),dict(aggressive_ttl=0),dict(aggressive_ttl='86400')):
            with self.subTest(value=value),self.assertRaises(ValueError):aggressive.settings(value)


@unittest.skipUnless(shutil.which('varnishtest'),'Native Varnish required')
class NativeAggressive(unittest.TestCase):
    run_policy=http.NativeProfiles.run_policy

    def aggressive(self,profile,responses,requests,*,ttl=86400,site_options=None,config=None):
        original=http.site
        def selected(*args,**kwargs):
            value=original(*args,**kwargs)
            if value['domain']=='example.test':
                value.update(aggressive=True,aggressive_ttl=ttl)
                value.update(site_options or {})
            return value
        with patch.object(http,'site',side_effect=selected):
            self.run_policy(profile,responses,requests,config=config,observe_ttl=True)

    def test_no_store_html_hits_with_selected_ttl_and_original_browser_headers(self):
        for profile in ('basic','ultracache'):
            headers=['Surrogate-Control: no-store','Pragma: no-cache','Expires: Wed, 17 Aug 2005 00:00:00 GMT']
            self.aggressive(profile,[http.origin('/page','public',headers,cache='private, no-store')],
                [http.get('/page','public',cache='MISS'),'expect resp.http.X-Test-Final-TTL == "604800.000"',
                 'expect resp.http.Cache-Control == "private, no-store"','expect resp.http.Surrogate-Control == "no-store"',
                 'expect resp.http.Pragma == "no-cache"','expect resp.http.Expires == "Wed, 17 Aug 2005 00:00:00 GMT"',
                 http.get('/page','public',cache='HIT'),'expect resp.http.Cache-Control == "private, no-store"',
                 'expect resp.http.X-SCP-Browser-Cache-Control == <undef>'],ttl=604800)

    def test_generic_session_cookie_is_forwarded_but_not_a_public_html_variant(self):
        for profile in ('basic','ultracache'):
            self.aggressive(profile,[http.origin('/?utm_source=A','public',headers=['Vary: Cookie'],cache='no-store',
                expect=['expect req.http.Cookie == "_ga=alice; _ga=A"','expect req.url == "/?utm_source=A"'])],
                [http.get('/?utm_source=A','public',['Cookie: _ga=alice; _ga=A'],cache='MISS'),
                 http.get('/?utm_source=B','public',['Cookie: _ga=bob; _ga=B'],cache='HIT')])

    def test_session_response_cookie_is_not_replayed_to_another_visitor(self):
        for profile in ('basic','ultracache'):
            self.aggressive(profile,[http.origin('/page','public',['Set-Cookie: _ga=alice; Path=/; HttpOnly','Vary: Cookie'],cache='no-cache, no-store'),
                                     http.origin('/other','other',['Set-Cookie: _ga=bob; Path=/; HttpOnly'],cache='no-store')],
                [http.get('/page','public',cache='MISS'),'expect resp.http.Set-Cookie == "_ga=alice; Path=/; HttpOnly"',
                 http.get('/page','public',cache='HIT'),'expect resp.http.Set-Cookie == <undef>',
                 http.get('/other','other',cache='MISS'),'expect resp.http.Set-Cookie == "_ga=bob; Path=/; HttpOnly"',
                 http.get('/page','public',['Cookie: _ga=bob'],cache='HIT'),'expect resp.http.Set-Cookie == <undef>'])

    def test_login_cart_actions_authentication_and_explicit_private_choices_still_pass(self):
        for profile in ('basic','ultracache'):
            responses=[http.origin('/page','public',cache='no-store')]
            requests=[http.get('/page','public',cache='MISS')]
            for path,header in [('/wp-login.php',None),('/checkout/',None),('/?add-to-cart=1',None),
                                ('/page','Cookie: wordpress_logged_in_abc=alice'),('/page','Cookie: woocommerce_items_in_cart=1'),
                                ('/page','Authorization: Bearer alice'),('/page','Cookie: private_choice=alice')]:
                responses.append(http.origin(path,'private'))
                requests.append(http.get(path,'private',[] if header is None else [header],cache='PASS'))
            requests.append(http.get('/page','public',cache='HIT'))
            config={'cookie_policies':{'schemaVersion':1,'rules':[dict(id='choice',match=dict(kind='exact',value='private_choice'),description='Explicit Private',action='private')]}}
            self.aggressive(profile,responses,requests,config=config)

    def test_aggressive_is_site_scoped_and_client_cannot_enable_it_with_headers(self):
        self.aggressive('basic',[http.origin('/page','public',cache='no-store'),http.origin('/page','other-A',cache='no-store'),http.origin('/page','other-B',cache='no-store')],
            [http.get('/page','public',cache='MISS'),http.get('/page','public',cache='HIT'),
             http.get('/page','other-A',['X-SCP-Aggressive: 1','X-SCP-Aggressive-TTL: 86400'],host='other.test',cache='PASS'),
             http.get('/page','other-B',host='other.test',cache='PASS')])

    def test_write_requests_do_not_reuse_or_seed_a_warm_public_object(self):
        for profile in ('basic','ultracache'):
            responses=[http.origin('/page','public',cache='no-store')]
            requests=[http.get('/page','public',cache='MISS')]
            for method in ('POST','PUT','PATCH','DELETE'):
                responses.append(http.origin('/page',method,cache='no-store',expect=['expect req.method == "'+method+'"']))
                requests.extend([http.get('/page',method,method=method,cache='PASS'),
                                 'expect resp.http.X-Webuzo-Varnish-Reason == "request-method"'])
            requests.append(http.get('/page','public',cache='HIT'))
            self.aggressive(profile,responses,requests)


if __name__=='__main__':unittest.main()
