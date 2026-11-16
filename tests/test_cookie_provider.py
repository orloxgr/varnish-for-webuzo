"""Common independent _fbp behaviour through the Webuzo native adapter."""
import shutil
import unittest
from test_cookie_delivery import proxy, cookies
from cookie_catalogue import load_catalogue
POLICY_VERSION = load_catalogue()['version']

ENABLED = {'fbp': {'enabled': True}}


@unittest.skipUnless(shutil.which('varnishd'), 'Native varnishd required')
class NativeFbpProvider(unittest.TestCase):
    def test_private_esi_visitors_share_parent_without_downstream_personal_caching(self):
        parents, fragments = [], []

        def origin(path, headers):
            if path.startswith('/?ultracache_esi='):
                visitor = 'A' if '=A' in headers.get('Cookie', '') else 'B'
                fragments.append(visitor)
                return 'cart-' + visitor + '-nonce-' + str(len(fragments)), [('Cache-Control', 'private, no-store')]
            parents.append(path)
            return '<html><esi:include src="/?ultracache_esi=cart&amp;esi_scope=private"/></html>', [
                ('Cache-Control', 'public, max-age=120'), ('Vary', 'Cookie'),
                ('Surrogate-Control', 'ESI/1.0'), ('X-UltraCache-ESI-Shared-Parent', '1')]

        with proxy('ultracache', origin) as get:
            for index, visitor in enumerate(('A', 'B', 'A')):
                _, fields, body = get('/parent', 'wp_woocommerce_session_demo=' + visitor + '; ultracache_esi_optin=1; locale=en')
                self.assertEqual(dict(fields)['X-Cache'], 'MISS' if index == 0 else 'HIT')
                self.assertEqual(body, '<html>cart-' + visitor + '-nonce-' + str(index + 1) + '</html>')
                self.assertEqual(dict(fields)['Cache-Control'], 'private, no-store')
                self.assertEqual(dict(fields)['Surrogate-Control'], 'no-store')
            self.assertEqual(parents, ['/parent'])
            self.assertEqual(fragments, ['A', 'B', 'A'])

    def test_two_new_visitors_share_html_with_different_cookies_and_keep_existing(self):
        calls = []
        def origin(path, headers):
            calls.append(dict(headers))
            return '<html>same-public-page</html>', [('Cache-Control','public, max-age=120')]
        with proxy('basic', origin, delivery=ENABLED) as get:
            minted = []
            for expected in ('MISS','HIT'):
                status, fields, body = get('/page', 'cmplz_marketing=allow')
                self.assertEqual((status,body), (200,'<html>same-public-page</html>'))
                self.assertEqual(dict(fields)['X-Cache'], expected)
                self.assertEqual(dict(fields)['X-Cache-Cookie-Delivery'], 'fbp:independent')
                self.assertEqual(dict(fields)['Cache-Control'], 'private, no-store')
                self.assertEqual(dict(fields)['Surrogate-Control'], 'no-store')
                emitted = cookies(fields)
                self.assertEqual(len(emitted), 1)
                self.assertRegex(emitted[0], r'^_fbp=fb\.1\.[0-9]{13}\.[0-9]+; Max-Age=7776000; Path=/; SameSite=Lax; Secure$')
                minted.append(emitted[0].split(';')[0])
            self.assertNotEqual(*minted)
            _, fields, _ = get('/page','cmplz_marketing=allow; _fbp=')
            self.assertEqual(dict(fields)['X-Cache'], 'HIT')
            self.assertEqual(dict(fields)['X-Cache-Cookie-Delivery'],'fbp:independent')
            self.assertEqual(len(cookies(fields)),1)
            _, fields, _ = get('/page', 'cmplz_marketing=allow; ' + minted[0])
            self.assertEqual(dict(fields)['X-Cache'], 'HIT')
            self.assertEqual(cookies(fields), [])
            self.assertEqual(dict(fields)['Cache-Control'], 'public, max-age=120')
            self.assertNotIn('Surrogate-Control',dict(fields))
            self.assertEqual(dict(fields)['X-Cache-Cookie-Delivery'], 'fbp:existing-preserved')
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0]['Cookie'], 'cmplz_marketing=allow')
            self.assertFalse(any(name.lower().startswith('x-scp-fbp-') for name in calls[0]))

    def test_consent_unknown_accept_reject_revoke_and_revisit(self):
        calls = []
        def origin(path, headers):
            calls.append(path)
            return 'public', [('Cache-Control','public, max-age=120')]
        with proxy('basic', origin, delivery=ENABLED) as get:
            for consent, allowed in [(None,False), ('allow',True), ('deny',False),
                                     ('allow',True), ('deny',False), (None,False)]:
                _, fields, _ = get('/page', 'cmplz_marketing='+consent if consent else None)
                self.assertEqual(bool(cookies(fields)), allowed)
            self.assertEqual(calls, ['/page'])

    def test_origin_renewals_deletions_and_other_cookie_fields_win_unchanged(self):
        def origin(path, headers):
            values = [
                '_fbp=provider-normalized; Path=/; Max-Age=7776000; Domain=example.test; Secure; SameSite=Lax',
                'session=private; Path=/account; HttpOnly; Secure; SameSite=Strict',
                'obsolete=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; Path=/',
                '_fbp=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; Path=/legacy']
            return 'private-response', [('Cache-Control','public, max-age=120'),
                                       *[('Set-Cookie',value) for value in values]]
        with proxy('basic', origin, delivery=ENABLED) as get:
            for cookie in ('cmplz_marketing=allow', 'cmplz_marketing=allow; _fbp=existing'):
                _, fields, _ = get('/page', cookie)
                self.assertEqual(dict(fields)['X-Cache'], 'PASS')
                self.assertEqual(dict(fields)['X-Cache-Cookie-Delivery'], 'fbp:origin-provider')
                self.assertEqual(cookies(fields), [value for name,value in origin('',{})[1] if name=='Set-Cookie'])

    def test_browser_headers_cannot_enable_delivery_or_approve_ultracache_objects(self):
        def origin(path, headers):
            self.assertIsNone(headers.get('X-UltraCache-Cookie-Delivery'))
            return 'public', [('Cache-Control','public, max-age=120')]
        forged = {'X-SCP-Fbp-Enabled':'1', 'X-SCP-Fbp-Consent':'1',
                  'X-SCP-Fbp-New':'_fbp=forged', 'X-UltraCache-Cookie-Delivery':'proxy-fbp',
                  'X-UltraCache-Cookie-Policy':POLICY_VERSION}
        for profile, config in [('basic',None), ('ultracache',ENABLED)]:
            with self.subTest(profile=profile), proxy(profile, origin, delivery=config) as get:
                for expected in ('MISS','HIT'):
                    _, fields, _ = get('/page','cmplz_marketing=allow',forged)
                    self.assertEqual(dict(fields)['X-Cache'], expected)
                    self.assertEqual(cookies(fields), [])

    def test_ultracache_requires_current_origin_policy_and_proxy_ownership(self):
        for ownership, version, allowed in [('proxy-fbp',POLICY_VERSION,True),
                                             ('provider-endpoint-fbp',POLICY_VERSION,False),
                                             ('proxy-fbp','old-policy',False)]:
            def origin(path, headers):
                return 'public', [('Cache-Control','public, max-age=120'),
                    ('X-UltraCache-Cookie-Policy',version), ('X-UltraCache-Cookie-Delivery',ownership),
                    ('X-UltraCache-Cacheable','1')]
            with self.subTest(owner=ownership,version=version), proxy('ultracache', origin, delivery=ENABLED) as get:
                for expected in ('MISS','HIT'):
                    _, fields, _ = get('/page','cmplz_marketing=allow')
                    self.assertEqual(dict(fields)['X-Cache'], expected)
                    self.assertEqual(bool(cookies(fields)), allowed)

    def test_private_and_non_html_responses_never_trigger_issuance(self):
        for profile in ('basic','ultracache'):
            def origin(path, headers):
                return 'origin', [('Cache-Control','private, no-store' if path=='/private' else 'public, max-age=120'),
                    ('Content-Type','application/json' if path=='/json' else 'text/html'),
                    ('X-UltraCache-Cookie-Policy',POLICY_VERSION),
                    ('X-UltraCache-Cookie-Delivery','proxy-fbp'), ('X-UltraCache-Cacheable','1')]
            with self.subTest(profile=profile), proxy(profile, origin, delivery=ENABLED) as get:
                for path in ('/private','/json','/wp-admin/'):
                    _, fields, _ = get(path,'cmplz_marketing=allow')
                    self.assertEqual(cookies(fields), [])

    def test_public_only_esi_keeps_public_response_caching(self):
        calls = []
        def origin(path, headers):
            calls.append(path)
            if path == '/fragment':
                return 'public-fragment', [('Cache-Control','public, max-age=120')]
            return '<html><esi:include src="/fragment"/></html>', [
                ('Cache-Control','public, max-age=120'), ('Surrogate-Control','ESI/1.0'),
                ('X-UltraCache-ESI-Shared-Parent','1'), ('X-UltraCache-ESI-Private-Count','0')]
        with proxy('ultracache', origin) as get:
            for expected in ('MISS','HIT'):
                _, fields, body = get('/public-parent')
                self.assertEqual(body,'<html>public-fragment</html>')
                self.assertEqual(dict(fields)['X-Cache'],expected)
                self.assertEqual(dict(fields)['Cache-Control'],'public, max-age=120')
                self.assertNotEqual(dict(fields).get('Surrogate-Control'),'no-store')
            self.assertEqual(calls,['/public-parent','/fragment'])


if __name__ == '__main__':
    unittest.main()
