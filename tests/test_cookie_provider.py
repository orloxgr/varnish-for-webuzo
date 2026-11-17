"""Generic cookie rules and private ESI; providers own cookie creation."""
import shutil
import unittest
from test_cookie_delivery import proxy, cookies


@unittest.skipUnless(shutil.which('varnishd'), 'Native varnishd required')
class NativeCookieProvider(unittest.TestCase):
    def test_fbp_uses_the_same_scoped_actions_without_native_cookie_creation(self):
        for profile in ('basic','ultracache'):
            for action in ('shared','variant','private'):
                calls=[]
                def origin(path,headers):
                    calls.append(headers.get('Cookie'))
                    return 'public', [('Cache-Control','public, max-age=120'),('Vary','Cookie')]
                choice={'schemaVersion':1,'rules':[dict(id='custom:fbp',match=dict(kind='exact',value='_fbp'),
                    description='Local choice',action=action)]}
                with self.subTest(profile=profile,action=action),proxy(profile,origin,configuration={'cookie_policies':choice}) as get:
                    expected={'shared':['MISS','HIT','HIT'],'variant':['MISS','MISS','HIT'],'private':['PASS']*3}[action]
                    for visitor,result in zip(('A','B','A'),expected):
                        _,fields,body=get('/page','_fbp='+visitor)
                        self.assertEqual(body,'public')
                        self.assertEqual(dict(fields)['X-Cache'],result)
                        self.assertEqual(cookies(fields),[])
                    self.assertEqual(calls,['_fbp=A'] if action=='shared' else ['_fbp=A','_fbp=B'] if action=='variant' else ['_fbp=A','_fbp=B','_fbp=A'])

    def test_consent_and_old_provider_headers_cannot_mint_an_identifier(self):
        for profile in ('basic','ultracache'):
            def origin(path,headers):
                return 'public', [('Cache-Control','public, max-age=120'),
                    ('X-UltraCache-Cookie-Delivery','proxy-fbp'),('X-UltraCache-Cacheable','1')]
            with self.subTest(profile=profile),proxy(profile,origin) as get:
                for expected in ('MISS','HIT'):
                    _,fields,_=get('/page','cmplz_marketing=allow',{'X-SCP-Fbp-Enabled':'1','X-SCP-Fbp-Consent':'1'})
                    self.assertEqual(dict(fields)['X-Cache'],expected)
                    self.assertEqual(cookies(fields),[])
                    self.assertNotIn('X-Cache-Cookie-Delivery',dict(fields))

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



if __name__ == "__main__":
    unittest.main()
