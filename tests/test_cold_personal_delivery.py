"""Native origin transport fixture, not application collector separation proof.

The mock origin supplies an already-personal visitor copy and authentic HTTP
cookie fields. Actual first-cold WP/provider execution remains root acceptance.
"""
import shutil
import unittest

from test_cookie_delivery import proxy,cookies


@unittest.skipUnless(shutil.which('varnishd'),'Native Varnish required; fixture unqualified when skipped')
class ColdPersonalDelivery(unittest.TestCase):
    def test_personal_first_body_and_cookies_never_replay_under_aggressive_or_public_esi(self):
        for aggressive in (False,True):
            for public_esi in (False,True):
                parent_calls=[];child_calls=[]
                def origin(path,headers):
                    self.assertIsNone(headers.get('X-SCP-Personal-Delivery'))
                    self.assertIsNone(headers.get('X-UltraCache-Delivery-Phase'),
                        'A full personal origin render must not trigger a second provider prepare')
                    if path=='/public-child':
                        child_calls.append(path);self.assertIsNone(headers.get('Cookie'))
                        return 'PUBLIC',[('Cache-Control','public, max-age=120')]
                    self.assertEqual(path,'/cold')
                    parent_calls.append(headers.get('Cookie'))
                    number=len(parent_calls)
                    # The first two responses issue ONLY default-Shared cookies;
                    # storage must not depend on a Private cookie blocking it.
                    fields=[('_fbp','provider-'+str(number)+'; Path=/; Secure; SameSite=Lax'),
                        ('_ga','metrics-'+str(number)+'; Expires=Wed, 21 Oct 2037 07:28:00 GMT; Path=/; HttpOnly')]
                    if number==3:fields.append(('private_owner','third; Path=/; HttpOnly'))
                    body='<html>literal-personal-'+str(number)
                    if public_esi:body+='[<esi:include src="/public-child"/>]'
                    body+='</html>'
                    return body,[('Cache-Control','private, no-store'),
                        ('Surrogate-Control','ESI/1.0, no-store' if public_esi else 'no-store'),
                        ('X-UltraCache-Cacheable','0'),('X-UltraCache-ESI-Private-Count','2'),
                        # Reserved upstream scratch must not undo browser privacy.
                        ('X-SCP-Aggressive-Response','1'),('X-SCP-Browser-Cache-Control','public, max-age=900'),
                        *[('Set-Cookie',name+'='+value) for name,value in fields]]
                with self.subTest(aggressive=aggressive,public_esi=public_esi),proxy('ultracache',origin,
                        site_settings={'aggressive':aggressive,'aggressive_ttl':86400}) as get:
                    for number,cookie in enumerate((None,'_fbp=other; _ga=other; sbjs_session=other',
                            '_fbp=returning; _ga=returning; private_owner=existing'),1):
                        status,fields,body=get('/cold',cookie,extra={'X-SCP-Personal-Delivery':'browser-spoof'})
                        self.assertEqual(status,200)
                        self.assertEqual(body,'<html>literal-personal-'+str(number)+('[PUBLIC]' if public_esi else '')+'</html>')
                        self.assertEqual(dict(fields)['X-Cache'],'PASS')
                        self.assertEqual(dict(fields)['Cache-Control'],'private, no-store')
                        expected=['_fbp=provider-'+str(number)+'; Path=/; Secure; SameSite=Lax',
                            '_ga=metrics-'+str(number)+'; Expires=Wed, 21 Oct 2037 07:28:00 GMT; Path=/; HttpOnly']
                        if number==3:expected.append('private_owner=third; Path=/; HttpOnly')
                        self.assertEqual(cookies(fields),expected)
                        self.assertNotIn('X-SCP-Personal-Delivery',dict(fields))
                    self.assertEqual(len(parent_calls),3,'A new visitor must never reuse personal body bytes')
                    self.assertEqual(child_calls,['/public-child'] if public_esi else [])

    def test_basic_does_not_adopt_ultracache_personal_body_metadata(self):
        calls=[]
        def origin(path,headers):
            self.assertIsNone(headers.get('X-SCP-Personal-Delivery'))
            calls.append(path)
            return 'ordinary public Basic HTML',[('Cache-Control','public, max-age=120'),
                ('X-UltraCache-Cacheable','0'),('X-UltraCache-ESI-Private-Count','2'),
                ('X-SCP-Personal-Delivery','1')]
        with proxy('basic',origin,site_settings={'aggressive':True,'aggressive_ttl':86400}) as get:
            for expected in ('MISS','HIT'):
                _,fields,body=get('/basic',extra={'X-SCP-Personal-Delivery':'browser-spoof'})
                self.assertEqual(body,'ordinary public Basic HTML')
                self.assertEqual(dict(fields)['X-Cache'],expected)
                self.assertNotIn('X-SCP-Personal-Delivery',dict(fields))
            self.assertEqual(calls,['/basic'])


if __name__=='__main__':unittest.main()
