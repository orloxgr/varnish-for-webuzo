"""Native raw-source routing; real WordPress CLI Warm is separate acceptance."""
import http.client
import shutil
import unittest

from test_cookie_delivery import proxy, cookies
from test_delivery_continuation import PARENT, BODY, META, envelope


@unittest.skipUnless(shutil.which('varnishd'), 'Native Varnish required; skipped is not acceptance')
class RequestNoStore(unittest.TestCase):
    def test_raw_warm_bypasses_existing_esi_parent_and_retired_publication(self):
        for aggressive in (False, True):
            calls=[];retired=False
            original='PHPSESSID=provider; esi_session=transport; ultracache_esi_optin=1; _ga=visitor'
            warm={'Cache-Control':'no-cache, no-store, must-revalidate, max-age=0',
                'X-UltraCache-Warm':'1', 'X-UltraCache-Internal-Request':'1',
                'X-UltraCache-Warm-Source':'raw-v1',
                'X-UltraCache-Runtime-Token':'owned-origin-test-token'}
            def origin(path, headers):
                phase=headers.get('X-UltraCache-Delivery-Phase')
                calls.append((path,phase,dict(headers)))
                if phase=='prepare':
                    if retired:
                        return 409,'publication retired',[
                            ('X-UltraCache-Delivery-Error','public-publication-unavailable')]
                    return envelope(headers,'current'),[('Cache-Control','private, no-store')]
                if headers.get('X-UltraCache-Warm')=='1':
                    self.assertEqual(path,PARENT);self.assertIsNone(phase)
                    self.assertEqual(headers.get('Cookie'),original)
                    for name,value in warm.items():self.assertEqual(headers.get(name),value)
                    # Even a cacheable raw response must not replace the parent.
                    return 'fresh raw source',[('Cache-Control','public, max-age=600'),
                        ('Set-Cookie','owner=warm-only; Path=/; HttpOnly')]
                if path==PARENT:return BODY,META
                return 'cold private child',[('Cache-Control','private, no-store')]
            with self.subTest(aggressive=aggressive),proxy('ultracache',origin,
                    site_settings={'aggressive':aggressive,'aggressive_ttl':600}) as get:
                self.assertEqual(get(PARENT)[0],200)
                status,fields,body=get(PARENT)
                self.assertEqual(status,200);self.assertEqual(dict(fields)['X-Cache'],'HIT')
                self.assertEqual(body,'<html>parent[private:current][private:current][nonce:current]</html>')
                retired=True;calls.clear()
                for _ in range(2):
                    status,fields,body=get(PARENT,original,extra=warm)
                    self.assertEqual(status,200);self.assertEqual(body,'fresh raw source')
                    self.assertEqual(dict(fields)['X-Cache'],'PASS')
                    self.assertEqual(cookies(fields),['owner=warm-only; Path=/; HttpOnly'])
                self.assertEqual([(path,phase) for path,phase,_ in calls],[(PARENT,None)]*2)
                retired=False;calls.clear()
                status,fields,body=get(PARENT,extra={'Cache-Control':'no-cache, max-age=0','Pragma':'no-cache'})
                self.assertEqual(status,200);self.assertEqual(dict(fields)['X-Cache'],'HIT')
                self.assertIn('private:current',body);self.assertEqual(cookies(fields),[])
                self.assertEqual([(path,phase) for path,phase,_ in calls],[(PARENT,'prepare')])

    def test_no_store_reaches_current_origin_without_filling_or_replacing_public_objects(self):
        for profile in ('basic','ultracache'):
            for aggressive in (False,True):
                calls=[]
                def origin(path,headers):
                    calls.append((path,headers.get('Cookie')))
                    return 'origin-'+str(len(calls)),[('Cache-Control','public, max-age=600')]
                with self.subTest(profile=profile,aggressive=aggressive),proxy(profile,origin,
                        site_settings={'aggressive':aggressive,'aggressive_ttl':600}) as get:
                    self.assertEqual(get('/existing')[2],'origin-1')
                    for path in ('/existing','/existing','/cold','/cold'):
                        status,fields,body=get(path,'_ga=preserved',extra={'Cache-Control':'no-store'})
                        self.assertEqual(status,200);self.assertEqual(dict(fields)['X-Cache'],'PASS')
                        self.assertEqual(body,'origin-'+str(len(calls)))
                        self.assertEqual(calls[-1],(path,'_ga=preserved'))
                    _,fields,body=get('/existing')
                    self.assertEqual(dict(fields)['X-Cache'],'HIT');self.assertEqual(body,'origin-1')
                    _,fields,body=get('/cold')
                    self.assertEqual(dict(fields)['X-Cache'],'MISS');self.assertEqual(body,'origin-6')

    def test_directive_boundaries_reload_and_repeated_cache_control_fields(self):
        for profile in ('basic','ultracache'):
            calls=[]
            def origin(path,headers):
                calls.append(path)
                return 'origin-'+str(len(calls)),[('Cache-Control','public, max-age=600')]
            with self.subTest(profile=profile),proxy(profile,origin) as get:
                self.assertEqual(get('/directives')[2],'origin-1')
                for control in ('no-cache','max-age=0','no-cache, max-age=0',
                        'x-no-store','no-store-extra','foo=no-store','no-store=invalid'):
                    _,fields,body=get('/directives',extra={'Cache-Control':control,'Pragma':'no-cache'})
                    self.assertEqual(dict(fields)['X-Cache'],'HIT');self.assertEqual(body,'origin-1')
                _,fields,_=get('/directives',extra={'Cache-Control':'max-age=0, No-StOrE , no-cache'})
                self.assertEqual(dict(fields)['X-Cache'],'PASS')
                client=http.client.HTTPConnection(*get.endpoint,timeout=10)
                try:
                    client.putrequest('GET','/directives',skip_host=True)
                    for name,value in [('Host','example.test'),('X-Forwarded-Proto','https'),
                            ('Cache-Control','no-cache'),('Cache-Control','no-store')]:
                        client.putheader(name,value)
                    client.endheaders();response=client.getresponse();response.read()
                    self.assertEqual(response.status,200);self.assertEqual(response.getheader('X-Cache'),'PASS')
                finally:client.close()
                _,fields,body=get('/directives')
                self.assertEqual(dict(fields)['X-Cache'],'HIT');self.assertEqual(body,'origin-1')
                self.assertEqual(len(calls),3)


if __name__=='__main__':unittest.main()
