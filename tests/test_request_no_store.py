"""Browser revalidation retains cache; authenticated raw-source routing is separate.

The mock verifies native wire/routing only. Actual WP source MAC validation and
CLI Warm require separate application acceptance.
"""
import http.client
import shutil
import unittest
from test_cookie_delivery import proxy,cookies
from test_delivery_continuation import PARENT,BODY,META,envelope
from test_guest_publication import Guests,register,GUEST_BODY


@unittest.skipUnless(shutil.which('varnishd'),'Native Varnish required; skipped is not acceptance')
class RequestNoStore(unittest.TestCase):
    def test_raw_warm_bypasses_hot_guest_and_keeps_origin_authentication_and_cookies(self):
        token='v2:1795448000:'+('a'*64)
        invalid='v2:1795448000:'+('b'*64)
        raw={'X-UltraCache-Warm':'1','X-UltraCache-Internal-Request':'1',
            'X-UltraCache-Warm-Source':'raw-v1','X-UltraCache-Warm-Registry':'1',
            'X-UltraCache-Runtime-Token':token}
        original_cookie='PHPSESSID=provider; esi_session=transport; ultracache_esi_optin=1; _ga=visitor'
        for aggressive in (False,True):
            app=Guests();requests=[]
            def origin(path,headers):
                if headers.get('X-UltraCache-Warm-Source')=='raw-v1':
                    requests.append((path,dict(headers)))
                    if headers.get('X-UltraCache-Runtime-Token')!=token:
                        return 403,'runtime credential refused',[('Cache-Control','private, no-store')]
                    return 'current raw source',[('Cache-Control','public, max-age=600'),
                        ('X-UltraCache-Warm-Body-Contract','raw-v1'),('X-UltraCache-Warm-Registry','current-registry')]
                return app(path,headers)
            with self.subTest(aggressive=aggressive),proxy('ultracache',origin,
                    site_settings={'aggressive':aggressive,'aggressive_ttl':600}) as get:
                self.assertEqual(register(get)[0],200)
                self.assertEqual(get('/warm')[2],GUEST_BODY)
                self.assertEqual(dict(get('/warm')[1])['X-Cache'],'HIT')
                for cookie in (None,original_cookie):
                    status,headers,body=get('/warm',cookie,extra=raw)
                    self.assertEqual((status,body),(200,'current raw source'))
                    self.assertEqual(dict(headers)['X-Cache'],'PASS')
                    self.assertEqual(dict(headers)['X-UltraCache-Warm-Registry'],'current-registry')
                    self.assertNotIn('X-UltraCache-Guest-Publication',dict(headers))
                status,headers,body=get('/warm',extra={**raw,'X-UltraCache-Runtime-Token':invalid})
                self.assertEqual((status,body),(403,'runtime credential refused'))
                self.assertEqual(dict(headers)['X-Cache'],'PASS')
                self.assertEqual([fields.get('Cookie') for _,fields in requests],[None,original_cookie,None])
                self.assertTrue(all(fields.get('X-UltraCache-Delivery-Phase') is None for _,fields in requests))
                status,headers,body=get('/warm')
                self.assertEqual((status,dict(headers)['X-Cache'],body),(200,'HIT',GUEST_BODY))
                for field in raw:
                    incomplete=dict(raw);del incomplete[field]
                    # Registry capture is optional for existing raw CSS callers.
                    if field=='X-UltraCache-Warm-Registry':
                        status,headers,body=get('/warm',extra=incomplete)
                        self.assertEqual((status,dict(headers)['X-Cache'],body),(200,'PASS','current raw source'))
                        continue
                    status,headers,body=get('/warm',extra=incomplete)
                    self.assertEqual((status,dict(headers)['X-Cache'],body),(200,'HIT',GUEST_BODY))

    def test_raw_warm_keeps_basic_cache_and_cannot_replace_a_regular_ultracache_object(self):
        raw={'X-UltraCache-Warm':'1','X-UltraCache-Internal-Request':'1',
            'X-UltraCache-Warm-Source':'raw-v1','X-UltraCache-Runtime-Token':'v2:1795448000:'+('a'*64)}
        for profile in ('basic','ultracache'):
            calls=[]
            def origin(path,headers):
                calls.append(path)
                return 'current origin '+str(len(calls)),[('Cache-Control','public, max-age=600')]
            with self.subTest(profile=profile),proxy(profile,origin) as get:
                self.assertEqual(get('/raw')[2],'current origin 1')
                status,headers,body=get('/raw',extra=raw)
                self.assertEqual((status,dict(headers)['X-Cache'],body),
                    (200,'HIT','current origin 1') if profile=='basic' else (200,'PASS','current origin 2'))
                status,headers,body=get('/raw')
                self.assertEqual((status,dict(headers)['X-Cache'],body),(200,'HIT','current origin 1'))

    def test_signed_raw_source_reaches_current_origin_without_using_browser_directives(self):
        for aggressive in (False,True):
            calls=[];retired=False
            browser_cookie='PHPSESSID=provider; esi_session=transport; ultracache_esi_optin=1; _ga=visitor'
            raw={'X-UltraCache-Warm':'1','X-UltraCache-Internal-Request':'1','X-UltraCache-Warm-Source':'raw-v1',
                'X-UltraCache-Session-Source-Kind':'native','X-UltraCache-Session-Source':'v1:'+':'.join(letter*64 for letter in 'abcd')}
            def origin(path,headers):
                phase=headers.get('X-UltraCache-Delivery-Phase');calls.append((path,phase,dict(headers)))
                if phase=='prepare':
                    if retired:return 409,'retired publication',[('Cache-Control','private, no-store')]
                    return envelope(headers,'current'),[('Cache-Control','private, no-store')]
                if headers.get('X-UltraCache-Session-Source'):
                    self.assertEqual(headers.get('Cookie'),browser_cookie)
                    return 'fresh raw source',[('Cache-Control','private, no-store'),('Set-Cookie','owner=raw-only; Path=/; HttpOnly')]
                if path==PARENT:return BODY,META
                return 'cold private child',[('Cache-Control','private, no-store')]
            with self.subTest(aggressive=aggressive),proxy('ultracache',origin,
                    site_settings={'aggressive':aggressive,'aggressive_ttl':600}) as get:
                self.assertEqual(get(PARENT)[0],200)
                self.assertEqual(dict(get(PARENT)[1])['X-Cache'],'HIT')
                retired=True;calls.clear()
                for directive in (None,'no-store'):
                    fields=dict(raw)
                    if directive:fields['Cache-Control']=directive
                    status,headers,body=get(PARENT,browser_cookie,extra=fields)
                    self.assertEqual(status,200);self.assertEqual(body,'fresh raw source')
                    self.assertEqual(dict(headers)['X-Cache'],'PASS')
                    self.assertEqual(cookies(headers),['owner=raw-only; Path=/; HttpOnly'])
                self.assertEqual([(path,phase) for path,phase,_ in calls],[(PARENT,None)]*2)
                retired=False;calls.clear()
                status,headers,body=get(PARENT,extra={'Cache-Control':'no-cache, no-store, max-age=0','Pragma':'no-cache'})
                self.assertEqual(status,200);self.assertEqual(dict(headers)['X-Cache'],'HIT')
                self.assertIn('private:current',body)
                self.assertEqual([(path,phase) for path,phase,_ in calls],[(PARENT,'prepare')])

    def test_no_store_uses_existing_object_and_fills_cold_object_normally(self):
        for profile in ('basic','ultracache'):
            for aggressive in (False,True):
                calls=[]
                def origin(path,headers):
                    calls.append((path,headers.get('Cookie')))
                    return 'origin-'+str(len(calls)),[('Cache-Control','public, max-age=600')]
                with self.subTest(profile=profile,aggressive=aggressive),proxy(profile,origin,
                        site_settings={'aggressive':aggressive,'aggressive_ttl':600}) as get:
                    self.assertEqual(get('/existing')[2],'origin-1')
                    for _ in range(2):
                        status,fields,body=get('/existing','_ga=preserved',extra={'Cache-Control':'no-store'})
                        self.assertEqual(status,200);self.assertEqual(dict(fields)['X-Cache'],'HIT');self.assertEqual(body,'origin-1')
                    status,fields,body=get('/cold','_ga=preserved',extra={'Cache-Control':'no-store'})
                    self.assertEqual(status,200);self.assertEqual(dict(fields)['X-Cache'],'MISS');self.assertEqual(body,'origin-2')
                    self.assertEqual(calls[-1],('/cold','_ga=preserved'))
                    self.assertEqual(dict(get('/cold',extra={'Cache-Control':'no-store'})[1])['X-Cache'],'HIT')
                    self.assertEqual(len(calls),2)

    def test_directive_boundaries_reload_and_repeated_cache_control_fields(self):
        for profile in ('basic','ultracache'):
            calls=[]
            def origin(path,headers):
                calls.append(path)
                return 'origin-'+str(len(calls)),[('Cache-Control','public, max-age=600')]
            with self.subTest(profile=profile),proxy(profile,origin) as get:
                self.assertEqual(get('/directives')[2],'origin-1')
                for control in ('no-store','no-cache','max-age=0','no-cache, no-store, max-age=0',
                        'x-no-store','no-store-extra','foo=no-store','no-store=invalid','max-age=0, No-StOrE , no-cache'):
                    _,fields,body=get('/directives',extra={'Cache-Control':control,'Pragma':'no-cache'})
                    self.assertEqual(dict(fields)['X-Cache'],'HIT');self.assertEqual(body,'origin-1')
                client=http.client.HTTPConnection(*get.endpoint,timeout=10)
                try:
                    client.putrequest('GET','/directives',skip_host=True)
                    for name,value in [*get.request_headers.items(),('Cache-Control','no-cache'),('Cache-Control','no-store')]:
                        client.putheader(name,value)
                    client.endheaders();response=client.getresponse();response.read()
                    self.assertEqual(response.status,200);self.assertEqual(response.getheader('X-Cache'),'HIT')
                finally:client.close()
                self.assertEqual(len(calls),1)


if __name__=='__main__':unittest.main()
