"""Real native responses: Shared includes storage and original field delivery."""
import concurrent.futures
import shutil
import unittest

from test_cookie_delivery import proxy, cookies
from test_cookie_admin_webuzo import choices

def settings(name,action):return choices(action,name)


@unittest.skipUnless(shutil.which('varnishd'), 'Native Varnish required')
class ResponseCookies(unittest.TestCase):
    def test_shared_response_keeps_original_fields_but_never_replays_them(self):
        for profile in ('basic','ultracache'):
            calls=[]
            def origin(path, headers):
                visitor=headers.get('X-Visitor','first')
                calls.append((path,headers.get('X-SCP-Cookie-Handoff')))
                return 'public body', [('Cache-Control','public, max-age=120'),
                    ('Set-Cookie','_fbp='+visitor+'; Expires=Wed, 18 Nov 2026 19:00:00 GMT; Path=/; Secure; SameSite=Lax'),
                    ('Set-Cookie','custom_measurement=; Max-Age=0; Path=/; HttpOnly; Secure')]
            with self.subTest(profile=profile), proxy(profile,origin,
                    policies=settings('custom_measurement','shared')) as get:
                def pair(i):
                    path='/response-'+str(i)
                    _,fields,body=get(path,extra={'X-Visitor':'owner-'+str(i)})
                    self.assertEqual(dict(fields)['X-Cache'],'MISS')
                    self.assertEqual(cookies(fields),[
                        '_fbp=owner-'+str(i)+'; Expires=Wed, 18 Nov 2026 19:00:00 GMT; Path=/; Secure; SameSite=Lax',
                        'custom_measurement=; Max-Age=0; Path=/; HttpOnly; Secure'])
                    self.assertEqual(dict(fields)['Cache-Control'],'private, no-store')
                    _,fields,hit=get(path,'_fbp=another-visitor',extra={'X-Visitor':'other'})
                    self.assertEqual(dict(fields)['X-Cache'],'HIT')
                    self.assertEqual(cookies(fields),[])
                    self.assertEqual(body,hit)
                    self.assertEqual(dict(fields)['Cache-Control'],'public, max-age=120')
                with concurrent.futures.ThreadPoolExecutor(max_workers=12) as workers:
                    list(workers.map(pair,range(36)))
                self.assertEqual(len(calls),36)
                self.assertTrue(all(key is None for _,key in calls))

    def test_variant_private_unknown_and_core_private_responses_stay_private(self):
        for profile in ('basic','ultracache'):
            for name,action in [('custom_cookie','variant'),('custom_cookie','private'),
                                ('unknown_cookie',None),('wordpress_logged_in_demo','shared')]:
                calls=[]
                def origin(path,headers):
                    calls.append(path)
                    return 'origin', [('Cache-Control','public, max-age=120'),
                        ('Set-Cookie','_fbp=real-id; Path=/'),('Set-Cookie',name+'=individual; HttpOnly')]
                with self.subTest(profile=profile,name=name,action=action), proxy(profile,origin,
                        policies=settings(name,action) if action else None) as get:
                    for _ in range(2):
                        _,fields,_=get('/mixed')
                        self.assertEqual(dict(fields)['X-Cache'],'PASS')
                        self.assertEqual(cookies(fields),['_fbp=real-id; Path=/',name+'=individual; HttpOnly'])
                    self.assertEqual(len(calls),2)

    def test_shared_does_not_cancel_origin_privacy_or_uncacheable_freshness(self):
        for profile in ('basic','ultracache'):
            for restrictions in [[('Cache-Control','private, no-store')],
                    [('Cache-Control','public, max-age=120'),('Surrogate-Control','no-store')],
                    [('Cache-Control','no-cache')], [('Cache-Control','public, max-age=0')],
                    [('Cache-Control','public, max-age=120'),('Vary','*')]]:
                def origin(path,headers):
                    return 'private body',restrictions+[('Set-Cookie','_fbp=real-original; Path=/')]
                with self.subTest(profile=profile,restrictions=restrictions),proxy(profile,origin) as get:
                    for _ in range(2):
                        _,fields,_=get('/origin-privacy')
                        self.assertEqual(dict(fields)['X-Cache'],'PASS')
                        self.assertEqual(cookies(fields),['_fbp=real-original; Path=/'])

    def test_response_resolution_matches_site_exact_and_longest_prefix_choices(self):
        policy={'schemaVersion':1,'rules':[
            {'id':'prefix','match':{'kind':'prefix','value':'metric_'},'description':'','action':'shared'},
            {'id':'exact','match':{'kind':'exact','value':'metric_private'},'description':'','action':'private'}]}
        def origin(path,headers):
            name='metric_private' if path=='/private' else 'metric_public'
            return 'public',[('Cache-Control','public, max-age=120'),('Set-Cookie',name+'=unique; Path=/')]
        for profile in ('basic','ultracache'):
            with self.subTest(profile=profile),proxy(profile,origin,policies=policy) as get:
                for path,expected in [('/public',['MISS','HIT']),('/private',['PASS','PASS'])]:
                    for result in expected:
                        _,fields,_=get(path)
                        self.assertEqual(dict(fields)['X-Cache'],result)

    def test_handoff_entries_are_finalized_after_delivery(self):
        def diagnostic(source):
            return source.replace('call scp_deliver;',
                'call scp_deliver; set resp.http.X-Test-Pending = cookie_handoff.pending();')
        def origin(path,headers):
            return 'body',[('Cache-Control','public, max-age=120'),('Set-Cookie','_fbp=original; Path=/')]
        with proxy('basic',origin,transform=diagnostic) as get:
            get('/delivery')
            _,fields,_=get('/delivery')
            self.assertEqual(dict(fields)['X-Test-Pending'],'0')


if __name__=='__main__':unittest.main()
