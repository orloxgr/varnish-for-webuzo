"""Native-only fixture: pre-header capture and request-owned fragment replay.

Mock origin tests transport/lifecycle, not real WordPress/WooCommerce semantics.
Do not count skipped tests or this fixture as application/browser acceptance.
Cold private children in this fixture issue no cookie: it does not qualify
initial-MISS delivery of cookies first created after the parent headers.
"""
import concurrent.futures
import json
import http.client
import shutil
import unittest

from test_cookie_delivery import proxy, cookies

PRIVATE='/index.php?ultracache_esi=signed-private&esi_scope=private'
ADAPTIVE='/index.php?ultracache_esi=signed-adaptive&esi_identity=wordpress'
MANIFEST='signed+manifest%2Ftoken'
PREPARE='/index.php?ultracache_delivery=signed%2Bmanifest%252Ftoken'
PARENT='/article?public=1&original=a%2Bb&original=c+d'
META=[('Cache-Control','public, max-age=120'),('Surrogate-Control','ESI/1.0'),
      ('X-UltraCache-ESI-Shared-Parent','1'),('X-UltraCache-ESI-Private-Count','3'),
      ('X-UltraCache-Delivery-Prepare',PREPARE)]
BODY='<html>parent[<esi:include src="'+PRIVATE.replace('&','&amp;')+'"/>]['+\
     '<esi:include src="'+PRIVATE.replace('&','&amp;')+'"/>]['+\
     '<esi:include src="'+ADAPTIVE.replace('&','&amp;')+'"/>]</html>'


def envelope(headers, visitor, change=None):
    result=dict(schemaVersion=1,requestId=headers.get('X-UltraCache-Delivery-Request'),
        originalUrl=headers.get('X-UltraCache-Delivery-Original-URL'),renderedFragments=[
            dict(url=PRIVATE,html='private:'+visitor,occurrences=2),
            dict(url=ADAPTIVE,html='nonce:'+visitor,occurrences=1)])
    if change: change(result)
    return json.dumps(result)


@unittest.skipUnless(shutil.which('varnishd'),'Native Varnish required; fixture unqualified when skipped')
class DeliveryContinuation(unittest.TestCase):
    def test_purged_parent_recovers_only_the_bound_public_snapshot_without_provider_rerun(self):
        calls=[]
        public='/public-child-after-prepare'
        body=BODY.replace('</html>','<esi:include src="'+public+'"/></html>')
        def origin(path,headers):
            phase=headers.get('X-UltraCache-Delivery-Phase')
            calls.append((path,phase))
            if phase=='prepare':
                # Real purge of only this disposable proxy's selected parent.
                connection=http.client.HTTPConnection(*get.endpoint,timeout=5)
                try:
                    connection.request('PURGE',PARENT,headers={'Host':'example.test',
                        'X-Forwarded-Proto':'https','X-UltraCache-Token':headers['X-UltraCache-Delivery-Authorization']})
                    response=connection.getresponse();response.read()
                    self.assertEqual(response.status,200)
                finally:connection.close()
                return envelope(headers,'prepared-once'),[('Cache-Control','private, no-store'),
                    ('X-UltraCache-Delivery-Recovery','public-snapshot-v1'),
                    ('Set-Cookie','owner=prepared-once; Path=/; HttpOnly')]
            if phase=='parent-snapshot':
                self.assertEqual(path,PARENT)
                self.assertEqual(headers.get('X-UltraCache-Delivery-Manifest'),MANIFEST)
                self.assertEqual(headers.get('X-UltraCache-Delivery-Recovery-Version'),'1')
                return body,META+[('X-UltraCache-Delivery-Recovery','public-snapshot-v1'),
                    ('X-UltraCache-Delivery-Request',headers['X-UltraCache-Delivery-Request']),
                    ('X-UltraCache-Delivery-Original-URL',PARENT)]
            if path==PARENT:return body,META
            if path==public:
                self.assertIsNone(headers.get('Cookie'))
                # Force a public child MISS even after the initial warm visit.
                return 'public-child',[('Cache-Control','public, max-age=0')]
            return 'cold-private',[('Cache-Control','private, no-store')]
        with proxy('ultracache',origin) as get:
            get(PARENT);calls.clear()
            status,fields,result=get(PARENT,'_fbp=visitor')
            self.assertEqual(status,200)
            self.assertEqual(result,'<html>parent[private:prepared-once][private:prepared-once][nonce:prepared-once]public-child</html>')
            self.assertEqual(cookies(fields),['owner=prepared-once; Path=/; HttpOnly'])
            self.assertEqual(calls,[(PARENT,'prepare'),(PARENT,'parent-snapshot'),(public,None)])
            for name in ('Request','Original-URL','Manifest','Authorization','Recovery'):
                self.assertNotIn('X-UltraCache-Delivery-'+name,dict(fields))

    def test_hit_cookie_headers_precede_replayed_private_fragments(self):
        calls=[]
        def origin(path,headers):
            calls.append((path,dict(headers)))
            if headers.get('X-UltraCache-Delivery-Phase')=='prepare':
                self.assertEqual(path,PARENT)
                self.assertEqual(headers.get('X-UltraCache-Delivery-Manifest'),MANIFEST)
                visitor=headers.get('Cookie','anonymous')
                return envelope(headers,visitor),[
                    ('Content-Type','application/vnd.ultracache.delivery+json'),
                    ('Cache-Control','private, no-store'),
                    ('Set-Cookie','session='+visitor+'; Path=/; Secure; HttpOnly; SameSite=Lax'),
                    ('Set-Cookie','old=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; Path=/'),
                    ('Set-Cookie','session=other-path; Path=/account; Secure')]
            if path==PARENT:return BODY,META
            return 'cold-fragment',[('Cache-Control','private, no-store')]
        with proxy('ultracache',origin) as get:
            self.assertEqual(get(PARENT)[0],200)
            calls.clear()
            for visitor in ('_fbp=alice','_fbp=bob','_fbp=alice'):
                status,fields,body=get(PARENT,visitor,extra={
                    'X-UltraCache-Delivery-Phase':'complete',
                    'X-UltraCache-Delivery-Request':'spoof',
                    'X-UltraCache-Delivery-Authorization':'spoof-credential',
                    'X-UltraCache-Delivery-Manifest':'spoof-manifest',
                    'X-UltraCache-Delivery-Original-URL':'/wrong'})
                self.assertEqual(status,200)
                self.assertEqual(body,'<html>parent[private:'+visitor+'][private:'+visitor+'][nonce:'+visitor+']</html>')
                self.assertEqual(cookies(fields),[
                    'session='+visitor+'; Path=/; Secure; HttpOnly; SameSite=Lax',
                    'old=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; Path=/',
                    'session=other-path; Path=/account; Secure'])
                self.assertEqual(dict(fields)['Cache-Control'],'private, no-store')
                self.assertEqual(dict(fields)['X-Cache'],'HIT')
                self.assertNotIn('X-UltraCache-Delivery-Prepare',dict(fields))
                self.assertNotIn('X-UltraCache-Delivery-Authorization',dict(fields))
                self.assertNotIn('X-UltraCache-Delivery-Manifest',dict(fields))
            self.assertEqual([p for p,_ in calls],[PARENT]*3)
            for _,headers in calls:
                self.assertEqual(headers['X-UltraCache-Delivery-Phase'],'prepare')
                self.assertEqual(headers['X-UltraCache-Delivery-Version'],'1')
                self.assertEqual(headers['X-UltraCache-Delivery-Original-URL'],PARENT)
                self.assertNotIn('X-SCP-Cookie-Handoff',headers)
                self.assertIn(headers['X-UltraCache-Delivery-Authorization'],('A'*32,'b'*64))

    def test_binding_schema_count_and_duplicate_fail_before_successful_parent_delivery(self):
        def wrong_id(e):e['requestId']='another-request'
        def wrong_url(e):e['originalUrl']='/another-page'
        def wrong_count(e):e['renderedFragments'][0]['occurrences']=1
        def duplicate(e):e['renderedFragments'][1]['url']=PRIVATE
        def foreign(e):e['renderedFragments'][0]['url']='https://foreign.test/fragment'
        for change in (wrong_id,wrong_url,wrong_count,duplicate,foreign):
            calls=[]
            def origin(path,headers):
                calls.append(path)
                if headers.get('X-UltraCache-Delivery-Phase')=='prepare':
                    self.assertEqual(path,PARENT)
                    self.assertEqual(headers.get('X-UltraCache-Delivery-Manifest'),MANIFEST)
                    return envelope(headers,'test',change),[('Cache-Control','private, no-store')]
                return (BODY,META) if path==PARENT else ('cold',[])
            with self.subTest(change=change.__name__),proxy('ultracache',origin) as get:
                get(PARENT);calls.clear()
                status,fields,_=get(PARENT)
                self.assertEqual(status,503);self.assertEqual(cookies(fields),[])
                self.assertEqual(calls,[PARENT])

    def test_post_prepare_miss_does_not_run_provider_or_parent_twice(self):
        calls=[]
        def origin(path,headers):
            calls.append(path)
            if headers.get('X-UltraCache-Delivery-Phase')=='prepare':
                self.assertEqual(path,PARENT)
                self.assertEqual(headers.get('X-UltraCache-Delivery-Manifest'),MANIFEST)
                return envelope(headers,'test'),[('Cache-Control','private, no-store')]
            return (BODY,META) if path==PARENT else ('cold',[])
        def force_miss(source):
            self.assertIn('call scp_recv;',source)
            return source.replace('call scp_recv;',
                'if (req.restarts == 2) { set req.hash_always_miss = true; }\n  call scp_recv;')
        with proxy('ultracache',origin,transform=force_miss) as get:
            get(PARENT);calls.clear()
            self.assertEqual(get(PARENT)[0],503)
            self.assertEqual(calls,[PARENT])

    def test_basic_ignores_the_delivery_contract(self):
        calls=[]
        def origin(path,headers):
            self.assertIsNone(headers.get('X-UltraCache-Delivery-Authorization'))
            self.assertIsNone(headers.get('X-UltraCache-Delivery-Manifest'))
            calls.append(path)
            return 'ordinary HTML',META+[('X-UltraCache-Delivery-Authorization','origin-echo'),('X-UltraCache-Delivery-Manifest','origin-echo')]
        with proxy('basic',origin) as get:
            for _ in range(2):
                _,fields,body=get(PARENT,extra={'X-UltraCache-Delivery-Authorization':'spoof','X-UltraCache-Delivery-Manifest':'spoof'})
                self.assertEqual(body,'ordinary HTML')
                self.assertNotIn('X-UltraCache-Delivery-Authorization',dict(fields))
                self.assertNotIn('X-UltraCache-Delivery-Manifest',dict(fields))
            self.assertEqual(calls,[PARENT])

    def test_concurrent_visitors_have_request_owned_results(self):
        def origin(path,headers):
            if headers.get('X-UltraCache-Delivery-Phase')=='prepare':
                self.assertEqual(path,PARENT)
                self.assertEqual(headers.get('X-UltraCache-Delivery-Manifest'),MANIFEST)
                visitor=headers.get('Cookie','anonymous')
                return envelope(headers,visitor),[('Cache-Control','private, no-store'),
                    ('Set-Cookie','owner='+visitor+'; Path=/; HttpOnly')]
            return (BODY,META) if path==PARENT else ('cold',[])
        with proxy('ultracache',origin) as get:
            get(PARENT)
            def visit(n):
                visitor='_fbp=owner'+str(n)
                status,fields,body=get(PARENT,visitor)
                self.assertEqual(status,200)
                self.assertEqual(body,'<html>parent[private:'+visitor+'][private:'+visitor+'][nonce:'+visitor+']</html>')
                self.assertEqual(cookies(fields),['owner='+visitor+'; Path=/; HttpOnly'])
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                list(pool.map(visit,range(24)))


if __name__=='__main__':unittest.main()
