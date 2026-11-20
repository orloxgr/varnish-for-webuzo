"""Real native HTTP transport with a declared mock resolver, not WCML evidence.

WordPress/provider/browser correctness is separate actual-application acceptance.
No installed service is changed; all control and reload target this test daemon.
"""
import base64
import hashlib
import http.client
import json
import shutil
import socket
import threading
import time
import unittest
from urllib.parse import quote
from test_cookie_delivery import proxy,cookies

CURRENCY='wcml_client_currency'
LANGUAGE='wcml_client_currency_language'
WP_POLICY='b'*64
PRIVATE='/index.php?ultracache_esi=mock-private&esi_scope=private'


def rules(currency='variant',language='variant'):
    return dict(schemaVersion=1,rules=[dict(id='custom:'+name,match=dict(kind='exact',value=name),
        description='Declared mock resolver',action=action) for name,action in ((CURRENCY,currency),(LANGUAGE,language))])


def control(get,operation='capabilities',*,enabled=None,names=None,path=None,token=True,extra=None):
    headers=dict(get.request_headers)
    headers.update({'X-UltraCache-Contract':'2','X-UltraCache-Operation':operation,
        'X-UltraCache-Token':('b'*64 if 'X-WV-Gateway' in headers else 'A'*32) if token else 'invalid'})
    if enabled is not None:
        headers.update({'X-UltraCache-Public-Selection-Version':'1',
            'X-UltraCache-Public-Selection-Enabled':'1' if enabled else '0',
            'X-UltraCache-Public-Selection-WordPress-Policy':WP_POLICY,
            'X-UltraCache-Public-Selection-Cookies':names or CURRENCY+','+LANGUAGE})
    headers.update(extra or {})
    client=http.client.HTTPConnection(*get.endpoint,timeout=15)
    try:
        client.request('PURGE',path or '/__ultracache-vcl-contract-v2',headers=headers)
        response=client.getresponse();body=response.read()
        return response.status,dict(response.getheaders()),body
    finally:client.close()


class Resolver:
    def __init__(self,*,esi=False,ttl=120,change=None,raw=None):
        self.esi=esi;self.ttl=ttl;self.change=change;self.raw=raw;self.calls=[];self.publications={};self.renders=0
    def __call__(self,path,headers):
        phase=headers.get('X-UltraCache-Delivery-Phase')
        self.calls.append((path,phase,dict(headers)))
        if self.raw is not None:return self.raw
        if phase!='public-select':return 'ordinary public',[('Cache-Control','public, max-age=120')]
        currency='EUR' if headers.get('X-Test-Country')=='DE' else 'USD'
        visitor=headers.get('X-Test-Visitor','guest')
        key=(path,currency);now=time.monotonic()
        if key not in self.publications or self.publications[key][1]<=now:
            self.renders+=1
            body='<html>'+currency+('20' if currency=='EUR' else '10')
            if self.esi:body+='[<esi:include src="'+PRIVATE.replace('&','&amp;')+'"/>]'
            body+='</html>'
            self.publications[key]=(body,now+self.ttl)
        body,deadline=self.publications[key]
        manifest='mock-'+hashlib.sha256((path+body).encode()).hexdigest()
        actions=json.loads(headers['X-UltraCache-Delivery-Public-Selection-Actions'])
        values={CURRENCY:currency,LANGUAGE:'en'}
        updates=[dict(name=name,valueBase64=base64.b64encode(value.encode()).decode())
            for name,value in values.items() if actions.get(name)=='variant']
        count=1 if self.esi else 0
        target_headers=['Content-Type: text/html; charset=UTF-8',
            'X-UltraCache-Delivery-Prepare: /index.php?ultracache_delivery='+quote(manifest,safe=''),
            'X-UltraCache-ESI-Private-Count: '+str(count),
            'X-UltraCache-Cookie-Settings: '+WP_POLICY,'Vary: Cookie',
            'X-UltraCache-Tags: '+('product-demo' if path.startswith('/book') else 'news-demo')]
        if self.esi:target_headers+=['Surrogate-Control: ESI/1.0','X-UltraCache-ESI-Shared-Parent: 1']
        selected=dict(policyDigest=headers['X-UltraCache-Delivery-Policy'],wordpressPolicyDigest=WP_POLICY,
            cookieUpdates=updates,manifest=manifest,occurrences=count,
            publicParent=dict(generation=hashlib.sha256(body.encode()).hexdigest(),
                bodyBase64=base64.b64encode(body.encode()).decode(),freshRemaining=max(0,int(deadline-now))),
            headers=target_headers,renderedFragments=[dict(url=PRIVATE,html='owner:'+visitor,occurrences=1)] if self.esi else [])
        output=dict(schemaVersion=1,requestId=headers['X-UltraCache-Delivery-Request'],
            originalUrl=headers['X-UltraCache-Delivery-Original-URL'],selectedPublic=selected)
        if self.change:self.change(output,headers)
        return json.dumps(output),[('Content-Type','application/vnd.ultracache.delivery+json'),
            ('Cache-Control','private, no-store'),('Surrogate-Control','no-store'),
            ('X-UltraCache-Delivery-Public-Selection-Version','1'),
            ('Set-Cookie',CURRENCY+'='+currency+'; Path=/; SameSite=Lax'),
            ('Set-Cookie','owner='+visitor+'; Path=/; HttpOnly')]


@unittest.skipUnless(shutil.which('varnishd'),'Native Varnish required; skipped is not acceptance')
class PublicSelectionRuntime(unittest.TestCase):
    def declare(self,get,**kwargs):
        status,fields,_=control(get,enabled=True,**kwargs)
        self.assertEqual(status,200)
        self.assertEqual(fields['X-UltraCache-VCL-Public-Selection-Version'],'1')
        self.assertEqual(fields['X-UltraCache-VCL-Public-Selection-WordPress-Policy'],WP_POLICY)
        return fields
    def test_original_route_cold_and_warm_targets_own_cookies_and_no_second_provider(self):
        for esi in (False,True):
            resolver=Resolver(esi=esi)
            with self.subTest(esi=esi),proxy('ultracache',resolver,policies=rules()) as get:
                self.declare(get)
                for index,(country,currency,visitor,cache) in enumerate([
                    ('US','USD','A','MISS'),('DE','EUR','B','MISS'),('US','USD','C','HIT'),
                    ('DE','EUR','A','HIT'),('DE','EUR','B','HIT')]):
                    stale=CURRENCY+'=USD; tracking=preserved' if country=='DE' else None
                    status,fields,body=get('/book/?exact=a%2Bb',stale,
                        extra={'X-Test-Country':country,'X-Test-Visitor':visitor})
                    self.assertEqual(status,200);self.assertEqual(dict(fields)['X-Cache'],cache)
                    self.assertIn(currency+('20' if currency=='EUR' else '10'),body)
                    if esi:self.assertIn('owner:'+visitor,body)
                    self.assertEqual(cookies(fields),[CURRENCY+'='+currency+'; Path=/; SameSite=Lax','owner='+visitor+'; Path=/; HttpOnly'])
                    self.assertEqual(len(resolver.calls),index+1)
                    self.assertEqual(resolver.calls[-1][1],'public-select')
                    if stale:self.assertEqual(resolver.calls[-1][2]['Cookie'],stale)
                    self.assertIn('Cookie',dict(fields).get('Vary',''))
                    self.assertNotIn('X-UltraCache-Delivery-Policy',dict(fields))
                self.assertEqual(resolver.renders,2)
    def test_capabilities_declaration_is_scoped_metadata_and_plain_probe_preserves_it(self):
        resolver=Resolver()
        with proxy('ultracache',resolver,policies=rules()) as get:
            status,_,_=control(get,enabled=True,token=False);self.assertEqual(status,403)
            self.assertEqual(get('/book/')[2],'ordinary public')
            fields=self.declare(get,names=CURRENCY+','+LANGUAGE+',unknown_name')
            actions=json.loads(fields['X-UltraCache-VCL-Public-Selection-Actions'])
            self.assertEqual(actions,{CURRENCY:'variant',LANGUAGE:'variant','unknown_name':'shared'})
            status,fields,_=control(get);self.assertEqual(status,200)
            self.assertEqual(fields['X-UltraCache-VCL-Public-Selection-WordPress-Policy'],WP_POLICY)
            status,fields,_=control(get,enabled=False);self.assertEqual(status,200)
            self.assertNotIn('X-UltraCache-VCL-Public-Selection-WordPress-Policy',fields)
            self.assertEqual(get('/book/')[2],'ordinary public')
    def test_browser_cache_directives_still_select_and_hit_correct_target(self):
        resolver=Resolver()
        with proxy('ultracache',resolver,policies=rules()) as get:
            self.declare(get);self.assertEqual(get('/book/')[0],200)
            for directive in ('no-store','no-cache','max-age=0','no-cache, no-store, must-revalidate, max-age=0'):
                status,fields,body=get('/book/',extra={'Cache-Control':directive,'Pragma':'no-cache'})
                self.assertEqual(status,200);self.assertEqual(dict(fields)['X-Cache'],'HIT');self.assertIn('USD10',body)
            self.assertTrue(all(phase=='public-select' for _,phase,_ in resolver.calls))
    def test_zero_fragments_without_cookie_issuance_keeps_public_native_hit_but_private_delivery(self):
        resolver=Resolver()
        def origin(path,headers):
            body,fields=resolver(path,headers)
            return body,[(name,value) for name,value in fields if name.lower() not in ('set-cookie','set-cookie2')]
        with proxy('ultracache',origin,policies=rules()) as get:
            self.declare(get)
            for expected in ('MISS','HIT','HIT'):
                status,fields,body=get('/book/',extra={'X-Test-Country':'DE'})
                self.assertEqual(status,200);self.assertEqual(dict(fields)['X-Cache'],expected)
                self.assertIn('EUR20',body);self.assertEqual(cookies(fields),[])
                self.assertIn('private',dict(fields)['Cache-Control']);self.assertIn('no-store',dict(fields)['Cache-Control'])
            self.assertEqual(len(resolver.calls),3);self.assertEqual(resolver.renders,1)
    def test_shared_private_and_basic_keep_their_selected_native_actions(self):
        resolver=Resolver()
        with proxy('ultracache',resolver,policies=rules('shared','shared')) as get:
            actions=json.loads(self.declare(get)['X-UltraCache-VCL-Public-Selection-Actions'])
            self.assertEqual(actions,{CURRENCY:'shared',LANGUAGE:'shared'})
            self.assertEqual(get('/book/',CURRENCY+'=USD')[0],200)
            _,fields,body=get('/book/',CURRENCY+'=EUR')
            self.assertEqual(dict(fields)['X-Cache'],'HIT');self.assertEqual(body,'ordinary public')
            self.assertEqual([phase for _,phase,_ in resolver.calls],[None])
        for profile in ('basic','ultracache'):
            resolver=Resolver()
            with self.subTest(profile=profile),proxy(profile,resolver,policies=rules('private','shared')) as get:
                if profile=='ultracache':self.declare(get)
                else:
                    self.assertEqual(control(get,enabled=True)[0],400)
                    # An authenticated cleanup stays possible after UC->Basic.
                    self.assertEqual(control(get,enabled=False)[0],200)
                for value in ('USD','EUR'):
                    _,fields,_=get('/book/',CURRENCY+'='+value)
                    self.assertEqual(dict(fields)['X-Cache'],'PASS')
                self.assertEqual([phase for _,phase,_ in resolver.calls],[None,None])
    def test_raw_non_protocol_response_preserves_status_type_headers_body_and_owner_fields(self):
        resolver=Resolver(raw=(404,'actual-js-body',[('Content-Type','application/javascript'),
            ('Cache-Control','public, max-age=600'),('Set-Cookie','actual=owner; Path=/'),('X-Actual','kept')]))
        with proxy('ultracache',resolver,policies=rules()) as get:
            self.declare(get)
            for _ in range(2):
                status,fields,body=get('/actual.js',extra={'Accept':'text/html','Sec-Fetch-Dest':'document'})
                self.assertEqual(status,404);self.assertEqual(body,'actual-js-body')
                self.assertEqual(dict(fields)['Content-Type'],'application/javascript')
                self.assertEqual(dict(fields)['X-Actual'],'kept')
                self.assertEqual(cookies(fields),['actual=owner; Path=/'])
                self.assertIn('no-store',dict(fields)['Cache-Control'])
            self.assertEqual(len(resolver.calls),2)
    def test_claimed_protocol_with_wrong_bindings_or_private_target_fails_closed(self):
        mutations=[lambda o,h:o.update(requestId='forged'),lambda o,h:o.update(originalUrl='/other/'),
            lambda o,h:o['selectedPublic'].update(policyDigest='f'*64),
            lambda o,h:o['selectedPublic'].update(wordpressPolicyDigest='f'*64),
            lambda o,h:o['selectedPublic']['headers'].append('Set-Cookie: leaked=bad'),
            lambda o,h:o['selectedPublic']['publicParent'].update(generation='f'*64),
            lambda o,h:o['selectedPublic']['headers'].append('Cache-Control: private, no-store'),
            lambda o,h:o['selectedPublic']['cookieUpdates'].append(dict(name='wordpress_logged_in_demo',valueBase64='eA=='))]
        for index,mutation in enumerate(mutations):
            resolver=Resolver(change=mutation)
            with self.subTest(mutation=index),proxy('ultracache',resolver,policies=rules()) as get:
                self.declare(get)
                self.assertEqual(get('/book/')[0],503)
                self.assertEqual(len(resolver.calls),1)
    def test_target_url_tag_invalidation_expiry_and_reload_keep_native_ownership(self):
        resolver=Resolver(ttl=5)
        with proxy('ultracache',resolver,policies=rules(),management=True) as get:
            self.declare(get)
            self.assertEqual(get('/book/')[0],200);self.assertEqual(get('/news/')[0],200)
            self.assertEqual(dict(get('/book/')[1])['X-Cache'],'HIT')
            self.assertEqual(control(get,operation='exact-purge',path='/book/')[0],200)
            self.assertEqual(dict(get('/book/')[1])['X-Cache'],'MISS')
            self.assertEqual(dict(get('/news/')[1])['X-Cache'],'HIT')
            get.adm('ban','obj.http.X-UltraCache-Tags','~','product-demo')
            self.assertEqual(dict(get('/book/')[1])['X-Cache'],'MISS')
            self.assertEqual(dict(get('/news/')[1])['X-Cache'],'HIT')
            # Same native DSO: registry survives VCL reload, no declaration call.
            get.activate('selection_reload',get.source+'\n# same DSO reload\n')
            before=len(resolver.calls)
            status,fields,_=get('/book/')
            self.assertEqual(status,200);self.assertEqual(resolver.calls[-1][1],'public-select')
            self.assertEqual(len(resolver.calls),before+1)
            time.sleep(5.1)
            status,fields,_=get('/book/')
            self.assertEqual(status,200);self.assertEqual(dict(fields)['X-Cache'],'MISS')

    def test_abandoned_owned_request_and_transport_errors_release_handoffs(self):
        started=threading.Event();release=threading.Event();resolver=Resolver()
        def origin(path,headers):
            if path=='/cancel/' and headers.get('X-UltraCache-Delivery-Phase')=='public-select':
                started.set();release.wait(5)
            return resolver(path,headers)
        def diagnostic(source):
            source=source.replace('call scp_recv;','if (req.url == "/__test_selection_pending") { return (synth(299)); } call scp_recv;',1)
            return source+'\nsub vcl_synth { if (resp.status == 299) { set resp.status = 200; set resp.body = "pending=" + cookie_handoff.pending(); return (deliver); } }\n'
        with proxy('ultracache',origin,policies=rules(),transform=diagnostic) as get:
            self.declare(get)
            client=socket.create_connection(get.endpoint,timeout=5)
            try:
                request='GET /cancel/ HTTP/1.1\r\n'+''.join(name+': '+value+'\r\n' for name,value in get.request_headers.items())+'Connection: close\r\n\r\n'
                client.sendall(request.encode());self.assertTrue(started.wait(5))
            finally:client.close();release.set()
            deadline=time.monotonic()+5
            while True:
                pending=get('/__test_selection_pending')[2]
                if pending=='pending=0':break
                self.assertLess(time.monotonic(),deadline,pending);time.sleep(.02)
            resolver.change=lambda o,h:o.update(requestId='forged')
            self.assertEqual(get('/failed/')[0],503)
            self.assertEqual(get('/__test_selection_pending')[2],'pending=0')


if __name__=='__main__':unittest.main()
