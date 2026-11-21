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


def pending_diagnostic(source):
    source=source.replace('call scp_recv;','if (req.url == "/__test_selection_pending") { return (synth(299)); } call scp_recv;',1)
    return source+'\nsub vcl_synth { if (resp.status == 299) { set resp.status = 200; set resp.body = "pending=" + cookie_handoff.pending(); return (deliver); } }\n'


def rules(currency='variant',language='variant'):
    return dict(schemaVersion=1,rules=[dict(id='custom:'+name,match=dict(kind='exact',value=name),
        description='Declared mock resolver',action=action) for name,action in ((CURRENCY,currency),(LANGUAGE,language))])


def control(get,operation='capabilities',*,enabled=None,names=None,path=None,token=True,extra=None,scope='/',wordpress_policy=WP_POLICY):
    headers=dict(get.request_headers)
    headers.update({'X-UltraCache-Contract':'2','X-UltraCache-Operation':operation,
        'X-UltraCache-Token':('b'*64 if 'X-WV-Gateway' in headers else 'A'*32) if token else 'invalid'})
    if enabled is not None:
        headers.update({'X-UltraCache-Public-Selection-Version':'1',
            'X-UltraCache-Public-Selection-Enabled':'1' if enabled else '0',
            'X-UltraCache-Public-Selection-WordPress-Policy':wordpress_policy,
            'X-UltraCache-Public-Selection-Cookies':CURRENCY+','+LANGUAGE if names is None else names})
    if scope is not None:headers['X-UltraCache-Public-Selection-Scope']=scope
    headers.update(extra or {})
    client=http.client.HTTPConnection(*get.endpoint,timeout=15)
    try:
        client.request('PURGE',path or '/__ultracache-vcl-contract-v2',headers=headers)
        response=client.getresponse();body=response.read()
        return response.status,dict(response.getheaders()),body
    finally:client.close()


class Resolver:
    def __init__(self,*,esi=False,ttl=120,change=None,raw=None,scope='/',wordpress_policy=WP_POLICY):
        self.esi=esi;self.ttl=ttl;self.change=change;self.raw=raw;self.calls=[];self.publications={};self.renders=0
        self.scope=scope;self.wordpress_policy=wordpress_policy
    def __call__(self,path,headers):
        phase=headers.get('X-UltraCache-Delivery-Phase')
        self.calls.append((path,phase,dict(headers)))
        if self.raw is not None:return self.raw
        if phase!='public-select':return 'ordinary public',[('Cache-Control','public, max-age=120')]
        assert headers['X-UltraCache-Delivery-Public-Selection-Scope']==self.scope
        assert headers['X-UltraCache-Delivery-WordPress-Policy']==self.wordpress_policy
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
            'X-UltraCache-Cookie-Settings: '+self.wordpress_policy,'Vary: Cookie',
            'X-UltraCache-Tags: '+('product-demo' if path.startswith('/book') else 'news-demo')]
        if self.esi:target_headers+=['Surrogate-Control: ESI/1.0','X-UltraCache-ESI-Shared-Parent: 1']
        selected=dict(policyDigest=headers['X-UltraCache-Delivery-Policy'],wordpressPolicyDigest=self.wordpress_policy,
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
        self.assertEqual(fields['X-UltraCache-VCL-Public-Selection-WordPress-Policy'],kwargs.get('wordpress_policy',WP_POLICY))
        self.assertEqual(fields['X-UltraCache-VCL-Public-Selection-Scope'],kwargs.get('scope','/'))
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
    def test_diagnostic_canaries_use_native_cache_and_exact_invalidation_without_selection(self):
        generation=[1];calls=[];root=Resolver();shop=Resolver(scope='/shop/')
        identifier='a1'*16
        paths=[prefix+route for prefix in ('','/shop') for route in (
            '/ultracache-varnishtest/'+identifier+'/',
            '/?ultracache_varnish_canary='+identifier,
            '/wp-content/uploads/ultracache/varnishtest/canary-'+identifier+'.html')]
        def origin(path,headers):
            if path not in paths:
                return (shop if path.startswith('/shop/') else root)(path,headers)
            calls.append((path,dict(headers)))
            # An unexpected selection must fail this test, just as the real
            # early canary cannot publish a normal selectedPublic document.
            self.assertNotIn('X-UltraCache-Delivery-Phase',headers)
            return 'canary-generation-'+str(generation[0]),[('Cache-Control','public, max-age=120')]
        with proxy('ultracache',origin,policies=rules(),management=True) as get:
            self.declare(get);self.declare(get,scope='/shop/')
            for path in paths:
                with self.subTest(path=path):
                    generation[0]=1;before=len(calls)
                    for expected in ('MISS','HIT'):
                        status,fields,body=get(path)
                        self.assertEqual((status,dict(fields)['X-Cache'],body),(200,expected,'canary-generation-1'))
                    self.assertEqual(len(calls),before+1)
                    generation[0]=2
                    self.assertEqual(get(path)[2],'canary-generation-1')
                    self.assertEqual(len(calls),before+1)
                    self.assertEqual(control(get,operation='exact-purge',path=path)[0],200)
                    for expected in ('MISS','HIT'):
                        status,fields,body=get(path)
                        self.assertEqual((status,dict(fields)['X-Cache'],body),(200,expected,'canary-generation-2'))
                    self.assertEqual(len(calls),before+2)
            # Both registered application scopes still resolve real currency;
            # diagnostics do not unregister or weaken the application's policy.
            for path,resolver in (('/book/',root),('/shop/book/',shop)):
                for country,currency in (('US','USD10'),('DE','EUR20')):
                    for expected in ('MISS','HIT'):
                        status,fields,body=get(path,extra={'X-Test-Country':country})
                        self.assertEqual((status,dict(fields)['X-Cache']),(200,expected))
                        self.assertIn(currency,body)
                        self.assertEqual(resolver.calls[-1][1],'public-select')

    def test_diagnostic_canary_lookalikes_and_forged_headers_keep_application_selection(self):
        resolver=Resolver();identifier='ab'*16
        paths=('/ultracache-varnishtest/not-an-id/',
            '/ultracache-varnishtest/'+identifier+'/child/',
            '/not-ultracache-varnishtest/'+identifier+'/',
            '/?ultracache_varnish_canary='+identifier+'extra',
            '/?other_ultracache_varnish_canary='+identifier,
            '/?next=/ultracache-varnishtest/'+identifier+'/',
            '/?ultracache_varnish_canary=invalid&next=ordinary',
            '/ultracache/varnishtest/canary-'+identifier+'.html/child',
            '/ultracache/varnishtest/not-canary-'+identifier+'.html')
        with proxy('ultracache',resolver,policies=rules()) as get:
            self.declare(get)
            for path in paths:
                with self.subTest(path=path):
                    self.assertIn('USD10',get(path,extra={'X-UltraCache-Varnish-Canary':'1'})[2])
                    self.assertEqual(resolver.calls[-1][1],'public-select')

    def test_diagnostic_routing_retains_origin_private_and_not_found_responses(self):
        calls=[];identifier='cd'*16
        def origin(path,headers):
            calls.append(dict(headers))
            return 404,'canary absent',[('Cache-Control','private, no-store'),('Set-Cookie','owner=actual; Path=/')]
        with proxy('ultracache',origin,policies=rules()) as get:
            self.declare(get)
            for _ in range(2):
                status,fields,body=get('/ultracache-varnishtest/'+identifier+'/')
                self.assertEqual((status,body),(404,'canary absent'))
                self.assertNotEqual(dict(fields)['X-Cache'],'HIT')
                self.assertEqual(cookies(fields),['owner=actual; Path=/'])
            self.assertEqual(len(calls),2)
            self.assertTrue(all('X-UltraCache-Delivery-Phase' not in headers for headers in calls))

    def test_diagnostic_esi_parents_keep_native_public_and_private_composition(self):
        # Declared transport fixture, not a WordPress token/signature test.
        token='declared.'+'a'*64;resolver=Resolver();calls=[]
        public_parent='/?ultracache_esi_probe='+token
        public_fragment='/?ultracache_esi_probe_fragment='+token
        private_parent='/?ultracache_esi_probe_private='+token
        private_fragment='/?ultracache_esi_probe_private_fragment='+token+'&esi_scope=private'
        def origin(path,headers):
            if path not in (public_parent,public_fragment,private_parent,private_fragment):
                return resolver(path,headers)
            calls.append((path,dict(headers)))
            self.assertNotIn('X-UltraCache-Delivery-Phase',headers)
            if path==private_fragment:
                self.assertEqual(headers.get('X-ESI-Private-Request'),'1')
                self.assertEqual(headers.get('X-ESI-Request-Level'),'1')
                owner=headers.get('Cookie','').split('esi_session=',1)[-1].split(';',1)[0]
                return 'owner:'+owner,[('Cache-Control','private, no-store'),('X-UltraCache-ESI-Private','1')]
            if path==public_fragment:
                self.assertNotIn('Cookie',headers)
                return 'public-child',[('Cache-Control','public, max-age=120')]
            child=private_fragment if path==private_parent else public_fragment
            fields=[('Cache-Control','public, max-age=120'),('Surrogate-Control','content="ESI/1.0"')]
            if path==private_parent:fields.append(('X-UltraCache-ESI-Shared-Parent','1'))
            return '<html>[<esi:include src="'+child.replace('&','&amp;')+'"/>]</html>',fields
        with proxy('ultracache',origin,policies=rules()) as get:
            self.declare(get)
            for _ in range(2):
                self.assertEqual(get(public_parent)[2],'<html>[public-child]</html>')
            for visitor in ('A','B','A'):
                self.assertEqual(get(private_parent,'esi_session='+visitor)[2],'<html>[owner:'+visitor+']</html>')
            self.assertEqual(sum(path==public_fragment for path,_ in calls),1)
            self.assertEqual(sum(path==private_fragment for path,_ in calls),3)
            self.assertIn('EUR20',get('/ordinary/',extra={'X-Test-Country':'DE'})[2])
            self.assertEqual(resolver.calls[-1][1],'public-select')

    def test_diagnostic_esi_invalid_token_retains_error_and_lookalike_keeps_selection(self):
        resolver=Resolver();calls=[]
        def origin(path,headers):
            if path=='/?ultracache_esi_probe=invalid':
                calls.append(dict(headers))
                return 404,'invalid probe',[('Cache-Control','private, no-store')]
            return resolver(path,headers)
        with proxy('ultracache',origin,policies=rules()) as get:
            self.declare(get)
            for _ in range(2):
                status,fields,body=get('/?ultracache_esi_probe=invalid')
                self.assertEqual((status,body),(404,'invalid probe'))
                self.assertNotEqual(dict(fields)['X-Cache'],'HIT')
            self.assertEqual(len(calls),2)
            self.assertTrue(all('X-UltraCache-Delivery-Phase' not in headers for headers in calls))
            for path in ('/?other_ultracache_esi_probe='+('a'*64),
                    '/?ultracache_esi_probe_other=invalid','/?ultracache_esi_probe='):
                self.assertIn('USD10',get(path)[2])
                self.assertEqual(resolver.calls[-1][1],'public-select')

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
            self.assertNotIn('X-UltraCache-VCL-Public-Selection-Scope',fields)
            self.assertEqual(get('/book/')[2],'ordinary public')

    def test_registration_requires_normalized_scope_and_rejection_preserves_declarations(self):
        resolver=Resolver()
        with proxy('ultracache',resolver,policies=rules()) as get:
            self.declare(get)
            for scope in (None,'','shop/','/shop','//shop/','/shop/?query=1','/shop/#hash','/shop/../','/./','/shop//nested/'):
                for enabled in (True,False):
                    with self.subTest(scope=scope,enabled=enabled):
                        self.assertEqual(control(get,enabled=enabled,scope=scope)[0],400)
            self.assertEqual(control(get,scope=None)[1]['X-UltraCache-VCL-Public-Selection-Scope'],'/')
            self.assertIn('USD10',get('/book/')[2])

    def test_independent_applications_use_longest_literal_scope_and_retire_only_exact_scope(self):
        root=Resolver();shop=Resolver(scope='/shop/',wordpress_policy='c'*64)
        blog=Resolver(scope='/blog/',wordpress_policy='d'*64)
        def origin(path,headers):
            base=path.split('?',1)[0]
            resolver=shop if base=='/shop' or base.startswith('/shop/') else blog if base=='/blog' or base.startswith('/blog/') else root
            return resolver(path,headers)
        with proxy('ultracache',origin,policies=rules(),management=True) as get:
            for resolver in (root,shop,blog):self.declare(get,scope=resolver.scope,wordpress_policy=resolver.wordpress_policy)
            for path,resolver in (('/book/',root),('/shopper/',root),('/?next=/shop/',root),('/shop',shop),
                    ('/shop?next=/blog/',shop),('/shop/book/?x=/blog/',shop),('/blog/',blog)):
                with self.subTest(path=path):
                    for expected in ('MISS','HIT'):
                        status,fields,body=get(path,extra={
                            'X-UltraCache-Delivery-Public-Selection-Scope':'/forged/',
                            'X-UltraCache-VCL-Public-Selection-Scope':'/forged/'})
                        self.assertEqual(status,200);self.assertEqual(dict(fields)['X-Cache'],expected)
                        self.assertIn('USD10',body)
                        self.assertEqual(resolver.calls[-1][2]['X-UltraCache-Delivery-Public-Selection-Scope'],resolver.scope)
                        self.assertNotIn('X-UltraCache-Delivery-Public-Selection-Scope',dict(fields))
            # Same-DSO reload preserves every application's metadata.
            get.activate('scoped_reload',get.source+'\n# scoped metadata survives\n')
            self.assertEqual(dict(get('/shop/book/?x=/blog/')[1])['X-Cache'],'HIT')
            status,fields,_=control(get,scope='/blog/')
            self.assertEqual(status,200);self.assertEqual(fields['X-UltraCache-VCL-Public-Selection-WordPress-Policy'],blog.wordpress_policy)
            # Remove root only. Both children stay active; ordinary root misses
            # do not carry a child's declaration or claimed internal fields.
            self.assertEqual(control(get,enabled=False,scope='/')[0],200)
            self.assertEqual(get('/after-root-retired/')[2],'ordinary public')
            self.assertEqual(root.calls[-1][1],None)
            self.assertNotIn('X-UltraCache-Delivery-Public-Selection-Scope',root.calls[-1][2])
            self.assertEqual(dict(get('/shop/book/?x=/blog/')[1])['X-Cache'],'HIT')
            self.assertEqual(control(get,enabled=False,scope='/shop/')[0],200)
            self.assertEqual(get('/shop/after-retire/')[2],'ordinary public')
            self.assertEqual(shop.calls[-1][1],None)
            self.assertIn('USD10',get('/blog/')[2]);self.assertEqual(blog.calls[-1][1],'public-select')

    def test_empty_resolver_boundary_prepares_only_its_own_cold_parent(self):
        resolver=Resolver()
        child=Resolver(scope='/blog/',wordpress_policy='c'*64)
        def origin(path,headers):
            base=path.split('?',1)[0]
            return (child if base=='/blog' or base.startswith('/blog/') else resolver)(path,headers)
        with proxy('ultracache',origin,policies=rules()) as get:
            self.declare(get)
            fields=self.declare(get,scope='/blog/',names='',wordpress_policy='c'*64)
            self.assertEqual(json.loads(fields['X-UltraCache-VCL-Public-Selection-Actions']),{})
            for path in ('/blog','/blog/','/blog/book/?next=/shop/'):
                self.assertIn('USD10',get(path)[2])
                self.assertEqual(dict(get(path)[1])['X-Cache'],'HIT')
            self.assertEqual([phase for _,phase,_ in child.calls],['public-select']*3)
            self.assertEqual(resolver.calls,[])
            self.assertIn('USD10',get('/blogger/')[2]);self.assertEqual(resolver.calls[-1][1],'public-select')
            # No-op query and a nested application's registration preserve the
            # empty boundary. Removing a nested scope cannot remove its parent.
            self.assertEqual(control(get,scope='/blog/')[1]['X-UltraCache-VCL-Public-Selection-WordPress-Policy'],'c'*64)
            self.assertEqual(control(get,enabled=True,scope='/blog/shop/')[0],200)
            self.assertEqual(control(get,enabled=False,scope='/blog/shop/')[0],200)
            self.assertIn('USD10',get('/blog/new/')[2])
            self.assertEqual(child.calls[-1][2]['X-UltraCache-Delivery-Public-Selection-Scope'],'/blog/')
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
            self.assertEqual(dict(fields)['X-Cache'],'HIT');self.assertIn('USD10',body)
            self.assertEqual([phase for _,phase,_ in resolver.calls],['public-select'])
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

    def test_non_protocol_stream_delivers_before_origin_eof_and_releases_owner(self):
        release=threading.Event();sent=threading.Event();finished=threading.Event();calls=[]
        first=b'owned-stream-'*16384;last=b'last-owner-bytes'
        def chunks():
            try:
                yield first
                sent.set();release.wait(5)
                yield last
            finally:finished.set()
        def origin(path,headers):
            calls.append((path,dict(headers)))
            return chunks(),[('Content-Type','application/octet-stream'),('Set-Cookie','stream=owner; Path=/'),
                ('Content-Disposition','attachment; filename="actual.bin"'),('Cache-Control','public, max-age=600')]
        with proxy('ultracache',origin,policies=rules(),transform=pending_diagnostic) as get:
            self.declare(get)
            client=http.client.HTTPConnection(*get.endpoint,timeout=10)
            try:
                client.request('GET','/actual-download',headers=get.request_headers)
                response=client.getresponse();fields=response.getheaders()
                prefix=response.read(16)
                self.assertTrue(sent.wait(5))
                self.assertFalse(finished.is_set(),'Body was buffered until origin EOF instead of streaming')
                self.assertEqual(prefix,first[:16]);self.assertEqual(response.status,200)
                self.assertEqual(dict(fields)['Content-Type'],'application/octet-stream')
                self.assertEqual(dict(fields)['Content-Disposition'],'attachment; filename="actual.bin"')
                self.assertEqual(cookies(fields),['stream=owner; Path=/'])
                self.assertEqual(dict(fields)['X-Cache'],'PASS');self.assertIn('no-store',dict(fields)['Cache-Control'])
                release.set();self.assertEqual(prefix+response.read(),first+last)
            finally:release.set();client.close()
            self.assertTrue(finished.wait(5));self.assertEqual(len(calls),1)
            self.assertEqual(calls[0][1]['X-UltraCache-Delivery-Phase'],'public-select')
            deadline=time.monotonic()+5
            while True:
                pending=get('/__test_selection_pending')[2]
                if pending=='pending=0':break
                self.assertLess(time.monotonic(),deadline,pending);time.sleep(.02)

    def test_original_route_preserves_range_if_range_and_actual_partial_response(self):
        calls=[];body='0123456789abcdefghijklmnopqrstuvwxyz';etag='"actual-download"'
        def origin(path,headers):
            calls.append(dict(headers))
            fields=[('Content-Type','application/octet-stream'),('ETag',etag),
                ('Accept-Ranges','bytes'),('Set-Cookie','range=owner; Path=/')]
            if headers.get('Range')=='bytes=8-15' and headers.get('If-Range')==etag:
                return 206,body[8:16],fields+[('Content-Range','bytes 8-15/'+str(len(body)))]
            return body,fields
        with proxy('ultracache',origin,policies=rules()) as get:
            self.declare(get)
            for validator,status,expected in ((etag,206,body[8:16]),('"stale-download"',200,body)):
                extra={'Range':'bytes=8-15','If-Range':validator,
                    'If-None-Match':'"not-forwarded"','If-Modified-Since':'Wed, 21 Oct 2015 07:28:00 GMT',
                    'If-Match':'"not-forwarded"','If-Unmodified-Since':'Wed, 21 Oct 2015 07:28:00 GMT'}
                actual,fields,output=get('/actual-download',extra=extra)
                self.assertEqual(actual,status);self.assertEqual(output,expected)
                self.assertEqual(calls[-1]['Range'],'bytes=8-15');self.assertEqual(calls[-1]['If-Range'],validator)
                for name in ('If-None-Match','If-Modified-Since','If-Match','If-Unmodified-Since'):
                    self.assertNotIn(name,calls[-1])
                self.assertEqual(cookies(fields),['range=owner; Path=/'])
                self.assertEqual(dict(fields)['X-Cache'],'PASS');self.assertIn('no-store',dict(fields)['Cache-Control'])
                if status==206:self.assertEqual(dict(fields)['Content-Range'],'bytes 8-15/'+str(len(body)))
            self.assertEqual(len(calls),2)

    def test_range_selects_complete_public_snapshot_then_ranges_final_native_delivery(self):
        resolver=Resolver()
        with proxy('ultracache',resolver,policies=rules()) as get:
            self.declare(get)
            for expected in ('MISS','HIT'):
                status,fields,body=get('/book/',extra={'Range':'bytes=6-10','If-Range':'"not-a-public-validator"'})
                # A mismatching If-Range preserves the complete representation.
                self.assertEqual(status,200);self.assertEqual(body,'<html>USD10</html>')
                self.assertEqual(dict(fields)['X-Cache'],expected)
                self.assertEqual(resolver.calls[-1][2]['Range'],'bytes=6-10')
                self.assertEqual(resolver.calls[-1][2]['If-Range'],'"not-a-public-validator"')
            status,fields,body=get('/book/',extra={'Range':'bytes=6-10'})
            self.assertEqual(status,206);self.assertEqual(body,'USD10')
            self.assertEqual(dict(fields)['X-Cache'],'HIT')
            self.assertEqual(dict(fields)['Content-Range'],'bytes 6-10/'+str(len('<html>USD10</html>')))
            self.assertEqual(resolver.renders,1);self.assertEqual(len(resolver.calls),3)

    def test_abandoned_non_protocol_stream_releases_native_owner(self):
        release=threading.Event();finished=threading.Event()
        def chunks():
            try:
                yield b'owned-stream-'*16384
                release.wait(5)
                yield b'end'*65536
            finally:finished.set()
        def origin(path,headers):
            return chunks(),[('Content-Type','application/octet-stream'),('Set-Cookie','abandoned=owner; Path=/')]
        with proxy('ultracache',origin,policies=rules(),transform=pending_diagnostic) as get:
            self.declare(get)
            client=http.client.HTTPConnection(*get.endpoint,timeout=10)
            response=None
            try:
                client.request('GET','/abandoned-download',headers=get.request_headers)
                response=client.getresponse();self.assertEqual(response.read(16),b'owned-stream-own')
            finally:
                if response is not None:response.close()
                client.close();release.set()
            self.assertTrue(finished.wait(5))
            deadline=time.monotonic()+5
            while True:
                pending=get('/__test_selection_pending')[2]
                if pending=='pending=0':break
                self.assertLess(time.monotonic(),deadline,pending);time.sleep(.02)

    def test_raw_html_keeps_ordinary_public_esi_without_prepared_child_contract(self):
        calls=[]
        def origin(path,headers):
            calls.append((path,dict(headers)))
            if path=='/public-fragment/':return 'public-child',[('Cache-Control','public, max-age=120')]
            return '<html>raw[<esi:include src="/public-fragment/"/>]</html>',[
                ('Surrogate-Control','ESI/1.0'),('Set-Cookie','raw=owner; Path=/')]
        with proxy('ultracache',origin,policies=rules()) as get:
            self.declare(get)
            for _ in range(2):
                status,fields,body=get('/raw-html/')
                self.assertEqual(status,200);self.assertEqual(body,'<html>raw[public-child]</html>')
                self.assertEqual(dict(fields)['X-Cache'],'PASS')
                self.assertEqual(cookies(fields),['raw=owner; Path=/'])
            self.assertEqual([path for path,_ in calls],['/raw-html/','/public-fragment/','/raw-html/'])
            self.assertEqual(calls[0][1]['X-UltraCache-Delivery-Phase'],'public-select')
            self.assertNotIn('X-UltraCache-Delivery-Public-Selection-Scope',calls[1][1])
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
        with proxy('ultracache',origin,policies=rules(),transform=pending_diagnostic) as get:
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
