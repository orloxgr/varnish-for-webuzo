"""Native mock transport, not actual WP identity/provider acceptance.

This isolated candidate uses authenticated lookup before rendering in the
same mock prepare invocation. Cookie presence is only a fixture visitor label;
production claims must come from actual application identity/state validation.
"""
import hashlib
import http.client
import json
from pathlib import Path
import shutil
import time
import unittest

from test_cookie_delivery import proxy,cookies
from test_delivery_continuation import BODY,META,PARENT,PRIVATE,ADAPTIVE,envelope


def exchange(get,method,path,key,token,extra=None):
    connection=http.client.HTTPConnection(*get.endpoint,timeout=10)
    try:
        headers={'Host':'example.test','X-Forwarded-Proto':'https',
            'X-UltraCache-Token':token,'X-UltraCache-Private-Key':key}
        headers.update(extra or {})
        connection.request(method,path,headers=headers)
        response=connection.getresponse()
        return response.status,response.getheaders(),response.read().decode()
    finally:connection.close()


@unittest.skipUnless(shutil.which('varnishd'),'Native Varnish required; fixture unqualified when skipped')
class PrivateFragmentTTL(unittest.TestCase):
    def test_private_object_evicted_after_lookup_uses_retained_hit_body_without_rendering_again(self):
        key=hashlib.sha256(b'fixture-authorized-stable-owner-and-state').hexdigest()
        renders=0;lookups=[];origin_calls=[];evict=False;prepares=0
        def origin(path,headers):
            nonlocal renders,prepares
            phase=headers.get('X-UltraCache-Delivery-Phase');origin_calls.append((path,phase))
            if phase=='prepare':
                prepares+=1;token=headers['X-UltraCache-Delivery-Authorization']
                status,fields,body=exchange(get,'UC-PRIVATE-GET',PRIVATE,key,token)
                lookups.append(status)
                if status==200:
                    self.assertEqual(cookies(fields),[])
                    ttl=int(dict(fields)['X-UltraCache-Private-Remaining'])
                    if evict:
                        # The actual native object disappears AFTER lookup
                        # returns but BEFORE ESI asks for its private body.
                        self.assertEqual(exchange(get,'PURGE',PRIVATE,key,token)[0],200)
                else:
                    self.assertEqual(status,404)
                    renders+=1;body='actual-render-'+str(renders);ttl=60
                def claim(result):
                    result['renderedFragments'][0]['html']=body
                    result['renderedFragments'][0]['cache']=dict(key=key,ttl=ttl,tags='widget-race')
                return envelope(headers,'request',claim),[('Cache-Control','private, no-store'),
                    ('Set-Cookie','issuer=current-'+str(prepares)+'; Path=/; HttpOnly')]
            return (BODY,META) if path==PARENT else ('cold-private',[('Cache-Control','private, no-store')])
        with proxy('ultracache',origin) as get:
            get(PARENT);origin_calls.clear()
            self.assertEqual(get(PARENT)[0],200)
            self.assertEqual(renders,1)
            evict=True
            status,fields,body=get(PARENT)
            self.assertEqual(status,200)
            self.assertEqual(body,'<html>parent[actual-render-1][actual-render-1][nonce:request]</html>')
            self.assertEqual(cookies(fields),['issuer=current-2; Path=/; HttpOnly'])
            self.assertEqual(lookups,[404,200])
            self.assertEqual(renders,1,'Eviction must refill the retained HIT bytes, never rerun the renderer')
            self.assertEqual(origin_calls,[(PARENT,'prepare'),(PARENT,'prepare')])
            evict=False
            self.assertEqual(get(PARENT)[0],200)
            self.assertEqual(lookups[-1],200)
            self.assertEqual(renders,1)

    def test_declaration_uses_existing_probe_and_owned_prepare_only(self):
        marker='X-UltraCache-Delivery-Private-Cache-Version'
        probe='/index.php?ultracache_esi_probe_private_fragment=signed-probe&esi_scope=private'
        observed=[]
        def origin(path,headers):
            phase=headers.get('X-UltraCache-Delivery-Phase')
            expected='1' if phase=='prepare' or path==probe else None
            self.assertEqual(headers.get(marker),expected)
            observed.append((path,phase,headers.get(marker)))
            if phase=='prepare':
                return envelope(headers,'prepared'),[('Cache-Control','private, no-store'),(marker,'origin-echo')]
            if path=='/probe':
                return '<esi:include src="'+probe.replace('&','&amp;')+'"/>',[
                    ('Cache-Control','public, max-age=0'),('Surrogate-Control','ESI/1.0'),(marker,'origin-echo')]
            if path==probe:return 'probe',[('Cache-Control','private, no-store'),(marker,'origin-echo')]
            return (BODY,META) if path==PARENT else ('cold-private',[('Cache-Control','private, no-store')])
        with proxy('ultracache',origin) as get:
            for path in ('/probe',PARENT,PARENT,PRIVATE):
                status,fields,_=get(path,extra={marker:'browser-spoof'})
                self.assertEqual(status,200)
                self.assertNotIn(marker,dict(fields),'Declaration must never leak from origin/objects to browser')
            self.assertIn((probe,None,'1'),observed)
            self.assertIn((PARENT,'prepare','1'),observed)

    def test_lookup_reuses_native_objects_without_renderer_or_cookie_replay_then_expires(self):
        rendered={};prepared=0;origin_calls=[];observed=[];credentials=[]
        lifetime=3
        def origin(path,headers):
            nonlocal prepared
            phase=headers.get('X-UltraCache-Delivery-Phase');origin_calls.append((path,phase))
            if phase=='prepare':
                self.assertEqual(headers.get('X-UltraCache-Delivery-Private-Cache-Version'),'1')
                prepared+=1
                visitor=headers.get('Cookie','anonymous')
                key=hashlib.sha256(('fixture-verified-state:'+visitor).encode()).hexdigest()
                token=headers['X-UltraCache-Delivery-Authorization'];credentials.append((key,token))
                status,fields,body=exchange(get,'UC-PRIVATE-GET',PRIVATE,key,token)
                observed.append(status)
                self.assertEqual(cookies(fields),[])
                if status==200:
                    self.assertEqual(dict(fields)['Cache-Control'],'private, no-store')
                    ttl=int(dict(fields)['X-UltraCache-Private-Remaining'])
                else:
                    self.assertEqual(status,404)
                    rendered[visitor]=rendered.get(visitor,0)+1
                    body='private:'+visitor+':render'+str(rendered[visitor]);ttl=lifetime
                fragment=dict(url=PRIVATE,html=body,occurrences=2)
                if ttl>0:fragment['cache']=dict(key=key,ttl=ttl,tags='widget-test')
                result=dict(schemaVersion=1,requestId=headers['X-UltraCache-Delivery-Request'],
                    originalUrl=headers['X-UltraCache-Delivery-Original-URL'],renderedFragments=[fragment,
                        dict(url=ADAPTIVE,html='nonce:'+visitor,occurrences=1)])
                return json.dumps(result),[('Cache-Control','private, no-store'),
                    ('Set-Cookie','issuer=current-'+str(prepared)+'; Path=/; HttpOnly')]
            return (BODY,META) if path==PARENT else ('cold-private',[('Cache-Control','private, no-store')])
        with proxy('ultracache',origin) as get:
            get(PARENT);origin_calls.clear()
            for visitor,expected_render in (('_fbp=A',1),('_fbp=A',1),('_fbp=B',1),('_fbp=A',1)):
                status,fields,body=get(PARENT,visitor)
                self.assertEqual(status,200)
                value='private:'+visitor+':render'+str(expected_render)
                self.assertEqual(body,'<html>parent['+value+']['+value+'][nonce:'+visitor+']</html>')
                self.assertEqual(cookies(fields),['issuer=current-'+str(prepared)+'; Path=/; HttpOnly'])
                for field in ('X-SCP-Private-Key','X-UltraCache-Private-Key','X-UltraCache-Private-Remaining'):
                    self.assertNotIn(field,dict(fields))
            self.assertEqual(observed,[404,200,404,200])
            self.assertEqual(rendered,{'_fbp=A':1,'_fbp=B':1})
            self.assertTrue(all(path==PARENT and phase=='prepare' for path,phase in origin_calls))
            count=len(origin_calls);key,token=credentials[0]
            self.assertEqual(exchange(get,'UC-PRIVATE-GET',PRIVATE,key,'wrong')[0],403)
            self.assertEqual(exchange(get,'UC-PRIVATE-GET',PRIVATE,'0'*64,token)[0],404)
            self.assertEqual(exchange(get,'UC-PRIVATE-GET',PRIVATE,key,token,
                {'X-Real-IP':'198.51.100.40'})[0],403)
            self.assertEqual(len(origin_calls),count,'Lookup failures must never call origin')
            # Existing scoped exact-URL invalidation also reaches the native
            # private object, without purging/rebuilding the shared parent.
            self.assertEqual(exchange(get,'PURGE',PRIVATE,key,token)[0],200)
            self.assertEqual(get(PARENT,'_fbp=A')[0],200)
            self.assertEqual(observed[-1],404)
            self.assertEqual(rendered,{'_fbp=A':2,'_fbp=B':1})
            self.assertEqual(get(PARENT,'_fbp=A')[0],200)
            self.assertEqual(observed[-1],200)
            time.sleep(lifetime+.2)
            self.assertEqual(get(PARENT,'_fbp=A')[0],200)
            self.assertEqual(observed[-1],404)
            self.assertEqual(rendered,{'_fbp=A':3,'_fbp=B':1})

    def test_basic_cannot_enter_private_lookup_namespace(self):
        calls=[]
        def origin(path,headers):
            self.assertIsNone(headers.get('X-UltraCache-Delivery-Private-Cache-Version'))
            calls.append(path);return 'ordinary',[]
        with proxy('basic',origin) as get:
            self.assertEqual(get('/ordinary',extra={'X-UltraCache-Delivery-Private-Cache-Version':'spoof'})[0],200)
            calls.clear()
            # Same valid site secret cannot enable the UltraCache-only protocol.
            token='b'*64 if (Path(__file__).resolve().parents[1]/'src/policy.py').is_file() else 'A'*32
            status,_,_=exchange(get,'UC-PRIVATE-GET',PRIVATE,'a'*64,token)
            self.assertEqual(status,403)
            self.assertEqual(calls,[])


if __name__=='__main__':unittest.main()
