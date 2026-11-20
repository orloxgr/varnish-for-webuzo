"""Native mock transport, not actual WP identity/provider acceptance.

This unadvertised candidate uses authenticated lookup before rendering in the
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
from test_delivery_continuation import BODY,META,PARENT,PRIVATE,ADAPTIVE


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
    def test_lookup_reuses_native_objects_without_renderer_or_cookie_replay_then_expires(self):
        rendered={};prepared=0;origin_calls=[];observed=[];credentials=[]
        lifetime=3
        def origin(path,headers):
            nonlocal prepared
            phase=headers.get('X-UltraCache-Delivery-Phase');origin_calls.append((path,phase))
            if phase=='prepare':
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
        def origin(path,headers):calls.append(path);return 'ordinary',[]
        with proxy('basic',origin) as get:
            # Same valid site secret cannot enable the UltraCache-only protocol.
            token='b'*64 if (Path(__file__).resolve().parents[1]/'src/policy.py').is_file() else 'A'*32
            status,_,_=exchange(get,'UC-PRIVATE-GET',PRIVATE,'a'*64,token)
            self.assertEqual(status,403)
            self.assertEqual(calls,[])


if __name__=='__main__':unittest.main()
