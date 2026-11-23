"""Experimental native multi-object lifecycle, not real provider/fast-path proof.

These fixtures deliberately still prepare on each retained request. Only the
isolated VCL calls the new methods; production VCL never enables them.
"""
import hashlib
import json
import os
import shutil
import socket
import threading
import time
import unittest
from unittest.mock import patch

from test_cookie_delivery import proxy
from test_private_fragment_ttl import exchange
from test_delivery_continuation import PARENT, PREPARE

COUNT = 14  # Exceeds the engine's per-request object-stash slots.
URLS = ['/index.php?ultracache_esi=fragment-'+str(i)+'&esi_scope=private' for i in range(COUNT)]
META = [('Cache-Control','public, max-age=120'),('Surrogate-Control','ESI/1.0'),
        ('X-UltraCache-ESI-Shared-Parent','1'),('X-UltraCache-ESI-Private-Count',str(COUNT+1)),
        ('X-UltraCache-Delivery-Prepare',PREPARE)]
BODY = '<html>'+''.join('<esi:include src="'+url.replace('&','&amp;')+'"/>' for url in [URLS[0],*URLS])+'</html>'


def qualified_vcl(source):
    fixture = '''
    if (req.esi_level == 0) {
        set resp.http.X-Fixture-Reuse = cookie_handoff.delivery_reuse_resolve();
        if (resp.http.X-Fixture-Reuse != "-1") {
            set resp.http.X-Fixture-Hits = cookie_handoff.delivery_reuse_count(true);
            set resp.http.X-Fixture-Misses = cookie_handoff.delivery_reuse_count(false);
            if (req.http.X-Fixture-Copy == "1") {
                set resp.http.X-Fixture-Copy = cookie_handoff.delivery_reuse_materialize();
            }
            if (req.http.X-Fixture-Ban == "1") {
                if (!std.ban("obj.http.X-SCP-Private-Object == 1")) { return (synth(503)); }
            }
        }
    }
'''
    return source.replace('sub scp_ultracache_deliver {','sub scp_ultracache_deliver {'+fixture)


@unittest.skipUnless(shutil.which('varnishd') and os.environ.get('SCP_EXPERIMENTAL_REUSE_TEST')=='1',
                     'Explicit matching-source experimental native module required')
class NativePrivateReuseResolver(unittest.TestCase):
    def test_default_build_cannot_enable_resolver_in_basic(self):
        module=os.environ.get('SCP_TEST_COOKIE_DISABLED_MODULE')
        self.assertTrue(module,'Qualifier must supply the separately built default DSO')
        def transform(source):
            return source.replace('sub vcl_deliver {','sub vcl_deliver { '+
                'set resp.http.X-Fixture-Reuse-Available = cookie_handoff.delivery_reuse_available();')
        with patch.dict(os.environ,{'SCP_TEST_COOKIE_MODULE':module}):
            with proxy('basic',lambda p,h:('ordinary',[('Cache-Control','public, max-age=60')]),transform=transform) as get:
                status,fields,body=get('/ordinary')
                self.assertEqual((status,body),(200,'ordinary'))
                self.assertEqual(dict(fields)['X-Fixture-Reuse-Available'],'false')

    def actor(self, short=None, uncacheable=None):
        state={'prepares':0,'ordinary':[], 'token':None}
        def key(owner,index):return hashlib.sha256((owner+':'+str(index)).encode()).hexdigest()
        def origin(path,headers):
            if headers.get('X-UltraCache-Delivery-Phase')=='prepare':
                state['prepares']+=1
                state['token']=headers['X-UltraCache-Delivery-Authorization']
                owner='B' if headers.get('Cookie')=='_fbp=B' else 'A'
                rows=[]
                for i,url in enumerate(URLS):
                    row=dict(url=url,html=owner+'-'+str(i)+'-render'+str(state['prepares'])+';',occurrences=2 if i==0 else 1)
                    if i!=uncacheable:row['cache']=dict(key=key(owner,i),ttl=2 if i==short else 60,tags='fixture-'+owner)
                    rows.append(row)
                return json.dumps(dict(schemaVersion=1,requestId=headers['X-UltraCache-Delivery-Request'],
                    originalUrl=headers['X-UltraCache-Delivery-Original-URL'],renderedFragments=rows)),[
                        ('Cache-Control','private, no-store')]
            state['ordinary'].append(path)
            return (BODY,META) if path==PARENT else ('cold',[('Cache-Control','private, no-store')])
        return state,key,origin

    def assert_plan(self,reply,hits,misses):
        status,fields,body=reply;headers=dict(fields)
        self.assertEqual(status,200)
        self.assertEqual(headers['X-Fixture-Hits'],str(hits))
        self.assertEqual(headers['X-Fixture-Misses'],str(misses))
        self.assertEqual(headers['X-Fixture-Reuse'],'1' if misses==0 else '0')
        return headers,body

    def test_fourteen_real_private_objects_resolve_in_existing_owner_and_release(self):
        state,key,origin=self.actor()
        with proxy('ultracache',origin,transform=qualified_vcl) as get:
            get(PARENT)
            self.assert_plan(get(PARENT,'_fbp=A'),0,COUNT)
            baseline=list(state['ordinary'])
            for _ in range(25):
                headers,body=self.assert_plan(get(PARENT,'_fbp=A',{'X-Fixture-Copy':'1'}),COUNT,0)
                self.assertEqual(headers['X-Fixture-Copy'],'true')
                self.assertIn('A-0-render1;A-0-render1;',body)
                self.assertNotIn('render2;',body)
            self.assertEqual(state['ordinary'],baseline,'No fragment-origin dispatch from native resolver')
            self.assertEqual(state['prepares'],26,'Fixture must not pretend it removed application bootstrap')
            # Kill the cache references after all parent owners finalized; no
            # request pin may keep an old object discoverable by a later lookup.
            for i,url in enumerate(URLS):
                self.assertEqual(exchange(get,'PURGE',url,key('A',i),state['token'])[0],200)
            self.assert_plan(get(PARENT,'_fbp=A'),0,COUNT)

    def test_partial_miss_preserves_hits_and_two_owners_never_cross(self):
        state,key,origin=self.actor()
        with proxy('ultracache',origin,transform=qualified_vcl) as get:
            get(PARENT);get(PARENT,'_fbp=A')
            self.assert_plan(get(PARENT,'_fbp=A'),COUNT,0)
            headers,body=self.assert_plan(get(PARENT,'_fbp=B'),0,COUNT)
            self.assertNotIn('A-',body);self.assertIn('B-0-',body)
            self.assert_plan(get(PARENT,'_fbp=B'),COUNT,0)
            self.assertEqual(exchange(get,'PURGE',URLS[5],key('A',5),state['token'])[0],200)
            headers,body=self.assert_plan(get(PARENT,'_fbp=A',{'X-Fixture-Copy':'1'}),COUNT-1,1)
            self.assertNotIn('B-',body)
            self.assertIn('A-0-render1;',body)
            self.assertIn('A-5-render5;',body)

    def test_materialized_native_hits_survive_ban_without_fresh_ttl(self):
        state,key,origin=self.actor(short=5)
        with proxy('ultracache',origin,transform=qualified_vcl) as get:
            get(PARENT);get(PARENT,'_fbp=A');time.sleep(.8)
            headers,body=self.assert_plan(get(PARENT,'_fbp=A',{
                'X-Fixture-Copy':'1','X-Fixture-Ban':'1'}),COUNT,0)
            self.assertEqual(headers['X-Fixture-Copy'],'true')
            self.assertIn('A-5-render1;',body,'Retained HIT bytes must feed existing local source after BAN')
            # Full original deadline passes; refilling retained bytes above must
            # not reset the original 2-second native TTL to a new prepare TTL.
            time.sleep(1.4)
            self.assert_plan(get(PARENT,'_fbp=A'),COUNT-1,1)

    def test_unclaimed_fragment_prevents_all_hit_without_reclassifying_it(self):
        state,key,origin=self.actor(uncacheable=3)
        with proxy('ultracache',origin,transform=qualified_vcl) as get:
            get(PARENT);get(PARENT,'_fbp=A')
            headers,body=self.assert_plan(get(PARENT,'_fbp=A',{'X-Fixture-Copy':'1'}),COUNT-1,1)
            self.assertIn('A-3-render2;',body)

    def test_client_abort_releases_all_multi_descriptor_owner_state(self):
        state,key,base=self.actor()
        entered=threading.Event();release=threading.Event()
        public='/fixture-blocked-public'
        def origin(path,headers):
            if path==public:
                if headers.get('X-Fixture-Block')=='1':
                    entered.set();release.wait(8)
                return 'public;',[('Cache-Control','private, no-store')]
            body,fields=base(path,headers)
            if path==PARENT and not headers.get('X-UltraCache-Delivery-Phase'):
                body=body.replace('<html>','<html><esi:include src="'+public+'"/>')
            return body,fields
        def transform(source):
            source=qualified_vcl(source)
            source=source.replace('sub vcl_recv {','sub vcl_recv { if (req.url == "/fixture-pending") { return (synth(200)); }')
            return source.replace('sub vcl_synth {','sub vcl_synth { if (req.url == "/fixture-pending") { '+
                'set resp.http.X-Fixture-Pending = cookie_handoff.pending(); return (deliver); }')
        with proxy('ultracache',origin,transform=transform) as get:
            get(PARENT);get(PARENT,'_fbp=A')
            connection=socket.create_connection(get.endpoint,timeout=8)
            try:
                headers=dict(get.request_headers,Cookie='_fbp=A',**{'X-Fixture-Copy':'1','X-Fixture-Block':'1'})
                wire='GET '+PARENT+' HTTP/1.1\r\n'+''.join(k+': '+v+'\r\n' for k,v in headers.items())+'\r\n'
                connection.sendall(wire.encode())
                received=b''
                while b'\r\n\r\n' not in received:
                    chunk=connection.recv(65536)
                    self.assertTrue(chunk,'Native response ended before headers')
                    received+=chunk
                self.assertIn(b'X-Fixture-Hits: 14\r\n',received)
                self.assertTrue(entered.wait(5),'Public child must stall AFTER native pre-header pinning')
            finally:
                connection.close();release.set()
            deadline=time.monotonic()+5
            while True:
                pending=dict(get('/fixture-pending')[1]).get('X-Fixture-Pending')
                if pending=='0':break
                if time.monotonic()>deadline:self.fail('Aborted top owner still retains continuation state')
                time.sleep(.05)
            self.assert_plan(get(PARENT,'_fbp=A'),COUNT,0)


if __name__=='__main__':unittest.main()
