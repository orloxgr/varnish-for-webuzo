"""Owned actual-native backend actors; mock signed producer, no SQL drain claim.

Only these isolated VCL transforms call the new backend functions. Production
VCL has no caller/capability until identity maps/recovery/admission qualify.
"""
import base64
import hashlib
import hmac
import http.client
import json
import os
import shutil
import threading
import unittest

from test_cookie_delivery import proxy,cookies
from test_reuse_authority import NativeReuseAuthority,TAG
from test_mutation_wire import FIELDS,request_frame,response_frame,json_header

KEY=hmac.digest(('b'*64).encode(),b'ultracache-mutation-key-v1','sha256')
TRANSACTION='9'*64


def actor_hooks(source):
    bind='cookie_handoff.bind(bereq.http.X-SCP-Cookie-Handoff);'
    source=source.replace(bind,bind+'''
    if (bereq.url ~ "/__owned_mutation") {
        call scp_delivery_authorization;
        if (cookie_handoff.mutation_backend_start(bereq.http.X-SCP-Site,
            bereq.http.X-SCP-Selection-Native-Policy,bereq.http.X-UltraCache-Delivery-Authorization)) {}
        unset bereq.http.X-UltraCache-Delivery-Authorization;
    }
''',1)
    return source.replace('sub scp_backend_response {','''sub scp_backend_response {
    if (cookie_handoff.mutation_backend_response()) { set beresp.http.X-Actor-Receipt-Verified = "1"; }
''',1)


def post(get,path='/__owned_mutation',extra=None):
    client=http.client.HTTPConnection(*get.endpoint,timeout=15)
    try:
        headers=dict(get.request_headers);headers.update(extra or {})
        client.request('POST',path,body='value=1',headers=headers)
        response=client.getresponse()
        return response.status,response.getheaders(),response.read()
    finally:client.close()


def producer_context(test,headers,method,url):
    test.assertNotIn('X-UltraCache-Delivery-Authorization',headers)
    test.assertNotIn('X-UltraCache-Mutation-Receipt',headers)
    encoded=headers.get('X-UltraCache-Mutation-Context')
    test.assertTrue(encoded)
    context=json.loads(base64.b64decode(encoded,validate=True))
    test.assertEqual(set(context),{'schemaVersion','proof',*FIELDS[:-2]})
    test.assertEqual(context['schemaVersion'],1)
    for field in ('requestId','challenge'):
        test.assertRegex(context[field],r'\A[0-9a-f]{64}\Z')
    test.assertNotEqual(context['requestId'],context['challenge'])
    signed=dict(context,method=method,url=url)
    test.assertEqual(hmac.new(KEY,request_frame(signed),hashlib.sha256).hexdigest(),context['proof'])
    return context


def receipt(context,state='dirty',pairs=((TAG,TRANSACTION),)):
    return json_header(dict(schemaVersion=1,state=state,
        transactions=[dict(tag=tag,transaction=transaction) for tag,transaction in pairs],
        mac=hmac.new(KEY,response_frame(context['proof'],state,pairs),hashlib.sha256).hexdigest())).decode()


@unittest.skipUnless(shutil.which('varnishd') and os.environ.get('SCP_EXPERIMENTAL_REUSE_TEST')=='1',
                     'Explicit qualified experimental native module required')
class NativeMutationBackend(unittest.TestCase):
    register=NativeReuseAuthority.register
    call=NativeReuseAuthority.call
    observe=NativeReuseAuthority.observe
    recover=NativeReuseAuthority.recover
    publish=NativeReuseAuthority.publish
    ready=NativeReuseAuthority.ready
    begin=NativeReuseAuthority.begin
    commit=NativeReuseAuthority.commit

    def test_owned_post_challenge_receipt_revokes_and_preserves_actual_response(self):
        seen=[]
        def origin(path,headers):
            context=producer_context(self,headers,'POST',path);seen.append(context)
            return 201,b'business write completed\n',[('Cache-Control','private, no-store'),
                ('Set-Cookie','actual_session=unique; Path=/; HttpOnly'),
                ('Set-Cookie','tracker=one; Path=/'),('X-UltraCache-Mutation-Receipt',receipt(context)),
                ('X-UltraCache-Mutation-Context','must-not-reach-browser')]
        with proxy('ultracache',origin,transform=actor_hooks,allow_post=True) as get:
            self.register(get);before=self.ready(get)
            status,fields,body=post(get,'/__owned_mutation?original=a%2Bb&original=c+d',extra={
                'X-UltraCache-Mutation-Context':'browser-spoof','X-UltraCache-Mutation-Receipt':'browser-spoof'})
            self.assertEqual((status,body),(201,b'business write completed\n'))
            self.assertEqual(cookies(fields),['actual_session=unique; Path=/; HttpOnly','tracker=one; Path=/'])
            self.assertEqual(dict(fields).get('X-Actor-Receipt-Verified'),'1')
            self.assertFalse(any(name.lower().startswith('x-ultracache-mutation-') for name,_ in fields))
            after=self.observe(get)
            self.assertEqual(after['state'],'dirty');self.assertEqual(after['remainingMutations'],1)
            self.assertEqual(after['scopeState'],'unbound')
            self.assertNotEqual(after['revision'],before['revision'])
            marker=after['unsettledExecutions'][0]
            self.assertEqual((marker['requestId'],marker['challenge']),(seen[0]['requestId'],seen[0]['challenge']))
            self.assertFalse(marker['awaitingReceipt']);self.assertTrue(marker['unknown'])

    def test_receipt_for_another_backend_request_is_rejected_without_cancelling_write(self):
        seen=[];replayed=[]
        def origin(path,headers):
            context=producer_context(self,headers,'POST',path);seen.append(context)
            if not replayed:replayed.append(receipt(context,'none',()))
            return 202,b'normal application result',[('Cache-Control','private, no-store'),
                ('Set-Cookie','own=value; Path=/'),('X-UltraCache-Mutation-Receipt',replayed[0])]
        with proxy('ultracache',origin,transform=actor_hooks,allow_post=True) as get:
            self.register(get)
            first=post(get);second=post(get)
            self.assertEqual((first[0],first[2]),(202,b'normal application result'))
            self.assertEqual((second[0],second[2]),(202,b'normal application result'))
            self.assertEqual(dict(first[1]).get('X-Actor-Receipt-Verified'),'1')
            self.assertNotIn('X-Actor-Receipt-Verified',dict(second[1]))
            self.assertEqual(cookies(second[1]),['own=value; Path=/'])
            self.assertNotEqual(seen[0]['requestId'],seen[1]['requestId'])
            self.assertEqual(self.observe(get)['scopeState'],'unbound')

    def test_missing_receipt_retains_only_own_scope_unknown_execution(self):
        def origin(path,headers):
            producer_context(self,headers,'POST',path)
            return 200,b'write not cancelled',[('Cache-Control','private, no-store'),('Set-Cookie','own=value; Path=/')]
        with proxy('ultracache',origin,transform=actor_hooks,allow_post=True) as get:
            self.register(get,'/shop/');self.register(get,'/blog/')
            self.ready(get,'/shop/');blog=self.ready(get,'/blog/')
            result=post(get,'/shop/__owned_mutation')
            self.assertEqual((result[0],result[2]),(200,b'write not cancelled'))
            shop=self.observe(get,'/shop/')
            self.assertEqual(shop['scopeState'],'unbound')
            self.assertTrue(shop['unsettledExecutions'][0]['unknown'])
            refused=self.call(get,'private-authority-recover',shop,scope='/shop/',tag=None,expected_status=409,
                extra={'X-UltraCache-Private-Drained':'1'})
            self.assertEqual(refused['reason'],'execution-unsettled','A boolean cannot erase an unknown execution')
            current=self.observe(get,'/blog/')
            self.assertEqual((current['state'],current['generation'],current['scopeRevision']),
                             ('clean',blog['generation'],blog['scopeRevision']))

    def test_completed_record_ack_gc_waits_for_owned_late_receipt(self):
        entered=threading.Event();release=threading.Event();result=[];errors=[]
        def origin(path,headers):
            context=producer_context(self,headers,'POST',path)
            entered.set()
            self.assertTrue(release.wait(10))
            return 'ordinary response',[('Cache-Control','private, no-store'),
                ('X-UltraCache-Mutation-Receipt',receipt(context,pairs=((TAG,done['transaction']),)))]
        with proxy('ultracache',origin,transform=actor_hooks,allow_post=True) as get:
            self.register(get);context=self.ready(get)
            tx=self.begin(get,context,'receipt-race');done=self.commit(get,tx)
            # Late receipt uses the exact completed ID, not a new mutation.
            def writer():
                try:result.append(post(get))
                except BaseException as error:errors.append(error)
            worker=threading.Thread(target=writer);worker.start()
            try:
                self.assertTrue(entered.wait(10))
                ack=self.call(get,'private-mutation-ack',done,expected_status=409,extra={
                    'X-UltraCache-Private-Transaction':done['transaction'],'X-UltraCache-Private-Lease':done['lease']})
                self.assertEqual(ack['reason'],'receipt-outstanding')
            finally:
                release.set();worker.join(timeout=15)
            self.assertFalse(worker.is_alive());self.assertEqual(errors,[])
            self.assertEqual(result[0][0],200)
            current=self.observe(get)
            self.assertEqual(current['remainingMutations'],0,'Completed receipt must not reopen a writer')
            self.call(get,'private-mutation-ack',current,extra={
                'X-UltraCache-Private-Transaction':done['transaction'],'X-UltraCache-Private-Lease':done['lease']})

    def test_backend_loss_keeps_unknown_marker_without_implicit_recovery(self):
        def origin(path,headers):
            producer_context(self,headers,'POST',path)
            return None
        with proxy('ultracache',origin,transform=actor_hooks,allow_post=True) as get:
            self.register(get);self.ready(get)
            result=post(get)
            self.assertEqual(result[0],503)
            state=self.observe(get)
            self.assertEqual(state['scopeState'],'unbound')
            self.assertTrue(state['unsettledExecutions'][0]['unknown'])
            self.call(get,'private-authority-recover',state,tag=None,expected_status=409,
                extra={'X-UltraCache-Private-Drained':'1'})


if __name__=='__main__':unittest.main()
