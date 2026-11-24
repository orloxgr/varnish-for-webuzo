"""Owned actual-native backend actors; mock signed producer, no SQL drain claim.

Isolated transforms narrow the normal generated backend boundary for focused
authority actors. The installed adapter uses the original dynamic boundary.
"""
import base64
import hashlib
import hmac
import http.client
import json
import os
import shutil
import subprocess
import threading
import time
import unittest

from test_cookie_delivery import proxy,cookies
from test_reuse_authority import NativeReuseAuthority,TAG
from test_mutation_wire import FIELDS,request_frame,response_frame,json_header

KEY=hmac.digest(('b'*64).encode(),b'ultracache-mutation-key-v1','sha256')
TRANSACTION='9'*64


def actor_hooks(source):
    # Narrow the NORMAL generated call for isolated authority actors. No test
    # function/caller is injected; installed routing uses the original boundary.
    call='call scp_mutation_backend_fetch;'
    if source.count(call)!=1:raise AssertionError('Normal mutation boundary missing or duplicated')
    source=source.replace(call,'if (bereq.url ~ "/__owned_mutation") { '+call+' }',1)
    response='if (cookie_handoff.mutation_backend_response()) {}'
    if source.count(response)!=1:raise AssertionError('Normal receipt boundary missing or duplicated')
    return source.replace(response,'if (cookie_handoff.mutation_backend_response()) { set beresp.http.X-Actor-Receipt-Verified = "1"; }',1)


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

    def ended(self,get,scope='/'):
        # Bounded actor synchronization only; no product lifetime or cleanup TTL.
        deadline=time.monotonic()+5
        while True:
            context=self.observe(get,scope)
            if all(not e['live'] and not e['awaitingReceipt'] for e in context.get('unsettledExecutions',[])):
                return context
            if time.monotonic()>=deadline:self.fail('Owned backend task did not finalize in the actor')
            time.sleep(.01)

    def drain(self,get,context,marker,*,scope='/',status=200,extra=None):
        headers={'X-UltraCache-Private-Request-Id':marker['requestId'],
            'X-UltraCache-Private-Challenge':marker['challenge'],'X-UltraCache-Private-Drained':'1'}
        headers.update(extra or {})
        return self.call(get,'private-execution-drained',context,scope=scope,tag=None,
                         expected_status=status,extra=headers)

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
            # Join the retained opaque identity to the real failing backend,
            # without needing its deliberately unlogged signed header values.
            execution_id=shop['unsettledExecutions'][0]['requestId']
            observed=subprocess.run(['varnishlog','-n',str(get.instance),'-d','-g','vxid','-i','VCL_Log'],
                                    capture_output=True,text=True,timeout=10)
            self.assertEqual(observed.returncode,0,observed.stderr)
            self.assertIn('UltraCache backend execution rejected: reason=receipt-missing execution='+execution_id,observed.stdout)
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
            ended=self.ended(get)
            marker=ended['unsettledExecutions'][0]
            self.assertFalse(marker['live']);self.assertFalse(marker['awaitingReceipt'])
            self.assertTrue(marker['unknown'],'Backend end is not application drain')
            retired=self.drain(get,ended,marker)
            self.assertEqual(retired['scopeState'],'unbound')
            self.assertEqual(retired['unsettledExecutions'],[])

    def test_exact_drained_marker_retirement_cannot_grant_clean_or_clear_other_scope(self):
        def origin(path,headers):
            context=producer_context(self,headers,'POST',path)
            return 'actual NONE response',[('Cache-Control','private, no-store'),
                ('X-UltraCache-Mutation-Receipt',receipt(context,'none',()))]
        with proxy('ultracache',origin,transform=actor_hooks,allow_post=True) as get:
            self.register(get,'/shop/');self.register(get,'/blog/')
            initial=self.ready(get,'/shop/');blog=self.ready(get,'/blog/')
            post(get,'/shop/__owned_mutation');post(get,'/shop/__owned_mutation')
            state=self.ended(get,'/shop/');markers=state['unsettledExecutions']
            self.assertEqual(len(markers),2)
            self.assertEqual(self.drain(get,initial,markers[0],scope='/shop/',status=409)['reason'],'scope-revision-changed')
            self.assertEqual(self.drain(get,blog,markers[0],scope='/blog/',status=409)['reason'],'execution-unavailable')
            self.assertEqual(self.drain(get,state,markers[0],scope='/shop/',status=409,
                extra={'X-UltraCache-Private-Challenge':'0'*64})['reason'],'execution-challenge-changed')
            self.assertEqual(self.drain(get,state,markers[0],scope='/shop/',status=409,
                extra={'X-UltraCache-Private-Request-Id':'0'*64})['reason'],'execution-unavailable')
            self.drain(get,state,markers[0],scope='/shop/',status=400,extra={'X-UltraCache-Private-Request-Id':'short'})
            self.drain(get,state,markers[0],scope='/shop/',status=400,extra={'X-UltraCache-Private-Drained':'0'})
            first=self.drain(get,state,markers[0],scope='/shop/')
            self.assertEqual((first['requestId'],first['challenge']),
                             (markers[0]['requestId'],markers[0]['challenge']))
            self.assertEqual(first['scopeState'],'unbound')
            self.assertEqual([e['requestId'] for e in first['unsettledExecutions']],[markers[1]['requestId']])
            self.drain(get,first,markers[0],scope='/shop/',status=409)
            self.call(get,'private-authority-recover',first,scope='/shop/',tag=None,expected_status=409,
                extra={'X-UltraCache-Private-Drained':'1'})
            final=self.drain(get,first,markers[1],scope='/shop/')
            self.assertEqual(final['unsettledExecutions'],[])
            self.assertEqual(final['scopeState'],'unbound')
            unchanged=self.observe(get,'/blog/')
            self.assertEqual((unchanged['state'],unchanged['generation'],unchanged['scopeRevision']),
                             ('clean',blog['generation'],blog['scopeRevision']))
            # Even retiring all actual-drain markers is not a fresh generation.
            self.assertEqual(self.observe(get,'/shop/')['state'],'unbound')
            self.recover(get,self.observe(get,'/shop/'),'/shop/')
            self.assertEqual(self.observe(get,'/shop/')['state'],'unbound')

    def test_drained_attestation_cannot_remove_live_or_awaiting_backend(self):
        entered=threading.Event();release=threading.Event();errors=[]
        def origin(path,headers):
            context=producer_context(self,headers,'POST',path)
            entered.set();self.assertTrue(release.wait(10))
            return 'actual response',[('Cache-Control','private, no-store'),
                ('X-UltraCache-Mutation-Receipt',receipt(context,'none',()))]
        with proxy('ultracache',origin,transform=actor_hooks,allow_post=True) as get:
            self.register(get);self.ready(get)
            def writer():
                try:post(get)
                except BaseException as error:errors.append(error)
            worker=threading.Thread(target=writer);worker.start()
            try:
                self.assertTrue(entered.wait(10))
                context=self.observe(get);marker=context['unsettledExecutions'][0]
                self.assertTrue(marker['live']);self.assertTrue(marker['awaitingReceipt'])
                result=self.drain(get,context,marker,status=409)
                self.assertEqual(result['reason'],'execution-active')
                self.assertEqual(len(result['unsettledExecutions']),1)
            finally:release.set();worker.join(timeout=15)
            self.assertFalse(worker.is_alive());self.assertEqual(errors,[])
            state=self.ended(get)
            self.drain(get,state,state['unsettledExecutions'][0])
            self.assertEqual(self.observe(get)['state'],'unbound')


if __name__=='__main__':unittest.main()
