"""Owned actual-native backend actors; mock signed event producer, no SQL claim.

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
                     'Matching-source native module required')
class NativeMutationBackend(unittest.TestCase):
    register=NativeReuseAuthority.register
    call=NativeReuseAuthority.call
    observe=NativeReuseAuthority.observe
    publish=NativeReuseAuthority.publish
    ready=NativeReuseAuthority.ready
    begin=NativeReuseAuthority.begin
    commit=NativeReuseAuthority.commit

    def test_owned_post_challenge_receipt_preserves_real_event_and_actual_response(self):
        holder={}
        def origin(path,headers):
            c=producer_context(self,headers,'POST',path)
            tx=self.call(holder['get'],'private-mutation-begin',self.observe(holder['get']),extra={
                'X-UltraCache-Private-Transaction':TRANSACTION,
                'X-UltraCache-Private-Request-Id':c['requestId'],
                'X-UltraCache-Private-Challenge':c['challenge']})
            self.assertEqual(tx['remainingMutations'],1)
            return 201,b'business write completed',[('Cache-Control','private, no-store'),
                ('Set-Cookie','actual_session=unique; Path=/; HttpOnly'),('Set-Cookie','tracker=one; Path=/'),
                ('X-UltraCache-Mutation-Receipt',receipt(c)),('X-UltraCache-Mutation-Context','not-public')]
        with proxy('ultracache',origin,transform=actor_hooks,allow_post=True) as get:
            holder['get']=get;self.register(get);before=self.ready(get)
            status,fields,body=post(get,'/__owned_mutation?original=a%2Bb&original=c+d',extra={
                'X-UltraCache-Mutation-Context':'browser-spoof','X-UltraCache-Mutation-Receipt':'browser-spoof'})
            self.assertEqual((status,body),(201,b'business write completed'))
            self.assertEqual(cookies(fields),['actual_session=unique; Path=/; HttpOnly','tracker=one; Path=/'])
            self.assertEqual(dict(fields).get('X-Actor-Receipt-Verified'),'1')
            self.assertFalse(any(n.lower().startswith('x-ultracache-mutation-') for n,_ in fields))
            after=self.observe(get)
            self.assertEqual((after['state'],after['remainingMutations'],after['scopeState']),('dirty',1,'ready'))
            self.assertNotEqual(after['contentRevision'],before['contentRevision'])
            self.assertEqual(after['scopeRevision'],before['scopeRevision'])

    def test_receipt_for_another_backend_is_rejected_without_cancelling_write(self):
        seen=[];replayed=[]
        def origin(path,headers):
            c=producer_context(self,headers,'POST',path);seen.append(c)
            if not replayed:replayed.append(receipt(c,'none',()))
            return 202,b'normal result',[('Cache-Control','private, no-store'),('Set-Cookie','own=value; Path=/'),
                ('X-UltraCache-Mutation-Receipt',replayed[0])]
        with proxy('ultracache',origin,transform=actor_hooks,allow_post=True) as get:
            self.register(get);before=self.ready(get);first=post(get);second=post(get)
            self.assertEqual((first[0],first[2]),(202,b'normal result'))
            self.assertEqual((second[0],second[2]),(202,b'normal result'))
            self.assertEqual(dict(first[1]).get('X-Actor-Receipt-Verified'),'1')
            self.assertNotIn('X-Actor-Receipt-Verified',dict(second[1]))
            self.assertEqual(cookies(second[1]),['own=value; Path=/'])
            self.assertNotEqual(seen[0]['requestId'],seen[1]['requestId'])
            after=self.observe(get)
            self.assertEqual((after['contentRevision'],after['scopeRevision']),(before['contentRevision'],before['scopeRevision']))

    def test_missing_receipt_does_not_create_a_writer_or_invalidate_another_scope(self):
        def origin(path,headers):
            producer_context(self,headers,'POST',path)
            return 200,b'not cancelled',[('Cache-Control','private, no-store'),('Set-Cookie','own=value; Path=/')]
        with proxy('ultracache',origin,transform=actor_hooks,allow_post=True) as get:
            self.register(get,'/shop/');self.register(get,'/blog/')
            shop=self.ready(get,'/shop/');blog=self.ready(get,'/blog/')
            result=post(get,'/shop/__owned_mutation')
            self.assertEqual((result[0],result[2]),(200,b'not cancelled'))
            self.assertEqual(cookies(result[1]),['own=value; Path=/'])
            for scope,before in (('/shop/',shop),('/blog/',blog)):
                after=self.observe(get,scope)
                self.assertEqual((after['state'],after['generation'],after['contentRevision'],after['scopeRevision']),
                    ('clean',before['generation'],before['contentRevision'],before['scopeRevision']))
                self.assertNotIn('unsettledExecutions',after)

    def test_backend_loss_preserves_real_pending_write_without_unrelated_invalidation(self):
        for real_write in (False,True):
            with self.subTest(real_write=real_write):
                holder={}
                def origin(path,headers):
                    producer_context(self,headers,'POST',path)
                    if real_write:self.begin(holder['get'],self.observe(holder['get']),'actual-before-eof')
                    return None
                with proxy('ultracache',origin,transform=actor_hooks,allow_post=True) as get:
                    holder['get']=get;self.register(get);before=self.ready(get)
                    self.assertEqual(post(get)[0],503)
                    after=self.observe(get)
                    self.assertEqual(after['scopeRevision'],before['scopeRevision'])
                    self.assertEqual(after['remainingMutations'],int(real_write))
                    self.assertEqual(after['state'],'dirty' if real_write else 'clean')
                    self.assertNotIn('unsettledExecutions',after)

    def test_signed_dirty_receipt_cannot_create_an_unregistered_write(self):
        def origin(path,headers):
            c=producer_context(self,headers,'POST',path)
            return 'ordinary result',[('Cache-Control','private, no-store'),('X-UltraCache-Mutation-Receipt',receipt(c))]
        with proxy('ultracache',origin,transform=actor_hooks,allow_post=True) as get:
            self.register(get);before=self.ready(get);result=post(get)
            self.assertEqual(result[0],200);self.assertNotIn('X-Actor-Receipt-Verified',dict(result[1]))
            after=self.observe(get)
            self.assertEqual((after['state'],after['remainingMutations'],after['contentRevision']),('clean',0,before['contentRevision']))


if __name__=='__main__':unittest.main()
