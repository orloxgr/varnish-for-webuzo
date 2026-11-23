"""Actual native candidate ownership, optional-failure isolation and context MAC.

The mock producer does not qualify SQL drain, final metadata or full composed HIT.
"""
import base64
import hashlib
import hmac
import json
import os
import shutil
import unittest
import test_reuse_authority as authority
from test_cookie_delivery import proxy
from test_delivery_continuation import BODY,META,PARENT,PRIVATE,ADAPTIVE,envelope
from test_reuse_delivery_context import all_origin_hooks,signed_context
from test_reuse_cookie_inputs import declaration,seal_recipe,lp

KEY=hmac.digest(('b'*64).encode(),b'ultracache-delivery-reuse-key-v1','sha256')
CONTEXT_FIELDS=('siteId','canonicalHost','scope','epoch','incarnation','scopeRevision','nativePolicy',
                'wordpressPolicy','reusePolicy','publicationDigest','representation','recipeDigest')

def hooks(source):
    source=all_origin_hooks(source)
    needle='sub scp_ultracache_deliver {'
    return source.replace(needle,needle+'''
    set resp.http.X-Owned-Finalization-Context = cookie_handoff.delivery_reuse_finalize_context();
''',1)

@unittest.skipUnless(shutil.which('varnishd') and os.environ.get('SCP_EXPERIMENTAL_REUSE_TEST')=='1',
    'Matching-source experimental native module required')
class NativeReuseCandidate(unittest.TestCase):
    register=authority.NativeReuseAuthority.register
    observe=authority.NativeReuseAuthority.observe
    call=authority.NativeReuseAuthority.call
    def test_native_candidate_joins_original_and_actual_parent_with_failure_isolation(self):
        holder={};seen=[];mode=['valid']
        recipe=seal_recipe(dict(inputs=declaration(['owner']),fragments=[
            dict(url=PRIVATE,provider='cart',occurrences=2),dict(url=ADAPTIVE,provider='nonce',occurrences=1)]))
        def origin(path,headers):
            if headers.get('X-UltraCache-Delivery-Phase')=='prepare':
                self.assertEqual(headers.get('X-UltraCache-Delivery-Reuse-Candidate-Version'),'1')
                signed=signed_context(self,headers,path,'GET')
                control=self.call(holder['get'],'delivery-reuse-context',tag=None,extra={
                    'X-UltraCache-Private-Request-Id':signed['requestId'],'X-UltraCache-Private-Challenge':signed['challenge'],
                    'X-UltraCache-Private-Epoch':signed['epoch'],'X-UltraCache-Private-Incarnation':signed['incarnation'],
                    'X-UltraCache-Delivery-Reuse-Recipe':recipe['digest']})
                original=headers.get('Cookie','');value=original.split('owner=',1)[1].split(';',1)[0]
                frame=(lp('ultracache-cookie-inputs-v1')+(1000).to_bytes(4,'big')+(1).to_bytes(4,'big')+lp('owner')+
                    (0).to_bytes(4,'big')+(1).to_bytes(4,'big')+lp('owner')+(1).to_bytes(4,'big')+lp('owner')+lp(value))
                fields=('siteId','canonicalHost','scope','epoch','nativePolicy','wordpressPolicy','reusePolicy')
                evidence=hmac.new(KEY,lp('ultracache-private-identity-binding-v1')+
                    b''.join(lp(control[n]) for n in fields)+lp(frame),'sha256').hexdigest()
                candidate=dict(version=1,requestId=signed['requestId'],challenge=signed['challenge'],recipe=recipe,inputEvidence=evidence)
                if mode[0]=='bad-evidence':candidate['inputEvidence']='0'*64
                if mode[0]=='bad-request':candidate['requestId']='0'*64
                if mode[0]=='bad-recipe':candidate['recipe']=dict(recipe,digest='0'*64)
                body=json.loads(envelope(headers,'owner'))
                for f in body['renderedFragments']:f['cache']=dict(key=hashlib.sha256(f['url'].encode()).hexdigest(),ttl=120,tags='fixture')
                body['reuseCandidate']=candidate
                seen.append((control,frame,evidence))
                return json.dumps(body),[('Cache-Control','private, no-store')]
            if path==PARENT:return BODY,META
            return 'cold',[('Cache-Control','private, no-store')]
        with proxy('ultracache',origin,transform=hooks) as get:
            holder['get']=get
            self.assertEqual(get(PARENT)[0],200)
            self.register(get)
            for setting in ('valid','bad-evidence','bad-request','bad-recipe'):
                mode[0]=setting
                status,headers,body=get(PARENT,'owner=actual; _fbp=unrelated')
                self.assertEqual(status,200);self.assertIn('private:owner',body)
                header=dict(headers).get('X-Owned-Finalization-Context')
                if setting!='valid':self.assertFalse(header);continue
                self.assertTrue(header)
                context=json.loads(base64.b64decode(header,validate=True));c=context['context']
                self.assertEqual(context['requestId'],seen[-1][0]['requestId'])
                self.assertEqual(context['inputEvidence'],seen[-1][2])
                self.assertEqual(c['publicationDigest'],hashlib.sha256(b'signed+manifest%2Ftoken').hexdigest())
                frame=lp('ultracache-private-finalize-context-v1')+lp('GET')+lp(PARENT)+\
                    b''.join(lp(context[n]) for n in ('requestId','challenge','deliveryRequestId'))+\
                    b''.join(lp(c[n]) for n in CONTEXT_FIELDS)+lp(context['binding'])+lp(context['inputEvidence'])
                self.assertEqual(context['proof'],hmac.new(KEY,frame,'sha256').hexdigest())
                page=('siteId','canonicalHost','scope','epoch','nativePolicy','wordpressPolicy','reusePolicy','publicationDigest','representation','recipeDigest')
                self.assertEqual(context['binding'],hmac.new(KEY,lp('ultracache-delivery-reuse-binding-v1')+
                    b''.join(lp(c[n]) for n in page)+lp(seen[-1][1]),'sha256').hexdigest())

if __name__=='__main__':unittest.main()
