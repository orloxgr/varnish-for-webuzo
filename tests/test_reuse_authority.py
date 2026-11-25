"""Actual event-driven native control/CAS; explicit mock producer generations.

No SQL proof or reusable body admission is inferred from these state actors.
"""
import hashlib
import json
import os
import shutil
import unittest

from test_cookie_delivery import proxy
from test_public_selection_runtime import control

TAG=hashlib.sha256(b'fixture-owner').hexdigest()
REUSE_POLICY='c'*64

@unittest.skipUnless(shutil.which('varnishd') and os.environ.get('SCP_EXPERIMENTAL_REUSE_TEST')=='1',
                     'Explicit matching-source experimental native module required')
class NativeReuseAuthority(unittest.TestCase):
    def register(self,get,scope='/',policy=REUSE_POLICY,wordpress_policy='b'*64):
        reply=control(get,enabled=True,names='',scope=scope,wordpress_policy=wordpress_policy,extra={
            'X-UltraCache-Public-Selection-Reuse-Version':'1',
            'X-UltraCache-Public-Selection-Reuse-Policy':policy})
        self.assertEqual(reply[0],200,reply)
        self.assertEqual(reply[1].get('X-UltraCache-VCL-Private-Authority-Version'),'1')
        self.assertNotIn('X-UltraCache-VCL-Delivery-Reuse-Version',reply[1],
                         'Authority transport does not advertise the unfinished zero-prepare fast path')
    def call(self,get,operation,context=None,*,scope='/',extra=None,tag=TAG,expected_status=200):
        headers={}
        if tag is not None:headers['X-UltraCache-Private-Tag']=tag
        if context:
            headers.update({'X-UltraCache-Private-Epoch':context['epoch'],
                'X-UltraCache-Private-Incarnation':context['incarnation'],
                'X-UltraCache-Private-Scope-Revision':context['scopeRevision'],
                'X-UltraCache-Private-Expected-Revision':context.get('revision','')})
        headers.update(extra or {})
        status,fields,body=control(get,operation,scope=scope,extra=headers)
        self.assertEqual(status,expected_status,(status,fields,body))
        self.assertEqual(fields.get('Content-Type'),'application/json')
        self.assertIn('no-store',fields.get('Cache-Control',''))
        result=json.loads(body)
        self.assertEqual(result['accepted'],status==200)
        return result
    def observe(self,get,scope='/'):return self.call(get,'private-authority-context',scope=scope)
    def publish(self,get,context,generation='d'*64,scope='/',status=200):
        return self.call(get,'private-generation-publish',context,scope=scope,expected_status=status,
            extra={'X-UltraCache-Private-Generation':generation})
    def ready(self,get,scope='/'):
        return self.publish(get,self.observe(get,scope),scope=scope)
    def begin(self,get,context,label):
        return self.call(get,'private-mutation-begin',context,
            extra={'X-UltraCache-Private-Transaction':hashlib.sha256(label.encode()).hexdigest()})
    def commit(self,get,context):
        return self.call(get,'private-mutation-commit',context,extra={
            'X-UltraCache-Private-Transaction':context['transaction'],'X-UltraCache-Private-Lease':context['lease']})

    def test_context_never_grants_clean_and_only_explicit_fresh_publish_does(self):
        with proxy('ultracache',lambda p,h:('ordinary',[('Cache-Control','public, max-age=60')])) as get:
            self.register(get)
            context=self.observe(get)
            self.assertEqual((context['scopeState'],context['state']),('ready','unbound'))
            self.assertEqual(self.observe(get)['revision'],context['revision'])
            self.assertNotIn('temporaryHolds',context)
            self.assertNotIn('scopeMutations',context)
            current=self.observe(get)
            self.assertEqual(current['state'],'unbound')
            self.assertEqual(self.publish(get,current)['state'],'clean')

    def test_two_writers_late_commit_and_stale_publish_cannot_restore_authority(self):
        with proxy('ultracache',lambda p,h:('ordinary',[])) as get:
            self.register(get);old=self.ready(get)
            a=self.begin(get,old,'writer-A');b=self.begin(get,a,'writer-B')
            self.assertEqual(b['remainingMutations'],2)
            b_done=self.commit(get,b)
            self.assertEqual(b_done['remainingMutations'],1)
            self.assertEqual(self.publish(get,b_done,status=409)['reason'],'mutation-active')
            a_done=self.commit(get,a)
            self.assertEqual((a_done['state'],a_done['remainingMutations']),('unbound',0))
            self.assertEqual(self.publish(get,old,status=409)['reason'],'revision-changed')
            fresh=self.publish(get,self.observe(get),'e'*64)
            late=self.commit(get,b)
            self.assertEqual(late['revision'],fresh['revision'])
            self.assertEqual(late['generation'],'e'*64)
            repeated=self.begin(get,fresh,'writer-B')
            self.assertFalse(repeated['active'],'A completed begin retry must never reopen a writer')
            self.assertEqual(repeated['revision'],fresh['revision'])

    def test_same_clean_dependency_generation_is_idempotent_without_bypassing_cas(self):
        with proxy('ultracache',lambda p,h:('ordinary',[])) as get:
            self.register(get);clean=self.ready(get)
            repeated=self.publish(get,clean,clean['generation'])
            self.assertEqual(repeated['revision'],clean['revision'])
            self.assertEqual(repeated['generation'],clean['generation'])
            changed=self.publish(get,repeated,'e'*64)
            self.assertNotEqual(changed['revision'],repeated['revision'])
            self.assertEqual(self.publish(get,clean,clean['generation'],status=409)['reason'],'revision-changed')
            self.assertEqual(self.publish(get,clean,'e'*64,status=409)['reason'],'revision-changed')
            writer=self.begin(get,changed,'same-generation-writer')
            self.assertEqual(self.publish(get,writer,'e'*64,status=409)['reason'],'mutation-active')
            self.commit(get,writer)
            self.assertEqual(self.publish(get,changed,'e'*64,status=409)['reason'],'revision-changed')
            current=self.observe(get)
            published=self.publish(get,current,'e'*64)
            self.assertEqual(published['revision'],current['revision'],'Fresh publication binds the already invalidated content revision')
            self.assertEqual(self.publish(get,published,'e'*64)['revision'],published['revision'])

    def test_ack_gc_and_tag_recreation_have_no_implicit_clean_state(self):
        with proxy('ultracache',lambda p,h:('ordinary',[])) as get:
            self.register(get);context=self.ready(get)
            transaction=self.begin(get,context,'writer');done=self.commit(get,transaction)
            self.call(get,'private-tag-retire',done,expected_status=409)
            self.call(get,'private-mutation-ack',done,extra={
                'X-UltraCache-Private-Transaction':done['transaction'],'X-UltraCache-Private-Lease':done['lease']})
            fresh=self.publish(get,self.observe(get),'e'*64)
            late=self.call(get,'private-mutation-begin',done,extra={
                'X-UltraCache-Private-Transaction':done['transaction']},expected_status=409)
            self.assertEqual(late['reason'],'revision-changed','Delayed old begin must not reopen after explicit ACK cleanup')
            self.assertEqual(self.observe(get)['revision'],fresh['revision'])
            self.call(get,'private-tag-retire',self.observe(get))
            current=self.observe(get)
            self.assertEqual(current['state'],'unbound')
            self.assertNotEqual(current['revision'],done['revision'])
            self.assertEqual(self.publish(get,done,status=409)['reason'],'revision-changed')

    def test_completed_begin_reobserved_after_publish_cannot_reopen_after_ack_gc(self):
        with proxy('ultracache',lambda p,h:('ordinary',[])) as get:
            self.register(get);context=self.ready(get)
            begun=self.begin(get,context,'late-completed-begin');done=self.commit(get,begun)
            fresh=self.publish(get,self.observe(get),'e'*64)
            retry=self.call(get,'private-mutation-begin',fresh,extra={
                'X-UltraCache-Private-Transaction':done['transaction']})
            self.assertFalse(retry['active']);self.assertEqual(retry['revision'],fresh['revision'])
            acknowledged=self.call(get,'private-mutation-ack',fresh,extra={
                'X-UltraCache-Private-Transaction':done['transaction'],'X-UltraCache-Private-Lease':done['lease']})
            self.assertNotEqual(acknowledged['revision'],retry['revision'])
            self.assertEqual((acknowledged['state'],acknowledged['generation']),('clean','e'*64))
            delayed=self.call(get,'private-mutation-begin',retry,expected_status=409,extra={
                'X-UltraCache-Private-Transaction':done['transaction']})
            self.assertEqual(delayed['reason'],'revision-changed')
            self.assertEqual(self.observe(get)['remainingMutations'],0)

    def test_scopes_isolate_identical_tags_and_bad_auth_never_reaches_operations(self):
        with proxy('ultracache',lambda p,h:('ordinary',[])) as get:
            self.register(get,'/shop/');self.register(get,'/blog/')
            shop=self.ready(get,'/shop/');blog=self.observe(get,'/blog/')
            self.assertNotEqual(shop['incarnation'],blog['incarnation'])
            self.assertEqual(blog['state'],'unbound')
            self.assertEqual(self.publish(get,shop,scope='/blog/',status=409)['reason'],'incarnation-changed')
            reply=control(get,'private-authority-context',scope='/shop/',token=False,
                extra={'X-UltraCache-Private-Tag':TAG})
            self.assertEqual(reply[0],403)
            self.assertEqual(self.observe(get,'/shop/')['revision'],shop['revision'])

    def test_new_native_epoch_rejects_old_authority_without_defaulting_to_clean(self):
        with proxy('ultracache',lambda p,h:('ordinary',[])) as get:
            self.register(get);old=self.ready(get)
        with proxy('ultracache',lambda p,h:('ordinary',[])) as get:
            self.register(get);current=self.observe(get)
            self.assertNotEqual(current['epoch'],old['epoch'])
            self.assertEqual((current['state'],current['scopeState']),('unbound','ready'))
            self.assertEqual(self.publish(get,old,status=409)['reason'],'epoch-changed')

    def test_policy_replacement_never_resurrects_old_tag_generation(self):
        with proxy('ultracache',lambda p,h:('ordinary',[])) as get:
            self.register(get);old=self.ready(get)
            self.assertEqual(self.observe(get)['scopeRevision'],old['scopeRevision'])
            self.register(get,policy='f'*64)
            current=self.observe(get)
            self.assertEqual((current['state'],current['scopeState']),('unbound','ready'))
            self.assertNotIn('generation',current)
            after=self.observe(get)
            self.assertEqual((after['state'],after['scopeState']),('unbound','ready'))
            self.assertNotIn('generation',after)
            self.assertEqual(self.publish(get,after)['state'],'clean')

    def test_wordpress_policy_replacement_cannot_reuse_old_authority_or_forget_writer(self):
        with proxy('ultracache',lambda p,h:('ordinary',[])) as get:
            self.register(get);old=self.ready(get);writer=self.begin(get,old,'old-policy-writer')
            self.assertEqual(control(get,enabled=True,names='',wordpress_policy='e'*64)[0],200)
            changed=self.call(get,'private-authority-context',expected_status=409)
            self.assertEqual(changed['reason'],'wordpress-policy-changed')
            self.register(get,wordpress_policy='e'*64)
            current=self.observe(get)
            self.assertEqual(current['remainingMutations'],1)
            self.assertEqual(self.publish(get,current,status=409)['reason'],'mutation-active')
            self.commit(get,writer)
            self.assertEqual(self.observe(get)['state'],'unbound')

if __name__=='__main__':unittest.main()
