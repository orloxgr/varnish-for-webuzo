"""Actual native child HTTP failures, distinct from application WP_Error fallback.

These fixtures send nonempty real HTTP responses or close the upstream socket.
They do not establish actual WordPress provider/application acceptance.
"""
import html
import re
import shutil
import subprocess
import unittest

from test_cookie_delivery import proxy,cookies
from test_public_fragment_ttl import fields

PARENT='/http-failure-parent'
CHILD='/index.php?ultracache_esi=signed-public-child'
SIBLING='/index.php?ultracache_esi=signed-public-sibling'
SCRATCH='X-SCP-Fragment-HTTP-Failure'


def error_component(code):
    return '<span role=alert data-ultracache-fragment-http-error='+str(code)+'>Page component unavailable (HTTP '+str(code)+').</span>'


def parent(child=CHILD,onerror=False):
    return '<html>before[<esi:include src="'+html.escape(child,quote=True)+'"'+(
        ' onerror="continue"' if onerror else '')+'/>]middle[<esi:include src="'+SIBLING+'"/>]tail</html>'


PARENT_FIELDS=[('Cache-Control','public, max-age=120'),('Surrogate-Control','ESI/1.0'),
    ('X-Owned-Generation','original-parent')]


@unittest.skipUnless(shutil.which('varnishd'),'Native Varnish required; fixture unqualified when skipped')
class FragmentHTTPFailures(unittest.TestCase):
    def check_public_failure(self,aggressive,onerror):
        counts={PARENT:0,CHILD:0,SIBLING:0};fault=False;recovered=False
        def origin(path,headers):
            self.assertIsNone(headers.get(SCRATCH))
            counts[path]+=1
            if path==PARENT:return parent(onerror=onerror),PARENT_FIELDS
            self.assertIsNone(headers.get('Cookie'))
            if path==SIBLING:return 'sibling',fields(120)
            if fault:
                return 503,'RAW FAILED CHILD '+str(counts[path]),[
                    ('Cache-Control','private, no-store'),('Surrogate-Control','no-store'),
                    ('Set-Cookie','failed_child=must-not-replay; Path=/')]
            return 'healthy-'+str(counts[path]),fields(60 if recovered else 0)
        with proxy('ultracache',origin,
                site_settings={'aggressive':aggressive,'aggressive_ttl':60}) as get:
            self.assertEqual(get(PARENT)[2],'<html>before[healthy-1]middle[sibling]tail</html>')
            fault=True
            for _ in range(2):
                status,headers,body=get(PARENT,extra={SCRATCH:'503','X-Owned-Failure-Case':'failed'})
                # Parent is the cached public shell; its headers predate late
                # ESI. Successful shell HIT is not complete-content success.
                self.assertEqual(status,200);self.assertEqual(dict(headers)['X-Cache'],'HIT')
                self.assertEqual(dict(headers)['X-Owned-Generation'],'original-parent')
                self.assertEqual(body,'<html>before['+error_component(503)+']middle[sibling]tail</html>')
                self.assertEqual(cookies(headers),[]);self.assertNotIn(SCRATCH,dict(headers))
            if shutil.which('varnishlog'):
                trace=subprocess.check_output(['varnishlog','-n',str(get.instance),'-d','-g','vxid',
                    '-q','ReqURL eq "'+CHILD+'" and ReqHeader:X-Owned-Failure-Case eq "failed"',
                    '-i','ReqURL,RespStatus'],text=True)
                statuses=re.findall(r'\bRespStatus\s+(\d+)',trace)
                self.assertTrue(statuses,trace)
                self.assertEqual(statuses[-1],'503','Actual final ESI child status must not become synthetic200')
            fault=False;recovered=True
            for _ in range(2):
                status,headers,body=get(PARENT)
                self.assertEqual(status,200);self.assertEqual(dict(headers)['X-Cache'],'HIT')
                self.assertEqual(body,'<html>before[healthy-4]middle[sibling]tail</html>')
                self.assertNotIn('data-ultracache-fragment-http-error',body)
            self.assertEqual(counts,{PARENT:1,CHILD:4,SIBLING:1})

    def test_public_http503_without_onerror_is_observable_and_recovers(self):self.check_public_failure(False,False)
    def test_public_http503_with_authored_continue_is_observable_and_recovers(self):self.check_public_failure(False,True)
    def test_aggressive_cannot_store_or_hide_public_http503(self):self.check_public_failure(True,False)
    def test_aggressive_authored_continue_keeps_public_http503_observable(self):self.check_public_failure(True,True)

    def test_private_nonce_and_existing_probe_non_success_children_remain_observable(self):
        paths=[('/index.php?ultracache_esi=signed-private&esi_scope=private',403),
            ('/index.php?ultracache_esi=signed-nonce&esi_identity=wordpress',500),
            ('/index.php?ultracache_esi_probe_private_fragment=invalid&esi_scope=private',404),
            (CHILD,302),(CHILD,201)]
        for child,code in paths:
            calls=[]
            def origin(path,headers):
                self.assertIsNone(headers.get(SCRATCH));calls.append(path)
                if path==PARENT:return parent(child),PARENT_FIELDS
                if path==SIBLING:return 'sibling',fields(120)
                self.assertEqual(path,child)
                return code,'RAW NONSUCCESS '+str(code),[('Cache-Control','public, max-age=120'),
                    ('Location','/must-not-follow'),(SCRATCH,'503')]
            with self.subTest(child=child,code=code),proxy('ultracache',origin) as get:
                for expected in ('MISS','HIT'):
                    status,headers,body=get(PARENT)
                    self.assertEqual(status,200);self.assertEqual(dict(headers)['X-Cache'],expected)
                    self.assertEqual(body,'<html>before['+error_component(code)+']middle[sibling]tail</html>')
                self.assertEqual(calls.count(PARENT),1);self.assertEqual(calls.count(SIBLING),1)
                self.assertEqual(calls.count(child),2,'Non-success child HTTP responses must not persist')

    def test_backend_fetch_error_is_observable_and_does_not_delay_recovery(self):
        for aggressive in (False,True):
            fault=True;child_calls=0
            def origin(path,headers):
                nonlocal child_calls
                self.assertIsNone(headers.get(SCRATCH))
                if path==PARENT:return parent(),PARENT_FIELDS
                if path==SIBLING:return 'sibling',fields(120)
                child_calls+=1
                if fault:return None # actual upstream EOF before an HTTP response
                return 'recovered',fields(60)
            with self.subTest(aggressive=aggressive),proxy('ultracache',origin,
                    site_settings={'aggressive':aggressive,'aggressive_ttl':60}) as get:
                status,headers,body=get(PARENT)
                self.assertEqual(status,200);self.assertEqual(body,'<html>before['+error_component(503)+']middle[sibling]tail</html>')
                fault=False;before=child_calls
                status,headers,body=get(PARENT)
                self.assertEqual(status,200);self.assertEqual(dict(headers)['X-Cache'],'HIT')
                self.assertEqual(body,'<html>before[recovered]middle[sibling]tail</html>')
                self.assertEqual(child_calls,before+1)

    def test_success_200_204_and_application_fallback200_are_not_http_failures(self):
        for code,body,error in ((200,'ordinary success',False),(204,'',False),(200,'application fallback',True)):
            def origin(path,headers):
                if path==PARENT:return parent(),PARENT_FIELDS
                if path==SIBLING:return 'sibling',fields(120)
                return code,body,fields(60,error=error)+[(SCRATCH,'503')]
            with self.subTest(code=code,error=error),proxy('ultracache',origin) as get:
                for _ in range(2):
                    self.assertEqual(get(PARENT)[2],'<html>before['+body+']middle[sibling]tail</html>')

    def test_required_prepared_dependency_failure_rejects_parent_before_success_and_recovers(self):
        from test_delivery_continuation import BODY,META,PARENT as OWNED_PARENT,envelope
        calls=[];fault=503
        outcome='X-UltraCache-Delivery-Outcome'
        def origin(path,headers):
            phase=headers.get('X-UltraCache-Delivery-Phase');calls.append((path,phase))
            if phase=='prepare':
                self.assertEqual(headers.get('X-UltraCache-VCL-Delivery-Outcome-Version'),'1')
                response=[('Cache-Control','private, no-store'),(outcome,'verified')]
                if isinstance(fault,int):
                    return fault,'RAW REQUIRED DEPENDENCY FAILURE',response+[
                        ('Set-Cookie','failed_prepare=must-not-replay; Path=/')]
                if fault=='missing':
                    return envelope(headers,'incomplete',lambda value:value['renderedFragments'].pop()),response
                return envelope(headers,'prepared'),response
            return (BODY,META) if path==OWNED_PARENT else ('cold',[('Cache-Control','private, no-store')])
        with proxy('ultracache',origin) as get:
            get(OWNED_PARENT)
            for fault in (403,500,503,'missing'):
                calls.clear()
                status,headers,body=get(OWNED_PARENT,extra={outcome:'verified'})
                self.assertEqual(status,503,'Required dependency failure cannot deliver a successful composed parent')
                self.assertNotEqual(dict(headers).get(outcome),'verified')
                self.assertEqual(cookies(headers),[])
                self.assertNotIn('RAW REQUIRED DEPENDENCY FAILURE',body)
                self.assertNotIn('data-ultracache-fragment-http-error',body,
                    'Pre-header owner must reject, not substitute a successful legacy child fallback')
                self.assertEqual(calls,[(OWNED_PARENT,'prepare')])
            fault=None;calls.clear()
            status,headers,body=get(OWNED_PARENT)
            self.assertEqual(status,200);self.assertEqual(dict(headers).get(outcome),'verified')
            self.assertEqual(body,'<html>parent[private:prepared][private:prepared][nonce:prepared]</html>')
            self.assertEqual(calls,[(OWNED_PARENT,'prepare')])

    def test_late_public_failure_is_visible_beyond_verified_private_prepare(self):
        from test_delivery_continuation import BODY,META,PARENT as OWNED_PARENT,PRIVATE,ADAPTIVE,envelope
        for onerror in (False,True):
            calls=[];fault=False
            include='<esi:include src="'+CHILD+'"'+(' onerror="continue"' if onerror else '')+'/>'
            source=BODY.replace('</html>','|public['+include+']|sibling[<esi:include src="'+SIBLING+'"/>]|tail</html>')
            def origin(path,headers):
                phase=headers.get('X-UltraCache-Delivery-Phase');calls.append((path,phase))
                if phase=='prepare':
                    self.assertEqual(headers.get('X-UltraCache-VCL-Delivery-Outcome-Version'),'1')
                    return envelope(headers,'prepared'),[('Cache-Control','private, no-store'),
                        ('X-UltraCache-Delivery-Outcome','verified')]
                if path==OWNED_PARENT:return source,META
                if path==SIBLING:return 'sibling',fields(120)
                if path==CHILD:
                    if fault:return 503,'RAW LATE PUBLIC FAILURE',[('Cache-Control','private, no-store'),
                        ('Location','/must-not-follow'),('Set-Cookie','late_child=must-not-replay; Path=/')]
                    return 'healthy-public',fields(0)
                self.assertIn(path,(PRIVATE,ADAPTIVE))
                return 'cold',[('Cache-Control','private, no-store')]
            with self.subTest(onerror=onerror),proxy('ultracache',origin) as get:
                get(OWNED_PARENT);calls.clear();fault=True
                status,headers,body=get(OWNED_PARENT)
                # This verdict covers prepared private bytes only. Neither it
                # nor a cached parent shell makes the later public error OK.
                self.assertEqual(status,200);self.assertEqual(dict(headers)['X-Cache'],'HIT')
                self.assertEqual(dict(headers).get('X-UltraCache-Delivery-Outcome'),'verified')
                self.assertEqual(body,'<html>parent[private:prepared][private:prepared][nonce:prepared]|public['+
                    error_component(503)+']|sibling[sibling]|tail</html>')
                self.assertEqual(cookies(headers),[]);self.assertNotIn('Location',dict(headers))
                self.assertEqual(calls,[(OWNED_PARENT,'prepare'),(CHILD,None)])
                fault=False;calls.clear()
                recovered=get(OWNED_PARENT)
                self.assertEqual(recovered[0],200);self.assertIn('|public[healthy-public]|',recovered[2])
                self.assertNotIn('data-ultracache-fragment-http-error',recovered[2])
                self.assertEqual(calls,[(OWNED_PARENT,'prepare'),(CHILD,None)])

    def test_top_level_fragment_http_status_body_and_cookies_are_preserved(self):
        for code in (200,201,302,404,503):
            original='Original top-level '+str(code)
            def origin(path,headers):
                self.assertIsNone(headers.get(SCRATCH))
                return code,original,[('Cache-Control','private, no-store'),
                    ('Set-Cookie','top_level=authentic; Path=/'),(SCRATCH,'503')]
            with self.subTest(code=code),proxy('ultracache',origin) as get:
                status,headers,body=get(CHILD,extra={SCRATCH:'503'})
                self.assertEqual(status,code);self.assertEqual(body,original)
                self.assertEqual(cookies(headers),['top_level=authentic; Path=/'])
                self.assertNotIn(SCRATCH,dict(headers))

    def test_basic_and_generic_esi_keep_prior_behavior(self):
        for profile,child in (('basic',CHILD),('ultracache','/generic-fragment')):
            calls=[]
            def origin(path,headers):
                self.assertIsNone(headers.get(SCRATCH));calls.append(path)
                if path==PARENT:return parent(child),PARENT_FIELDS
                if path==SIBLING:return 'sibling',fields(120)
                return 503,'Generic original error',[('Cache-Control','private, no-store')]
            with self.subTest(profile=profile),proxy(profile,origin) as get:
                for _ in range(2):
                    body=get(PARENT,extra={SCRATCH:'503'})[2]
                    self.assertEqual(body,parent(child) if profile=='basic' else
                        '<html>before[Generic original error]middle[sibling]tail</html>')
                if profile=='basic':self.assertEqual(calls,[PARENT])


if __name__=='__main__':unittest.main()
