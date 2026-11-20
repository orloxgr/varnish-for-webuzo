"""Actual native child HTTP failures, distinct from application WP_Error fallback.

These fixtures send nonempty real HTTP responses or close the upstream socket.
They do not establish actual WordPress provider/application acceptance.
"""
import html
import shutil
import unittest

from test_cookie_delivery import proxy,cookies
from test_public_fragment_ttl import fields

PARENT='/http-failure-parent'
CHILD='/index.php?ultracache_esi=signed-public-child'
SIBLING='/index.php?ultracache_esi=signed-public-sibling'
SCRATCH='X-SCP-Fragment-HTTP-Failure'


def parent(child=CHILD,onerror=False):
    return '<html>before[<esi:include src="'+html.escape(child,quote=True)+'"'+(
        ' onerror="continue"' if onerror else '')+'/>]middle[<esi:include src="'+SIBLING+'"/>]tail</html>'


PARENT_FIELDS=[('Cache-Control','public, max-age=120'),('Surrogate-Control','ESI/1.0'),
    ('X-Owned-Generation','original-parent')]


@unittest.skipUnless(shutil.which('varnishd'),'Native Varnish required; fixture unqualified when skipped')
class FragmentHTTPFailures(unittest.TestCase):
    def check_public_failure(self,aggressive):
        for onerror in (False,True):
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
            with self.subTest(onerror=onerror),proxy('ultracache',origin,
                    site_settings={'aggressive':aggressive,'aggressive_ttl':60}) as get:
                self.assertEqual(get(PARENT)[2],'<html>before[healthy-1]middle[sibling]tail</html>')
                fault=True
                for _ in range(2):
                    status,headers,body=get(PARENT,extra={SCRATCH:'503'})
                    self.assertEqual(status,200);self.assertEqual(dict(headers)['X-Cache'],'HIT')
                    self.assertEqual(dict(headers)['X-Owned-Generation'],'original-parent')
                    self.assertEqual(body,'<html>before[]middle[sibling]tail</html>')
                    self.assertEqual(cookies(headers),[]);self.assertNotIn(SCRATCH,dict(headers))
                fault=False;recovered=True
                for _ in range(2):
                    status,headers,body=get(PARENT)
                    self.assertEqual(status,200);self.assertEqual(dict(headers)['X-Cache'],'HIT')
                    self.assertEqual(body,'<html>before[healthy-4]middle[sibling]tail</html>')
                self.assertEqual(counts,{PARENT:1,CHILD:4,SIBLING:1})

    def test_public_http503_is_empty_without_attributes_and_recovers(self):self.check_public_failure(False)
    def test_aggressive_cannot_store_or_embed_public_http503(self):self.check_public_failure(True)

    def test_private_nonce_and_existing_probe_non_success_children_are_omitted(self):
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
                    self.assertEqual(body,'<html>before[]middle[sibling]tail</html>')
                self.assertEqual(calls.count(PARENT),1);self.assertEqual(calls.count(SIBLING),1)
                self.assertEqual(calls.count(child),2,'Non-success child HTTP responses must not persist')

    def test_backend_fetch_error_is_empty_and_does_not_delay_recovery(self):
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
                self.assertEqual(status,200);self.assertEqual(body,'<html>before[]middle[sibling]tail</html>')
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
