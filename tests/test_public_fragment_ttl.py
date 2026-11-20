"""Native public-fragment TTL transport, separate from actual WP renderers.

The mock origin supplies the existing signed-endpoint success/error contract.
Only real native execution qualifies expiry, ESI composition or aggressive mode.
"""
import shutil
import time
import unittest

from test_cookie_delivery import proxy

FAST='/index.php?ultracache_esi=signed-public-fast'
SLOW='/index.php?ultracache_esi=signed-public-slow'
PARENT='/public-fragments'
BODY='<html>[<esi:include src="'+FAST+'"/>][<esi:include src="'+SLOW+'"/>]</html>'
SCRATCH='X-SCP-Public-Fragment'


def fields(ttl,*,error=False):
    return [('Content-Type','text/html; charset=UTF-8'),
        ('Cache-Control','private, no-store' if error else 'public, max-age=0, s-maxage='+str(ttl)),
        ('X-UltraCache-ESI-Scope','public'),('X-UltraCache-ESI-Fragment','fixture-public'),
        ('X-UltraCache-ESI-TTL',str(ttl)),('X-UltraCache-Cacheable','0' if error else '1'),
        *([('Surrogate-Control','no-store'),('X-UltraCache-ESI-Error-Contained','1')] if error else [])]


def inherited_windows(source):
    # Deterministic native inherited budgets, before the product response rules.
    needle='call scp_backend_response;'
    if source.count(needle)!=1:raise AssertionError('Expected one complete adapter response entry point')
    return source.replace(needle,'set beresp.grace = 10s; set beresp.keep = 17s; '+needle)


@unittest.skipUnless(shutil.which('varnishd'),'Native Varnish required; fixture unqualified when skipped')
class PublicFragmentTTL(unittest.TestCase):
    def check_lifetime(self,aggressive,ttl):
        counts={PARENT:0,FAST:0,SLOW:0}
        def origin(path,headers):
            self.assertIsNone(headers.get(SCRATCH))
            self.assertIsNone(headers.get('X-UltraCache-Delivery-Phase'))
            counts[path]+=1
            if path==PARENT:
                return BODY,[('Cache-Control','public, max-age=120'),('Surrogate-Control','ESI/1.0')]
            self.assertIsNone(headers.get('Cookie'),'Public ESI children must remain cookie-free')
            if path==FAST:
                if counts[path]>1:time.sleep(.1) # stale background delivery cannot masquerade as the new body
                return 'fast-'+str(counts[path]),fields(ttl)
            return 'slow-'+str(counts[path]),fields(120)
        with proxy('ultracache',origin,transform=inherited_windows,
                site_settings={'aggressive':aggressive,'aggressive_ttl':60}) as get:
            _,_,body=get(PARENT)
            self.assertEqual(body,'<html>[fast-1][slow-1]</html>')
            _,headers,body=get(PARENT)
            self.assertEqual(dict(headers)['X-Cache'],'HIT')
            self.assertEqual(body,'<html>[fast-'+('1' if ttl else '2')+'][slow-1]</html>')
            if ttl:time.sleep(4.1) # beyond ttl3, strictly inside inherited grace10/keep17
            _,headers,body=get(PARENT)
            self.assertEqual(dict(headers)['X-Cache'],'HIT','The public parent must remain reusable')
            self.assertEqual(body,'<html>[fast-'+('2' if ttl else '3')+'][slow-1]</html>')
            self.assertNotIn(SCRATCH,dict(headers))
            if ttl:
                self.assertEqual(get(PARENT)[2],'<html>[fast-2][slow-1]</html>')
            self.assertEqual(counts,{PARENT:1,FAST:2 if ttl else 3,SLOW:1})

    def test_ttl3_expires_without_inherited_grace_or_keep(self):self.check_lifetime(False,3)
    def test_aggressive_preserves_declared_ttl3_and_expiry(self):self.check_lifetime(True,3)
    def test_ttl0_renders_each_time_while_parent_and_sibling_stay_cached(self):self.check_lifetime(False,0)
    def test_aggressive_preserves_ttl0(self):self.check_lifetime(True,0)

    def check_error(self,aggressive):
        counts={PARENT:0,FAST:0,SLOW:0}
        def origin(path,headers):
            self.assertIsNone(headers.get(SCRATCH))
            counts[path]+=1
            if path==PARENT:return BODY,[('Cache-Control','public, max-age=120'),('Surrogate-Control','ESI/1.0')]
            self.assertIsNone(headers.get('Cookie'))
            if path==FAST:
                return ('fallback' if counts[path]==1 else 'recovered'),fields(30,error=counts[path]==1)
            return 'sibling',fields(120)
        with proxy('ultracache',origin,transform=inherited_windows,
                site_settings={'aggressive':aggressive,'aggressive_ttl':60}) as get:
            self.assertEqual(get(PARENT)[2],'<html>[fallback][sibling]</html>')
            for _ in range(2):
                status,headers,body=get(PARENT)
                self.assertEqual(status,200);self.assertEqual(dict(headers)['X-Cache'],'HIT')
                self.assertEqual(body,'<html>[recovered][sibling]</html>')
                self.assertNotIn(SCRATCH,dict(headers))
            self.assertEqual(counts,{PARENT:1,FAST:2,SLOW:1},'Contained fallback must never become cached success')

    def test_contained_error_is_not_replayed_and_next_success_can_cache(self):self.check_error(False)
    def test_aggressive_cannot_cache_contained_error(self):self.check_error(True)

    def test_basic_generic_and_unconfirmed_metadata_keep_existing_aggressive_behavior(self):
        for profile,path,complete in (('basic',FAST,True),('ultracache','/generic',True),('ultracache',FAST,False)):
            calls=[]
            def origin(path,headers):
                self.assertIsNone(headers.get(SCRATCH),'A browser scratch field must never reach the origin')
                calls.append(path)
                metadata=fields(0)
                if not complete:metadata=[(name,value) for name,value in metadata if name!='X-UltraCache-ESI-Fragment']
                return 'ordinary-'+str(len(calls)),metadata+[(SCRATCH,'1')]
            with self.subTest(profile=profile,path=path,complete=complete),proxy(profile,origin,transform=inherited_windows,
                    site_settings={'aggressive':True,'aggressive_ttl':60}) as get:
                for expected in ('MISS','HIT'):
                    status,headers,body=get(path,extra={SCRATCH:'1'})
                    self.assertEqual(status,200);self.assertEqual(body,'ordinary-1')
                    self.assertEqual(dict(headers)['X-Cache'],expected)
                    self.assertNotIn(SCRATCH,dict(headers),'Native scratch/echo cannot become browser metadata')
                self.assertEqual(calls,[path])


if __name__=='__main__':unittest.main()
