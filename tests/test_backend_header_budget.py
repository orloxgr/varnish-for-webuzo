"""Native transport fits ordinary browser requests at http_max_hdr=64.

Declared mock producer, real isolated daemon; no installed service is changed.
"""
import shutil
import subprocess
import unittest

from test_cookie_delivery import proxy
from test_cms_cookie_choices import cache
from test_cold_public_selection import Application, choices
from test_public_selection_runtime import control

BROWSER = {
    'X-Forwarded-Host':'example.test', 'X-Forwarded-Port':'443',
    'X-Real-IP':'192.0.2.12', 'X-Forwarded-For':'192.0.2.12',
    'Pragma':'no-cache', 'Cache-Control':'no-cache',
    'Sec-CH-UA':'"Chromium";v="142", "Not_A Brand";v="99"',
    'Sec-CH-UA-Mobile':'?0', 'Sec-CH-UA-Platform':'"Windows"',
    'Upgrade-Insecure-Requests':'1',
    'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/142.0.0.0 Safari/537.36',
    'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Sec-Fetch-Site':'same-origin', 'Sec-Fetch-Mode':'navigate',
    'Sec-Fetch-User':'?1', 'Sec-Fetch-Dest':'document',
    'Referer':'https://example.test/account/?from=ordinary-navigation',
    'Accept-Language':'en-US,en;q=0.9', 'Priority':'u=0, i',
    'Via':'1.1 isolated-browser-proxy',
}
EXPIRED = ('X-SCP-CMS','X-SCP-CMS-Path','X-SCP-CMS-Query',
    'X-SCP-Selection-Operation','X-SCP-Selection-Eligible','X-SCP-Selection-State',
    'X-SCP-Selection-Names','X-SCP-Selection-Scope','X-SCP-Selection-Actions',
    'X-SCP-Selection-Native-Policy')

class BrowserApplication(Application):
    def __init__(self):
        super().__init__(private=True)
        self.requests=[]
    def __call__(self,path,headers):
        self.requests.append(headers)
        return super().__call__(path,headers)

@unittest.skipUnless(shutil.which('varnishd'),'Native Varnish required')
class BackendHeaderBudget(unittest.TestCase):
    def test_browser_cold_and_warm_private_batches_fit_native_64_header_limit(self):
        app=BrowserApplication()
        with proxy('ultracache',app,policies=choices(('shared_metric','shared'),('public_variant','variant')),
                site_settings={'cms_installations':[{'cms':'wordpress','base':'/'}]},
                daemon_parameters=('http_max_hdr=64',)) as get:
            self.assertEqual(control(get,enabled=True,names='')[0],200)
            for visitor,expected in [('A','MISS'),('B','HIT'),('A','HIT')]:
                headers={**BROWSER,'X-Test-Visitor':visitor}
                status,fields,body=get('/browser','shared_metric='+visitor+'; public_variant=common',extra=headers)
                self.assertEqual((status,cache(fields)),(200,expected))
                self.assertEqual(dict(fields).get('X-UltraCache-Delivery-Outcome'),'verified')
                self.assertEqual(body.count('private:'+visitor),2)
                self.assertEqual(body.count('nonce:'+visitor),1)
            self.assertEqual([phase for _,phase,_ in app.calls],['public-select','prepare','prepare'])
            self.assertEqual([cookie for _,_,cookie in app.calls],['shared_metric=A; public_variant=common','shared_metric=B; public_variant=common','shared_metric=A; public_variant=common'])
            for received in app.requests:
                for name,value in BROWSER.items():
                    if name not in ('X-Forwarded-For','Via'):
                        self.assertEqual(received.get(name),value,name)
                for name in EXPIRED:self.assertIsNone(received.get(name),name)
                self.assertTrue(received.get('X-UltraCache-Delivery-Authorization'))
                self.assertTrue(received.get('X-UltraCache-Delivery-Request'))
                self.assertEqual(received.get('X-UltraCache-Delivery-Original-URL'),'/browser')
            for name in ('X-SCP-Vary-Accept','X-SCP-Vary-Accept-Language',
                         'X-SCP-HTML-Accept','X-SCP-Vary-Cookie','X-SCP-Vary-ESI-Cookie'):
                self.assertIsNotNone(app.requests[0].get(name),'Keep native representation inputs: '+name)

    def test_actual_repeated_prepare_is_still_rejected_without_origin_work(self):
        app=BrowserApplication()
        def repeat(source):
            marker='if (cookie_handoff.delivery_backend()) {'
            assert source.count(marker)==1
            return source.replace(marker,marker+'\nif (cookie_handoff.delivery_backend()) {}',1)
        with proxy('ultracache',app,transform=repeat,
                daemon_parameters=('http_max_hdr=64',)) as get:
            self.assertEqual(control(get,enabled=True,names='')[0],200)
            self.assertEqual(get('/repeat')[0],503)
            self.assertEqual(app.calls,[],'Never send a duplicated provider operation')
            trace=subprocess.check_output(['varnishlog','-n',str(get.instance),'-d',
                '-i','VCL_Error'],text=True,timeout=10)
            self.assertIn('UltraCache prepare cannot be repeated',trace)
            self.assertNotIn('header slots or workspace exhausted',trace)


    def test_header_capacity_is_reported_as_resource_failure_without_origin_work(self):
        app=BrowserApplication()
        def stale_slots(source):
            # Fault injection: restore the six completed scratch fields that
            # formerly occupied slots during prepare. Keep the browser intact.
            marker='if (cookie_handoff.delivery_backend()) {'
            scratch={'X-SCP-CMS':'wordpress','X-SCP-CMS-Path':'/',
                     'X-SCP-CMS-Query':'','X-SCP-Selection-Eligible':'1',
                     'X-SCP-Selection-State':'1','X-SCP-Selection-Native-Policy':'a'*64}
            fields='\n'.join('set bereq.http.'+name+' = "'+value+'";' for name,value in scratch.items())
            assert source.count(marker)==1
            return source.replace(marker,fields+'\n'+marker,1)
        with proxy('ultracache',app,transform=stale_slots,
                policies=choices(('shared_metric','shared'),('public_variant','variant')),
                site_settings={'cms_installations':[{'cms':'wordpress','base':'/'}]},
                daemon_parameters=('http_max_hdr=64',)) as get:
            self.assertEqual(control(get,enabled=True,names='')[0],200)
            status,_,_=get('/browser','shared_metric=A; public_variant=common',
                extra={**BROWSER,'X-Test-Visitor':'A'})
            self.assertEqual(status,503)
            self.assertEqual(app.calls,[],'Resource failure must precede provider side effects')
            trace=subprocess.check_output(['varnishlog','-n',str(get.instance),'-d',
                '-i','VCL_Error,LostHeader'],text=True,timeout=10)
            self.assertIn('LostHeader',trace)
            self.assertIn('UltraCache backend header slots or workspace exhausted',trace)
            self.assertNotIn('UltraCache prepare cannot be repeated',trace)

if __name__=='__main__':unittest.main()
