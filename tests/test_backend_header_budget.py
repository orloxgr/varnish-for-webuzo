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
from test_guest_publication import GUEST_POLICY, Guests, register

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
    def test_overlapping_cleanup_reload_preserves_registry_guest_and_other_site_object(self):
        guest=Guests();candidate={}
        def origin(path,headers):
            if headers.get('Host')=='other.test':
                return '<html>other site</html>',[('Cache-Control','public, max-age=120')]
            return guest(path,headers)
        def previous(source):
            candidate['source']=source
            source=source.replace('        set resp.http.X-UltraCache-VCL-Publication-Reselect-Version = "1";\n','')
            source=source.replace('        unset bereq.http.X-ESI-Original-Cookie;\n'
                                  '        unset bereq.http.X-UltraCache-ESI-Opt-In;\n'
                                  '        unset bereq.http.X-SCP-Pass;\n','')
            source=source.replace('    unset bereq.http.X-SCP-Warm-Projection-Supported;\n'
                                  '    # Hints cannot authorize','    # Hints cannot authorize')
            source=source.replace('unset bereq.http.X-UltraCache-ESI-Cookie-Check;',
                                  'unset bereq.http.X-ESI-Original-Cookie;\n'
                                  'unset bereq.http.X-UltraCache-ESI-Cookie-Check;\n'
                                  'unset bereq.http.X-UltraCache-ESI-Opt-In;')
            return source
        with proxy('ultracache',origin,transform=previous,other_profile='basic',management=True) as get:
            status,before,_=register(get)
            self.assertEqual(status,200)
            self.assertNotIn('X-UltraCache-VCL-Publication-Reselect-Version',before)
            self.assertEqual(get('/warm',extra={'Accept':'text/html'})[0],200)
            warmed=get('/warm',extra={'Accept':'text/html'})
            other_headers={'Host':'other.test','Accept':'text/html'}
            self.assertEqual(get('/other',extra=other_headers)[0],200)
            other=get('/other',extra=other_headers)
            self.assertEqual((cache(warmed[1]),cache(other[1])),('HIT','HIT'))
            objects=[dict(response[1])['X-Varnish'].split()[-1] for response in (warmed,other)]
            calls=len(guest.calls)
            try:
                get.activate('header_cleanup',candidate['source'])
            except AssertionError as error:
                # The manager can finish compilation after the CLI client's
                # reply deadline. As in the installer, verify registration;
                # never repeat the load or activate an absent candidate.
                if 'CLI communication error' not in str(error):
                    raise
                listing=get.adm('vcl.list')
                self.assertTrue(any(line.split()[-1:] == ['header_cleanup'] for line in listing.splitlines()),listing)
                get.adm('vcl.use','header_cleanup')
            get.adm('vcl.discard','boot')
            status,after,_=control(get)
            self.assertEqual(status,200)
            self.assertEqual(after['X-UltraCache-VCL-Publication-Reselect-Version'],'1')
            for name in ('X-UltraCache-VCL-Public-Selection-Epoch',
                         'X-UltraCache-VCL-Public-Selection-Native-Policy',
                         'X-UltraCache-VCL-Public-Selection-WordPress-Policy',
                         'X-UltraCache-VCL-Guest-Publication-Policy'):
                self.assertEqual(after[name],before[name],name)
            for index,(path,headers) in enumerate((('/warm',{'Accept':'text/html'}),('/other',other_headers))):
                status,fields,_=get(path,extra=headers)
                self.assertEqual((status,cache(fields)),(200,'HIT'))
                self.assertEqual(dict(fields)['X-Varnish'].split()[-1],objects[index])
            self.assertEqual(len(guest.calls),calls)

    def test_real_browser_returning_cookie_context_with_guest_and_warm_negotiation(self):
        app=BrowserApplication()
        cookies='; '.join(('shared_metric=A','public_variant=common','ultracache_esi_optin=1',
                           'wp_woocommerce_session_fixture='+('s'*64),
                           'woocommerce_items_in_cart=1','woocommerce_cart_hash='+'c'*32))
        with proxy('ultracache',app,
                policies=choices(('shared_metric','shared'),('public_variant','variant')),
                site_settings={'cms_installations':[{'cms':'wordpress','base':'/'}]},
                daemon_parameters=('http_max_hdr=64',)) as get:
            self.assertEqual(control(get,enabled=True,names='',extra={
                'X-UltraCache-Public-Selection-Guest-Version':'1',
                'X-UltraCache-Public-Selection-Guest-Policy':GUEST_POLICY})[0],200)
            for visitor,expected in (('A','MISS'),('B','HIT')):
                raw=cookies.replace('shared_metric=A','shared_metric='+visitor)
                # The captured Edge navigation has these fields; Pragma and
                # Referer are absent, and its encoding list is normalized natively.
                headers={name:value for name,value in BROWSER.items() if name not in ('Pragma','Referer')}
                headers.update({'Accept-Encoding':'gzip, deflate, br, zstd',
                                'X-UC-Live-Test':'owned-header-budget'})
                status,fields,body=get('/browser-cart',raw,
                    extra=headers)
                if status != 200:
                    trace=subprocess.run(['varnishlog','-n',str(get.instance),'-d','-g','request',
                        '-i','Error,VCL_Error,RespReason,BerespReason,LostHeader'],capture_output=True,text=True)
                    self.fail('HTTP '+str(status)+'\n'+trace.stdout[-4000:])
                self.assertEqual((status,cache(fields)),(200,expected))
                self.assertIn('private:guest',body)
            self.assertEqual([phase for _,phase,_ in app.calls],['public-select','prepare'])
            self.assertEqual([cookie for _,_,cookie in app.calls],
                             [cookies,cookies.replace('shared_metric=A','shared_metric=B')])
            for received in app.requests:
                self.assertTrue(received.get('X-UltraCache-Delivery-Authorization'))
                for name in ('X-ESI-Original-Cookie','X-UltraCache-ESI-Opt-In',
                             'X-SCP-Pass','X-SCP-Warm-Projection-Supported'):
                    self.assertIsNone(received.get(name),name)
                self.assertIn('wp_woocommerce_session_fixture='+'s'*64,received.get('Cookie',''))

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
            self.assertIsNone(app.requests[0].get('X-SCP-HTML-Accept'))
            for name in ('X-SCP-Vary-Accept','X-SCP-Vary-Accept-Language',
                         'X-SCP-Vary-Cookie','X-SCP-Vary-ESI-Cookie'):
                self.assertIsNone(app.requests[0].get(name),
                    'Owned typed prepare has no cacheable HTTP representation: '+name)

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
            # Fault injection: fill the HTTP table after request-side work.
            # Four ordinary fields retain the slots now released from typed
            # prepare, so the actual capacity-failure branch remains exercised.
            marker='if (cookie_handoff.delivery_backend()) {'
            scratch={'X-SCP-CMS':'wordpress','X-SCP-CMS-Path':'/',
                     'X-SCP-CMS-Query':'','X-SCP-Selection-Eligible':'1',
                     'X-SCP-Selection-State':'1','X-SCP-Selection-Native-Policy':'a'*64,
                     **{'X-Test-Occupied-Slot-'+str(i):'fixture' for i in range(4)}}
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
