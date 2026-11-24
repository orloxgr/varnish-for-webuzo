"""Native transport fixture for complete guest objects, not WordPress acceptance."""
import base64
import hashlib
import json
import shutil
import subprocess
import unittest
from test_cookie_delivery import proxy,cookies
from test_cold_public_selection import Application,choices
from test_public_selection_runtime import control
from test_cms_cookie_choices import cache

GUEST_POLICY='d'*64
GUEST_BODY='<html><span>empty cart</span><input value="guest-nonce"/></html>'

class Guests(Application):
    def __init__(self):
        super().__init__(private=True)
        self.change=None;self.outer=[];self.force=False;self.guest_requests=[];self.scope='/';self.formats=False;self.decline=False
    def __call__(self,path,headers):
        if self.decline or (headers.get('X-UltraCache-Delivery-Guest-Publication-Version')!='1' and not self.force):
            return super().__call__(path,headers)
        self.calls.append((path,headers.get('X-UltraCache-Delivery-Phase'),headers.get('Cookie')))
        self.guest_requests.append(dict(headers))
        assert headers.get('Cookie') is None
        bucket='avif' if 'image/avif' in headers.get('Accept','') else 'webp' if 'image/webp' in headers.get('Accept','') else 'orig'
        body=GUEST_BODY+bucket if self.formats else GUEST_BODY
        payload=dict(schemaVersion=1,requestId=headers['X-UltraCache-Delivery-Request'],
            originalUrl=headers['X-UltraCache-Delivery-Original-URL'],guestPublic=dict(
            policyDigest=headers['X-UltraCache-Delivery-Policy'],
            wordpressPolicyDigest=headers['X-UltraCache-Delivery-WordPress-Policy'],
            guestPolicyDigest=headers.get('X-UltraCache-Delivery-Guest-Publication-Policy',GUEST_POLICY),
            registryEpoch=headers['X-UltraCache-VCL-Public-Selection-Epoch'],scope=self.scope,
            manifest='guest.'+hashlib.sha256((path+body).encode()).hexdigest(),
            sourceManifest='source.signed',sourceGeneration=hashlib.sha256(b'source').hexdigest(),
            resolvedOccurrences=3,
            publicParent=dict(generation=hashlib.sha256(body.encode()).hexdigest(),
                bodyBase64=base64.b64encode(body.encode()).decode(),freshRemaining=120),
            headers=['Content-Type: text/html; charset=UTF-8','X-UltraCache-Tags: guest-test'],
            cookieDelivery='deferred'))
        if self.formats:payload['guestPublic']['headers']+=['Vary: Accept','X-UltraCache-Variant: '+bucket]
        if self.change:self.change(payload)
        return json.dumps(payload),[('Content-Type','application/vnd.ultracache.delivery+json'),
            ('Cache-Control','private, no-store'),('Surrogate-Control','no-store'),
            ('X-UltraCache-Delivery-Public-Selection-Version','1'),
            ('X-UltraCache-Delivery-Guest-Publication-Version','1'),*self.outer]


def register(get,**kwargs):
    return control(get,enabled=True,names='',extra={
        'X-UltraCache-Public-Selection-Guest-Version':'1',
        'X-UltraCache-Public-Selection-Guest-Policy':GUEST_POLICY},**kwargs)

@unittest.skipUnless(shutil.which('varnishd'),'Native Varnish required; skips are not acceptance')
class GuestPublication(unittest.TestCase):
    def test_failure_diagnostic_is_one_fixed_line_and_valid_delivery_stays_valid(self):
        app = Guests()
        app.change = lambda value: value['guestPublic']['headers'].append('Surrogate-Control: no-store, private-secret-marker')
        with proxy('ultracache', app) as get:
            self.assertEqual(register(get)[0], 200)
            self.assertEqual(get('/bad-diagnostic')[0], 503)
            app.change = None
            self.assertEqual(get('/good-diagnostic')[0], 200)
            log = subprocess.check_output(['varnishlog', '-n', str(get.instance), '-d', '-g', 'request',
                '-i', 'VCL_Log'], text=True)
            messages = [line.split('UltraCache delivery rejected: ', 1)[1] for line in log.splitlines()
                if 'UltraCache delivery rejected: ' in line]
            self.assertEqual(messages, ['stage=prepare role=guest reason=header-surrogate-control-private'])
            self.assertNotIn('private-secret-marker', '\n'.join(messages))

    def test_complete_guest_fill_then_two_independent_zero_origin_hits(self):
        app=Guests()
        with proxy('ultracache',app) as get:
            status,fields,_=register(get)
            self.assertEqual(status,200)
            self.assertEqual(fields.get('X-UltraCache-VCL-Guest-Publication-Version'),'1')
            self.assertEqual(fields.get('X-UltraCache-VCL-Guest-Publication-Policy'),GUEST_POLICY)
            first=get('/guest')
            if first[0]!=200:
                self.fail(str(app.guest_requests)+subprocess.check_output(['varnishlog','-n',str(get.instance),'-d','-g','request'],text=True)[-16000:])
            self.assertEqual((first[0],cache(first[1]),first[2]),(200,'MISS',GUEST_BODY))
            self.assertEqual(dict(first[1]).get('X-UltraCache-Guest-Publication'),'1')
            self.assertNotIn('X-UltraCache-Delivery-Outcome',dict(first[1]))
            self.assertEqual([p for _,p,_ in app.calls],['public-select'])
            get.stop_origin()
            for jar in ('fresh-A','fresh-B'):
                status,fields,body=get('/guest',extra={'X-Test-Visitor':jar})
                self.assertEqual((status,cache(fields),body),(200,'HIT',GUEST_BODY))
                self.assertEqual(dict(fields).get('X-UltraCache-Guest-Publication'),'1')
                self.assertNotIn('X-UltraCache-Delivery-Outcome',dict(fields))
                self.assertEqual(cookies(fields),[])
                self.assertFalse(any(name.startswith('X-SCP-Guest-') for name,_ in fields))
                log=subprocess.check_output(['varnishlog','-n',str(get.instance),'-d','-g','request',
                    '-q','ReqHeader:X-Test-Visitor eq "'+jar+'"','-i','Begin,ReqURL,Link,RespStatus'],text=True)
                self.assertIn('/guest',log)
                self.assertNotIn('bereq',log)
            self.assertEqual(len(app.calls),1)

    def test_all_three_warmed_representations_have_two_zero_origin_guest_hits(self):
        app=Guests();app.formats=True
        formats={'orig':'text/html','webp':'text/html,image/webp','avif':'text/html,image/avif,image/webp'}
        with proxy('ultracache',app) as get:
            self.assertEqual(register(get)[0],200)
            for bucket,accept in formats.items():
                status,fields,body=get('/formats',extra={'Accept':accept})
                self.assertEqual((status,cache(fields),body),(200,'MISS',GUEST_BODY+bucket))
            get.stop_origin()
            for owner in ('A','B'):
                for bucket,accept in formats.items():
                    status,fields,body=get('/formats',extra={'Accept':accept,'X-Test-Visitor':owner})
                    self.assertEqual((status,cache(fields),body),(200,'HIT',GUEST_BODY+bucket))
                    self.assertEqual(dict(fields).get('X-UltraCache-Guest-Publication'),'1')
            self.assertEqual(len(app.guest_requests),3)

    def test_producer_declining_guest_keeps_existing_private_outcome(self):
        app=Guests();app.decline=True
        with proxy('ultracache',app) as get:
            self.assertEqual(register(get)[0],200)
            for visitor in ('A','B'):
                status,fields,body=get('/declined',extra={'X-Test-Visitor':visitor})
                self.assertEqual(status,200);self.assertIn('private:'+visitor,body)
                self.assertNotIn('X-UltraCache-Guest-Publication',dict(fields))

    def test_guest_outcome_without_negotiation_is_rejected(self):
        app=Guests();app.force=True
        with proxy('ultracache',app) as get:
            self.assertEqual(control(get,enabled=True,names='')[0],200)
            status,fields,_=get('/not-negotiated')
            self.assertEqual(status,503)
            self.assertNotIn('X-UltraCache-Guest-Publication',dict(fields))

    def test_client_and_ordinary_origin_cannot_forge_complete_guest_provenance(self):
        def ordinary(path,headers):
            return 'ordinary public',[('Cache-Control','public, max-age=120'),
                ('X-SCP-Guest-Complete','1'),('X-SCP-Guest-Key','forged'),
                ('X-SCP-Guest-Manifest','forged'),('X-UltraCache-Guest-Publication','1')]
        with proxy('ultracache',ordinary) as get:
            for expected in ('MISS','HIT'):
                status,fields,body=get('/ordinary',extra={'X-UltraCache-Guest-Publication':'1','X-SCP-Guest-Complete':'1'})
                self.assertEqual((status,cache(fields),body),(200,expected,'ordinary public'))
                self.assertNotIn('X-UltraCache-Guest-Publication',dict(fields))
                self.assertFalse(any(name.startswith('X-SCP-Guest-') for name,_ in fields))

    def test_any_cookie_keeps_existing_owner_path_without_poisoning_guest(self):
        app=Guests()
        with proxy('ultracache',app,policies=choices(('shared_metric','shared'))) as get:
            self.assertEqual(register(get)[0],200)
            self.assertEqual(get('/guest')[2],GUEST_BODY)
            for owner in ('A','B'):
                status,fields,body=get('/guest','shared_metric='+owner,{'X-Test-Visitor':owner})
                self.assertEqual(status,200);self.assertIn('private:'+owner,body)
                self.assertEqual(dict(fields).get('X-UltraCache-Delivery-Outcome'),'verified')
                self.assertNotIn('X-UltraCache-Guest-Publication',dict(fields))
            status,fields,body=get('/guest')
            self.assertEqual((status,cache(fields),body),(200,'HIT',GUEST_BODY))
            self.assertEqual(len(app.guest_requests),1)

    def test_present_empty_cookie_and_authorization_are_not_absent(self):
        for extra,cookie in (({},''),({'Authorization':''},None)):
            app=Guests()
            with self.subTest(extra=extra,cookie=cookie),proxy('ultracache',app) as get:
                self.assertEqual(register(get)[0],200)
                status,fields,body=get('/empty',cookie,extra)
                self.assertEqual(status,200)
                self.assertNotIn('X-UltraCache-Guest-Publication',dict(fields))
                self.assertEqual(app.guest_requests,[])

    def test_internal_warm_auth_headers_do_not_disqualify_guest(self):
        app=Guests()
        with proxy('ultracache',app) as get:
            self.assertEqual(register(get)[0],200)
            status,fields,body=get('/warm',extra={'X-UltraCache-Internal-Request':'1',
                'X-UltraCache-Warm':'1','X-UltraCache-Token':'not-browser-authorization'})
            self.assertEqual((status,body),(200,GUEST_BODY))
            self.assertEqual(dict(fields).get('X-UltraCache-Guest-Publication'),'1')

    def test_guest_registration_removal_and_exact_scope_shadowing(self):
        app=Guests()
        with proxy('ultracache',app) as get:
            self.assertEqual(register(get)[0],200)
            self.assertEqual(control(get,enabled=True,names='',scope='/child/')[0],200)
            self.assertEqual(get('/root')[2],GUEST_BODY)
            status,fields,body=get('/child/page')
            self.assertEqual(status,200);self.assertNotIn('X-UltraCache-Guest-Publication',dict(fields))
            self.assertEqual(control(get,enabled=True,names='')[0],200)
            self.assertNotIn('X-UltraCache-VCL-Guest-Publication-Policy',control(get)[1])
            status,fields,body=get('/root')
            self.assertEqual(status,200);self.assertNotIn('X-UltraCache-Guest-Publication',dict(fields))

    def test_large_guest_manifest_does_not_become_an_http_metadata_header(self):
        app=Guests();app.change=lambda x:x['guestPublic'].update(manifest='guest.'+'x'*32000)
        with proxy('ultracache',app) as get:
            self.assertEqual(register(get)[0],200)
            self.assertEqual(get('/large-manifest')[0],200)
            get.stop_origin()
            status,fields,body=get('/large-manifest')
            self.assertEqual((status,cache(fields),body),(200,'HIT',GUEST_BODY))

    def test_native_url_purge_invalidates_guest_object(self):
        app=Guests()
        with proxy('ultracache',app) as get:
            self.assertEqual(register(get)[0],200)
            self.assertEqual(get('/purge')[0],200)
            self.assertEqual(cache(get('/purge')[1]),'HIT')
            self.assertEqual(control(get,operation='exact-purge',path='/purge')[0],200)
            self.assertEqual(cache(get('/purge')[1]),'MISS')
            self.assertEqual(len(app.guest_requests),2)

    def test_malformed_guest_claim_never_becomes_complete_hit(self):
        changes=[lambda x:x.update(requestId='other'),lambda x:x.update(originalUrl='/other'),
            lambda x:x['guestPublic'].update(policyDigest='0'*64),
            lambda x:x['guestPublic'].update(wordpressPolicyDigest='0'*64),
            lambda x:x['guestPublic'].update(guestPolicyDigest='0'*64),
            lambda x:x['guestPublic'].update(registryEpoch='0'*64),
            lambda x:x['guestPublic'].update(scope='/other/'),
            lambda x:x['guestPublic'].update(sourceGeneration='bad'),
            lambda x:x['guestPublic'].update(sourceManifest=''),
            lambda x:x['guestPublic'].update(resolvedOccurrences=True),
            lambda x:x['guestPublic'].update(cookieDelivery='unsafe'),
            lambda x:x['guestPublic'].update(unexpected=1),
            lambda x:x['guestPublic']['publicParent'].update(generation='0'*64),
            lambda x:x['guestPublic']['headers'].append('Set-Cookie: owner=warm'),
            lambda x:x['guestPublic']['headers'].append('X-UltraCache-ESI-Private-Count: 0')]
        for i,change in enumerate(changes):
            app=Guests();app.change=change
            with self.subTest(case=i),proxy('ultracache',app) as get:
                self.assertEqual(register(get)[0],200)
                status,fields,_=get('/bad')
                self.assertEqual(status,503)
                self.assertNotIn('X-UltraCache-Guest-Publication',dict(fields))

    def test_unresolved_esi_and_outer_cookie_are_rejected(self):
        def unresolved(payload):
            raw=b'<html><esi:include src="/private"/></html>'
            payload['guestPublic']['publicParent'].update(bodyBase64=base64.b64encode(raw).decode(),
                generation=hashlib.sha256(raw).hexdigest())
        for kind in ('esi','cookie','cookie2'):
            app=Guests()
            if kind=='esi':app.change=unresolved
            else:app.outer=[('Set-Cookie2' if kind=='cookie2' else 'Set-Cookie','owner=warm')]
            with self.subTest(kind=kind),proxy('ultracache',app) as get:
                self.assertEqual(register(get)[0],200)
                status,fields,_=get('/bad')
                self.assertEqual(status,503);self.assertEqual(cookies(fields),[])

if __name__=='__main__':unittest.main()
