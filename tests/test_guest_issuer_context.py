"""Native canonical context stamping; issuer HMAC/lifecycle belongs to WordPress."""
import http.client
import hmac
import hashlib
import json
import shutil
import unittest
from test_cookie_delivery import proxy
from test_guest_publication import Guests,register
from test_public_selection_runtime import control

KEY='ultracache_guest_cookie_delivery'
PREFIX='X-UltraCache-Guest-Issuer-'

def post(get,path,extra=None):
    c=http.client.HTTPConnection(*get.endpoint,timeout=15)
    try:
        h=dict(get.request_headers);h.update(extra or {})
        c.request('POST',path,body=b'',headers=h)
        r=c.getresponse();return r.status,r.getheaders(),r.read()
    finally:c.close()

@unittest.skipUnless(shutil.which('varnishd'),'Native Varnish required; skips are not acceptance')
class GuestIssuerContext(unittest.TestCase):
    def test_guest_cold_fill_exposes_same_native_canonical_copy_without_url_rewrite(self):
        app=Guests()
        with proxy('ultracache',app) as get:
            self.assertEqual(register(get)[0],200)
            path='/p?unknown=one&utm_source=A&unknown=two'
            self.assertEqual(get(path)[0],200)
            fields=app.guest_requests[-1]
            self.assertEqual(fields['X-UltraCache-Delivery-Guest-Publication-Canonical-URL'],'/p?unknown=one&unknown=two')
            self.assertEqual(fields['X-UltraCache-Delivery-Original-URL'],path)
            self.assertNotIn(PREFIX+'Authorization',fields)
            count=len(app.calls)
            self.assertEqual(get('/p?unknown=one&utm_source=B&unknown=two')[0],200)
            self.assertEqual(len(app.calls),count)

    def test_private_post_preserves_real_uri_and_native_functional_query_projection(self):
        seen=[]
        def issuer(path,headers):
            seen.append((path,dict(headers)))
            echo=[(name,headers[name]) for name in (PREFIX+'Version',PREFIX+'Canonical-URL',PREFIX+'Authorization') if name in headers]
            return 204,'',[('Cache-Control','private, no-store'),('Set-Cookie','owner=real; Path=/'),*echo]
        cases=[('/p?utm_source=B&ref=campaign&x=a%20b&x=a+b&'+KEY+'=ticket','/p?ref=campaign&x=a%20b&x=a+b'),
            ('/p?'+KEY+'=ticket&functional=&utm_source=B&functional=2','/p?functional=&functional=2'),
            ('/p?x=1&&x=2&'+KEY+'=ticket','/p?x=1&&x=2'),
            ('/p?x=1&'+KEY+'=ticket&x=2','/p?x=1&x=2'),
            ('/p?'+KEY+'=ticket','/p')]
        with proxy('ultracache',issuer,allow_post=True) as get:
            for raw,canonical in cases:
                status,fields,_=post(get,raw,{PREFIX+'Authorization':'forged',PREFIX+'Canonical-URL':'/forged'})
                self.assertEqual(status,204)
                original,headers=seen[-1]
                self.assertEqual(original,raw)
                self.assertEqual(headers[PREFIX+'Version'],'1')
                self.assertEqual(headers[PREFIX+'Canonical-URL'],canonical)
                message=('ultracache-guest-issuer-v1\nPOST\nexample.test\n'+raw+'\n'+canonical).encode()
                self.assertEqual(headers[PREFIX+'Authorization'],'v1:'+hmac.new(b'b'*64,message,hashlib.sha256).hexdigest())
                self.assertNotIn('b'*64,headers[PREFIX+'Authorization'])
                self.assertNotIn('X-UltraCache-Delivery-Authorization',headers)
                self.assertFalse(any(name.startswith(PREFIX) for name,_ in fields))
                self.assertIn(('Set-Cookie','owner=real; Path=/'),fields)
            self.assertEqual(len(seen),len(cases))

    def test_proof_uses_actual_forwarded_origin_host(self):
        seen=[]
        def origin(path,headers):
            seen.append(dict(headers));return 204,'',[('Cache-Control','private, no-store')]
        with proxy('ultracache',origin,allow_post=True) as get:
            raw='/p?'+KEY+'=ticket'
            self.assertEqual(post(get,raw,{'Host':'ExAmPlE.TeSt:443'})[0],204)
            headers=seen[-1];host=next(v for k,v in headers.items() if k.lower()=='host')
            message=('ultracache-guest-issuer-v1\nPOST\n'+host.lower().strip()+'\n'+raw+'\n/p').encode()
            self.assertEqual(headers[PREFIX+'Authorization'],'v1:'+hmac.new(b'b'*64,message,hashlib.sha256).hexdigest())

    def test_duplicate_operation_pair_get_and_ordinary_post_cannot_forge_stamp(self):
        seen=[]
        def origin(path,headers):
            seen.append(dict(headers));return '',[('Cache-Control','private, no-store')]
        forged={PREFIX+'Version':'1',PREFIX+'Authorization':'forged',PREFIX+'Canonical-URL':'/forged','X-SCP-Guest-Issuer':'1'}
        with proxy('ultracache',origin,allow_post=True) as get:
            for path in ('/p?'+KEY+'=one&'+KEY+'=two','/p?ordinary=1','/p?'+KEY+'='):
                self.assertEqual(post(get,path,forged)[0],200)
                self.assertFalse(any(name.startswith(PREFIX) for name in seen[-1]))
            self.assertEqual(get('/p?'+KEY+'=ticket',extra=forged)[0],200)
            self.assertFalse(any(name.startswith(PREFIX) for name in seen[-1]))

    def test_phpinfo_like_echo_has_no_reusable_key_and_proof_cannot_purge_or_move(self):
        observed=[]
        def echo(path,headers):
            observed.append(dict(headers));return json.dumps(dict(headers)),[('Cache-Control','private, no-store')]
        with proxy('ultracache',echo,allow_post=True) as get:
            raw='/phpinfo.php?'+KEY+'=public-ticket'
            status,fields,body=post(get,raw)
            self.assertEqual(status,200)
            headers=observed[-1];proof=headers[PREFIX+'Authorization']
            self.assertNotIn('b'*64,body.decode())
            self.assertNotIn('X-UltraCache-Delivery-Authorization',headers)
            for candidate in (proof,proof.removeprefix('v1:')):
                self.assertNotEqual(control(get,operation='exact-purge',path='/phpinfo.php',extra={'X-UltraCache-Token':candidate})[0],200)
            for method,route,host,canonical in [('GET',raw,'example.test','/phpinfo.php'),
                ('POST','/other?'+KEY+'=public-ticket','example.test','/phpinfo.php'),
                ('POST',raw,'other.test','/phpinfo.php'),('POST',raw,'example.test','/other')]:
                message=('ultracache-guest-issuer-v1\n'+method+'\n'+host+'\n'+route+'\n'+canonical).encode()
                self.assertNotEqual(proof,'v1:'+hmac.new(b'b'*64,message,hashlib.sha256).hexdigest())

    def test_basic_post_does_not_acquire_issuer_or_prepare_credentials(self):
        seen=[]
        def origin(path,headers):
            seen.append(dict(headers));return '',[('Cache-Control','private, no-store')]
        with proxy('basic',origin,allow_post=True) as get:
            self.assertEqual(post(get,'/p?'+KEY+'=ticket',{PREFIX+'Authorization':'forged'})[0],200)
            self.assertFalse(any(name.startswith(PREFIX) for name in seen[-1]))
            self.assertNotIn('X-UltraCache-Delivery-Authorization',seen[-1])

if __name__=='__main__':unittest.main()
