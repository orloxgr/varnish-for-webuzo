"""Webuzo owned continuations reauthorize ingress without retaining a gateway.

Native generated-policy fixture, not actual Webuzo panel/Nginx/CLI acceptance.
"""
import http.client
import shutil
import unittest

from test_cookie_delivery import proxy,cookies
from test_delivery_continuation import BODY,META,PARENT,PRIVATE,ADAPTIVE,envelope


@unittest.skipUnless(shutil.which('varnishd'),'Native Varnish required; fixture unqualified when skipped')
class ContinuationGateway(unittest.TestCase):
    def test_owned_resume_preserves_ingress_authorization_without_forwarding_gateway(self):
        calls=[]
        public='/gateway-public'
        body=BODY.replace('</html>','<esi:include src="'+public+'"/></html>')
        def origin(path,headers):
            self.assertIsNone(headers.get('X-WV-Gateway'),'Global gateway must never leave request scope')
            phase=headers.get('X-UltraCache-Delivery-Phase');calls.append((path,phase))
            if phase=='prepare':
                return envelope(headers,'gateway-once'),[('Cache-Control','private, no-store'),
                    ('Set-Cookie','owner=current; Path=/; HttpOnly'),('X-WV-Gateway','origin-echo')]
            if path==PARENT:return body,META+[('X-WV-Gateway','origin-echo')]
            if path==public:
                self.assertIsNone(headers.get('Cookie'))
                return 'PUBLIC',[('Cache-Control','public, max-age=120'),('X-WV-Gateway','origin-echo')]
            self.assertIn(path,(PRIVATE,ADAPTIVE))
            return 'cold-private',[('Cache-Control','private, no-store'),('X-WV-Gateway','origin-echo')]
        with proxy('ultracache',origin) as get:
            # Wrong/missing credentials remain denied before any origin work.
            self.assertEqual(get(PARENT,extra={'X-WV-Gateway':'wrong',
                'X-UltraCache-Delivery-Phase':'prepare','X-WV-Site':'a'*32,
                'X-SCP-Site':'a'*32,'X-SCP-Cookie-Handoff':'42'})[0],403)
            connection=http.client.HTTPConnection(*get.endpoint,timeout=5)
            try:
                connection.request('GET',PARENT,headers={'Host':'example.test','X-Forwarded-Proto':'https'})
                response=connection.getresponse();response.read()
                self.assertEqual(response.status,403)
            finally:connection.close()
            self.assertEqual(calls,[])
            status,fields,_=get(PARENT)
            self.assertEqual(status,200);self.assertNotIn('X-WV-Gateway',dict(fields))
            self.assertIn((public,None),calls)
            calls.clear()
            status,fields,result=get(PARENT,'_fbp=visitor')
            self.assertEqual(status,200)
            self.assertEqual(result,'<html>parent[private:gateway-once][private:gateway-once][nonce:gateway-once]PUBLIC</html>')
            self.assertEqual(cookies(fields),['owner=current; Path=/; HttpOnly'])
            self.assertNotIn('X-WV-Gateway',dict(fields))
            self.assertEqual(calls,[(PARENT,'prepare')])
            # A successful earlier request does not authenticate a new one.
            self.assertEqual(get(PARENT,extra={'X-WV-Gateway':'wrong'})[0],403)
            self.assertEqual(calls,[(PARENT,'prepare')])

    def test_owned_restart_cannot_change_site_host_uri_or_expected_restart_before_ingress_proof(self):
        for name,mutation in (
                ('site','set req.http.X-WV-Site = "'+'c'*32+'";'),
                ('host','set req.http.host = "other.test";'),
                ('uri','set req.url = "/changed";'),
                ('restart','return (restart);')):
            calls=[]
            def origin(path,headers):
                self.assertIsNone(headers.get('X-WV-Gateway'))
                self.assertIsNone(headers.get('X-UltraCache-Delivery-Phase'),
                    'A changed continuation binding must be refused before origin/provider work')
                calls.append(path)
                return (BODY,META) if path==PARENT else ('cold-private',[('Cache-Control','private, no-store')])
            def mutate_restart(source):
                anchor=' if (req.esi_level > 0) {\n   if (req_top.http.X-WV-Site'
                self.assertEqual(source.count(anchor),1)
                return source.replace(anchor,' if (req.restarts == 1) { '+mutation+' }\n'+anchor)
            with self.subTest(binding=name),proxy('ultracache',origin,transform=mutate_restart) as get:
                self.assertEqual(get(PARENT)[0],200)
                calls.clear()
                status,fields,_=get(PARENT)
                self.assertEqual(status,403)
                self.assertEqual(cookies(fields),[])
                self.assertEqual(calls,[])


if __name__=='__main__':unittest.main()
