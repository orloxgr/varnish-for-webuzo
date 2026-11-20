"""Native private-document wire fixture; actual native WP templates are separate.

No theme/provider substitute here proves Woo notice consumption or bootstrap.
"""
import base64
import json
import shutil
import unittest

from test_cookie_delivery import proxy,cookies
from test_delivery_continuation import BODY,META,PARENT,PRIVATE,envelope

MARKER='X-UltraCache-Delivery-Private-Document-Version'


def document(headers,body,status=200):
    return dict(schemaVersion=1,requestId=headers['X-UltraCache-Delivery-Request'],
        originalUrl=headers['X-UltraCache-Delivery-Original-URL'],privateDocument=dict(
            bodyBase64=base64.b64encode(body.encode()).decode(),contentType='text/html; charset=UTF-8',status=status))


@unittest.skipUnless(shutil.which('varnishd'),'Native Varnish required; fixture unqualified when skipped')
class PrivateDocument(unittest.TestCase):
    def test_owned_document_has_fresh_headers_cookies_once_and_never_replaces_public_parent(self):
        calls=[]
        literal='<html>notice Ελληνικά <esi:include src="/must-not-execute"/></html>'
        owner_fields=['owner=current; Path=/; Secure; HttpOnly; SameSite=Lax',
            'old=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; Path=/',
            'owner=other-path; Path=/account; Secure']
        def origin(path,headers):
            phase=headers.get('X-UltraCache-Delivery-Phase');calls.append((path,phase))
            self.assertIsNone(headers.get('X-UltraCache-Application-Private'))
            if phase=='prepare':
                self.assertEqual(headers.get(MARKER),'1')
                if headers.get('Cookie')=='_fbp=notice-owner':
                    return json.dumps(document(headers,literal)),[
                        ('Content-Type','application/vnd.ultracache.delivery+json'),
                        ('Cache-Control','private, no-store'),
                        ('Content-Security-Policy',"script-src 'nonce-fresh'"),
                        ('Link','</fresh>; rel=preload'),('Content-Language','el'),
                        ('ETag','json-wire-etag'),('Last-Modified','Thu, 01 Jan 1970 00:00:00 GMT'),
                        ('X-UltraCache-Application-Private','test-notices'),
                        (MARKER,'origin-spoof'),*[('Set-Cookie',value) for value in owner_fields]]
                return envelope(headers,'other-owner'),[('Cache-Control','private, no-store')]
            self.assertIsNone(headers.get(MARKER),'A client cannot declare whole-document support')
            if path==PARENT:return BODY,META+[('ETag','public-generation'),('Content-Security-Policy',"script-src 'nonce-old'")]
            return 'cold-child',[('Cache-Control','private, no-store')]
        with proxy('ultracache',origin) as get:
            get(PARENT);calls.clear()
            status,fields,result=get(PARENT,'_fbp=notice-owner',extra={MARKER:'client-spoof',
                'X-UltraCache-Application-Private':'client-spoof'})
            values=dict(fields)
            self.assertEqual(status,200);self.assertEqual(result,literal)
            self.assertEqual(cookies(fields),owner_fields)
            self.assertEqual(values['Content-Type'],'text/html; charset=UTF-8')
            self.assertEqual(values['Content-Security-Policy'],"script-src 'nonce-fresh'")
            self.assertEqual(values['Content-Language'],'el');self.assertEqual(values['Link'],'</fresh>; rel=preload')
            self.assertEqual(values['X-Cache'],'PASS');self.assertEqual(values['Cache-Control'],'private, no-store')
            self.assertEqual(values['X-UltraCache-Application-Private'],'test-notices')
            for name in (MARKER,'ETag','Last-Modified','X-UltraCache-Delivery-Prepare','X-UltraCache-Delivery-Request'):
                self.assertNotIn(name,values)
            self.assertEqual(calls,[(PARENT,'prepare')],'Whole document must not refetch/compose any child or parent')
            calls.clear()
            status,fields,result=get(PARENT,'_fbp=another-owner')
            self.assertEqual(status,200)
            self.assertEqual(result,'<html>parent[private:other-owner][private:other-owner][nonce:other-owner]</html>')
            self.assertEqual(dict(fields)['X-Cache'],'HIT')
            self.assertEqual(dict(fields)['ETag'],'public-generation')
            self.assertEqual(dict(fields)['Content-Security-Policy'],"script-src 'nonce-old'")
            self.assertEqual(cookies(fields),[])
            self.assertEqual(calls,[(PARENT,'prepare')])

    def test_actual_status_and_no_body_statuses_are_preserved(self):
        calls=[]
        def origin(path,headers):
            if headers.get('X-UltraCache-Delivery-Phase')=='prepare':
                code=int(headers['Cookie'].split('=',1)[1]);calls.append(code)
                return json.dumps(document(headers,'<html>current-'+str(code)+'</html>',code)),[
                    ('Cache-Control','private, no-store'),('Location','/current-destination')]
            return (BODY,META) if path==PARENT else ('cold',[('Cache-Control','private, no-store')])
        with proxy('ultracache',origin) as get:
            get(PARENT)
            for code in (404,302,204,304,503):
                status,fields,result=get(PARENT,'_fbp='+str(code))
                self.assertEqual(status,code)
                self.assertEqual(result,'' if code in (204,304) else '<html>current-'+str(code)+'</html>')
                self.assertEqual(dict(fields)['Cache-Control'],'private, no-store')
                self.assertEqual(dict(fields)['X-Cache'],'PASS')
                self.assertEqual(dict(fields)['Location'],'/current-destination')
            self.assertEqual(calls,[404,302,204,304,503])

    def test_invalid_mixed_or_misbound_document_refuses_without_cookie_or_child_delivery(self):
        def wrong_id(result):result['requestId']='wrong'
        def wrong_url(result):result['originalUrl']='/wrong'
        def mixed(result):result['renderedFragments']=[]
        def bad_status(result):result['privateDocument']['status']=199
        def bad_body(result):result['privateDocument']['bodyBase64']='invalid!'
        def mixed_snapshot(result):result['publicParent']=dict(generation='a'*64,bodyBase64='eA==',freshRemaining=30)
        for change in (wrong_id,wrong_url,mixed,bad_status,bad_body,mixed_snapshot):
            calls=[]
            def origin(path,headers):
                calls.append((path,headers.get('X-UltraCache-Delivery-Phase')))
                if headers.get('X-UltraCache-Delivery-Phase')=='prepare':
                    result=document(headers,'private');change(result)
                    return json.dumps(result),[('Cache-Control','private, no-store'),('Set-Cookie','must-not-replay=value')]
                return (BODY,META) if path==PARENT else ('cold',[('Cache-Control','private, no-store')])
            with self.subTest(change=change.__name__),proxy('ultracache',origin) as get:
                get(PARENT);calls.clear()
                status,fields,_=get(PARENT)
                self.assertEqual(status,503);self.assertEqual(cookies(fields),[])
                self.assertEqual(calls,[(PARENT,'prepare')])

    def test_origin_application_private_without_fragments_blocks_aggressive_and_client_marker_cannot_forward(self):
        calls=[]
        def origin(path,headers):
            self.assertIsNone(headers.get('X-UltraCache-Application-Private'))
            self.assertIsNone(headers.get('X-UltraCache-Delivery-Phase'))
            calls.append(path);number=len(calls)
            return '<html>personal-'+str(number)+'</html>',[('Cache-Control','public, max-age=120'),
                ('X-UltraCache-Application-Private','application-state'),
                ('X-UltraCache-Cacheable','1'),('X-UltraCache-ESI-Private-Count','0'),
                ('X-UltraCache-ESI-Shared-Parent','1'),('X-UltraCache-Delivery-Parent-Source','public-snapshot-v1'),
                ('Set-Cookie','_fbp=owner-'+str(number)+'; Path=/')]
        with proxy('ultracache',origin,site_settings={'aggressive':True,'aggressive_ttl':86400}) as get:
            for number in (1,2):
                status,fields,result=get('/ordinary',extra={'X-UltraCache-Application-Private':'client-spoof'})
                self.assertEqual(status,200);self.assertEqual(result,'<html>personal-'+str(number)+'</html>')
                self.assertEqual(dict(fields)['X-Cache'],'PASS')
                self.assertEqual(dict(fields)['X-UltraCache-Cacheable'],'0')
                self.assertEqual(dict(fields)['Cache-Control'],'private, no-store')
                self.assertEqual(cookies(fields),['_fbp=owner-'+str(number)+'; Path=/'])
            self.assertEqual(calls,['/ordinary','/ordinary'])

    def test_basic_ignores_application_private_metadata_and_never_composes_esi(self):
        calls=[]
        literal='<html>Basic best effort <esi:include src="/must-not-execute"/></html>'
        def origin(path,headers):
            self.assertIsNone(headers.get('X-UltraCache-Application-Private'))
            self.assertIsNone(headers.get(MARKER))
            calls.append(path)
            return literal,[('Cache-Control','public, max-age=120'),
                ('Surrogate-Control','ESI/1.0'),('X-UltraCache-Application-Private','application-state'),
                ('X-UltraCache-Cacheable','0'),('X-UltraCache-ESI-Private-Count','2')]
        with proxy('basic',origin,site_settings={'aggressive':True,'aggressive_ttl':86400}) as get:
            for expected in ('MISS','HIT'):
                status,fields,result=get('/basic',extra={MARKER:'browser-spoof',
                    'X-UltraCache-Application-Private':'browser-spoof'})
                self.assertEqual(status,200);self.assertEqual(result,literal)
                self.assertEqual(dict(fields)['X-Cache'],expected)
                self.assertNotIn(MARKER,dict(fields))
            self.assertEqual(calls,['/basic'])

    def test_declaration_uses_existing_private_probe_and_owned_prepare_only(self):
        probe='/index.php?ultracache_esi_probe_private_fragment=signed-probe&esi_scope=private'
        observed=[]
        def origin(path,headers):
            phase=headers.get('X-UltraCache-Delivery-Phase')
            expected='1' if phase=='prepare' or path==probe else None
            self.assertEqual(headers.get(MARKER),expected)
            observed.append((path,phase,headers.get(MARKER)))
            if phase=='prepare':
                return envelope(headers,'prepared'),[('Cache-Control','private, no-store'),(MARKER,'origin-echo')]
            if path=='/probe':
                return '<esi:include src="'+probe.replace('&','&amp;')+'"/>',[
                    ('Cache-Control','public, max-age=0'),('Surrogate-Control','ESI/1.0'),(MARKER,'origin-echo')]
            if path==probe:return 'probe',[('Cache-Control','private, no-store'),(MARKER,'origin-echo')]
            return (BODY,META) if path==PARENT else ('cold-private',[('Cache-Control','private, no-store')])
        with proxy('ultracache',origin) as get:
            for path in ('/probe',PARENT,PARENT,PRIVATE):
                status,fields,_=get(path,extra={MARKER:'browser-spoof'})
                self.assertEqual(status,200);self.assertNotIn(MARKER,dict(fields))
            self.assertIn((probe,None,'1'),observed)
            self.assertIn((PARENT,'prepare','1'),observed)

    def test_document_cannot_also_declare_public_snapshot_recovery(self):
        for capability in ('public-snapshot-v1','request-snapshot-v1'):
            calls=[]
            def origin(path,headers):
                phase=headers.get('X-UltraCache-Delivery-Phase');calls.append((path,phase))
                if phase=='prepare':
                    return json.dumps(document(headers,'must not deliver')),[('Cache-Control','private, no-store'),
                        ('X-UltraCache-Delivery-Recovery',capability),('Set-Cookie','must-not-replay=value')]
                return (BODY,META) if path==PARENT else ('cold-private',[('Cache-Control','private, no-store')])
            with self.subTest(capability=capability),proxy('ultracache',origin) as get:
                get(PARENT);calls.clear()
                status,fields,_=get(PARENT)
                self.assertEqual(status,503);self.assertEqual(cookies(fields),[])
                self.assertEqual(calls,[(PARENT,'prepare')])


if __name__=='__main__':unittest.main()
