"""Debug-only prepare outcome visibility; mock origin is not WP acceptance."""
import json
import base64
import hashlib
import http.client
import shutil
import subprocess
import unittest

from test_cookie_delivery import proxy,cookies
from test_delivery_continuation import BODY,META,PARENT,PRIVATE,envelope
from test_private_document import document
from test_public_selection_runtime import Resolver,control,rules

MARKER='X-UltraCache-ESI-Error-Contained'
MESSAGE='UltraCache prepare degraded: contained renderer fallback'


def diagnostics(get):
    result=subprocess.run(['varnishlog','-n',str(get.instance),'-d','-g','raw','-i','VCL_Log'],
                          capture_output=True,text=True,timeout=10)
    if result.returncode:raise AssertionError(result.stderr)
    return [line for line in result.stdout.splitlines() if MESSAGE in line]


@unittest.skipUnless(shutil.which('varnishd') and shutil.which('varnishlog'),
                     'Native Varnish and VSL reader required; skipped is not acceptance')
class PrepareDiagnostics(unittest.TestCase):
    def test_debug_off_invalid_and_duplicate_markers_add_no_diagnostic(self):
        marker=[]
        def origin(path,headers):
            self.assertIsNone(headers.get(MARKER),'Client diagnostic headers must not reach the provider')
            if headers.get('X-UltraCache-Delivery-Phase')=='prepare':
                return envelope(headers,'owner'),[('Cache-Control','private, no-store'),*marker]
            return (BODY,META) if path==PARENT else ('cold',[('Cache-Control','private, no-store')])
        with proxy('ultracache',origin) as get:
            get(PARENT)
            for fields in ([],[(MARKER,'0')],[(MARKER,'yes')],[(MARKER,'1,1')],[(MARKER,'1'),(MARKER,'1')]):
                marker[:]=fields
                status,headers,body=get(PARENT,extra={MARKER:'1'})
                self.assertEqual(status,200);self.assertIn('private:owner',body)
                self.assertNotIn(MARKER,dict(headers));self.assertEqual(diagnostics(get),[])

    def test_one_debug_marker_logs_once_per_owner_without_changing_repeated_output_or_cookies(self):
        enabled=True;prepares=0
        def origin(path,headers):
            nonlocal prepares
            if headers.get('X-UltraCache-Delivery-Phase')=='prepare':
                prepares+=1
                visitor='A' if headers.get('Cookie')=='_fbp=A' else 'B'
                return envelope(headers,visitor),[('Cache-Control','private, no-store'),
                    ('Set-Cookie','owner='+visitor+'; Path=/; HttpOnly'),*([(MARKER,'1')] if enabled else [])]
            return (BODY,META) if path==PARENT else ('cold',[('Cache-Control','private, no-store')])
        with proxy('ultracache',origin) as get:
            get(PARENT)
            for index,visitor in enumerate(('A','B'),1):
                status,headers,body=get(PARENT,'_fbp='+visitor)
                self.assertEqual(status,200);self.assertEqual(dict(headers)['X-Cache'],'HIT')
                self.assertEqual(body,'<html>parent[private:'+visitor+'][private:'+visitor+'][nonce:'+visitor+']</html>')
                self.assertEqual(cookies(headers),['owner='+visitor+'; Path=/; HttpOnly'])
                self.assertNotIn(MARKER,dict(headers))
                lines=diagnostics(get);self.assertEqual(len(lines),index)
                self.assertTrue(all(line.endswith(MESSAGE) for line in lines))
            enabled=False
            get(PARENT,'_fbp=A')
            self.assertEqual(len(diagnostics(get)),2,'No diagnostic retained in a shared parent or next request')
            self.assertEqual(prepares,3)

    def test_rejected_http_or_envelope_never_becomes_degraded_success(self):
        fault='http409'
        def origin(path,headers):
            if headers.get('X-UltraCache-Delivery-Phase')=='prepare':
                fields=[('Cache-Control','private, no-store'),(MARKER,'1')]
                if fault.startswith('http'):return int(fault[4:]),'RAW FAILED PREPARE',fields
                if fault=='json':return '{not-json',fields
                if fault=='binding':return envelope(headers,'owner',lambda value:value.update(requestId='wrong-owner')),fields
                return envelope(headers,'recovered'),fields
            return (BODY,META) if path==PARENT else ('cold',[('Cache-Control','private, no-store')])
        with proxy('ultracache',origin) as get:
            get(PARENT)
            for value in ('http409','http500','json','binding'):
                fault=value
                status,headers,body=get(PARENT)
                self.assertEqual(status,503);self.assertNotIn(MARKER,dict(headers))
                self.assertNotIn('RAW FAILED PREPARE',body);self.assertEqual(diagnostics(get),[])
            fault='healthy';self.assertEqual(get(PARENT)[0],200)
            self.assertEqual(len(diagnostics(get)),1)

    def test_valid_private_document_reports_fallback_without_exposing_marker(self):
        def origin(path,headers):
            if headers.get('X-UltraCache-Delivery-Phase')=='prepare':
                return json.dumps(document(headers,'<html>private fallback</html>',409)),[
                    ('Content-Type','application/vnd.ultracache.delivery+json'),
                    ('Cache-Control','private, no-store'),(MARKER,'1')]
            return (BODY,META) if path==PARENT else ('cold',[('Cache-Control','private, no-store')])
        with proxy('ultracache',origin) as get:
            get(PARENT)
            status,headers,body=get(PARENT)
            self.assertEqual((status,body),(409,'<html>private fallback</html>'))
            self.assertNotIn(MARKER,dict(headers));self.assertEqual(len(diagnostics(get)),1)

    def test_request_snapshot_recovery_reports_once_after_parent_loss(self):
        calls=[]
        def origin(path,headers):
            phase=headers.get('X-UltraCache-Delivery-Phase');calls.append((path,phase))
            if phase=='prepare':
                client=http.client.HTTPConnection(*get.endpoint,timeout=5)
                try:
                    client.request('PURGE',PARENT,headers={'Host':'example.test','X-Forwarded-Proto':'https',
                        'X-UltraCache-Token':headers['X-UltraCache-Delivery-Authorization']})
                    response=client.getresponse();response.read();self.assertEqual(response.status,200)
                finally:client.close()
                def snapshot(value):
                    value['publicParent']=dict(generation=hashlib.sha256(BODY.encode()).hexdigest(),
                        bodyBase64=base64.b64encode(BODY.encode()).decode(),freshRemaining=120)
                return envelope(headers,'snapshot',snapshot),[('Cache-Control','private, no-store'),
                    ('X-UltraCache-Delivery-Recovery','request-snapshot-v1'),(MARKER,'1')]
            return (BODY,META) if path==PARENT else ('cold',[('Cache-Control','private, no-store')])
        with proxy('ultracache',origin) as get:
            get(PARENT)
            status,headers,body=get(PARENT)
            self.assertEqual(status,200);self.assertIn('private:snapshot',body)
            self.assertNotIn(MARKER,dict(headers));self.assertEqual(len(diagnostics(get)),1)
            self.assertEqual(sum(phase=='prepare' for _,phase in calls),1)
            self.assertEqual(sum(path==PARENT and phase is None for path,phase in calls),1)

    def test_ordinary_endpoint_and_parent_marker_do_not_claim_prepared_failure(self):
        def origin(path,headers):
            self.assertIsNone(headers.get(MARKER))
            return 'ordinary',[('Cache-Control','private, no-store'),(MARKER,'1')]
        with proxy('ultracache',origin) as get:
            self.assertEqual(get(PRIVATE,extra={MARKER:'1'})[0],200)
            self.assertEqual(get(PARENT,extra={MARKER:'1'})[0],200)
            self.assertEqual(diagnostics(get),[])

    def test_public_selection_protocol_accepts_optional_marker_after_validation(self):
        resolver=Resolver(esi=True)
        def origin(path,headers):
            body,fields=resolver(path,headers)
            return body,[*fields,(MARKER,'1')]
        with proxy('ultracache',origin,policies=rules()) as get:
            self.assertEqual(control(get,enabled=True)[0],200)
            status,headers,body=get('/book',extra={'X-Test-Visitor':'A'})
            self.assertEqual(status,200);self.assertIn('owner:A',body)
            self.assertNotIn(MARKER,dict(headers));self.assertEqual(len(diagnostics(get)),1)


if __name__=='__main__':unittest.main()
