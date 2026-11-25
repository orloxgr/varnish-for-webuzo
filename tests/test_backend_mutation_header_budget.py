"""Real cold native fetch with signed event contexts at unmodified budgets.

The application/receipts are explicitly mock. Browser fields and long consent
cookies are synthetic; no captured customer values or identities are included.
"""
import base64
import http.client
import json
import os
import shutil
import subprocess
import unittest

from test_backend_header_budget import BROWSER
from test_cookie_delivery import proxy
from test_cold_public_selection import choices
from test_guest_publication import GUEST_POLICY
from test_public_selection_runtime import control
from test_public_source import SourceApplication
from test_reuse_delivery_context import signed_context
from test_mutation_backend import receipt
import test_reuse_authority as authority


def synthetic_consent_cookie(size=2315):
    rows = [('cmplz_consented_services', 'fixture'), ('cmplz_policy_id', '1'),
        ('cmplz_functional', 'allow'), ('cmplz_saved_services', ''),
        ('cmplz_id', 'fixture'), ('_fbp', 'fixture'),
        ('_tt_enable_cookie', '1'), ('_ttp', 'fixture')]
    wire = '; '.join(name+'='+value for name, value in rows)
    rows[3] = (rows[3][0], 's'*(size-len(wire)))
    wire = '; '.join(name+'='+value for name, value in rows)
    assert len(wire) == size
    return wire


def browser_headers(extra_navigation=False):
    headers = {name: value for name, value in BROWSER.items()
        if extra_navigation or name not in ('Pragma', 'Referer')}
    headers.update({'Cache-Control': 'max-age=0',
        'Accept-Encoding': 'gzip, deflate, br, zstd',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7'})
    return headers


@unittest.skipUnless(shutil.which('varnishd') and os.environ.get('SCP_EXPERIMENTAL_REUSE_TEST') == '1',
    'Matching native engine required; application is an explicit mock')
class ActiveMutationHeaderBudget(unittest.TestCase):
    def register(self, get):
        status, fields, _ = control(get, enabled=True, names='', extra={
            'X-UltraCache-Public-Selection-Reuse-Version':'1',
            'X-UltraCache-Public-Selection-Reuse-Policy':authority.REUSE_POLICY,
            'X-UltraCache-Public-Selection-Public-Source-Version':'1',
            'X-UltraCache-Public-Selection-Public-Source-Projection-Version':'1',
            'X-UltraCache-Public-Selection-Guest-Version':'1',
            'X-UltraCache-Public-Selection-Guest-Policy':GUEST_POLICY})
        self.assertEqual(status, 200)
        self.assertNotIn('X-UltraCache-VCL-Public-Selection-Coverage-Version', fields)
        self.assertNotIn('X-UltraCache-VCL-Public-Selection-Execution-Drain-Version', fields)

    def run_cold(self, extra_navigation=False, cookie_size=2315):
        source_app = SourceApplication()
        received = []
        received_contexts = []
        def origin(path, headers):
            received.append(dict(headers))
            if headers.get('X-UltraCache-Delivery-Public-Source-Role') == 'resolver-v1':
                incoming = dict(pair.strip().split('=',1) for pair in headers.get('Cookie','').split(';') if '=' in pair)
                projection = [dict(name=name, valueBase64=base64.b64encode(value.encode()).decode())
                    for name,value in sorted(incoming.items()) if name.startswith('cmplz_')]
                body = json.dumps(dict(schemaVersion=1,
                    requestId=headers['X-UltraCache-Delivery-Request'],
                    originalUrl=headers['X-UltraCache-Delivery-Original-URL'],
                    resolvedPublic=dict(version=1,bucket='orig',locale='en_US',language='en',cookieValues=projection)))
                fields = [('Content-Type','application/vnd.ultracache.delivery+json'),
                    ('Cache-Control','private, no-store'),
                    ('X-UltraCache-Delivery-Public-Selection-Version','1'),
                    ('X-UltraCache-Delivery-Public-Source-Version','1'),
                    ('X-UltraCache-Delivery-Public-Source-Outcome','resolved')]
            else:
                body, fields = source_app(path, headers)
                if headers.get('X-UltraCache-Delivery-Phase') == 'public-select':
                    value = json.loads(body)
                    value['selectedPublic']['resolvedPublic'] = json.loads(base64.b64decode(
                        headers['X-UltraCache-Delivery-Public-Source-Projection']))
                    body = json.dumps(value)
            if headers.get('X-UltraCache-Mutation-Context'):
                value = signed_context(self, headers, path, 'GET')
                received_contexts.append(value)
                fields = [*fields, ('X-UltraCache-Mutation-Receipt', receipt(value, 'none', ()))]
            return body, fields
        policies = choices(*[(name, 'variant') for name in (
            'cmplz_consented_services', 'cmplz_policy_id', 'cmplz_functional',
            'cmplz_saved_services', 'cmplz_id')],
            ('_fbp','shared'), ('_tt_enable_cookie','shared'), ('_ttp','shared'))
        with proxy('ultracache', origin, policies=policies,
                site_settings={'cms_installations':[{'cms':'wordpress','base':'/'}]},
                daemon_parameters=('http_max_hdr=64','workspace_backend=96k',
                    'workspace_client=96k','http_req_hdr_len=8k','http_req_size=32k')) as get:
            self.register(get)
            raw = synthetic_consent_cookie(cookie_size)
            status, fields, body = get('/browser-consent', raw, extra=browser_headers(extra_navigation))
            trace = subprocess.check_output(['varnishlog','-n',str(get.instance),'-d',
                '-i','Error,VCL_Error,LostHeader,RespReason,BerespReason'],text=True)
            self.assertEqual(status, 200, trace+'\nMock executions: '+str(len(received)))
            self.assertIn('private:guest', body)
            self.assertTrue(received_contexts, 'The actual backend request must have its signed event context')
            self.assertEqual(received[0].get('X-UltraCache-Delivery-Phase'), 'public-select')
            self.assertEqual(received[0].get('X-UltraCache-Delivery-Public-Source-Role'), 'resolver-v1')
            self.assertEqual(received[0].get('Cookie'), raw, 'Original consent cookie wire must reach PHP unchanged')
            self.assertNotIn('X-UltraCache-VCL-Execution-Drain-Version', received[0])
            self.assertTrue(received[0].get('X-UltraCache-Delivery-Authorization'))
            for name, value in browser_headers(extra_navigation).items():
                if name not in ('X-Forwarded-For','Via','Accept-Encoding'):
                    self.assertEqual(received[0].get(name), value, name)
            self.assertIsNone(received[0].get('X-SCP-HTML-Accept'))
            for name in ('X-SCP-Vary-Accept', 'X-SCP-Vary-Accept-Language',
                         'X-SCP-Vary-Cookie', 'X-SCP-Vary-ESI-Cookie'):
                self.assertIsNone(received[0].get(name),
                    'Uncacheable owned prepare does not store a Vary representation: '+name)
            self.assertNotIn('header slots or workspace exhausted', trace)

    def test_first_cold_consent_navigation_with_actual_signed_event_context(self):
        self.run_cold()

    def test_cold_signed_navigation_keeps_pragma_and_referer(self):
        self.run_cold(extra_navigation=True)

    def test_large_cold_consent_navigation_with_actual_signed_event_context(self):
        self.run_cold(cookie_size=6144)

    def test_large_cold_signed_navigation_keeps_pragma_and_referer(self):
        self.run_cold(extra_navigation=True, cookie_size=6144)

    def test_ordinary_authenticated_post_preserves_cookie_url_and_form_body(self):
        received = []
        path = '/form-submit?campaign=synthetic&action=save'
        body = b'name=fixture&message=%CE%B4%CE%BF%CE%BA%CE%B9%CE%BC%CE%AE&empty='
        raw = synthetic_consent_cookie()
        def origin(url, headers, request_body):
            value = signed_context(self, headers, url, 'POST')
            received.append((url, dict(headers), request_body))
            return 'ordinary form response', [
                ('Cache-Control', 'private, no-store'),
                ('X-UltraCache-Mutation-Receipt', receipt(value, 'none', ()))]
        with proxy('ultracache', origin, allow_post=True, request_body=True,
                site_settings={'cms_installations':[{'cms':'wordpress','base':'/'}]},
                daemon_parameters=('http_max_hdr=64','workspace_backend=96k',
                    'workspace_client=96k','http_req_hdr_len=8k','http_req_size=32k')) as get:
            self.register(get)
            headers = {**get.request_headers, **browser_headers(True), 'Cookie':raw,
                'Authorization':'Bearer synthetic-owned-form-token',
                'Content-Type':'application/x-www-form-urlencoded'}
            client = http.client.HTTPConnection(*get.endpoint, timeout=15)
            try:
                client.request('POST', path, body=body, headers=headers)
                response = client.getresponse()
                self.assertEqual(response.status, 200)
                self.assertEqual(response.read(), b'ordinary form response')
            finally:
                client.close()
            self.assertEqual(len(received), 1)
            url, actual, actual_body = received[0]
            self.assertEqual((url, actual_body), (path, body))
            self.assertEqual(actual.get('Cookie'), raw)
            self.assertEqual(actual.get('Authorization'), headers['Authorization'])
            self.assertEqual(actual.get('Content-Type'), headers['Content-Type'])
            self.assertIsNone(actual.get('X-UltraCache-Delivery-Phase'))
            self.assertIsNone(actual.get('X-UltraCache-Delivery-Authorization'))
            trace = subprocess.check_output(['varnishlog','-n',str(get.instance),'-d',
                '-i','Error,VCL_Error,LostHeader'],text=True)
            self.assertNotIn('header slots or workspace exhausted', trace)


if __name__ == '__main__': unittest.main()
