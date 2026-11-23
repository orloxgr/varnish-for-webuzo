"""Unmodified generated VCL, actual native module; MOCK covered origin/drain.

Actual Nginx physical-file routing and PHP/SQL drain require installed Lab tests.
"""
import os
import shutil
import unittest

import test_mutation_backend as backend
import test_mutation_coverage_runtime as coverage
import test_reuse_authority as authority
from test_cookie_delivery import proxy
from test_public_selection_runtime import control


@unittest.skipUnless(shutil.which('varnishd') and os.environ.get('SCP_EXPERIMENTAL_REUSE_TEST')=='1',
                     'Matching installed-engine module required')
class NormalGeneratedMutationBoundary(unittest.TestCase):
    call=authority.NativeReuseAuthority.call
    observe=authority.NativeReuseAuthority.observe
    recover=authority.NativeReuseAuthority.recover
    publish=authority.NativeReuseAuthority.publish
    ready=authority.NativeReuseAuthority.ready
    ended=backend.NativeMutationBackend.ended
    drain=coverage.NativeCoverageHolds.drain

    def test_normal_dynamic_get_and_post_use_signed_coverage_without_test_vcl_injection(self):
        for method,path in (('GET','/wp-json/wp/v2/types?context=view'),
                            ('GET','/wp-json/custom/dynamic.css'),
                            ('POST','/wp-admin/admin-ajax.php?action=owned_read')):
            with self.subTest(method=method,path=path):
                captured=[]
                def origin(actual,headers):
                    self.assertEqual(actual,path)
                    c=coverage.context(self,headers,method,path);captured.append(c)
                    if headers.get('X-UltraCache-Delivery-Phase')=='public-select':
                        self.assertEqual(headers.get('X-UltraCache-Delivery-Authorization'),'b'*64)
                    else:
                        self.assertNotIn('X-UltraCache-Delivery-Authorization',headers)
                    return 'original application response',[
                        ('Content-Type','application/json'),('Cache-Control','private, no-store'),
                        coverage.response_receipt(c)]
                with proxy('ultracache',origin,allow_post=True) as get:
                    coverage.register(self,get);old=self.ready(get)
                    response=get(path) if method=='GET' else backend.post(get,path)
                    self.assertEqual(response[0],200)
                    self.assertEqual(len(captured),1)
                    self.assertNotIn('X-UltraCache-Mutation-Receipt',dict(response[1]))
                    pending=self.ended(get)
                    self.assertEqual(pending['temporaryHolds'],1)
                    self.assertEqual(pending['scopeRevision'],old['scopeRevision'])
                    self.drain(get,captured[0])
                    current=self.observe(get)
                    self.assertEqual((current['scopeState'],current.get('temporaryHolds',0),current['scopeRevision']),
                                     ('ready',0,old['scopeRevision']))

    def test_normal_basic_and_old_producers_do_not_receive_mutation_contract(self):
        for profile,old_declaration in (('basic',False),('ultracache',False),('ultracache',True)):
            with self.subTest(profile=profile,old_declaration=old_declaration):
                captured=[]
                def origin(path,headers):
                    captured.append(dict(headers))
                    self.assertNotIn('X-UltraCache-Mutation-Context',headers)
                    return 'unchanged response',[('Content-Type','application/json'),('Cache-Control','private, no-store')]
                with proxy(profile,origin) as get:
                    if old_declaration:
                        self.assertEqual(control(get,enabled=True,names='')[0],200)
                    response=get('/wp-json/wp/v2/types')
                    self.assertEqual(response[0],200)
                    self.assertEqual(len(captured),1)


if __name__=='__main__':unittest.main()
