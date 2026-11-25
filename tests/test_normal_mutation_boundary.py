"""Unmodified generated VCL, actual native module; mock signed event producer.

Actual Nginx file routing and PHP/SQL persistence require installed Lab tests.
"""
import os
import shutil
import unittest

import test_mutation_backend as backend
import test_reuse_authority as authority
from test_cookie_delivery import proxy
from test_public_selection_runtime import control
from test_reuse_delivery_context import signed_context


@unittest.skipUnless(shutil.which('varnishd') and os.environ.get('SCP_EXPERIMENTAL_REUSE_TEST')=='1',
                     'Matching installed-engine module required')
class NormalGeneratedMutationBoundary(unittest.TestCase):
    call=authority.NativeReuseAuthority.call
    observe=authority.NativeReuseAuthority.observe
    publish=authority.NativeReuseAuthority.publish
    ready=authority.NativeReuseAuthority.ready

    def test_normal_dynamic_get_and_post_use_signed_context_without_test_vcl_injection(self):
        for method,path in (('GET','/wp-json/wp/v2/types?context=view'),
                            ('GET','/wp-json/custom/dynamic.css'),
                            ('POST','/wp-admin/admin-ajax.php?action=owned_read')):
            with self.subTest(method=method,path=path):
                captured=[]
                def origin(actual,headers):
                    self.assertEqual(actual,path)
                    c=signed_context(self,headers,path,method);captured.append(c)
                    self.assertEqual(set(c),{'schemaVersion','proof',*backend.FIELDS[:-2]})
                    self.assertEqual(c['schemaVersion'],1)
                    if headers.get('X-UltraCache-Delivery-Phase')=='public-select':
                        self.assertEqual(headers.get('X-UltraCache-Delivery-Authorization'),'b'*64)
                    else:
                        self.assertNotIn('X-UltraCache-Delivery-Authorization',headers)
                    return 'original application response',[
                        ('Content-Type','application/json'),('Cache-Control','private, no-store'),
                        ('X-UltraCache-Mutation-Receipt',backend.receipt(c,'none',()))]
                with proxy('ultracache',origin,allow_post=True) as get:
                    authority.NativeReuseAuthority.register(self,get);old=self.ready(get)
                    response=get(path) if method=='GET' else backend.post(get,path)
                    self.assertEqual(response[0],200)
                    self.assertEqual(len(captured),1)
                    self.assertNotIn('X-UltraCache-Mutation-Receipt',dict(response[1]))
                    current=self.observe(get)
                    self.assertEqual((current['scopeState'],current['contentRevision'],current['scopeRevision']),
                                     ('ready',old['contentRevision'],old['scopeRevision']))
                    self.assertNotIn('temporaryHolds',current)
                    self.assertNotIn('unsettledExecutions',current)

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
