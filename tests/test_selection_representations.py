"""Publication metadata must preserve representation Vary even for identical HTML."""
import hashlib
import json
import shutil
import unittest
from urllib.parse import quote
from test_cookie_delivery import proxy
from test_cms_cookie_choices import cache
from test_cold_public_selection import Application, choices
from test_delivery_continuation import envelope
from test_public_selection_runtime import control


class ImagePublications(Application):
    def __init__(self, image_vary=True, inner_status="HIT"):
        super().__init__(private=True)
        self.image_vary=image_vary
        self.inner_status=inner_status
    def __call__(self,path,headers):
        accept=headers.get('Accept','')
        bucket='avif' if 'image/avif' in accept else 'webp' if 'image/webp' in accept else 'orig'
        manifest='image-'+hashlib.sha256((path+'|'+bucket).encode()).hexdigest()
        if headers.get('X-UltraCache-Delivery-Phase')=='prepare':
            self.calls.append((path,'prepare',headers.get('Cookie')))
            if headers.get('X-UltraCache-Delivery-Manifest')!=manifest:
                return 409,'publication-binding-mismatch',[('Cache-Control','private, no-store')]
            return envelope(headers,headers.get('X-Test-Visitor','guest')),[('Cache-Control','private, no-store'),('X-UltraCache-Delivery-Outcome','verified')]
        raw,fields=super().__call__(path,headers)
        if headers.get('X-UltraCache-Delivery-Phase')!='public-select':
            return raw,fields
        output=json.loads(raw);selected=output['selectedPublic'];selected['manifest']=manifest
        selected['headers']=[line for line in selected['headers'] if not line.startswith(('Vary:','X-UltraCache-Delivery-Prepare:'))]
        selected['headers'] += ['Vary: '+('Accept, Cookie' if self.image_vary else 'Cookie'),
            'X-UltraCache-Delivery-Prepare: /index.php?ultracache_delivery='+quote(manifest,safe=''),
            'X-UltraCache-Variant: '+bucket,'X-UltraCache-Cacheable: 1']
        if self.inner_status is not None:selected['headers'].append('X-Ultra-Cache: '+self.inner_status)
        return json.dumps(output),fields


@unittest.skipUnless(shutil.which('varnishd'),'Native Varnish required')
class SelectionRepresentations(unittest.TestCase):
    def test_wildcard_document_reuses_warmed_original_publication(self):
        app=ImagePublications()
        with proxy('ultracache',app,policies=choices(('shared_metric','shared'))) as get:
            self.assertEqual(control(get,enabled=True,names='')[0],200)
            status,fields,body=get('/wildcard-document',extra={'Accept':'text/html','X-Test-Visitor':'A'})
            self.assertEqual((status,cache(fields)),(200,'MISS'))
            for accept in ('*/*',' */* ; q=1.0 '):
                status,fields,body=get('/wildcard-document',extra={'Accept':accept,'X-Test-Visitor':'B'})
                self.assertEqual((status,cache(fields)),(200,'HIT'))
                self.assertEqual(dict(fields).get('X-UltraCache-Variant'),'orig')
                self.assertEqual(dict(fields).get('X-UltraCache-Delivery-Outcome'),'verified')
                self.assertIn('private:B',body)
                self.assertNotIn('private:A',body)
            self.assertEqual(sum(phase=='public-select' for _,phase,_ in app.calls),1)

    def test_other_negotiations_and_non_document_fetches_keep_their_own_variant(self):
        for accept,destination in (('*/*;q=0',None),('application/json,*/*',None),
                ('*/*','image'),('text/plain,*/*',None)):
            app=ImagePublications()
            with self.subTest(accept=accept,destination=destination),proxy('ultracache',app,policies=choices(('shared_metric','shared'))) as get:
                self.assertEqual(control(get,enabled=True,names='')[0],200)
                self.assertEqual(cache(get('/exact-negotiation',extra={'Accept':'text/html'})[1]),'MISS')
                headers={'Accept':accept}
                if destination is not None:headers['Sec-Fetch-Dest']=destination
                status,fields,body=get('/exact-negotiation',extra=headers)
                self.assertEqual((status,cache(fields)),(200,'PASS' if destination=='image' else 'MISS'))

    def test_three_equal_body_publications_keep_their_own_locator_and_reuse_each_bucket(self):
        self.exercise(ImagePublications())
    def test_fresh_selected_snapshot_without_inner_hit_uses_its_actual_representation(self):
        for status in (None, 'STORE'):
            with self.subTest(inner_status=status):self.exercise(ImagePublications(inner_status=status))
    def exercise(self,app):
        path='/same-body-three-publications'
        with proxy('ultracache',app,policies=choices(('shared_metric','shared'))) as get:
            self.assertEqual(control(get,enabled=True,names='')[0],200)
            visits=[('text/html','orig','MISS'),('text/html,image/webp','webp','MISS'),
                ('text/html,image/avif,image/webp','avif','MISS'),
                ('text/html,application/xhtml+xml,image/webp,*/*;q=0.8','webp','HIT'),
                ('text/html,application/xhtml+xml,image/avif,image/webp,*/*;q=0.8','avif','HIT'),
                ('text/html,application/xhtml+xml,*/*;q=0.8','orig','HIT')]
            for i,(accept,bucket,expected) in enumerate(visits):
                visitor='A' if i%2==0 else 'B'
                status,fields,body=get(path,'shared_metric='+visitor,extra={'Accept':accept,'X-Test-Visitor':visitor})
                self.assertEqual((status,cache(fields)),(200,expected))
                self.assertEqual(dict(fields).get('X-UltraCache-Variant'),bucket)
                self.assertEqual(dict(fields).get('X-UltraCache-Delivery-Outcome'),'verified')
                self.assertEqual(body.count('private:'+visitor),2)
                self.assertEqual(body.count('nonce:'+visitor),1)
                self.assertIn('Accept',dict(fields).get('Vary',''))
            self.assertEqual([phase for _,phase,_ in app.calls],['public-select']*3+['prepare']*3)

    def test_ordinary_store_and_client_marker_cannot_claim_authenticated_selection(self):
        for profile in ('basic','ultracache'):
            calls=[]
            def origin(path,headers):
                calls.append(headers.get('Accept'))
                return '<html>ordinary STORE</html>',[('Content-Type','text/html'),
                    ('Cache-Control','public, max-age=120'),('Vary','Accept'),
                    ('X-UltraCache-Variant','webp'),('X-UltraCache-Cacheable','1'),
                    ('X-Ultra-Cache','STORE'),('X-SCP-Selection-Local','1')]
            with self.subTest(profile=profile),proxy(profile,origin) as get:
                for accept in ('text/html,image/webp','text/html,application/xhtml+xml,image/webp'):
                    status,fields,body=get('/ordinary-store',extra={'Accept':accept,'X-SCP-Selection-Local':'1'})
                    self.assertEqual((status,cache(fields),body),(200,'MISS','<html>ordinary STORE</html>'))
                self.assertEqual(len(calls),2)


if __name__=='__main__':unittest.main()
