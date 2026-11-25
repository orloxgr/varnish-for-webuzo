"""Unified HTML reuses its parent; genuine negotiation and personal output stay separate."""
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
        bucket=('avif' if 'image/avif' in accept else 'webp' if 'image/webp' in accept else 'orig') if self.image_vary else 'html'
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
            'X-UltraCache-Cacheable: 1']
        if self.inner_status is not None:selected['headers'].append('X-Ultra-Cache: '+self.inner_status)
        return json.dumps(output),fields


@unittest.skipUnless(shutil.which('varnishd'),'Native Varnish required')
class SelectionRepresentations(unittest.TestCase):
    def test_wildcard_document_reuses_warmed_original_publication(self):
        app=ImagePublications(image_vary=False)
        with proxy('ultracache',app,policies=choices(('shared_metric','shared'))) as get:
            self.assertEqual(control(get,enabled=True,names='')[0],200)
            status,fields,body=get('/wildcard-document',extra={'Accept':'text/html','X-Test-Visitor':'A'})
            self.assertEqual((status,cache(fields)),(200,'MISS'))
            for accept in ('*/*',' */* ; q=1.0 '):
                status,fields,body=get('/wildcard-document',extra={'Accept':accept,'X-Test-Visitor':'B'})
                self.assertEqual((status,cache(fields)),(200,'HIT'))
                self.assertNotIn('X-UltraCache-Variant',dict(fields))
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

    def test_unified_html_keeps_one_publication_across_image_accepts_and_personal_owners(self):
        self.exercise(ImagePublications(image_vary=False))

    def test_real_origin_accept_vary_keeps_each_publication_separate(self):
        self.exercise(ImagePublications())
    def test_fresh_selected_snapshot_without_inner_hit_uses_its_actual_representation(self):
        for status in (None, 'STORE'):
            with self.subTest(inner_status=status):self.exercise(ImagePublications(image_vary=False,inner_status=status))
    def exercise(self,app):
        path='/same-body-three-publications'
        with proxy('ultracache',app,policies=choices(('shared_metric','shared'))) as get:
            self.assertEqual(control(get,enabled=True,names='')[0],200)
            visits=[('text/html','orig','MISS'),('text/html,image/webp','webp','MISS'),
                ('text/html,image/avif,image/webp','avif','MISS'),
                ('text/html,image/webp','webp','HIT'),
                ('text/html,image/avif,image/webp','avif','HIT'),
                ('text/html','orig','HIT')]
            for i,(accept,bucket,expected) in enumerate(visits):
                if not app.image_vary:expected = 'MISS' if i == 0 else 'HIT'
                visitor='A' if i%2==0 else 'B'
                status,fields,body=get(path,'shared_metric='+visitor,extra={'Accept':accept,'X-Test-Visitor':visitor})
                self.assertEqual((status,cache(fields)),(200,expected))
                self.assertNotIn('X-UltraCache-Variant',dict(fields))
                self.assertEqual(dict(fields).get('X-UltraCache-Delivery-Outcome'),'verified')
                self.assertEqual(body.count('private:'+visitor),2)
                self.assertEqual(body.count('nonce:'+visitor),1)
                self.assertEqual('Accept' in dict(fields).get('Vary',''), app.image_vary)
            self.assertEqual(sum(phase=='public-select' for _,phase,_ in app.calls),3 if app.image_vary else 1)
            self.assertEqual(sum(phase=='prepare' for _,phase,_ in app.calls),3 if app.image_vary else 5)

    def test_unified_public_html_serves_other_image_accepts_after_origin_stops(self):
        app = Application()
        with proxy('ultracache', app) as get:
            self.assertEqual(control(get, enabled=True, names='')[0], 200)
            first = get('/unified', extra={'Accept': 'text/html'})
            self.assertEqual((first[0], cache(first[1])), (200, 'MISS'))
            get.stop_origin()
            for accept in ('text/html,image/webp', 'text/html,image/avif,image/webp',
                           'text/html,image/avif;q=0,image/webp', '*/*'):
                repeated = get('/unified', extra={'Accept': accept})
                self.assertEqual((repeated[0], cache(repeated[1]), repeated[2]), (200, 'HIT', first[2]))
            self.assertEqual(len(app.calls), 1)

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
