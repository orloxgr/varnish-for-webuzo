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
    def __init__(self, image_vary=True):
        super().__init__(private=True)
        self.image_vary=image_vary
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
        output=json.loads(raw);selected=output['selectedPublic'];selected['manifest']=manifest
        selected['headers']=[line for line in selected['headers'] if not line.startswith(('Vary:','X-UltraCache-Delivery-Prepare:'))]
        selected['headers'] += ['Vary: '+('Accept, Cookie' if self.image_vary else 'Cookie'),
            'X-UltraCache-Delivery-Prepare: /index.php?ultracache_delivery='+quote(manifest,safe=''),
            'X-UltraCache-Variant: '+bucket,'X-UltraCache-Cacheable: 1','X-Ultra-Cache: HIT']
        return json.dumps(output),fields


@unittest.skipUnless(shutil.which('varnishd'),'Native Varnish required')
class SelectionRepresentations(unittest.TestCase):
    def application(self):
        return ImagePublications()
    def test_three_equal_body_publications_keep_their_own_locator_and_reuse_each_bucket(self):
        app=self.application();path='/same-body-three-publications'
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


if __name__=='__main__':unittest.main()
