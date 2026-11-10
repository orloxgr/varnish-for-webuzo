"""Browser policy boundaries and real Nginx response/fallback behavior."""
import http.client
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import browser_cache
import engine
import native
import routing


def site(identity='a'):
    return dict(id=identity*32,names=['example.test'],enabled=True,error='',bypass=[])


class BrowserPolicies(unittest.TestCase):
    def test_ultracache_automatic_pattern_preserves_preferences_and_follows_profile(self):
        first=site();first['profile']='ultracache'
        choice=browser_cache.defaults({});choice.update(static_seconds=123,versioned_seconds=456,versioned_paths=['/assets/app-{hash}.js'])
        first['browser_cache']=choice
        selected=browser_cache.selected(first,{})
        preset=browser_cache.PROFILE_PATHS['ultracache'][0]
        self.assertEqual(selected['versioned_paths'],['/assets/app-{hash}.js',preset])
        self.assertEqual(selected['versioned_seconds'],456)
        self.assertEqual(choice['versioned_paths'],['/assets/app-{hash}.js'])
        choice['enabled']=False
        self.assertFalse(browser_cache.selected(first,{})['enabled'])
        self.assertNotIn('immutable',browser_cache.maps({first['id']:first},{}))
        first['profile']='wordpress'
        self.assertEqual(browser_cache.selected(first,{})['versioned_paths'],['/assets/app-{hash}.js'])
        first.update(profile='ultracache',browser_cache=None)
        inherited=browser_cache.selected(first,dict(browser_cache=choice))
        self.assertEqual(inherited['versioned_paths'],['/assets/app-{hash}.js',preset])
        self.assertFalse(inherited['enabled'])
        choice['versioned_paths'].append(preset)
        self.assertEqual(browser_cache.selected(first,dict(browser_cache=choice))['versioned_paths'].count(preset),1)

    def test_defaults_and_site_overrides_do_not_mutate_shared_settings(self):
        config={};first=site();second=site('b')
        self.assertEqual(browser_cache.selected(first,config)['static_seconds'],2592000)
        own=browser_cache.defaults(config);own['static_seconds']=123;first['browser_cache']=own
        self.assertEqual(browser_cache.selected(first,config)['static_seconds'],123)
        self.assertEqual(browser_cache.selected(second,config)['static_seconds'],2592000)
        central=browser_cache.defaults(config);central['static_seconds']=456;config['browser_cache']=central
        self.assertEqual(browser_cache.selected(first,config)['static_seconds'],123)
        self.assertEqual(browser_cache.selected(second,config)['static_seconds'],456)
        first['browser_cache']=None
        self.assertEqual(browser_cache.selected(first,config)['static_seconds'],456)

    def test_existing_and_new_inventory_keep_central_inheritance_or_explicit_override(self):
        first,second=site(),site('b')
        for row in (first,second):row.update(domain='example.test')
        choice=browser_cache.defaults({});choice['enabled']=False
        config=dict(sites={first['id']:dict(browser_cache=choice)})
        with patch.object(native,'collect',return_value={row['id']:row for row in (first,second)}):
            found=engine.inventory(config)
        self.assertEqual(found[first['id']]['browser_cache'],choice)
        self.assertIsNone(found[second['id']]['browser_cache'])

    def test_invalid_values_and_configuration_injection_are_rejected(self):
        base=browser_cache.defaults({})
        for key,value in [('enabled',1),('static_seconds',True),('static_seconds',-1),('versioned_seconds',1.5),('static_seconds',2147483648),('versioned_paths','/assets/')]:
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):browser_cache.validate(dict(base,**{key:value}))
        with self.assertRaises(ValueError):browser_cache.validate(dict(base,nginx='return 200;'))
        for value in ['/assets/*.js','relative-{hash}.css','/a/{hash}.php','/a/{hash}.js?ver=x','/a/{hash}.js;return 200','/a/{hash}.js\nreturn 200','/../{hash}.css','/**/{hash}.js','/{other}-{hash}.css']:
            with self.subTest(value=value),self.assertRaises(ValueError):browser_cache.pattern(value)

    def test_only_declared_fingerprints_get_immutable_and_never_query_strings(self):
        first=site();choice=browser_cache.defaults({});choice['versioned_paths']=['/assets/app-{hash}.js']
        text=browser_cache.maps({first['id']:first},dict(browser_cache=choice))
        self.assertIn('immutable',text);self.assertIn('$request_method:$status:$uri',text)
        self.assertNotIn('$args',text);self.assertNotIn('$arg_ver',text)
        self.assertNotIn('immutable',browser_cache.maps({first['id']:first},{}))
        self.assertEqual(browser_cache.control(0,True),'no-cache')


class Origin(BaseHTTPRequestHandler):
    def do_GET(self):
        status=404 if self.path.startswith('/missing') else 200
        body=b'private application response'
        self.send_response(status);self.send_header('Content-Type','text/html')
        self.send_header('Cache-Control','private, no-store');self.send_header('Content-Length',str(len(body)))
        self.end_headers();self.wfile.write(body)
    def log_message(self,*args):pass


@unittest.skipUnless(sys.platform.startswith('linux') and native.NGINX.is_file(),'Native Webuzo Nginx is required')
class NativeBrowserHeaders(unittest.TestCase):
    def test_generated_static_policy_validators_mime_and_application_fallbacks(self):
        with tempfile.TemporaryDirectory(prefix='wvw-browser-') as folder:
            root=Path(folder);first=site();choice=browser_cache.defaults({});choice['versioned_paths']=['/app-{hash}.js']
            for name in ('plain.css','app-'+('a'*32)+'.js','module.mjs','font.woff2','image.avifs','program.wasm','app.webmanifest'):(root/name).write_text('public asset content')
            # The same generated locations/HTTP maps used in the native panel.
            origin=ThreadingHTTPServer(('127.0.0.1',0),Origin);worker=threading.Thread(target=origin.serve_forever,daemon=True);worker.start()
            with socket.socket() as listener:listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
            proxy='http://127.0.0.1:'+str(origin.server_port)
            def configure(settings):
                front=routing.domain(first,'e'*64).replace('http://unix:/run/varnish-for-webuzo-cache/frontend.sock:',proxy).replace('http://127.0.0.1:8081',proxy)
                config='worker_processes 1;\n'+('user root;\n' if os.geteuid()==0 else '')+'pid '+str(root/'nginx.pid')+';\nerror_log '+str(root/'nginx.log')+';\nevents {}\nhttp { access_log off;\n'+browser_cache.maps({first['id']:first},dict(browser_cache=settings))+'server { listen 127.0.0.1:'+str(port)+'; server_name example.test; root '+str(root)+';\n'+front+'\n}\n}'
                (root/'nginx.conf').write_text(config)
                result=subprocess.run([str(native.NGINX),'-p',str(root),'-c',str(root/'nginx.conf'),'-t'],capture_output=True,text=True)
                self.assertEqual(result.returncode,0,result.stderr)
            configure(choice)
            log=(root/'process.log').open('w+')
            process=subprocess.Popen([str(native.NGINX),'-p',str(root),'-c',str(root/'nginx.conf'),'-g','daemon off;'],stdout=log,stderr=subprocess.STDOUT)
            try:
                def request(path,headers=None,method='GET'):
                    connection=http.client.HTTPConnection('127.0.0.1',port,timeout=5)
                    try:
                        connection.request(method,path,headers={'Host':'example.test',**(headers or {})})
                        response=connection.getresponse();body=response.read()
                        return response.status,response.getheaders(),body
                    finally:connection.close()
                for _ in range(100):
                    try:request('/plain.css');break
                    except OSError:
                        if process.poll() is not None:log.seek(0);self.fail(log.read())
                        time.sleep(.05)
                else:self.fail('Disposable Nginx did not start')
                def cache(path,expected,**args):
                    status,headers,body=request(path,**args)
                    values=[v for k,v in headers if k.lower()=='cache-control']
                    self.assertEqual(values,[expected],(path,status,headers));return status,dict((k.lower(),v) for k,v in headers),body
                ordinary='public, max-age=2592000';immutable='public, max-age=31536000, immutable'
                status,headers,_=cache('/plain.css',ordinary);self.assertEqual(status,200)
                self.assertEqual(cache('/plain.css',ordinary,headers={'If-None-Match':headers['etag']})[0],304)
                self.assertEqual(cache('/plain.css',ordinary,headers={'If-Modified-Since':headers['last-modified']})[0],304)
                self.assertEqual(cache('/plain.css',ordinary,headers={'Range':'bytes=0-3'})[0],206)
                self.assertEqual(cache('/plain.css',ordinary,method='HEAD')[2],b'')
                cache('/plain.css?ver=1',ordinary);cache('/app-'+('a'*32)+'.js?ver=1',immutable)
                for path,mime in [('module.mjs','application/javascript'),('image.avifs','image/avif-sequence'),('program.wasm','application/wasm'),('app.webmanifest','application/manifest+json'),('font.woff2','font/woff2')]:
                    self.assertEqual(cache('/'+path,ordinary)[1]['content-type'],mime)
                self.assertEqual(cache('/missing.css','private, no-store')[0],404)
                self.assertEqual(cache('/application.css','private, no-store')[0],200)
                self.assertEqual(cache('/page','private, no-store')[0],200)
                status,headers,_=request('/plain.css',method='POST');self.assertEqual(status,405)
                self.assertNotIn('cache-control',dict((k.lower(),v) for k,v in headers))
                # The named bypass location must retain the application's policy
                # even when its URL points at an existing asset.
                first['bypass']=['/plain.css'];configure(choice)
                subprocess.run([str(native.NGINX),'-p',str(root),'-c',str(root/'nginx.conf'),'-s','reload'],check=True,capture_output=True)
                for _ in range(100):
                    status,headers,_=request('/plain.css')
                    if dict((k.lower(),v) for k,v in headers).get('cache-control')=='private, no-store':break
                    time.sleep(.05)
                else:self.fail('Static bypass did not reach the application')
                # Selecting UltraCache applies its preset to a real existing CSS
                # bundle without writing a site override or changing lifetimes.
                path='/wp-content/uploads/ultracache/css-bundles/bundle-aggressive-'+('b'*32)+'.css'
                asset=root/path[1:];asset.parent.mkdir(parents=True);asset.write_text('body {color:blue}')
                for profile,expected in [('ultracache',immutable),('wordpress',ordinary)]:
                    first['profile']=profile;configure(choice)
                    subprocess.run([str(native.NGINX),'-p',str(root),'-c',str(root/'nginx.conf'),'-s','reload'],check=True,capture_output=True)
                    for _ in range(100):
                        status,headers,_=request(path)
                        values=[v for k,v in headers if k.lower()=='cache-control']
                        if values==[expected]:break
                        time.sleep(.05)
                    else:self.fail('Automatic preset did not follow profile '+profile)
                    self.assertEqual(status,200)
            finally:
                process.terminate();process.wait(timeout=10);log.close();origin.shutdown();origin.server_close();worker.join()


if __name__=='__main__':unittest.main()
