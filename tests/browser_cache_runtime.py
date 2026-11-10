"""Verify browser-cache settings on two disposable native Webuzo sites."""
import argparse
import copy
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import sys

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--disposable',action='store_true',required=True)
parser.add_argument('--address',required=True)
parser.add_argument('--sites',nargs=2,required=True)
parser.add_argument('--self-signed',action='store_true')
args=parser.parse_args()
if os.geteuid()!=0:parser.error('Run as root only on the disposable server')
ipaddress.ip_address(args.address)
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import browser_cache
import engine
import native
import service

def call(action,**values):return engine.action(dict(actor='root',admin=True,action=action,**values))

call('reconcile');original=copy.deepcopy(engine.settings())
sites=[next(s for s in original['sites'].values() if s['domain']==name) for name in args.sites]
if len({s['uid'] for s in sites})!=2 or any(not s['enabled'] or s['error'] for s in sites):parser.error('Select two enabled disposable sites on separate accounts')
prefix='/wvw-browser-'+secrets.token_hex(8);fingerprint=hashlib.sha256(b'console.log("public asset");').hexdigest()
assets={prefix+'.css':b'body {color:blue}',prefix+'-'+fingerprint+'.js':b'console.log("public asset");',prefix+'.mjs':b'export default 1;',prefix+'.avifs':b'test',prefix+'.wasm':b'\x00asm',prefix+'.webmanifest':b'{"name":"test"}',prefix+'.woff2':b'test'}
public=prefix+'-public.php';private=prefix+'-private.php'
assets[public]=b'<?php header("Content-Type: text/html");header("Cache-Control: public, max-age=300");echo microtime(true);'
assets[private]=b'<?php header("Content-Type: text/html");header("Cache-Control: private, no-store");echo microtime(true);'
created=[];checks=[]
fixed=[Path('/usr/local/apps/nginx/etc/nginx.conf'),Path('/usr/local/apps/nginx/etc/conf.d/proxy.conf'),Path('/usr/local/apps/apache2/etc/httpd.conf')]
hashes={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in fixed}
pid=native.run('systemctl','show','varnish-for-webuzo','--property=MainPID','--value').strip()

def check(value,label):
    if not value:raise AssertionError(label)
    checks.append(label)

def request(site,path,port=80,headers=None,method='GET'):
    client=http.client.HTTPSConnection(args.address,port,context=ssl._create_unverified_context() if args.self_signed else ssl.create_default_context(),timeout=15) if port==443 else http.client.HTTPConnection(args.address,port,timeout=15)
    try:
        client.request(method,path,headers={'Host':site['domain'],**(headers or {})})
        response=client.getresponse();body=response.read();pairs=response.getheaders()
        return response.status,{k.lower():v for k,v in pairs},body,[v for k,v in pairs if k.lower()=='cache-control']
    finally:client.close()

try:
    for site in sites:
        for path,body in assets.items():
            target=Path(site['path'])/path[1:]
            subprocess.run(['python3','-c','import sys;open(sys.argv[1],"xb").write(bytes.fromhex(sys.argv[2]))',str(target),body.hex()],user=site['uid'],group=site['gid'],extra_groups=[],check=True)
            created.append((site,target))
        call('browser_site',id=site['id'],settings=None)
    choice=browser_cache.defaults({});choice.update(static_seconds=1234,versioned_seconds=98765,versioned_paths=[prefix+'-{hash}.js'])
    call('browser_defaults',settings=choice)
    for site in sites:
        for port in (80,443):
            response=request(site,prefix+'.css',port)
            check(response[0]==200 and response[3]==['public, max-age=1234'] and response[1].get('x-webuzo-varnish')=='STATIC','Static headers '+site['domain']+' '+str(port))
            check(request(site,prefix+'-'+fingerprint+'.js',port)[3]==['public, max-age=98765, immutable'],'Declared fingerprint '+site['domain']+' '+str(port))
            check(request(site,prefix+'.css?ver=123',port)[3]==['public, max-age=1234'],'Query version is not guessed '+site['domain']+' '+str(port))
            check(request(site,prefix+'.css',port,headers={'If-None-Match':response[1]['etag']})[0]==304,'Native ETag revalidation '+site['domain']+' '+str(port))
        for extension,mime in [('mjs','application/javascript'),('avifs','image/avif-sequence'),('wasm','application/wasm'),('webmanifest','application/manifest+json'),('woff2','font/woff2')]:
            response=request(site,prefix+'.'+extension)
            check(response[0]==200 and response[1].get('content-type')==mime,'Native MIME '+extension+' '+site['domain'])
        response=request(site,private)
        check(response[3]==['private, no-store'] and response[1].get('x-webuzo-varnish')=='PASS','Private HTML policy preserved '+site['domain'])
        request(site,public);response=request(site,public)
        check(response[1].get('x-webuzo-varnish')=='HIT','Public HTML cache still works '+site['domain'])
    first,second=sites
    own=dict(choice,static_seconds=4321);call('browser_site',id=first['id'],settings=own)
    check(request(first,prefix+'.css')[3]==['public, max-age=4321'] and request(second,prefix+'.css')[3]==['public, max-age=1234'],'Per-site override preserves other account')
    choice['static_seconds']=2345;call('browser_defaults',settings=choice)
    check(request(first,prefix+'.css')[3]==['public, max-age=4321'] and request(second,prefix+'.css')[3]==['public, max-age=2345'],'Central change respects explicit site override')
    check(all(request(site,public)[1].get('x-webuzo-varnish')=='HIT' for site in sites),'Browser policy changes preserve warm HTML objects')
    own['enabled']=False;call('browser_site',id=first['id'],settings=own)
    check(not request(first,prefix+'.css')[3],'Per-site browser cache headers can be disabled')
    own.update(enabled=True,static_seconds=0);call('browser_site',id=first['id'],settings=own)
    check(request(first,prefix+'.css')[3]==['no-cache'],'Zero lifetime requires revalidation')
    call('browser_site',id=first['id'],settings=None);call('reconcile')
    check(request(first,prefix+'.css')[3]==['public, max-age=2345'],'Restore central inheritance and retain after refresh')
    before=engine.SETTINGS.read_bytes()
    try:call('browser_defaults',settings=dict(choice,versioned_paths=['/assets/{hash}.js;return 200']))
    except ValueError:pass
    else:raise AssertionError('Malformed URL pattern accepted')
    check(engine.SETTINGS.read_bytes()==before,'Rejected settings leave saved configuration unchanged')
    check(native.run('systemctl','show','varnish-for-webuzo','--property=MainPID','--value').strip()==pid,'No Varnish manager restart')
    check(hashes=={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in fixed},'Native Webuzo factory files unchanged')
finally:
    engine.apply(engine.settings(),original)
    for site,target in created:
        subprocess.run(['python3','-c','from pathlib import Path;import sys;Path(sys.argv[1]).unlink(missing_ok=True)',str(target)],user=site['uid'],group=site['gid'],extra_groups=[],check=True)
    for site in sites:service.purge(site)
print(json.dumps(dict(passed=len(checks),checks=checks),indent=2))
