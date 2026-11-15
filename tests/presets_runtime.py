"""Run the generated two-preset Nginx/Varnish chain in a disposable lab.

No panel installation, native configuration edits or active service restart.
Optional hold file lets an external browser verify the same isolated listeners.
"""
import argparse
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import browser_cache
import native
import policy

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--disposable',action='store_true',required=True)
parser.add_argument('--address',default='127.0.0.1')
parser.add_argument('--port',type=int,default=0)
parser.add_argument('--hold-file',type=Path)
args=parser.parse_args()
if os.geteuid()!=0:parser.error('Run only as root on a disposable lab')
counts=Counter();seen={};guard=threading.Lock()
WARM='text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8'
BROWSER='text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8'
BODY=b'''<html><body><h1 id="public">Shared page</h1><div id="hover">Hover here</div><script>document.querySelector('#hover').onmouseenter=()=>{document.cookie='_ga=after-hover;path=/';};</script></body></html>'''
class Origin(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def log_message(self,*values):pass
    def do_GET(self):
        with guard:
            counts[(self.headers.get('Host'),self.path)]+=1
            seen[(self.headers.get('Host'),self.path)]=self.headers.get('Cookie')
        private=self.path=='/personal'
        body=(self.headers.get('Cookie','anonymous').encode() if private else BODY)
        self.send_response(200)
        self.send_header('Content-Type','text/html')
        self.send_header('Cache-Control','private, no-store' if private else 'public, max-age=300')
        if not private:
            self.send_header('X-Ultra-Cache-Source','apache-static')
            self.send_header('X-UltraCache-Cacheable','1')
            self.send_header('X-UltraCache-Variant','orig')
            self.send_header('Vary','Accept, Cookie')
        self.send_header('Content-Length',str(len(body)))
        self.end_headers();self.wfile.write(body)

def port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]

def ready(number,process):
    deadline=time.monotonic()+20
    while process.poll() is None:
        try:
            with socket.create_connection(('127.0.0.1',number),timeout=.2):return
        except OSError:
            if time.monotonic()>deadline:break
            time.sleep(.05)
    raise RuntimeError('Isolated test process did not become ready')

origin=ThreadingHTTPServer(('127.0.0.1',0),Origin)
threading.Thread(target=origin.serve_forever,daemon=True).start()
processes=[];logs=[];checks=[]
try:
    with tempfile.TemporaryDirectory(prefix='wvw-presets-runtime-') as folder:
        root=Path(folder);root.chmod(0o755)
        front_port=args.port or port();varnish_port=port();admin_port=port()
        sites={}
        for marker,profile in [('a','basic'),('b','ultracache')]:
            domain=profile+'.example.test'
            sites[marker*32]=dict(id=marker*32,domain=domain,names=[domain],enabled=True,error='',token=marker*64,bypass=[],profile=profile)
        baseline=native.proxy_timeouts()
        vcl=policy.render(sites,'e'*64,'f'*64,{'proxy_timeouts':baseline})
        bridges=__import__('routing').origins('f'*64,baseline)
        for scheme in ('http','https'):
            old='/run/varnish-for-webuzo-origin-'+scheme+'.sock';new=str(root/(scheme+'.sock'))
            vcl=vcl.replace(old,new);bridges=bridges.replace(old,new)
        bridges=bridges.replace('http://127.0.0.1:8081','http://127.0.0.1:'+str(origin.server_port)).replace('https://127.0.0.1:8082','http://127.0.0.1:'+str(origin.server_port))
        (root/'active.vcl').write_text(vcl);(root/'secret').write_text('isolated-test-secret')
        log=(root/'varnish.log').open('w+');logs.append(log)
        v=subprocess.Popen(['/usr/sbin/varnishd','-j','none','-F','-a','public=127.0.0.1:'+str(varnish_port),'-T','127.0.0.1:'+str(admin_port),'-S',str(root/'secret'),'-f',str(root/'active.vcl'),'-n',str(root/'cache'),'-s','malloc,32m'],stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
        processes.append(v);ready(varnish_port,v)
        bridges+=browser_cache.maps(sites,{})
        servers=[]
        for site in sites.values():
            front=__import__('routing').domain(site,'e'*64,baseline).replace('http://127.0.0.1:8081','http://127.0.0.1:'+str(origin.server_port)).replace('http://unix:/run/varnish-for-webuzo-cache/frontend.sock:','http://127.0.0.1:'+str(varnish_port))
            servers.append('server { listen '+args.address+':'+str(front_port)+'; server_name '+site['domain']+'; root '+str(root)+';\n'+front+'\n}\n')
        config='worker_processes 1;\nuser root;\npid '+str(root/'nginx.pid')+';\nerror_log '+str(root/'nginx.log')+';\nevents { worker_connections 128; }\nhttp { access_log off;\n'+bridges+'\n'+''.join(servers)+'\n}'
        (root/'nginx.conf').write_text(config)
        subprocess.run([str(native.NGINX),'-p',str(root),'-c',str(root/'nginx.conf'),'-t'],check=True,capture_output=True)
        log=(root/'nginx-start.log').open('w+');logs.append(log)
        n=subprocess.Popen([str(native.NGINX),'-p',str(root),'-c',str(root/'nginx.conf'),'-g','daemon off;'],stdout=log,stderr=subprocess.STDOUT,start_new_session=True);processes.append(n)
        deadline=time.monotonic()+20
        while True:
            try:
                with socket.create_connection((args.address,front_port),timeout=.2):break
            except OSError:
                if n.poll() is not None or time.monotonic()>deadline:raise RuntimeError('Isolated Nginx did not start')
                time.sleep(.05)
        def request(host,path,headers=None):
            conn=http.client.HTTPConnection(args.address,front_port,timeout=15)
            conn.request('GET',path,headers={'Host':host,**(headers or {})})
            response=conn.getresponse();data=response.read();h={k.lower():v for k,v in response.getheaders()};status=response.status;conn.close()
            assert status==200,(status,data)
            return h,data
        for site in sites.values():
            host=site['domain']
            h,b=request(host,'/public',{'Accept':WARM});assert h['x-webuzo-varnish']=='MISS'
            h,b=request(host,'/public',{'Accept':BROWSER,'Cookie':'_ga=hover'});assert h['x-webuzo-varnish']=='HIT'
            assert counts[(host,'/public')]==1
            first='/landing?utm_source=facebook&lang=el'
            second='/landing?lang=el&utm_source=google'
            h,b=request(host,first,{'Cookie':'lang=el; _ga=A'})
            assert h['x-webuzo-varnish']=='MISS'
            h,b=request(host,second,{'Cookie':'lang=el; _ga=B'})
            assert h['x-webuzo-varnish']=='HIT'
            assert counts[(host,first)]==1 and counts[(host,second)]==0
            assert seen[(host,first)]=='lang=el; _ga=A'
            h,b=request(host,second,{'Cookie':'lang=en; _ga=C'})
            assert h['x-webuzo-varnish']=='MISS'
            assert seen[(host,second)]=='lang=en; _ga=C'
            for person in ('alice','bob'):
                h,b=request(host,'/personal',{'Cookie':'wordpress_logged_in_demo='+person})
                assert h['x-webuzo-varnish']=='PASS' and person.encode() in b
            for path in ('/wp-json/wp/v2/posts','/?s=shoes','/article/?ref=campaign'):
                h,b=request(host,path,{'X-Requested-With':'XMLHttpRequest'});assert h['x-webuzo-varnish']=='MISS'
                h,b=request(host,path,{'X-Requested-With':'XMLHttpRequest'});assert h['x-webuzo-varnish']=='HIT'
            request(host,'/browser',{'Accept':WARM})
            checks.append(host+': warmup/browser HIT, tracking cookie HIT, separate authenticated bodies, public REST/search/ref AJAX HIT')
        print(json.dumps({'passed':checks,'front_port':front_port}),flush=True)
        if args.hold_file:
            args.hold_file.write_text(json.dumps({'port':front_port,'hosts':[s['domain'] for s in sites.values()]}))
            args.hold_file.chmod(0o644)
            while args.hold_file.exists():time.sleep(.2)
finally:
    for process in reversed(processes):
        try:os.killpg(process.pid,signal.SIGTERM);process.wait(timeout=10)
        except ProcessLookupError:pass
        except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()
    for log in logs:log.close()
    origin.shutdown();origin.server_close()
