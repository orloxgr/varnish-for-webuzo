"""Exercise slow GET, POST and streaming through isolated generated proxies.

Run as root on a disposable Linux host with native Nginx and Varnish installed.
No existing service, domain, cache or hosting configuration is changed.
"""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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
import native
import policy
import routing
import timeouts

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--disposable',action='store_true',required=True)
parser.add_argument('--delay',type=float,default=125,help='Slow-origin delay; default exceeds the old 60s and 120s timers')
args=parser.parse_args()
if os.geteuid()!=0 or args.delay<=0:parser.error('Use a positive delay on a disposable Linux/root host')
counts=Counter()
guard=threading.Lock()


class Origin(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def log_message(self,*values):pass
    def do_GET(self):self.respond()
    def do_POST(self):self.respond()
    def respond(self):
        body=self.rfile.read(int(self.headers.get('Content-Length','0')))
        with guard:counts[(self.command,self.path)]+=1
        if self.path.startswith('/slow'):time.sleep(args.delay)
        output=(self.command+':'+self.path+':'+body.decode()).encode()
        self.send_response(200)
        self.send_header('Content-Type','text/html')
        self.send_header('Cache-Control','public, max-age=300')
        self.send_header('Content-Length',str(len(output)))
        self.end_headers()
        if self.path=='/stream':
            self.wfile.write(output[:1]);self.wfile.flush();time.sleep(2)
            self.wfile.write(output[1:])
        else:self.wfile.write(output)


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));return sock.getsockname()[1]


def ready(port,process):
    # Harness startup bound only; never used in the generated hosting policy.
    start=time.monotonic()
    while True:
        if process.poll() is not None:raise RuntimeError('Isolated test process stopped during startup')
        try:
            with socket.create_connection(('127.0.0.1',port),timeout=.2):return
        except OSError:
            if time.monotonic()-start>20:raise RuntimeError('Isolated test listener did not start')
            time.sleep(.05)


origin=ThreadingHTTPServer(('127.0.0.1',0),Origin)
threading.Thread(target=origin.serve_forever,daemon=True).start()
processes=[]
try:
    with tempfile.TemporaryDirectory(prefix='wvw-timeouts-') as folder:
        root=Path(folder);root.chmod(0o755)
        baseline=native.proxy_timeouts()
        front_port,varnish_port,admin_port=free_port(),free_port(),free_port()
        site=dict(id='a'*32,domain='example.test',names=['example.test'],enabled=True,error='',token='b'*64,ttl=300,bypass=[],profile='woocommerce')
        content=policy.render({site['id']:site},'e'*64,'f'*64,{'proxy_timeouts':baseline})
        bridges=routing.origins('f'*64,baseline)
        for scheme in ('http','https'):
            old='/run/varnish-for-webuzo-origin-'+scheme+'.sock'
            new=str(root/(scheme+'.sock'))
            content=content.replace(old,new);bridges=bridges.replace(old,new)
        bridges=bridges.replace('http://127.0.0.1:8081','http://127.0.0.1:'+str(origin.server_port)).replace('https://127.0.0.1:8082','http://127.0.0.1:'+str(origin.server_port))
        (root/'active.vcl').write_text(content)
        (root/'secret').write_text('disposable-test-admin-secret')
        # Deliberately hostile runtime defaults prove that the generated VCL
        # overrides both the old first-byte and between-bytes defaults.
        command=['/usr/sbin/varnishd','-j','none','-F','-a','public=127.0.0.1:'+str(varnish_port),'-T','127.0.0.1:'+str(admin_port),'-S',str(root/'secret'),'-f',str(root/'active.vcl'),'-n',str(root/'cache'),'-s','malloc,32m','-p','first_byte_timeout=1','-p','between_bytes_timeout=1','-p','idle_send_timeout=1','-p','send_timeout=1']
        varnish_log=(root/'varnish.log').open('w+')
        varnish=subprocess.Popen(command,stdout=varnish_log,stderr=subprocess.STDOUT,start_new_session=True);processes.append(varnish)
        ready(varnish_port,varnish)
        front=routing.domain(site,'e'*64,baseline)
        front=front.replace('http://127.0.0.1:8081','http://127.0.0.1:'+str(origin.server_port)).replace('http://unix:/run/varnish-for-webuzo-cache/frontend.sock:','http://127.0.0.1:'+str(varnish_port))
        config='worker_processes 1;\nuser root;\npid '+str(root/'nginx.pid')+';\nerror_log '+str(root/'nginx.log')+';\nevents { worker_connections 128; }\nhttp { access_log off;\n'+bridges+'\nserver { listen 127.0.0.1:'+str(front_port)+'; server_name example.test; root '+str(root)+';\n'+front+'\n}\n}\n'
        (root/'nginx.conf').write_text(config)
        subprocess.run([str(native.NGINX),'-p',str(root),'-c',str(root/'nginx.conf'),'-t'],check=True,capture_output=True)
        nginx_log=(root/'nginx-start.log').open('w+')
        nginx=subprocess.Popen([str(native.NGINX),'-p',str(root),'-c',str(root/'nginx.conf'),'-g','daemon off;'],stdout=nginx_log,stderr=subprocess.STDOUT,start_new_session=True);processes.append(nginx)
        ready(front_port,nginx)

        def request(path,method='GET'):
            start=time.monotonic()
            conn=http.client.HTTPConnection('127.0.0.1',front_port,timeout=args.delay+60)
            try:
                conn.request(method,path,body=b'one-write' if method=='POST' else None,headers={'Host':'example.test'})
                response=conn.getresponse();body=response.read()
                expected=(method+':'+path+':'+('one-write' if method=='POST' else '')).encode()
                assert response.status==200 and body==expected,(path,response.status,body)
                return dict(path=path,method=method,seconds=round(time.monotonic()-start,2),cache=response.getheader('X-Webuzo-Varnish'))
            finally:conn.close()

        print(json.dumps(dict(native_proxy_ms=baseline,first_byte_ms=timeouts.first_byte(baseline),frontend_proxy_ms=timeouts.frontend(baseline))),flush=True)
        with ThreadPoolExecutor(max_workers=3) as pool:
            futures=[pool.submit(request,'/slow-get'),pool.submit(request,'/slow-post','POST'),pool.submit(request,'/stream')]
            for future in futures:print(json.dumps(future.result()),flush=True)
        warm=request('/slow-get');assert warm['cache']=='HIT',warm
        assert counts[('GET','/slow-get')]==1 and counts[('POST','/slow-post')]==1,counts
        print(json.dumps(dict(warm=warm,checks=['Slow GET exceeds old first-byte and Nginx timers','Slow POST completes exactly once without fallback replay','Streaming gap exceeds hostile runtime between-bytes default','Warm response remains a cache HIT'],passed=4)),flush=True)
        for process in reversed(processes):
            os.killpg(process.pid,signal.SIGTERM)
            try:process.wait(timeout=10)
            except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()
        processes.clear();varnish_log.close();nginx_log.close()
finally:
    for process in reversed(processes):
        try:os.killpg(process.pid,signal.SIGTERM);process.wait(timeout=10)
        except ProcessLookupError:pass
        except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()
    origin.shutdown();origin.server_close()
