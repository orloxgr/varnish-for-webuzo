"""Exercise settings against two disposable native Webuzo sites."""
import argparse
import copy
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--disposable',action='store_true',required=True)
parser.add_argument('--address',required=True)
parser.add_argument('--sites',nargs=2,required=True)
args=parser.parse_args()
if os.geteuid()!=0:parser.error('Run as root on the disposable Linux server')
ipaddress.ip_address(args.address)
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import engine
import native
import service

config=engine.settings();sites=[next(s for s in config['sites'].values() if s['domain']==name) for name in args.sites]
if len({s['uid'] for s in sites})!=2 or any(not s['enabled'] or s['error'] for s in sites):parser.error('Select two enabled sites on separate accounts')
original=copy.deepcopy(sites);size=config.get('memory_mb',256);prefix='/wvw-settings-'+secrets.token_hex(8)
created=[];report=[]

def call(action,**values):return engine.action(dict(actor='root',admin=True,action=action,**values))
def check(condition,label):
    if not condition:raise AssertionError(label)
    report.append(label)
def request(site,suffix,headers=None):
    conn=http.client.HTTPConnection(args.address,timeout=20)
    conn.request('GET',prefix+suffix+'.php',headers={'Host':site['domain'],**(headers or {})})
    response=conn.getresponse();body=response.read();status=response.status;h=dict((k.lower(),v) for k,v in response.getheaders());conn.close()
    if status!=200:raise AssertionError('Unexpected HTTP response: '+str(status))
    return h,body
def warm(site,suffix):
    request(site,suffix);r=request(site,suffix)
    check(r[0].get('x-webuzo-varnish')=='HIT','HIT '+site['domain']+' '+suffix)
    return r
def pid():return native.run('systemctl','show','varnish-for-webuzo','--property=MainPID','--value').strip()

try:
    for site in sites:
        for suffix in ('public','private','cookie','bypass'):
            path=Path(site['path'])/(prefix[1:]+suffix+'.php');created.append((site,path))
            extra="header('Cache-Control: private, no-store');" if suffix=='private' else "setcookie('test_private','1');" if suffix=='cookie' else ''
            code="<?php header('Content-Type: text/html'); header('Cache-Control: public, max-age=300'); "+extra+"echo microtime(true);"
            subprocess.run(['python3','-c','from pathlib import Path;import sys;Path(sys.argv[1]).write_text(sys.argv[2])',str(path),code],user=site['uid'],group=site['gid'],extra_groups=[],check=True)
    first,second=sites
    for site in sites:call('purge',id=site['id'])
    for site in sites:warm(site,'public')
    before=warm(second,'public')[1]
    recv='if (req.url ~ "^'+prefix+'bypass[.]php$") { return (pass); }'
    backend='set beresp.http.X-User-Policy = "site-rule"; set beresp.ttl = 120s;'
    call('vcl',id=first['id'],recv_vcl=recv,backend_vcl=backend)
    a=request(first,'public');check(a[0].get('x-webuzo-varnish')=='MISS','VCL save invalidates selected site')
    check(a[0].get('x-user-policy')=='site-rule','Site response VCL executes')
    other=request(second,'public');check(other[0].get('x-webuzo-varnish')=='HIT' and other[1]==before,'VCL save preserves other account cache')
    check('x-user-policy' not in other[0],'Site VCL cannot modify another account response')
    check(request(first,'bypass')[0].get('x-webuzo-varnish')=='PASS','Request VCL return pass executes')
    for suffix in ('private','cookie'):
        a,b=request(first,suffix),request(first,suffix)
        check(a[0].get('x-webuzo-varnish')=='PASS' and b[1]!=a[1],'Custom TTL cannot cache '+suffix+' responses')
    before_policy=service.ACTIVE.read_bytes();before_settings=engine.SETTINGS.read_bytes()
    try:call('vcl',id=first['id'],recv_vcl='if (req.url ~ "[") { return (pass); }',backend_vcl='')
    except RuntimeError:pass
    else:raise AssertionError('Invalid native regex was accepted')
    check(service.ACTIVE.read_bytes()==before_policy and engine.SETTINGS.read_bytes()==before_settings,'Compiler failure preserves active VCL and settings')
    warm(first,'public');warm(second,'public')
    usage=call('usage')['usage'];check(usage['used_bytes']>0 and usage['free_bytes']>0,'Real cache used/free counters')
    connection=call('connection',id=first['id'])['connection']
    check(connection['key']==first['token'] and connection['socket'].endswith('/frontend.sock') and connection['method']=='PURGE','Connection information matches actual scoped capability')
    check(first['token'] not in json.dumps(call('status')),'Status does not disclose site key')
    current_pid=pid();call('resize',memory_mb=size)
    check(pid()==current_pid,'Unchanged cache budget does not restart manager')
    fixed=[Path('/usr/local/apps/nginx/etc/nginx.conf'),Path('/usr/local/apps/nginx/etc/conf.d/proxy.conf'),Path('/usr/local/apps/apache2/etc/httpd.conf')]
    hashes={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in fixed}
    call('resize',memory_mb=size+64)
    check(pid()!=current_pid and engine.settings()['memory_mb']==size+64,'Changed budget restarts only owned service and persists')
    check(request(first,'public')[0].get('x-webuzo-varnish')=='MISS' and request(second,'public')[0].get('x-webuzo-varnish')=='MISS','Resize clears shared cache')
    check(call('usage')['usage']['budget_mb']==size+64,'Usage reflects new configured budget')
    native.run('systemctl','restart','varnish-for-webuzo');service.wait()
    check(engine.settings()['memory_mb']==size+64 and service.UNIT.read_text()==service.unit(size+64),'Nondefault cache budget survives service restart')
    check(hashes=={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in fixed},'Native Webuzo factory files unchanged')
    warm(first,'public');warm(second,'public')
finally:
    for site in original:
        call('vcl',id=site['id'],recv_vcl=site.get('recv_vcl',''),backend_vcl=site.get('backend_vcl',''))
    if engine.settings().get('memory_mb',256)!=size:call('resize',memory_mb=size)
    for site,path in created:
        subprocess.run(['python3','-c','from pathlib import Path;import sys;Path(sys.argv[1]).unlink(missing_ok=True)',str(path)],user=site['uid'],group=site['gid'],extra_groups=[],check=True)
    for site in sites:call('purge',id=site['id'])
print(json.dumps(dict(passed=len(report),checks=report),indent=2))
