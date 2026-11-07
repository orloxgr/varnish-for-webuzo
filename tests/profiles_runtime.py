"""Verify profiles and central defaults on two disposable native Webuzo sites."""
import argparse
import copy
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--disposable',action='store_true',required=True)
parser.add_argument('--address',required=True)
parser.add_argument('--sites',nargs=2,required=True)
args=parser.parse_args()
if os.geteuid()!=0:parser.error('Run as root on the disposable Linux server')
ipaddress.ip_address(args.address)
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import engine
import profiles
import service

config=engine.settings();sites=[next(s for s in config['sites'].values() if s['domain']==name) for name in args.sites]
if len({s['uid'] for s in sites})!=2 or any(not s['enabled'] or s['error'] for s in sites):parser.error('Select two enabled sites on separate accounts')
original=copy.deepcopy(sites);default=profiles.default(config);basic=profiles.rules(config,'basic')
prefix='/wvw-profiles-'+secrets.token_hex(8);created=[];report=[]

def call(action,**values):return engine.action(dict(actor='root',admin=True,action=action,**values))
def check(value,label):
    if not value:raise AssertionError(label)
    report.append(label)
def assign(site,profile):
    return call('configure',id=site['id'],profile=profile,enabled=site['enabled'],ttl=site['ttl'],bypass=site['bypass'])
def request(site,suffix,headers=None,method='GET'):
    conn=http.client.HTTPConnection(args.address,timeout=20)
    conn.request(method,prefix+suffix+'.php',headers={'Host':site['domain'],**(headers or {})})
    response=conn.getresponse();body=response.read();h={k.lower():v for k,v in response.getheaders()};status=response.status;conn.close()
    return status,h,body
def warm(site,suffix):
    request(site,suffix);r=request(site,suffix);check(r[0]==200 and r[1].get('x-webuzo-varnish')=='HIT','Warm '+site['domain']+' '+suffix);return r
class UnixHTTP(http.client.HTTPConnection):
    def __init__(self):super().__init__('localhost',timeout=15)
    def connect(self):self.sock=socket.socket(socket.AF_UNIX);self.sock.settimeout(15);self.sock.connect('/run/varnish-for-webuzo-cache/frontend.sock')
def capability(site,host=None):
    conn=UnixHTTP();conn.request('PURGE','/__ultracache-vcl-contract-v2',headers={'Host':host or site['domain'],'X-UltraCache-Token':site['token'],'X-UltraCache-Contract':'2','X-UltraCache-Operation':'capabilities'})
    response=conn.getresponse();response.read();result=response.status,dict((k.lower(),v) for k,v in response.getheaders());conn.close();return result

fixed=[Path('/usr/local/apps/nginx/etc/nginx.conf'),Path('/usr/local/apps/nginx/etc/conf.d/proxy.conf'),Path('/usr/local/apps/apache2/etc/httpd.conf')]
hashes={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in fixed}
try:
    for site in sites:
        for suffix in ('public','parent','fragment'):
            path=Path(site['path'])/(prefix[1:]+suffix+'.php');created.append((site,path))
            code="<?php header('Content-Type: text/html'); header('Cache-Control: public, max-age=300'); "
            if suffix=='fragment':code+="echo $_COOKIE['esi_session'] ?? 'MISSING';"
            elif suffix=='parent':
                body='<html><esi:include src="'+prefix+'fragment.php?ultracache_esi=cart&amp;esi_scope=private"/></html>'
                code+="header('Surrogate-Control: ESI/1.0'); header('X-UltraCache-ESI-Shared-Parent: 1'); echo "+json.dumps(body)+";"
            else:code+='echo microtime(true);'
            subprocess.run(['python3','-c','from pathlib import Path;import sys;Path(sys.argv[1]).write_text(sys.argv[2])',str(path),code],user=site['uid'],group=site['gid'],extra_groups=[],check=True)
    first,second=sites
    assign(second,'basic');second_before=warm(second,'public')[2]
    for profile in profiles.NAMES:
        assign(first,profile);call('purge',id=first['id'])
        a,b=request(first,'public',{'Cookie':'unknown_vendor=A'}),request(first,'public',{'Cookie':'unknown_vendor=B'})
        check(a[0]==b[0]==200 and b[1].get('x-webuzo-varnish-profile')==profile,'Selected native profile '+profile)
        check((a[2]!=b[2] and b[1].get('x-webuzo-varnish')=='PASS') if profile=='basic' else (a[2]==b[2] and b[1].get('x-webuzo-varnish')=='HIT'),'Cookie behavior '+profile)
        a,b=request(first,'public',{'Cookie':'PHPSESSID=A'}),request(first,'public',{'Cookie':'PHPSESSID=B'})
        check(a[2]!=b[2] and b[1].get('x-webuzo-varnish')=='PASS','Private session bypass '+profile)
        other=request(second,'public');check(other[1].get('x-webuzo-varnish')=='HIT' and other[2]==second_before,'Profile change preserves other account '+profile)
    a,b=[request(first,'parent',{'Cookie':'esi_session='+visitor+'; woocommerce_items_in_cart=1; ultracache_esi_optin=1'}) for visitor in ('A','B')]
    check(a[2]==b'<html>A</html>' and b[2]==b'<html>B</html>' and b[1].get('x-webuzo-varnish')=='HIT','Native Apache/PHP ESI serves per-visitor fragments from a shared parent')
    status,headers=capability(first);check(status==200 and headers.get('x-ultracache-vcl-adapter')=='ultracache-webuzo-v2','UltraCache Unix capability contract')
    assign(second,'ultracache')
    check(capability(first,second['domain'])[0]==403,'UltraCache token cannot control another account')
    check(request(first,'public',{'X-UltraCache-Token':first['token']},method='PURGE')[0]==403,'Nginx rejects public token-based control')
    assign(first,'basic');assign(second,'wordpress');first_before=warm(first,'public')[2];second_before=warm(second,'public')[2]
    call('defaults',profile='woocommerce')
    current=engine.settings();check(current['sites'][first['id']]['profile']=='basic' and current['sites'][second['id']]['profile']=='wordpress','Changing default preserves existing site profiles')
    check(request(first,'public')[2]==first_before and request(second,'public')[2]==second_before,'Changing default preserves warm existing sites')
    call('profile_rules',profile='basic',recv_vcl='',backend_vcl='set beresp.http.X-User-Central = "basic-template";')
    a=request(first,'public');check(a[1].get('x-webuzo-varnish')=='MISS' and a[1].get('x-user-central')=='basic-template','Central Basic template applied to its sites')
    b=request(second,'public');check(b[1].get('x-webuzo-varnish')=='HIT' and b[2]==second_before and 'x-user-central' not in b[1],'Central Basic change preserves another profile')
    old_policy=service.ACTIVE.read_bytes();old_settings=engine.SETTINGS.read_bytes()
    try:call('profile_rules',profile='basic',recv_vcl='if (req.url ~ "[") { return (pass); }',backend_vcl='')
    except RuntimeError:pass
    else:raise AssertionError('Invalid central regex was accepted')
    check(service.ACTIVE.read_bytes()==old_policy and engine.SETTINGS.read_bytes()==old_settings,'Invalid central VCL preserves prior policy and preferences')
    check(hashes=={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in fixed},'Native Webuzo factory files unchanged')
finally:
    call('profile_rules',profile='basic',**basic)
    call('defaults',profile=default)
    for site in original:assign(site,profiles.selected(site))
    for site,path in created:
        subprocess.run(['python3','-c','from pathlib import Path;import sys;Path(sys.argv[1]).unlink(missing_ok=True)',str(path)],user=site['uid'],group=site['gid'],extra_groups=[],check=True)
    for site in sites:call('purge',id=site['id'])
print(json.dumps(dict(passed=len(report),checks=report),indent=2))
