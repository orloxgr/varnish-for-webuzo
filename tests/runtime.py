"""Run only on an explicitly selected disposable Webuzo installation."""
from pathlib import Path
import argparse,hashlib,http.client,ipaddress,json,os,pwd,secrets,socket,ssl,subprocess,sys,time
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--disposable',action='store_true',required=True)
parser.add_argument('--address',required=True,help='This disposable serverβ€™s frontend IP')
parser.add_argument('--self-signed',action='store_true',help='Allow self-signed certificates in this disposable test only')
parser.add_argument('--sites',nargs=2,required=True,help='Two enabled disposable WordPress domains with HTTPS')
args=parser.parse_args()
if os.geteuid()!=0:parser.error('Run on the disposable Linux server as root')
ipaddress.ip_address(args.address)
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import engine,service
config=engine.settings()
sites=[next(s for s in config['sites'].values() if s['domain']==name) for name in args.sites]
if len({s['uid'] for s in sites})!=2 or any(not s['enabled'] or s['error'] for s in sites):parser.error('Select two enabled, separate hosting accounts')
original={s['id']:dict(enabled=s['enabled'],ttl=s['ttl'],bypass=list(s['bypass'])) for s in sites}
nonce=secrets.token_hex(8);prefix='wvw-'+nonce
expected_source=[None]
report={};created=[]

def as_user(site,args):return subprocess.run(args,user=site['uid'],group=site['gid'],extra_groups=[],capture_output=True,text=True,check=True)
class UnixHTTP(http.client.HTTPConnection):
 def __init__(self,path):super().__init__('localhost',timeout=15);self.socket_path=path
 def connect(self):self.sock=socket.socket(socket.AF_UNIX);self.sock.settimeout(15);self.sock.connect(self.socket_path)

def request(site,path,port=80,headers=None,method='GET',local=False,origin=False):
 if local or origin:c=UnixHTTP('/run/varnish-for-webuzo-origin-http.sock' if origin else '/run/varnish-for-webuzo-cache/frontend.sock')
 else:c=http.client.HTTPSConnection(args.address,port,context=ssl._create_unverified_context() if args.self_signed else ssl.create_default_context(),timeout=15) if port==443 else http.client.HTTPConnection(args.address,port,timeout=15)
 c.connect()
 if not (local or origin):expected_source[0]=c.sock.getsockname()[0]
 c.request(method,path,headers={'Host':site['domain'],'User-Agent':'VarnishWebuzoLab',**(headers or {})});r=c.getresponse();body=r.read();h={k.lower():v for k,v in r.getheaders()};status=r.status;c.close();return status,h,body

def check(value,message):
 if not value:raise AssertionError(message)
 report[message]=True

def pair(site,path,expected='HIT',**kw):
 a=request(site,path,**kw);b=request(site,path,**kw)
 check(a[0]==200 and b[0]==200,'200 '+path+' '+str(kw))
 check(b[1].get('x-webuzo-varnish')==expected,expected+' '+path+' '+str(kw))
 if expected=='HIT':check(a[2]==b[2],'cached body '+path+' '+str(kw))
 return a,b

try:
 for site in sites:
  for case in ('public','private','cookie','error','css','protected'):
   suffix='.css' if case in ('css','protected') else '.php'
   name=prefix+'-'+case+suffix;path=Path(site['path'])/name;created.append((site,path))
   if case in ('css','protected'):code='/* '+nonce+' '+site['owner']+' */'
   else:
    extra="header('Cache-Control: private, no-store');" if case=='private' else "setcookie('private_session','demo');" if case=='cookie' else 'http_response_code(500);' if case=='error' else ''
    code="<?php require __DIR__.'/wp-load.php'; header('Content-Type: text/html; charset=UTF-8'); header('Cache-Control: public, max-age=60'); "+extra+" echo json_encode(['owner'=>"+json.dumps(site['owner'])+",'time'=>microtime(true),'ssl'=>is_ssl(),'ip'=>$_SERVER['REMOTE_ADDR'],'proto'=>$_SERVER['HTTP_X_FORWARDED_PROTO']??'','method'=>$_SERVER['REQUEST_METHOD']]);"
   as_user(site,['python3','-c','from pathlib import Path;import sys;Path(sys.argv[1]).write_text(sys.argv[2])',str(path),code])
 for site in sites:
  for port in (80,443):
   a,b=pair(site,'/'+prefix+'-public.php',port=port)
   data=json.loads(a[2]);check(data['ssl']==(port==443),'origin SSL '+site['owner']+' '+str(port));check(data['ip']==expected_source[0],'real IP '+site['owner']+' '+str(port))
   check(data['owner']==site['owner'],'account boundary '+site['owner']+' '+str(port))
   check('x-cache-status' not in b[1],'no Nginx page cache '+site['owner']+' '+str(port))
   pair(site,'/'+prefix+'-css.css','STATIC',port=port)
  for headers in ({'Cookie':'wordpress_logged_in_demo=1'},{'Cookie':'wp_woocommerce_session_demo=1'},{'Cookie':'unknown_personalization=1'},{'Authorization':'Basic demo'}):
   a,b=pair(site,'/'+prefix+'-public.php','PASS',headers=headers);check(a[2]!=b[2],'private request not reused '+str(headers))
  pair(site,'/'+prefix+'-public.php?preview=1','PASS')
  pair(site,'/'+prefix+'-public.php','PASS',method='POST')
  pair(site,'/'+prefix+'-private.php','PASS');pair(site,'/'+prefix+'-cookie.php','PASS')
  error=request(site,'/'+prefix+'-error.php');check(error[0]==500 and error[1].get('x-webuzo-varnish')=='PASS','500 never cached '+site['owner'])
  attack=request(site,'/'+prefix+'-public.php',headers={'Cookie':'bypass=1','X-Forwarded-For':'203.0.113.99','X-Real-IP':'203.0.113.99','X-Forwarded-Proto':'https','X-WV-Site':sites[-1]['id']})
  data=json.loads(attack[2]);check(data['ip']==expected_source[0] and not data['ssl'] and data['owner']==site['owner'],'spoofed headers ignored '+site['owner'])
  check(request(site,'/'+prefix+'-public.php',local=True)[0]==403,'direct local gateway denied '+site['owner'])
  check(request(site,'/',origin=True)[0]==403,'direct origin bridge denied '+site['owner'])
 # Cache purge must invalidate only the selected site, across HTTP and HTTPS.
 before={s['id']:{p:request(s,'/'+prefix+'-public.php',port=p)[2] for p in (80,443)} for s in sites}
 first,second=sites[:2]
 check(request(second,'/',local=True,method='PURGE',headers={'X-Webuzo-Varnish-Token':first['token']})[0]==403,'cross-account purge token denied')
 check(request(first,'/',method='PURGE',headers={'X-Webuzo-Varnish-Token':first['token']})[0]==403,'public endpoint purge denied')
 check(request(first,'/',local=True,method='PURGE',headers={'X-Webuzo-Varnish-Token':first['token']})[0]==200,'site credential purge accepted')
 for port in (80,443):
  a,b=pair(first,'/'+prefix+'-public.php',port=port)
  check(a[1].get('x-webuzo-varnish')=='MISS' and a[2]!=before[first['id']][port],'purge clears scheme '+str(port))
  check(request(second,'/'+prefix+'-public.php',port=port)[2]==before[second['id']][port],'purge preserves other account '+str(port))
 # Administrator bypasses must apply to static assets as well as HTML.
 engine.action(dict(actor='root',admin=True,action='configure',id=first['id'],enabled=True,ttl=300,bypass=['/'+prefix+'-protected']))
 time.sleep(.2)
 check(request(first,'/'+prefix+'-protected.css')[1].get('x-webuzo-varnish')=='PASS','configured static bypass reaches application')
 # Service failure: static assets stay native; GET/HEAD fall back; writes are not replayed.
 subprocess.run(['systemctl','stop','varnish-for-webuzo'],check=True)
 for port in (80,443):
  r=request(first,'/'+prefix+'-public.php',port=port)
  check(r[0]==200 and r[1].get('x-webuzo-varnish')=='FALLBACK','Varnish outage GET fallback '+str(port))
  check(json.loads(r[2])['ssl']==(port==443),'fallback SSL '+str(port))
  check(request(first,'/'+prefix+'-css.css',port=port)[1].get('x-webuzo-varnish')=='STATIC','static independent of Varnish '+str(port))
  check(request(first,'/'+prefix+'-public.php',port=port,method='POST')[0]==503,'outage write not replayed '+str(port))
 subprocess.run(['systemctl','start','varnish-for-webuzo'],check=True);service.wait()
 # Native rebuild and restarts must preserve the owned extension points.
 fixed=[Path('/usr/local/apps/nginx/etc/nginx.conf'),Path('/usr/local/apps/nginx/etc/conf.d/proxy.conf'),Path('/usr/local/apps/apache2/etc/httpd.conf')]
 baseline={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in fixed}
 subprocess.run(['/usr/local/emps/bin/php','/usr/local/webuzo/cli.php','--rebuild_vhost'],check=True,capture_output=True)
 subprocess.run(['systemctl','restart','nginx'],check=True);subprocess.run(['systemctl','restart','varnish-for-webuzo'],check=True);service.wait()
 for site in sites:
  for port in (80,443):pair(site,'/'+prefix+'-public.php',port=port)
 check(baseline=={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in fixed},'factory configuration hashes unchanged')
 print(json.dumps(report,indent=2))
finally:
 subprocess.run(['systemctl','start','varnish-for-webuzo'],check=True);service.wait()
 for site,path in created:
  as_user(site,['python3','-c','from pathlib import Path;import sys;Path(sys.argv[1]).unlink(missing_ok=True)',str(path)])
 # Restore each selected site's original settings.
 for site in sites:engine.action(dict(actor='root',admin=True,action='configure',id=site['id'],**original[site['id']]))
