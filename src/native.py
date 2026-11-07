"""Read native Webuzo inventory and configuration; never bootstrap sites as root."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess

NGINX=Path('/usr/local/apps/nginx/sbin/nginx')
VHOST=Path('/usr/local/apps/nginx/etc/conf.d/webuzoVH.conf')
GLOBAL=Path('/usr/local/apps/nginx/etc/conf.d/custom.conf')
CUSTOM=Path('/var/webuzo-data/nginx/custom/domains')
APACHE_CUSTOM=Path('/var/webuzo-data/apache2/custom/domains')
APACHE=Path('/usr/local/apps/apache2/bin/apachectl')
PHP='/usr/local/emps/bin/php'
CLI='/usr/local/webuzo/cli.php'
ENV={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'}

def run(*args,timeout=120):
    result=subprocess.run([str(a) for a in args],capture_output=True,text=True,env=ENV,timeout=timeout)
    if result.returncode:raise RuntimeError((result.stderr or result.stdout or 'Command failed')[-3000:])
    return result.stdout

def hostname(value):
    if not isinstance(value,str) or len(value)>253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',p) for p in value.split('.')):
        raise ValueError('Invalid hostname')
    return value

def open_native(path,directory=False):
    path=Path(path); panel=pwd.getpwnam('webuzo')
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        if not path.is_absolute() or '..' in path.parts:raise ValueError('Invalid native path')
        for index,piece in enumerate(path.parts[1:]):
            last=index==len(path.parts)-2
            new=os.open(piece,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|(0 if last and not directory else os.O_DIRECTORY),dir_fd=fd)
            os.close(fd);fd=new;info=os.fstat(fd)
            if (info.st_uid not in (0,panel.pw_uid) or info.st_mode&0o002 or
                (info.st_mode&0o020 and info.st_gid not in (0,panel.pw_gid)) or
                not (stat.S_ISREG(info.st_mode) if last and not directory else stat.S_ISDIR(info.st_mode))):raise ValueError('Untrusted native configuration: '+str(path))
        result=fd;fd=None;return result
    finally:
        if fd is not None:os.close(fd)

def read(path):
    with os.fdopen(open_native(path),'rb') as stream:return stream.read()

def write_custom(path,value,mode,uid=0,gid=0):
    import secrets
    path=Path(path)
    if path!=GLOBAL and path.parent not in (CUSTOM,APACHE_CUSTOM):raise ValueError('Invalid native extension path')
    if path.parent in (CUSTOM,APACHE_CUSTOM):hostname(path.stem)
    for base in (APACHE_CUSTOM.parent.parent,APACHE_CUSTOM.parent,APACHE_CUSTOM):
        if path.parent==APACHE_CUSTOM and not base.exists():
            parent=open_native(base.parent,True)
            try:os.mkdir(base.name,0o755,dir_fd=parent)
            finally:os.close(parent)
    parent=open_native(path.parent,True);temporary='.wvw-'+secrets.token_hex(16)
    try:
        if value is None:os.unlink(path.name,dir_fd=parent)
        else:
            fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode,dir_fd=parent)
            with os.fdopen(fd,'wb') as stream:
                stream.write(value);stream.flush();os.fchown(stream.fileno(),uid,gid);os.fchmod(stream.fileno(),mode);os.fsync(stream.fileno())
            os.replace(temporary,path.name,src_dir_fd=parent,dst_dir_fd=parent);os.fsync(parent)
    finally:
        try:os.unlink(temporary,dir_fd=parent)
        except FileNotFoundError:pass
        os.close(parent)

TOKEN=re.compile(r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\#[^\n]*|[{};]|(?:\\.|[^\s{};\#"'])+''')
def directives(text):
    tokens=[t for t in TOKEN.findall(text) if not t.startswith('#')]
    def parse(index,nested=False):
        nodes=[];words=[]
        while index<len(tokens):
            value=tokens[index];index+=1
            if value=='{':
                if not words:raise ValueError('Invalid Nginx block')
                children,index=parse(index,True);nodes.append((words[0],words[1:],children));words=[]
            elif value==';':
                if not words:raise ValueError('Empty Nginx directive')
                nodes.append((words[0],words[1:],None));words=[]
            elif value=='}':
                if not nested or words:raise ValueError('Invalid Nginx block end')
                return nodes,index
            else:words.append(value[1:-1] if value[:1] in ('"',"'") else value)
        if nested or words:raise ValueError('Incomplete Nginx configuration')
        return nodes,index
    return parse(0)[0]

def listing(kind):
    if kind not in ('users','domains'):raise ValueError('Invalid native listing')
    def request(*extra):
        data=json.loads(run(PHP,CLI,'--api','act='+kind,*extra))
        if data.get('error'):raise ValueError('Native inventory failed')
        return data
    data=request();total=int(data['num_res'])
    if len(data[kind])<total:data=request('--reslen='+str(total))
    rows=data[kind]
    if rows==[] and total==0:return []
    if not isinstance(rows,dict) or len(rows)!=total:raise ValueError('Incomplete native inventory')
    return list(rows.values())

def collect():
    users={}
    for row in listing('users'):
        name=row['user']
        if not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]*',name):raise ValueError('Invalid account')
        unix=pwd.getpwnam(name)
        if unix.pw_uid==0 or name=='webuzo' or unix.pw_dir!=row['homedir']:raise ValueError('Native account mismatch')
        users[name]=dict(owner=name,uid=unix.pw_uid,gid=unix.pw_gid,home=unix.pw_dir,suspended=bool(row['status']))
    blocks=[]
    for key,args,children in directives(read(VHOST).decode()):
        if key!='server' or children is None:continue
        values={}
        for k,a,c in children:
            if c is None:values.setdefault(k,[]).append(a)
        if len(values.get('server_name',[]))==1:blocks.append(values)
    rows=listing('domains');canonical={(r['user'],r['domain']):r for r in rows};groups={}
    for row in rows:
        owner=row['user'];name=hostname(row['domain']);visited=set();root=row
        while root.get('type')=='alias':
            target=hostname(root['alias'])
            if target in visited:raise ValueError('Recursive domain alias')
            visited.add(target);root=canonical[(owner,target)]
        if owner not in users:raise ValueError('Unknown domain owner')
        primary=hostname(root['domain']);sid=hashlib.sha256((owner+'\0'+primary).encode()).hexdigest()[:32]
        site=groups.setdefault(sid,dict(users[owner],id=sid,domain=primary,names=[],custom_domains=[],path=root['path'],error='',
            credential_roots=[r['path'] for r in rows if r['user']==owner]))
        for host in (name,'www.'+name):
            if host not in site['names']:site['names'].append(hostname(host))
    for site in groups.values():
        matching=[b for b in blocks if set(site['names']).intersection(b['server_name'][0])]
        for block in matching:
            pointer=str(CUSTOM/(block['server_name'][0][0]+'.conf'))
            if [pointer] not in block.get('include',[]):site['error']='Rebuild this domain through Webuzo to load its native custom include'
            else:site['custom_domains'].append(Path(pointer).stem)
            if not any(a[0]=='$webuzoproxy' and a[1] in ('http://127.0.0.1:8081','https://127.0.0.1:8082') for a in block.get('set',[]) if len(a)==2):
                site['error']='This domain needs the Webuzo Nginx to Apache reverse proxy topology (8081/8082)'
        site['custom_domains']=sorted(set(site['custom_domains']))
        if not matching:site['error']='No native Nginx virtual host found'
        if site['suspended']:site['error']='Hosting account is suspended'
    return groups
