"""Render owned snippets and edit only documented custom include pointers."""
from pathlib import Path
import re
import native
import state
import policy
from urllib.parse import unquote

CONFIG=Path('/etc/varnish-for-webuzo')
BEGIN='# BEGIN Varnish for Webuzo\n'
END='# END Varnish for Webuzo\n'
TEMPLATES=Path(__file__).resolve().parents[1]/'templates'

def proxy(target,gateway='',origin=False):
    return '''proxy_pass '''+target+''';
proxy_cache off;
proxy_http_version 1.1;
proxy_set_header Connection "";
proxy_set_header Host $host;
proxy_set_header Proxy "";
proxy_set_header X-Forwarded-Host $host;
proxy_set_header X-Forwarded-Proto '''+('$http_x_forwarded_proto' if origin else '$scheme')+''';
proxy_set_header X-Forwarded-Port '''+('$http_x_forwarded_port' if origin else '$server_port')+''';
proxy_set_header X-Real-IP '''+('$http_x_real_ip' if origin else '$remote_addr')+''';
proxy_set_header X-Forwarded-For '''+('$http_x_real_ip' if origin else '$remote_addr')+''';
proxy_set_header CF-Connecting-IP "";
proxy_set_header CF-Visitor "";
proxy_set_header Forwarded "";
proxy_set_header X-WV-Origin "";
proxy_set_header X-WV-Gateway "'''+gateway+'''";
proxy_set_header X-Webuzo-Varnish-Token "";
proxy_ssl_server_name on;
proxy_ssl_name $host;
proxy_connect_timeout 2s;
proxy_read_timeout 120s;
proxy_send_timeout 120s;
proxy_next_upstream off;
'''

def domain(site,gateway):
    hosts='^('+'|'.join(re.escape(native.hostname(n)).replace('\\.','[.]') for n in site['names'])+')$'
    exclusions=[]
    for path in policy.paths(site.get('bypass',[])):
        exclusions.append('if ($uri ~* '+policy.quoted('^'+policy.literal_bytes(unquote(path)))+') { return 419; }')
    return (TEMPLATES/'domain.conf').read_text().replace('@@STATIC_BYPASS@@','\n'.join(exclusions)).replace('@@HOSTS@@',hosts).replace('@@VARNISH_PROXY@@',proxy('http://unix:/run/varnish-for-webuzo-cache/frontend.sock:',gateway)).replace('@@NATIVE_PROXY@@',proxy('$wv_native_origin'))

def origins(secret):
    text=[]
    for scheme,target in (('http','http://127.0.0.1:8081'),('https','https://127.0.0.1:8082')):
        text.append('server { listen unix:/run/varnish-for-webuzo-origin-'+scheme+'.sock; server_name _;\n'+
            'if ($http_x_wv_origin != "'+secret+'") { return 403; }\nlocation / {\n'+proxy(target,origin=True)+'}\n}\n')
    return '\n'.join(text)

def pointer(path,target,manifest,enabled):
    path=Path(path)
    if path!=native.GLOBAL:
        if path.parent not in (native.CUSTOM,native.APACHE_CUSTOM):raise ValueError('Invalid native custom path')
        native.hostname(path.stem)
    raw=native.read(path).decode() if path.exists() or path.is_symlink() else None
    directive=('Include '+str(target)+'\n') if path.parent==native.APACHE_CUSTOM else ('include '+str(target)+';\n')
    block=BEGIN+directive+END
    text=raw or ''
    if BEGIN in text or END in text:
        if text.count(block)!=1 or text.count(BEGIN)!=1 or text.count(END)!=1:raise ValueError('The owned custom include was changed: '+str(path))
        if str(path) not in manifest:raise ValueError('Unregistered owned include')
    elif str(path) in manifest and not (not enabled and raw is None):raise ValueError('A managed include is missing')
    entry=manifest.get(str(path),dict(created=raw is None,separator='' if not text or text.endswith('\n') else '\n'))
    if enabled:after=text if block in text else text+entry['separator']+block
    else:
        after=text.replace(block,'')
        if entry['separator'] and after.endswith('\n'):after=after[:-1]
        if entry['created'] and after=='':after=None
    info=path.stat() if raw is not None else None
    return dict(path=str(path),before=raw,after=after,mode=(info.st_mode&0o777) if info else 0o644,uid=info.st_uid if info else 0,gid=info.st_gid if info else 0),entry

def replace(change,reverse=False):
    path=Path(change['path']);expected=change['after'] if reverse else change['before'];value=change['before'] if reverse else change['after']
    raw=native.read(path).decode() if path.exists() or path.is_symlink() else None
    if raw==value:return
    if raw!=expected:raise ValueError('Configuration changed during apply: '+str(path))
    if path==native.GLOBAL or path.parent in (native.CUSTOM,native.APACHE_CUSTOM):
        native.write_custom(path,None if value is None else value.encode(),change['mode'],change.get('uid',0),change.get('gid',0));return
    state.trusted(path.parent,True)
    if value is None:path.unlink()
    else:
        state.write(path,value.encode());path.chmod(change['mode'])
