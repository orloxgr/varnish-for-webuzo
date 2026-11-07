"""Conservative HTML policy adapted from varnish-for-hestia's site boundaries."""
import json
import re
from urllib.parse import quote,unquote
import native

def quoted(value):return json.dumps(value,ensure_ascii=False)

def paths(value):
    if not isinstance(value,list):raise ValueError('Bypass paths must be a list')
    result=[]
    for path in value:
        if not isinstance(path,str) or len(path)>4096 or not path.startswith('/') or re.search(r'%(?![0-9a-fA-F]{2})',path):raise ValueError('Use valid URL paths starting with /')
        decoded=unquote(path,errors='strict')
        if any(ord(c)<32 or ord(c)==127 or c in '?#\\' for c in decoded):raise ValueError('Bypass paths cannot contain queries, fragments or control characters')
        canonical=quote(decoded,safe='/-._~')
        if canonical not in result:result.append(canonical)
    return result

def literal_bytes(value):return ''.join('\\x'+format(b,'02x') for b in value.encode())

def render(sites,gateway,origin_secret):
    if not re.fullmatch('[0-9a-f]{64}',gateway) or not re.fullmatch('[0-9a-f]{64}',origin_secret):raise ValueError('Invalid internal credential')
    text=['''vcl 4.1;
import std;
backend plain { .path = "/run/varnish-for-webuzo-origin-http.sock"; }
backend secure { .path = "/run/varnish-for-webuzo-origin-https.sock"; }
sub vcl_recv {
 unset req.http.X-WV-Site;
 unset req.http.X-WV-Mode;
 unset req.http.X-WV-Disabled;
 unset req.http.X-WV-Origin;
 set req.http.host = std.tolower(regsub(req.http.host, ":[0-9]+$", ""));
''']
    names=set()
    for site in sorted(sites.values(),key=lambda s:s['id']):
        if site.get('error'):continue
        if not re.fullmatch('[0-9a-f]{32}',site['id']) or not re.fullmatch('[0-9a-f]{64}',site['token']):raise ValueError('Invalid site scope')
        if type(site['ttl']) is not int or not 1<=site['ttl']<=2147483647:raise ValueError('Use a positive cache lifetime within the supported integer range')
        for name in site['names']:
            native.hostname(name)
            if name in names:raise ValueError('Duplicate hostname scope')
            names.add(name)
        cond=' || '.join('req.http.host == '+quoted(n) for n in site['names'])
        text.append(' if ('+cond+') {\n set req.http.X-WV-Site = '+quoted(site['id'])+';\n'+
            (' set req.http.X-WV-Disabled = "1";\n' if not site.get('enabled') else '')+
            ' if (req.method == "PURGE") {\n'+
            ' if (req.http.X-WV-Disabled || local.socket != "public" || req.http.X-Webuzo-Varnish-Token != '+quoted(site['token'])+') { return (synth(403)); }\n'+
            ' ban("obj.http.X-WV-Site == '+site['id']+'"); return (synth(200, "Site cache cleared")); }\n }')
    text.append('''
 if (req.method == "PURGE" || req.method == "BAN") { return (synth(403)); }
 if (!req.http.X-WV-Site) { return (synth(421)); }
 if (req.http.X-WV-Gateway != '''+quoted(gateway)+''') { return (synth(403)); }
 unset req.http.X-WV-Gateway;
 unset req.http.X-Webuzo-Varnish-Token;
 unset req.http.CF-Connecting-IP;
 unset req.http.CF-Visitor;
 unset req.http.Forwarded;
 if (req.http.X-Forwarded-Proto == "https") { set req.backend_hint = secure; }
 else { set req.http.X-Forwarded-Proto = "http"; set req.backend_hint = plain; }
 set req.http.X-Forwarded-For = req.http.X-Real-IP;
 set req.http.X-WV-Origin = '''+quoted(origin_secret)+''';
 std.collect(req.http.Cookie, "; ");
 if (req.http.X-WV-Disabled || req.method != "GET" && req.method != "HEAD" || req.http.Authorization || req.http.Cookie || req.http.Upgrade ||
     req.url ~ "[?]" || req.url ~ "(?i)^/(wp-admin(?:/|$)|wp-login[.]php|wp-json(?:/|$)|xmlrpc[.]php|wp-cron[.]php|cart(?:/|$)|checkout(?:/|$)|my-account(?:/|$)|wc-api(?:/|$))") {
   set req.http.X-WV-Mode = "PASS"; return (pass);
 }
''')
    for site in sites.values():
        if not site.get('enabled') or site.get('error'):continue
        prefixes=paths(site.get('bypass',[]))
        for path in prefixes:
            # Literal prefix; no caller-supplied VCL or regular expression.
            pattern='(?i)^('+re.escape(path).replace('\\.','[.]')+'|'+literal_bytes(unquote(path))+')'
            text.append(' if (req.http.X-WV-Site == '+quoted(site['id'])+' && req.url ~ '+quoted(pattern)+') { set req.http.X-WV-Mode = "PASS"; return (pass); }')
    text.append(''' return (hash);
}
sub vcl_hash {
 hash_data("webuzo-html-policy-v1");
 hash_data(req.http.X-WV-Site); hash_data(req.http.host); hash_data(req.http.X-Forwarded-Proto); hash_data(req.url);
 return (lookup);
}
sub vcl_backend_response {
 set beresp.http.X-WV-Site = bereq.http.X-WV-Site;
 if (beresp.status != 200 || beresp.http.Content-Type !~ "(?i)^text/html(?:;|$)" ||
     beresp.http.Set-Cookie || beresp.http.Vary == "*" || beresp.ttl <= 0s ||
     beresp.http.Cache-Control ~ "(?i)(private|no-store|no-cache)" || beresp.http.Pragma ~ "(?i)no-cache" ||
     beresp.http.Surrogate-Control ~ "(?i)no-store") {
   set beresp.uncacheable = true; set beresp.ttl = 120s; set beresp.grace = 0s; return (deliver);
 }
''')
    for site in sites.values():
        if site.get('enabled') and not site.get('error'):
            text.append(' if (bereq.http.X-WV-Site == '+quoted(site['id'])+' && beresp.ttl > '+str(site['ttl'])+'s) { set beresp.ttl = '+str(site['ttl'])+'s; }')
    text.append(''' set beresp.grace = 0s; return (deliver);
}
sub vcl_deliver {
 if (req.http.X-WV-Mode == "PASS" || obj.uncacheable) { set resp.http.X-Webuzo-Varnish = "PASS"; }
 else if (obj.hits > 0) { set resp.http.X-Webuzo-Varnish = "HIT"; }
 else { set resp.http.X-Webuzo-Varnish = "MISS"; }
 unset resp.http.X-WV-Site;
 set resp.http.X-Accel-Expires = "0";
}
sub vcl_synth { set resp.http.Cache-Control = "no-store"; set resp.http.X-Accel-Expires = "0"; }
''')
    return '\n'.join(text)+'\n'
