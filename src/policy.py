"""Conservative HTML policy adapted from varnish-for-hestia's site boundaries."""
import json
import re
from urllib.parse import quote,unquote
import native
import fragments
import profiles
import cookie_policy
import timeouts

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

def render(sites,gateway,origin_secret,config=None):
    config=config or {}
    allowances=timeouts.settings(config)
    if not re.fullmatch('[0-9a-f]{64}',gateway) or not re.fullmatch('[0-9a-f]{64}',origin_secret):raise ValueError('Invalid internal credential')
    text=['''vcl 4.1;
import std;
import purge;
''']
    for scheme,name in (('http','plain'),('https','secure')):
        text.append('backend '+name+' { .path = "/run/varnish-for-webuzo-origin-'+scheme+'.sock"; '+
            '.connect_timeout = '+timeouts.seconds(allowances['connect'])+'; '+
            '.first_byte_timeout = '+timeouts.seconds(timeouts.first_byte(allowances))+'; '+
            '.between_bytes_timeout = '+timeouts.seconds(allowances['read'])+'; }')
    text += [profiles.program(),'''
sub vcl_recv {
 set sess.idle_send_timeout = '''+timeouts.seconds(allowances['read'])+''';
 # Never shorten the engine's response budget; allow every upstream phase.
 if (sess.send_timeout < '''+timeouts.seconds(timeouts.frontend(allowances)['read'])+''') {
   set sess.send_timeout = '''+timeouts.seconds(timeouts.frontend(allowances)['read'])+''';
 }
 unset req.http.X-WV-Site;
 unset req.http.X-WV-Profile;
 unset req.http.X-WV-Mode;
 unset req.http.X-WV-Disabled;
 unset req.http.X-WV-Origin;
 unset req.http.X-WV-Control;
 unset req.http.X-WV-Soft-Purge;
 unset req.http.X-WV-Ban-Host;
 unset req.http.X-WV-Ban-Pattern;
 unset req.http.X-WV-Ban-HTML;
 if (req.esi_level == 0) {
   unset req.http.X-ESI-Private-Request;
   unset req.http.X-ESI-Request-Level;
   unset req.http.X-ESI-Original-Cookie;
   unset req.http.X-UltraCache-ESI-Candidate;
   unset req.http.X-UltraCache-ESI-Cookie-Check;
   unset req.http.X-UltraCache-ESI-Opt-In;
   unset req.http.X-UltraCache-ESI-Shared-Parent;
 }
 set req.http.host = std.tolower(regsub(req.http.host, ":[0-9]+$", ""));
 if (req.http.X-Forwarded-Proto != "https") { set req.http.X-Forwarded-Proto = "http"; }
''']
    names=set()
    for site in sorted(sites.values(),key=lambda s:s['id']):
        if site.get('error'):continue
        if not re.fullmatch('[0-9a-f]{32}',site['id']) or not re.fullmatch('[0-9a-f]{64}',site['token']):raise ValueError('Invalid site scope')
        if type(site['ttl']) is not int or not 0<=site['ttl']<=2147483647:raise ValueError('Use zero for the origin cache policy or a positive maximum cache lifetime within the supported integer range')
        for name in site['names']:
            native.hostname(name)
            if name in names:raise ValueError('Duplicate hostname scope')
            names.add(name)
        cond=' || '.join('req.http.host == '+quoted(n) for n in site['names'])
        profile=profiles.selected(site)
        text.append(' if ('+cond+') {\n set req.http.X-WV-Site = '+quoted(site['id'])+';\n'+
            ' set req.http.X-WV-Profile = '+quoted(profile)+';\n'+
            (' set req.http.X-WV-Disabled = "1";\n' if not site.get('enabled') else '')+
            ' if (req.method == "HEAD" && req.http.X-WV-Control-Discovery == "1" && local.socket == "public") { return (synth(405, "HTTP cache control endpoint")); }\n'+
            ' if (req.method == "PURGE" || req.method == "BAN") {\n'+
            ' if (req.http.X-WV-Disabled || req.esi_level > 0 || local.socket != "public" || (req.http.X-Webuzo-Varnish-Token != '+quoted(site['token'])+' &&\n'+
            ' req.http.X-UltraCache-Token != '+quoted(site['token'])+')) { return (synth(403)); }\n'+
            ' if (req.http.X-UltraCache-Token == '+quoted(site['token'])+') { call wvw_http_control; }\n'+
            ' if (req.method != "PURGE") { return (synth(403)); }\n'+
            ' ban("obj.http.X-WV-Site == '+site['id']+'"); return (synth(200, "Site cache cleared")); }\n }')
    text.append('''
 if (req.method == "PURGE" || req.method == "BAN") { return (synth(403)); }
 if (!req.http.X-WV-Site) { return (synth(421)); }
 if (req.esi_level > 0) {
   if (req_top.http.X-WV-Site != req.http.X-WV-Site || req_top.http.X-WV-Profile != "ultracache") { return (synth(403)); }
   set req.http.X-Forwarded-Proto = req_top.http.X-Forwarded-Proto;
 } else if (req.http.X-WV-Gateway != '''+quoted(gateway)+''') { return (synth(403)); }
 unset req.http.X-WV-Gateway;
 unset req.http.X-Webuzo-Varnish-Token;
 unset req.http.X-UltraCache-Token;
 unset req.http.X-WV-Control-Discovery;
 unset req.http.X-Ban-Expression;
 unset req.http.X-UltraCache-Contract;
 unset req.http.X-UltraCache-Operation;
 unset req.http.X-UltraCache-Object-Expression;
 unset req.http.X-UltraCache-Soft-Purge;
 unset req.http.X-Purge;
 unset req.http.CF-Connecting-IP;
 unset req.http.CF-Visitor;
 unset req.http.Forwarded;
 if (req.http.X-Forwarded-Proto == "https") { set req.backend_hint = secure; }
 else { set req.http.X-Forwarded-Proto = "http"; set req.backend_hint = plain; }
 set req.http.X-Forwarded-For = req.http.X-Real-IP;
 set req.http.X-WV-Origin = '''+quoted(origin_secret)+''';
 std.collect(req.http.Cookie, "; ");
 if (req.http.X-WV-Disabled || req.method != "GET" && req.method != "HEAD" || req.http.Authorization || req.http.Upgrade ||
     req.url ~ "^/[.]well-known/(acme-challenge|pki-validation)/") {
   set req.http.X-WV-Mode = "PASS"; return (pass);
 }
''')
    for profile in profiles.NAMES:
        fragment=fragments.validate(profiles.rules(config,profile)['recv_vcl'],'recv',mark_pass=True)
        if fragment:text.append(' if (req.http.X-WV-Profile == '+quoted(profile)+') { '+fragment+' }')
    for site in sites.values():
        if not site.get('enabled') or site.get('error'):continue
        prefixes=paths(site.get('bypass',[]))
        for path in prefixes:
            # Literal prefix; no caller-supplied VCL or regular expression.
            pattern='(?i)^('+re.escape(path).replace('\\.','[.]')+'|'+literal_bytes(unquote(path))+')'
            text.append(' if (req.http.X-WV-Site == '+quoted(site['id'])+' && req.url ~ '+quoted(pattern)+') { set req.http.X-WV-Mode = "PASS"; return (pass); }')
        fragment=fragments.validate(site.get('recv_vcl',''),'recv',mark_pass=True)
        if fragment:text.append(' if (req.http.X-WV-Site == '+quoted(site['id'])+') { '+fragment+' }')
    text.append('''
 if (req.http.X-WV-Profile == "basic") { call wvw_basic_recv; }
 if (req.http.X-WV-Profile == "wordpress") { call wvw_wordpress_recv; }
 if (req.http.X-WV-Profile == "woocommerce") { call wvw_woocommerce_recv; }
 if (req.http.X-WV-Profile == "ultracache") { call wvw_ultracache_recv; }
 call wvw_private_cookie_recv;
 call wvw_cart_cookie_recv;
 return (hash);
}
sub wvw_private_cookie_recv {
 if (req.http.Cookie ~ '''+cookie_policy.vcl_pattern(cookie_policy.PRIVATE)+''') {
   set req.http.X-WV-Mode = "PASS"; return (pass);
 }
}
sub wvw_cart_cookie_recv {
 if (req.http.Cookie ~ '''+cookie_policy.vcl_pattern(cookie_policy.CART)+''' ||
     req.http.Cookie ~ '''+cookie_policy.vcl_pattern(cookie_policy.SESSION)+''') {
   if (req.http.X-WV-Profile == "ultracache" && req.http.X-UltraCache-ESI-Opt-In == "1") {
     set req.http.X-UltraCache-ESI-Candidate = "1";
   } else { set req.http.X-WV-Mode = "PASS"; return (pass); }
 }
}
sub vcl_hash {
 hash_data("webuzo-html-policy-v1");
 if (req.http.X-WV-Profile != "basic") { hash_data(req.http.X-WV-Profile); }
 hash_data(req.http.X-WV-Site); hash_data(req.http.host);
 if (req.http.X-WV-Profile != "ultracache") { hash_data(req.http.X-Forwarded-Proto); }
 hash_data(req.url);
 return (lookup);
}
sub vcl_hit {
 if (req.http.X-WV-Soft-Purge == "1") { call wvw_soft_purge; }
 if (req.http.X-WV-Profile == "ultracache") { call wvw_ultracache_hit; }
}
sub vcl_miss { if (req.http.X-WV-Soft-Purge == "1") { call wvw_soft_purge; } }
sub wvw_soft_purge {
 set req.http.X-WV-Soft-Purge = purge.soft(); return (synth(200, "Soft purge completed"));
}
sub vcl_backend_fetch {
 if (bereq.http.X-WV-Profile == "ultracache") { call wvw_ultracache_backend_fetch; }
}
sub wvw_mark_uncacheable {
 set beresp.uncacheable = true; set beresp.ttl = 120s; set beresp.grace = 0s; set beresp.keep = 0s;
}
sub vcl_backend_response {
 set beresp.http.X-WV-Site = bereq.http.X-WV-Site;
 set beresp.http.X-Cache-Object-Host = bereq.http.host;
 set beresp.http.X-Cache-Object-URL = bereq.url;
 if (bereq.http.X-WV-Profile == "ultracache") { set beresp.keep = 5m; }
 else { set beresp.grace = 0s; }
''')
    for profile in profiles.NAMES:
        fragment=fragments.validate(profiles.rules(config,profile)['backend_vcl'],'backend_response')
        if fragment:text.append(' if (bereq.http.X-WV-Profile == '+quoted(profile)+') { '+fragment+' }')
    for site in sites.values():
        if not site.get('enabled') or site.get('error'):continue
        fragment=fragments.validate(site.get('backend_vcl',''),'backend_response')
        if fragment:text.append(' if (bereq.http.X-WV-Site == '+quoted(site['id'])+') { '+fragment+' }')
    text.append('''
 std.collect(beresp.http.Surrogate-Control);
 if (beresp.http.Surrogate-Control ~ "(?i)no-store") { call wvw_mark_uncacheable; }
 if (bereq.http.X-WV-Profile == "ultracache") { call wvw_ultracache_backend_response; }
 if (beresp.uncacheable || beresp.status != 200 || beresp.http.Content-Type !~ "(?i)^text/html(?:;|$)" ||
     beresp.http.Set-Cookie || beresp.http.Vary == "*" || beresp.ttl <= 0s ||
     beresp.http.Cache-Control ~ "(?i)(private|no-store|no-cache)" || beresp.http.Pragma ~ "(?i)no-cache" ||
     beresp.http.Surrogate-Control ~ "(?i)no-store") {
   call wvw_mark_uncacheable; return (deliver);
 }
''')
    for site in sites.values():
        if site.get('enabled') and not site.get('error') and site['ttl']:
            text.append(' if (bereq.http.X-WV-Site == '+quoted(site['id'])+' && beresp.ttl > '+str(site['ttl'])+'s) { set beresp.ttl = '+str(site['ttl'])+'s; }')
    text.append(''' return (deliver);
}
sub vcl_deliver {
 if (req.http.X-WV-Profile == "ultracache") { call wvw_ultracache_deliver; }
 if (req.http.X-WV-Mode == "PASS" || obj.uncacheable) { set resp.http.X-Webuzo-Varnish = "PASS"; }
 else if (obj.hits > 0) { set resp.http.X-Webuzo-Varnish = "HIT"; }
 else { set resp.http.X-Webuzo-Varnish = "MISS"; }
 unset resp.http.X-WV-Site;
 unset resp.http.X-Cache-Object-Host;
 unset resp.http.X-Cache-Object-URL;
 set resp.http.X-Webuzo-Varnish-Profile = req.http.X-WV-Profile;
 set resp.http.X-Accel-Expires = "0";
}
sub vcl_synth { set resp.http.Cache-Control = "no-store"; set resp.http.X-Accel-Expires = "0"; }
''')
    return '\n'.join(text)+'\n'
