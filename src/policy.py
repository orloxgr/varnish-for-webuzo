"""Public HTTP cache policy with immutable account and private-state boundaries."""
import json
import re
from urllib.parse import quote,unquote
import native
import fragments
import profiles
import timeouts
import cookie_policy
import cookie_views
import cookie_bridge

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
import header;
import blob;
''']
    for scheme,name in (('http','plain'),('https','secure')):
        text.append('backend '+name+' { .path = "/run/varnish-for-webuzo-origin-'+scheme+'.sock"; '+
            '.connect_timeout = '+timeouts.seconds(allowances['connect'])+'; '+
            '.first_byte_timeout = '+timeouts.seconds(timeouts.first_byte(allowances))+'; '+
            '.between_bytes_timeout = '+timeouts.seconds(allowances['read'])+'; }')
    admin_rules=[]
    for site in sorted(sites.values(),key=lambda s:s['id']):
        if site.get('enabled') and not site.get('error'):
            body=cookie_views.compile_recv(config,site)
            if body:admin_rules.append('if (req.http.X-WV-Site == '+quoted(site['id'])+') {\n'+body+'\n}')
    text += [profiles.program('\n'.join(admin_rules)),'''
sub vcl_recv {
 call scp_init;
 set sess.idle_send_timeout = '''+timeouts.seconds(allowances['read'])+''';
 # Never shorten the engine's response budget; allow every upstream phase.
 if (sess.send_timeout < '''+timeouts.seconds(timeouts.frontend(allowances)['read'])+''') {
   set sess.send_timeout = '''+timeouts.seconds(timeouts.frontend(allowances)['read'])+''';
 }
 unset req.http.X-WV-Site;
 unset req.http.X-WV-Profile;
 unset req.http.X-WV-Mode;
 unset req.http.X-WV-Reason;
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
        for name in site['names']:
            native.hostname(name)
            if name in names:raise ValueError('Duplicate hostname scope')
            names.add(name)
        cond=' || '.join('req.http.host == '+quoted(n) for n in site['names'])
        profile=profiles.selected(site)
        cookie_contract=cookie_bridge.cookie_control.cache_contract(site.get('cookie_integration'),site['domain'],site['names'],config.get('cookie_policies'),site.get('cookie_policies'))
        text.append(' if ('+cond+') {\n set req.http.X-WV-Site = '+quoted(site['id'])+';\n'+
            ' set req.http.X-WV-Profile = '+quoted(profile)+';\n set req.http.X-SCP-Profile = '+quoted(profile)+';\n'+
            (' set req.http.X-SCP-Cookie-Contract = '+quoted(cookie_contract)+';\n' if cookie_contract else '')+
            (' set req.http.X-WV-Disabled = "1";\n' if not site.get('enabled') else '')+
            ' if (req.method == "HEAD" && req.http.X-WV-Control-Discovery == "1" && local.socket == "public") { return (synth(405, "HTTP cache control endpoint")); }\n'+
            ' if (req.method == "PURGE" || req.method == "BAN") {\n'+
            ' if (req.http.X-WV-Disabled || req.esi_level > 0 || local.socket != "public" || (req.http.X-Webuzo-Varnish-Token != '+quoted(site['token'])+' &&\n'+
            ' req.http.X-UltraCache-Token != '+quoted(site['token'])+')) { return (synth(403)); }\n'+
            ' if (req.http.X-UltraCache-Token == '+quoted(site['token'])+') { call wvw_http_control; }\n'+
            ' if (req.method != "PURGE") { return (synth(403)); }\n'+
            ' ban("obj.http.X-WV-Site == '+site['id']+'"); return (synth(200, "Site cache cleared")); }\n }')
        delivery=cookie_policy.delivery_configuration(site,sites)
        if delivery:text.append(' if ('+cond+') {\n'+delivery+'\n }')
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
 if (req.http.X-WV-Disabled) { set req.http.X-WV-Reason = "site-disabled"; return (pass); }
''')
    for profile in profiles.NAMES:
        fragment=fragments.validate(profiles.rules(config,profile)['recv_vcl'],'recv',mark_pass=True,pass_reason='central-profile-vcl')
        if fragment:text.append(' if (req.http.X-WV-Profile == '+quoted(profile)+') { '+fragment+' }')
    for site in sites.values():
        if not site.get('enabled') or site.get('error'):continue
        prefixes=paths(site.get('bypass',[]))
        for path in prefixes:
            # Literal prefix; no caller-supplied VCL or regular expression.
            pattern='(?i)^('+re.escape(path).replace('\\.','[.]')+'|'+literal_bytes(unquote(path))+')'
            text.append(' if (req.http.X-WV-Site == '+quoted(site['id'])+' && req.url ~ '+quoted(pattern)+') { set req.http.X-WV-Reason = "site-bypass-path"; set req.http.X-WV-Mode = "PASS"; return (pass); }')
        fragment=fragments.validate(site.get('recv_vcl',''),'recv',mark_pass=True,pass_reason='site-request-vcl')
        if fragment:text.append(' if (req.http.X-WV-Site == '+quoted(site['id'])+') { '+fragment+' }')
    text.append('''
 call scp_recv;
 return (hash);
}
sub vcl_pass { call scp_pass; }
sub vcl_hash {
 call scp_key;
 call scp_cookie_hash;
 hash_data("webuzo-shared-policy-v7");
 hash_data(req.http.X-WV-Site); hash_data(req.http.host);
 hash_data(req.http.X-SCP-Key-URL);
 return (lookup);
}
sub vcl_hit {
 if (req.http.X-WV-Soft-Purge == "1") { call wvw_soft_purge; }
 call scp_hit;
}
sub vcl_miss { if (req.http.X-WV-Soft-Purge == "1") { call wvw_soft_purge; } }
sub wvw_soft_purge {
 set req.http.X-WV-Soft-Purge = purge.soft(); return (synth(200, "Soft purge completed"));
}
sub vcl_backend_fetch { call scp_backend_fetch; }
sub vcl_backend_response {
 set beresp.http.X-WV-Site = bereq.http.X-WV-Site;
 set beresp.http.X-Cache-Object-Host = bereq.http.host;
 set beresp.http.X-Cache-Object-URL = bereq.http.X-SCP-Key-URL;
''')
    for profile in profiles.NAMES:
        fragment=fragments.validate(profiles.rules(config,profile)['backend_vcl'],'backend_response')
        if fragment:text.append(' if (bereq.http.X-WV-Profile == '+quoted(profile)+') { '+fragment+' }')
    for site in sites.values():
        if not site.get('enabled') or site.get('error'):continue
        fragment=fragments.validate(site.get('backend_vcl',''),'backend_response')
        if fragment:text.append(' if (bereq.http.X-WV-Site == '+quoted(site['id'])+') { '+fragment+' }')
    text.append('''
 call scp_backend_response;
 return (deliver);
}
sub vcl_deliver {
 call scp_deliver;
 set resp.http.X-Webuzo-Varnish = resp.http.X-SCP-Result;
 if (req.http.X-WV-Reason) { set resp.http.X-Webuzo-Varnish-Reason = req.http.X-WV-Reason; }
 else { set resp.http.X-Webuzo-Varnish-Reason = resp.http.X-SCP-Result-Reason; }
 unset resp.http.X-SCP-Result;
 unset resp.http.X-SCP-Result-Reason;
 unset resp.http.X-WV-Site;
 unset resp.http.X-Cache-Object-Host;
 unset resp.http.X-Cache-Object-URL;
 set resp.http.X-Webuzo-Varnish-Profile = req.http.X-WV-Profile;
 set resp.http.X-Accel-Expires = "0";
}
sub vcl_synth { set resp.http.Cache-Control = "no-store"; set resp.http.X-Accel-Expires = "0"; }
''')
    return '\n'.join(text)+'\n'
