"""Exercise all four product VCL profiles with native Varnish HTTP origins."""
import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import engine
import native
import policy
import profiles

def site(identity='a',domain='example.test',profile='basic',token='b'):
    return dict(id=identity*32,domain=domain,names=[domain],enabled=True,error='',token=token*64,ttl=300,bypass=[],recv_vcl='',backend_vcl='',profile=profile)

def program(profile='basic',config=None):
    first=site(profile=profile);second=site('c','other.test',profile,'d')
    source=policy.render({first['id']:first,second['id']:second},'e'*64,'f'*64,config)
    for scheme in ('http','https'):
        source=source.replace('.path = "/run/varnish-for-webuzo-origin-'+scheme+'.sock";','.host = "127.0.0.1"; .port = "${s1_port}";')
    # The disposable varnishtest listener is TCP. Product purges use a protected
    # Unix socket; exercise its authenticated branch with the isolated client.
    return source.replace('local.socket != "public"','client.ip != "127.0.0.1"')

def origin(path,body,headers=(),expect=(),status=200,cache='public, max-age=120'):
    return '\n'.join(['accept','rxreq','expect req.url == '+json.dumps(path),*expect,
        'txresp -status '+str(status)+' -hdr "Connection: close" -hdr "Content-Type: text/html" -hdr '+json.dumps('Cache-Control: '+cache)+' '+
        ' '.join('-hdr {'+h+'}' for h in headers)+' -body {'+body+'}'])

def get(path,body,headers=(),cache=None,host='example.test',method='GET',status=200):
    return '\n'.join(['txreq -req '+method+' -url '+json.dumps(path)+' -hdr "Host: '+host+'" -hdr "X-WV-Gateway: '+'e'*64+'" '+
        ' '.join('-hdr {'+h+'}' for h in headers),'rxresp','expect resp.status == '+str(status),*(['expect resp.body == {'+body+'}'] if body is not None else []),
        *(['expect resp.http.X-Webuzo-Varnish == "'+cache+'"'] if cache else [])])

def control(path='/',host='example.test',token='b',headers=(),method='PURGE',status=200):
    return '\n'.join(['txreq -req '+method+' -url '+json.dumps(path)+' -hdr "Host: '+host+'" -hdr "X-UltraCache-Token: '+token*64+'" '+
        ' '.join('-hdr {'+h+'}' for h in headers),'rxresp','expect resp.status == '+str(status)])

class ProfileChoices(unittest.TestCase):
    def test_four_real_profiles_and_central_basic_default(self):
        self.assertEqual(profiles.NAMES,('basic','wordpress','woocommerce','ultracache'))
        self.assertEqual(profiles.default({}),'basic')
        catalog=profiles.catalog({});self.assertEqual(len({p['source'] for p in catalog}),4)
        self.assertTrue(all(p['source'] and p['description'] for p in catalog))
    def test_new_sites_inherit_default_and_existing_profiles_remain_assigned(self):
        first,second=site(),site('c','other.test','woocommerce','d')
        observed={s['id']:dict(s) for s in (first,second)}
        config=dict(default_profile='wordpress',sites={first['id']:{},second['id']:dict(second)})
        third=site('f','new.test','basic','0');observed[third['id']]=third
        with patch.object(native,'collect',return_value=observed):found=engine.inventory(config)
        self.assertEqual(found[first['id']]['profile'],'basic')
        self.assertEqual(found[second['id']]['profile'],'woocommerce')
        self.assertEqual(found[third['id']]['profile'],'wordpress');self.assertFalse(found[third['id']]['enabled'])
    def test_invalid_profile_or_central_code_never_enters_policy(self):
        for value in ('general','../wordpress','basic;return(pass);',None,{}):
            with self.subTest(value=value),self.assertRaises(ValueError):profiles.name(value)
        with self.assertRaises(ValueError):profiles.rules({'profile_rules':{'basic':{'recv_vcl':'include "/etc/passwd";'}}},'basic')

@unittest.skipUnless(shutil.which('varnishtest'),'Native varnishtest is required')
class NativeProfiles(unittest.TestCase):
    def run_policy(self,profile,responses,requests,config=None):
        source='varnishtest "Webuzo '+profile+' profile"\nserver s1 {\n'+'\n'.join(responses).removeprefix('accept\n')+'\n} -start\nvarnish v1 -vcl {\n'+program(profile,config)+'\n} -start\nclient c1 {\n'+'\n'.join(requests)+'\n} -run\nserver s1 -wait\n'
        with tempfile.TemporaryDirectory(prefix='wvw-profiles-') as folder:
            path=Path(folder)/'profile.vtc';path.write_text(source)
            result=subprocess.run(['varnishtest','-t','20',str(path)],capture_output=True,text=True,timeout=30)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
    def test_plain_html_works_with_every_profile_without_a_wordpress_plugin(self):
        for profile in profiles.NAMES:
            with self.subTest(profile=profile):self.run_policy(profile,[origin('/page','public')],[get('/page','public',cache='MISS'),get('/page','public',cache='HIT')])
    def test_basic_preserves_conservative_cookie_and_query_bypass(self):
        self.run_policy('basic',[origin('/page','A'),origin('/page','B'),origin('/page?q=1','C'),origin('/page?q=1','D')],
            [get('/page','A',['Cookie: unknown_vendor=A'],cache='PASS'),get('/page','B',['Cookie: unknown_vendor=B'],cache='PASS'),get('/page?q=1','C',cache='PASS'),get('/page?q=1','D',cache='PASS')])
    def test_wordpress_and_shop_profiles_keep_tracking_cookies_but_share_public_html(self):
        for profile in ('wordpress','woocommerce','ultracache'):
            with self.subTest(profile=profile):self.run_policy(profile,[origin('/page','public',expect=['expect req.http.Cookie == "unknown_vendor=A"'])],
                [get('/page','public',['Cookie: unknown_vendor=A'],cache='MISS'),get('/page','public',['Cookie: unknown_vendor=B'],cache='HIT')])
    def test_private_sessions_and_duplicate_cookie_headers_never_reuse_public_objects(self):
        for profile in profiles.NAMES:
            with self.subTest(profile=profile):self.run_policy(profile,[origin('/page','public'),origin('/page','A'),origin('/page','B')],
                [get('/page','public',cache='MISS'),get('/page','A',['Cookie: tracking=1','Cookie: wordpress_logged_in_a=A'],cache='PASS'),get('/page','B',['Cookie: PHPSESSID=B'],cache='PASS'),get('/page','public',cache='HIT')])
    def test_shop_session_alone_cannot_share_unmarked_personal_html(self):
        self.run_policy('woocommerce',
            [origin('/product/example/','public'),origin('/product/example/','notice-A'),origin('/product/example/','visitor-B')],
            [get('/product/example/','public',cache='MISS'),
             get('/product/example/','notice-A',['Cookie: wp_woocommerce_session_demo=A'],cache='PASS'),
             get('/product/example/','visitor-B',['Cookie: wp_woocommerce_session_demo=B'],cache='PASS'),
             get('/product/example/','public',cache='HIT')])
    def test_cart_markers_still_bypass_an_existing_public_object(self):
        for marker in ('woocommerce_items_in_cart=1','woocommerce_cart_hash=nonempty'):
            with self.subTest(marker=marker):self.run_policy('woocommerce',
                [origin('/product/example/','public'),origin('/product/example/','cart-A'),origin('/product/example/','cart-B')],
                [get('/product/example/','public',cache='MISS'),
                 get('/product/example/','cart-A',['Cookie: wp_woocommerce_session_demo=A; '+marker],cache='PASS'),
                 get('/product/example/','cart-B',['Cookie: wp_woocommerce_session_demo=B; '+marker],cache='PASS'),
                 get('/product/example/','public',cache='HIT')])
    def test_session_only_does_not_relax_other_profiles(self):
        for profile in ('basic','wordpress','ultracache'):
            with self.subTest(profile=profile):self.run_policy(profile,[origin('/page','A'),origin('/page','B')],
                [get('/page','A',['Cookie: wp_woocommerce_session_demo=A'],cache='PASS'),get('/page','B',['Cookie: wp_woocommerce_session_demo=B'],cache='PASS')])
    def test_shop_session_does_not_override_origin_cookie_or_privacy_headers(self):
        responses,requests=[],[]
        for path,headers,cache in [('/private',[], 'private, no-store'),('/cookie',['Set-Cookie: wp_woocommerce_session_demo=new'],'public, max-age=120')]:
            for visitor in ('A','B'):
                responses.append(origin(path,visitor,headers,cache=cache))
                requests.append(get(path,visitor,['Cookie: wp_woocommerce_session_demo='+visitor],cache='PASS'))
        self.run_policy('woocommerce',responses,requests)
    def test_spoofed_esi_transport_headers_are_not_forwarded_by_any_profile(self):
        headers=['X-ESI-Private-Request: 1','X-ESI-Request-Level: 1','X-ESI-Original-Cookie: private_session=forged','X-UltraCache-ESI-Candidate: 1']
        expected=['expect req.http.X-ESI-Private-Request == <undef>','expect req.http.X-ESI-Request-Level == <undef>','expect req.http.X-ESI-Original-Cookie == <undef>','expect req.http.X-UltraCache-ESI-Candidate == <undef>']
        for profile in profiles.NAMES:
            with self.subTest(profile=profile):self.run_policy(profile,[origin('/page','public',expect=expected)],[get('/page','public',headers,cache='MISS')])
    def test_private_origin_responses_and_cookies_never_become_shared(self):
        for profile in profiles.NAMES:
            responses,requests=[],[]
            for path,cache,headers,status in [('/private','private, no-store',[],200),('/cookie','public, max-age=120',['Set-Cookie: PHPSESSID=fixture'],200),('/error','public, max-age=120',[],500)]:
                for body in ('A','B'):
                    responses.append(origin(path,body,headers,status=status,cache=cache));requests.append(get(path,body,cache='PASS',status=status))
            with self.subTest(profile=profile):self.run_policy(profile,responses,requests)
    def test_wordpress_routes_and_woocommerce_actions_have_distinct_exclusions(self):
        for profile,paths in [('wordpress',['/wp-admin/','/wp-json/users','/?preview=1']),('woocommerce',['/wp-admin/','/cart/','/checkout/','/my-account/','/?wc-ajax=add_to_cart'])]:
            responses,requests=[],[]
            for path in paths:
                for body in ('A','B'):responses.append(origin(path,body));requests.append(get(path,body,cache='PASS'))
            with self.subTest(profile=profile):self.run_policy(profile,responses,requests)
    def test_ultracache_normalizes_marketing_parameters(self):
        self.run_policy('ultracache',[origin('/page','public')],[get('/page?utm_source=first','public',cache='MISS'),get('/page?utm_source=second','public',cache='HIT')])
    def test_ultracache_approved_esi_parent_keeps_private_fragments_per_visitor(self):
        fragment='/?ultracache_esi=cart&esi_scope=private'
        parent='<html><esi:include src="/?ultracache_esi=cart&amp;esi_scope=private"/></html>'
        self.run_policy('ultracache',[origin('/parent',parent,['Surrogate-Control: ESI/1.0','X-UltraCache-ESI-Shared-Parent: 1'],expect=['expect req.http.Cookie == "woocommerce_items_in_cart=1; tracking=A"','expect req.http.X-UltraCache-ESI-Candidate == "1"']),
            *[origin(fragment,visitor,expect=['expect req.http.Cookie == "esi_session='+visitor+'; woocommerce_items_in_cart=1"','expect req.http.X-ESI-Original-Cookie == <undef>','expect req.http.X-ESI-Private-Request == "1"']) for visitor in ('A','B')]],
            [get('/parent','<html>'+visitor+'</html>',['Cookie: esi_session='+visitor+'; woocommerce_items_in_cart=1; ultracache_esi_optin=1; tracking='+visitor],cache='MISS' if visitor=='A' else 'HIT') for visitor in ('A','B')])
    def test_ultracache_without_origin_approval_does_not_share_cart_parent(self):
        self.run_policy('ultracache',[origin('/parent',body) for body in ('A','B')],
            [get('/parent',body,['Cookie: woocommerce_items_in_cart=1; ultracache_esi_optin=1'],cache='PASS') for body in ('A','B')])
    def test_no_store_parent_cannot_be_approved_for_shared_esi(self):
        self.run_policy('ultracache',[origin('/parent',body,['Surrogate-Control: ESI/1.0, no-store','X-UltraCache-ESI-Shared-Parent: 1']) for body in ('A','B')],
            [get('/parent',body,['Cookie: woocommerce_items_in_cart=1; ultracache_esi_optin=1'],cache='PASS') for body in ('A','B')])
    def test_client_cannot_spoof_cart_esi_opt_in_using_headers(self):
        self.run_policy('ultracache',[origin('/parent',body) for body in ('A','B')],
            [get('/parent',body,['Cookie: woocommerce_items_in_cart=1','X-UltraCache-ESI-Opt-In: 1','X-UltraCache-ESI-Candidate: 1'],cache='PASS') for body in ('A','B')])
    def test_esi_subrequest_cannot_read_another_account(self):
        parent='<html><esi:include src="http://other.test/foreign"/></html>'
        self.run_policy('ultracache',[origin('/parent',parent,['Surrogate-Control: ESI/1.0']),origin('/foreign','OTHER-ACCOUNT',expect=['expect req.http.host == "other.test"'])],
            [get('/parent',None,cache='MISS'),'expect resp.body ~ "403"','expect resp.body !~ "OTHER-ACCOUNT"',get('/foreign','OTHER-ACCOUNT',host='other.test',cache='MISS')])
    def test_exact_purge_clears_both_scheme_variants(self):
        self.run_policy('ultracache',[origin('/page','http'),origin('/page','https'),origin('/page','http-new'),origin('/page','https-new')],
            [get('/page','http',['X-Forwarded-Proto: http'],cache='MISS'),get('/page','https',['X-Forwarded-Proto: https'],cache='MISS'),
             control('/page'),get('/page','http-new',['X-Forwarded-Proto: http'],cache='MISS'),get('/page','https-new',['X-Forwarded-Proto: https'],cache='MISS')])
    def test_malformed_expression_cannot_turn_into_a_broad_ban(self):
        self.run_policy('ultracache',[origin('/page','public')],
            [get('/page','public',cache='MISS'),control(method='BAN',headers=['X-Ban-Expression: obj.http.X-WV-Site ~ .*'],status=400),
             get('/page','public',cache='HIT'),control('/__ultracache-vcl-contract-v2',headers=['X-UltraCache-Contract: 2','X-UltraCache-Operation: host-ban','X-UltraCache-Object-Expression: obj.http.X-Cache-Object-Host == "other.test" && obj.http.X-Cache-Object-URL ~ ".*"'],status=403),get('/page','public',cache='HIT')])
    def test_central_and_site_rules_cannot_escape_private_or_account_boundaries(self):
        config={'profile_rules':{'basic':{'recv_vcl':'if (req.url == "/members/") { return (pass); }','backend_vcl':'set beresp.http.X-User-Profile = "central";'}}}
        self.run_policy('basic',[origin('/members/','A'),origin('/members/','B')],[get('/members/','A',cache='PASS'),'expect resp.http.X-User-Profile == "central"',get('/members/','B',cache='PASS')],config)
    def test_ultracache_control_authentication_and_scoped_invalidation(self):
        self.run_policy('ultracache',[origin('/page','first'),origin('/page','other'),origin('/page','updated')],
            [get('/page','first',cache='MISS'),get('/page','other',cache='MISS',host='other.test'),
             control('/page',host='other.test',status=403),
             control('/__ultracache-vcl-contract-v2',headers=['X-UltraCache-Contract: 2','X-UltraCache-Operation: capabilities']),
             'expect resp.http.X-UltraCache-VCL-Adapter == "ultracache-webuzo-v2"',
             control('/page'),get('/page','updated',cache='MISS'),get('/page','other',cache='HIT',host='other.test')])
    def test_ultracache_exact_and_batch_bans_keep_unselected_urls_warm(self):
        def ban(operation,pattern):
            return control('/__ultracache-vcl-contract-v2',headers=['X-UltraCache-Contract: 2','X-UltraCache-Operation: '+operation,
                'X-UltraCache-Object-Expression: obj.http.X-Cache-Object-Host == "example.test" && obj.http.X-Cache-Object-URL ~ "'+pattern+'"'])
        self.run_policy('ultracache',[origin('/one','one'),origin('/two','two'),origin('/control','control'),origin('/one','one-new'),origin('/one','one-newer'),origin('/two','two-new')],
            [get('/one','one'),get('/two','two'),get('/control','control'),ban('exact-ban','^/one$'),get('/two','two',cache='HIT'),get('/one','one-new',cache='MISS'),
             ban('batch-ban','^(/one|/two)$'),get('/control','control',cache='HIT'),get('/one','one-newer',cache='MISS'),get('/two','two-new',cache='MISS')])
    def test_ultracache_html_and_host_bans_preserve_other_accounts(self):
        for operation,selector in [('html-ban','obj.http.Content-Type ~ "^text/html"'),('host-ban','obj.http.X-Cache-Object-URL ~ ".*"')]:
            with self.subTest(operation=operation):self.run_policy('ultracache',[origin('/page','first'),origin('/page','other'),origin('/page','new')],
                [get('/page','first'),get('/page','other',host='other.test'),control('/__ultracache-vcl-contract-v2',headers=['X-UltraCache-Contract: 2','X-UltraCache-Operation: '+operation,
                 'X-UltraCache-Object-Expression: obj.http.X-Cache-Object-Host == "example.test" && '+selector]),get('/page','other',host='other.test',cache='HIT'),get('/page','new',cache='MISS')])
    def test_ultracache_soft_purge_expires_only_selected_url(self):
        config={'profile_rules':{'ultracache':{'recv_vcl':'','backend_vcl':'set beresp.grace = 0s;'}}}
        self.run_policy('ultracache',[origin('/target','old'),origin('/control','control'),origin('/target','other'),origin('/target','new')],
            [get('/target','old'),get('/control','control'),get('/target','other',host='other.test'),
             control('/target',headers=['X-UltraCache-Contract: 2','X-UltraCache-Operation: soft-purge']),
             get('/control','control',cache='HIT'),get('/target','other',host='other.test',cache='HIT'),get('/target','new',cache='MISS')],config)

if __name__=='__main__':unittest.main()
