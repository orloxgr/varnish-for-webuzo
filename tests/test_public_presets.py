"""HIT regressions and private-response boundaries for both presets."""
import shutil
import unittest
import test_profiles as helpers
import profiles
from test_profiles import origin, get, control

WARM = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8'
BROWSER = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,application/signed-exchange;v=b3;q=0.7,*/*;q=0.8'
STATIC = ['X-Ultra-Cache-Source: apache-static','X-UltraCache-Cacheable: 1','X-UltraCache-Variant: avif','Vary: Accept, Cookie, Accept-Language']

@unittest.skipUnless(shutil.which('varnishtest'), 'Native varnishtest is required')
class PublicPresets(unittest.TestCase):
    run_policy = helpers.NativeProfiles.run_policy

    def test_public_rest_search_ajax_and_referral_reads_warm_in_both_presets(self):
        for profile in profiles.NAMES:
            responses, requests = [], []
            for path in ('/wp-json/wp/v2/posts','/?rest_route=/wp/v2/posts','/?s=shoes','/?s=shirts','/article/?ref=campaign','/public-ajax'):
                headers=['X-Requested-With: XMLHttpRequest']
                responses.append(origin(path,path,expect=['expect req.http.X-Requested-With == "XMLHttpRequest"']))
                requests.extend([get(path,path,headers,cache='MISS'),get(path,path,headers,cache='HIT')])
            with self.subTest(profile=profile):self.run_policy(profile,responses,requests)

    def test_authenticated_rest_headers_cannot_reuse_warmed_public_answers(self):
        for profile in profiles.NAMES:
            responses=[origin('/wp-json/data','public')];requests=[get('/wp-json/data','public',cache='MISS')]
            for header in ('X-WP-Nonce: alice','Nonce: alice','Cart-Token: alice','Authorization: Bearer alice'):
                responses.append(origin('/wp-json/data','private-'+header))
                requests.append(get('/wp-json/data','private-'+header,[header],cache='PASS'))
            requests.append(get('/wp-json/data','public',cache='HIT'))
            with self.subTest(profile=profile):self.run_policy(profile,responses,requests)

    def test_referrals_setting_cookies_reach_origin_for_each_visitor(self):
        for profile in profiles.NAMES:
            responses=[];requests=[]
            for visitor in ('alice','bob'):
                responses.append(origin('/?ref=affiliate',visitor,['Set-Cookie: referral_session='+visitor]))
                requests.extend([get('/?ref=affiliate',visitor,cache='PASS'),'expect resp.http.Set-Cookie == "referral_session='+visitor+'"'])
            with self.subTest(profile=profile):self.run_policy(profile,responses,requests)

    def test_campaign_keys_are_shared_without_losing_search_or_referral_arguments(self):
        for profile in profiles.NAMES:
            self.run_policy(profile,[origin('/?utm_source=A&s=shoes&utm_medium=x&ref=partner','shoes'),origin('/?s=shirts&ref=partner&utm_source=A','shirts')],
                [get('/?utm_source=A&s=shoes&utm_medium=x&ref=partner','shoes',cache='MISS'),
                 get('/?utm_source=B&s=shoes&ref=partner','shoes',cache='HIT'),
                 get('/?s=shirts&ref=partner&utm_source=A','shirts',cache='MISS')])

    def test_static_html_warmup_matches_browser_without_rewriting_origin_accept(self):
        for profile in profiles.NAMES:
            responses=[origin('/page','en',STATIC,expect=['expect req.http.Accept == "'+WARM+'"']),
                       origin('/page','fr',STATIC)]
            requests=[get('/page','en',['Accept: '+WARM,'Accept-Language: en','Cookie: _ga=A'],cache='MISS'),
                      'expect resp.http.Vary ~ "Accept"','expect resp.http.Vary !~ "X-WV"',
                      get('/page','en',['Accept: '+BROWSER,'Accept-Language: en','Cookie: _ga=B'],cache='HIT'),
                      get('/page','fr',['Accept: '+BROWSER,'Accept-Language: fr'],cache='MISS'),
                      get('/page','fr',['Accept: '+WARM,'Accept-Language: fr'],cache='HIT')]
            with self.subTest(profile=profile):self.run_policy(profile,responses,requests)

    def test_static_contract_is_not_inferred_from_cacheable_html_or_request_headers(self):
        forged=['X-Ultra-Cache-Source: apache-static','X-UltraCache-Cacheable: 1','X-UltraCache-Variant: avif','X-WV-HTML-Accept: html;avif;webp']
        for profile in profiles.NAMES:
            self.run_policy(profile,[origin('/page','warm',['Vary: Accept, Cookie']),origin('/page','browser',['Vary: Accept, Cookie'])],
                [get('/page','warm',['Accept: '+WARM,*forged],cache='MISS'),
                 get('/page','browser',['Accept: '+BROWSER,*forged],cache='MISS'),
                 get('/page','browser',['Accept: '+BROWSER,*forged],cache='HIT')])

    def test_codec_refusals_and_non_html_requests_keep_distinct_representations(self):
        for profile in profiles.NAMES:
            denied='text/html,image/avif;q=0,image/webp'
            duplicate='text/html,image/avif,image/avif;q=0,image/webp'
            requests=[get('/page','avif',['Accept: '+WARM],cache='MISS'),
                      get('/page','webp',['Accept: '+denied],cache='MISS'),
                      get('/page','webp',['Accept: '+duplicate],cache='HIT'),
                      get('/page','json',['Accept: application/json'],cache='MISS'),
                      get('/page','xml',['Accept: application/xml'],cache='MISS'),
                      get('/page','no-html',['Accept: text/html;q=0,application/json'],cache='MISS'),
                      get('/page','avif',['Accept: '+BROWSER],cache='HIT')]
            responses=[origin('/page','avif',STATIC),origin('/page','webp',[h.replace(': avif',': webp') for h in STATIC]),
                       origin('/page','json',['Vary: Accept'],mime='application/json'),
                       origin('/page','xml',['Vary: Accept'],mime='application/xml'),
                       origin('/page','no-html',['Vary: Accept'],mime='application/json')]
            with self.subTest(profile=profile):self.run_policy(profile,responses,requests)

    def test_real_cookie_variation_is_not_removed_from_dynamic_html(self):
        for profile in profiles.NAMES:
            self.run_policy(profile,[origin('/page','A',['Vary: Cookie']),origin('/page','B',['Vary: Cookie'])],
                [get('/page','A',['Accept: '+WARM,'Cookie: audience=A'],cache='MISS'),
                 get('/page','B',['Accept: '+WARM,'Cookie: audience=B'],cache='MISS'),
                 get('/page','A',['Accept: '+WARM,'Cookie: audience=A'],cache='HIT')])

    def test_client_labels_and_reasons_agree_for_origin_privacy_and_sessions(self):
        self.run_policy('ultracache',[origin('/public','public'),origin('/public','alice'),origin('/public','bob'),
                                     origin('/private','private',cache='private, no-store')],
            [get('/public','public',cache='MISS'),'expect resp.http.X-Cache == "MISS"',
             get('/public','alice',['Cookie: wordpress_logged_in_demo=alice'],cache='PASS'),
             'expect resp.http.X-Cache == "PASS"','expect resp.http.X-Webuzo-Varnish-Reason == "private-session-cookie"',
             get('/public','bob',['Cookie: wp_woocommerce_session_demo=bob'],cache='PASS'),
             'expect resp.http.X-Webuzo-Varnish-Reason == "woocommerce-session-cookie"',
             get('/private','private',cache='PASS'),'expect resp.http.X-Cache == "PASS"',
             'expect resp.http.X-Webuzo-Varnish-Reason == "origin-cache-policy"',
             get('/public','public',cache='HIT'),'expect resp.http.X-Cache == "HIT"',
             'expect resp.http.X-Webuzo-Varnish-Reason == "cached-response"'])

    def test_unusual_accept_parameters_do_not_collapse_different_codec_outputs(self):
        unusual='text/html,image/avif;foo=q=0,image/webp'
        refused='text/html,image/avif;q=0,image/webp'
        for profile in profiles.NAMES:
            self.run_policy(profile,[origin('/page','unusual-avif',STATIC),
                                     origin('/page','refused-webp',[h.replace(': avif',': webp') for h in STATIC])],
                [get('/page','unusual-avif',['Accept: '+unusual],cache='MISS'),
                 get('/page','refused-webp',['Accept: '+refused],cache='MISS'),
                 get('/page','refused-webp',['Accept: '+refused],cache='HIT')])

    def test_exact_purge_uses_the_same_campaign_key_and_preserves_other_sites(self):
        for profile in profiles.NAMES:
            self.run_policy(profile,[origin('/page?utm_source=A&ref=partner','first'),origin('/page?ref=partner','other'),origin('/page?ref=partner','new')],
                [get('/page?utm_source=A&ref=partner','first',cache='MISS'),
                 get('/page?ref=partner','other',host='other.test',cache='MISS'),
                 control('/page?utm_source=B&ref=partner'),
                 get('/page?ref=partner','new',cache='MISS'),
                 get('/page?ref=partner','other',host='other.test',cache='HIT')])
