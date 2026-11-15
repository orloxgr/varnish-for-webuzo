"""Origin/native freshness without addon status or retention overrides."""
import shutil
import unittest
from unittest.mock import patch
import test_profiles as http
from test_profiles import profiles


@unittest.skipUnless(shutil.which('varnishtest'),'Native Varnish required')
class NativePolicy(unittest.TestCase):
    run_policy=http.NativeProfiles.run_policy

    def test_runtime_retention_and_marker_settings_are_preserved(self):
        original=http.program
        def instrument(*args,**kwargs):
            return original(*args,**kwargs).replace('\n}\n\nsub scp_backend_response {',
                '\n set beresp.http.X-Test-Marker-TTL = beresp.ttl; set beresp.http.X-Test-Marker-Grace = beresp.grace; set beresp.http.X-Test-Marker-Keep = beresp.keep;\n}\n\nsub scp_backend_response {')
        for profile in profiles.NAMES:
            observation='set beresp.http.X-User-TTL = beresp.ttl; set beresp.http.X-User-Grace = beresp.grace; set beresp.http.X-User-Keep = beresp.keep;'
            config={'profile_rules':{profile:dict(recv_vcl='',backend_vcl=observation)}}
            with patch.object(http,'program',side_effect=instrument):self.run_policy(profile,
                [http.origin('/public','public',cache='public, max-age=1800'),http.origin('/private','A',cache='private, no-store'),http.origin('/private','B',cache='private, no-store')],
                [http.get('/public','public',cache='MISS'),'expect resp.http.X-User-TTL == "1800.000"',
                 'expect resp.http.X-User-Grace == "41.000"','expect resp.http.X-User-Keep == "23.000"',http.get('/public','public',cache='HIT'),
                 http.get('/private','A',cache='PASS'),'expect resp.http.X-Test-Marker-TTL == "37.000"',
                 'expect resp.http.X-Test-Marker-Grace == "41.000"','expect resp.http.X-Test-Marker-Keep == "23.000"',http.get('/private','B',cache='PASS')],
                config=config,varnish_args='-arg "-p uncacheable_ttl=37 -p default_grace=41 -p default_keep=23"',
                tail='varnish v1 -expect MAIN.cache_hitmiss == 1')

    def test_cacheable_404_and_410_can_hit_but_private_errors_remain_private(self):
        for profile in profiles.NAMES:
            responses=[];requests=[]
            for status in (404,410):
                path='/status-'+str(status)
                responses.append(http.origin(path,'public',status=status,cache='public, max-age=1800'))
                requests.extend([http.get(path,'public',status=status,cache='MISS'),http.get(path,'public',status=status,cache='HIT')])
                for visitor in ('A','B'):
                    responses.append(http.origin(path+'-private',visitor,status=status,cache='private, no-store'))
                    requests.append(http.get(path+'-private',visitor,status=status,cache='PASS'))
            self.run_policy(profile,responses,requests)

    def test_500_follows_native_freshness_and_explicit_admin_rule_without_bypassing_privacy(self):
        for profile in profiles.NAMES:
            for override in (False,True):
                responses=[];requests=[]
                for status in (500,503):
                    path='/status-'+str(status)
                    for visitor in (('public',) if override else ('A','B')):
                        responses.append(http.origin(path,visitor,status=status,cache='public, max-age=1800'))
                        requests.append(http.get(path,visitor,status=status,cache='MISS' if override else 'PASS'))
                    if override:requests.append(http.get(path,'public',status=status,cache='HIT'))
                    for visitor in ('A','B'):
                        responses.append(http.origin(path+'-private',visitor,status=status,cache='private, no-store'))
                        requests.append(http.get(path+'-private',visitor,status=status,cache='PASS'))
                self.run_policy(profile,responses,requests,config={'profile_rules':{profile:dict(recv_vcl='',backend_vcl='set beresp.ttl = 1800s;' if override else '')}})

    def test_cookie_responses_keep_origin_policy_and_separate_visitors(self):
        for profile in profiles.NAMES:
            self.run_policy(profile,
                [http.origin('/cookie',visitor,['Set-Cookie: visitor='+visitor],cache='public, max-age=1800') for visitor in ('A','B')],
                [http.get('/cookie','A',cache='PASS'),'expect resp.http.Set-Cookie == "visitor=A"',
                 'expect resp.http.Cache-Control == "public, max-age=1800"',http.get('/cookie','B',cache='PASS'),'expect resp.http.Set-Cookie == "visitor=B"'])


if __name__=='__main__':unittest.main()
