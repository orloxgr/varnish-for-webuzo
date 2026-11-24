"""Application storage approval is separate from the browser's HTTP policy."""
import shutil
import unittest
import test_profiles as http


@unittest.skipUnless(shutil.which('varnishtest'), 'Native Varnish required')
class NativeApplicationCachePolicy(unittest.TestCase):
    run_policy = http.NativeProfiles.run_policy
    approval = ['X-UltraCache-Cacheable: 1', 'X-UltraCache-Surrogate-TTL: 120',
                'X-UltraCache-Stale-While-Revalidate: 17']

    def test_approved_html_hits_without_enabling_aggressive_and_keeps_browser_headers(self):
        fields = self.approval + ['Pragma: no-cache', 'Expires: Thu, 19 Nov 1981 08:52:00 GMT']
        self.run_policy('ultracache', [http.origin('/page', 'public', fields, cache='private, no-store')],
            [http.get('/page', 'public', cache='MISS'),
             'expect resp.http.X-Test-Final-TTL == "120.000"',
             'expect resp.http.X-Test-Final-Grace == "17.000"',
             'expect resp.http.X-Cache-Mode == "standard"',
             'expect resp.http.Cache-Control == "private, no-store"',
             'expect resp.http.Pragma == "no-cache"',
             'expect resp.http.Expires == "Thu, 19 Nov 1981 08:52:00 GMT"',
             http.get('/page', 'public', cache='HIT'),
             'expect resp.http.Cache-Control == "private, no-store"',
             'expect resp.http.Pragma == "no-cache"',
             'expect resp.http.Expires == "Thu, 19 Nov 1981 08:52:00 GMT"',
             'expect resp.http.X-SCP-Browser-Cache-Control == <undef>',
             'expect resp.http.X-SCP-Aggressive-Response == <undef>'], observe_ttl=True)

    def test_basic_does_not_consume_the_application_override(self):
        self.run_policy('basic',
            [http.origin('/page', visitor, self.approval, cache='private, no-store') for visitor in ('A', 'B')],
            [http.get('/page', visitor, cache='PASS') for visitor in ('A', 'B')])

    def test_missing_denied_or_invalid_application_approval_cannot_override_browser_policy(self):
        responses = []; requests = []
        for index, fields in enumerate(([], ['X-UltraCache-Cacheable: 0', 'X-UltraCache-Surrogate-TTL: 120'],
                ['X-UltraCache-Cacheable: 1', 'X-UltraCache-Surrogate-TTL: 0'],
                ['X-UltraCache-Cacheable: 1', 'X-UltraCache-Surrogate-TTL: invalid'],
                self.approval + ['Surrogate-Control: no-store'],
                self.approval + ['X-UltraCache-Application-Private: actual-personal-body'])):
            path = '/case-' + str(index)
            for visitor in ('A', 'B'):
                responses.append(http.origin(path, visitor, fields, cache='private, no-store'))
                requests.append(http.get(path, visitor, cache='PASS'))
        self.run_policy('ultracache', responses, requests)

    def test_age_is_subtracted_from_application_lifetime(self):
        self.run_policy('ultracache', [http.origin('/page', 'public', self.approval + ['Age: 37'], cache='no-store')],
            [http.get('/page', 'public', cache='MISS'),
             'expect resp.http.X-Test-Final-TTL == "83.000"',
             http.get('/page', 'public', cache='HIT')], observe_ttl=True)

    def test_expired_application_object_is_not_refreshed_by_approval(self):
        self.run_policy('ultracache',
            [http.origin('/page', visitor, self.approval + ['Age: 121'], cache='no-store') for visitor in ('A', 'B')],
            [http.get('/page', visitor, cache='PASS') for visitor in ('A', 'B')])

    def test_shared_response_cookie_belongs_only_to_the_fetching_visitor(self):
        self.run_policy('ultracache',
            [http.origin('/page', 'public', self.approval + ['Set-Cookie: _ga=A; Path=/; HttpOnly'], cache='no-store')],
            [http.get('/page', 'public', cache='MISS'),
             'expect resp.http.Set-Cookie == "_ga=A; Path=/; HttpOnly"',
             http.get('/page', 'public', cache='HIT'), 'expect resp.http.Set-Cookie == <undef>'])

    def test_private_response_cookie_still_uses_the_active_policy(self):
        self.run_policy('ultracache',
            [http.origin('/page', visitor, self.approval + ['Set-Cookie: private_choice=' + visitor], cache='no-store')
             for visitor in ('A', 'B')], [http.get('/page', visitor, cache='PASS') for visitor in ('A', 'B')],
            config={'cookie_policies': {'schemaVersion': 1, 'rules': [dict(id='choice',
                match=dict(kind='exact', value='private_choice'), description='Explicit Private', action='private')]}})


if __name__ == '__main__':
    unittest.main()
