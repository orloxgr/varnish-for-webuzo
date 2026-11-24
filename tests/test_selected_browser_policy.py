"""Native selected/guest snapshots keep browser policy and actual shared TTL."""
import shutil
import time
import unittest
from test_cookie_delivery import proxy
from test_guest_publication import Guests, register, GUEST_BODY
from test_public_selection_runtime import Resolver, control
from test_cms_cookie_choices import cache


BROWSER = ['Cache-Control: private, no-store', 'Cache-Control: max-age=0',
    'Pragma: no-cache', 'Pragma: legacy-option', 'Expires: Thu, 19 Nov 1981 08:52:00 GMT',
    "Content-Security-Policy: default-src 'self'", 'X-Content-Type-Options: nosniff']


@unittest.skipUnless(shutil.which('varnishd'), 'Actual isolated Varnish required; skip is not acceptance')
class SelectedBrowserPolicy(unittest.TestCase):
    def browser_policy(self, fields, personal=False):
        values = dict(fields)
        for name, expected in (('Cache-Control', {'private', 'no-store'} if personal else {'private', 'no-store', 'max-age=0'}),
                ('Pragma', {'no-cache', 'legacy-option'})):
            found = [value for key, value in fields if key.lower() == name.lower()]
            self.assertEqual(len(found), 1)
            directives = {part.strip() for part in found[0].split(',')}
            if personal and name == 'Cache-Control':
                # The original per-request wrapper may omit redundant max-age=0;
                # a plain public-object HIT preserves it. Both forbid storage.
                self.assertTrue(expected <= directives <= expected | {'max-age=0'})
            else:
                self.assertEqual(directives, expected)
        self.assertEqual(values['Expires'], 'Thu, 19 Nov 1981 08:52:00 GMT')
        self.assertEqual(values['Content-Security-Policy'], "default-src 'self'")
        self.assertEqual(values['X-Content-Type-Options'], 'nosniff')
        self.assertNotIn('X-SCP-Browser-Cache-Control', values)
        return values

    def test_complete_guest_hits_with_restrictive_browser_headers_and_decreasing_age(self):
        app = Guests()
        def selected(value):
            value['guestPublic']['headers'] += BROWSER
            value['guestPublic']['publicParent']['freshRemaining'] = 8
        app.change = selected
        with proxy('ultracache', app) as get:
            self.assertEqual(register(get)[0], 200)
            status, fields, body = get('/guest-browser-policy')
            self.assertEqual((status, cache(fields), body), (200, 'MISS', GUEST_BODY))
            first = self.browser_policy(fields)
            self.assertGreater(int(first['X-UltraCache-Surrogate-TTL']), 0)
            self.assertLessEqual(int(first['X-UltraCache-Surrogate-TTL']), 8)
            app_count = len(app.calls)
            time.sleep(1.05)
            status, fields, body = get('/guest-browser-policy')
            self.assertEqual((status, cache(fields), body), (200, 'HIT', GUEST_BODY))
            hit = self.browser_policy(fields)
            self.assertGreaterEqual(int(hit['Age']), 1)
            self.assertEqual(len(app.calls), app_count)

    def test_selected_parent_hits_and_keeps_existing_downstream_personal_privacy(self):
        def selected(value, headers):
            value['selectedPublic']['headers'] += BROWSER
            value['selectedPublic']['publicParent']['freshRemaining'] = 8
        app = Resolver(change=selected)
        with proxy('ultracache', app) as get:
            self.assertEqual(control(get, enabled=True, names='')[0], 200)
            first = get('/selected-browser-policy')
            self.assertEqual((first[0], cache(first[1])), (200, 'MISS'))
            # Non-guest selected delivery still requires each visitor's real
            # provider selection; keep its existing stricter no-store wrapper.
            self.browser_policy(first[1], personal=True)
            self.assertLessEqual(int(dict(first[1])['X-UltraCache-Surrogate-TTL']), 8)
            count = len(app.calls)
            second = get('/selected-browser-policy')
            self.assertEqual((second[0], cache(second[1]), second[2]), (200, 'HIT', first[2]))
            self.browser_policy(second[1], personal=True); self.assertEqual(len(app.calls), count)

    def test_expired_selected_parent_cannot_borrow_a_long_browser_lifetime(self):
        def selected(value, headers):
            value['selectedPublic']['headers'].append('Cache-Control: public, max-age=31536000')
            value['selectedPublic']['publicParent']['freshRemaining'] = 0
        app = Resolver(change=selected)
        with proxy('ultracache', app) as get:
            self.assertEqual(control(get, enabled=True, names='')[0], 200)
            for _ in range(2):
                status, fields, body = get('/expired-browser-policy')
                self.assertEqual(status, 200)
                self.assertNotEqual(cache(fields), 'HIT')
                self.assertEqual(dict(fields)['Cache-Control'], 'private, no-store')
                self.assertEqual(dict(fields)['X-UltraCache-Surrogate-TTL'], '0')
            self.assertEqual(len(app.calls), 2)


if __name__ == '__main__': unittest.main()
