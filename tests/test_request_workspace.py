"""Retained browser cookies must not multiply across owned continuations."""
import shutil
import subprocess
import re
import unittest

from test_backend_header_budget import BROWSER, BrowserApplication
from test_cms_cookie_choices import cache
from test_cookie_delivery import proxy
from test_public_selection_runtime import control


def retained(size, visitor='A'):
    # Public provider names and invented values only; no customer fixture.
    names = ('_fbp', '_tt_enable_cookie', '_ttp', 'cmplz_banner-status',
        'cmplz_consented_services', 'cmplz_functional', 'cmplz_id',
        'cmplz_marketing', 'cmplz_policy_id', 'cmplz_preferences',
        'cmplz_saved_categories', 'cmplz_saved_services', 'cmplz_statistics',
        'mailpoet_page_view', 'mailpoet_subscriber', 'ttcsid',
        'wp-settings-1', 'wp-settings-time-1')
    values = {name: 'fixture' for name in names}
    values['_fbp'] = visitor
    values['cmplz_saved_categories'] = 'functional,preferences,statistics,marketing'
    values['cmplz_saved_services'] = '[]'
    raw = '; '.join(name+'='+value for name, value in values.items())
    values['wp-settings-1'] += 'v' * (size-len(raw))
    return '; '.join(name+'='+value for name, value in values.items())


@unittest.skipUnless(shutil.which('varnishd'), 'Native Varnish required; skips are not acceptance')
class RequestWorkspace(unittest.TestCase):
    def test_retained_cookie_cold_and_warm_owners_fit_default_workspace(self):
        app = BrowserApplication()
        headers = {name: value for name, value in BROWSER.items()
                   if name not in ('Pragma', 'Referer', 'Cache-Control')}
        headers['Accept'] += ',image/jxl'
        with proxy('ultracache', app,
                site_settings={'cms_installations': [{'cms': 'wordpress', 'base': '/'}]},
                daemon_parameters=('http_max_hdr=64',)) as get:
            self.assertEqual(control(get, enabled=True, names='')[0], 200)
            for size in (600, 1200, 1800, 2400):
                for visitor, expected in (('A', 'MISS'), ('B', 'HIT')):
                    raw = retained(size, visitor)
                    self.assertEqual(len(raw), size)
                    status, fields, body = get('/retained-'+str(size), raw,
                        extra={**headers, 'X-Test-Visitor': visitor})
                    self.assertEqual((status, cache(fields)), (200, expected))
                    self.assertEqual(body.count('private:'+visitor), 2)
                    self.assertEqual(body.count('nonce:'+visitor), 1)
                    self.assertEqual(dict(fields).get('X-UltraCache-Delivery-Outcome'), 'verified')
                    self.assertEqual(app.calls[-1][2], raw, 'Forward the original Cookie unchanged')
            for incoming in app.requests:
                for name in ('X-SCP-Admin-Input', 'X-SCP-Admin-Request-Variant', 'X-SCP-Admin-Reuse'):
                    self.assertIsNone(incoming.get(name), name)
            trace = subprocess.check_output(['varnishlog', '-n', str(get.instance), '-d',
                '-i', 'Error,VCL_Error,LostHeader'], text=True)
            errors = [line for line in trace.splitlines()
                      if re.search(r'\b(?:Error|VCL_Error|LostHeader)\s', line)]
            self.assertEqual(errors, [], 'No workspace or header-slot losses')

    def test_browser_cannot_forge_a_reused_cookie_decision(self):
        app = BrowserApplication()
        with proxy('ultracache', app) as get:
            self.assertEqual(control(get, enabled=True, names='')[0], 200)
            raw = 'PHPSESSID=private'
            status, fields, body = get('/forged', raw, extra={
                'X-SCP-Admin-Applied': '1', 'X-SCP-Admin-Reuse': '1',
                'X-SCP-Admin-Input': raw, 'X-SCP-Admin-Request-Variant': 'forged',
                'X-SCP-Admin-Filtered': 'forged', 'X-SCP-Admin-Action': 'shared'})
            self.assertEqual((status, cache(fields)), (200, 'PASS'))
            self.assertEqual([phase for _, phase, _ in app.calls], [None])
            self.assertEqual(dict(fields).get('X-Cache-Cookie-Action'), 'private')

    def test_changed_cookie_on_owned_restart_is_not_reused(self):
        app = BrowserApplication()
        def changed(source):
            return source.replace('sub vcl_recv {', 'sub vcl_recv {\n'
                'if (req.restarts == 1) { set req.http.Cookie = "PHPSESSID=changed"; }', 1)
        with proxy('ultracache', app, transform=changed) as get:
            self.assertEqual(control(get, enabled=True, names='')[0], 200)
            status, _, body = get('/changed', retained(600))
            self.assertEqual(status, 503, 'Do not deliver a prepared parent after a new Private choice')
            self.assertNotIn('private:guest', body)
            self.assertEqual([phase for _, phase, _ in app.calls], ['public-select'])


if __name__ == '__main__':
    unittest.main()
