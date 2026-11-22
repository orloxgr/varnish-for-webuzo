"""Actual native protocol transitions; producer collector ownership is tested in WP."""
import json
import shutil
import unittest

from test_cookie_delivery import proxy
from test_cold_public_selection import choices
from test_cms_cookie_choices import cache
from test_guest_publication import Guests, GUEST_BODY, register
from test_public_selection_runtime import control
from test_publication_reselect import Publications


HEADER = 'X-UltraCache-VCL-Publication-Reselect-Version'


class ContextPublications:
    def __init__(self):
        self.ready = False
        self.guest = Guests()
        self.partial = Publications()
        self.contexts = {name: Publications() for name in ('one', 'two')}
        for name, app in self.contexts.items():
            app.generations['/same'] = name + '-A'

    def __call__(self, path, headers):
        cookie = headers.get('Cookie', '')
        for name, app in self.contexts.items():
            if 'cmp_a=' + name in cookie:
                return app(path, headers)
        if self.ready and headers.get('X-UltraCache-Delivery-Guest-Publication-Version') == '1':
            return self.guest(path, headers)
        result = self.partial(path, headers)
        if not self.ready and headers.get('X-UltraCache-Delivery-Phase') == 'public-select':
            body, fields = result
            payload = json.loads(body)
            payload['selectedPublic']['publicParent']['freshRemaining'] = 0
            return json.dumps(payload), fields
        return result


@unittest.skipUnless(shutil.which('varnishd'), 'Actual native engine required; skipped is not acceptance')
class PublicationReselectCapability(unittest.TestCase):
    def test_capability_is_authenticated_and_ultracache_only(self):
        for profile in ('basic', 'ultracache'):
            with self.subTest(profile=profile), proxy(profile, Guests()) as get:
                status, fields, _ = control(get, enabled=False, names='')
                self.assertEqual(status, 200)
                self.assertEqual(fields.get(HEADER), '1' if profile == 'ultracache' else None)
                status, fields, _ = control(get, enabled=False, token=False, extra={HEADER: '1'})
                self.assertEqual(status, 403)
                self.assertNotIn(HEADER, fields)

    def test_unfinished_fallback_does_not_poison_later_complete_guest(self):
        app = ContextPublications()
        with proxy('ultracache', app) as get:
            self.assertEqual(register(get)[0], 200)
            for _ in range(2):
                status, fields, _ = get('/partial', extra={'Accept': 'text/html'})
                self.assertEqual(status, 200)
                self.assertNotIn('X-UltraCache-Guest-Publication', dict(fields))
            app.ready = True
            status, fields, body = get('/partial', extra={'Accept': 'text/html'})
            self.assertEqual((status, cache(fields), body), (200, 'MISS', GUEST_BODY))
            self.assertEqual(dict(fields).get('X-UltraCache-Guest-Publication'), '1')
            get.stop_origin()
            for _ in range(2):
                status, fields, body = get('/partial', extra={'Accept': 'text/html'})
                self.assertEqual((status, cache(fields), body), (200, 'HIT', GUEST_BODY))
                self.assertEqual(dict(fields).get('X-UltraCache-Guest-Publication'), '1')

    def test_existing_parent_reselection_preserves_guest_and_public_context_sibling(self):
        app = ContextPublications()
        app.ready = True
        with proxy('ultracache', app, policies=choices(('cmp_a', 'variant'))) as get:
            self.assertEqual(register(get)[0], 200)
            status, fields, _ = get('/same', extra={'Accept': 'text/html'})
            self.assertEqual((status, cache(fields)), (200, 'MISS'))
            for name in ('one', 'two'):
                status, fields, body = get('/same', 'cmp_a=' + name, {'Accept': 'text/html'})
                self.assertEqual((status, cache(fields)), (200, 'MISS'))
                self.assertIn(name + '-A[', body)
            app.contexts['one'].generations['/same'] = 'one-B'
            before = len(app.contexts['one'].observed)
            status, fields, body = get('/same', 'cmp_a=one', {'Accept': 'text/html'})
            self.assertEqual((status, cache(fields)), (200, 'MISS'))
            self.assertIn('one-B[', body)
            self.assertEqual([phase for _, phase, _, _ in app.contexts['one'].observed[before:]],
                             ['prepare', 'public-select'])
            status, fields, body = get('/same', 'cmp_a=two', {'Accept': 'text/html'})
            self.assertEqual((status, cache(fields)), (200, 'HIT'))
            self.assertIn('two-A[', body)
            guest_calls = len(app.guest.calls)
            status, fields, body = get('/same', extra={'Accept': 'text/html'})
            self.assertEqual((status, cache(fields), body), (200, 'HIT', GUEST_BODY))
            self.assertEqual(dict(fields).get('X-UltraCache-Guest-Publication'), '1')
            self.assertEqual(len(app.guest.calls), guest_calls)
