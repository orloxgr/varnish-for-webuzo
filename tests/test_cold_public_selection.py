"""Registered application cold handoff without a compulsory provider on plain HIT."""
import base64
import hashlib
import json
import shutil
import unittest
from urllib.parse import quote

from test_cookie_delivery import proxy, cookies
from test_cms_cookie_choices import cache
from test_delivery_continuation import BODY, envelope
from test_public_selection_runtime import control, WP_POLICY


def choices(*rows):
    return dict(schemaVersion=2, rules=[dict(id='custom:'+name, match=dict(kind='exact', value=name),
        description='Fixture choice', actions=dict(basic=action, ultracache=action)) for name, action in rows])


class Application:
    """Declared mock application, not actual WordPress or a fabricated issuer."""
    def __init__(self, private=False):
        self.private = private
        self.calls = []
        self.invalid = False
        self.updates = []

    def __call__(self, path, headers):
        phase = headers.get('X-UltraCache-Delivery-Phase')
        self.calls.append((path, phase, headers.get('Cookie')))
        visitor = headers.get('X-Test-Visitor', 'guest')
        if phase == 'prepare':
            return envelope(headers, visitor), [('Cache-Control', 'private, no-store'),
                ('X-UltraCache-Delivery-Outcome', 'verified')]
        if phase != 'public-select':
            return 'ordinary private composition', [('Cache-Control', 'private, no-store')]
        incoming = dict(pair.strip().split('=', 1) for pair in headers.get('Cookie', '').split(';') if '=' in pair)
        variant = {name: value for name, value in incoming.items() if name.startswith('cmp_')}
        body = BODY if self.private else '<html>public '+json.dumps(variant, sort_keys=True)+'</html>'
        manifest = 'mock.'+hashlib.sha256((path+'|'+body).encode()).hexdigest()
        count = 3 if self.private else 0
        fields = ['Content-Type: text/html; charset=UTF-8', 'Vary: Cookie',
            'X-UltraCache-Cookie-Settings: '+WP_POLICY,
            'X-UltraCache-Delivery-Prepare: /index.php?ultracache_delivery='+quote(manifest, safe=''),
            'X-UltraCache-ESI-Private-Count: '+str(count)]
        if self.private:
            fields += ['Surrogate-Control: ESI/1.0', 'X-UltraCache-ESI-Shared-Parent: 1']
        fragments = json.loads(envelope(headers, visitor))['renderedFragments'] if self.private else []
        selected = dict(policyDigest=headers['X-UltraCache-Delivery-Policy'],
            wordpressPolicyDigest=headers['X-UltraCache-Delivery-WordPress-Policy'],
            cookieUpdates=self.updates, manifest=manifest, occurrences=count,
            publicParent=dict(generation=hashlib.sha256(body.encode()).hexdigest(),
                bodyBase64=base64.b64encode(body.encode()).decode(), freshRemaining=120),
            headers=fields, renderedFragments=fragments)
        if self.invalid:
            selected['occurrences'] = count+1
        result = dict(schemaVersion=1, requestId=headers['X-UltraCache-Delivery-Request'],
            originalUrl=headers['X-UltraCache-Delivery-Original-URL'], selectedPublic=selected)
        return json.dumps(result), [('Content-Type', 'application/vnd.ultracache.delivery+json'),
            ('Cache-Control', 'private, no-store'), ('Surrogate-Control', 'no-store'),
            ('X-UltraCache-Delivery-Public-Selection-Version', '1'), ('X-UltraCache-Delivery-Outcome', 'verified')]


@unittest.skipUnless(shutil.which('varnishd'), 'Native Varnish required')
class ColdPublicSelection(unittest.TestCase):
    def test_empty_cookie_registration_prepares_cold_then_plain_hit_needs_no_origin(self):
        app = Application()
        with proxy('ultracache', app) as get:
            self.assertEqual(control(get, enabled=True, names='')[0], 200)
            status, fields, body = get('/plain')
            self.assertEqual((status, cache(fields), body), (200, 'MISS', '<html>public {}</html>'))
            self.assertEqual(dict(fields).get('X-UltraCache-Delivery-Outcome'), 'verified')
            self.assertEqual([phase for _, phase, _ in app.calls], ['public-select'])
            get.stop_origin()
            status, fields, repeated = get('/plain')
            self.assertEqual((status, cache(fields), repeated), (200, 'HIT', body))
            self.assertEqual(len(app.calls), 1)

    def test_shared_only_registration_preserves_one_public_object_across_values(self):
        app = Application()
        with proxy('ultracache', app, policies=choices(('shared_metric', 'shared'))) as get:
            self.assertEqual(control(get, enabled=True, names='shared_metric')[0], 200)
            first = get('/shared', 'shared_metric=first')
            self.assertEqual((first[0], cache(first[1]), first[2]), (200, 'MISS', '<html>public {}</html>'))
            get.stop_origin()
            second = get('/shared', 'shared_metric=second')
            self.assertEqual((second[0], cache(second[1]), second[2]), (200, 'HIT', first[2]))
            self.assertEqual(len(app.calls), 1)

    def test_cold_cmp_variants_without_resolver_names_use_the_original_lookup_key(self):
        app = Application()
        policy = choices(('cmp_a', 'variant'), ('cmp_longer_name', 'variant'))
        with proxy('ultracache', app, policies=policy) as get:
            self.assertEqual(control(get, enabled=True, names='')[0], 200)
            for raw, expected in [('cmp_a=one; cmp_longer_name=one', 'MISS'),
                                  ('cmp_longer_name=two; cmp_a=two', 'MISS'),
                                  ('cmp_longer_name=one; cmp_a=one', 'HIT')]:
                status, fields, body = get('/cmp', raw)
                self.assertEqual((status, cache(fields)), (200, expected))
                self.assertIn('"cmp_a": "'+('two' if 'two' in raw else 'one')+'"', body)
            self.assertEqual([phase for _, phase, _ in app.calls], ['public-select', 'public-select'])

    def test_cold_nonresolver_cannot_change_an_existing_variant_key(self):
        app = Application()
        with proxy('ultracache', app, policies=choices(('cmp_a', 'variant'))) as get:
            self.assertEqual(control(get, enabled=True, names='')[0], 200)
            app.updates = [dict(name='cmp_a', valueBase64=base64.b64encode(b'changed').decode())]
            status, fields, _ = get('/bound-variant', 'cmp_a=original')
            self.assertEqual(status, 503)
            self.assertNotEqual(dict(fields).get('X-UltraCache-Delivery-Outcome'), 'verified')
            app.updates = []
            status, fields, body = get('/bound-variant', 'cmp_a=original')
            self.assertEqual((status, cache(fields)), (200, 'MISS'))
            self.assertIn('"cmp_a": "original"', body)
            get.stop_origin()
            self.assertEqual(cache(get('/bound-variant', 'cmp_a=original')[1]), 'HIT')

    def test_private_parent_hits_keep_one_prepare_for_two_contexts_and_three_slots(self):
        app = Application(private=True)
        with proxy('ultracache', app, policies=choices(('shared_metric', 'shared'))) as get:
            self.assertEqual(control(get, enabled=True, names='')[0], 200)
            for visitor, expected in [('A', 'MISS'), ('B', 'HIT'), ('A', 'HIT')]:
                status, fields, body = get('/private-parent', 'shared_metric='+visitor, extra={'X-Test-Visitor': visitor})
                self.assertEqual((status, cache(fields)), (200, expected))
                self.assertEqual(dict(fields).get('X-UltraCache-Delivery-Outcome'), 'verified')
                self.assertEqual(body.count('private:'+visitor), 2)
                self.assertEqual(body.count('nonce:'+visitor), 1)
            self.assertEqual([phase for _, phase, _ in app.calls], ['public-select', 'prepare', 'prepare'])

    def test_private_cookie_actions_and_unregistered_or_basic_requests_do_not_start_cold_prepare(self):
        for profile, registered, cookie in [('basic', True, None), ('ultracache', False, None),
                                            ('ultracache', True, 'PHPSESSID=private')]:
            app = Application()
            with self.subTest(profile=profile, registered=registered), proxy(profile, app) as get:
                if registered:
                    self.assertEqual(control(get, enabled=True, names='')[0], 400 if profile=='basic' else 200)
                status, fields, body = get('/ordinary', cookie)
                self.assertEqual((status, cache(fields), body), (200, 'PASS', 'ordinary private composition'))
                self.assertEqual([phase for _, phase, _ in app.calls], [None])

    def test_incomplete_cold_coverage_is_rejected_and_a_later_request_can_recover(self):
        app = Application(private=True)
        with proxy('ultracache', app) as get:
            self.assertEqual(control(get, enabled=True, names='')[0], 200)
            app.invalid = True
            status, fields, _ = get('/incomplete')
            self.assertEqual(status, 503)
            self.assertNotEqual(dict(fields).get('X-UltraCache-Delivery-Outcome'), 'verified')
            app.invalid = False
            status, fields, body = get('/incomplete')
            self.assertEqual((status, cache(fields)), (200, 'MISS'))
            self.assertIn('private:guest', body)


if __name__ == '__main__':
    unittest.main()
