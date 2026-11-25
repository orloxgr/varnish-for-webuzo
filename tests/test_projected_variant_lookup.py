"""Same existing projection codec at initial lookup and projected publication.

The application is an explicit native transport mock, not WordPress/Enterprise
acceptance. Bundled choices deliberately exercise the grouped classifier.
"""
import base64
import hashlib
import itertools
import json
import shutil
import unittest

from test_cookie_delivery import proxy, cookies
from test_cms_cookie_choices import cache
from test_cold_public_selection import Application
from test_public_selection_runtime import control

NAMES = ('cmplz_id', 'cmplz_saved_categories', 'cmplz_saved_services')


class ProjectedVariants:
    def __init__(self):
        self.base = Application()
        self.calls = []

    def resolve(self, raw):
        # Same first-value projection semantics as the existing native codec.
        values = {}
        for pair in (raw or '').split(';'):
            if '=' in pair:
                name, value = pair.lstrip(' \t').split('=', 1)
                if name in NAMES and name not in values:
                    values[name] = value
        encoded = [dict(name=name, valueBase64=base64.b64encode(values[name].encode()).decode()
                        if name in values else None) for name in NAMES]
        return dict(version=1, bucket='tuple-' + hashlib.sha256(json.dumps(encoded).encode()).hexdigest(),
                    locale='el_GR', language='el', cookieValues=encoded)

    def __call__(self, path, headers):
        self.calls.append((path, dict(headers)))
        role = headers.get('X-UltraCache-Delivery-Public-Source-Role')
        if role == 'resolver-v1':
            body = dict(schemaVersion=1, requestId=headers['X-UltraCache-Delivery-Request'],
                originalUrl=headers['X-UltraCache-Delivery-Original-URL'],
                resolvedPublic=self.resolve(headers.get('Cookie')))
            return json.dumps(body), [('Content-Type', 'application/vnd.ultracache.delivery+json'),
                ('Cache-Control', 'private, no-store'),
                ('X-UltraCache-Delivery-Public-Selection-Version', '1'),
                ('X-UltraCache-Delivery-Public-Source-Version', '1'),
                ('X-UltraCache-Delivery-Public-Source-Outcome', 'resolved')]
        raw, fields = self.base(path, headers)
        if headers.get('X-UltraCache-Delivery-Phase') != 'public-select':
            return raw, fields
        value = json.loads(raw)
        selected = value['selectedPublic']
        expected = json.loads(base64.b64decode(headers['X-UltraCache-Delivery-Public-Source-Projection']))
        selected['resolvedPublic'] = expected
        public = '<html>public ' + json.dumps(expected['cookieValues'], sort_keys=True) + '</html>'
        selected['publicParent']['bodyBase64'] = base64.b64encode(public.encode()).decode()
        selected['publicParent']['generation'] = hashlib.sha256(public.encode()).hexdigest()
        selected['manifest'] = 'tuple.' + hashlib.sha256((path + public).encode()).hexdigest()
        selected['headers'] = [line for line in selected['headers'] if not line.startswith('X-UltraCache-Delivery-Prepare:')]
        selected['headers'].append('X-UltraCache-Delivery-Prepare: /index.php?ultracache_delivery=' + selected['manifest'])
        if role == 'parent-v1':
            selected.pop('cookieUpdates'); selected.pop('renderedFragments')
            selected['publicSource'] = dict(version=1, role='parent-v1')
            fields = [(k, v) for k, v in fields if k != 'X-UltraCache-Delivery-Outcome']
            fields += [('X-UltraCache-Delivery-Public-Source-Version', '1'),
                       ('X-UltraCache-Delivery-Public-Source-Outcome', 'captured')]
        return json.dumps(value), fields


@unittest.skipUnless(shutil.which('varnishd'), 'Native Varnish required; skipped is not acceptance')
class ProjectedVariantLookup(unittest.TestCase):
    def declare(self, get):
        self.assertEqual(control(get, enabled=True, names='', extra={
            'X-UltraCache-Public-Selection-Public-Source-Version': '1',
            'X-UltraCache-Public-Selection-Public-Source-Projection-Version': '1'})[0], 200)

    def test_bundled_wire_permutations_reuse_the_same_projected_publication_without_origin(self):
        app = ProjectedVariants()
        pairs = ['cmplz_saved_services={}', 'cmplz_saved_categories=["functional"]', 'cmplz_id=first']
        with proxy('ultracache', app) as get:
            self.declare(get)
            expected = None
            for index, order in enumerate([pairs, pairs] + list(itertools.permutations(pairs))):
                raw = '; '.join(order)
                status, fields, body = get('/variant-order', raw)
                self.assertEqual((status, cache(fields)), (200, 'MISS' if index == 0 else 'HIT'))
                if expected is None:
                    expected = body
                    self.assertEqual([h.get('X-UltraCache-Delivery-Public-Source-Role') for _, h in app.calls],
                                     ['resolver-v1', 'parent-v1', None])
                    self.assertEqual(app.calls[0][1].get('Cookie'), raw)
                self.assertEqual(body, expected)
                self.assertEqual(len(app.calls), 3)
                self.assertEqual(cookies(fields), [])

    def test_issuer_resolved_publication_keeps_the_original_lookup_key(self):
        class IssuedVariant(ProjectedVariants):
            def resolve(self, raw):
                if 'cmplz_id=' not in (raw or ''):
                    raw = (raw or '') + '; cmplz_id=issuer-default'
                return super().resolve(raw)
        app = IssuedVariant()
        with proxy('ultracache', app) as get:
            self.declare(get)
            original = 'cmplz_saved_services={}; cmplz_saved_categories=["functional"]'
            first = get('/issuer-input', original)
            self.assertEqual((first[0], cache(first[1])), (200, 'MISS'))
            self.assertIn(base64.b64encode(b'issuer-default'), first[2])
            self.assertEqual(len(app.calls), 3)
            repeated = get('/issuer-input', original)
            self.assertEqual((repeated[0], cache(repeated[1]), repeated[2]), (200, 'HIT', first[2]))
            self.assertEqual(len(app.calls), 3)

    def test_changed_absent_and_empty_values_have_distinct_keys(self):
        app = ProjectedVariants()
        states = ['cmplz_saved_services={}', 'cmplz_saved_services={}; cmplz_id=',
                  'cmplz_saved_services={}; cmplz_id=A', 'cmplz_saved_services={}; cmplz_id=B']
        bodies = []
        with proxy('ultracache', app) as get:
            self.declare(get)
            for index, raw in enumerate(states):
                status, fields, body = get('/variant-states', raw)
                self.assertEqual((status, cache(fields)), (200, 'MISS'))
                bodies.append(body)
                self.assertEqual(len(app.calls), (index + 1) * 3)
            self.assertEqual(len(set(bodies)), len(states))
            before = len(app.calls)
            for raw, expected in zip(states, bodies):
                reordered = '; '.join(reversed(raw.split('; ')))
                status, fields, body = get('/variant-states', reordered)
                self.assertEqual((status, cache(fields), body), (200, 'HIT', expected))
            self.assertEqual(len(app.calls), before)

    def test_duplicate_first_value_semantics_and_raw_cookie_are_preserved(self):
        app = ProjectedVariants()
        with proxy('ultracache', app) as get:
            self.declare(get)
            raw = 'cmplz_saved_services={}; cmplz_id=A; cmplz_id=B'
            first = get('/variant-duplicates', raw)
            self.assertEqual((first[0], cache(first[1])), (200, 'MISS'))
            self.assertEqual(app.calls[0][1].get('Cookie'), raw)
            for raw in ('cmplz_id=A; cmplz_saved_services={}', 'cmplz_id=A; cmplz_id=C; cmplz_saved_services={}'):
                result = get('/variant-duplicates', raw)
                self.assertEqual((result[0], cache(result[1]), result[2]), (200, 'HIT', first[2]))
                self.assertEqual(len(app.calls), 3)
            changed = get('/variant-duplicates', 'cmplz_saved_services={}; cmplz_id=B; cmplz_id=A')
            self.assertEqual((changed[0], cache(changed[1])), (200, 'MISS'))
            self.assertNotEqual(changed[2], first[2])

    def test_active_6144_byte_variant_repeats_without_workspace_growth_or_origin(self):
        app = ProjectedVariants()
        pairs = ['cmplz_saved_services={}', 'cmplz_id=' + 'a' * 6144, 'cmplz_saved_categories=["functional"]']
        with proxy('ultracache', app) as get:
            self.declare(get)
            first = get('/large-variant', '; '.join(pairs))
            self.assertEqual((first[0], cache(first[1])), (200, 'MISS'))
            for order in (pairs, list(reversed(pairs)), pairs[1:] + pairs[:1]):
                result = get('/large-variant', '; '.join(order))
                self.assertEqual((result[0], cache(result[1]), result[2]), (200, 'HIT', first[2]))
                self.assertEqual(len(app.calls), 3)

    def test_basic_unregistered_and_nonprojected_paths_keep_their_original_lookup_keys(self):
        first = 'cmplz_saved_services={}; cmplz_id=A'
        second = 'cmplz_id=A; cmplz_saved_services={}'
        for profile, register in (('basic', False), ('ultracache', False), ('ultracache', True)):
            app = Application() if register else None
            calls = []
            def ordinary(path, headers):
                calls.append(headers.get('Cookie'))
                return '<html>ordinary</html>', [('Content-Type', 'text/html'), ('Cache-Control', 'public, max-age=120')]
            with self.subTest(profile=profile, register=register), proxy(profile, app or ordinary) as get:
                if register:
                    self.assertEqual(control(get, enabled=True, names='')[0], 200)
                self.assertEqual(cache(get('/unchanged-key', first)[1]), 'MISS')
                self.assertEqual(cache(get('/unchanged-key', second)[1]), 'MISS')
                self.assertEqual(cache(get('/unchanged-key', first)[1]), 'HIT')
                self.assertEqual(len(app.calls if register else calls), 2)


if __name__ == '__main__':
    unittest.main()
