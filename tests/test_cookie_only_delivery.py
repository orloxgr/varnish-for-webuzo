"""Native transport for observed-issuer publications; mock is not an issuer integration."""
import json
import shutil
import unittest
from test_cookie_delivery import proxy, cookies
from test_cms_cookie_choices import cache
from test_cold_public_selection import choices, Application
from test_delivery_continuation import PREPARE, MANIFEST
from test_public_selection_runtime import control


class ObservedIssuer:
    def __init__(self):
        self.calls = []
        self.change = None
    def __call__(self, path, headers):
        phase = headers.get('X-UltraCache-Delivery-Phase')
        self.calls.append((path, phase, dict(headers)))
        if phase == 'prepare':
            assert headers.get('X-UltraCache-Cookie-Delivery') == '1'
            assert headers.get('X-UltraCache-Delivery-Manifest') == MANIFEST
            result = dict(schemaVersion=1, requestId=headers['X-UltraCache-Delivery-Request'],
                originalUrl=headers['X-UltraCache-Delivery-Original-URL'],
                cookieDelivery=True, renderedFragments=[])
            if self.change:
                self.change(result)
            visitor = headers.get('X-Test-Visitor', 'guest')
            operation = headers.get('X-Test-Command', 'create')
            value = '' if operation == 'delete' else visitor+'-'+operation
            attrs = '; Domain=example.test; Path=/; Secure; HttpOnly; SameSite=Lax'
            if operation == 'delete':
                attrs += '; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0'
            return json.dumps(result), [('Content-Type', 'application/json'),
                ('Cache-Control', 'private, no-store'), ('X-UltraCache-Delivery-Outcome', 'verified'),
                ('Set-Cookie', 'provider_visit='+value+attrs),
                ('Set-Cookie', 'provider_visit='+value+'; Path=/shop; Secure; SameSite=None')]
        fields = [('Content-Type', 'text/html'), ('Cache-Control', 'public, max-age=120')]
        if path.startswith('/observed'):
            fields += [('X-UltraCache-Cookie-Delivery', '1'),
                ('X-UltraCache-ESI-Private-Count', '0'), ('X-UltraCache-Delivery-Prepare', PREPARE),
                ('Set-Cookie', 'provider_visit=seed-owner; Path=/; Secure')]
        return '<html>same public parent</html>', fields


@unittest.skipUnless(shutil.which('varnishd'), 'Native Varnish required')
class CookieOnlyDelivery(unittest.TestCase):
    def test_observed_parent_prepares_one_actual_owner_operation_per_warm_visit(self):
        app = ObservedIssuer()
        with proxy('ultracache', app, policies=choices(('provider_visit', 'shared'))) as get:
            first = get('/observed')
            self.assertEqual((first[0], cache(first[1])), (200, 'MISS'))
            self.assertEqual(cookies(first[1]), ['provider_visit=seed-owner; Path=/; Secure'])
            for visitor, command in [('A', 'create'), ('B', 'create'), ('A', 'renew'), ('A', 'delete')]:
                status, fields, body = get('/observed', extra={'X-Test-Visitor': visitor, 'X-Test-Command': command})
                self.assertEqual((status, cache(fields), body), (200, 'HIT', first[2]))
                self.assertEqual(dict(fields).get('X-UltraCache-Delivery-Outcome'), 'verified')
                actual = cookies(fields)
                self.assertEqual(len(actual), 2)
                self.assertTrue(all('seed-owner' not in field for field in actual))
                expected = '' if command=='delete' else visitor+'-'+command
                self.assertTrue(all(field.startswith('provider_visit='+expected+';') for field in actual))
                self.assertIn('Secure; HttpOnly; SameSite=Lax', actual[0])
                if command=='delete':
                    self.assertIn('Max-Age=0', actual[0])
                self.assertIn('no-store', dict(fields)['Cache-Control'])
                self.assertEqual(dict(fields).get('X-UltraCache-Cookie-Delivery'), '1')
            self.assertEqual([phase for _, phase, _ in app.calls], [None]+['prepare']*4)
            self.assertTrue(all(path=='/observed' for path, _, _ in app.calls))

    def test_cold_selected_publication_carries_marker_into_its_next_cookie_only_hit(self):
        public=Application();issuer=ObservedIssuer()
        def origin(path,headers):
            if headers.get('X-UltraCache-Delivery-Phase')=='prepare':
                return issuer(path,headers)
            raw,fields=public(path,headers)
            output=json.loads(raw);selected=output['selectedPublic']
            selected['cookieDelivery']=True;selected['manifest']=MANIFEST
            selected['headers']=[line for line in selected['headers'] if not line.startswith('X-UltraCache-Delivery-Prepare:')]
            selected['headers'] += ['X-UltraCache-Cookie-Delivery: 1','X-UltraCache-Delivery-Prepare: '+PREPARE]
            return json.dumps(output),fields+[('Set-Cookie','provider_visit=cold-owner; Path=/; Secure')]
        with proxy('ultracache',origin,policies=choices(('provider_visit','shared'))) as get:
            self.assertEqual(control(get,enabled=True,names='')[0],200)
            first=get('/observed-selected')
            self.assertEqual((first[0],cache(first[1])),(200,'MISS'))
            self.assertEqual(dict(first[1]).get('X-UltraCache-Delivery-Outcome'),'verified')
            self.assertEqual(cookies(first[1]),['provider_visit=cold-owner; Path=/; Secure'])
            second=get('/observed-selected',extra={'X-Test-Visitor':'B'})
            self.assertEqual((second[0],cache(second[1]),second[2]),(200,'HIT',first[2]))
            self.assertEqual(dict(second[1]).get('X-UltraCache-Delivery-Outcome'),'verified')
            self.assertTrue(all('B-create' in field for field in cookies(second[1])))
            self.assertEqual(len(public.calls),1);self.assertEqual(len(issuer.calls),1)

    def test_unmarked_plain_hit_needs_no_backend_and_client_cannot_create_marker(self):
        app = ObservedIssuer()
        with proxy('ultracache', app) as get:
            self.assertEqual(cache(get('/clean', extra={'X-UltraCache-Cookie-Delivery':'1'})[1]), 'MISS')
            self.assertNotIn('X-UltraCache-Cookie-Delivery', app.calls[-1][2])
            get.stop_origin()
            self.assertEqual(cache(get('/clean')[1]), 'HIT')
            self.assertEqual(len(app.calls), 1)

    def test_empty_envelope_requires_both_marker_and_bound_boolean(self):
        for mutate in (lambda d: d.pop('cookieDelivery'),
                       lambda d: d.update(cookieDelivery=False),
                       lambda d: d.update(cookieDelivery='true'),
                       lambda d: d.update(renderedFragments=[dict(url='/private', html='bad', occurrences=1)])):
            app = ObservedIssuer(); app.change = mutate
            with self.subTest(mutate=mutate), proxy('ultracache', app, policies=choices(('provider_visit','shared'))) as get:
                self.assertEqual(cache(get('/observed-invalid')[1]), 'MISS')
                status, fields, _ = get('/observed-invalid')
                self.assertEqual(status, 503)
                self.assertNotEqual(dict(fields).get('X-UltraCache-Delivery-Outcome'), 'verified')

    def test_basic_never_enters_cookie_only_prepare_and_capabilities_are_separate(self):
        for profile in ('basic', 'ultracache'):
            app = ObservedIssuer()
            with self.subTest(profile=profile), proxy(profile, app, policies=choices(('provider_visit','shared'))) as get:
                status, fields, _ = control(get)
                self.assertEqual(status, 200)
                self.assertEqual(fields.get('X-UltraCache-VCL-Cookie-Delivery-Version'), '1' if profile=='ultracache' else None)
                if profile=='basic':
                    for _ in range(2):
                        self.assertEqual(get('/observed-basic')[0], 200)
                    self.assertTrue(all(phase is None for _, phase, _ in app.calls))
                else:
                    get('/clean-hint')
                    self.assertEqual(app.calls[-1][2].get('X-UltraCache-VCL-Cookie-Delivery-Version'), '1')


if __name__ == '__main__':
    unittest.main()
