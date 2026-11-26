"""Paired native Warm transport with a declared mock producer, not WP proof."""
import base64
import hashlib
import json
import shutil
import unittest

from test_cookie_delivery import proxy, cookies
from test_cold_public_selection import Application, choices
from test_cms_cookie_choices import cache
from test_delivery_continuation import BODY
from test_guest_projected_variant import ProjectedGuests
from test_guest_publication import GUEST_POLICY
from test_guest_warm_projection import proof, PROJECTION, DELIVERY
from test_projected_variant_lookup import NAMES
from test_public_selection_runtime import control

GUEST_FILL = 'X-UltraCache-Warm-Guest'


class PairedProducer(ProjectedGuests):
    def __init__(self, *, wrong_source=False):
        super().__init__()
        self.base = Application(private=True)
        self.wrong_source = wrong_source

    def __call__(self, path, headers):
        value, fields = super().__call__(path, headers)
        role = headers.get('X-UltraCache-Delivery-Public-Source-Role')
        if role == 'parent-v1':
            envelope = json.loads(value)
            selected = envelope['selectedPublic']
            raw = BODY.replace('</html>', '<span>'+self.tuple_key(selected['resolvedPublic'])+'</span></html>')
            selected['publicParent'].update(bodyBase64=base64.b64encode(raw.encode()).decode(),
                generation=hashlib.sha256(raw.encode()).hexdigest(), freshRemaining=90)
            selected['manifest'] = 'paired.'+hashlib.sha256(raw.encode()).hexdigest()
            selected['headers'] = [line for line in selected['headers']
                if not line.startswith('X-UltraCache-Delivery-Prepare:')]
            selected['headers'].append('X-UltraCache-Delivery-Prepare: /index.php?ultracache_delivery='+selected['manifest'])
            self.sources[self.tuple_key(selected['resolvedPublic'])] = selected
            value = json.dumps(envelope)
        elif headers.get('X-UltraCache-Delivery-Guest-Publication-Version') == '1':
            envelope = json.loads(value)
            envelope['guestPublic']['publicParent']['freshRemaining'] = 30
            if self.wrong_source:
                envelope['guestPublic']['sourceGeneration'] = '0'*64
            value = json.dumps(envelope)
        elif role is None and headers.get('X-UltraCache-Delivery-Phase') == 'public-select':
            envelope = json.loads(value)
            selected = envelope['selectedPublic']
            source = self.sources[self.tuple_key(selected['resolvedPublic'])]
            # This real personal rendering uses the same selected public
            # publication and its own newly rendered fragments/cookie updates.
            for field in ('manifest', 'publicParent', 'headers'):
                selected[field] = source[field]
            value = json.dumps(envelope)
        return value, fields


@unittest.skipUnless(shutil.which('varnishd'), 'Native Varnish required; skip is not acceptance')
class PairedWarm(unittest.TestCase):
    def test_public_opt_in_is_authenticated_and_legacy_parent_keeps_personal_delivery(self):
        app = PairedProducer()
        with proxy('ultracache', app, policies=self.policy()) as get:
            caps = self.declare(get)
            self.assertEqual(caps.get('X-UltraCache-VCL-Warm-Delivery-Version'), '1')
            for path, modified in (
                    ('/added', {**proof('/added', caps, public_only=False), DELIVERY:'public-parent-only'}),
                    ('/removed', {k:v for k,v in proof('/removed', caps).items() if k != DELIVERY}),
                    ('/changed', {**proof('/changed', caps), DELIVERY:'other'})):
                before = len(app.calls)
                self.assertEqual(get(path, 'cmplz_id=one', modified)[0], 403)
                self.assertEqual(len(app.calls), before)
            result = get('/legacy', 'cmplz_id=one', {
                **proof('/legacy', caps, public_only=False), 'X-Test-Visitor':'legacy'})
            self.assertEqual(result[0], 200)
            self.assertIn('private:legacy', result[2])
            self.assertNotIn(DELIVERY, dict(result[1]))
            self.assertNotIn(GUEST_FILL, dict(result[1]))
            self.assertEqual(dict(result[1]).get('X-UltraCache-Delivery-Outcome'), 'verified')
            self.assertEqual(len(app.guest_calls), 0)
            self.assertTrue(all(DELIVERY not in headers for _, headers in app.calls))

    def declare(self, get):
        status, caps, _ = control(get, enabled=True, names=','.join(NAMES), extra={
            'X-UltraCache-Public-Selection-Public-Source-Version': '1',
            'X-UltraCache-Public-Selection-Public-Source-Projection-Version': '1',
            'X-UltraCache-Public-Selection-Guest-Version': '1',
            'X-UltraCache-Public-Selection-Guest-Policy': GUEST_POLICY})
        self.assertEqual(status, 200)
        return caps

    def policy(self):
        return choices(*[(name, 'variant') for name in NAMES], ('actual_session', 'shared'))

    def test_cold_paired_fill_then_real_guest_and_parent_hits_without_origin(self):
        app = PairedProducer()
        with proxy('ultracache', app, policies=self.policy()) as get:
            caps = self.declare(get)
            for value in (None, 'one', 'two'):
                path = '/paired' if value else '/default'
                cookie = 'cmplz_id='+value if value else None
                before = len(app.calls)
                parent = get(path, cookie, proof(path, caps))
                self.assertEqual((parent[0], cache(parent[1])), (200, 'MISS'), parent)
                self.assertEqual(dict(parent[1]).get(DELIVERY), 'public-parent-only')
                self.assertEqual(dict(parent[1]).get(GUEST_FILL), 'populated')
                self.assertEqual(dict(parent[1]).get('X-UltraCache-Delivery-Outcome'), 'not-executed')
                self.assertEqual(cookies(parent[1]), [])
                self.assertIn('<esi:include', parent[2])
                source = next(reversed(app.sources.values()))
                self.assertEqual(hashlib.sha256(parent[2].encode()).hexdigest(), source['publicParent']['generation'])
                self.assertEqual([h.get('X-UltraCache-Delivery-Public-Source-Role') for _, h in app.calls[before:]],
                    ['resolver-v1', 'parent-v1', None])
                self.assertEqual(len(app.guest_calls), (1 if value is None else 2 if value=='one' else 3))
                filled = len(app.calls)
                for visitor in ('A', 'B'):
                    guest = get(path, cookie, {'X-Test-Visitor': visitor})
                    self.assertEqual((guest[0], cache(guest[1])), (200, 'HIT'))
                    self.assertEqual(dict(guest[1]).get('X-UltraCache-Guest-Publication'), '1')
                    self.assertIn('complete guest', guest[2])
                    self.assertNotIn('<esi:', guest[2])
                    self.assertNotIn(GUEST_FILL, dict(guest[1]))
                    self.assertEqual(cookies(guest[1]), [])
                again = get(path, cookie, proof(path, caps))
                self.assertEqual((again[0], cache(again[1]), again[2]), (200, 'HIT', parent[2]))
                self.assertNotIn(GUEST_FILL, dict(again[1]))
                self.assertEqual(len(app.calls), filled)
                # Each object's own application lifetime survives the two fills.
                self.assertGreater(int(dict(parent[1])['X-UltraCache-Surrogate-TTL']),
                    int(dict(guest[1])['X-UltraCache-Surrogate-TTL']))

    def test_normal_private_owners_and_exact_invalidation_keep_their_real_flow(self):
        app = PairedProducer()
        with proxy('ultracache', app, policies=self.policy()) as get:
            caps = self.declare(get)
            path = '/owners'; signed = proof(path, caps)
            self.assertEqual(get(path, 'cmplz_id=one', signed)[0], 200)
            before = len(app.calls)
            for owner in ('A', 'B'):
                result = get(path, 'cmplz_id=one; actual_session='+owner, {'X-Test-Visitor': owner})
                self.assertEqual((result[0], cache(result[1])), (200, 'HIT'))
                self.assertEqual(result[2].count('private:'+owner), 2)
                self.assertEqual(result[2].count('nonce:'+owner), 1)
                self.assertNotIn(PROJECTION, dict(result[1]))
                self.assertNotIn(GUEST_FILL, dict(result[1]))
                self.assertEqual(dict(result[1]).get('X-UltraCache-Delivery-Outcome'), 'verified')
            self.assertEqual(len(app.calls)-before, 2)
            self.assertEqual(control(get, operation='exact-purge', path=path)[0], 200)
            before = len(app.calls)
            fresh = get(path, 'cmplz_id=one', signed)
            self.assertEqual((fresh[0], cache(fresh[1])), (200, 'MISS'))
            self.assertEqual(dict(fresh[1]).get(GUEST_FILL), 'populated')
            self.assertEqual(len(app.calls)-before, 3)

    def test_bad_complete_source_binding_cannot_report_population_or_cache_guest(self):
        app = PairedProducer(wrong_source=True)
        with proxy('ultracache', app, policies=self.policy()) as get:
            caps = self.declare(get); path = '/wrong-source'
            result = get(path, 'cmplz_id=one', proof(path, caps))
            self.assertEqual(result[0], 503)
            self.assertNotIn(GUEST_FILL, dict(result[1]))
            app.wrong_source = False
            result = get(path, 'cmplz_id=one')
            self.assertEqual((result[0], cache(result[1])), (200, 'MISS'))
            self.assertEqual(dict(result[1]).get('X-UltraCache-Guest-Publication'), '1')


if __name__ == '__main__':
    unittest.main()
