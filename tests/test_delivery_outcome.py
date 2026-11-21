"""Final request-local fragment outcome, separate from the parent cache HIT."""
import json
import shutil
import unittest

from test_cookie_delivery import proxy
from test_cms_cookie_choices import cache
from test_delivery_continuation import BODY, META, PARENT, PRIVATE, envelope
from test_private_document import document
from test_prepare_diagnostics import MARKER, diagnostics
from test_public_selection_runtime import Resolver, control, rules

OUTCOME = 'X-UltraCache-Delivery-Outcome'
CAPABILITY = 'X-UltraCache-VCL-Delivery-Outcome-Version'


@unittest.skipUnless(shutil.which('varnishd') and shutil.which('varnishlog'), 'Native Varnish and VSL required')
class DeliveryOutcome(unittest.TestCase):
    def test_debug_off_healthy_and_degraded_are_request_owned_not_cached(self):
        outcome = 'verified'
        def origin(path, headers):
            self.assertIsNone(headers.get(OUTCOME), 'Client health cannot reach the producer')
            if headers.get('X-UltraCache-Delivery-Phase') == 'prepare':
                self.assertEqual(headers.get(CAPABILITY), '1')
                return envelope(headers, headers.get('Cookie', 'none')), [
                    ('Cache-Control', 'private, no-store'), (OUTCOME, outcome)]
            return (BODY, META+[(OUTCOME, 'verified')]) if path == PARENT else ('cold', [('Cache-Control', 'private, no-store')])
        with proxy('ultracache', origin) as get:
            status, fields, _ = get(PARENT, extra={OUTCOME: 'verified', CAPABILITY: '99'})
            self.assertEqual((status, cache(fields), dict(fields).get(OUTCOME)), (200, 'MISS', 'unverified'))
            for selected in ('verified', 'degraded', 'verified'):
                outcome = selected
                status, fields, body = get(PARENT, 'owner='+selected)
                self.assertEqual((status, cache(fields), dict(fields).get(OUTCOME)), (200, 'HIT', selected))
                self.assertIn('private:owner='+selected, body)
            self.assertEqual(diagnostics(get), [], 'Debug OFF must not gain an always-on log')

    def test_missing_invalid_duplicate_or_contradictory_outcome_is_unverified(self):
        fields = []
        def origin(path, headers):
            if headers.get('X-UltraCache-Delivery-Phase') == 'prepare':
                return envelope(headers, 'owner'), [('Cache-Control', 'private, no-store'), *fields]
            return (BODY, META) if path == PARENT else ('cold', [('Cache-Control', 'private, no-store')])
        with proxy('ultracache', origin) as get:
            get(PARENT)
            for value in ([], [(OUTCOME, '1')], [(OUTCOME, 'verified,degraded')],
                          [(OUTCOME, 'verified'), (OUTCOME, 'verified')],
                          [(OUTCOME, 'verified'), (MARKER, '1')]):
                fields[:] = value
                status, headers, _ = get(PARENT)
                self.assertEqual((status, dict(headers).get(OUTCOME)), (200, 'unverified'))

    def test_debug_marker_remains_a_separate_optional_log(self):
        def origin(path, headers):
            if headers.get('X-UltraCache-Delivery-Phase') == 'prepare':
                return envelope(headers, 'fallback'), [('Cache-Control', 'private, no-store'),
                    (OUTCOME, 'degraded'), (MARKER, '1')]
            return (BODY, META) if path == PARENT else ('cold', [('Cache-Control', 'private, no-store')])
        with proxy('ultracache', origin) as get:
            get(PARENT)
            status, fields, _ = get(PARENT)
            self.assertEqual((status, dict(fields).get(OUTCOME)), (200, 'degraded'))
            self.assertNotIn(MARKER, dict(fields))
            self.assertEqual(len(diagnostics(get)), 1)

    def test_failed_http_or_binding_cannot_report_a_verified_fragment_delivery(self):
        fault = 'http500'
        def origin(path, headers):
            if headers.get('X-UltraCache-Delivery-Phase') == 'prepare':
                fields = [('Cache-Control', 'private, no-store'), (OUTCOME, 'verified')]
                if fault.startswith('http'):
                    return int(fault[4:]), 'RAW FAILURE', fields
                if fault == 'json':
                    return '{broken', fields
                if fault == 'coverage':
                    return envelope(headers, 'missing', lambda value: value['renderedFragments'].pop()), fields
                return envelope(headers, 'wrong', lambda value: value.update(requestId='wrong-owner')), fields
            return (BODY, META) if path == PARENT else ('cold', [('Cache-Control', 'private, no-store')])
        with proxy('ultracache', origin) as get:
            get(PARENT)
            for selected in ('http409', 'http500', 'json', 'binding', 'coverage'):
                fault = selected
                status, fields, body = get(PARENT)
                self.assertEqual(status, 503)
                self.assertNotEqual(dict(fields).get(OUTCOME), 'verified')
                self.assertNotIn('RAW FAILURE', body)

    def test_private_document_outcome_is_owned_and_keeps_actual_http_status(self):
        def origin(path, headers):
            if headers.get('X-UltraCache-Delivery-Phase') == 'prepare':
                return json.dumps(document(headers, '<html>private fallback</html>', 409)), [
                    ('Content-Type', 'application/vnd.ultracache.delivery+json'),
                    ('Cache-Control', 'private, no-store'), (OUTCOME, 'degraded')]
            return (BODY, META) if path == PARENT else ('cold', [('Cache-Control', 'private, no-store')])
        with proxy('ultracache', origin) as get:
            get(PARENT)
            status, fields, body = get(PARENT)
            self.assertEqual((status, dict(fields).get(OUTCOME), body),
                             (409, 'degraded', '<html>private fallback</html>'))

    def test_complete_public_selection_and_real_capability_use_the_same_outcome(self):
        resolver = Resolver(esi=True)
        def origin(path, headers):
            self.assertEqual(headers.get(CAPABILITY), '1')
            body, fields = resolver(path, headers)
            return body, [*fields, (OUTCOME, 'verified')]
        with proxy('ultracache', origin, policies=rules()) as get:
            status, fields, _ = control(get, enabled=True)
            self.assertEqual((status, fields.get(CAPABILITY)), (200, '1'))
            status, fields, body = get('/book', extra={'X-Test-Visitor': 'A'})
            self.assertEqual((status, dict(fields).get(OUTCOME)), (200, 'verified'))
            self.assertIn('owner:A', body)
            resolver.change = lambda value, headers: value['selectedPublic']['renderedFragments'].clear()
            status, fields, _ = get('/book', extra={'X-Test-Visitor': 'missing'})
            self.assertEqual(status, 503)
            self.assertNotEqual(dict(fields).get(OUTCOME), 'verified')

    def test_basic_and_ordinary_late_esi_cannot_claim_verified_from_origin_or_client(self):
        def origin(path, headers):
            self.assertIsNone(headers.get(OUTCOME))
            if path == '/late':
                body = '<html><esi:include src="'+PRIVATE.replace('&', '&amp;')+'"/></html>'
                return body, [(name, value) for name, value in META if name != 'X-UltraCache-Delivery-Prepare']+[(OUTCOME, 'verified')]
            return 'plain public', [('Cache-Control', 'public, max-age=120'), (OUTCOME, 'verified')]
        for profile in ('basic', 'ultracache'):
            with self.subTest(profile=profile), proxy(profile, origin) as get:
                for wanted in ('MISS', 'HIT'):
                    status, fields, _ = get('/plain', extra={OUTCOME: 'verified'})
                    self.assertEqual((status, cache(fields)), (200, wanted))
                    self.assertEqual(dict(fields).get(OUTCOME), None if profile == 'basic' else 'unverified')
                for wanted in ('MISS', 'HIT'):
                    status, fields, _ = get('/late', extra={OUTCOME: 'verified'})
                    self.assertEqual((status, cache(fields)), (200, wanted))
                    self.assertEqual(dict(fields).get(OUTCOME), None if profile == 'basic' else 'unverified')


if __name__ == '__main__':
    unittest.main()
