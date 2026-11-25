"""One native Variant guest flow with a typed mock producer, not WP proof."""
import base64
import hashlib
import json
import shutil
import subprocess
import unittest

from test_cookie_delivery import proxy
from test_cold_public_selection import choices
from test_cms_cookie_choices import cache
from test_guest_publication import GUEST_POLICY
from test_guest_shared_inputs import declaration
from test_projected_variant_lookup import NAMES, ProjectedVariants
from test_public_selection_runtime import control


class ProjectedGuests(ProjectedVariants):
    def __init__(self):
        super().__init__()
        self.sources = {}
        self.guest_calls = []

    @staticmethod
    def tuple_key(value):
        return json.dumps(value, sort_keys=True)

    def __call__(self, path, headers):
        role = headers.get('X-UltraCache-Delivery-Public-Source-Role')
        if role is None and 'actual_session=actual' in headers.get('Cookie', ''):
            self.calls.append((path, dict(headers)))
            private = ('private:' + headers.get('X-Test-Visitor', '')).encode()
            value = dict(schemaVersion=1, requestId=headers['X-UltraCache-Delivery-Request'],
                originalUrl=headers['X-UltraCache-Delivery-Original-URL'], privateDocument=dict(
                    status=200, contentType='text/html', bodyBase64=base64.b64encode(private).decode()))
            return json.dumps(value), [('Content-Type', 'application/vnd.ultracache.delivery+json'),
                ('Cache-Control', 'private, no-store'), ('X-UltraCache-Delivery-Public-Selection-Version', '1')]
        if headers.get('X-UltraCache-Delivery-Guest-Publication-Version') == '1':
            assert role is None
            self.calls.append((path, dict(headers)))
            self.guest_calls.append(dict(headers))
            expected = json.loads(base64.b64decode(headers['X-UltraCache-Delivery-Public-Source-Projection']))
            source = self.sources[self.tuple_key(expected)]
            body = '<html>complete guest ' + self.tuple_key(expected) + '</html>'
            value = dict(schemaVersion=1, requestId=headers['X-UltraCache-Delivery-Request'],
                originalUrl=headers['X-UltraCache-Delivery-Original-URL'], guestPublic=dict(
                    policyDigest=headers['X-UltraCache-Delivery-Policy'],
                    wordpressPolicyDigest=headers['X-UltraCache-Delivery-WordPress-Policy'],
                    guestPolicyDigest=GUEST_POLICY,
                    registryEpoch=headers['X-UltraCache-VCL-Public-Selection-Epoch'], scope='/',
                    manifest='guest.' + hashlib.sha256(body.encode()).hexdigest(),
                    sourceManifest=source['manifest'], sourceGeneration=source['publicParent']['generation'],
                    resolvedPublic=expected, resolvedOccurrences=3,
                    publicParent=dict(bodyBase64=base64.b64encode(body.encode()).decode(),
                        generation=hashlib.sha256(body.encode()).hexdigest(), freshRemaining=120),
                    headers=['Content-Type: text/html; charset=UTF-8', 'Vary: Cookie'],
                    cookieDelivery='none', guestInputs=declaration()))
            if headers.get('Cookie') is None:
                value['guestPublic'].pop('guestInputs')  # remains optional for literal no-Cookie
            return json.dumps(value), [('Content-Type', 'application/vnd.ultracache.delivery+json'),
                ('Cache-Control', 'private, no-store'),
                ('X-UltraCache-Delivery-Public-Selection-Version', '1'),
                ('X-UltraCache-Delivery-Guest-Publication-Version', '1')]
        result = super().__call__(path, headers)
        if role == 'parent-v1':
            source = json.loads(result[0])['selectedPublic']
            self.sources[self.tuple_key(source['resolvedPublic'])] = source
        return result


@unittest.skipUnless(shutil.which('varnishd'), 'Native Varnish required; skip is not acceptance')
class GuestProjectedVariant(unittest.TestCase):
    def test_variant_fill_two_fresh_visitors_and_original_private_input_fallback(self):
        app = ProjectedGuests()
        policy = choices(*[(name, 'variant') for name in NAMES], ('metric', 'shared'), ('actual_session', 'shared'))
        with proxy('ultracache', app, policies=policy) as get:
            self.assertEqual(control(get, enabled=True, names=','.join(NAMES), extra={
                'X-UltraCache-Public-Selection-Public-Source-Version': '1',
                'X-UltraCache-Public-Selection-Public-Source-Projection-Version': '1',
                'X-UltraCache-Public-Selection-Guest-Version': '1',
                'X-UltraCache-Public-Selection-Guest-Policy': GUEST_POLICY})[0], 200)
            status, fields, literal = get('/literal')
            self.assertEqual(status, 200)
            self.assertEqual(dict(fields).get('X-UltraCache-Guest-Publication'), '1')
            bodies = {}
            for value in ('one', 'two'):
                raw = 'cmplz_id=' + value + '; metric=warm'
                before = len(app.calls)
                status, fields, body = get('/variant', raw)
                if status != 200:
                    self.fail(str(app.calls) + subprocess.check_output(['varnishlog', '-n', str(get.instance),
                        '-d', '-g', 'request'], text=True)[-20000:])
                self.assertEqual((status, cache(fields)), (200, 'MISS'), (status, fields, body))
                self.assertEqual(dict(fields).get('X-UltraCache-Guest-Publication'), '1')
                self.assertEqual(len(app.calls) - before, 3)
                self.assertEqual(app.guest_calls[-1].get('Cookie'), 'cmplz_id=' + value)
                self.assertEqual(app.calls[before][1].get('Cookie'), raw)
                bodies[value] = body
            self.assertNotEqual(bodies['one'], bodies['two'])

            # A real provider input differs even when saved as Shared. Cold
            # guest fill must resume this same visitor, without publishing it.
            raw = 'cmplz_id=one; actual_session=actual; metric=original'
            before = len(app.calls)
            status, fields, body = get('/cold-private', raw, {'X-Test-Visitor': 'actual-owner'})
            self.assertEqual(status, 200, (fields, body))
            self.assertNotIn('X-UltraCache-Guest-Publication', dict(fields))
            self.assertIn('private:actual-owner', body)
            # The existing resolver retains non-public inputs and appends its
            # measured public Variant values; it does not substitute an owner.
            self.assertEqual(app.calls[-1][1].get('Cookie'),
                'actual_session=actual; metric=original; cmplz_id=one')
            self.assertEqual(len(app.calls) - before, 4)

            app_calls = len(app.calls)
            get.stop_origin()
            self.assertEqual(get('/literal')[2], literal)
            for visitor in ('fresh-A', 'fresh-B'):
                for value in ('one', 'two'):
                    marker = visitor + '-' + value
                    status, fields, body = get('/variant', 'cmplz_id=' + value + '; metric=' + visitor,
                        {'X-Test-Visitor': marker})
                    self.assertEqual((status, cache(fields), body), (200, 'HIT', bodies[value]))
                    log = subprocess.check_output(['varnishlog', '-n', str(get.instance), '-d', '-g', 'request',
                        '-q', 'ReqHeader:X-Test-Visitor eq "' + marker + '"', '-i', 'Begin,Link,ReqURL'], text=True)
                    self.assertNotIn('bereq', log)
            self.assertEqual(len(app.calls), app_calls)


if __name__ == '__main__':
    unittest.main()
