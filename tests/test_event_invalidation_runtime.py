"""Actual native full-HIT/event invalidation; explicit mock signed producer.

No PHP/SQL drain, whole-application quiescence, or LiteSpeed Enterprise claim.
"""
import base64
import copy
from contextlib import contextmanager
import hashlib
import hmac
import json
import os
import shutil
import threading
import time
import unittest

from test_cookie_delivery import proxy
from test_delivery_continuation import BODY, META, PARENT, PRIVATE, ADAPTIVE, envelope
from test_mutation_backend import post, receipt, KEY
from test_public_selection_runtime import control
from test_mutation_wire import request_frame, FIELDS
from test_private_fragment_ttl import exchange
from test_reuse_authority import NativeReuseAuthority, TAG
from test_reuse_cookie_inputs import declaration, seal_recipe
from test_reuse_delivery_context import all_origin_hooks
from test_reuse_full_runtime import identity_mac


def signed_context(test, headers, method, path):
    value = json.loads(base64.b64decode(headers['X-UltraCache-Mutation-Context'], validate=True))
    test.assertEqual(set(value), {'schemaVersion', 'proof', *FIELDS[:-2]})
    test.assertEqual(value['schemaVersion'], 1)
    test.assertEqual(value['proof'], hmac.new(KEY, request_frame(dict(value, method=method, url=path)), hashlib.sha256).hexdigest())
    return value


@unittest.skipUnless(shutil.which('varnishd') and os.environ.get('SCP_EXPERIMENTAL_REUSE_TEST') == '1',
                     'Matching-source native module required')
class NativeEventInvalidation(unittest.TestCase):
    call = NativeReuseAuthority.call
    observe = NativeReuseAuthority.observe
    publish = NativeReuseAuthority.publish
    begin = NativeReuseAuthority.begin
    commit = NativeReuseAuthority.commit

    @contextmanager
    def actor(self, public_generation=None):
        public_generation = public_generation or {"number": 1}
        holder = {}; calls = []; prepared = {}; versions = {'A': 1, 'B': 1}
        entered = threading.Event(); release = threading.Event()
        recipe = seal_recipe(dict(inputs=declaration(['owner']), fragments=[
            dict(url=PRIVATE, provider='personal', occurrences=2),
            dict(url=ADAPTIVE, provider='nonce', occurrences=1)]))
        def owner_tag(owner):
            return TAG if owner == 'A' else hashlib.sha256(('other-event-owner:' + owner).encode()).hexdigest()
        def origin(path, headers):
            phase = headers.get('X-UltraCache-Delivery-Phase'); calls.append((path, phase))
            if path == '/__unrelated-server-error':
                entered.set(); self.assertTrue(release.wait(10))
                return 403, 'server directory response', [('Cache-Control', 'private, no-store')]
            if phase == 'public-select':
                signed = signed_context(self, headers, 'GET', path)
                owner = headers['Cookie'].split('owner=', 1)[1].split(';', 1)[0]
                generation = public_generation['number']
                parent = BODY.replace('parent[', 'parent' + str(generation) + '[')
                manifest = 'public-generation-' + str(generation)
                fields = [(name, '/index.php?ultracache_delivery=' + manifest)
                          if name == 'X-UltraCache-Delivery-Prepare' else (name, value) for name, value in META]
                fragments = json.loads(envelope(headers, owner + '-v' + str(versions[owner])))['renderedFragments']
                selected = dict(policyDigest=headers['X-UltraCache-Delivery-Policy'],
                    wordpressPolicyDigest=headers['X-UltraCache-Delivery-WordPress-Policy'],
                    cookieUpdates=[], manifest=manifest, occurrences=3,
                    publicParent=dict(generation=hashlib.sha256(parent.encode()).hexdigest(),
                        bodyBase64=base64.b64encode(parent.encode()).decode(), freshRemaining=120),
                    headers=['Content-Type: text/html'] + [name + ': ' + value for name, value in fields],
                    renderedFragments=fragments)
                body = dict(schemaVersion=1, requestId=headers['X-UltraCache-Delivery-Request'],
                    originalUrl=headers['X-UltraCache-Delivery-Original-URL'], selectedPublic=selected)
                return json.dumps(body), [('Content-Type', 'application/vnd.ultracache.delivery+json'),
                    ('Cache-Control', 'private, no-store'), ('Surrogate-Control', 'no-store'),
                    ('X-UltraCache-Delivery-Public-Selection-Version', '1'), ('X-UltraCache-Delivery-Outcome', 'verified'),
                    ('X-UltraCache-Mutation-Receipt', receipt(signed, 'none', ()))]
            if phase == 'prepare':
                signed = signed_context(self, headers, 'GET', path)
                context = self.call(holder['get'], 'delivery-reuse-context', tag=None, extra={
                    'X-UltraCache-Private-Request-Id': signed['requestId'],
                    'X-UltraCache-Private-Challenge': signed['challenge'],
                    'X-UltraCache-Private-Epoch': signed['epoch'],
                    'X-UltraCache-Private-Incarnation': signed['incarnation'],
                    'X-UltraCache-Delivery-Reuse-Recipe': recipe['digest']})
                owner = headers['Cookie'].split('owner=', 1)[1].split(';', 1)[0]
                body = json.loads(envelope(headers, owner + '-v' + str(versions[owner])))
                for fragment in body['renderedFragments']:
                    fragment['cache'] = dict(ttl=120, tags='owner:' + owner,
                        key=hashlib.sha256((fragment['url'] + owner + str(versions[owner])).encode()).hexdigest())
                body['reuseCandidate'] = dict(version=1, requestId=signed['requestId'], challenge=signed['challenge'],
                    recipe=recipe, inputEvidence=identity_mac(context, owner, recipe['inputs']))
                prepared[signed['requestId']] = (copy.deepcopy(body), owner)
                return json.dumps(body), [('Cache-Control', 'private, no-store'), ('X-UltraCache-Mutation-Receipt', receipt(signed, 'none', ()))]
            if phase == 'reuse-finalize':
                self.assertIsNone(headers.get('Cookie'))
                self.assertIsNone(headers.get('X-UltraCache-Mutation-Context'))
                context = json.loads(base64.b64decode(headers['X-UltraCache-Delivery-Reuse-Context'], validate=True))
                old, owner = prepared[context['requestId']]
                tag = owner_tag(owner)
                before = self.call(holder['get'], 'private-authority-context', tag=tag)
                published = self.call(holder['get'], 'private-generation-publish', before, tag=tag,
                    extra={'X-UltraCache-Private-Generation': hashlib.sha256(str(versions[owner]).encode()).hexdigest()})
                self.assertEqual(published['revision'], before['revision'], 'Fresh fill binds the actual event revision')
                page = dict(context['context'], scopeRevision=published['scopeRevision'])
                deadline = int(time.time()) + 90
                rows = []
                for descriptor in recipe['fragments']:
                    fragment = next(row for row in old['renderedFragments'] if row['url'] == descriptor['url'])
                    rows.append(dict(descriptor=descriptor['descriptor'], url=descriptor['url'], cache=fragment['cache'],
                        bodyValidUntil=deadline + 10, identity=dict(identityState='personal', identityInputs=declaration(['owner']),
                            identityBinding=identity_mac(page, owner), owner=tag, tags=[tag], validUntil=deadline + 20),
                        authority=[dict(tag=tag, revision=published['revision'], generation=published['generation'])]))
                record = dict(schemaVersion=1, requestId=context['deliveryRequestId'], originalUrl=path,
                    reuse=dict(version=1, context=page, recipe=recipe, admission=dict(binding=context['binding'],
                        validUntil=deadline, cookieWork=dict(state='none', validUntil=deadline + 20), fragments=rows)))
                return json.dumps(record), [('Content-Type', 'application/vnd.ultracache.reuse+json'),
                    ('Cache-Control', 'private, no-store'), ('X-UltraCache-Delivery-Reuse-Outcome', 'finalized'),
                    ('X-UltraCache-Delivery-Reuse-Fresh-Remaining', '89')]
            if path == PARENT:
                generation = public_generation['number']
                fields = [(name, '/index.php?ultracache_delivery=public-generation-' + str(generation))
                          if name == 'X-UltraCache-Delivery-Prepare' else (name, value) for name, value in META]
                return BODY.replace('parent[', 'parent' + str(generation) + '['), fields
            return 'unexpected source', [('Cache-Control', 'private, no-store')]
        with proxy('ultracache', origin, transform=all_origin_hooks, allow_post=True) as get:
            holder['get'] = get; get(PARENT); NativeReuseAuthority.register(self, get)
            bodies = {}
            try:
                for owner in versions:
                    calls.clear(); status, _, body = get(PARENT, 'owner=' + owner)
                    self.assertEqual(status, 200); self.assertIn('private:' + owner + '-v1', body)
                    self.assertEqual(calls, [(PARENT, 'prepare'), (PARENT, 'reuse-finalize')])
                    bodies[owner] = body; calls.clear()
                    self.assertEqual(get(PARENT, 'owner=' + owner)[2], body)
                    self.assertEqual(calls, [], 'A complete first fill must immediately become a zero-backend HIT')
                yield get, calls, versions, bodies, entered, release, owner_tag
            finally: release.set()

    def test_public_regeneration_reuses_private_owner_objects_after_recipe_discovery(self):
        generation = {'number': 1}
        with self.actor(generation) as (get, calls, versions, bodies, _, _, _):
            generation['number'] = 2
            self.assertEqual(control(get, operation='exact-purge', path=PARENT)[0], 200)
            # An existing public Warm learns the new authenticated declaration
            # through B. That must not revoke A's unchanged private fragments.
            # Resolve the new public source first, then complete the same Warm
            # through its cached parent and actual mock private producer.
            get(PARENT, 'owner=B')
            status, warm_headers, warm = get(PARENT, 'owner=B')
            self.assertEqual(status, 200)
            self.assertIn('parent2[', warm)
            self.assertIn('private:B-v1', warm, repr({'calls': calls, 'headers': warm_headers}))
            calls.clear()
            status, _, reused = get(PARENT, 'owner=A')
            self.assertEqual(status, 200)
            self.assertIn('parent2[', reused)
            self.assertIn('private:A-v1', reused)
            self.assertNotIn('private:B-', reused)
            self.assertEqual(calls, [], 'Public regeneration alone cannot require a private prepare')

    def test_ordinary_inflight_and_missing_receipt_do_not_gate_a_complete_hit(self):
        with self.actor() as (get, calls, _, bodies, entered, release, _):
            original = self.observe(get); results = []; errors = []
            def unrelated():
                try: results.append(post(get, '/__unrelated-server-error'))
                except BaseException as error: errors.append(error)
            worker = threading.Thread(target=unrelated); worker.start()
            try:
                self.assertTrue(entered.wait(10)); calls.clear()
                self.assertEqual(get(PARENT, 'owner=A')[2], bodies['A'])
                self.assertEqual(calls, [], 'An unrelated live request is not a private-cache approval dependency')
            finally: release.set(); worker.join(timeout=15)
            self.assertFalse(worker.is_alive()); self.assertEqual(errors, [])
            self.assertEqual((results[0][0], results[0][2]), (403, b'server directory response'))
            calls.clear(); self.assertEqual(get(PARENT, 'owner=A')[2], bodies['A']); self.assertEqual(calls, [])
            current = self.observe(get)
            self.assertEqual((current['scopeRevision'], current['revision'], current['scopeState']),
                             (original['scopeRevision'], original['revision'], 'ready'))
            self.assertNotIn('temporaryHolds', current)

    def test_real_owner_event_invalidates_only_its_dependency_and_refills_once(self):
        with self.actor() as (get, calls, versions, bodies, _, _, owner_tag):
            a = self.observe(get)
            b = self.call(get, 'private-authority-context', tag=owner_tag('B'))
            writer = self.begin(get, a, 'actual-owner-event')
            self.assertNotEqual(writer['revision'], a['revision'])
            self.assertEqual(writer['scopeRevision'], a['scopeRevision'])
            calls.clear(); self.assertEqual(get(PARENT, 'owner=B')[2], bodies['B']); self.assertEqual(calls, [])
            done = self.commit(get, writer)
            self.assertNotEqual(done['revision'], writer['revision'])
            self.call(get, 'private-mutation-ack', done, extra={
                'X-UltraCache-Private-Transaction': done['transaction'], 'X-UltraCache-Private-Lease': done['lease']})
            versions['A'] = 2; calls.clear()
            status, _, updated = get(PARENT, 'owner=A')
            self.assertEqual(status, 200); self.assertIn('private:A-v2', updated)
            self.assertEqual(calls, [(PARENT, 'prepare'), (PARENT, 'reuse-finalize')])
            calls.clear(); self.assertEqual(get(PARENT, 'owner=A')[2], updated); self.assertEqual(calls, [])
            self.assertEqual(get(PARENT, 'owner=B')[2], bodies['B']); self.assertEqual(calls, [])
            after = self.call(get, 'private-authority-context', tag=owner_tag('B'))
            self.assertEqual((after['revision'], after['generation']), (b['revision'], b['generation']))
            key = hashlib.sha256((PRIVATE + 'A2').encode()).hexdigest()
            self.assertEqual(exchange(get, 'PURGE', PRIVATE, key, 'b' * 64)[0], 200)
            calls.clear(); self.assertEqual(get(PARENT, 'owner=A')[2], updated)
            self.assertEqual(calls, [(PARENT, 'prepare'), (PARENT, 'reuse-finalize')],
                             'A genuinely missing private body still needs an actual fill')
            calls.clear(); self.assertEqual(get(PARENT, 'owner=A')[2], updated); self.assertEqual(calls, [])


if __name__ == '__main__': unittest.main()
