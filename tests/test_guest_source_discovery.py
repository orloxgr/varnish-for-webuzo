"""Causal native HSH actor with a trusted mock producer, not WordPress proof."""
import base64
import copy
import hashlib
import json
import os
import shutil
import subprocess
import unittest

from test_delivery_continuation import BODY, META, PARENT, PRIVATE, ADAPTIVE, envelope
from test_event_invalidation_runtime import NativeEventInvalidation, signed_context
from test_guest_publication import GUEST_POLICY
from test_guest_warm_projection import proof
from test_mutation_backend import receipt
from test_public_selection_runtime import control
from test_reuse_authority import REUSE_POLICY
from test_reuse_cookie_inputs import declaration, seal_recipe


class SourceWarm:
    def __init__(self, test, generation):
        self.test = test
        self.generation = generation
        self.bad_source = False
        self.other_representation = False
        self.inputs = True
        self.recipe = seal_recipe(dict(inputs=declaration(['owner']), fragments=[
            dict(url=PRIVATE, provider='personal', occurrences=2),
            dict(url=ADAPTIVE, provider='nonce', occurrences=1)]))

    def __call__(self, path, headers):
        role = headers.get('X-UltraCache-Delivery-Public-Source-Role')
        guest = headers.get('X-UltraCache-Delivery-Guest-Publication-Version') == '1'
        if role is None and not guest and ('owner=' in headers.get('Cookie', '') or
                headers.get('X-UltraCache-Delivery-Phase') != 'public-select'):
            return None
        public = BODY.replace('parent[', 'parent' + str(self.generation['number']) + '[')
        manifest = 'public-generation-' + str(self.generation['number'])
        generation = hashlib.sha256(public.encode()).hexdigest()
        projection = dict(version=1, bucket='ordinary-public-tuple', locale='el_GR', language='el', cookieValues=[])
        value = dict(schemaVersion=1, requestId=headers['X-UltraCache-Delivery-Request'],
                     originalUrl=headers['X-UltraCache-Delivery-Original-URL'])
        fields = [('Content-Type', 'application/vnd.ultracache.delivery+json'),
                  ('Cache-Control', 'private, no-store'),
                  ('X-UltraCache-Delivery-Public-Selection-Version', '1')]
        if role == 'resolver-v1':
            value['resolvedPublic'] = projection
            fields += [('X-UltraCache-Delivery-Public-Source-Version', '1'),
                       ('X-UltraCache-Delivery-Public-Source-Outcome', 'resolved')]
        elif guest:
            body = '<html>complete guest ' + str(self.generation['number']) + '</html>'
            selected = dict(policyDigest=headers['X-UltraCache-Delivery-Policy'],
                wordpressPolicyDigest=headers['X-UltraCache-Delivery-WordPress-Policy'],
                guestPolicyDigest=GUEST_POLICY, registryEpoch=headers['X-UltraCache-VCL-Public-Selection-Epoch'],
                scope='/', manifest='guest.' + hashlib.sha256(body.encode()).hexdigest(),
                sourceManifest=manifest, sourceGeneration='0'*64 if self.bad_source else generation,
                resolvedPublic=projection, resolvedOccurrences=3,
                publicParent=dict(bodyBase64=base64.b64encode(body.encode()).decode(),
                    generation=hashlib.sha256(body.encode()).hexdigest(), freshRemaining=120),
                headers=['Content-Type: text/html'], cookieDelivery='none')
            if self.inputs:
                selected['guestInputs'] = dict(version=1, privateOccurrences=3, recipe=copy.deepcopy(self.recipe))
            value['guestPublic'] = selected
            fields.append(('X-UltraCache-Delivery-Guest-Publication-Version', '1'))
        else:
            source_headers = ['Content-Type: text/html'] + [name + ': ' + (
                '/index.php?ultracache_delivery=' + manifest if name == 'X-UltraCache-Delivery-Prepare' else content)
                for name, content in META]
            if self.other_representation: source_headers.append('Vary: X-Test-Representation')
            selected = dict(policyDigest=headers['X-UltraCache-Delivery-Policy'],
                wordpressPolicyDigest=headers['X-UltraCache-Delivery-WordPress-Policy'],
                manifest=manifest, occurrences=3, resolvedPublic=projection,
                publicParent=dict(bodyBase64=base64.b64encode(public.encode()).decode(),
                    generation=generation, freshRemaining=120), headers=source_headers)
            if role == 'parent-v1':
                selected['publicSource'] = dict(version=1, role='parent-v1')
                fields += [('X-UltraCache-Delivery-Public-Source-Version', '1'),
                           ('X-UltraCache-Delivery-Public-Source-Outcome', 'captured')]
            else:
                selected['cookieUpdates'] = []
                selected['renderedFragments'] = json.loads(envelope(headers, 'guest'))['renderedFragments']
                fields.append(('X-UltraCache-Mutation-Receipt', receipt(signed_context(self.test, headers, 'GET', path), 'none', ())))
            value['selectedPublic'] = selected
        return json.dumps(value), fields


@unittest.skipUnless(shutil.which('varnishd') and os.environ.get('SCP_EXPERIMENTAL_REUSE_TEST') == '1',
                     'Matching-source native module required; skips are not acceptance')
class GuestSourceDiscovery(unittest.TestCase):
    def declare(self, get):
        status, caps, _ = control(get, enabled=True, names='', extra={
            'X-UltraCache-Public-Selection-Reuse-Version': '1',
            'X-UltraCache-Public-Selection-Reuse-Policy': REUSE_POLICY,
            'X-UltraCache-Public-Selection-Public-Source-Version': '1',
            'X-UltraCache-Public-Selection-Public-Source-Projection-Version': '1',
            'X-UltraCache-Public-Selection-Guest-Version': '1',
            'X-UltraCache-Public-Selection-Guest-Policy': GUEST_POLICY})
        self.assertEqual(status, 200)
        return caps

    def warm(self, get, caps, generation, source):
        generation['number'] += 1
        self.assertEqual(control(get, operation='exact-purge', path=PARENT)[0], 200)
        reply = get(PARENT)
        if not source.bad_source:
            self.assertEqual(reply[0], 200, reply)
            self.assertEqual(dict(reply[1]).get('X-UltraCache-Guest-Publication'), '1', reply)
        else:
            self.assertEqual(reply[0], 503, reply)
        # The normal authenticated parent Warm renders guest fragments, not a
        # fabricated retained owner. It cannot create a personal admission.
        warm = get(PARENT, extra=proof(PARENT, caps))
        self.assertEqual(warm[0], 200, warm)
        self.assertIn('parent' + str(generation['number']) + '[', warm[2])

    def test_complete_guest_recipe_recovers_existing_owner_on_first_postwarm_visit(self):
        generation = {'number': 1}; source = SourceWarm(self, generation)
        actor = NativeEventInvalidation()
        with actor.actor(generation, source_response=source) as (get, calls, versions, _, _, _, _):
            caps = self.declare(get)
            self.warm(get, caps, generation, source)
            calls.clear()
            status, headers, body = get(PARENT, 'owner=A', {'X-Test-Visitor': 'retained-after-warm'})
            log = subprocess.check_output(['varnishlog', '-n', str(get.instance), '-d', '-g', 'request',
                                          '-q', 'ReqHeader:X-Test-Visitor eq "retained-after-warm"',
                                          '-i', 'Debug'], text=True)
            self.assertEqual(status, 200)
            self.assertIn('parent2[', body); self.assertIn('private:A-v1', body)
            self.assertEqual(calls, [], 'Existing owner must be found on the FIRST post-Warm visit: ' + log)
            self.assertEqual(dict(headers).get('X-UltraCache-Private-Cache'), 'HIT')
            # A declaration alone must not admit a new actual owner.
            versions['C'] = 1; calls.clear()
            self.assertIn('private:C-v1', get(PARENT, 'owner=C')[2])
            self.assertEqual(calls, [(PARENT, 'prepare'), (PARENT, 'reuse-finalize')])

    def test_wrong_source_or_changed_native_representation_cannot_reuse_old_owner(self):
        for refusal in ('source', 'representation'):
            with self.subTest(refusal=refusal):
                generation = {'number': 1}; source = SourceWarm(self, generation)
                actor = NativeEventInvalidation()
                with actor.actor(generation, source_response=source) as (get, calls, _, _, _, _, _):
                    caps = self.declare(get)
                    source.bad_source = refusal == 'source'
                    source.other_representation = refusal == 'representation'
                    self.warm(get, caps, generation, source)
                    calls.clear()
                    self.assertIn('private:A-v1', get(PARENT, 'owner=A')[2])
                    self.assertEqual(calls, [(PARENT, 'prepare'), (PARENT, 'reuse-finalize')])


if __name__ == '__main__': unittest.main()
