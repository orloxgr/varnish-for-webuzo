"""Actual native fragment admission with a signed MOCK application producer.

Zero producer calls on HIT is measured, not inferred from an outer cache label.
Actual WordPress provider/SQL semantics require the separate paired fixture.
"""
import base64
import contextlib
import hashlib
import hmac
import json
import os
import shutil
import subprocess
import time
import unittest
from urllib.parse import parse_qs, urlsplit

from test_cookie_delivery import proxy
import test_fragment_batch_runtime as batch_tests
from test_fragment_batch_wire import token
from test_reuse_cookie_inputs import declaration, descriptor_digest, lp
from test_reuse_delivery_context import all_origin_hooks
from test_mutation_backend import receipt, KEY as MUTATION_KEY
from test_mutation_wire import request_frame
from test_private_fragment_ttl import exchange
from test_public_selection_runtime import control

KEY = hmac.digest(('b'*64).encode(), b'ultracache-delivery-reuse-key-v1', 'sha256')
FIELDS = ('siteId', 'canonicalHost', 'scope', 'epoch', 'nativePolicy', 'wordpressPolicy', 'reusePolicy')


def binding(context, inputs, pairs):
    names, prefixes = sorted(inputs['cookieNames']), sorted(inputs['cookiePrefixes'])
    selected = sorted((name, value) for name, value in pairs.items()
        if name in names or any(name.startswith(prefix) for prefix in prefixes))
    frame = (lp('ultracache-cookie-inputs-v1')+inputs['phpMaxInputVars'].to_bytes(4, 'big')
        +len(names).to_bytes(4, 'big')+b''.join(lp(n) for n in names)
        +len(prefixes).to_bytes(4, 'big')+b''.join(lp(n) for n in prefixes)
        +len(selected).to_bytes(4, 'big')
        +b''.join(lp(name)+(1).to_bytes(4, 'big')+lp(name)+lp(value) for name, value in selected))
    return hmac.new(KEY, lp('ultracache-private-identity-binding-v1')
        +b''.join(lp(context[name]) for name in FIELDS)+lp(frame), 'sha256').hexdigest()


@unittest.skipUnless(shutil.which('varnishd') and os.environ.get('SCP_TEST_COOKIE_MODULE'),
                     'An explicitly supplied matching native module is required')
class NativeFragmentReuse(unittest.TestCase):
    register = batch_tests.NativeFragmentBatch.register
    call = batch_tests.NativeFragmentBatch.call
    observe = batch_tests.NativeFragmentBatch.observe
    ready = batch_tests.NativeFragmentBatch.ready
    begin = batch_tests.NativeFragmentBatch.begin
    commit = batch_tests.NativeFragmentBatch.commit
    batch = batch_tests.NativeFragmentBatch.batch

    @contextlib.contextmanager
    def actor(self, *, anonymous=False, lifetime=90, fail_metadata=False):
        value, wire, uri = self.batch()
        state = dict(calls=[], contexts={}, versions={}, receipts=True, mutation_contexts=[])
        inputs = declaration(['owner', 'viewed']) if not anonymous else declaration()
        identity_inputs = declaration(['owner']) if not anonymous else declaration()

        def origin(path, headers):
            self.assertEqual(headers.get('X-UltraCache-Delivery-Phase'), 'fragment-prepare')
            state['calls'].append(path)
            # Verify the existing actual signed execution header, not a new
            # client cookie claim or a test-injected admission bypass.
            self.assertTrue(headers.get('X-UltraCache-Mutation-Context'))
            execution = json.loads(base64.b64decode(headers['X-UltraCache-Mutation-Context']))
            self.assertEqual(execution['proof'], hmac.new(MUTATION_KEY,
                request_frame(dict(execution, method='GET', url=path)), 'sha256').hexdigest())
            state['mutation_contexts'].append(execution)
            query = parse_qs(urlsplit(path).query)
            if not path.startswith('/index.php?') or query['ultracache_fragment_delivery'] != [wire]:
                return 400, 'invalid-ticket', [('Cache-Control', 'private, no-store'),
                    ('X-UltraCache-Mutation-Receipt', receipt(execution, 'none', ()))]
            selected = [int(i) for i in query['ultracache_fragment_subset'][0].split(',')] if 'ultracache_fragment_subset' in query else list(range(len(value['fragments'])))
            pairs = dict(pair.strip().split('=', 1) for pair in headers.get('Cookie', '').split(';') if '=' in pair)
            owner = pairs.get('owner', '')
            tag = hashlib.sha256(('fragment-owner-'+owner).encode()).hexdigest()
            observed = self.call(get, 'private-authority-context', tag=tag)
            context = state['contexts'][owner] if observed.get('remainingMutations') else self.call(get, 'private-generation-publish', observed, tag=tag, extra={
                'X-UltraCache-Private-Generation': hashlib.sha256(str(state['versions'].get(owner, 1)).encode()).hexdigest()})
            state['contexts'][owner] = context
            page = dict(context, siteId=execution['siteId'], canonicalHost=execution['canonicalHost'])
            deadline = int(time.time())+lifetime
            facts = [] if anonymous else [dict(tag=tag, revision=context['contentRevision'], generation=context['generation'])]
            rendered, admitted = [], []
            for index in selected:
                item = value['fragments'][index]
                html = 'fragment:%s:%s:%s:v%s' % (index, owner, pairs.get('viewed', ''), state['versions'].get(owner, 1))
                cache = dict(key=hashlib.sha256(html.encode()).hexdigest(), ttl=lifetime,
                    tags='' if anonymous else tag)
                rendered.append(dict(item, html=html, cache=dict(cache, **({'identityState': 'anonymous'} if anonymous else {}))))
                admitted.append(dict(descriptor=descriptor_digest(item['url'], 'fixture-provider'), url=item['url'],
                    cache=cache, bodyValidUntil=deadline, inputs=inputs, inputBinding=binding(page, inputs, pairs),
                    identity=dict(identityState='anonymous' if anonymous else 'personal', identityInputs=identity_inputs,
                        identityBinding=binding(page, identity_inputs, pairs), owner=None if anonymous else tag,
                        tags=[] if anonymous else [tag], validUntil=deadline), authority=facts))
            authority = {name: context[name] for name in ('scope', 'epoch', 'incarnation', 'scopeRevision', 'nativePolicy', 'wordpressPolicy', 'reusePolicy')}
            authority['fragments'] = [dict(url=row['url'], authority=facts) for row in rendered]
            body = dict(schemaVersion=2, requestId=headers['X-UltraCache-Delivery-Request'], originalUrl=path,
                requestDigest=headers['X-UltraCache-Fragment-Delivery-Request-Digest'], renderedFragments=rendered,
                failedFragments=[], authority=authority)
            if state['receipts']:
                body['reuseAdmission'] = dict(version=1, cookieValidUntil=deadline, fragments=admitted)
            return json.dumps(body), [('Content-Type', 'application/vnd.ultracache.fragment-delivery+json; version=1'),
                ('X-UltraCache-Fragment-Delivery-Version', '1'), ('Cache-Control', 'private, no-store'),
                ('X-UltraCache-Mutation-Receipt', receipt(execution, 'none', ()))]

        def transform(source):
            source = all_origin_hooks(source)
            if fail_metadata:
                needle = 'call scp_backend_fetch;'
                self.assertEqual(source.count(needle), 1)
                source = source.replace(needle, 'if (bereq.url ~ "^/__ultracache-native/reuse-v1/") '
                    '{ return (error(503,"Owned metadata storage failure")); } '+needle, 1)
            return source

        with proxy('ultracache', origin, transform=transform, management=True, daemon_parameters=('vsl_mask=+Debug',)) as get:
            self.register(get, parent=False)
            try:
                yield get, state, value, wire, uri
            except Exception:
                try: print(get.adm('panic.show'))
                except AssertionError: pass
                trace = subprocess.run(['varnishlog', '-n', str(get.instance), '-d', '-g', 'request',
                    '-i', 'Debug,FetchError,Error,VCL_Error,VCL_Log,RespStatus,BerespStatus,ReqURL'],
                    capture_output=True, text=True, timeout=10)
                print(trace.stdout[-18000:])
                raise

    def result(self, get, uri, cookie='owner=A; viewed=one', reuse='MISS'):
        result = get(uri, cookie)
        self.assertEqual(result[0], 200, result)
        fields = dict(result[1])
        self.assertEqual(fields.get('X-UltraCache-Fragment-Reuse'), reuse, result)
        self.assertNotIn('Set-Cookie', fields, 'A reused object must not replay an issuer cookie')
        return json.loads(result[2])

    def test_private_owner_render_inputs_and_overlapping_subsets_need_no_producer_on_hit(self):
        with self.actor() as (get, state, value, wire, uri):
            a0 = self.result(get, uri+'&ultracache_fragment_subset=0')
            self.assertEqual(self.result(get, uri+'&ultracache_fragment_subset=0', reuse='HIT'), a0)
            self.assertEqual(len(state['calls']), 1)
            b0 = self.result(get, uri+'&ultracache_fragment_subset=0', 'owner=B; viewed=one')
            self.assertEqual(self.result(get, uri+'&ultracache_fragment_subset=0', 'owner=B; viewed=one', 'HIT'), b0)
            self.assertNotEqual(a0, b0)
            self.result(get, uri+'&ultracache_fragment_subset=1')
            both = self.result(get, uri, reuse='HIT')
            self.assertEqual(len(both['results']), 2)
            self.assertEqual(len(state['calls']), 3)
            self.result(get, uri, 'owner=A; viewed=two')
            self.result(get, uri, 'owner=A; viewed=two', 'HIT')
            self.result(get, uri, reuse='HIT')
            self.assertEqual(len(state['calls']), 4, 'Different render input must MISS; earlier exact input still HITs')

    def test_unauthenticated_full_ticket_and_missing_body_cannot_reuse_hot_admission(self):
        with self.actor() as (get, state, value, wire, uri):
            self.result(get, uri); self.result(get, uri, reuse='HIT')
            forged = wire[:-1]+('1' if wire[-1] != '1' else '2')
            self.assertEqual(get(uri.replace(wire, forged), 'owner=A; viewed=one')[0], 400)
            changed = dict(value, sourceUrl='/other-source/')
            self.assertEqual(get(uri.replace(wire, token(changed).decode()), 'owner=A; viewed=one')[0], 400)
            self.assertEqual(len(state['calls']), 3, 'Unknown complete ticket must reach real authentication')
            registered = control(get, enabled=False, names='', scope='/other/', wordpress_policy='b'*64, extra={
                'X-UltraCache-Public-Selection-Reuse-Version': '1', 'X-UltraCache-Public-Selection-Reuse-Policy': 'c'*64,
                'X-UltraCache-Fragment-Delivery-Version': '1', 'X-UltraCache-Fragment-Delivery-Route': '/other/index.php',
                'X-UltraCache-Fragment-Caching-Enabled': '1'})
            self.assertEqual(registered[0], 200)
            self.assertEqual(get(uri.replace('/index.php?', '/other/index.php?', 1), 'owner=A; viewed=one')[0], 400)
            self.assertEqual(len(state['calls']), 4, 'A second scope must authenticate its own full ticket')
            key = hashlib.sha256(b'fragment:0:A:one:v1').hexdigest()
            self.assertEqual(exchange(get, 'PURGE', value['fragments'][0]['url'], key, 'b'*64)[0], 200)
            self.result(get, uri); self.result(get, uri, reuse='HIT')
            self.assertEqual(len(state['calls']), 5, 'Retired body must refill through the producer')

    def test_writer_invalidates_hot_receipt_then_actual_fresh_generation_refills(self):
        with self.actor() as (get, state, value, wire, uri):
            self.result(get, uri); self.result(get, uri, reuse='HIT')
            old = state['contexts']['A']; tag = old['tag']
            transaction = hashlib.sha256(b'actual-fragment-write').hexdigest()
            begun = self.call(get, 'private-mutation-begin', old, tag=tag,
                extra={'X-UltraCache-Private-Transaction': transaction})
            conflicted = self.result(get, uri)
            self.assertTrue(all(row['status'] == 409 for row in conflicted['results']))
            self.call(get, 'private-mutation-commit', begun, tag=tag, extra={
                'X-UltraCache-Private-Transaction': transaction, 'X-UltraCache-Private-Lease': begun['lease']})
            state['versions']['A'] = 2
            fresh = self.result(get, uri)
            self.assertTrue(all(':v2' in row['html'] for row in fresh['results']))
            self.assertEqual(self.result(get, uri, reuse='HIT'), fresh)
            self.assertEqual(len(state['calls']), 3)

    def test_missing_admission_and_full_participation_teardown_do_not_reuse_old_receipt(self):
        with self.actor() as (get, state, value, wire, uri):
            state['receipts'] = False
            self.result(get, uri); self.result(get, uri)
            self.assertEqual(len(state['calls']), 2)
            state['receipts'] = True
            self.result(get, uri); self.result(get, uri, reuse='HIT')
            reply = control(get, enabled=False, names='', wordpress_policy='b'*64, extra={
                'X-UltraCache-Public-Selection-Reuse-Version': '1',
                'X-UltraCache-Public-Selection-Reuse-Enabled': '0',
                'X-UltraCache-Public-Selection-Reuse-Policy': 'c'*64})
            self.assertEqual(reply[0], 200)
            self.register(get, parent=False)
            self.result(get, uri); self.result(get, uri, reuse='HIT')
            self.assertEqual(len(state['calls']), 4)

    def test_anonymous_receipt_storage_switch_and_natural_deadline(self):
        with self.actor(anonymous=True, lifetime=3) as (get, state, value, wire, uri):
            first = self.result(get, uri, '')
            self.assertTrue(all(row['cacheScope'] == 'anonymous' for row in first['results']))
            self.result(get, uri, '', 'HIT')
            time.sleep(3.1)
            self.result(get, uri, '')
            self.assertEqual(len(state['calls']), 2)
            self.register(get, caching=False, parent=False)
            self.result(get, uri, ''); self.result(get, uri, '')
            self.assertEqual(len(state['calls']), 4)
            self.register(get, parent=False)
            self.result(get, uri, ''); self.result(get, uri, '', 'HIT')
            self.assertEqual(len(state['calls']), 5)

    def test_optional_metadata_failure_preserves_completed_original_fragments(self):
        with self.actor(fail_metadata=True) as (get, state, value, wire, uri):
            first = self.result(get, uri)
            self.assertEqual(len(first['results']), 2)
            self.assertTrue(all(row['status'] == 200 and 'fragment:' in row['html'] for row in first['results']))
            self.assertEqual(self.result(get, uri), first)
            self.assertEqual(len(state['calls']), 2, 'Failed metadata never manufactures admission or loses completed results')
