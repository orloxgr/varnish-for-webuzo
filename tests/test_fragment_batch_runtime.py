"""Disposable actual native batch transport with a trusted mock producer.

This tests normal hash/fetch storage; it is not actual WordPress identity proof.
"""
import hashlib
import json
import os
import shutil
import subprocess
import unittest

from test_cookie_delivery import proxy, cookies
from test_fragment_batch_wire import payload, token, PRIVATE, ADAPTIVE
from test_public_selection_runtime import control
from test_private_fragment_ttl import exchange
import test_reuse_authority as authority_tests


@unittest.skipUnless(shutil.which('varnishd') and os.environ.get('SCP_TEST_COOKIE_MODULE'),
                     'An explicitly supplied isolated matching native module is required')
class NativeFragmentBatch(unittest.TestCase):
    call = authority_tests.NativeReuseAuthority.call
    observe = authority_tests.NativeReuseAuthority.observe
    publish = authority_tests.NativeReuseAuthority.publish
    ready = authority_tests.NativeReuseAuthority.ready
    begin = authority_tests.NativeReuseAuthority.begin
    commit = authority_tests.NativeReuseAuthority.commit

    def register(self, get, caching=True, parent=True):
        result = control(get, enabled=parent, names='', wordpress_policy='b'*64, extra={
            'X-UltraCache-Public-Selection-Reuse-Version': '1',
            'X-UltraCache-Public-Selection-Reuse-Policy': 'c'*64,
            'X-UltraCache-Fragment-Delivery-Version': '1',
            'X-UltraCache-Fragment-Delivery-Route': '/index.php',
            'X-UltraCache-Fragment-Caching-Enabled': '1' if caching else '0'})
        self.assertEqual(result[0], 200, result)
        self.assertEqual(result[1].get('X-UltraCache-VCL-Fragment-Delivery-Version'), '1')
        self.assertEqual(result[1].get('X-UltraCache-VCL-Fragment-Caching-Enabled'), '1' if caching else '0')
        self.assertEqual(result[1].get('X-UltraCache-VCL-Fragment-Anonymous-Authority'), '1')
        self.assertEqual(result[1].get('X-UltraCache-VCL-Fragment-Batch-Compression'), 'deflate-v1')
        self.assertEqual(result[1].get('X-UltraCache-VCL-Fragment-Subset'), 'indices-v1')
        self.assertEqual(result[1].get('X-UltraCache-VCL-Public-Selection-Enabled'), '1' if parent else '0')

    def test_unregistered_capabilities_do_not_advertise_partial_contract_then_register(self):
        fields = ('X-UltraCache-VCL-Fragment-Batch-Compression', 'X-UltraCache-VCL-Fragment-Anonymous-Authority', 'X-UltraCache-VCL-Fragment-Delivery-Version',
                  'X-UltraCache-VCL-Fragment-Delivery-Route',
                  'X-UltraCache-VCL-Fragment-Caching-Enabled')
        with proxy('ultracache', lambda path, headers: ('unused', [])) as get:
            initial = control(get)
            self.assertEqual(initial[0], 200, initial)
            for field in fields:
                self.assertNotIn(field, initial[1], 'Unregistered scope must not emit a partial contract')
            self.register(get)
            accepted = control(get)
            self.assertEqual(accepted[0], 200, accepted)
            self.assertEqual(tuple(accepted[1].get(field) for field in fields), ('deflate-v1', '1', '1', '/index.php', '1'))

    def test_selected_signed_rows_only_and_invalid_subsets_never_prepare(self):
        value, wire, uri = self.batch(3)
        selected, seen = [1], []
        def origin(path, headers):
            seen.append(path)
            index_list = ','.join(str(i) for i in selected)
            digest = hashlib.sha256(('ultracache-fragment-delivery-subset-v1\n'+wire+'\n'+index_list).encode()).hexdigest()
            self.assertEqual(headers.get('X-UltraCache-Fragment-Delivery-Request-Digest'), digest)
            self.assertEqual(headers.get('X-UltraCache-Delivery-Manifest'), wire)
            self.assertEqual(headers.get('X-UltraCache-Delivery-Original-URL'), path)
            body = dict(schemaVersion=2, requestId=headers['X-UltraCache-Delivery-Request'],
                originalUrl=path, requestDigest=digest,
                renderedFragments=[dict(value['fragments'][i], html='selected-'+str(i)) for i in selected],
                failedFragments=[])
            return json.dumps(body), [('Content-Type', 'application/vnd.ultracache.fragment-delivery+json; version=1'),
                ('X-UltraCache-Fragment-Delivery-Version', '1'), ('Cache-Control', 'private, no-store')]
        with proxy('ultracache', origin) as get:
            self.register(get)
            for selection, encoded in (([1], '1'), ([0, 2], '0%2C2')):
                selected[:] = selection
                result = get(uri+'&ultracache_fragment_subset='+encoded)
                self.assertEqual(result[0], 200, result)
                self.assertEqual([(r['url'], r['html']) for r in json.loads(result[2])['results']],
                    [(value['fragments'][i]['url'], 'selected-'+str(i)) for i in selected])
            self.assertEqual(len(seen), 2)
            for suffix in ('', '3', '1,0', '0,0', '01', '0%252C2',
                '1&ultracache_fragment_subset=2', '1&ultracache_fragment_delivery='+wire):
                self.assertEqual(get(uri+'&ultracache_fragment_subset='+suffix)[0], 400, suffix)
            self.assertEqual(len(seen), 2, 'Rejected membership must not execute the producer')

    def batch(self, count=2):
        value = payload(); value['context']['policy'] = 'b'*64
        if count != 2:
            value['fragments'] = [dict(url='/?ultracache_esi=item-'+str(i)+'&esi_scope=private', occurrences=1)
                                  for i in range(count)]
        wire = token(value).decode()
        return value, wire, '/index.php?ultracache_fragment_delivery='+wire

    def response(self, headers, wire, rows, failures=(), authority=None):
        value = dict(schemaVersion=2, requestId=headers['X-UltraCache-Delivery-Request'],
            originalUrl=headers['X-UltraCache-Delivery-Original-URL'],
            requestDigest=hashlib.sha256(('ultracache-fragment-delivery-v1\n'+wire).encode()).hexdigest(),
            renderedFragments=rows, failedFragments=list(failures))
        if authority is not None: value['authority'] = authority
        self.assertEqual(headers.get('X-UltraCache-Fragment-Delivery-Request-Digest'), value['requestDigest'])
        return json.dumps(value), [('Content-Type', 'application/vnd.ultracache.fragment-delivery+json; version=1'),
            ('X-UltraCache-Fragment-Delivery-Version', '1'), ('Cache-Control', 'private, no-store'),
            ('Set-Cookie', 'issuer=current; Path=/; HttpOnly')]

    def test_compressed_large_plan_uses_one_existing_prepare_and_rejects_bad_native_mac(self):
        import base64
        from test_fragment_batch_compression import compressed_token
        value, _, _ = self.batch(3)
        for i, item in enumerate(value['fragments']):
            opaque = ''.join(hashlib.sha256(('public-fixture-'+str(i)+'-'+str(n)).encode()).hexdigest() for n in range(94))
            item['url'] = '/?ultracache_esi='+opaque+'&esi_scope=private'
        wire = compressed_token(value, secret=b'b'*64, scope='/').decode()
        uri = '/index.php?ultracache_fragment_delivery='+wire
        self.assertGreater(len(json.dumps(value)), 18000)
        self.assertLess(len(uri), len('/index.php?ultracache_fragment_delivery='+token(value).decode()))
        seen = []
        def origin(path, headers):
            seen.append(path)
            self.assertEqual(path, uri)
            self.assertEqual(headers.get('X-UltraCache-Delivery-Phase'), 'fragment-prepare')
            return self.response(headers, wire, [dict(item, html='output-'+str(i))
                for i, item in enumerate(value['fragments'])])
        with proxy('ultracache', origin, coalesce_response=True) as get:
            self.register(get)
            result = get(uri)
            self.assertEqual(result[0], 200, result)
            self.assertEqual([(row['status'], row['html'], row['cacheScope']) for row in json.loads(result[2])['results']],
                [(200, 'output-'+str(i), 'none') for i in range(3)])
            self.assertEqual(len(seen), 1)
            first = wire.split('.')[0][3:]
            frame = bytearray(base64.urlsafe_b64decode(first+'='*(-len(first)%4))); frame[9] ^= 1
            forged = 'z1_'+base64.urlsafe_b64encode(frame).rstrip(b'=').decode()+'.'+'c'*64
            self.assertEqual(get('/index.php?ultracache_fragment_delivery='+forged)[0], 400)
            self.assertEqual(len(seen), 1, 'Invalid native MAC cannot reach the application')

    def test_request_local_batch_has_one_prepare_and_sanitized_results(self):
        value, wire, uri = self.batch()
        seen = []
        def origin(path, headers):
            seen.append((path, headers.get('X-UltraCache-Delivery-Phase'), headers.get('Cookie')))
            self.assertEqual(path, uri)
            self.assertEqual(headers.get('X-UltraCache-Delivery-Phase'), 'fragment-prepare')
            self.assertEqual(headers.get('X-UltraCache-Delivery-Authorization'), 'b'*64)
            self.assertIsNone(headers.get('X-SCP-Key-URL'))
            self.assertEqual(headers.get('X-UltraCache-Delivery-Original-URL'), uri)
            self.assertEqual(headers.get('X-UltraCache-Delivery-Manifest'), wire)
            rows = [dict(item, html='actual-'+str(i)+'\x00"Ελληνικά') for i, item in enumerate(value['fragments'])]
            return self.response(headers, wire, rows)
        with proxy('ultracache', origin, daemon_parameters=('vsl_mask=+Debug',)) as get:
            self.register(get)
            status, fields, body = get(uri, '_fbp=actual')
            self.assertEqual(status, 200, (status, fields, body))
            result = json.loads(body)
            self.assertEqual(len(result['results']), 2)
            self.assertEqual(result['results'][0]['html'], 'actual-0\x00"Ελληνικά')
            self.assertEqual(cookies(fields), ['issuer=current; Path=/; HttpOnly'])
            self.assertIn('private', dict(fields)['Cache-Control'])
            self.assertNotIn('renderedFragments', body)
            self.assertNotIn('X-UltraCache-Delivery-Authorization', str(fields))
            self.assertEqual(seen, [(uri, 'fragment-prepare', '_fbp=actual')])

    def test_positive_objects_use_normal_storage_without_restart_count_cliff(self):
        value, wire, uri = self.batch(7)
        state = {'context': None, 'prepares': 0, 'renders': 0, 'lookups': []}
        keys = {item['url']: hashlib.sha256(item['url'].encode()).hexdigest() for item in value['fragments']}
        def origin(path, headers):
            self.assertEqual(path, uri)
            self.assertEqual(headers.get('X-UltraCache-Delivery-Phase'), 'fragment-prepare')
            state['prepares'] += 1
            rows = []
            for item in value['fragments']:
                status, fields, body = exchange(get, 'UC-PRIVATE-GET', item['url'], keys[item['url']], 'b'*64)
                state['lookups'].append(status)
                if status == 200:
                    ttl = int(dict(fields)['X-UltraCache-Private-Remaining'])
                else:
                    self.assertEqual(status, 404)
                    state['renders'] += 1; body = 'rendered-'+item['url']; ttl = 60
                rows.append(dict(item, html=body, cache=dict(key=keys[item['url']], ttl=ttl, tags='fixture')))
            context = state['context']
            grant = {key: context[key] for key in ('scope', 'epoch', 'incarnation', 'scopeRevision',
                                                   'nativePolicy', 'wordpressPolicy', 'reusePolicy')}
            grant['fragments'] = [dict(url=item['url'], authority=[dict(tag=context['tag'],
                revision=context['contentRevision'], generation=context['generation'])]) for item in value['fragments']]
            return self.response(headers, wire, rows, authority=grant)
        with proxy('ultracache', origin, daemon_parameters=('vsl_mask=+Debug',)) as get:
            self.register(get); state['context'] = self.ready(get)
            first = get(uri)
            if first[0] != 200:
                trace = subprocess.run(['varnishlog', '-n', str(get.instance), '-d', '-g', 'request',
                    '-i', 'VCL_call,VCL_return,VCL_Error,Error,FetchError,RespStatus,BerespStatus,BerespReason,VCL_Log,TTL,Debug'],
                    capture_output=True, text=True, timeout=10)
                self.fail(str(first)+'\n'+trace.stdout+trace.stderr)
            self.assertEqual(state['renders'], 7)
            second = get(uri)
            self.assertEqual(second[0], 200, second)
            self.assertEqual(json.loads(second[2]), json.loads(first[2]))
            self.assertEqual((state['prepares'], state['renders']), (2, 7))
            self.assertEqual(state['lookups'], [404]*7+[200]*7)

    def test_esi_and_ajax_fill_and_reuse_the_same_individual_objects_both_directions(self):
        value, wire, uri = self.batch()
        state = dict(context=None, renders=0, lookups=[], prepares=0)
        keys = {row['url']: hashlib.sha256(('actual-owner|'+row['url']).encode()).hexdigest() for row in value['fragments']}
        parent = '/esi-parent/'
        body = '<html>'+''.join('<esi:include src="'+row['url'].replace('&','&amp;')+'"/>'
            for row in value['fragments'] for _ in range(row['occurrences']))+'</html>'
        meta = [('Cache-Control', 'public, max-age=120'), ('Surrogate-Control', 'ESI/1.0'),
            ('X-UltraCache-ESI-Shared-Parent', '1'), ('X-UltraCache-ESI-Private-Count', '3'),
            ('X-UltraCache-Delivery-Prepare', '/index.php?ultracache_delivery=fixture.token')]
        def origin(path, headers):
            phase = headers.get('X-UltraCache-Delivery-Phase')
            if phase not in ('prepare', 'fragment-prepare'):
                return (body, meta) if path == parent else ('initial-private', [('Cache-Control', 'private, no-store')])
            state['prepares'] += 1
            rows = []
            for item in value['fragments']:
                status, fields, output = exchange(get, 'UC-PRIVATE-GET', item['url'], keys[item['url']], 'b'*64)
                state['lookups'].append(status)
                if status == 200:
                    ttl = int(dict(fields)['X-UltraCache-Private-Remaining'])
                else:
                    self.assertEqual(status, 404); state['renders'] += 1
                    output = 'owner-body-'+str(state['renders']); ttl = 60
                rows.append(dict(item, html=output, cache=dict(key=keys[item['url']], ttl=ttl, tags='fixture')))
            if phase == 'prepare':
                return json.dumps(dict(schemaVersion=1, requestId=headers['X-UltraCache-Delivery-Request'],
                    originalUrl=headers['X-UltraCache-Delivery-Original-URL'], renderedFragments=rows)), [('Cache-Control', 'private, no-store')]
            context = state['context']
            grant = {name: context[name] for name in ('scope', 'epoch', 'incarnation', 'scopeRevision',
                'nativePolicy', 'wordpressPolicy', 'reusePolicy')}
            grant['fragments'] = [dict(url=item['url'], authority=[dict(tag=context['tag'],
                revision=context['contentRevision'], generation=context['generation'])]) for item in value['fragments']]
            return self.response(headers, wire, rows, authority=grant)
        with proxy('ultracache', origin) as get:
            self.assertEqual(get(parent)[0], 200)
            self.register(get); state['context'] = self.ready(get)
            esi_first = get(parent)
            self.assertEqual(esi_first[0], 200, esi_first)
            self.assertEqual(state['renders'], 2)
            ajax = get(uri)
            self.assertEqual(ajax[0], 200, ajax)
            self.assertEqual(state['renders'], 2, 'ESI-filled objects must HIT in Ajax')
            for item in value['fragments']:
                self.assertEqual(exchange(get, 'PURGE', item['url'], keys[item['url']], 'b'*64)[0], 200)
            ajax_first = get(uri)
            self.assertEqual(ajax_first[0], 200, ajax_first)
            self.assertEqual(state['renders'], 4)
            esi = get(parent)
            self.assertEqual(esi[0], 200, esi)
            self.assertEqual(state['renders'], 4, 'Ajax-filled objects must HIT in ESI')
            self.assertEqual(state['lookups'], [404, 404, 200, 200, 404, 404, 200, 200])
            self.assertIn('owner-body-3', esi[2])
            self.assertNotIn('owner-body-1', esi[2])

    def test_fragment_cache_off_bypasses_hot_public_object_and_preserves_parent_cache(self):
        calls = []
        public = '/?ultracache_esi=public-descriptor'
        def origin(path, headers):
            calls.append(path)
            return 'public-'+str(len(calls)), [('Cache-Control', 'public, max-age=120')]
        with proxy('ultracache', origin) as get:
            self.assertEqual(get(public)[0], 200)
            self.assertEqual(get(public)[2], 'public-1')
            self.assertEqual(get('/ordinary-parent/')[0], 200)
            parent_calls = len(calls)
            self.register(get, caching=False)
            self.assertEqual(get('/ordinary-parent/')[0], 200)
            self.assertEqual(len(calls), parent_calls, 'Common parent cache remains enabled')
            a = get(public); b = get(public)
            self.assertEqual((a[0], b[0]), (200, 200))
            self.assertNotEqual(a[2], b[2], 'OFF must bypass an already hot public fragment')
            self.assertEqual(exchange(get, 'UC-PRIVATE-GET', PRIVATE, 'a'*64, 'b'*64)[0], 404)

    def test_cache_scope_reports_committed_anonymous_private_and_storage_off(self):
        value, wire, uri = self.batch()
        state = dict(context=None)
        keys = {item['url']: hashlib.sha256(item['url'].encode()).hexdigest()
                for item in value['fragments']}
        def origin(path, headers):
            self.assertEqual(path, uri)
            context = state['context']
            rows, grants = [], []
            for i, item in enumerate(value['fragments']):
                cache = dict(key=keys[item['url']], ttl=60, tags='fixture' if i else '')
                if not i: cache['identityState'] = 'anonymous'
                rows.append(dict(item, html='output-'+str(i), cache=cache))
                grants.append(dict(url=item['url'], authority=[dict(tag=context['tag'],
                    revision=context['contentRevision'], generation=context['generation'])] if i else []))
            grant = {name: context[name] for name in ('scope', 'epoch', 'incarnation',
                'scopeRevision', 'nativePolicy', 'wordpressPolicy', 'reusePolicy')}
            grant['fragments'] = grants
            return self.response(headers, wire, rows, authority=grant)
        with proxy('ultracache', origin) as get:
            self.register(get); state['context'] = self.ready(get)
            for item in value['fragments']:
                self.assertEqual(exchange(get, 'UC-PRIVATE-GET', item['url'], keys[item['url']], 'b'*64)[0], 404)
            for _ in range(2):
                result = get(uri)
                self.assertEqual(result[0], 200, result)
                rows = json.loads(result[2])['results']
                self.assertEqual([row['cacheScope'] for row in rows], ['anonymous', 'private'])
                for i, item in enumerate(value['fragments']):
                    retained = exchange(get, 'UC-PRIVATE-GET', item['url'], keys[item['url']], 'b'*64)
                    self.assertEqual((retained[0], retained[2]), (200, 'output-'+str(i)))
                self.assertNotIn('authority', result[2])
                for key in keys.values(): self.assertNotIn(key, result[2])
            self.register(get, caching=False)
            result = get(uri)
            self.assertEqual(result[0], 200, result)
            self.assertEqual([row['cacheScope'] for row in json.loads(result[2])['results']], ['none', 'none'])
            for item in value['fragments']:
                self.assertEqual(exchange(get, 'UC-PRIVATE-GET', item['url'], keys[item['url']], 'b'*64)[0], 404)

    def test_anonymous_content_dependency_reuses_then_retires_hot_body_and_refills(self):
        value, wire, uri = self.batch(1)
        item = value['fragments'][0]
        tag = hashlib.sha256(b'fixture-product-content').hexdigest()
        state = dict(context=None, renders=0, lookups=[])
        def call(operation, context=None, **kwargs):
            return self.call(get, operation, context, tag=tag, **kwargs)
        def origin(path, headers):
            self.assertEqual(path, uri)
            context = state['context']
            key = hashlib.sha256(('product|'+context['generation']).encode()).hexdigest()
            status, fields, body = exchange(get, 'UC-PRIVATE-GET', item['url'], key, 'b'*64)
            state['lookups'].append(status)
            if status == 200:
                ttl = int(dict(fields)['X-UltraCache-Private-Remaining'])
            else:
                self.assertEqual(status, 404); state['renders'] += 1
                body = 'product-output-'+str(state['renders']); ttl = 60
            grant = {name: context[name] for name in ('scope', 'epoch', 'incarnation',
                'scopeRevision', 'nativePolicy', 'wordpressPolicy', 'reusePolicy')}
            grant['fragments'] = [dict(url=item['url'], authority=[dict(tag=tag,
                revision=context['contentRevision'], generation=context['generation'])])]
            row = dict(item, html=body, cache=dict(key=key, ttl=ttl, tags='content-product', identityState='anonymous'))
            return self.response(headers, wire, [row], authority=grant)
        with proxy('ultracache', origin) as get:
            self.register(get)
            state['context'] = call('private-generation-publish', call('private-authority-context'),
                extra={'X-UltraCache-Private-Generation': '1'*64})
            first = get(uri); second = get(uri)
            self.assertEqual((first[0], second[0]), (200, 200), (first, second))
            self.assertEqual(json.loads(first[2]), json.loads(second[2]))
            self.assertEqual(json.loads(second[2])['results'][0]['cacheScope'], 'anonymous')
            self.assertEqual((state['renders'], state['lookups']), (1, [404, 200]))
            writer = call('private-mutation-begin', state['context'],
                extra={'X-UltraCache-Private-Transaction': hashlib.sha256(b'product-change').hexdigest()})
            retired = get(uri)
            self.assertEqual(retired[0], 200, retired)
            self.assertEqual(json.loads(retired[2])['results'], [dict(url=item['url'], status=409,
                error=dict(code='state-conflict'))])
            self.assertEqual((state['renders'], state['lookups']), (1, [404, 200, 200]),
                'An existing hot body must not bypass the changed product authority')
            call('private-mutation-commit', writer, extra={'X-UltraCache-Private-Transaction': writer['transaction'],
                'X-UltraCache-Private-Lease': writer['lease']})
            state['context'] = call('private-generation-publish', call('private-authority-context'),
                extra={'X-UltraCache-Private-Generation': '2'*64})
            fresh = get(uri); reused = get(uri)
            self.assertEqual((fresh[0], reused[0]), (200, 200), (fresh, reused))
            self.assertEqual(json.loads(fresh[2]), json.loads(reused[2]))
            self.assertEqual(json.loads(reused[2])['results'][0]['cacheScope'], 'anonymous')
            self.assertIn('product-output-2', reused[2]); self.assertNotIn('product-output-1', reused[2])
            self.assertEqual((state['renders'], state['lookups']), (2, [404, 200, 200, 404, 200]))

    def test_writer_after_render_retires_claim_before_fill_and_final_projection(self):
        value, wire, uri = self.batch(1)
        item = value['fragments'][0]
        key = hashlib.sha256(b'actual-owner-and-original-generation').hexdigest()
        state = dict(context=None)
        def origin(path, headers):
            context = state['context']
            grant = {name: context[name] for name in ('scope', 'epoch', 'incarnation', 'scopeRevision',
                'nativePolicy', 'wordpressPolicy', 'reusePolicy')}
            grant['fragments'] = [dict(url=item['url'], authority=[dict(tag=context['tag'],
                revision=context['contentRevision'], generation=context['generation'])])]
            # Real control BEGIN races after the trusted producer rendered its
            # old state, before native admission/fill. No new authority is forged.
            self.begin(get, context, 'writer-during-fragment-batch')
            rows = [dict(item, html='retired-personal-body', cache=dict(key=key, ttl=60, tags='fixture'))]
            return self.response(headers, wire, rows, authority=grant)
        with proxy('ultracache', origin) as get:
            self.register(get); state['context'] = self.ready(get)
            status, fields, body = get(uri)
            self.assertEqual(status, 200, (status, fields, body))
            self.assertNotIn('retired-personal-body', body)
            result = json.loads(body)['results'][0]
            self.assertEqual(result, dict(url=item['url'], status=409, error=dict(code='state-conflict')))
            self.assertEqual(exchange(get, 'UC-PRIVATE-GET', item['url'], key, 'b'*64)[0], 404)

    def test_explicit_stateless_fragment_reuses_native_object_and_namespace_revoke_rejects_hot_claim(self):
        value, wire, uri = self.batch(1)
        item = value['fragments'][0]
        key = hashlib.sha256(b'trusted-stateless-empty').hexdigest()
        state = dict(context=None, renders=0, lookups=[], revoke=False)
        def origin(path, headers):
            self.assertEqual(path, uri)
            self.assertEqual(headers.get('X-UltraCache-Delivery-Phase'), 'fragment-prepare')
            status, fields, body = exchange(get, 'UC-PRIVATE-GET', item['url'], key, 'b'*64)
            state['lookups'].append(status)
            if status == 200:
                ttl = int(dict(fields)['X-UltraCache-Private-Remaining'])
            else:
                self.assertEqual(status, 404); state['renders'] += 1
                body = 'trusted-empty-'+str(state['renders']); ttl = 60
            row = dict(item, html=body, cache=dict(key=key, ttl=ttl, tags='', identityState='anonymous'))
            context = state['context']
            grant = {name: context[name] for name in ('scope', 'epoch', 'incarnation', 'scopeRevision',
                'nativePolicy', 'wordpressPolicy', 'reusePolicy')}
            grant['fragments'] = [dict(url=item['url'], authority=[])]
            if state['revoke']:
                result = control(get, enabled=True, names='', extra={
                    'X-UltraCache-Public-Selection-Reuse-Version': '1',
                    'X-UltraCache-Public-Selection-Reuse-Policy': 'f'*64,
                    'X-UltraCache-Fragment-Delivery-Version': '1',
                    'X-UltraCache-Fragment-Delivery-Route': '/index.php',
                    'X-UltraCache-Fragment-Caching-Enabled': '1'})
                self.assertEqual(result[0], 200, result)
            return self.response(headers, wire, [row], authority=grant)
        with proxy('ultracache', origin) as get:
            self.register(get)
            state['context'] = self.observe(get)  # no synthetic owner/tag publication
            first = get(uri); second = get(uri)
            self.assertEqual((first[0], second[0]), (200, 200), (first, second))
            self.assertEqual(json.loads(first[2]), json.loads(second[2]))
            self.assertEqual((state['renders'], state['lookups']), (1, [404, 200]))
            self.assertNotIn('identityState', second[2])
            state['revoke'] = True
            retired = get(uri)
            self.assertEqual(retired[0], 200, retired)
            self.assertEqual(json.loads(retired[2])['results'], [dict(url=item['url'], status=409,
                error=dict(code='state-conflict'))])
            self.assertEqual((state['renders'], state['lookups']), (1, [404, 200, 200]),
                'A hot native body cannot authorize release under a revoked namespace')
            self.assertNotEqual(self.observe(get)['scopeRevision'], state['context']['scopeRevision'])

    def test_hot_parent_and_fragment_controls_are_independent_until_full_teardown(self):
        value, wire, uri = self.batch(1)
        item = value['fragments'][0]
        key = hashlib.sha256(b'committed-fragment-owner').hexdigest()
        state = dict(context=None, renders=0, parent_calls=0, lookups=[])
        def origin(path, headers):
            if path != uri:
                self.assertEqual(path, '/ordinary-parent/')
                self.assertIsNone(headers.get('X-UltraCache-Delivery-Phase'))
                state['parent_calls'] += 1
                return 'fresh-parent-'+str(state['parent_calls']), [('Cache-Control', 'public, max-age=120')]
            if headers.get('X-UltraCache-Delivery-Phase') != 'fragment-prepare':
                return 403, 'no-shadow-native-fragment', [('Cache-Control', 'private, no-store')]
            caching = headers.get('X-UltraCache-Fragment-Caching-Enabled') == '1'
            if caching:
                status, fields, output = exchange(get, 'UC-PRIVATE-GET', item['url'], key, 'b'*64)
                state['lookups'].append(status)
            else:
                status, fields, output = 404, [], ''
            if status == 200:
                ttl = int(dict(fields)['X-UltraCache-Private-Remaining'])
            else:
                self.assertEqual(status, 404); state['renders'] += 1
                output = 'fragment-render-'+str(state['renders']); ttl = 60
            row = dict(item, html=output)
            grant = None
            if caching:
                row['cache'] = dict(key=key, ttl=ttl, tags='fixture')
                context = state['context']
                grant = {name: context[name] for name in ('scope', 'epoch', 'incarnation', 'scopeRevision',
                    'nativePolicy', 'wordpressPolicy', 'reusePolicy')}
                grant['fragments'] = [dict(url=item['url'], authority=[dict(tag=context['tag'],
                    revision=context['contentRevision'], generation=context['generation'])])]
            return self.response(headers, wire, [row], authority=grant)
        with proxy('ultracache', origin) as get:
            self.assertEqual(get('/ordinary-parent/')[2], 'fresh-parent-1')
            self.register(get); state['context'] = self.ready(get)
            self.assertEqual(get('/ordinary-parent/')[2], 'fresh-parent-1')
            self.assertEqual(get(uri)[0], 200)
            self.assertEqual(get(uri)[0], 200)
            self.assertEqual((state['parent_calls'], state['renders']), (1, 1))
            before = self.observe(get)
            before_remaining = int(dict(exchange(get, 'UC-PRIVATE-GET', item['url'], key, 'b'*64)[1])['X-UltraCache-Private-Remaining'])
            self.register(get, parent=False)
            after = self.observe(get)
            self.assertEqual((after['scopeRevision'], after['contentRevision'], after['generation']),
                (before['scopeRevision'], before['contentRevision'], before['generation']))
            self.assertEqual(get('/ordinary-parent/')[2], 'fresh-parent-2')
            self.assertEqual(get('/ordinary-parent/')[2], 'fresh-parent-3')
            self.assertEqual(get('/ordinary-parent/', extra={'Accept': 'application/json'})[2], 'fresh-parent-4',
                'A different request Accept cannot expose retained HTML while parent delivery is OFF')
            hot = get(uri)
            self.assertEqual(hot[0], 200, hot)
            self.assertEqual(json.loads(hot[2])['results'][0]['html'], 'fragment-render-1')
            self.assertEqual(state['renders'], 1, 'Parent OFF cannot disable or refresh the native fragment')
            remaining = int(dict(exchange(get, 'UC-PRIVATE-GET', item['url'], key, 'b'*64)[1])['X-UltraCache-Private-Remaining'])
            self.assertLessEqual(remaining, before_remaining, 'Parent toggle must not reset original fragment expiry')
            self.register(get, caching=False, parent=False)
            self.assertEqual(exchange(get, 'UC-PRIVATE-GET', item['url'], key, 'b'*64)[0], 404)
            first = get(uri); second = get(uri)
            self.assertEqual((first[0], second[0]), (200, 200))
            self.assertEqual(state['renders'], 3)
            self.assertNotEqual(json.loads(first[2]), json.loads(second[2]))
            disabled = self.observe(get)
            self.assertEqual(disabled['scopeRevision'], before['scopeRevision'])
            self.assertEqual(get('/ordinary-parent/')[2], 'fresh-parent-5')
            teardown = control(get, enabled=False, names='')
            self.assertEqual(teardown[0], 200, teardown)
            for header in ('X-UltraCache-VCL-Public-Selection-Enabled', 'X-UltraCache-VCL-Public-Selection-Scope',
                'X-UltraCache-VCL-Fragment-Batch-Compression', 'X-UltraCache-VCL-Fragment-Anonymous-Authority', 'X-UltraCache-VCL-Fragment-Delivery-Version', 'X-UltraCache-VCL-Fragment-Delivery-Route',
                'X-UltraCache-VCL-Fragment-Caching-Enabled'):
                self.assertNotIn(header, teardown[1])
            retired = self.call(get, 'private-authority-context', expected_status=409)
            self.assertEqual(retired['reason'], 'authority-unavailable')
            self.assertEqual(get(uri)[0], 403, 'Full teardown restores the ordinary unregistered origin path')


if __name__ == '__main__': unittest.main()
