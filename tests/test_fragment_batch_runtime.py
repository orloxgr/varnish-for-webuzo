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

    def register(self, get, caching=True):
        result = control(get, enabled=True, names='', wordpress_policy='b'*64, extra={
            'X-UltraCache-Public-Selection-Reuse-Version': '1',
            'X-UltraCache-Public-Selection-Reuse-Policy': 'c'*64,
            'X-UltraCache-Fragment-Delivery-Version': '1',
            'X-UltraCache-Fragment-Delivery-Route': '/index.php',
            'X-UltraCache-Fragment-Caching-Enabled': '1' if caching else '0'})
        self.assertEqual(result[0], 200, result)
        self.assertEqual(result[1].get('X-UltraCache-VCL-Fragment-Delivery-Version'), '1')
        self.assertEqual(result[1].get('X-UltraCache-VCL-Fragment-Caching-Enabled'), '1' if caching else '0')

    def test_unregistered_capabilities_do_not_advertise_partial_contract_then_register(self):
        fields = ('X-UltraCache-VCL-Fragment-Delivery-Version',
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
            self.assertEqual(tuple(accepted[1].get(field) for field in fields), ('1', '/index.php', '1'))

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

    def test_request_local_batch_has_one_prepare_and_sanitized_results(self):
        value, wire, uri = self.batch()
        seen = []
        def origin(path, headers):
            seen.append((path, headers.get('X-UltraCache-Delivery-Phase'), headers.get('Cookie')))
            self.assertEqual(path, uri)
            self.assertEqual(headers.get('X-UltraCache-Delivery-Phase'), 'fragment-prepare')
            self.assertEqual(headers.get('X-UltraCache-Delivery-Authorization'), 'b'*64)
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


if __name__ == '__main__': unittest.main()
