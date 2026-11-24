"""Source grammar and real native continuation; application is a declared mock.

Actual WordPress/provider/SQL drain acceptance belongs to composed integration.
"""
import base64
import ctypes
import json
import shutil
import unittest

from test_public_selection import (CC, PublicSelection, SelectionPointer, sample,
    NATIVE, WORDPRESS, URL)
from test_cookie_delivery import proxy, cookies
from test_cms_cookie_choices import cache
from test_cold_public_selection import Application, choices
from test_public_selection_runtime import control


def source_sample():
    result = sample()
    selected = result['selectedPublic']
    selected.pop('cookieUpdates')
    selected.pop('renderedFragments')
    selected['publicSource'] = dict(version=1, role='parent-v1')
    return result


@unittest.skipUnless(CC, 'C compiler required; skipped is not acceptance')
class PublicSourceGrammar(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        PublicSelection.setUpClass.__func__(cls)
        cls.lib.delivery_public_source_parse.argtypes = [ctypes.c_void_p, ctypes.c_size_t]+[
            ctypes.c_char_p]*4+[ctypes.POINTER(SelectionPointer)]
        cls.lib.delivery_public_source_parse.restype = ctypes.c_int

    tearDownClass = classmethod(PublicSelection.tearDownClass.__func__)

    def parse(self, value, url=URL):
        data = json.dumps(value).encode() if isinstance(value, dict) else value
        selected = SelectionPointer()
        accepted = self.lib.delivery_public_source_parse(data, len(data), b'42', url.encode(),
            NATIVE.encode(), WORDPRESS.encode(), ctypes.byref(selected))
        try:
            if not accepted:
                self.assertFalse(selected)
                return None
            return dict(body=ctypes.string_at(selected.contents.parent.contents.body,
                selected.contents.parent.contents.length), count=selected.contents.occurrences)
        finally:
            self.lib.delivery_selection_free(selected)

    def test_source_preserves_private_slots_without_preparing_them(self):
        value = source_sample()
        value['selectedPublic']['occurrences'] = 3
        value['selectedPublic']['headers'] = [line.replace('Count: 0', 'Count: 3')
            for line in value['selectedPublic']['headers']]
        self.assertEqual(self.parse(value), dict(body=b'<html>EUR20</html>', count=3))

    def test_source_and_personal_wire_are_not_interchangeable(self):
        self.assertIsNone(self.parse(sample()))
        self.assertIsNone(PublicSelection.parse(self, source_sample()))
        for field, extra in [('cookieUpdates', []), ('renderedFragments', []),
                ('reuseCandidate', {}), ('cacheClaims', {}), ('recipe', {})]:
            value = source_sample(); value['selectedPublic'][field] = extra
            with self.subTest(field=field): self.assertIsNone(self.parse(value))

    def test_role_fields_duplicates_and_types_are_strict(self):
        for role in ({}, dict(version=1), dict(version=2, role='parent-v1'),
                dict(version=True, role='parent-v1'), dict(version=1, role='guest'),
                dict(version=1, role='parent-v1', policy='new-owner')):
            value = source_sample(); value['selectedPublic']['publicSource'] = role
            with self.subTest(role=role): self.assertIsNone(self.parse(value))
        raw = json.dumps(source_sample()).replace('"version": 1', '"version": 1, "version": 1')
        self.assertIsNone(self.parse(raw.encode()))

    def test_existing_body_identity_policy_count_and_private_header_checks_remain(self):
        self.assertIsNone(self.parse(source_sample(), url='/different/'))
        for field, invalid in [('policyDigest', 'c'*64), ('wordpressPolicyDigest', 'd'*64),
                ('occurrences', 1)]:
            value = source_sample(); value['selectedPublic'][field] = invalid
            with self.subTest(field=field): self.assertIsNone(self.parse(value))
        value = source_sample(); value['selectedPublic']['publicParent']['generation'] = 'e'*64
        self.assertIsNone(self.parse(value))
        value = source_sample(); value['selectedPublic']['headers'].append('Set-Cookie: visitor=source')
        self.assertIsNone(self.parse(value))
        value = source_sample(); value.pop('selectedPublic')
        value['privateDocument'] = dict(status=200, contentType='text/html', bodyBase64='')
        self.assertIsNone(self.parse(value))


class SourceApplication(Application):
    def __init__(self, mode='success'):
        super().__init__(private=True)
        self.mode = mode
        self.wire = []

    def __call__(self, path, headers):
        self.wire.append((path, dict(headers)))
        is_source = headers.get('X-UltraCache-Delivery-Public-Source-Role') == 'parent-v1'
        if is_source and self.mode == 'decline':
            self.calls.append((path, headers.get('X-UltraCache-Delivery-Phase'), headers.get('Cookie')))
            return 409, b'', [('Cache-Control', 'private, no-store'),
                ('X-UltraCache-Delivery-Public-Source-Version', '1'),
                ('X-UltraCache-Delivery-Public-Source-Outcome', 'unavailable')]
        if headers.get('X-UltraCache-Delivery-Public-Source-Fallback') == 'public-source-unavailable':
            self.calls.append((path,headers.get('X-UltraCache-Delivery-Phase'),headers.get('Cookie')))
            visitor=headers.get('X-Test-Visitor','guest')
            document=dict(schemaVersion=1,requestId=headers['X-UltraCache-Delivery-Request'],
                originalUrl=headers['X-UltraCache-Delivery-Original-URL'],privateDocument=dict(
                    status=200,contentType='text/html',bodyBase64=base64.b64encode(('private:'+visitor).encode()).decode()))
            return json.dumps(document),[('Content-Type','application/vnd.ultracache.delivery+json'),
                ('X-UltraCache-Delivery-Public-Selection-Version','1'),('Cache-Control','private, no-store'),
                ('Set-Cookie','visitor_session='+visitor+'; Path=/; HttpOnly')]
        body, fields = super().__call__(path, headers)
        if headers.get('X-UltraCache-Delivery-Phase') == 'public-select':
            value = json.loads(body)
            if is_source:
                value['selectedPublic'].pop('renderedFragments')
                value['selectedPublic'].pop('cookieUpdates')
                value['selectedPublic']['publicSource'] = dict(version=1, role='parent-v1')
                fields = [(name, val) for name, val in fields if name != 'X-UltraCache-Delivery-Outcome']
                fields += [('X-UltraCache-Delivery-Public-Source-Version', '1'),
                    ('X-UltraCache-Delivery-Public-Source-Outcome', 'captured'),
                    ('Set-Cookie', 'source_session=never-replay; Path=/')]
                if self.mode == 'corrupt': value['selectedPublic']['publicSource']['role'] = 'guest'
            # The declared mock uses one actual publication for raw tracking
            # aliases, like the application's canonical snapshot lookup.
            if not is_source and self.wire[0][1].get('X-UltraCache-Delivery-Public-Source-Role'):
                import hashlib
                from test_delivery_continuation import BODY
                value['selectedPublic']['manifest'] = 'mock.'+hashlib.sha256((self.wire[0][0]+'|'+BODY).encode()).hexdigest()
                manifest = value['selectedPublic']['manifest']
                value['selectedPublic']['headers'] = [
                    'X-UltraCache-Delivery-Prepare: /index.php?ultracache_delivery='+manifest
                    if line.startswith('X-UltraCache-Delivery-Prepare:') else line
                    for line in value['selectedPublic']['headers']]
                if self.mode == 'mismatch':
                    value['selectedPublic']['manifest'] += '.different'
                    value['selectedPublic']['headers'] = [line+'.different'
                        if line.startswith('X-UltraCache-Delivery-Prepare:') else line
                        for line in value['selectedPublic']['headers']]
            if not is_source: fields.append(('Set-Cookie', 'visitor_session=personal; Path=/; HttpOnly'))
            body = json.dumps(value)
        return body, fields


@unittest.skipUnless(shutil.which('varnishd'), 'Native Varnish required')
class NativePublicSource(unittest.TestCase):
    def declare(self, get):
        status, fields, _ = control(get, enabled=True, names='', extra={
            'X-UltraCache-Public-Selection-Public-Source-Version': '1'})
        self.assertEqual(status, 200)
        self.assertEqual(fields.get('X-UltraCache-VCL-Public-Selection-Public-Source-Version'), '1')

    def test_source_projects_actual_variant_then_restores_original_visitor_once(self):
        app = SourceApplication()
        policy = choices(('cmp_language', 'variant'), ('brandCurrency', 'variant'),
            ('shared_metric', 'shared'), ('wp_woocommerce_session_fixture', 'shared'))
        raw = 'shared_metric=A; cmp_language=el-GR; wp_woocommerce_session_fixture=owner-A; brandCurrency=EUR'
        with proxy('ultracache', app, policies=policy) as get:
            self.declare(get)
            status, fields, body = get('/source?utm_source=one', raw, extra={'X-Test-Visitor': 'A'})
            self.assertEqual((status, cache(fields)), (200, 'MISS'))
            self.assertEqual(body.count('private:A'), 2)
            self.assertEqual(body.count('nonce:A'), 1)
            self.assertEqual(dict(fields).get('X-UltraCache-Public-Source-Outcome'), 'parent-v1')
            self.assertEqual(cookies(fields), ['visitor_session=personal; Path=/; HttpOnly'])
            self.assertEqual(len(app.wire), 2)
            source, personal = app.wire
            self.assertEqual(source[1].get('Cookie'), 'brandCurrency=EUR; cmp_language=el-GR')
            self.assertEqual(source[0], '/source')
            self.assertEqual(source[1]['X-UltraCache-Delivery-Original-URL'], '/source')
            self.assertEqual(personal[0], '/source?utm_source=one')
            self.assertEqual(personal[1]['Cookie'], raw)
            self.assertNotIn('X-UltraCache-Delivery-Public-Source-Role', personal[1])
            status, fields, body = get('/source?utm_source=two', raw, extra={'X-Test-Visitor': 'B'})
            self.assertEqual((status, cache(fields)), (200, 'HIT'))
            self.assertIn('private:B', body)
            self.assertEqual(len(app.wire), 3)
            self.assertEqual(app.wire[-1][1].get('X-UltraCache-Delivery-Phase'), 'prepare')

    def test_saved_private_cookie_choice_still_bypasses_before_any_source(self):
        app = SourceApplication()
        with proxy('ultracache', app, policies=choices(('owner_session', 'private'))) as get:
            self.declare(get)
            status, fields, body = get('/private', 'owner_session=A')
            self.assertEqual((status, cache(fields), body), (200, 'PASS', 'ordinary private composition'))
            self.assertEqual(len(app.wire), 1)
            self.assertNotIn('X-UltraCache-Delivery-Public-Source-Role', app.wire[0][1])

    def test_empty_projection_is_no_cookie_and_source_does_not_complete_delivery(self):
        app = SourceApplication()
        with proxy('ultracache', app) as get:
            self.declare(get)
            status, fields, body = get('/empty', extra={'X-Test-Visitor': 'A'})
            self.assertEqual(status, 200)
            self.assertNotIn('Cookie', app.wire[0][1])
            self.assertEqual([entry[1].get('X-UltraCache-Delivery-Phase') for entry in app.wire],
                ['public-select', 'public-select'])
            self.assertEqual(dict(fields).get('X-UltraCache-Delivery-Outcome'), 'verified')
            self.assertEqual(cookies(fields), ['visitor_session=personal; Path=/; HttpOnly'])

    def test_typed_decline_restores_real_visitor_for_one_personal_execution(self):
        app = SourceApplication('decline')
        with proxy('ultracache', app) as get:
            self.declare(get)
            status, fields, body = get('/declined', extra={'X-Test-Visitor': 'A'})
            self.assertEqual(status, 200)
            self.assertIn('private:A', body)
            self.assertEqual(len(app.wire), 2)
            self.assertEqual(app.wire[-1][1].get('X-UltraCache-Delivery-Public-Source-Fallback'),'public-source-unavailable')
            self.assertEqual(dict(fields).get('X-UltraCache-Public-Source-Outcome'), 'unavailable')
            self.assertIn('private, no-store',dict(fields).get('Cache-Control',''))
            self.assertEqual(cookies(fields),['visitor_session=A; Path=/; HttpOnly'])
            self.assertEqual(get('/declined',extra={'X-Test-Visitor':'B'})[2],'private:B')
            self.assertEqual(len(app.wire),4,'Another visitor must execute its own private response')

    def test_corrupt_source_or_different_publication_cannot_be_accepted(self):
        for mode, count in [('corrupt', 1), ('mismatch', 2)]:
            app = SourceApplication(mode)
            with self.subTest(mode=mode), proxy('ultracache', app) as get:
                self.declare(get)
                status, fields, _ = get('/invalid')
                self.assertEqual(status, 503)
                self.assertNotEqual(dict(fields).get('X-UltraCache-Delivery-Outcome'), 'verified')
                self.assertEqual(dict(fields).get('X-UltraCache-Public-Source-Outcome'), 'protocol-error')
                self.assertEqual(len(app.wire), count)

    def test_source_mutation_context_signs_actual_source_url_without_private_candidate(self):
        import test_reuse_authority as authority
        from test_reuse_delivery_context import signed_context
        from test_mutation_backend import receipt
        app = SourceApplication(); seen = []
        def origin(path, headers):
            context = signed_context(self, headers, path, 'GET')
            seen.append(context)
            result = app(path, headers)
            return result[0], result[1]+[('X-UltraCache-Mutation-Receipt', receipt(context, 'none', ()))]
        with proxy('ultracache', origin) as get:
            status, fields, _ = control(get, enabled=True, names='', extra={
                'X-UltraCache-Public-Selection-Public-Source-Version': '1',
                'X-UltraCache-Public-Selection-Reuse-Version': '1',
                'X-UltraCache-Public-Selection-Reuse-Policy': authority.REUSE_POLICY})
            self.assertEqual(status, 200)
            registry = authority.NativeReuseAuthority(); before = registry.observe(get)
            status, _, _ = get('/signed-source?utm_source=original')
            self.assertEqual(status, 200)
            self.assertEqual(len(seen), 2)
            source, personal = app.wire
            self.assertEqual(source[0], '/signed-source')
            self.assertEqual(personal[0], '/signed-source?utm_source=original')
            self.assertNotIn('X-UltraCache-Delivery-Reuse-Candidate-Version', source[1])
            self.assertNotIn('X-UltraCache-Delivery-Reuse-Context', source[1])
            self.assertEqual(personal[1].get('X-UltraCache-Delivery-Reuse-Candidate-Version'), '1')
            self.assertEqual(len({context['requestId'] for context in seen}), 2)
            after = registry.observe(get)
            self.assertNotIn('temporaryHolds', after)
            self.assertNotIn('unsettledExecutions', after)
            self.assertEqual(before['scopeRevision'], after['scopeRevision'])


if __name__ == '__main__': unittest.main()
