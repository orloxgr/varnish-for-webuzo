"""Native actual-tuple continuation with declared mock issuers, not WP evidence."""
import base64
import copy
import json
import shutil
import unittest

from test_cookie_delivery import proxy, cookies
from test_cms_cookie_choices import cache
from test_cold_public_selection import choices
from test_public_source import SourceApplication
from test_public_selection_runtime import control


def tuple_for(currency='EUR'):
    return dict(version=1, bucket='actual-'+currency, locale='el_GR', language='el', cookieValues=[
        dict(name='brandCurrency', valueBase64=base64.b64encode(currency.encode()).decode()),
        dict(name='cmp_language', valueBase64='ZWw='), dict(name='optional', valueBase64=None)])


class ProjectedApplication:
    def __init__(self, change=False, unstable=False, raw=False, wrong=False):
        self.normal = SourceApplication()
        self.calls = []
        self.resolvers = 0
        self.change = change
        self.unstable = unstable
        self.raw = raw
        self.wrong = wrong

    def __call__(self, path, headers):
        self.calls.append((path, dict(headers)))
        role = headers.get('X-UltraCache-Delivery-Public-Source-Role')
        if role == 'resolver-v1':
            self.resolvers += 1
            currency = 'GBP' if self.change and self.resolvers > 1 and not self.unstable else 'EUR'
            result = dict(schemaVersion=1, requestId=headers['X-UltraCache-Delivery-Request'],
                originalUrl=headers['X-UltraCache-Delivery-Original-URL'], resolvedPublic=tuple_for(currency))
            return json.dumps(result), [('Content-Type', 'application/vnd.ultracache.delivery+json'),
                ('X-UltraCache-Delivery-Public-Selection-Version', '1'),
                ('X-UltraCache-Delivery-Public-Source-Version', '1'),
                ('X-UltraCache-Delivery-Public-Source-Outcome', 'resolved'),
                ('Cache-Control', 'private, no-store'),
                ('Set-Cookie', 'brandCurrency='+currency+'; Path=/; SameSite=Lax'),
                ('Set-Cookie', 'optional=; Path=/; Max-Age=0')]
        if headers.get('X-UltraCache-Delivery-Public-Source-Fallback'):
            if self.raw:
                return 'actual raw private fallback', [('Cache-Control', 'private, no-store'),
                    ('Set-Cookie', 'brandCurrency=JPY; Path=/; SameSite=Lax')]
            result = dict(schemaVersion=1, requestId=headers['X-UltraCache-Delivery-Request'],
                originalUrl=headers['X-UltraCache-Delivery-Original-URL'], privateDocument=dict(
                    status=200, contentType='text/html', bodyBase64=base64.b64encode(b'actual private fallback').decode()))
            return json.dumps(result), [('Content-Type', 'application/vnd.ultracache.delivery+json'),
                ('X-UltraCache-Delivery-Public-Selection-Version', '1'), ('Cache-Control', 'private, no-store')]
        if role == 'parent-v1' and self.change and (self.resolvers == 1 or self.unstable):
            result = dict(schemaVersion=1, requestId=headers['X-UltraCache-Delivery-Request'],
                originalUrl=headers['X-UltraCache-Delivery-Original-URL'], resolvedPublic=tuple_for('GBP'))
            return json.dumps(result), [('Content-Type', 'application/vnd.ultracache.delivery+json'),
                ('X-UltraCache-Delivery-Public-Selection-Version', '1'),
                ('X-UltraCache-Delivery-Public-Source-Version', '1'),
                ('X-UltraCache-Delivery-Public-Source-Outcome', 'resolved'),
                ('Cache-Control', 'private, no-store'), ('Set-Cookie', 'pure_source=never-replay; Path=/')]
        result = self.normal(path, headers)
        if headers.get('X-UltraCache-Delivery-Phase') == 'public-select':
            body, fields = result; value = json.loads(body)
            expected = json.loads(base64.b64decode(headers['X-UltraCache-Delivery-Public-Source-Projection']))
            if self.wrong and role == 'parent-v1': expected = tuple_for('GBP')
            value['selectedPublic']['resolvedPublic'] = expected
            return json.dumps(value), fields
        return result


@unittest.skipUnless(shutil.which('varnishd'), 'Native Varnish required')
class ProjectedSourceRuntime(unittest.TestCase):
    def policy(self):
        return choices(('brandCurrency', 'variant'), ('cmp_language', 'variant'),
            ('optional', 'variant'), ('cart', 'shared'), ('tracking', 'shared'))

    def declare(self, get):
        status, fields, _ = control(get, enabled=True, names='brandCurrency', extra={
            'X-UltraCache-Public-Selection-Public-Source-Version': '1',
            'X-UltraCache-Public-Selection-Public-Source-Projection-Version': '1'})
        self.assertEqual(status, 200)
        self.assertEqual(fields.get('X-UltraCache-VCL-Public-Selection-Public-Source-Projection-Version'), '1')

    def test_real_resolver_issuer_then_pure_parent_then_effective_personal_and_warm_lookup(self):
        app = ProjectedApplication()
        original = 'cart=A; brandCurrency=USD; optional=old; cmp_language=el; tracking=original'
        with proxy('ultracache', app, policies=self.policy()) as get:
            self.declare(get)
            status, fields, body = get('/projected?utm_source=one', original, extra={'X-Test-Visitor': 'A'})
            self.assertEqual((status, cache(fields)), (200, 'MISS'))
            self.assertIn('private:A', body)
            self.assertEqual(len(app.calls), 3)
            resolver, source, personal = app.calls
            self.assertEqual(resolver[0], '/projected?utm_source=one')
            self.assertEqual(resolver[1].get('Cookie'), original)
            self.assertNotIn('X-UltraCache-Delivery-Public-Source-Projection', resolver[1])
            self.assertEqual(source[0], '/projected')
            self.assertEqual(source[1].get('Cookie'), 'brandCurrency=EUR; cmp_language=el')
            self.assertEqual(json.loads(base64.b64decode(source[1]['X-UltraCache-Delivery-Public-Source-Projection'])), tuple_for())
            self.assertEqual(personal[0], '/projected?utm_source=one')
            self.assertEqual(personal[1].get('Cookie'), 'cart=A; tracking=original; brandCurrency=EUR; cmp_language=el')
            self.assertNotIn('X-UltraCache-Delivery-Public-Source-Role', personal[1])
            self.assertEqual(cookies(fields), ['brandCurrency=EUR; Path=/; SameSite=Lax',
                'optional=; Path=/; Max-Age=0', 'visitor_session=personal; Path=/; HttpOnly'])
            status, fields, body = get('/projected?utm_source=two',
                'cart=B; brandCurrency=EUR; cmp_language=el; tracking=new', extra={'X-Test-Visitor': 'B'})
            self.assertEqual((status, cache(fields)), (200, 'HIT'))
            self.assertIn('private:B', body)
            self.assertEqual(app.resolvers, 1)
            self.assertEqual(len(app.calls), 4)
            self.assertEqual(app.calls[-1][1].get('X-UltraCache-Delivery-Phase'), 'prepare')

    def test_private_prepare_return_keeps_the_canonical_public_lookup_key(self):
        app = ProjectedApplication()
        # The classifier follows rule order; publication sorts literal names.
        # A real personal continuation must return to that same public object.
        policy = choices(('cmp_language', 'variant'), ('brandCurrency', 'variant'),
            ('optional', 'variant'), ('cart', 'shared'), ('tracking', 'shared'))
        with proxy('ultracache', app, policies=policy) as get:
            self.declare(get)
            cookie = 'cart=A; cmp_language=el; brandCurrency=EUR'
            first = get('/canonical-return', cookie, extra={'X-Test-Visitor': 'A'})
            self.assertEqual((first[0], cache(first[1])), (200, 'MISS'))
            repeated = get('/canonical-return', cookie, extra={'X-Test-Visitor': 'A'})
            self.assertEqual((repeated[0], cache(repeated[1])), (200, 'HIT'))
            self.assertIn('private:A', repeated[2])
            self.assertEqual(app.resolvers, 1)
            self.assertEqual(len(app.calls), 4)
            self.assertEqual(app.calls[-1][1].get('X-UltraCache-Delivery-Phase'), 'prepare')

    def test_changed_source_returns_to_real_visitor_issuer_once_without_replaying_source_cookie(self):
        app = ProjectedApplication(change=True)
        with proxy('ultracache', app, policies=self.policy()) as get:
            self.declare(get)
            status, fields, body = get('/changed', 'brandCurrency=USD; cmp_language=el; cart=A')
            self.assertEqual(status, 200)
            self.assertEqual(app.resolvers, 2)
            roles = [h.get('X-UltraCache-Delivery-Public-Source-Role') for _, h in app.calls]
            self.assertEqual(roles, ['resolver-v1', 'parent-v1', 'resolver-v1', 'parent-v1', None])
            self.assertIn('brandCurrency=GBP; Path=/; SameSite=Lax', cookies(fields))
            self.assertFalse(any('pure_source' in cookie or 'source_session' in cookie for cookie in cookies(fields)))
            self.assertIn('brandCurrency=EUR', app.calls[2][1]['Cookie'])
            self.assertEqual(app.calls[3][1]['Cookie'], 'brandCurrency=GBP; cmp_language=el')
            self.assertIn('private:guest', body)

    def test_unstable_actual_source_private_fallback_does_not_loop_or_cache(self):
        app = ProjectedApplication(change=True, unstable=True)
        with proxy('ultracache', app, policies=self.policy()) as get:
            self.declare(get)
            status, fields, body = get('/unstable', 'brandCurrency=USD; cmp_language=el; cart=A')
            self.assertEqual((status, body), (200, 'actual private fallback'))
            self.assertEqual(app.resolvers, 2)
            self.assertEqual(len(app.calls), 5)
            self.assertEqual(dict(fields).get('X-UltraCache-Public-Source-Outcome'), 'unstable-public-projection')
            self.assertNotEqual(dict(fields).get('X-UltraCache-Delivery-Outcome'), 'verified')
            self.assertNotIn('X-UltraCache-Delivery-Public-Source-Projection', app.calls[-1][1])
            self.assertEqual(app.calls[-1][1]['X-UltraCache-Delivery-Public-Source-Fallback'], 'unstable-public-projection')
            self.assertFalse(any('GBP' in cookie or 'pure_source' in cookie for cookie in cookies(fields)))

    def test_raw_private_fallback_streams_with_real_issuer_cookie_chronology(self):
        app = ProjectedApplication(change=True, unstable=True, raw=True)
        with proxy('ultracache', app, policies=self.policy()) as get:
            self.declare(get)
            status, fields, body = get('/raw-private', 'brandCurrency=USD; cmp_language=el; cart=A')
            self.assertEqual((status, body), (200, 'actual raw private fallback'))
            self.assertEqual(len(app.calls), 5)
            self.assertEqual(cookies(fields)[-1], 'brandCurrency=JPY; Path=/; SameSite=Lax')
            self.assertTrue(cookies(fields)[0].startswith('brandCurrency=EUR;'))
            self.assertFalse(any('GBP' in cookie or 'pure_source' in cookie for cookie in cookies(fields)))

    def test_wrong_tuple_cannot_label_a_parent_or_complete_personal_delivery(self):
        app = ProjectedApplication(wrong=True)
        with proxy('ultracache', app, policies=self.policy()) as get:
            self.declare(get)
            status, fields, _ = get('/wrong-tuple', 'brandCurrency=USD; cmp_language=el')
            self.assertEqual(status, 503)
            self.assertEqual(len(app.calls), 2)
            self.assertEqual(dict(fields).get('X-UltraCache-Public-Source-Outcome'), 'protocol-error')
            self.assertNotEqual(dict(fields).get('X-UltraCache-Delivery-Outcome'), 'verified')

    def test_unfinished_source_uses_one_actual_private_execution_per_visitor_without_projection_mix(self):
        app=ProjectedApplication();personal=[]
        def origin(path,headers):
            if headers.get('X-UltraCache-Delivery-Public-Source-Role')=='parent-v1':
                app.calls.append((path,dict(headers)))
                return 409,b'',[('Cache-Control','private, no-store'),
                    ('X-UltraCache-Delivery-Public-Source-Version','1'),
                    ('X-UltraCache-Delivery-Public-Source-Outcome','unavailable')]
            if headers.get('X-UltraCache-Delivery-Public-Source-Fallback')=='public-source-unavailable':
                app.calls.append((path,dict(headers)));personal.append(dict(headers))
                visitor=headers['X-Test-Visitor']
                value=dict(schemaVersion=1,requestId=headers['X-UltraCache-Delivery-Request'],
                    originalUrl=headers['X-UltraCache-Delivery-Original-URL'],privateDocument=dict(
                        status=200,contentType='text/html',bodyBase64=base64.b64encode(('actual-private:'+visitor).encode()).decode()))
                return json.dumps(value),[('Content-Type','application/vnd.ultracache.delivery+json'),
                    ('X-UltraCache-Delivery-Public-Selection-Version','1'),('Cache-Control','private, no-store'),
                    ('Set-Cookie','private_session='+visitor+'; Path=/; HttpOnly')]
            return app(path,headers)
        with proxy('ultracache',origin,policies=self.policy()) as get:
            self.declare(get)
            for visitor in ('A','B'):
                status,fields,body=get('/unfinished','brandCurrency=USD; cart='+visitor,extra={'X-Test-Visitor':visitor})
                self.assertEqual((status,body),(200,'actual-private:'+visitor))
                self.assertEqual(cookies(fields)[-1],'private_session='+visitor+'; Path=/; HttpOnly')
                self.assertTrue(cookies(fields)[0].startswith('brandCurrency=EUR;'))
                self.assertNotIn('X-UltraCache-Delivery-Public-Source-Projection',personal[-1])
                self.assertNotIn('X-UltraCache-Delivery-Public-Source-Role',personal[-1])
                self.assertIn('cart='+visitor,personal[-1].get('Cookie',''))
                self.assertIn('private, no-store',dict(fields).get('Cache-Control',''))
            self.assertEqual(len(app.calls),6,'Only resolver, source and original private execution per visitor')
            self.assertEqual(len(personal),2)

    def test_unavailable_source_cannot_replace_private_fallback_with_a_claimed_public_selection(self):
        app=ProjectedApplication()
        def origin(path,headers):
            if headers.get('X-UltraCache-Delivery-Public-Source-Role')=='parent-v1':
                return 409,b'',[('Cache-Control','private, no-store'),
                    ('X-UltraCache-Delivery-Public-Source-Version','1'),
                    ('X-UltraCache-Delivery-Public-Source-Outcome','unavailable')]
            if headers.get('X-UltraCache-Delivery-Public-Source-Fallback'):
                fields=dict(headers);fields.pop('X-UltraCache-Delivery-Public-Source-Fallback')
                fields['X-UltraCache-Delivery-Public-Source-Projection']=base64.b64encode(json.dumps(tuple_for()).encode()).decode()
                return app(path,fields)
            return app(path,headers)
        with proxy('ultracache',origin,policies=self.policy()) as get:
            self.declare(get)
            status,fields,_=get('/unfinished-invalid','brandCurrency=USD; cart=A')
            self.assertEqual(status,503)
            self.assertNotEqual(dict(fields).get('X-UltraCache-Delivery-Outcome'),'verified')

    def test_each_real_phase_has_exact_execution_and_only_personal_attaches_private_candidate(self):
        import test_mutation_coverage_runtime as coverage
        import test_reuse_authority as authority
        from test_execution_drain_runtime import NativeExecutionDrain
        app = ProjectedApplication(); seen = []
        def origin(path, headers):
            context = coverage.context(self, headers, 'GET', path); seen.append(context)
            body, fields = app(path, headers)
            return body, fields+[coverage.response_receipt(context)]
        with proxy('ultracache', origin, policies=self.policy()) as get:
            status, _, _ = control(get, enabled=True, names='brandCurrency', extra={
                'X-UltraCache-Public-Selection-Public-Source-Version': '1',
                'X-UltraCache-Public-Selection-Public-Source-Projection-Version': '1',
                'X-UltraCache-Public-Selection-Reuse-Version': '1',
                'X-UltraCache-Public-Selection-Reuse-Policy': authority.REUSE_POLICY,
                'X-UltraCache-Public-Selection-Coverage-Version': '1',
                'X-UltraCache-Public-Selection-Coverage-Policy': coverage.POLICY,
                'X-UltraCache-Public-Selection-Execution-Drain-Version': '1'})
            self.assertEqual(status, 200)
            gate = NativeExecutionDrain(); before = gate.ready(get)
            status, _, _ = get('/projected-proof?utm_source=actual',
                'brandCurrency=USD; cmp_language=el; cart=actual-owner')
            self.assertEqual(status, 200)
            self.assertEqual([path for path, _ in app.calls],
                ['/projected-proof?utm_source=actual', '/projected-proof', '/projected-proof?utm_source=actual'])
            for _, fields in app.calls[:2]:
                self.assertNotIn('X-UltraCache-Delivery-Reuse-Candidate-Version', fields)
                self.assertNotIn('X-UltraCache-Delivery-Reuse-Context', fields)
            self.assertEqual(app.calls[2][1].get('X-UltraCache-Delivery-Reuse-Candidate-Version'), '1')
            self.assertEqual(len(seen), 3)
            self.assertEqual(gate.ended(get).get('temporaryHolds'), 3)
            for context in seen: gate.drain(get, context)
            after = gate.observe(get)
            self.assertEqual(after.get('temporaryHolds', 0), 0)
            self.assertEqual(before['scopeRevision'], after['scopeRevision'])


if __name__ == '__main__': unittest.main()
