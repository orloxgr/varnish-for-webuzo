"""Authenticated ordinary Warm projection; mock native transport, not WP proof."""
import hashlib
import hmac
import http.client
import shutil
import unittest
from test_cookie_delivery import proxy, cookies
from test_guest_publication import Guests, GUEST_BODY, register
from test_cold_public_selection import choices
from test_public_selection_runtime import control
from test_cms_cookie_choices import cache
from test_reuse_delivery_context import exact_authority_origin_hooks
from test_projected_variant_lookup import NAMES, ProjectedVariants
from test_guest_publication import GUEST_POLICY

PROJECTION = 'X-UltraCache-Warm-Projection'
AUTHORIZATION = PROJECTION + '-Authorization'
DELIVERY = 'X-UltraCache-Warm-Delivery'
FORMATS = ('text/html', 'text/html,image/webp', 'text/html,image/avif,image/webp')


def proof(path, capabilities, *, accept='', host='example.test', scheme='https', scope='/', key=b'b'*64, public_only=True, **replace):
    fields = dict(native=capabilities['X-UltraCache-VCL-Public-Selection-Native-Policy'],
        wordpress=capabilities['X-UltraCache-VCL-Public-Selection-WordPress-Policy'],
        guest=capabilities['X-UltraCache-VCL-Guest-Publication-Policy'],
        epoch=capabilities['X-UltraCache-VCL-Public-Selection-Epoch'])
    fields.update(replace)
    prefix = ('ultracache-warm-projection-v2','parent-v1','public-parent-only') if public_only else (
        'ultracache-warm-projection-v1','parent-v1')
    message='\n'.join((*prefix,'GET',host,path,scheme,accept,scope,
        fields['native'],fields['wordpress'],fields['guest'],fields['epoch']))
    return {PROJECTION:'parent-v1', AUTHORIZATION:'v1:'+hmac.new(key,message.encode(),hashlib.sha256).hexdigest(),
        **({'Accept':accept} if accept else {}), **({DELIVERY:'public-parent-only'} if public_only else {})}


class RecordedGuests(Guests):
    def __init__(self):
        super().__init__()
        self.origin_fields=[]
    def __call__(self,path,headers):
        self.origin_fields.append(dict(headers))
        return super().__call__(path,headers)


@unittest.skipUnless(shutil.which('varnishd'),'Native Varnish required; skips are not acceptance')
class GuestWarmProjection(unittest.TestCase):
    def test_plain_and_esi_comment_parent_bytes_remain_exact_for_warm(self):
        import base64
        import json
        from test_public_source import SourceApplication
        from test_delivery_continuation import BODY
        for body, count in (('<!DOCTYPE html><html>plain public</html>', 0),
                ('<!--esi <span>conditional ESI text</span> -->'+BODY, 3)):
            app = SourceApplication()
            def origin(path, headers):
                value, fields = app(path, headers)
                if headers.get('X-UltraCache-Delivery-Public-Source-Role') == 'parent-v1':
                    envelope = json.loads(value)
                    selected = envelope['selectedPublic']
                    selected['publicParent']['bodyBase64'] = base64.b64encode(body.encode()).decode()
                    selected['publicParent']['generation'] = hashlib.sha256(body.encode()).hexdigest()
                    selected['occurrences'] = count
                    selected['headers'] = [line.replace('Private-Count: 3', 'Private-Count: '+str(count))
                        for line in selected['headers'] if count or not line.startswith(
                            ('Surrogate-Control:', 'X-UltraCache-ESI-Shared-Parent:'))]
                    value = json.dumps(envelope)
                return value, fields
            with self.subTest(count=count), proxy('ultracache', origin) as get:
                status, caps, _ = control(get, enabled=True, names='', extra={
                    'X-UltraCache-Public-Selection-Public-Source-Version': '1',
                    'X-UltraCache-Public-Selection-Guest-Version': '1',
                    'X-UltraCache-Public-Selection-Guest-Policy': GUEST_POLICY})
                self.assertEqual(status, 200)
                for expected in ('MISS', 'HIT'):
                    result = get('/exact-parent', extra=proof('/exact-parent', caps))
                    self.assertEqual((result[0], cache(result[1]), result[2]), (200, expected, body))
                    self.assertEqual(dict(result[1]).get(DELIVERY), 'public-parent-only')
                self.assertEqual(len(app.wire), 1)

    def test_public_source_warm_cold_hot_exact_parent_then_normal_private_visitors(self):
        from test_public_source import SourceApplication
        from test_delivery_continuation import BODY
        app = SourceApplication()
        with proxy('ultracache', app, policies=choices(('shared_metric', 'shared'))) as get:
            status, caps, _ = control(get, enabled=True, names='', extra={
                'X-UltraCache-Public-Selection-Public-Source-Version': '1',
                'X-UltraCache-Public-Selection-Guest-Version': '1',
                'X-UltraCache-Public-Selection-Guest-Policy': GUEST_POLICY})
            self.assertEqual(status, 200)
            path = '/source-warm?utm_source=one'
            signed = proof(path, caps)
            for expected in ('MISS', 'HIT'):
                status, fields, body = get(path, extra=signed)
                self.assertEqual((status, cache(fields), body), (200, expected, BODY))
                self.assertEqual(hashlib.sha256(body.encode()).hexdigest(), hashlib.sha256(BODY.encode()).hexdigest())
                self.assertEqual(dict(fields).get(DELIVERY), 'public-parent-only')
                self.assertEqual(dict(fields).get(PROJECTION), 'parent-v1')
                self.assertEqual(dict(fields).get('X-UltraCache-Delivery-Outcome'), 'not-executed')
                self.assertEqual(dict(fields).get('X-UltraCache-Private-Cache'), 'NOT-APPLICABLE')
                self.assertEqual(cookies(fields), [])
                self.assertEqual(len(app.wire), 1, 'Hot parent Warm must not execute PHP or private ESI')
            self.assertEqual(app.wire[0][1].get('X-UltraCache-Delivery-Public-Source-Role'), 'parent-v1')
            # The same stored ESI parent still composes each real owner normally.
            for owner in ('A', 'B'):
                status, fields, body = get(path, 'shared_metric='+owner, {'X-Test-Visitor': owner})
                self.assertEqual((status, cache(fields)), (200, 'HIT'))
                self.assertEqual(body.count('private:'+owner), 2)
                self.assertEqual(body.count('nonce:'+owner), 1)
                self.assertNotIn(DELIVERY, dict(fields))
                self.assertEqual(dict(fields).get('X-UltraCache-Delivery-Outcome'), 'verified')
            self.assertEqual([h.get('X-UltraCache-Delivery-Phase') for _, h in app.wire],
                ['public-select', 'prepare', 'prepare'])
            self.assertEqual(control(get, operation='exact-purge', path=path)[0], 200)
            self.assertEqual(cache(get(path, extra=signed)[1]), 'MISS')
            self.assertEqual(len(app.wire), 4, 'Invalidated parent must be captured again')

    def test_projected_source_warm_retains_actual_tuple_without_cookie_replay(self):
        from test_projected_source_runtime import ProjectedApplication
        from test_delivery_continuation import BODY
        app = ProjectedApplication()
        policy = choices(('brandCurrency', 'variant'), ('cmp_language', 'variant'),
            ('optional', 'variant'), ('tracking', 'shared'))
        with proxy('ultracache', app, policies=policy) as get:
            status, caps, _ = control(get, enabled=True, names='brandCurrency,cmp_language,optional', extra={
                'X-UltraCache-Public-Selection-Public-Source-Version': '1',
                'X-UltraCache-Public-Selection-Public-Source-Projection-Version': '1',
                'X-UltraCache-Public-Selection-Guest-Version': '1',
                'X-UltraCache-Public-Selection-Guest-Policy': GUEST_POLICY})
            self.assertEqual(status, 200)
            path = '/projected-warm'
            for expected in ('MISS', 'HIT'):
                status, fields, body = get(path, 'brandCurrency=EUR; cmp_language=el; tracking=A', proof(path, caps))
                self.assertEqual((status, cache(fields), body), (200, expected, BODY))
                self.assertEqual(dict(fields).get(DELIVERY), 'public-parent-only')
                self.assertEqual(cookies(fields), [])
                self.assertEqual(len(app.calls), 3)
                self.assertNotIn('X-UltraCache-Warm-Guest', dict(fields))
            self.assertEqual([h.get('X-UltraCache-Delivery-Public-Source-Role') for _, h in app.calls],
                ['resolver-v1', 'parent-v1', None])
            before = len(app.calls)
            bad = proof(path, caps, key=b'wrong')
            bad[DELIVERY] = 'public-parent-only'
            self.assertEqual(get(path, extra=bad)[0], 403)
            self.assertEqual(len(app.calls), before)

    def test_one_parent_warm_covers_image_accepts_but_proof_still_binds_actual_accept(self):
        app = RecordedGuests()
        with proxy('ultracache', app) as get:
            self.assertEqual(register(get)[0], 200)
            caps = control(get)[1]
            path = '/unified-parent'
            self.assertEqual(get(path, extra={'Accept': 'text/html'})[0], 200)
            parent = get(path, extra=proof(path, caps, accept='text/html'))
            self.assertEqual(parent[0], 200)
            self.assertEqual(dict(parent[1]).get(PROJECTION), 'parent-v1')
            before = len(app.calls)
            forged = proof(path, caps, accept='text/html')
            forged['Accept'] = 'text/html,image/webp'
            self.assertEqual(get(path, extra=forged)[0], 403)
            self.assertEqual(len(app.calls), before)
            get.stop_origin()
            for accept in FORMATS:
                guest = get(path, extra={'Accept': accept})
                self.assertEqual((guest[0], cache(guest[1]), guest[2]), (200, 'HIT', GUEST_BODY))
            self.assertEqual(len(app.calls), before)

    def test_authenticated_parent_warm_accepts_actual_public_variant_inputs(self):
        app = ProjectedVariants()
        policy = choices(*[(name, 'variant') for name in NAMES],
            ('shared_metric', 'shared'), ('actual_private', 'private'))
        with proxy('ultracache', app, policies=policy) as get:
            status, caps, _ = control(get, enabled=True, names=','.join(NAMES), extra={
                'X-UltraCache-Public-Selection-Public-Source-Version': '1',
                'X-UltraCache-Public-Selection-Public-Source-Projection-Version': '1',
                'X-UltraCache-Public-Selection-Guest-Version': '1',
                'X-UltraCache-Public-Selection-Guest-Policy': GUEST_POLICY})
            self.assertEqual(status, 200)
            path = '/public-parent'; bodies = []
            signed = proof(path, caps, accept='text/html')
            for variant in ('one', 'two'):
                raw = 'cmplz_id=' + variant + '; shared_metric=warm'
                first = get(path, raw, signed)
                self.assertEqual((first[0], cache(first[1])), (200, 'MISS'), first)
                self.assertEqual(dict(first[1]).get(PROJECTION), 'parent-v1')
                self.assertNotIn('X-UltraCache-Guest-Publication', dict(first[1]))
                repeat = get(path, raw, signed)
                self.assertEqual((repeat[0], cache(repeat[1]), repeat[2]), (200, 'HIT', first[2]))
                bodies.append(first[2])
            self.assertNotEqual(bodies[0], bodies[1])
            before = len(app.calls)
            self.assertEqual(get(path, 'cmplz_id=one', proof(path, caps, accept='text/html', key=b'wrong'))[0], 403)
            self.assertEqual(len(app.calls), before)
            private = get(path, 'actual_private=owner', signed)
            self.assertEqual(private[0], 200)
            self.assertNotIn(PROJECTION, dict(private[1]))
            self.assertEqual(app.calls[-1][1].get('Cookie'), 'actual_private=owner')

    def test_exact_authority_warm_binds_accepted_host_and_all_real_accept_formats(self):
        app=RecordedGuests();app.formats=True
        authority='127.0.0.1:38751'
        accepts=('text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8')
        with proxy('ultracache',app,transform=exact_authority_origin_hooks,
            site_settings={'domain':'127.0.0.1','names':['127.0.0.1']}) as original:
            def get(path,cookie=None,extra=None):
                headers={'Host':authority,'X-Forwarded-Proto':'http'};headers.update(extra or {})
                return original(path,cookie,headers)
            get.endpoint=original.endpoint
            get.request_headers=dict(original.request_headers,Host=authority,**{'X-Forwarded-Proto':'http'})
            status,caps,_=register(get);self.assertEqual(status,200)
            accepted_host=caps['X-UltraCache-VCL-Public-Selection-Canonical-Host']
            self.assertEqual(accepted_host,authority)
            for bucket,accept in zip(('orig','webp','avif'),accepts):
                path='/actual-accept-'+bucket
                first=get(path,extra={'Accept':accept})
                self.assertEqual(first[0],200);self.assertEqual(first[2],GUEST_BODY+bucket)
                self.assertEqual(dict(first[1]).get('X-UltraCache-Guest-Publication'),'1')
                before=len(app.calls)
                # A hostname-only proof does not bind the accepted authority.
                rejected=get(path,extra=proof(path,caps,accept=accept,host='127.0.0.1',scheme='http'))
                self.assertEqual(rejected[0],403);self.assertEqual(len(app.calls),before)
                accepted=get(path,extra=proof(path,caps,accept=accept,host=accepted_host,scheme='http'))
                self.assertEqual(accepted[0],200);self.assertEqual(dict(accepted[1]).get(PROJECTION),'parent-v1')
                self.assertNotIn('X-UltraCache-Guest-Publication',dict(accepted[1]))
                self.assertNotIn('X-UltraCache-VCL-Public-Selection-Canonical-Host',dict(accepted[1]))
                before=len(app.calls)
                for visitor in ('independent-A','independent-B'):
                    guest=get(path,extra={'Accept':accept,'X-Test-Visitor':visitor})
                    self.assertEqual((guest[0],cache(guest[1]),guest[2]),(200,'HIT',GUEST_BODY+bucket))
                    self.assertEqual(dict(guest[1]).get('X-UltraCache-Guest-Publication'),'1')
                self.assertEqual(len(app.calls),before)

    def test_warm_both_namespaces_then_first_stateful_html_is_hit(self):
        app=RecordedGuests()
        with proxy('ultracache',app,policies=choices(('shared_metric','shared'))) as get:
            status,caps,_=register(get)
            self.assertEqual(status,200)
            self.assertEqual(caps['X-UltraCache-VCL-Warm-Projection-Version'],'1')
            self.assertEqual(caps['X-UltraCache-VCL-Public-Selection-Canonical-Host'],'example.test')
            path='/both?unknown=one&utm_source=warm&unknown=two'
            self.assertEqual(get(path)[2],GUEST_BODY)
            status,fields,parent=get(path,extra=proof(path,caps))
            self.assertEqual((status,cache(fields)),(200,'MISS'))
            self.assertNotEqual(parent,GUEST_BODY)
            self.assertNotIn('X-UltraCache-Guest-Publication',dict(fields))
            self.assertEqual(dict(fields).get(PROJECTION),'parent-v1')
            self.assertEqual([phase for _,phase,_ in app.calls],['public-select','public-select'])
            for original in app.origin_fields:
                self.assertNotIn(PROJECTION,original)
                self.assertNotIn(AUTHORIZATION,original)
            repeated=get(path,extra=proof(path,caps))
            self.assertEqual((repeated[0],cache(repeated[1])),(200,'HIT'))
            self.assertEqual(dict(repeated[1]).get(PROJECTION),'parent-v1')
            # Guest still has zero-origin complete HIT; parent prepares each
            # actual owner independently while its public HTML is already HIT.
            before=len(app.calls)
            self.assertEqual(get('/both?unknown=one&utm_source=visitor&unknown=two')[2],GUEST_BODY)
            self.assertNotIn(PROJECTION,dict(get(path)[1]))
            self.assertEqual(len(app.calls),before)
            for owner in ('A','B'):
                status,fields,body=get(path,'shared_metric='+owner,{'X-Test-Visitor':owner})
                self.assertEqual((status,cache(fields)),(200,'HIT'))
                self.assertIn('private:'+owner,body)
                self.assertEqual(app.calls[-1][1],'prepare')
                self.assertNotIn('X-UltraCache-Guest-Publication',dict(fields))
                self.assertNotIn(PROJECTION,dict(fields))
            self.assertEqual(len(app.guest_requests),1)
            self.assertEqual(control(get,operation='exact-purge',path=path)[0],200)
            self.assertEqual(cache(get(path)[1]),'MISS')
            self.assertEqual(cache(get(path,extra=proof(path,caps))[1]),'MISS')

    def test_parent_warm_does_not_change_scope_registry_or_guest_selection(self):
        app=RecordedGuests();app.formats=True
        with proxy('ultracache',app,policies=choices(('shared_metric','shared'))) as get:
            self.assertEqual(register(get)[0],200)
            caps=control(get)[1]
            for index,accept in enumerate(FORMATS):
                path='/format-'+str(index)
                self.assertEqual(get(path,extra={'Accept':accept})[0],200)
                parent=get(path,extra=proof(path,caps,accept=accept))
                self.assertEqual(parent[0],200)
                self.assertEqual(dict(parent[1]).get(PROJECTION),'parent-v1')
                again=control(get)[1]
                for name in ('X-UltraCache-VCL-Public-Selection-Epoch','X-UltraCache-VCL-Guest-Publication-Policy'):
                    self.assertEqual(again[name],caps[name])
                for owner in ('A','B'):
                    status,fields,body=get(path,extra={'Accept':accept,'X-Test-Visitor':owner})
                    self.assertEqual((status,cache(fields)),(200,'HIT'))
                    self.assertTrue(body.startswith(GUEST_BODY))
                    self.assertEqual(cookies(fields),[])
                    self.assertEqual(dict(fields).get('X-UltraCache-Guest-Publication'),'1')
                status,fields,body=get(path,'shared_metric=A',{'Accept':accept,'X-Test-Visitor':'A'})
                self.assertEqual((status,cache(fields)),(200,'HIT'))
                self.assertIn('private:A',body)

    def test_proof_is_bound_to_request_and_registration(self):
        app=RecordedGuests()
        with proxy('ultracache',app) as get:
            self.assertEqual(register(get)[0],200)
            caps=control(get)[1]
            for changed in ({'key':b'wrong'},{'host':'other.test'},{'scheme':'http'},
                {'accept':'text/plain'},{'scope':'/child/'},{'native':'0'*64},
                {'wordpress':'0'*64},{'guest':'0'*64},{'epoch':'0'*64}):
                header=proof('/bound',caps,**changed)
                if 'accept' in changed:header.pop('Accept')
                self.assertEqual(get('/bound',extra=header)[0],403,changed)
            self.assertEqual(get('/changed',extra=proof('/bound',caps))[0],403)
            self.assertEqual(app.calls,[])
            # Invalid proof cannot poison the normal guest namespace.
            self.assertEqual(get('/bound')[2],GUEST_BODY)
            self.assertEqual(cache(get('/bound')[1]),'HIT')
            old=proof('/removed',caps)
            self.assertEqual(control(get,enabled=False)[0],200)
            self.assertEqual(get('/removed',extra=old)[0],403)

    def test_malformed_duplicates_and_empty_cookie_cannot_force_parent(self):
        app=RecordedGuests()
        with proxy('ultracache',app,policies=choices(('shared_metric','shared'))) as get:
            self.assertEqual(register(get)[0],200);caps=control(get)[1]
            for headers in ({PROJECTION:'parent-v1'},{AUTHORIZATION:'v1:'+'0'*64},
                {**proof('/bad',caps),PROJECTION:'guest-v1'},
                {**proof('/bad',caps),AUTHORIZATION:'v1:bad'}):
                self.assertEqual(get('/bad',extra=headers)[0],403)
            header=proof('/bad',caps)
            self.assertEqual(get('/bad','',header)[0],403)
            for duplicated in (PROJECTION,AUTHORIZATION,DELIVERY):
                client=http.client.HTTPConnection(*get.endpoint,timeout=15)
                try:
                    client.putrequest('GET','/bad',skip_host=True)
                    for k,v in {**get.request_headers,**header}.items():client.putheader(k,v)
                    client.putheader(duplicated,header[duplicated]);client.endheaders()
                    response=client.getresponse();response.read()
                    self.assertEqual(response.status,403)
                finally:client.close()
            self.assertEqual(app.calls,[])

    def test_private_routes_and_cookie_policy_still_win(self):
        app=RecordedGuests()
        with proxy('ultracache',app) as get:
            self.assertEqual(register(get)[0],200);caps=control(get)[1]
            for path,cookie in (('/wp-admin/',None),('/private','PHPSESSID=real')):
                result=get(path,cookie,proof(path,caps))
                self.assertEqual(result[0],200)
                self.assertNotEqual(cache(result[1]),'HIT')
                self.assertEqual(app.calls[-1][1],None)
                self.assertEqual(app.calls[-1][2],cookie)
                self.assertNotIn(AUTHORIZATION,app.origin_fields[-1])

    def test_basic_does_not_advertise_or_forward_warm_selector(self):
        seen=[]
        def origin(path,headers):
            seen.append(dict(headers));return '<html>basic</html>',[('Cache-Control','public, max-age=120'),
                (PROJECTION,'parent-v1'),(AUTHORIZATION,'origin-forged')]
        with proxy('basic',origin) as get:
            status,caps,_=control(get)
            self.assertEqual(status,200)
            self.assertNotIn('X-UltraCache-VCL-Warm-Projection-Version',caps)
            response=get('/basic',extra={PROJECTION:'parent-v1',AUTHORIZATION:'forged'})
            self.assertEqual(response[0],200)
            self.assertNotIn(PROJECTION,dict(response[1]));self.assertNotIn(AUTHORIZATION,dict(response[1]))
            self.assertNotIn(PROJECTION,seen[-1]);self.assertNotIn(AUTHORIZATION,seen[-1])
            self.assertNotIn(PROJECTION,dict(get('/basic')[1]))


if __name__=='__main__':unittest.main()
