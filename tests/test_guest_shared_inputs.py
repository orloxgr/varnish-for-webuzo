"""Native mocked transport only; actual WP/browser qualification is separate."""
import copy
import json
import shutil
import subprocess
import unittest
from test_cookie_delivery import proxy,cookies
from test_cold_public_selection import choices
from test_guest_publication import Guests,GUEST_BODY,GUEST_POLICY,register
from test_public_selection_runtime import control
from test_cms_cookie_choices import cache
from test_reuse_cookie_inputs import seal_recipe

def declaration(names=('actual_session',),prefixes=('actual_auth_',),fragments=True):
    rows=[dict(url='/nested/private',provider='registered-provider',occurrences=2)] if fragments else []
    recipe=seal_recipe(dict(inputs=dict(cookieNames=list(names),cookiePrefixes=list(prefixes),phpMaxInputVars=1000),fragments=rows))
    return dict(version=1,privateOccurrences=2 if fragments else 0,recipe=recipe)

class SharedGuests(Guests):
    def __init__(self):
        super().__init__();self.inputs=declaration();self.negotiate=True;self.vary_cookie=False
    def __call__(self,path,headers):
        result=super().__call__(path,headers)
        if headers.get('X-UltraCache-Delivery-Guest-Publication-Version')=='1':
            self.asserted_version=headers.get('X-UltraCache-VCL-Guest-Inputs-Version')
            body,fields=result;payload=json.loads(body)
            if self.negotiate and self.asserted_version=='1':payload['guestPublic']['guestInputs']=copy.deepcopy(self.inputs)
            if self.vary_cookie:payload['guestPublic']['headers'].append('Vary: Cookie')
            return json.dumps(payload),fields
        return result

@unittest.skipUnless(shutil.which('varnishd'),'Native Varnish required; skips are not acceptance')
class SharedGuestInputs(unittest.TestCase):
    def test_unrelated_shared_first_admissions_reuse_one_complete_guest_without_origin(self):
        app=SharedGuests()
        with proxy('ultracache',app,policies=choices(('metric','shared'))) as get:
            self.assertEqual(register(get)[0],200)
            self.assertEqual(get('/shared')[2],GUEST_BODY)
            self.assertEqual(app.asserted_version,'1')
            self.assertEqual(register(get)[0],200) # same declaration must retain evidence
            get.stop_origin()
            for owner in ('first-A','first-B'):
                status,fields,body=get('/shared','metric='+owner,{'X-Test-Visitor':owner})
                self.assertEqual((status,cache(fields),body),(200,'HIT',GUEST_BODY))
                self.assertEqual(dict(fields).get('X-UltraCache-Guest-Publication'),'1')
                self.assertEqual(cookies(fields),[])
                log=subprocess.check_output(['varnishlog','-n',str(get.instance),'-d','-g','request',
                    '-q','ReqHeader:X-Test-Visitor eq "'+owner+'"','-i','Begin,Link,ReqURL'],text=True)
                self.assertNotIn('bereq',log)
            self.assertEqual(len(app.calls),1)

    def test_actual_shared_provider_inputs_keep_original_cookie_and_stateful_route(self):
        app=SharedGuests()
        policy=choices(('metric','shared'),('actual_session','shared'),('actual_auth_user','shared'))
        with proxy('ultracache',app,policies=policy) as get:
            self.assertEqual(register(get)[0],200);get('/provider')
            for name in ('actual_session','actual_auth_user'):
                raw=name+'=real; metric=one'
                before=len(app.calls)
                status,fields,body=get('/provider',raw,{'X-Test-Visitor':name})
                self.assertEqual(status,200);self.assertIn('private:'+name,body)
                self.assertNotIn('X-UltraCache-Guest-Publication',dict(fields))
                self.assertTrue(app.calls[before:]);self.assertTrue(all(c==raw for _,_,c in app.calls[before:]))
            self.assertEqual(len(app.guest_requests),1)

    def test_cold_shared_candidate_falls_back_without_sending_cookie_to_guest_origin(self):
        app=SharedGuests()
        with proxy('ultracache',app,policies=choices(('metric','shared'))) as get:
            register(get)
            status,fields,body=get('/cold','metric=original',{'X-Test-Visitor':'cold'})
            self.assertEqual(status,200);self.assertIn('private:cold',body)
            self.assertNotIn('X-UltraCache-Guest-Publication',dict(fields))
            self.assertFalse(app.guest_requests);self.assertTrue(app.calls)
            self.assertTrue(all(c=='metric=original' for _,_,c in app.calls))

    def test_missing_invalid_and_changed_policy_evidence_retains_legacy_and_stateful_fallback(self):
        for kind in ('missing','malformed','policy'):
            with self.subTest(kind=kind):
                app=SharedGuests()
                if kind=='missing':app.negotiate=False
                if kind=='malformed':app.inputs['recipe']['digest']='0'*64
                with proxy('ultracache',app,policies=choices(('metric','shared'))) as get:
                    register(get);get('/proof')
                    self.assertEqual(cache(get('/proof')[1]),'HIT')
                    if kind=='policy':
                        control(get,enabled=True,names='metric',extra={
                            'X-UltraCache-Public-Selection-Guest-Version':'1',
                            'X-UltraCache-Public-Selection-Guest-Policy':GUEST_POLICY})
                    status,fields,body=get('/proof','metric=x',{'X-Test-Visitor':kind})
                    self.assertEqual(status,200);self.assertIn('private:'+kind,body)
                    self.assertNotIn('X-UltraCache-Guest-Publication',dict(fields))

    def test_explicit_variant_and_private_cookies_do_not_enter_extended_guest_key(self):
        for name,action in (('cmp_value','variant'),('secret','private'),
                            ('ultracache_esi_optin','variant'),('ultracache_esi_optin','private')):
            with self.subTest(name=name):
                app=SharedGuests();policy=choices(*([(name,action)] if action else []))
                with proxy('ultracache',app,policies=policy) as get:
                    register(get);get('/ordinary')
                    status,fields,_=get('/ordinary',name+'=value')
                    self.assertEqual(status,200)
                    self.assertNotIn('X-UltraCache-Guest-Publication',dict(fields))
                    self.assertEqual(len(app.guest_requests),1)

    def test_existing_shared_fallback_reuses_guest_without_requiring_a_named_rule(self):
        app=SharedGuests();app.vary_cookie=True
        with proxy('ultracache',app) as get:
            register(get);get('/fallback');get.stop_origin()
            for owner in ('A','B'):
                status,fields,body=get('/fallback','unlisted_functional='+owner)
                self.assertEqual((status,cache(fields),body),(200,'HIT',GUEST_BODY))
            self.assertEqual(len(app.calls),1)

    def test_shared_fallback_still_binds_actual_provider_input(self):
        app=SharedGuests();app.inputs=declaration(names=('unlisted_provider_input',),prefixes=())
        with proxy('ultracache',app) as get:
            register(get);get('/actual-input')
            status,fields,body=get('/actual-input','unlisted_provider_input=present',{'X-Test-Visitor':'provider'})
            self.assertEqual(status,200);self.assertIn('private:provider',body)
            self.assertNotIn('X-UltraCache-Guest-Publication',dict(fields))
            self.assertEqual(len(app.guest_requests),1)

    def test_empty_actual_private_closure_still_checks_all_shared_policy(self):
        app=SharedGuests();app.inputs=declaration(names=(),prefixes=(),fragments=False)
        with proxy('ultracache',app,policies=choices(('metric','shared'))) as get:
            register(get);get('/empty');get.stop_origin()
            self.assertEqual(cache(get('/empty','metric=A')[1]),'HIT')

    def test_three_representations_reuse_complete_guest_across_first_shared_values(self):
        app=SharedGuests();app.formats=True
        formats={'orig':'text/html','webp':'text/html,image/webp','avif':'text/html,image/avif,image/webp'}
        with proxy('ultracache',app,policies=choices(('metric','shared'))) as get:
            register(get)
            for accept in formats.values():self.assertEqual(get('/formats',extra={'Accept':accept})[0],200)
            get.stop_origin()
            for owner in ('A','B'):
                for bucket,accept in formats.items():
                    status,fields,body=get('/formats','metric='+owner,{'Accept':accept})
                    self.assertEqual((status,cache(fields),body),(200,'HIT',GUEST_BODY+bucket))
            self.assertEqual(len(app.calls),3)

    def test_present_empty_provider_cookie_is_not_absence(self):
        app=SharedGuests()
        with proxy('ultracache',app,policies=choices(('actual_session','shared'))) as get:
            register(get);get('/presence')
            status,fields,body=get('/presence','actual_session=',{'X-Test-Visitor':'empty-present'})
            self.assertEqual(status,200);self.assertIn('private:empty-present',body)
            self.assertNotIn('X-UltraCache-Guest-Publication',dict(fields))
            self.assertEqual(len(app.guest_requests),1)

    def test_bundled_shared_sourcebuster_does_not_require_first_stateful_admission(self):
        app=SharedGuests();app.vary_cookie=True
        with proxy('ultracache',app,daemon_parameters=('vsl_mask=+Debug',)) as get:
            register(get);get('/sourcebuster');get.stop_origin()
            for owner in ('A','B'):
                raw='; '.join(name+'='+owner for name in ('sbjs_current','sbjs_current_add','sbjs_first',
                    'sbjs_first_add','sbjs_migrations','sbjs_session','sbjs_udata'))+'; ultracache_esi_optin=1'
                status,fields,body=get('/sourcebuster',raw)
                self.assertEqual((status,cache(fields),body),(200,'HIT',GUEST_BODY))
            self.assertEqual(len(app.calls),1)
            log=subprocess.check_output(['varnishlog','-n',str(get.instance),'-d','-g','request','-i','Debug'],text=True)
            self.assertIn('uc-guest-inputs admitted=1 reason=empty-provider-inputs',log)

if __name__=='__main__':unittest.main()
