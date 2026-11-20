"""Native cart choices/HTTP issuer fields, not actual Woo provider acceptance.

Real wc-ajax cart mutations, session issuance and private mini-cart rendering
are separate app/Lab proof. These plain-origin tests seed request values and
emit declared Set-Cookie fields to qualify native profile behavior only.
"""
import copy
import json
from pathlib import Path
import shutil
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'shared'))
import cookie_admin as admin
import cookie_control as control
import cookie_defaults as defaults
from cookie_catalogue import load_catalogue
from test_cookie_wire_contract import choices,response_action,compiled_selectors,selected_action

MATCHES=(('exact','woocommerce_items_in_cart'),('exact','woocommerce_cart_hash'),('prefix','wp_woocommerce_session_'))
NAMES=('woocommerce_items_in_cart','woocommerce_cart_hash','wp_woocommerce_session_shop')
ASSESSMENTS=('f1e0e5b1-d7a1-4afc-80b6-1ba4430c237f','8a23f0ad-722d-4d91-9ef8-52528e903a4f','8f50fe5d-20dc-4811-b118-e49d52a0fc35')
ACTIONS=dict(basic='private',ultracache='shared')


def reset(profile):
    return dict(schemaVersion=2,rules=[dict(id='custom:'+name,match=dict(kind=kind,value=name),description='',
        actions={p:None if p==profile else 'variant' for p in ACTIONS}) for kind,name in MATCHES])


class WooCartDefaults(unittest.TestCase):
    def test_three_exact_profile_choices_match_assessments_artifact_and_catalogue(self):
        artifact=json.loads((ROOT/'shared/cookie-defaults.json').read_text(encoding='utf-8'))
        catalogue=load_catalogue();policy,metadata=defaults.bundle()
        self.assertEqual((artifact['version'],catalogue['version'],metadata['version']),('2026.11.20.11',)*3)
        for ident in ASSESSMENTS:self.assertEqual(metadata['records'][ident]['actions'],ACTIONS)
        for source in (artifact['rules'],policy['rules'],catalogue['policies']):
            for kind,name in MATCHES:
                rows=[r for r in source if r['match']==dict(kind=kind,value=name)]
                self.assertEqual(len(rows),1);self.assertEqual(rows[0]['actions'],ACTIONS)
        self.assertEqual(artifact['rules'],policy['rules'])

    def test_compiler_uses_each_actual_profile_action_without_a_broad_woo_rule(self):
        for profile,expected in ACTIONS.items():
            wire=admin.response_rules(profile=profile)
            selectors=compiled_selectors(admin.compile_vcl(profile=profile))
            for name in NAMES:
                self.assertEqual(response_action(wire,name),expected)
                self.assertEqual(selected_action(selectors,name),expected)
            self.assertEqual(response_action(wire,'woocommerce_unrelated_cookie'),None)

    def test_three_manual_actions_and_partial_reset_override_each_default_independently(self):
        for profile,default in ACTIONS.items():
            for action in ('shared','variant','private'):
                selected=choices(*[(kind,name,action) for kind,name in MATCHES]);before=copy.deepcopy(selected)
                snapshot=control.materialized_snapshot(site=selected,profile=profile)
                for name in NAMES:self.assertEqual(response_action(admin.response_rules(snapshot['central'],snapshot['site']),name),action)
                self.assertEqual(selected,before)
            snapshot=control.materialized_snapshot(site=reset(profile),profile=profile)
            for name in NAMES:self.assertEqual(response_action(admin.response_rules(snapshot['central'],snapshot['site']),name),default)
            self.assertEqual(control.effective_digest('example.test',snapshot),
                control.effective_digest('example.test',control.materialized_snapshot(profile=profile)))


@unittest.skipUnless(shutil.which('varnishd'),'Native Varnish required; skipped is not acceptance')
class NativeWooCartDefaults(unittest.TestCase):
    def test_each_shipped_cookie_is_private_in_basic_and_public_parent_shared_in_ultracache(self):
        from test_cookie_delivery import proxy
        for profile in ACTIONS:
            calls=[]
            def origin(path,headers):
                raw=headers.get('Cookie');calls.append((path,raw))
                return (raw or 'absent') if profile=='basic' else 'public parent',[
                    ('Cache-Control','public, max-age=120'),('Vary','Cookie')]
            with self.subTest(profile=profile),proxy(profile,origin) as get:
                for name in NAMES:
                    for value,expected in ((None,'MISS'),('A','PASS'),('B','PASS'),(None,'HIT')):
                        raw=name+'='+value if value else None
                        status,fields,body=get('/ordinary-woo-page/'+name,raw)
                        self.assertEqual(status,200)
                        self.assertEqual(dict(fields)['X-Cache'],expected if profile=='basic' else 'MISS' if expected=='MISS' else 'HIT')
                        self.assertEqual(body,(raw or 'absent') if profile=='basic' else 'public parent')
                self.assertEqual(len(calls),len(NAMES)*(3 if profile=='basic' else 1))

    def test_each_origin_cookie_field_is_private_basic_or_owned_uc_miss_handoff(self):
        from test_cookie_delivery import proxy,cookies
        for profile in ACTIONS:
            calls=[]
            def origin(path,headers):
                name=path.rsplit('/',1)[1];visitor=headers.get('X-Test-Visitor','A')
                calls.append((path,visitor))
                return 'public',[('Cache-Control','public, max-age=120'),
                    ('Set-Cookie',name+'='+visitor+'; Path=/; HttpOnly')]
            with self.subTest(profile=profile),proxy(profile,origin) as get:
                for name in NAMES:
                    for i,visitor in enumerate(('A','B','A')):
                        status,fields,body=get('/issued-woo-cookie/'+name,extra={'X-Test-Visitor':visitor})
                        self.assertEqual(status,200);self.assertEqual(body,'public')
                        self.assertEqual(dict(fields)['X-Cache'],'PASS' if profile=='basic' else 'MISS' if i==0 else 'HIT')
                        self.assertEqual(cookies(fields),[name+'='+visitor+'; Path=/; HttpOnly'] if profile=='basic' or i==0 else [])
                self.assertEqual(len(calls),len(NAMES)*(3 if profile=='basic' else 1))

    def test_shared_variant_private_and_reset_remain_authoritative_for_each_selector(self):
        from test_cookie_delivery import proxy
        for profile in ACTIONS:
            for action in ('shared','variant','private','reset'):
                selected=reset(profile) if action=='reset' else choices(*[(kind,name,action) for kind,name in MATCHES])
                effective=ACTIONS[profile] if action=='reset' else action
                expected=('MISS','HIT','HIT') if effective=='shared' else ('PASS',)*3 if effective=='private' else ('MISS','MISS','HIT')
                calls=[]
                def origin(path,headers):
                    calls.append(headers.get('Cookie'))
                    return 'public',[('Cache-Control','public, max-age=120')]
                with self.subTest(profile=profile,action=action),proxy(profile,origin,policies=selected) as get:
                    for name in NAMES:
                        for value,cache in zip(('A','B','A'),expected):
                            status,fields,body=get('/saved-woo-page/'+name,name+'='+value)
                            self.assertEqual(status,200);self.assertEqual(body,'public')
                            self.assertEqual(dict(fields)['X-Cache'],cache)
                    self.assertEqual(len(calls),len(NAMES)*(1 if effective=='shared' else 3 if effective=='private' else 2))


if __name__=='__main__':unittest.main()
