"""Declared User Switching cookie transport, not actual provider authentication.

The root-owned Lab separately performs actual WordPress login/switch-off,
provider issuance and private return-region rendering. These plain origins
qualify visible profile actions, literal selectors and native issuer ownership.
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

MATCHES=(('prefix','wordpress_user_sw_'),)
NAMES=('wordpress_user_sw_shop','wordpress_user_sw_secure_shop','wordpress_user_sw_olduser_shop')
ACTIONS=dict(basic='private',ultracache='shared')


def reset(profile):
    return dict(schemaVersion=2,rules=[dict(id='custom:'+name,match=dict(kind=kind,value=name),description='',
        actions={p:None if p==profile else 'variant' for p in ACTIONS}) for kind,name in MATCHES])


class UserSwitchingDefaults(unittest.TestCase):
    def test_visible_prefix_profile_choices_match_artifact_and_catalogue(self):
        artifact=json.loads((ROOT/'shared/cookie-defaults.json').read_text(encoding='utf-8'))
        catalogue=load_catalogue();policy,metadata=defaults.bundle()
        self.assertEqual((artifact['version'],catalogue['version'],metadata['version']),('2026.11.21.1',)*3)
        for source in (artifact['rules'],policy['rules'],catalogue['policies']):
            for kind,name in MATCHES:
                rows=[r for r in source if r['match']==dict(kind=kind,value=name)]
                self.assertEqual(len(rows),1);self.assertEqual(rows[0]['actions'],ACTIONS)
        self.assertEqual(artifact['rules'],policy['rules'])
        row=next(r for r in catalogue['policies'] if r['match']==dict(kind='prefix',value='wordpress_user_sw_'))
        self.assertEqual((row['provider'],row['integration']),('User Switching','wordpress-user-switching-return'))
        self.assertFalse(any(row['consumers'].values()),'Actions remain visible; no secondary cookie veto')
        self.assertTrue(any('97e2d56b56d82bd75ea00bffbf832ad883ccae88' in source for source in row['sources']))


    def test_new_explicit_row_changes_both_fingerprints_without_other_policy_deltas(self):
        import hashlib
        prior=json.loads((ROOT/'tests/fixtures/cookie-defaults-2026.11.20.10.json').read_text(encoding='utf-8'))
        # Later CMS defaults are independent additions to the .11 bundle.
        added_cms={'SSESS','SESS','PrestaShop-','joomla_user_state','joomla_remember_me_'}
        remaining=[r for r in defaults.defaults()['rules'] if r['match']!=dict(kind='prefix',value='wordpress_user_sw_')
                   and r['match']['value'] not in added_cms]
        for profile in ACTIONS:
            projection=sorted((r['match']['kind'],r['match']['value'],r['actions'][profile]) for r in remaining)
            old=hashlib.sha256(json.dumps(projection,ensure_ascii=True,separators=(',',':')).encode()).hexdigest()
            self.assertEqual(old,prior['saved']['cookie_defaults_profile_digests'][profile])
            self.assertNotEqual(old,defaults.fingerprint(profile))

    def test_compiler_uses_each_actual_profile_action_without_a_broad_wordpress_rule(self):
        for profile,expected in ACTIONS.items():
            wire=admin.response_rules(profile=profile)
            selectors=compiled_selectors(admin.compile_vcl(profile=profile))
            for name in NAMES:
                self.assertEqual(response_action(wire,name),expected)
                self.assertEqual(selected_action(selectors,name),expected)
            self.assertEqual(response_action(wire,'wordpress_user_unrelated_cookie'),None)

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
            rows=admin.table({'records':[]},load_catalogue(),site=reset(profile),profile=profile)
            row=next(r for r in rows if r['match']==dict(kind='prefix',value='wordpress_user_sw_'))
            self.assertEqual(row['profile_actions'][profile]['action'],default)
            other='ultracache' if profile=='basic' else 'basic'
            self.assertEqual(row['profile_actions'][other]['action'],'variant')
            for action in ('shared','variant','private'):
                saved=choices(('prefix','wordpress_user_sw_',action))
                snapshot=control.materialized_snapshot(central=saved,profile=profile)
                self.assertTrue(all(response_action(admin.response_rules(snapshot['central'],snapshot['site']),name)==action for name in NAMES))



@unittest.skipUnless(shutil.which('varnishd'),'Native Varnish required; skipped is not acceptance')
class NativeUserSwitchingDefaults(unittest.TestCase):
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
                        status,fields,body=get('/ordinary-user-switching-page/'+name,raw)
                        self.assertEqual(status,200)
                        self.assertEqual(dict(fields)['X-Cache'],expected if profile=='basic' else 'MISS' if expected=='MISS' else 'HIT')
                        self.assertEqual(body,(raw or 'absent') if profile=='basic' else 'public parent')
                self.assertEqual(len(calls),len(NAMES)*(3 if profile=='basic' else 1))

    def test_each_origin_cookie_field_is_private_basic_or_owned_uc_miss_handoff(self):
        from test_cookie_delivery import proxy,cookies
        for profile in ACTIONS:
            calls=[]
            def issued(path,visitor):
                stage,name=path.rsplit('/',2)[-2:]
                return name+'='+('' if stage=='delete' else visitor)+('; Max-Age=0' if stage=='delete' else '; Max-Age=600' if stage=='renew' else '')+'; Path=/; HttpOnly; SameSite=Lax'
            def origin(path,headers):
                visitor=headers.get('X-Test-Visitor','A');calls.append((path,visitor))
                return 'public',[('Cache-Control','public, max-age=120'),('Set-Cookie',issued(path,visitor))]
            with self.subTest(profile=profile),proxy(profile,origin) as get:
                for stage in ('create','renew','delete'):
                    for name in NAMES:
                        path='/issued-user-switching-cookie/'+stage+'/'+name
                        for i,visitor in enumerate(('A','B','A')):
                            status,fields,body=get(path,extra={'X-Test-Visitor':visitor})
                            self.assertEqual(status,200);self.assertEqual(body,'public')
                            self.assertEqual(dict(fields)['X-Cache'],'PASS' if profile=='basic' else 'MISS' if i==0 else 'HIT')
                            self.assertEqual(cookies(fields),[issued(path,visitor)] if profile=='basic' or i==0 else [])
                self.assertEqual(len(calls),len(NAMES)*3*(3 if profile=='basic' else 1))

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
                            status,fields,body=get('/saved-user-switching-page/'+name,name+'='+value)
                            self.assertEqual(status,200);self.assertEqual(body,'public')
                            self.assertEqual(dict(fields)['X-Cache'],cache)
                    self.assertEqual(len(calls),len(NAMES)*(1 if effective=='shared' else 3 if effective=='private' else 2))


if __name__=='__main__':unittest.main()
