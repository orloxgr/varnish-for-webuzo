"""Profile choices and native transport, not real YITH table/widget proof.

Actual provider REST actions, private embedded rows, nonce ageing and ESI-off
fallback need separate WordPress acceptance. No renderer or provider is mocked
as actual YITH here; the plain origin only qualifies native cache actions.
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

PREFIX='yith_wcwl_session_'
NAMES=(PREFIX,PREFIX+'visitor')
ACTIONS=dict(basic='private',ultracache='shared')


def reset(profile):
    return dict(schemaVersion=2,rules=[dict(id='custom:yith',match=dict(kind='prefix',value=PREFIX),
        description='',actions={p:None if p==profile else 'variant' for p in ACTIONS})])


class YithCookieDefaults(unittest.TestCase):
    def test_exact_assessment_and_prefix_have_independent_concrete_profile_choices(self):
        artifact=json.loads((ROOT/'shared/cookie-defaults.json').read_text(encoding='utf-8'))
        policy,metadata=defaults.bundle();catalogue=load_catalogue()
        self.assertEqual((artifact['version'],metadata['version'],catalogue['version']),('2026.11.20.10',)*3)
        self.assertEqual(metadata['records']['7bbc4d04-8776-45f3-85dc-c474d5907b24']['actions'],ACTIONS)
        for rules in (artifact['rules'],policy['rules']):
            for kind in ('exact','prefix'):
                rows=[r for r in rules if r['match']==dict(kind=kind,value=PREFIX)]
                self.assertEqual(len(rows),1);self.assertEqual(rows[0]['actions'],ACTIONS)
        row=next(r for r in catalogue['policies'] if r['id']=='yith-wcwl-session-prefix')
        self.assertEqual(row['actions'],ACTIONS)
        self.assertEqual(artifact['rules'],policy['rules'])

    def test_compiler_uses_profile_actions_not_legacy_catalogue_private_flag(self):
        # Legacy role metadata remains unchanged; it must not override the
        # selected profile's actual request/response action.
        row=next(r for r in load_catalogue()['policies'] if r['id']=='yith-wcwl-session-prefix')
        self.assertTrue(row['consumers']['varnishPrivate'])
        for profile,expected in ACTIONS.items():
            wire=admin.response_rules(profile=profile)
            selectors=compiled_selectors(admin.compile_vcl(profile=profile))
            for name in NAMES:
                self.assertEqual(response_action(wire,name),expected)
                self.assertEqual(selected_action(selectors,name),expected)
            self.assertEqual(response_action(wire,'yith_woocompare_demo'),'private')

    def test_central_site_three_actions_and_reset_preserve_scope_and_other_profile(self):
        for profile,default in ACTIONS.items():
            for action in ('shared','variant','private'):
                central=choices(('prefix',PREFIX,action))
                for site_action in (None,'shared','variant','private'):
                    site=choices(('prefix',PREFIX,site_action)) if site_action else None
                    before=copy.deepcopy((central,site))
                    wire=control.materialized_snapshot(central,site,profile)
                    for name in NAMES:self.assertEqual(response_action(admin.response_rules(wire['central'],wire['site']),name),site_action or action)
                    self.assertEqual((central,site),before)
            wire=control.materialized_snapshot(site=reset(profile),profile=profile)
            for name in NAMES:self.assertEqual(response_action(admin.response_rules(wire['central'],wire['site']),name),default)
            self.assertEqual(control.effective_digest('example.test',wire),
                control.effective_digest('example.test',control.materialized_snapshot(profile=profile)))


@unittest.skipUnless(shutil.which('varnishd'),'Native Varnish required; skipped is not acceptance')
class YithNativeDefaults(unittest.TestCase):
    def test_shipped_basic_private_and_ultracache_shared_keep_raw_owner_cookie(self):
        from test_cookie_delivery import proxy
        for profile in ACTIONS:
            calls=[]
            def origin(path,headers):
                calls.append(headers.get('Cookie'))
                return 'public parent',[('Cache-Control','public, max-age=120')]
            with self.subTest(profile=profile),proxy(profile,origin) as get:
                for name in NAMES:
                    path='/wishlist-parent/'+name
                    for value,expected in ((None,'MISS'),('A','PASS'),('B','PASS'),(None,'HIT')):
                        raw=name+'='+value if value else None
                        status,fields,body=get(path,raw)
                        self.assertEqual(status,200);self.assertEqual(body,'public parent')
                        self.assertEqual(dict(fields)['X-Cache'],expected if profile=='basic' else 'MISS' if value is None and expected=='MISS' else 'HIT')
                self.assertEqual(calls,[value for name in NAMES for value in (None,name+'=A',name+'=B')] if profile=='basic' else [None]*len(NAMES))

    def test_saved_shared_variant_private_and_reset_remain_authoritative(self):
        from test_cookie_delivery import proxy
        for profile in ACTIONS:
            for action in ('shared','variant','private','reset'):
                selected=reset(profile) if action=='reset' else choices(('prefix',PREFIX,action))
                effective=ACTIONS[profile] if action=='reset' else action
                expected=('MISS','HIT','HIT') if effective=='shared' else ('PASS',)*3 if effective=='private' else ('MISS','MISS','HIT')
                calls=[]
                def origin(path,headers):
                    calls.append(headers.get('Cookie'))
                    return 'public',[('Cache-Control','public, max-age=120')]
                with self.subTest(profile=profile,action=action),proxy(profile,origin,policies=selected) as get:
                    for name in NAMES:
                        for value,cache in zip(('A','B','A'),expected):
                            status,fields,body=get('/saved/'+name,name+'='+value)
                            self.assertEqual(status,200);self.assertEqual(body,'public')
                            self.assertEqual(dict(fields)['X-Cache'],cache)
                    self.assertEqual(len(calls),len(NAMES)*(1 if effective=='shared' else 3 if effective=='private' else 2))


if __name__=='__main__':unittest.main()
