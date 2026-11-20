"""Native policy from shipped defaults, not WordPress history/widget acceptance.

No history override is seeded in the default scenarios: Basic is Private,
UltraCache is Shared. Real provider tracking, cookies on parent HIT and ESI-off
fallback remain app/Lab acceptance.
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
if shutil.which('varnishd'):
    from test_cookie_delivery import proxy,cookies

NAME='woocommerce_recently_viewed'
ACTIONS=dict(basic='private',ultracache='shared')


def reset(profile):
    return dict(schemaVersion=2,rules=[dict(id='custom:history',match=dict(kind='exact',value=NAME),
        description='',actions={p:None if p==profile else 'variant' for p in ACTIONS})])


class RecentlyViewedPolicy(unittest.TestCase):
    def test_source_assessment_artifact_and_wire_use_the_actual_profile_defaults(self):
        row=next(r for r in load_catalogue()['policies'] if r['id']=='woocommerce-recently-viewed')
        self.assertEqual((row['htmlEffect'],row['cacheKey'],row['integration']),('private-fragment','ignore','woocommerce-esi'))
        self.assertFalse(row['consumers']['varnishPrivate'])
        policy,metadata=defaults.bundle()
        assessment=next(r for r in metadata['records'].values() if r['name']==NAME)
        self.assertEqual(assessment['actions'],ACTIONS)
        artifact=json.loads((ROOT/'shared/cookie-defaults.json').read_text(encoding='utf-8'))
        for rules in (policy['rules'],artifact['rules']):
            winner=next(r for r in rules if r['match']==dict(kind='exact',value=NAME))
            self.assertEqual(winner['actions'],ACTIONS)
        self.assertEqual(artifact['version'],metadata['version'])
        for profile,action in ACTIONS.items():
            self.assertEqual(response_action(admin.response_rules(profile=profile),NAME),action)
            self.assertEqual(selected_action(compiled_selectors(admin.compile_vcl(profile=profile)),NAME),action)

    def test_saved_central_and_site_choices_keep_precedence_without_mutating_snapshots(self):
        for profile in ACTIONS:
            for central_action in ('shared','variant','private'):
                for site_action in (None,'shared','variant','private'):
                    central=choices(('exact',NAME,central_action))
                    site=choices(('exact',NAME,site_action)) if site_action else None
                    before=copy.deepcopy((central,site));expected=site_action or central_action
                    materialized=control.materialized_snapshot(central,site,profile)
                    for c,s in ((central,site),(materialized['central'],materialized['site'])):
                        self.assertEqual(response_action(admin.response_rules(c,s,profile=profile),NAME),expected)
                    selectors=compiled_selectors(admin.compile_vcl(central,site,chain_defaults=True,profile=profile))
                    self.assertEqual(selected_action(selectors,NAME),expected)
                    self.assertEqual((central,site),before)

    def test_reset_restores_only_the_selected_profile_default(self):
        for profile,action in ACTIONS.items():
            snapshot=control.materialized_snapshot(site=reset(profile),profile=profile)
            self.assertEqual(response_action(admin.response_rules(snapshot['central'],snapshot['site']),NAME),action)
            self.assertEqual(control.effective_digest('example.test',snapshot),
                control.effective_digest('example.test',control.materialized_snapshot(profile=profile)))


@unittest.skipUnless(shutil.which('varnishd'),'Native Varnish required; fixture unqualified when skipped')
class RecentlyViewedNativeDefaults(unittest.TestCase):
    def test_shipped_basic_isolates_histories_while_ultracache_shares_public_parent(self):
        for profile in ('basic','ultracache'):
            calls=[]
            def origin(path,headers):
                calls.append(headers.get('Cookie'))
                return (headers.get('Cookie') or 'absent') if profile=='basic' else 'public parent',[
                    ('Cache-Control','public, max-age=120'),('Vary','Cookie')]
            with self.subTest(profile=profile),proxy(profile,origin) as get:
                for expected,cookie in [('MISS',None),('PASS',NAME+'=10%7C20'),('PASS',NAME+'=30%7C40'),('HIT',None)]:
                    status,headers,body=get('/public-history',cookie)
                    self.assertEqual(status,200);self.assertEqual(dict(headers)['X-Cache'],expected if profile=='basic' else 'MISS' if expected=='MISS' else 'HIT')
                    self.assertEqual(body,(cookie or 'absent') if profile=='basic' else 'public parent')
                self.assertEqual(calls,[None,NAME+'=10%7C20',NAME+'=30%7C40'] if profile=='basic' else [None])

    def test_shipped_history_response_is_private_in_basic_and_owner_handoff_in_ultracache(self):
        value=NAME+'=10%7C20; Path=/; Max-Age=3600; Secure; HttpOnly; SameSite=Lax'
        for profile in ('basic','ultracache'):
            calls=[]
            def origin(path,headers):
                calls.append(path)
                return 'otherwise-public',[('Cache-Control','public, max-age=120'),('Set-Cookie',value)]
            with self.subTest(profile=profile),proxy(profile,origin) as get:
                _,headers,_=get('/issued-history')
                self.assertEqual(dict(headers)['X-Cache'],'PASS' if profile=='basic' else 'MISS');self.assertEqual(cookies(headers),[value])
                for cookie in (NAME+'=other-history',None):
                    _,headers,body=get('/issued-history',cookie)
                    self.assertEqual(body,'otherwise-public');self.assertEqual(dict(headers)['X-Cache'],'PASS' if profile=='basic' else 'HIT')
                    self.assertEqual(cookies(headers),[value] if profile=='basic' else [])
                self.assertEqual(calls,['/issued-history']*(3 if profile=='basic' else 1))

    def test_explicit_shared_history_choice_and_profile_reset_keep_their_own_behavior(self):
        for profile in ACTIONS:
            for action in ('shared','reset'):
                calls=[]
                def origin(path,headers):
                    calls.append(headers.get('Cookie'))
                    return 'public',[('Cache-Control','public, max-age=120')]
                selected=choices(('exact',NAME,'shared')) if action=='shared' else reset(profile)
                effective='shared' if action=='shared' else ACTIONS[profile]
                with self.subTest(profile=profile,action=action),proxy(profile,origin,policies=selected) as get:
                    for i,history in enumerate(('A','B','A')):
                        _,fields,body=get('/saved-shared-or-reset',NAME+'='+history)
                        self.assertEqual(body,'public')
                        self.assertEqual(dict(fields)['X-Cache'],'PASS' if effective=='private' else 'MISS' if i==0 else 'HIT')
                    self.assertEqual(calls,[NAME+'=A',NAME+'=B',NAME+'=A'] if effective=='private' else [NAME+'=A'])

    def test_explicit_saved_private_history_choice_still_passes(self):
        for profile in ('basic','ultracache'):
            calls=[]
            def origin(path,headers):
                calls.append(headers.get('Cookie'))
                return 'private-'+str(len(calls)),[('Cache-Control','public, max-age=120')]
            with self.subTest(profile=profile),proxy(profile,origin,
                    policies=choices(('exact',NAME,'private'))) as get:
                for i,history in enumerate(('10%7C20','30%7C40'),1):
                    _,headers,body=get('/saved-private',NAME+'='+history)
                    self.assertEqual(body,'private-'+str(i));self.assertEqual(dict(headers)['X-Cache'],'PASS')
                    self.assertEqual(dict(headers)['Cache-Control'],'private, no-store')
                self.assertEqual(calls,[NAME+'=10%7C20',NAME+'=30%7C40'])

    def test_explicit_saved_variant_history_choice_separates_and_reuses_values(self):
        for profile in ('basic','ultracache'):
            calls=[]
            def origin(path,headers):
                value=headers.get('Cookie') or 'absent';calls.append(value)
                return value,[('Cache-Control','public, max-age=120'),('Vary','Cookie')]
            with self.subTest(profile=profile),proxy(profile,origin,
                    policies=choices(('exact',NAME,'variant'))) as get:
                for history,expected in [('A','MISS'),('B','MISS'),('A','HIT'),('B','HIT'),(None,'MISS')]:
                    value=NAME+'='+history if history else None
                    _,headers,body=get('/saved-variant',value)
                    self.assertEqual(body,value or 'absent');self.assertEqual(dict(headers)['X-Cache'],expected)
                self.assertEqual(calls,[NAME+'=A',NAME+'=B','absent'])

    def test_shared_history_keeps_origin_privacy_and_actual_uc_application_private_reason(self):
        for profile,aggressive in (('basic',False),('ultracache',False),('ultracache',True)):
            calls=[]
            def origin(path,headers):
                calls.append(headers.get('Cookie'))
                return 'personal-'+str(len(calls)),[('Cache-Control','private, no-store'),
                    ('X-UltraCache-Application-Private','history-widget-personal-response')]
            with self.subTest(profile=profile,aggressive=aggressive),proxy(profile,origin,
                    site_settings={'aggressive':aggressive,'aggressive_ttl':60},
                    policies=choices(('exact',NAME,'shared'))) as get:
                for i,history in enumerate(('A','B'),1):
                    _,headers,body=get('/origin-private-history',NAME+'='+history)
                    self.assertEqual(body,'personal-'+str(i));self.assertEqual(dict(headers)['X-Cache'],'PASS')
                    self.assertEqual(dict(headers)['Cache-Control'],'private, no-store')
                self.assertEqual(calls,[NAME+'=A',NAME+'=B'])

    def test_default_shared_history_retains_visitor_identity_on_existing_private_child_transport(self):
        child='/?ultracache_esi=signed-history-fixture&esi_scope=private';calls=[]
        def origin(path,headers):
            calls.append((path,headers.get('Cookie')))
            if path=='/history-parent':
                return '<html>[<esi:include src="'+child.replace('&','&amp;')+'"/>]</html>',[
                    ('Cache-Control','public, max-age=120'),('Vary','Cookie'),('Surrogate-Control','ESI/1.0'),
                    ('X-UltraCache-ESI-Shared-Parent','1'),('X-UltraCache-ESI-Private-Count','1')]
            self.assertEqual(path,child)
            return headers.get('Cookie'),[('Cache-Control','private, no-store')]
        with proxy('ultracache',origin) as get:
            for history,expected in [('A','MISS'),('B','HIT'),('A','HIT')]:
                _,headers,body=get('/history-parent',NAME+'='+history)
                self.assertEqual(body,'<html>['+NAME+'='+history+']</html>')
                self.assertEqual(dict(headers)['X-Cache'],expected)
            self.assertEqual(sum(path=='/history-parent' for path,_ in calls),1)
            self.assertEqual([cookie for path,cookie in calls if path==child],[NAME+'=A',NAME+'=B',NAME+'=A'])


if __name__=='__main__':unittest.main()
