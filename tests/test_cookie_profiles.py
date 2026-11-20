"""Independent columns, scoped inheritance and the unchanged signed wire."""
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
from test_cookie_delivery import proxy,cookies,policy_for_choices
NAME='comment_author_demo'


def dual(basic,ultracache,name='comment_author_',kind='prefix'):
    return {'schemaVersion':2,'rules':[dict(id='custom:dual',match=dict(kind=kind,value=name),
        description='Dual choice',actions=dict(basic=basic,ultracache=ultracache))]}


class CookieProfiles(unittest.TestCase):
    def test_all_defaults_have_two_concrete_actions_and_only_app_integrated_choices_differ(self):
        policy,metadata=defaults.bundle()
        artifact=json.loads((ROOT/'shared/cookie-defaults.json').read_text(encoding='utf-8'))
        self.assertEqual(policy['schemaVersion'],2)
        self.assertEqual(set(artifact),{'schemaVersion','rules','version','sourceRevision'})
        self.assertEqual(artifact['rules'],policy['rules'])
        different=[]
        for r in policy['rules']:
            self.assertEqual(set(r['actions']),{'basic','ultracache'})
            self.assertTrue(all(a in ('shared','variant','private') for a in r['actions'].values()))
            if r['actions']['basic']!=r['actions']['ultracache']:different.append(r['match'])
        self.assertCountEqual(different,[dict(kind='prefix',value=n) for n in
            ('comment_author_','comment_author_url_','yith_wcwl_session_')]+[
            dict(kind='exact',value='yith_wcwl_session_'),
            dict(kind='exact',value='woocommerce_recently_viewed')])
        self.assertTrue(all(set(r['actions'])=={'basic','ultracache'} for r in metadata['records'].values()))

    def test_legacy_choices_preserved_in_both_columns_without_mutation(self):
        for action in ('shared','variant','private'):
            old=choices(('prefix','comment_author_',action));before=copy.deepcopy(old)
            converted=admin.concrete(old)
            self.assertEqual(converted['rules'][0]['actions'],dict(basic=action,ultracache=action))
            for p in admin.PROFILES:self.assertEqual(admin.project(converted,p),old)
            self.assertEqual(old,before)

    def test_partial_reset_precedes_scope_and_specificity_independently(self):
        central=dual('variant','private');site=dual('shared',None)
        for p,expected in (('basic','shared'),('ultracache','private')):
            self.assertEqual(response_action(admin.response_rules(central,site,profile=p),NAME),expected)
            self.assertEqual(selected_action(compiled_selectors(admin.compile_vcl(central,site,profile=p)),NAME),expected)
        site=dual(None,'variant',name='comment_author_url_')
        for p in admin.PROFILES:self.assertEqual(response_action(admin.response_rules(central,site,profile=p),'comment_author_url_demo'),'variant')
        self.assertEqual(response_action(admin.response_rules(central,site,profile='ultracache'),NAME),'private')

    def test_editing_other_column_preserves_execution_and_signed_identity(self):
        old=dual('private','variant');new=dual('shared','variant')
        for p,equal in (('basic',False),('ultracache',True)):
            self.assertEqual(admin.executable(None,old,p)==admin.executable(None,new,p),equal)
            a=control.materialized_snapshot(None,old,p);b=control.materialized_snapshot(None,new,p)
            self.assertEqual(control.effective_digest('example.test',a)==control.effective_digest('example.test',b),equal)

    def test_inactive_column_edit_does_not_reload_an_unchanged_profile_program(self):
        for profile,a,b in (('ultracache',dual('private','variant'),dual('shared','variant')),
                ('basic',dual('variant','private'),dual('variant','shared'))):
            self.assertEqual(policy_for_choices(profile,a),policy_for_choices(profile,b))

    def test_managed_wire_stays_concrete_schema_one_for_the_selected_profile(self):
        for p,expected in (('basic','private'),('ultracache','shared')):
            wire=control.materialized_snapshot(profile=p)
            self.assertEqual(set(wire),{'schemaVersion','central','site'})
            self.assertEqual(wire['schemaVersion'],1)
            self.assertEqual(response_action(admin.response_rules(wire['central'],wire['site']),NAME),expected)
            self.assertTrue(all('action' in r and 'actions' not in r for s in ('central','site') for r in wire[s]['rules']))
        self.assertEqual(control.snapshot(),{'schemaVersion':1,'central':{'schemaVersion':1,'rules':[]},'site':{'schemaVersion':1,'rules':[]}})

    def test_table_has_actual_inherited_and_reset_metadata_for_each_column(self):
        rows=admin.table({'records':[]},load_catalogue(),site=dual('variant',None))
        row=next(r for r in rows if r['match']==dict(kind='prefix',value='comment_author_'))
        b,u=(row['profile_actions'][p] for p in admin.PROFILES)
        self.assertEqual((b['action'],b['inherited_action'],u['action'],u['inherited_action']),('variant','private','shared','shared'))
        self.assertEqual(b['reset_metadata']['effective_action'],'private')
        self.assertEqual(u['reset_metadata']['effective_action'],'shared')

    def test_profile_default_identity_targets_legacy_installs(self):
        after=dict(cookie_defaults_digest=defaults.fingerprint(),cookie_defaults_profile_digests=defaults.profile_digests())
        before=dict(cookie_defaults_digest=defaults.fingerprint('basic'))
        self.assertFalse(defaults.changed(before,after,'basic'))
        self.assertTrue(defaults.changed(before,after,'ultracache'))
        self.assertFalse(defaults.changed(after,copy.deepcopy(after),'ultracache'))

    def test_missing_invalid_or_empty_actions_are_rejected(self):
        for actions in ({'basic':'private'},{'basic':'private','ultracache':'bogus'},{'basic':'automatic','ultracache':'shared'},
                {'basic':None,'ultracache':None},{'basic':'private','ultracache':'shared','other':'variant'}):
            value=dual('private','shared');value['rules'][0]['actions']=actions
            with self.subTest(actions=actions),self.assertRaises(ValueError):admin.normalize(value)


@unittest.skipUnless(shutil.which('varnishd'),'Native Varnish required; skipped is not acceptance')
class NativeCookieProfiles(unittest.TestCase):
    def test_both_profiles_coexist_in_one_daemon_with_their_own_response_policy(self):
        issued='comment_author_url_demo=origin-owner; Path=/; HttpOnly'
        for first,second in (('basic','ultracache'),('ultracache','basic')):
            calls=[]
            def origin(path,headers):
                calls.append(path)
                return 'public',[('Cache-Control','public, max-age=120'),('Set-Cookie',issued)]
            with self.subTest(first=first),proxy(first,origin,other_profile=second) as get:
                host={'basic':'example.test' if first=='basic' else 'other.test',
                      'ultracache':'example.test' if first=='ultracache' else 'other.test'}
                for profile,value,cache in (('basic','A','PASS'),('ultracache','A','MISS'),
                        ('ultracache','B','HIT'),('basic','B','PASS')):
                    status,fields,body=get('/mixed-profiles',NAME+'='+value,extra={'Host':host[profile]})
                    self.assertEqual(status,200);self.assertEqual(body,'public')
                    self.assertEqual(dict(fields)['X-Cache'],cache)
                    self.assertEqual(cookies(fields),[] if cache=='HIT' else [issued])
                self.assertEqual(len(calls),3)

    def test_selected_column_does_not_change_the_other_profile(self):
        for profile in ('basic','ultracache'):
            for basic in ('private','shared'):
                def origin(path,headers):return 'public',[('Cache-Control','public, max-age=120')]
                with self.subTest(profile=profile,basic=basic),proxy(profile,origin,policies=dual(basic,'variant')) as get:
                    expected=('MISS','MISS','HIT') if profile=='ultracache' else ('PASS',)*3 if basic=='private' else ('MISS','HIT','HIT')
                    for value,cache in zip(('A','B','A'),expected):
                        status,fields,body=get('/profile-choice',NAME+'='+value)
                        self.assertEqual(status,200);self.assertEqual(body,'public');self.assertEqual(dict(fields)['X-Cache'],cache)


if __name__=='__main__':unittest.main()
