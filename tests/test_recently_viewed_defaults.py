"""Native policy from shipped defaults, not WordPress history/widget acceptance.

No history Shared override is seeded in the default scenarios. Real provider
tracking, cookies on parent HIT and ESI-off fallback remain app/Lab acceptance.
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
from test_cookie_delivery import proxy,cookies

NAME='woocommerce_recently_viewed'


class RecentlyViewedPolicy(unittest.TestCase):
    def test_reviewed_source_assessment_artifact_and_wire_use_the_same_shared_default(self):
        row=next(r for r in load_catalogue()['policies'] if r['id']=='woocommerce-recently-viewed')
        self.assertEqual((row['htmlEffect'],row['cacheKey'],row['integration']),('private-fragment','ignore','woocommerce-esi'))
        self.assertFalse(row['consumers']['varnishPrivate'])
        policy,metadata=defaults.bundle()
        assessment=next(r for r in metadata['records'].values() if r['name']==NAME)
        self.assertEqual(assessment['actions'],{'basic':'shared','ultracache':'shared'})
        artifact=json.loads((ROOT/'shared/cookie-defaults.json').read_text(encoding='utf-8'))
        for rules in (policy['rules'],artifact['rules']):
            winner=next(r for r in rules if r['match']==dict(kind='exact',value=NAME))
            self.assertEqual(winner['actions'],{'basic':'shared','ultracache':'shared'})
        self.assertEqual(artifact['version'],metadata['version'])
        self.assertEqual(response_action(admin.response_rules(),NAME),'shared')
        self.assertEqual(selected_action(compiled_selectors(admin.compile_vcl()),NAME),'shared')

    def test_saved_central_and_site_choices_keep_precedence_without_mutating_snapshots(self):
        for central_action in ('shared','variant','private'):
            for site_action in (None,'shared','variant','private'):
                central=choices(('exact',NAME,central_action))
                site=choices(('exact',NAME,site_action)) if site_action else None
                before=copy.deepcopy((central,site));expected=site_action or central_action
                materialized=control.materialized_snapshot(central,site)
                for c,s in ((central,site),(materialized['central'],materialized['site'])):
                    self.assertEqual(response_action(admin.response_rules(c,s),NAME),expected)
                # Exercise the real adapter's explicit-rule chain without
                # repeatedly flattening the unchanged 2k-row bundled body.
                selectors=compiled_selectors(admin.compile_vcl(central,site,chain_defaults=True))
                self.assertEqual(selected_action(selectors,NAME),expected)
                self.assertEqual((central,site),before)


@unittest.skipUnless(shutil.which('varnishd'),'Native Varnish required; fixture unqualified when skipped')
class RecentlyViewedNativeDefaults(unittest.TestCase):
    def test_shipped_default_reuses_plain_public_parent_across_absence_and_two_histories(self):
        for profile in ('basic','ultracache'):
            calls=[]
            def origin(path,headers):
                calls.append(headers.get('Cookie'))
                return 'public HTML; no personal widget asserted',[('Cache-Control','public, max-age=120'),('Vary','Cookie')]
            with self.subTest(profile=profile),proxy(profile,origin) as get:
                for expected,cookie in [('MISS',None),('HIT',NAME+'=10%7C20'),('HIT',NAME+'=30%7C40'),('HIT',None)]:
                    status,headers,body=get('/public-history',cookie)
                    self.assertEqual(status,200);self.assertEqual(dict(headers)['X-Cache'],expected)
                    self.assertEqual(body,'public HTML; no personal widget asserted')
                self.assertEqual(calls,[None])

    def test_shipped_shared_response_cookie_is_owner_only_and_not_replayed_on_hit(self):
        value=NAME+'=10%7C20; Path=/; Max-Age=3600; Secure; HttpOnly; SameSite=Lax'
        for profile in ('basic','ultracache'):
            calls=[]
            def origin(path,headers):
                calls.append(path)
                return 'otherwise-public',[('Cache-Control','public, max-age=120'),('Set-Cookie',value)]
            with self.subTest(profile=profile),proxy(profile,origin) as get:
                _,headers,_=get('/issued-history')
                self.assertEqual(dict(headers)['X-Cache'],'MISS');self.assertEqual(cookies(headers),[value])
                for cookie in (NAME+'=other-history',None):
                    _,headers,body=get('/issued-history',cookie)
                    self.assertEqual(body,'otherwise-public');self.assertEqual(dict(headers)['X-Cache'],'HIT')
                    self.assertEqual(cookies(headers),[])
                self.assertEqual(calls,['/issued-history'])

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
                    site_settings={'aggressive':aggressive,'aggressive_ttl':60}) as get:
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
