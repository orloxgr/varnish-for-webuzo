"""Aelia source-reviewed choices and declared native HTTP fixtures only.

The commercial provider is not installed here. These checks establish cookie
dimensions/actions/reset; they do not claim actual Aelia geolocation or tax
runtime correctness. No fabricated resolver, issuer or first-visit bypass.
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
from test_cookie_wire_contract import response_action,compiled_selectors,selected_action

NAMES=('aelia_cs_selected_currency','aelia_customer_country','aelia_customer_state','aelia_tax_exempt')
SOURCE='https://aelia.freshdesk.com/support/solutions/articles/3000042591'


def choices(basic,ultracache):
    return dict(schemaVersion=2,rules=[dict(id='custom:'+name,match=dict(kind='exact',value=name),
        description='',actions=dict(basic=basic,ultracache=ultracache)) for name in NAMES])


class AeliaCookieDefaults(unittest.TestCase):
    def test_four_exact_default_dimensions_match_common_artifact_and_source_metadata(self):
        artifact=json.loads((ROOT/'shared/cookie-defaults.json').read_text(encoding='utf-8'))
        catalogue=load_catalogue();policy,metadata=defaults.bundle()
        self.assertEqual((artifact['version'],catalogue['version'],metadata['version']),('2026.11.21.1',)*3)
        for source in (artifact['rules'],policy['rules'],catalogue['policies']):
            for name in NAMES:
                rows=[r for r in source if r['match']==dict(kind='exact',value=name)]
                self.assertEqual(len(rows),1)
                self.assertEqual(rows[0]['actions'],dict(basic='variant',ultracache='variant'))
        for row in catalogue['policies']:
            if row['match']['value'] in NAMES:
                self.assertIn(SOURCE,row['sources']);self.assertFalse(any(row['consumers'].values()))
        self.assertEqual(admin.normalize(dict(schemaVersion=2,rules=artifact['rules'])),admin.normalize(policy))

    def test_each_profile_compiles_all_four_dimensions_without_a_broad_prefix(self):
        for profile in ('basic','ultracache'):
            wire=admin.response_rules(profile=profile)
            selectors=compiled_selectors(admin.compile_vcl(profile=profile))
            for name in NAMES:
                self.assertEqual(response_action(wire,name),'variant')
                self.assertEqual(selected_action(selectors,name),'variant')
            self.assertEqual(response_action(wire,'aelia_unrelated_cookie'),None)

    def test_all_three_choices_and_independent_reset_restore_each_default_dimension(self):
        for profile in ('basic','ultracache'):
            other='ultracache' if profile=='basic' else 'basic'
            base=control.effective_digest('example.test',control.materialized_snapshot(profile=profile))
            for action in ('shared','variant','private'):
                site=choices(action,action);before=copy.deepcopy(site)
                snapshot=control.materialized_snapshot(site=site,profile=profile)
                for name in NAMES:self.assertEqual(response_action(admin.response_rules(snapshot['central'],snapshot['site']),name),action)
                self.assertEqual(site,before)
                for row in site['rules']:row['actions'][profile]=None;row['actions'][other]='private'
                reset=control.materialized_snapshot(site=site,profile=profile)
                for name in NAMES:self.assertEqual(response_action(admin.response_rules(reset['central'],reset['site']),name),'variant')
                self.assertEqual(control.effective_digest('example.test',reset),base)


@unittest.skipUnless(shutil.which('varnishd'),'Native Varnish required; skipped is not acceptance')
class AeliaNativeDefaults(unittest.TestCase):
    def test_shipped_incoming_dimensions_are_independent_and_absence_is_not_a_bypass(self):
        from test_cookie_delivery import proxy
        baseline=dict(zip(NAMES,('USD','US','CA','0')))
        values=[None,baseline]
        for name,value in zip(NAMES,('EUR','DE','TX','1')):
            row=dict(baseline);row[name]=value;values.append(row)
        def cookie(row):return '; '.join(name+'='+row[name] for name in NAMES) if row is not None else None
        for profile in ('basic','ultracache'):
            calls=[]
            def origin(path,headers):
                self.assertNotIn('X-UltraCache-Delivery-Phase',headers)
                calls.append(headers.get('Cookie'))
                return 'incoming:'+headers.get('Cookie','absent'),[('Cache-Control','public, max-age=120')]
            with self.subTest(profile=profile),proxy(profile,origin) as get:
                # No explicit policies and no resolver declaration: real shipped
                # choices alone must vary all four incoming dimensions.
                for expected in ('MISS','HIT'):
                    for row in values:
                        raw=cookie(row);status,fields,body=get('/declared-aelia-context/',raw)
                        self.assertEqual(status,200);self.assertEqual(dict(fields)['X-Cache'],expected)
                        self.assertEqual(body,'incoming:'+(raw or 'absent'))
                self.assertEqual(calls,[cookie(row) for row in values])

    def test_each_selector_obeys_shared_variant_private_and_reset_in_each_profile(self):
        from test_cookie_delivery import proxy
        for profile in ('basic','ultracache'):
            for action in ('shared','variant','private','reset'):
                if action=='reset':
                    selected=choices(None,'private') if profile=='basic' else choices('private',None)
                else:selected=choices(action,action)
                calls=[]
                def origin(path,headers):
                    calls.append((path,headers.get('Cookie')))
                    return 'public',[('Cache-Control','public, max-age=120')]
                expected=('MISS','HIT','HIT') if action=='shared' else ('PASS',)*3 if action=='private' else ('MISS','MISS','HIT')
                with self.subTest(profile=profile,action=action),proxy(profile,origin,policies=selected) as get:
                    for name in NAMES:
                        for value,cache in zip(('A','B','A'),expected):
                            status,fields,body=get('/selector/'+name,name+'='+value)
                            self.assertEqual(status,200);self.assertEqual(body,'public')
                            self.assertEqual(dict(fields)['X-Cache'],cache)
                    self.assertEqual(len(calls),len(NAMES)*(1 if action=='shared' else 3 if action=='private' else 2))


if __name__=='__main__':unittest.main()
