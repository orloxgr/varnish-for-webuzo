"""WCML defaults: native cookie behavior, not actual provider/location proof.

The actual WP/WCML/FPM acceptance is separate. No prototype choices are seeded
in the native default cases below; every action comes from the shipped bundle.
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

NAMES=('wcml_client_currency','wcml_client_currency_language')


class WcmlCookieDefaults(unittest.TestCase):
    def test_catalogue_artifact_and_derived_defaults_have_both_exact_variant_choices(self):
        artifact=json.loads((ROOT/'shared/cookie-defaults.json').read_text(encoding='utf-8'))
        catalogue=load_catalogue();policy,metadata=defaults.bundle()
        self.assertEqual((artifact['version'],catalogue['version'],metadata['version']),('2026.11.20.10',)*3)
        for source in (artifact['rules'],policy['rules'],catalogue['policies']):
            for name in NAMES:
                rows=[r for r in source if r['match']==dict(kind='exact',value=name)]
                self.assertEqual(len(rows),1)
                self.assertEqual(rows[0]['actions'],dict(basic='variant',ultracache='variant'))
        self.assertEqual(admin.normalize(dict(schemaVersion=2,rules=artifact['rules'])),admin.normalize(policy))

    def test_each_profile_compiles_variant_without_a_wcml_prefix_or_extra_private_flag(self):
        for profile in ('basic','ultracache'):
            wire=admin.response_rules(profile=profile)
            selectors=compiled_selectors(admin.compile_vcl(profile=profile))
            for name in NAMES:
                self.assertEqual(response_action(wire,name),'variant')
                self.assertEqual(selected_action(selectors,name),'variant')
            self.assertEqual(response_action(wire,'wcml_unrelated_cookie'),None)
        for row in load_catalogue()['policies']:
            if row['match']['value'] in NAMES:
                self.assertFalse(any(row['consumers'].values()))

    def test_saved_central_and_site_choices_keep_independent_profile_precedence(self):
        for name in NAMES:
            central=choices(('exact',name,'private'));site=dict(schemaVersion=2,rules=[dict(
                id='custom:'+name,match=dict(kind='exact',value=name),description='',
                actions=dict(basic=None,ultracache='shared'))])
            before=copy.deepcopy((central,site))
            for profile,expected in (('basic','private'),('ultracache','shared')):
                wire=control.materialized_snapshot(central,site,profile)
                self.assertEqual(response_action(admin.response_rules(wire['central'],wire['site']),name),expected)
            self.assertEqual((central,site),before)


@unittest.skipUnless(shutil.which('varnishd'),'Native Varnish required; skipped is not acceptance')
class WcmlNativeDefaults(unittest.TestCase):
    def test_basic_uses_incoming_currency_and_language_without_a_resolver(self):
        from test_cookie_delivery import proxy
        calls=[]
        def origin(path,headers):
            calls.append(headers.get('Cookie'))
            return 'incoming:'+headers.get('Cookie','absent'),[('Cache-Control','public, max-age=120')]
        with proxy('basic',origin) as get:
            values=[None,NAMES[0]+'=USD',NAMES[0]+'=EUR',NAMES[0]+'=EUR; '+NAMES[1]+'=de',
                NAMES[0]+'=USD',None,NAMES[0]+'=EUR; '+NAMES[1]+'=de']
            for value,cache in zip(values,('MISS','MISS','MISS','MISS','HIT','HIT','HIT')):
                status,fields,body=get('/book/',value)
                self.assertEqual(status,200);self.assertEqual(dict(fields)['X-Cache'],cache)
                self.assertEqual(body,'incoming:'+(value or 'absent'))
            self.assertEqual(calls,values[:4])

    def test_ultracache_declares_shipped_variant_choices_and_selects_before_lookup(self):
        from test_cookie_delivery import proxy,cookies
        from test_public_selection_runtime import Resolver,control
        resolver=Resolver()
        with proxy('ultracache',resolver) as get:
            status,fields,_=control(get,enabled=True)
            self.assertEqual(status,200)
            self.assertEqual(json.loads(fields['X-UltraCache-VCL-Public-Selection-Actions']),{name:'variant' for name in NAMES})
            for country,expected,cache in (('US','USD','MISS'),('DE','EUR','MISS'),('DE','EUR','HIT'),('US','USD','HIT')):
                status,fields,body=get('/book/',NAMES[0]+'=USD',extra={'X-Test-Country':country})
                self.assertEqual(status,200);self.assertEqual(dict(fields)['X-Cache'],cache)
                self.assertIn(expected+('20' if expected=='EUR' else '10'),body)
                self.assertTrue(any(value.startswith(NAMES[0]+'='+expected+';') for value in cookies(fields)))
            self.assertEqual(len(resolver.calls),4);self.assertEqual(resolver.renders,2)


if __name__=='__main__':unittest.main()
