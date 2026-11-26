"""Five source-reviewed corrections through the existing scoped policy owner."""
import copy
import csv
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'shared'), str(ROOT/'src')]
import cookie_admin as admin
import cookie_defaults as defaults
from cookie_catalogue import load_catalogue
from test_cookie_profiles import dual
from test_cookie_wire_contract import response_action, compiled_selectors, selected_action
from test_cookie_delivery import proxy
from test_cms_cookie_choices import cache

FIXTURE = json.loads((ROOT/'tests/fixtures/reviewed-cookie-defaults-2026.11.26.json').read_text())
MATCHES = {(row['kind'], row['value']) for row in FIXTURE['changes']}
RAW_A = 'wp-settings-7=editorA; wp-settings-time-7=1; wp_lang=el; cmplz_saved_categories=A; cmplz_saved_services=A'
RAW_B = 'wp-settings-7=editorB; wp-settings-time-7=2; wp_lang=en; cmplz_saved_categories=B; cmplz_saved_services=B'


class ReviewedCookieDefaults(unittest.TestCase):
    def test_only_five_execution_decisions_change_from_the_recorded_baseline(self):
        rows = defaults.defaults()['rules']
        rest = sorted((r['match']['kind'], r['match']['value'], r['actions']['basic'], r['actions']['ultracache'])
                      for r in rows if (r['match']['kind'], r['match']['value']) not in MATCHES)
        digest = hashlib.sha256(json.dumps(rest,ensure_ascii=True,separators=(',',':')).encode()).hexdigest()
        self.assertEqual(len(rows), FIXTURE['baselineRuleCount'])
        self.assertEqual(digest, FIXTURE['unaffectedExecutionSha256'])
        for kind, value in MATCHES:
            row = defaults.rule_for(dict(kind=kind,value=value))
            self.assertEqual(row['actions'], dict(basic='shared',ultracache='shared'))
        for name in ('cmplz_id','cmplz_marketing','cmplz_statistics','cmplz_consented_services'):
            self.assertEqual(defaults.rule_for(dict(kind='exact',value=name))['actions'],
                             dict(basic='variant',ultracache='variant'))

    def test_source_reason_and_reviewed_actions_survive_the_canonical_generator(self):
        catalogue = load_catalogue()
        records = [r for r in defaults.bundle()[1]['records'].values()
                   if r['name'] in {v for _,v in MATCHES} | {'cmplz_id'}]
        self.assertEqual(len(records), 6)
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder)/'synthetic.csv'; output = Path(folder)/'generated.json'
            fields = ['ID','Cookie / Data Key name','Platform','Domain','Description','Wildcard match','Data Controller']
            with source.open('w',newline='',encoding='utf-8') as stream:
                writer = csv.DictWriter(stream,fieldnames=fields); writer.writeheader()
                for index,row in enumerate(records):
                    writer.writerow(dict(zip(fields,[str(index),row['name'],row['provider'],row['domain'],
                        row['description'],int(row['wildcard']),row.get('dataController','')])))
            result = subprocess.run([sys.executable,str(ROOT/'tools/build-cookie-assessments.py'),
                '--source',str(source),'--revision','0'*40,'--output',str(output)],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            generated = json.loads(output.read_text(encoding='utf-8'))
        for row in generated['records'].values():
            match = admin._recognition_match(row)
            if row['name']=='cmplz_id':
                self.assertEqual(row['actions'],dict(basic='variant',ultracache='variant'))
                continue
            self.assertEqual(row['actions'],dict(basic='shared',ultracache='shared'))
            self.assertEqual(row['method'],'existing-reviewed-execution-policy')
            self.assertEqual(row['confidence'],'reviewed')
            reviewed = admin._proposal(match,catalogue)
            self.assertEqual(row['reason'],reviewed['reason'])
            self.assertTrue(any('/blob/' in source for source in row['sources']))
            self.assertNotIn('Consent can select scripts/HTML',row['reason'])

    def test_manual_choices_remain_authoritative_for_both_profiles_and_wire(self):
        for kind,value in MATCHES:
            actual = value+'7' if kind=='prefix' else value
            central = dual('variant','private',name=value,kind=kind)
            site = dual('private','variant',name=value,kind=kind)
            before = copy.deepcopy((central,site))
            for profile, central_action, site_action in (('basic','variant','private'),('ultracache','private','variant')):
                self.assertEqual(response_action(admin.response_rules(profile=profile),actual),'shared')
                self.assertEqual(response_action(admin.response_rules(central,profile=profile),actual),central_action)
                self.assertEqual(response_action(admin.response_rules(central,site,profile=profile),actual),site_action)
                self.assertEqual(selected_action(compiled_selectors(admin.compile_vcl(central,site,profile=profile)),actual),site_action)
            self.assertEqual((central,site),before)


@unittest.skipUnless(shutil.which('varnishd'),'Native Varnish required; skip is not acceptance')
class NativeReviewedCookieDefaults(unittest.TestCase):
    def test_five_shared_values_reuse_html_and_original_cookie_reaches_origin(self):
        for profile in ('basic','ultracache'):
            calls=[]
            def origin(path,headers):
                calls.append(headers.get('Cookie'))
                return '<html>public page</html>', [('Cache-Control','public, max-age=120')]
            with self.subTest(profile=profile), proxy(profile,origin) as get:
                self.assertEqual(cache(get('/public',RAW_A)[1]),'MISS')
                self.assertEqual(cache(get('/public',RAW_B)[1]),'HIT')
                self.assertEqual(calls,[RAW_A])
                self.assertEqual(cache(get('/public',RAW_B+'; cmplz_id=one')[1]),'MISS')
                self.assertEqual(cache(get('/public',RAW_B+'; cmplz_id=two')[1]),'MISS')
                self.assertEqual(cache(get('/public',RAW_A+'; cmplz_id=one')[1]),'HIT')
                self.assertEqual(calls,[RAW_A,RAW_B+'; cmplz_id=one',RAW_B+'; cmplz_id=two'])

    def test_shared_bookkeeping_does_not_disable_authentication_or_private_routes(self):
        for profile in ('basic','ultracache'):
            calls=[]
            def origin(path,headers):
                calls.append((path,headers.get('Cookie')))
                return '<html>application</html>', [('Cache-Control','public, max-age=120')]
            with self.subTest(profile=profile), proxy(profile,origin) as get:
                for path,raw,extra in (('/wp-admin/',RAW_A,{}),
                        ('/authorized',RAW_A,{'Authorization':'Bearer synthetic-fixture'}),
                        ('/account',RAW_A+'; wordpress_logged_in_fixture=synthetic',{})):
                    for _ in range(2):
                        self.assertEqual(cache(get(path,raw,extra)[1]),'PASS')
                self.assertEqual(len(calls),6)


if __name__=='__main__':
    unittest.main()
