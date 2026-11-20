"""Shipped commenter rules and native transport, not real WordPress integration.

Template fields, pending visibility, wpDiscuz and ESI-off application fallback
require separate actual WordPress acceptance. No Shared override seeds defaults.
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
from test_delivery_continuation import PARENT,BODY,META,envelope

PREFIXES=('comment_author_','comment_author_url_')
NAMES=('comment_author_demo','comment_author_email_demo','comment_author_url_demo')


def commenter(visitor):
    return '; '.join(name+'='+visitor+'-'+str(i) for i,name in enumerate(NAMES))


class CommentCookiePolicy(unittest.TestCase):
    def test_reviewed_metadata_both_prefixes_and_request_response_rules_agree(self):
        row=next(r for r in load_catalogue()['policies'] if r['id']=='comment-author-prefix')
        self.assertEqual((row['integration'],row['htmlEffect'],row['cacheKey']),
            ('wordpress-comments-esi','private-fragment','ignore'))
        self.assertFalse(row['consumers']['varnishPrivate'])
        policy,metadata=defaults.bundle()
        artifact=json.loads((ROOT/'shared/cookie-defaults.json').read_text(encoding='utf-8'))
        self.assertEqual(artifact['version'],metadata['version'])
        for prefix in PREFIXES:
            assessment=next(r for r in metadata['records'].values() if r['name']==prefix)
            self.assertEqual((assessment['proposal'],assessment['htmlEffect']),('shared','private-fragment'))
            for rules in (policy['rules'],artifact['rules']):
                rule=next(r for r in rules if r['match']==dict(kind='prefix',value=prefix))
                self.assertEqual(rule['action'],'shared')
        selectors=compiled_selectors(admin.compile_vcl())
        for name in NAMES:
            self.assertEqual(response_action(admin.response_rules(),name),'shared')
            self.assertEqual(selected_action(selectors,name),'shared')

    def test_saved_choices_override_both_default_prefixes_without_snapshot_mutation(self):
        for prefix in PREFIXES:
            name=prefix+'demo'
            for central_action in ('shared','variant','private'):
                for site_action in (None,'shared','variant','private'):
                    central=choices(('prefix',prefix,central_action))
                    site=choices(('prefix',prefix,site_action)) if site_action else None
                    before=copy.deepcopy((central,site));expected=site_action or central_action
                    materialized=control.materialized_snapshot(central,site)
                    for c,s in ((central,site),(materialized['central'],materialized['site'])):
                        self.assertEqual(response_action(admin.response_rules(c,s),name),expected)
                    selectors=compiled_selectors(admin.compile_vcl(central,site,chain_defaults=True))
                    self.assertEqual(selected_action(selectors,name),expected)
                    self.assertEqual((central,site),before)


@unittest.skipUnless(shutil.which('varnishd'),'Native Varnish required; skipped is not acceptance')
class NativeCommentCookieDefaults(unittest.TestCase):
    def test_default_reuses_public_parent_across_absence_and_two_commenters(self):
        for profile in ('basic','ultracache'):
            calls=[]
            def origin(path,headers):
                calls.append(headers.get('Cookie'))
                return 'public; no personal template asserted',[('Cache-Control','public, max-age=120'),('Vary','Cookie')]
            with self.subTest(profile=profile),proxy(profile,origin) as get:
                for value,expected in ((None,'MISS'),(commenter('A'),'HIT'),(commenter('B'),'HIT'),(None,'HIT')):
                    status,fields,body=get('/public-comments',value)
                    self.assertEqual(status,200);self.assertEqual(dict(fields)['X-Cache'],expected)
                    self.assertEqual(body,'public; no personal template asserted')
                self.assertEqual(calls,[None])

    def test_explicit_saved_shared_variant_and_private_choices_keep_their_behavior(self):
        for profile in ('basic','ultracache'):
            for action in ('shared','variant','private'):
                calls=[]
                def origin(path,headers):
                    value=headers.get('Cookie');calls.append(value)
                    return 'public' if action=='shared' else value,[
                        ('Cache-Control','public, max-age=120'),('Vary','Cookie')]
                # These are declared explicit-choice scenarios, not default seeds.
                with self.subTest(profile=profile,action=action),proxy(profile,origin,
                        policies=choices(('prefix','comment_author_',action))) as get:
                    expected={'shared':('MISS','HIT','HIT'),'variant':('MISS','MISS','HIT'),
                        'private':('PASS','PASS','PASS')}[action]
                    for visitor,cache in zip(('A','B','A'),expected):
                        value=commenter(visitor)
                        status,fields,body=get('/saved-comment-choice',value)
                        self.assertEqual(status,200);self.assertEqual(dict(fields)['X-Cache'],cache)
                        self.assertEqual(body,'public' if action=='shared' else value)
                    self.assertEqual(len(calls),{'shared':1,'variant':2,'private':3}[action])

    def test_prepared_parent_uses_full_current_commenter_cookie_and_owner_only_response(self):
        calls=[]
        def origin(path,headers):
            phase=headers.get('X-UltraCache-Delivery-Phase')
            calls.append((path,phase,headers.get('Cookie')))
            if phase=='prepare':
                value=headers.get('Cookie')
                self.assertIn(value,(commenter('A'),commenter('B')))
                return envelope(headers,value),[('Cache-Control','private, no-store'),
                    ('Set-Cookie','comment_author_url_demo='+value[-3:]+'; Path=/; HttpOnly')]
            if path==PARENT:return BODY,META
            return 'cold child',[('Cache-Control','private, no-store')]
        with proxy('ultracache',origin) as get:
            self.assertEqual(get(PARENT)[0],200);calls.clear()
            for visitor in ('A','B','A'):
                value=commenter(visitor)
                status,fields,body=get(PARENT,value)
                self.assertEqual(status,200);self.assertEqual(dict(fields)['X-Cache'],'HIT')
                self.assertEqual(body,'<html>parent[private:'+value+'][private:'+value+'][nonce:'+value+']</html>')
                self.assertEqual(cookies(fields),['comment_author_url_demo='+value[-3:]+'; Path=/; HttpOnly'])
            self.assertEqual(calls,[(PARENT,'prepare',commenter(visitor)) for visitor in ('A','B','A')])

    def test_application_private_comment_response_still_passes_in_normal_and_uc_aggressive(self):
        for profile,aggressive in (('basic',False),('ultracache',False),('ultracache',True)):
            calls=[]
            def origin(path,headers):
                calls.append(headers.get('Cookie'))
                return 'private-'+str(len(calls)),[('Cache-Control','private, no-store'),
                    ('X-UltraCache-Application-Private','personal-comment-template')]
            with self.subTest(profile=profile,aggressive=aggressive),proxy(profile,origin,
                    site_settings={'aggressive':aggressive,'aggressive_ttl':600}) as get:
                for i,visitor in enumerate(('A','B'),1):
                    status,fields,body=get('/private-comments',commenter(visitor))
                    self.assertEqual(status,200);self.assertEqual(dict(fields)['X-Cache'],'PASS')
                    self.assertEqual(body,'private-'+str(i))
                    self.assertEqual(dict(fields)['Cache-Control'],'private, no-store')
                self.assertEqual(calls,[commenter('A'),commenter('B')])


if __name__=='__main__':unittest.main()
