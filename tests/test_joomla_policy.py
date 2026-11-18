"""Opt-in Joomla HTML is unchanged and public HIT needs no external work."""
import shutil
import socket
import unittest
from unittest.mock import patch
import test_profiles as http
from test_cookie_delivery import proxy,cookies

COOKIE='0123456789abcdef0123456789abcdef'
TOKEN='fedcba9876543210fedcba9876543210'


@unittest.skipUnless(shutil.which('varnishd'),'Native Varnish required')
class JoomlaPolicy(unittest.TestCase):
    def selected(self,*args,**kwargs):
        row=self.original(*args,**kwargs)
        if row['domain']=='example.test':
            row.update(aggressive=True,aggressive_ttl=86400,cms_installations=[dict(cms='joomla',base='/')],
                       cms_cookies=[dict(cms='joomla',base='/',cookie_name=COOKIE,supported=True)])
        return row

    def test_warm_html_and_tokens_survive_closed_origin_without_helper_or_cookie_replay(self):
        body='<html><script type="application/json" class="joomla-script-options">{"csrf.token":"'+TOKEN+'"}</script><form method="post"><input type="hidden" name="'+TOKEN+'" value="1"></form></html>'
        for profile in ('basic','ultracache'):
            calls=[];self.original=http.site
            def origin(path,headers):
                calls.append((path,headers.get('Cookie')))
                return body,[('Cache-Control','no-store, no-cache'),('Surrogate-Control','no-store'),
                             ('Vary','Cookie'),('Set-Cookie',COOKIE+'=visitor-A; Path=/; HttpOnly')]
            with self.subTest(profile=profile),patch.object(http,'site',side_effect=self.selected),proxy(profile,origin) as get:
                status,fields,first=get('/el/page?ref=partner&utm_source=A',COOKIE+'=visitor-A; PHPSESSID=A; _ga=A')
                self.assertEqual((status,first),(200,body));self.assertEqual(dict(fields)['X-Cache'],'MISS')
                self.assertEqual(cookies(fields),[COOKIE+'=visitor-A; Path=/; HttpOnly'])
                get.stop_origin()
                with self.assertRaises(OSError):socket.create_connection(get.origin_endpoint,timeout=.2)
                for visitor in ('B','C','A'):
                    status,fields,html=get('/el/page?ref=partner&utm_source='+visitor,COOKIE+'=visitor-'+visitor+'; PHPSESSID='+visitor+'; _ga='+visitor)
                    self.assertEqual((status,html),(200,body));self.assertEqual(dict(fields)['X-Cache'],'HIT')
                    self.assertEqual(cookies(fields),[])
                self.assertEqual(calls,[('/el/page?ref=partner&utm_source=A',COOKIE+'=visitor-A; PHPSESSID=A; _ga=A')])

    def test_known_joomla_login_markers_and_explicit_private_cookie_still_pass(self):
        self.original=http.site
        for profile in ('basic','ultracache'):
            responses=[http.origin('/page','public',cache='no-store')]
            requests=[http.get('/page','public',cache='MISS')]
            for path,header in [('/administrator/',None),('/?option=com_users&task=user.login',None),
                                ('/page','Cookie: joomla_user_state=logged_in'),
                                ('/page','Cookie: joomla_remember_me_abc=remember'),
                                ('/page','Cookie: '+COOKIE+'=private')]:
                responses.append(http.origin(path,'private',cache='no-store'))
                requests.append(http.get(path,'private',[] if header is None else [header],cache='PASS'))
            config={'cookie_policies':{'schemaVersion':1,'rules':[dict(id='explicit',match=dict(kind='exact',value=COOKIE),action='private',description='Explicit site choice')]}}
            with patch.object(http,'site',side_effect=self.selected):
                http.NativeProfiles.run_policy(self,profile,responses,requests,config=config)


if __name__=='__main__':unittest.main()
