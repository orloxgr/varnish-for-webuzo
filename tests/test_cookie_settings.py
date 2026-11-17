"""Removed provider-specific state cannot activate native cookie generation."""
import copy
import shutil
import unittest
from unittest.mock import patch

import test_profiles as http
import engine
import policy


def account(identity='a', domain='example.test', owner='account-a'):
    return dict(http.site(identity, domain), owner=owner)


class CookieSettings(unittest.TestCase):
    def test_inventory_ignores_old_provider_settings_without_mutating_saved_state(self):
        first=account();second=account('c','other.test','account-b')
        config={'sites':{first['id']:{'cookie_delivery':{'fbp':{'enabled':True}}}}}
        before=copy.deepcopy(config)
        with patch.object(engine.native,'collect',return_value={s['id']:s for s in (first,second)}):
            found=engine.inventory(config)
        self.assertEqual(config,before)
        self.assertTrue(all('cookie_delivery' not in site for site in found.values()))

    def test_renderer_does_not_read_old_provider_settings(self):
        first=account();sites={first['id']:first}
        expected=policy.render(sites,'e'*64,'f'*64)
        for previous in ({'fbp':{'enabled':True}}, {'fbp':{'enabled':True,'domain':'unowned.test'}}, 'obsolete'):
            first['cookie_delivery']=previous
            self.assertEqual(policy.render(sites,'e'*64,'f'*64),expected)
        self.assertNotIn('scp_cookie_delivery',expected)
        self.assertNotIn('set req.http.X-SCP-Fbp-Enabled = "1"',expected)

    def test_old_provider_action_is_rejected_before_any_native_change(self):
        with patch.object(engine,'apply') as apply:
            with self.assertRaisesRegex(ValueError,'Unknown action'):
                engine.action(dict(actor='root',admin=True,action='cookie_delivery',id='a'*32,settings={'fbp':{'enabled':True}}))
        apply.assert_not_called()


@unittest.skipUnless(shutil.which('varnishtest'), 'Native varnishtest required')
class NativeCookieSettings(unittest.TestCase):
    run_policy=http.NativeProfiles.run_policy

    def test_old_enabled_provider_state_cannot_reactivate_generation(self):
        original=http.site
        def old_settings(*args,**kwargs):
            result=original(*args,**kwargs)
            result['cookie_delivery']={'fbp':{'enabled':True,'consent_cookie':'cmplz_marketing','consent_value':'allow'}}
            return result
        with patch.object(http,'site',side_effect=old_settings):
            for profile in ('basic','ultracache'):
                requests=[http.get('/page','public',headers=('Cookie: cmplz_marketing=allow',),cache=value)+
                    '\nexpect resp.http.Set-Cookie == <undef>\nexpect resp.http.X-Cache-Cookie-Delivery == <undef>' for value in ('MISS','HIT')]
                self.run_policy(profile,[http.origin('/page','public')],requests)


if __name__=='__main__':unittest.main()
