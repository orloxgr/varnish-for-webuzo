"""Real cookie choices, native account isolation and transactional persistence."""
import copy
import json
import os
import pwd
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import cookie_views
import cookie_admin
import cookie_bridge
import engine
import native
import service
import state
import transport
import cookie_catalogue
import vcl_source
import test_profiles as http
import test_backend

_read_runtime_source=service.current_source


def choices(action='shared', name='campaign_id', kind='exact', identity='custom:campaign'):
    return {'schemaVersion':1, 'rules':[{'id':identity, 'match':{'kind':kind,'value':name},
                                      'description':'A local policy', 'action':action}]}


def account(identity='a', domain='example.test', owner='account_a'):
    return dict(http.site(identity, domain), owner=owner)


@unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid() == 0, 'Linux/root isolated state')
class NativeScope(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir='/var/lib', prefix='wvw-cookie-admin-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.enterContext(patch.object(state, 'ROOT', self.root))
        self.enterContext(patch.object(engine, 'SETTINGS', self.root / 'settings.json'))
        self.enterContext(patch.object(engine, 'JOURNAL', self.root / 'transaction.json'))
        self.enterContext(patch.object(engine, 'recover'))
        self.first, self.second = account(), account('c','other.test','account_b')
        self.sites = {row['id']:row for row in (self.first,self.second)}
        self.enterContext(patch.object(native, 'collect', side_effect=lambda: copy.deepcopy(self.sites)))
        self.enterContext(patch.object(cookie_views.recognition, 'database', return_value={'revision':'test','records':[]}))
        state.save(engine.SETTINGS, {'installed':False, 'sites':copy.deepcopy(self.sites)})

    def request(self, action='cookie_policies_status', actor='account_a', **extra):
        return engine.action(dict(actor=actor, admin=actor == 'root', action=action, **extra))

    def row_id(self,name):
        return next(row['id'] for row in self.request()['cookie_policies']['rows'] if row['name']==name)

    def test_bundled_rules_remain_active_when_recognition_snapshot_has_no_rows(self):
        view=self.request()['cookie_policies']
        self.assertGreater(len(view['rows']),2000)
        self.assertTrue(all(row['active_rule'] and row['scope']=='bundled' and row['action'] in ('shared','variant','private') for row in view['rows']))
        self.assertEqual(view['settings']['rules'],[])

    def test_aggressive_session_default_and_explicit_private_are_shown_as_executed(self):
        previous=engine.settings();previous['sites'][self.first['id']]['aggressive']=True
        state.save(engine.SETTINGS,previous)
        view=self.request()['cookie_policies'];row=next(r for r in view['rows'] if r['name']=='PHPSESSID')
        self.assertTrue(view['aggressive'])
        tracking=next(r for r in view['rows'] if r['name']=='_ga')
        self.assertIn('Aggressive mode can override',tracking['core_precedence'])
        self.assertEqual((row['action'],row['effective_action'],row['inherited']['action']),('shared','shared','shared'))
        self.assertEqual(row['mode_default_action'],'shared')
        previous['sites'][self.first['id']]['cookie_policies']=choices('private','PHPSESSID',identity=row['id'])
        state.save(engine.SETTINGS,previous)
        row=next(r for r in self.request()['cookie_policies']['rows'] if r['name']=='PHPSESSID')
        self.assertEqual((row['action'],row['effective_action']),('private','private'))
        self.assertEqual(row['inherited']['action'],'shared')
        previous['sites'][self.first['id']]['aggressive']=False
        previous['sites'][self.first['id']]['cookie_policies']=None;state.save(engine.SETTINGS,previous)
        row=next(r for r in self.request()['cookie_policies']['rows'] if r['name']=='PHPSESSID')
        self.assertEqual(row['action'],'private')

    def test_new_recognition_metadata_is_visible_without_claiming_an_executed_rule(self):
        database={'revision':'new','records':[dict(id='new',name='new_unbundled_cookie_17',provider='',wildcard=False)]}
        with patch.object(cookie_views.recognition,'database',return_value=database):
            rows=self.request()['cookie_policies']['rows']
        row=next(row for row in rows if row['name']=='new_unbundled_cookie_17')
        self.assertEqual((row['action'],row['scope'],row['active_rule'],row['effective_action']),('variant','recognition',False,'existing-policy'))
        self.assertGreater(len(rows),2000)

    def test_legacy_automatic_is_concrete_in_editor_without_rewriting_saved_snapshot(self):
        previous=engine.settings();previous['sites'][self.first['id']]['cookie_policies']=choices('automatic','unknown_legacy_cookie_17')
        state.save(engine.SETTINGS,previous);before=engine.SETTINGS.read_bytes()
        view=self.request()['cookie_policies']
        self.assertEqual(view['settings']['rules'][0]['action'],'variant')
        self.assertEqual(engine.SETTINGS.read_bytes(),before)

    def test_owner_sees_only_native_owned_sites_and_no_credentials(self):
        value = self.request()['cookie_policies']
        self.assertEqual([s['id'] for s in value['sites']], [self.first['id']])
        self.assertEqual(value['id'], self.first['id'])
        self.assertEqual(value['scope'], 'site')
        self.assertFalse(value['administrator'])
        def assert_public_fields(item):
            if isinstance(item,dict):
                self.assertTrue(set(item).isdisjoint({'token','home','uid','gid','credential_roots','custom_domains'}))
                for entry in item.values():assert_public_fields(entry)
            elif isinstance(item,list):
                for entry in item:assert_public_fields(entry)
        assert_public_fields(value)
        self.assertNotIn(self.first['token'],json.dumps(value))
        with self.assertRaisesRegex(ValueError, 'not available'):
            self.request(id=self.second['id'])

    def test_owner_global_save_and_other_service_actions_are_rejected(self):
        before = engine.SETTINGS.read_bytes()
        for values in ({'id':None,'settings':choices()}, {'id':self.second['id'],'settings':choices()},
                       {'id':self.first['id'],'settings':choices(),'owner':'account_b'}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                self.request('cookie_policies_save', **values)
        for operation in ('install','configure','profile_rules','cookie_delivery','recognition_update'):
            with self.subTest(operation=operation), self.assertRaises(ValueError): self.request(operation)
        self.assertEqual(engine.SETTINGS.read_bytes(), before)

    def test_owner_save_preserves_other_site_and_central_choices(self):
        previous = engine.settings(); previous['cookie_policies'] = choices('private')
        previous['sites'][self.second['id']]['cookie_policies'] = choices('variant')
        state.save(engine.SETTINGS, previous)
        result = self.request('cookie_policies_save', id=self.first['id'], settings=choices('automatic'))
        saved = engine.settings()
        self.assertEqual(saved['cookie_policies'], previous['cookie_policies'])
        self.assertEqual(saved['sites'][self.second['id']]['cookie_policies'], previous['sites'][self.second['id']]['cookie_policies'])
        self.assertEqual(saved['sites'][self.first['id']]['cookie_policies'], choices('automatic'))
        self.assertFalse(result['cookie_policies']['enabled'])

    def test_transferred_site_is_rechecked_against_native_inventory(self):
        self.sites[self.first['id']]['owner'] = 'account_b'
        with self.assertRaisesRegex(ValueError, 'not available'):
            self.request('cookie_policies_save', id=self.first['id'], settings=choices())

    def test_owner_save_does_not_reconcile_or_disable_another_account(self):
        previous=engine.settings();other=copy.deepcopy(previous['sites'][self.second['id']])
        self.sites[self.second['id']]['error']='A native domain rebuild is pending'
        self.request('cookie_policies_save',id=self.first['id'],settings=choices())
        self.assertEqual(engine.settings()['sites'][self.second['id']],other)

    def test_new_metadata_does_not_rewrite_saved_match_snapshots(self):
        self.request('cookie_policies_save', id=self.first['id'], settings=choices('variant'))
        before = engine.SETTINGS.read_bytes()
        database = {'revision':'new','records':[dict(id='new',name='other_cookie',provider='Changed provider',wildcard=False)]}
        with patch.object(cookie_views.recognition,'database',return_value=database):
            self.request()
        self.assertEqual(engine.SETTINGS.read_bytes(), before)

    def test_saved_rename_reset_view_restores_inherited_private_metadata(self):
        view=self.request()['cookie_policies']
        original=next(row for row in view['rows'] if row['match']['value']=='PHPSESSID')
        rule=choices('shared','renamed_public_choice',identity=original['id'])
        self.request('cookie_policies_save',id=self.first['id'],settings=rule)
        renamed=next(row for row in self.request()['cookie_policies']['rows'] if row['id']==original['id'])
        self.assertEqual(renamed['match']['value'],'renamed_public_choice')
        inherited=renamed['inherited']
        self.assertEqual(inherited['match'],original['match'])
        self.assertEqual(inherited['proposal'],'private')
        self.assertEqual(inherited['effective_action'],'private')
        self.assertEqual(inherited['reason'],original['reason'])

    def test_basic_cart_shared_choice_explains_the_reviewed_private_rule(self):
        self.request('cookie_policies_save',id=self.first['id'],settings=choices('shared','woocommerce_cart_hash'))
        before=engine.SETTINGS.read_bytes()
        view=self.request()['cookie_policies']
        row=next(row for row in view['rows'] if row['id']=='custom:campaign')
        self.assertEqual((row['action'],row['effective_action']),('shared','private'))
        self.assertIn('WooCommerce cart/session protection',row['core_precedence'])
        self.assertIn('Basic passes',row['core_precedence'])
        self.assertEqual(engine.SETTINGS.read_bytes(),before)

    def test_ultracache_and_central_cart_metadata_explain_the_application_contract(self):
        previous=engine.settings();previous['sites'][self.first['id']]['profile']='ultracache'
        state.save(engine.SETTINGS,previous)
        for actor in ('account_a','root'):
            with self.subTest(actor=actor):
                row=next(row for row in self.request(actor=actor)['cookie_policies']['rows'] if row['name']=='woocommerce_cart_hash')
                self.assertEqual(row['effective_action'],'application-contract')
                self.assertIn('approved ESI parent with private fragments',row['core_precedence'])
                self.assertIn('without that application contract it also passes',row['core_precedence'])

    def test_saved_cart_rename_reset_keeps_the_inherited_profile_explanation(self):
        identity=self.row_id('woocommerce_cart_hash')
        self.request('cookie_policies_save',id=self.first['id'],settings=choices('shared','campaign_id',identity=identity))
        row=next(row for row in self.request()['cookie_policies']['rows'] if row['id']==identity)
        self.assertEqual(row['effective_action'],'shared')
        self.assertEqual(row['reset_metadata']['effective_action'],'private')
        self.assertEqual(row['inherited']['effective_action'],'private')
        self.assertIn('WooCommerce cart/session protection',row['reset_metadata']['core_precedence'])
        self.assertIn('Basic passes',row['inherited']['core_precedence'])

    def test_ultracache_explicit_private_cart_passes_entire_request_and_reset_restores_esi_metadata(self):
        previous=engine.settings();previous['sites'][self.first['id']]['profile']='ultracache'
        state.save(engine.SETTINGS,previous)
        identity=self.row_id('woocommerce_cart_hash')
        self.request('cookie_policies_save',id=self.first['id'],settings=choices('private','woocommerce_cart_hash',identity=identity))
        before=engine.SETTINGS.read_bytes()
        row=next(row for row in self.request()['cookie_policies']['rows'] if row['id']==identity)
        self.assertEqual((row['action'],row['effective_action']),('private','private'))
        self.assertIn('passes the entire request',row['core_precedence'])
        self.assertEqual(row['reset_metadata']['effective_action'],'application-contract')
        self.assertEqual(row['inherited']['effective_action'],'application-contract')
        self.assertIn('approved ESI parent',row['reset_metadata']['core_precedence'])
        self.assertEqual(engine.SETTINGS.read_bytes(),before)

    def test_ultracache_cart_inherits_explicit_central_private_until_site_automatic_override(self):
        previous=engine.settings();previous['sites'][self.first['id']]['profile']='ultracache'
        previous['cookie_policies']=choices('private','woocommerce_cart_hash')
        state.save(engine.SETTINGS,previous)
        inherited=next(row for row in self.request()['cookie_policies']['rows'] if row['id']=='custom:campaign')
        self.assertEqual(inherited['effective_action'],'private')
        self.assertEqual(inherited['reset_metadata']['effective_action'],'private')
        self.assertIn('passes the entire request',inherited['core_precedence'])
        self.request('cookie_policies_save',id=self.first['id'],settings=choices('automatic','woocommerce_cart_hash'))
        override=next(row for row in self.request()['cookie_policies']['rows'] if row['id']=='custom:campaign')
        self.assertEqual(override['effective_action'],'application-contract')
        self.assertEqual(override['reset_metadata']['effective_action'],'private')
        self.assertEqual(override['inherited']['effective_action'],'private')

    def test_malformed_snapshot_does_not_reach_native_apply(self):
        previous = engine.settings(); previous['installed'] = True; state.save(engine.SETTINGS, previous)
        malformed = choices(); malformed['rules'][0]['match']['value'] = 'x"; return(pass);'
        with patch.object(engine,'apply') as apply, self.assertRaises(ValueError):
            self.request('cookie_policies_save', id=self.first['id'], settings=malformed)
        apply.assert_not_called()

    def test_app_only_save_does_not_touch_native_services_or_routing(self):
        previous=engine.settings();previous['sites'][self.first['id']]['cookie_integration']=dict(enabled=True,url='https://example.test'+cookie_bridge.cookie_control.PATH)
        state.save(engine.SETTINGS,previous)
        calls=[]; original=cookie_bridge.cookie_control.Client
        class Client(original):
            def call(client,operation):
                calls.append(operation)
                if operation=='status':client.base_digest='1'*64
                return {'capabilities':{'scopedCookiePolicies':True}}
        with (patch.object(cookie_bridge.cookie_control,'Client',Client),patch.object(engine,'apply') as apply,
              patch.object(engine,'reload_servers') as reload,patch.object(service,'load') as load,
              patch.object(service,'stop') as stop,patch.object(native,'run') as command):
            result=self.request('cookie_policies_save',id=self.first['id'],settings=choices('private'))
        for mocked in (apply,reload,load,stop,command):mocked.assert_not_called()
        self.assertEqual(calls,['status','prepare','commit'])
        self.assertIn('UltraCache',result['message'])
        self.assertEqual(engine.settings()['sites'][self.first['id']]['cookie_policies'],choices('private'))

    def test_connection_check_uses_the_same_native_owner_boundary(self):
        with patch.object(cookie_bridge,'status') as status,self.assertRaises(ValueError):
            self.request('cookie_integration_status',id=self.second['id'],integration=dict(enabled=True,url='https://other.test'+cookie_bridge.cookie_control.PATH))
        status.assert_not_called()

    def test_inventory_revokes_removed_alias_and_owner_save_does_not_contact_it(self):
        previous=engine.settings();old=previous['sites'][self.first['id']]
        old['names'].append('former.example.test')
        old['cookie_integration']=dict(enabled=True,url='https://former.example.test'+cookie_bridge.cookie_control.PATH)
        state.save(engine.SETTINGS,previous)
        with patch.object(cookie_bridge.cookie_control,'Client') as client:
            view=self.request()['cookie_policies']
            self.assertFalse(view['integration']['enabled'])
            self.assertIn('no longer assigned',view['integration_error'])
            self.request('cookie_policies_save',id=self.first['id'],settings=choices())
        client.assert_not_called()
        self.assertFalse(engine.settings()['sites'][self.first['id']]['cookie_integration']['enabled'])

    def test_large_authenticated_spreadsheet_is_consumed_without_addon_size_ceiling(self):
        panel=pwd.getpwnam('webuzo');directory=self.root/'ipc';directory.mkdir(mode=0o730)
        directory.chmod(0o730);os.chown(directory,0,panel.pw_gid)
        identity='d'*64;file=directory/(identity+'.json')
        rows=[dict(id='custom:'+str(index),match=dict(kind='exact',value='cookie_'+str(index)),description='x'*800,action='automatic')for index in range(1500)]
        payload={'actor':'account_a','admin':False,'action':'cookie_policies_save','id':self.first['id'],
                 'settings':{'schemaVersion':1,'rules':rows}}
        self.assertGreater(len(json.dumps(payload)),1024*1024)
        file.write_text(json.dumps(payload));file.chmod(0o600);os.chown(file,panel.pw_uid,panel.pw_gid)
        with patch.object(state,'RUN',directory):self.assertEqual(transport.request(identity),payload)
        self.assertFalse(file.exists())


@unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid() == 0, 'Linux/root isolated transaction')
class PolicyTransactions(unittest.TestCase):
    setUp = test_backend.Boundaries.setUp
    tearDown = test_backend.Boundaries.tearDown

    def apply_settings(self, previous, following):
        with (patch.object(engine,'plans',return_value=[]),
              patch.object(engine,'reload_servers'), patch.object(engine.connections,'wait'),
              patch.object(service,'load',return_value=('old','candidate')) as load,
              patch.object(service,'admin') as admin, patch.object(service,'prune'),
              patch.object(service,'purge') as purge):
            engine.apply(previous, following)
        return load, admin, purge

    def configuration(self):
        sites = {row['id']:row for row in (account(),account('c','other.test','account_b'))}
        return dict(installed=True,sites=sites,gateway='e'*64,origin='f'*64,proxy_timeouts=native.proxy_timeouts(),
                    cookie_defaults_version=cookie_views.default_version(),cookie_defaults_digest=cookie_views.default_digest())

    def test_bundle_upgrade_invalidates_enabled_sites_and_records_current_version(self):
        previous=self.configuration();previous['cookie_defaults_digest']='previous-execution'
        following=copy.deepcopy(previous);service.ACTIVE.write_text('previous VCL')
        _,_,purge=self.apply_settings(previous,following)
        self.assertEqual({call.args[0]['id'] for call in purge.call_args_list},set(previous['sites']))
        self.assertEqual(engine.settings()['cookie_defaults_version'],cookie_views.default_version())

    def test_editorial_version_change_does_not_invalidate_or_reload_policy(self):
        previous=self.configuration();previous['cookie_defaults_version']='previous-editorial-version'
        following=copy.deepcopy(previous)
        service.ACTIVE.write_text(engine.policy.render(previous['sites'],previous['gateway'],previous['origin'],previous))
        load,admin,purge=self.apply_settings(previous,following)
        load.assert_not_called();admin.assert_not_called();purge.assert_not_called()
        self.assertEqual(engine.settings()['cookie_defaults_digest'],previous['cookie_defaults_digest'])

    def test_apply_reuses_cookie_projection_across_invalidation_stages(self):
        previous=self.configuration();following=copy.deepcopy(previous)
        service.ACTIVE.write_text(engine.policy.render(previous['sites'],previous['gateway'],previous['origin'],previous))
        actual=cookie_admin.executable
        with patch.object(cookie_admin,'executable',wraps=actual) as projection:
            load,admin,purge=self.apply_settings(previous,following)
        self.assertEqual(projection.call_count,1)
        load.assert_not_called();admin.assert_not_called();purge.assert_not_called()

    def test_removing_old_provider_state_does_not_change_policy_or_invalidate(self):
        previous=self.configuration();following=copy.deepcopy(previous)
        previous['sites']['a'*32]['cookie_delivery']={'fbp':{'enabled':True}}
        service.ACTIVE.write_text(engine.policy.render(previous['sites'],previous['gateway'],previous['origin'],previous))
        load,admin,purge=self.apply_settings(previous,following)
        load.assert_not_called();admin.assert_not_called();purge.assert_not_called()

    def test_site_rule_invalidates_only_its_enabled_site(self):
        previous = self.configuration(); following = copy.deepcopy(previous)
        following['sites']['a'*32]['cookie_policies'] = choices()
        service.ACTIVE.write_text('previous VCL')
        load, admin, purge = self.apply_settings(previous,following)
        load.assert_called_once(); admin.assert_called_once_with('vcl.use','candidate')
        self.assertEqual([call.args[0]['id'] for call in purge.call_args_list], ['a'*32])

    def test_description_only_save_neither_invalidates_nor_creates_generation(self):
        previous = self.configuration(); previous['cookie_policies'] = choices()
        following = copy.deepcopy(previous)
        following['cookie_policies']['rules'][0]['description'] = 'Updated description only'
        native_policy = engine.policy.render(previous['sites'],previous['gateway'],previous['origin'],previous)
        service.ACTIVE.write_text(native_policy)
        load, admin, purge = self.apply_settings(previous,following)
        load.assert_not_called(); admin.assert_not_called(); purge.assert_not_called()
        self.assertEqual(engine.settings()['cookie_policies'], following['cookie_policies'])

    def test_central_change_invalidates_affected_sites_without_restart(self):
        previous = self.configuration(); following = copy.deepcopy(previous); following['cookie_policies'] = choices('variant')
        service.ACTIVE.write_text('previous VCL')
        _, admin, purge = self.apply_settings(previous,following)
        self.assertEqual({call.args[0]['id'] for call in purge.call_args_list}, {'a'*32,'c'*32})
        self.assertEqual(admin.call_args_list[0].args, ('vcl.use','candidate'))

    def test_shadowed_central_choice_does_not_invalidate_site_override(self):
        previous = self.configuration(); previous['cookie_policies'] = choices('variant')
        previous['sites']['a'*32]['cookie_policies'] = choices('shared')
        following = copy.deepcopy(previous); following['cookie_policies'] = choices('private')
        service.ACTIVE.write_text('previous VCL')
        _, _, purge = self.apply_settings(previous,following)
        self.assertEqual([call.args[0]['id']for call in purge.call_args_list], ['c'*32])

    def test_module_only_change_is_in_complete_candidate_with_unchanged_coordinator(self):
        previous = self.configuration()
        content = engine.policy.render(previous['sites'],previous['gateway'],previous['origin'],previous)
        service.ACTIVE.write_text(content)
        shared = Path(cookie_catalogue.__file__).resolve().parent
        copied = self.root / 'shared'; shutil.copytree(shared,copied)
        coordinator = (copied/'cache-policy.vcl').read_bytes()
        module = copied/'vcl/cookies.vcl'; module.write_text(module.read_text()+'\n# Module-only change\n')
        with patch.object(cookie_catalogue,'expand',side_effect=lambda source:vcl_source.expand(source,copied)):
            load, _, purge = self.apply_settings(previous,copy.deepcopy(previous))
        self.assertEqual((copied/'cache-policy.vcl').read_bytes(),coordinator)
        load.assert_called_once(); self.assertIn('# Module-only change',load.call_args.args[0])
        self.assertNotRegex(load.call_args.args[0],r'(?m)^include ')
        purge.assert_not_called()

    def test_runtime_drift_is_not_hidden_by_an_unchanged_startup_file(self):
        previous=self.configuration()
        desired=engine.policy.render(previous['sites'],previous['gateway'],previous['origin'],previous)
        service.ACTIVE.write_text(desired)
        with patch.object(service,'current_source',return_value=('old','A different running program')):
            load,admin,_=self.apply_settings(previous,copy.deepcopy(previous))
        load.assert_called_once();admin.assert_called_once_with('vcl.use','candidate')

    def test_runtime_read_error_never_echoes_private_vcl_source(self):
        with patch.object(service,'admin',side_effect=RuntimeError('secret-token-value')):
            with self.assertRaises(RuntimeError) as error:_read_runtime_source()
        self.assertNotIn('secret-token-value',str(error.exception))

    def test_lost_remote_commit_reply_rolls_back_before_settings_commit(self):
        previous=self.configuration(); following=copy.deepcopy(previous)
        following['sites']['a'*32]['cookie_integration']=dict(enabled=True,url='https://example.test'+cookie_bridge.cookie_control.PATH)
        following['sites']['a'*32]['cookie_policies']=choices('variant')
        state.save(engine.SETTINGS,previous);service.ACTIVE.write_text('previous VCL')
        remote={'active':'1'*64}; calls=[]; original=cookie_bridge.cookie_control.Client
        class Client(original):
            def call(client,operation):
                calls.append(operation)
                if operation=='status':client.base_digest=remote['active']
                elif operation=='commit':
                    self.assertEqual(state.read(engine.JOURNAL)['cookie_operations'][0]['phase'],'committing')
                    remote['active']=client.target_digest
                    raise cookie_bridge.cookie_control.ControlError('Lost commit reply')
                elif operation=='rollback':
                    remote['active']=client.base_digest
                    return {'rollbackState':'restored','activeDigest':remote['active']}
                return {'capabilities':{'scopedCookiePolicies':True}}
        with (patch.object(engine,'plans',return_value=[]),patch.object(engine,'reload_servers'),
              patch.object(service,'load',return_value=('old','candidate')),patch.object(service,'admin'),
              patch.object(service,'running',return_value=True),patch.object(service,'purge'),
              patch.object(cookie_bridge.cookie_control,'Client',Client)):
            with self.assertRaises(cookie_bridge.cookie_control.ControlError):engine.apply(previous,following)
        self.assertEqual(remote['active'],'1'*64)
        self.assertEqual(calls,['status','prepare','commit','rollback'])
        self.assertEqual(engine.settings(),previous);self.assertEqual(service.ACTIVE.read_text(),'previous VCL')
        self.assertFalse(engine.JOURNAL.exists())

    def test_remote_prepare_failure_does_not_start_or_reload_native_services(self):
        previous=self.configuration();following=copy.deepcopy(previous)
        following['sites']['a'*32]['cookie_integration']=dict(enabled=True,url='https://example.test'+cookie_bridge.cookie_control.PATH)
        state.save(engine.SETTINGS,previous);service.ACTIVE.write_text('previous VCL')
        with (patch.object(engine,'plans',return_value=[]),patch.object(engine,'reload_servers') as reload,
              patch.object(service,'load') as load,patch.object(service,'running') as running,
              patch.object(service,'stop') as stop,patch.object(service,'write_vcl') as write,
              patch.object(cookie_bridge.cookie_control.Client,'call',side_effect=cookie_bridge.cookie_control.ControlError('Connection unavailable'))):
            with self.assertRaises(cookie_bridge.cookie_control.ControlError):engine.apply(previous,following)
        for mocked in (reload,load,running,stop,write):mocked.assert_not_called()
        self.assertEqual(engine.settings(),previous);self.assertFalse(engine.JOURNAL.exists())

    def test_superseded_app_only_abort_keeps_newer_settings_and_private_evidence(self):
        previous=self.configuration();previous['installed']=False
        following=copy.deepcopy(previous)
        following['sites']['a'*32]['cookie_integration']=dict(enabled=True,url='https://example.test'+cookie_bridge.cookie_control.PATH)
        state.save(engine.SETTINGS,previous)
        original=cookie_bridge.cookie_control.Client
        class Client(original):
            def call(client,operation):
                if operation=='status':client.base_digest='1'*64
                elif operation=='commit':raise cookie_bridge.cookie_control.ControlError('Concurrent application update')
                elif operation=='rollback':return {'rollbackState':'superseded','activeDigest':'2'*64}
                return {'capabilities':{'scopedCookiePolicies':True}}
        with (patch.object(cookie_bridge.cookie_control,'Client',Client),patch.object(service,'stop') as stop,
              patch.object(engine,'reload_servers') as reload):
            with self.assertRaisesRegex(cookie_bridge.cookie_control.ControlError,'Newer WordPress cookie settings were preserved'):
                engine.apply_cookie_only(previous,following)
        stop.assert_not_called();reload.assert_not_called()
        self.assertEqual(engine.settings(),previous);self.assertFalse(engine.JOURNAL.exists())
        evidence=state.read(state.ROOT/'last-cookie-rollback.json')
        self.assertEqual(evidence,{'preserved_newer_application_policy':[{'site':'a'*32,'state':'superseded','active_digest':'2'*64}]})
        self.assertNotIn('b'*64,json.dumps(evidence))

    def test_failed_native_rollback_keeps_journal_local_started_for_recovery(self):
        previous=self.configuration();state.save(engine.SETTINGS,previous)
        service.ACTIVE.write_text('current VCL')
        change=dict(path=str(self.root/'route.conf'),before='old',after='new',mode=0o600)
        journal=dict(previous=previous,changes=[change],active_before='previous VCL',old_vcl='old',
                     local_started=True,cookie_operations=[],cookie_purge_sites=[])
        state.save(engine.JOURNAL,journal)
        with patch.object(engine.routing,'replace',side_effect=RuntimeError('Native route rollback failed')):
            with self.assertRaisesRegex(RuntimeError,'Native route rollback failed'):engine.recover()
        self.assertTrue(state.read(engine.JOURNAL)['local_started'])
        self.assertEqual(service.ACTIVE.read_text(),'current VCL')
        with (patch.object(engine.routing,'replace') as replace,patch.object(service,'running',return_value=True),
              patch.object(service,'admin') as admin,patch.object(engine,'reload_servers')):
            engine.recover()
        replace.assert_called_once_with(change,reverse=True);admin.assert_called_once_with('vcl.use','old')
        self.assertFalse(engine.JOURNAL.exists());self.assertEqual(service.ACTIVE.read_text(),'previous VCL')


@unittest.skipUnless(shutil.which('varnishtest'), 'Native Varnish required')
class NativeCookieRules(unittest.TestCase):
    run_policy = http.NativeProfiles.run_policy

    def test_admission_fix_retires_old_warm_objects_without_restart_or_purge(self):
        for profile in ('basic','ultracache'):
            with self.subTest(profile=profile):
                # Webuzo already omits an unconfigured contract header. Model
                # the historical empty-header caller to reproduce the common
                # admission defect and prove old bad objects cannot survive it.
                current=http.program(profile).replace(' call scp_recv;',' set req.http.X-SCP-Cookie-Contract = "";\n call scp_recv;')
                self.assertIn('webuzo-shared-policy-v8',current)
                guarded_v7=current.replace('webuzo-shared-policy-v8','webuzo-shared-policy-v7')
                bad_v7=guarded_v7.replace('bereq.http.X-SCP-Cookie-Contract ~ "^[0-9a-f]{64}$"','bereq.http.X-SCP-Cookie-Contract')
                self.assertNotEqual(bad_v7,guarded_v7)
                headers=['Vary: Cookie','X-UltraCache-Cookie-Settings:','X-UltraCache-Cookie-Vary: policy-only']
                origin='\n'.join([http.origin('/warm','old-alice',headers),http.origin('/warm','alice',headers),http.origin('/warm','bob',headers)]).removeprefix('accept\n')
                first='\n'.join([http.get('/warm','old-alice',['Cookie: vendor_id=alice'],cache='MISS'),http.get('/warm','old-alice',['Cookie: vendor_id=bob'],cache='HIT')])
                second=http.get('/warm','old-alice',['Cookie: vendor_id=bob'],cache='HIT')
                final='\n'.join([http.get('/warm','alice',['Cookie: vendor_id=alice'],cache='MISS'),http.get('/warm','bob',['Cookie: vendor_id=bob'],cache='MISS'),http.get('/warm','alice',['Cookie: vendor_id=alice'],cache='HIT')])
                source=('varnishtest "Admission upgrade retires old warm cache objects"\nserver s1 {\n'+origin+'\n} -start\n'
                        'varnish v1 -vcl {\n'+bad_v7+'\n} -start\nclient c1 {\n'+first+'\n} -run\n'
                        'varnish v1 -vcl {\n'+guarded_v7+'\n}\nclient c2 {\n'+second+'\n} -run\n'
                        'varnish v1 -vcl {\n'+current+'\n}\nclient c3 {\n'+final+'\n} -run\nserver s1 -wait\n')
                with tempfile.TemporaryDirectory(prefix='wvw-admission-upgrade-') as folder:
                    path=Path(folder)/'upgrade.vtc';path.write_text(source)
                    result=subprocess.run(['varnishtest','-t','30',str(path)],capture_output=True,text=True,timeout=40)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_many_distinct_site_choices_share_one_native_defaults_body(self):
        sites={}
        for index in range(48):
            domain='site-'+str(index)+'.example.test'
            row=dict(http.site(),id=format(index,'032x'),domain=domain,names=[domain],
                     cookie_policies=choices('variant' if index%2==0 else 'shared','local_option',identity='custom:'+str(index)))
            sites[row['id']]=row
        source=engine.policy.render(sites,'e'*64,'f'*64)
        self.assertEqual(source.count('sub scp_bundled_cookie_rules {'),1)
        self.assertEqual(source.count('if (cookie_handoff.detach({"'),2)
        for scheme in ('http','https'):
            source=source.replace('.path = "/run/varnish-for-webuzo-origin-'+scheme+'.sock";','.host = "127.0.0.1"; .port = "${s1_port}";')
        source=source.replace('local.socket != "public"','client.ip != "127.0.0.1"').replace('local.socket == "public"','client.ip == "127.0.0.1"')
        with patch.object(http,'program',return_value=source):
            self.run_policy('basic',
                [http.origin('/page','first-a'),http.origin('/page','first-b'),http.origin('/page','second-shared'),
                 http.origin('/cookie','private-fields',['Set-Cookie: local_option=variant-new']),
                 http.origin('/cookie','shared-fields',['Set-Cookie: local_option=shared-new'])],
                [http.get('/page','first-a',['Cookie: local_option=A'],cache='MISS',host='site-0.example.test'),
                 http.get('/page','first-a',['Cookie: local_option=A'],cache='HIT',host='site-0.example.test'),
                 http.get('/page','first-b',['Cookie: local_option=B'],cache='MISS',host='site-0.example.test'),
                 http.get('/page','second-shared',['Cookie: local_option=A'],cache='MISS',host='site-1.example.test'),
                 http.get('/page','second-shared',['Cookie: local_option=B'],cache='HIT',host='site-1.example.test'),
                 http.get('/cookie','private-fields',cache='PASS',host='site-0.example.test'),
                 'expect resp.http.Set-Cookie == "local_option=variant-new"',
                 http.get('/cookie','shared-fields',cache='MISS',host='site-1.example.test'),
                 'expect resp.http.Set-Cookie == "local_option=shared-new"',
                 http.get('/cookie','shared-fields',cache='HIT',host='site-1.example.test'),
                 'expect resp.http.Set-Cookie == <undef>'])

    def test_bundled_defaults_share_tracking_vary_consent_and_pass_private_session(self):
        for profile in ('basic','ultracache'):
            with self.subTest(profile=profile):
                self.run_policy(profile,
                    [http.origin('/page','public',expect=['expect req.http.Cookie == <undef>']),
                     http.origin('/page','consent-a'),http.origin('/page','consent-b'),
                     http.origin('/page','private-session')],
                    [http.get('/page','public',cache='MISS'),
                     http.get('/page','public',['Cookie: __hstc=one'],cache='HIT'),
                     http.get('/page','public',['Cookie: __hstc=two'],cache='HIT'),
                     http.get('/page','consent-a',['Cookie: __hstc=three; cookieyes-consent=A'],cache='MISS'),
                     http.get('/page','consent-b',['Cookie: __hstc=four; cookieyes-consent=B'],cache='MISS'),
                     http.get('/page','consent-a',['Cookie: __hstc=five; cookieyes-consent=A'],cache='HIT'),
                     http.get('/page','private-session',['Cookie: JSESSIONID=private'],cache='PASS')])

    def test_connected_old_shared_policy_keeps_origin_cookie_vary_when_digest_changes(self):
        original=http.site;rules=choices('shared','site_currency')
        connection=dict(enabled=True,url='https://example.test'+cookie_bridge.cookie_control.PATH)
        drift=cookie_bridge.cookie_control.effective_digest('example.test',cookie_bridge.cookie_control.snapshot(choices('variant','site_currency')))
        def connected(*args,**kwargs):
            row=original(*args,**kwargs)
            if row['domain']=='example.test':row['cookie_integration']=connection
            return row
        headers=['Vary: Cookie','X-UltraCache-Cookie-Settings: '+drift,'X-UltraCache-Cookie-Vary: policy-only']
        for profile in ('basic','ultracache'):
            with self.subTest(profile=profile),patch.object(http,'site',side_effect=connected):
                self.run_policy(profile,[http.origin('/page','EUR',headers=headers),http.origin('/page','USD',headers=headers)],
                    [http.get('/page','EUR',['Cookie: site_currency=EUR'],cache='MISS'),
                     http.get('/page','EUR',['Cookie: site_currency=EUR'],cache='HIT'),
                     http.get('/page','USD',['Cookie: site_currency=USD'],cache='MISS'),
                     http.get('/page','USD',['Cookie: site_currency=USD'],cache='HIT'),
                     'expect resp.http.Vary ~ "Cookie"'],config={'cookie_policies':rules})

    def test_connected_matching_shared_policy_has_a_digest_and_reuses_shared_html(self):
        original=http.site;rules=choices('shared','site_currency')
        connection=dict(enabled=True,url='https://example.test'+cookie_bridge.cookie_control.PATH)
        expected=cookie_bridge.cookie_control.effective_digest('example.test',cookie_bridge.cookie_control.materialized_snapshot(rules))
        self.assertEqual(cookie_bridge.cookie_control.cache_contract(connection,'example.test',['example.test'],rules),expected)
        def connected(*args,**kwargs):
            row=original(*args,**kwargs)
            if row['domain']=='example.test':row['cookie_integration']=connection
            return row
        headers=['Vary: Cookie','X-UltraCache-Cookie-Settings: '+expected,'X-UltraCache-Cookie-Vary: policy-only']
        for profile in ('basic','ultracache'):
            with self.subTest(profile=profile),patch.object(http,'site',side_effect=connected):
                self.run_policy(profile,[http.origin('/page','public',headers=headers)],
                    [http.get('/page','public',['Cookie: site_currency=EUR'],cache='MISS'),
                     http.get('/page','public',['Cookie: site_currency=USD'],cache='HIT'),
                     'expect resp.http.Vary ~ "Cookie"'],config={'cookie_policies':rules})

    def test_connected_empty_policy_keeps_new_origin_tracking_cookie_variants_separate(self):
        original=http.site
        connection=dict(enabled=True,url='https://example.test'+cookie_bridge.cookie_control.PATH)
        drift=cookie_bridge.cookie_control.effective_digest('example.test',cookie_bridge.cookie_control.snapshot(choices('variant','_ga')))
        def connected(*args,**kwargs):
            row=original(*args,**kwargs)
            if row['domain']=='example.test':row['cookie_integration']=connection
            return row
        headers=['Vary: Cookie','X-UltraCache-Cookie-Settings: '+drift,'X-UltraCache-Cookie-Vary: policy-only']
        for profile in ('basic','ultracache'):
            with self.subTest(profile=profile),patch.object(http,'site',side_effect=connected):
                self.run_policy(profile,[http.origin('/page','first',headers=headers),http.origin('/page','second',headers=headers)],
                    [http.get('/page','first',['Cookie: _ga=first'],cache='MISS'),
                     http.get('/page','first',['Cookie: _ga=first'],cache='HIT'),
                     http.get('/page','second',['Cookie: _ga=second'],cache='MISS'),
                     http.get('/page','second',['Cookie: _ga=second'],cache='HIT'),
                     'expect resp.http.Vary ~ "Cookie"'])

    def test_absent_private_cookie_keeps_public_hits_and_downstream_cookie_vary(self):
        for profile in ('basic','ultracache'):
            with self.subTest(profile=profile):
                self.run_policy(profile,[http.origin('/page','public'),http.origin('/page','private')],
                    [http.get('/page','public',cache='MISS'),
                     'expect resp.http.Vary ~ "Cookie"',
                     http.get('/page','public',cache='HIT'),
                     'expect resp.http.Vary ~ "Cookie"',
                     http.get('/page','private',['Cookie: site_personal=yes'],cache='PASS'),
                     'expect resp.http.Cache-Control ~ "private"',
                     'expect resp.http.Cache-Control ~ "no-store"',
                     http.get('/page','public',cache='HIT')],
                    config={'cookie_policies':choices('private','site_personal')})

    def test_connected_private_only_contract_ignores_unrelated_cookie_variation(self):
        original=http.site;rules=choices('private','site_personal')
        connection=dict(enabled=True,url='https://example.test'+cookie_bridge.cookie_control.PATH)
        digest=cookie_bridge.cookie_control.cache_contract(connection,'example.test',['example.test'],rules)
        self.assertTrue(digest)
        def connected(*args,**kwargs):
            row=original(*args,**kwargs)
            if row['domain']=='example.test':row['cookie_integration']=connection
            return row
        headers=['Vary: Cookie','X-UltraCache-Cookie-Settings: '+digest,'X-UltraCache-Cookie-Vary: policy-only']
        for profile in ('basic','ultracache'):
            with self.subTest(profile=profile),patch.object(http,'site',side_effect=connected):
                self.run_policy(profile,[http.origin('/page','public',headers=headers),http.origin('/page','private',headers=headers)],
                    [http.get('/page','public',['Cookie: vendor_id=one'],cache='MISS'),
                     http.get('/page','public',['Cookie: vendor_id=two'],cache='HIT'),
                     'expect resp.http.Vary ~ "Cookie"',
                     http.get('/page','private',['Cookie: vendor_id=two; site_personal=yes'],cache='PASS'),
                     'expect resp.http.Cache-Control ~ "private"'],config={'cookie_policies':rules})

    def test_connected_policy_cookie_vary_uses_native_digest_and_keeps_public_variants(self):
        original=http.site;rules=choices('variant','site_currency')
        connection=dict(enabled=True,url='https://example.test'+cookie_bridge.cookie_control.PATH)
        digest=cookie_bridge.cookie_control.cache_contract(connection,'example.test',['example.test'],rules)
        def connected(*args,**kwargs):
            row=original(*args,**kwargs)
            if row['domain']=='example.test':row['cookie_integration']=connection
            return row
        for profile in ('basic','ultracache'):
            with self.subTest(profile=profile),patch.object(http,'site',side_effect=connected):
                headers=['Vary: Cookie','X-UltraCache-Cookie-Settings: '+digest,'X-UltraCache-Cookie-Vary: policy-only']
                self.run_policy(profile,[http.origin('/page','EUR',headers=headers,expect=['expect req.http.Cookie == "vendor_id=one; site_currency=EUR"']),http.origin('/page','USD',headers=headers)],
                    [http.get('/page','EUR',['Cookie: vendor_id=one; site_currency=EUR'],cache='MISS'),
                     'expect resp.http.X-Cache-Cookie-Names == "site_currency"',
                     http.get('/page','EUR',['Cookie: vendor_id=two; site_currency=EUR'],cache='HIT'),
                     'expect resp.http.X-Cache-Cookie-Names == "site_currency"',
                     'expect resp.http.Vary ~ "Cookie"',
                     http.get('/page','USD',['Cookie: vendor_id=two; site_currency=USD'],cache='MISS'),
                     http.get('/page','USD',['Cookie: vendor_id=three; site_currency=USD'],cache='HIT')],config={'cookie_policies':rules})

    def test_client_cannot_forge_a_policy_contract_on_an_unconnected_site(self):
        rules=choices('variant','site_currency')
        digest=cookie_bridge.cookie_control.effective_digest('example.test',cookie_bridge.cookie_control.materialized_snapshot(rules))
        headers=['Vary: Cookie','X-UltraCache-Cookie-Settings: '+digest,'X-UltraCache-Cookie-Vary: policy-only']
        for profile in ('basic','ultracache'):
            with self.subTest(profile=profile):
                self.run_policy(profile,[http.origin('/page','first',headers=headers),http.origin('/page','second',headers=headers)],
                    [http.get('/page','first',['Cookie: vendor_id=one; site_currency=EUR','X-SCP-Cookie-Contract: '+digest],cache='MISS'),
                     http.get('/page','second',['Cookie: vendor_id=two; site_currency=EUR','X-SCP-Cookie-Contract: '+digest],cache='MISS')],config={'cookie_policies':rules})

    def test_shared_ids_hit_and_origin_still_receives_the_cookie(self):
        for profile in ('basic','ultracache'):
            with self.subTest(profile=profile):
                self.run_policy(profile,[http.origin('/page','shared',headers=['Vary: Cookie'],expect=['expect req.http.Cookie == "campaign_id=first"'])],
                    [http.get('/page','shared',['Cookie: campaign_id=first'],cache='MISS'),
                     http.get('/page','shared',['Cookie: campaign_id=second'],cache='HIT'),
                     'expect resp.http.X-Cache-Cookie-Action == "shared"',
                     'expect resp.http.X-Cache-Cookie-Rule == "custom:campaign"',
                     'expect resp.http.X-Cache-Cookie-Scope == "central"',
                     'expect resp.http.X-Cache-Cookie-Names == "campaign_id"'],
                    config={'cookie_policies':choices()})

    def test_public_variant_is_in_hash_without_origin_vary(self):
        for profile in ('basic','ultracache'):
            with self.subTest(profile=profile):
                self.run_policy(profile,[http.origin('/page','EN',expect=['expect req.http.Cookie == "site_language=en"']),
                                          http.origin('/page','EL',expect=['expect req.http.Cookie == "site_language=el"'])],
                    [http.get('/page','EN',['Cookie: site_language=en'],cache='MISS'),
                     http.get('/page','EN',['Cookie: site_language=en'],cache='HIT'),
                     http.get('/page','EL',['Cookie: site_language=el'],cache='MISS'),
                     http.get('/page','EL',['Cookie: site_language=el'],cache='HIT')],
                    config={'cookie_policies':choices('variant','site_language')})

    def test_private_rule_passes_and_shared_cannot_override_origin_privacy(self):
        for action, cache_control in (('private','public, max-age=120'),('shared','private, no-store')):
            for profile in ('basic','ultracache'):
                with self.subTest(action=action,profile=profile):
                    self.run_policy(profile,[http.origin('/page','first',cache=cache_control),http.origin('/page','second',cache=cache_control)],
                        [http.get('/page','first',['Cookie: campaign_id=one'],cache='PASS'),
                         http.get('/page','second',['Cookie: campaign_id=two'],cache='PASS')],
                        config={'cookie_policies':choices(action)})

    def test_prefix_variants_ignore_unrelated_cookie_values(self):
        for profile in ('basic','ultracache'):
            with self.subTest(profile=profile):
                self.run_policy(profile,[http.origin('/page','EUR'), http.origin('/page','USD')],
                    [http.get('/page','EUR',['Cookie: ordinary=one; site_currency_shop=EUR'],cache='MISS'),
                     http.get('/page','EUR',['Cookie: ordinary=two; site_currency_shop=EUR'],cache='HIT'),
                     http.get('/page','USD',['Cookie: ordinary=three; site_currency_shop=USD'],cache='MISS'),
                     http.get('/page','USD',['Cookie: ordinary=four; site_currency_shop=USD'],cache='HIT')],
                    config={'cookie_policies':choices('variant','site_currency_','prefix')})

    def test_site_automatic_cancels_central_shared_without_affecting_other_account(self):
        original = http.site
        def scoped(*args, **kwargs):
            row = original(*args, **kwargs)
            if row['id'] == 'a'*32: row['cookie_policies'] = choices('automatic')
            return row
        with patch.object(http,'site',side_effect=scoped):
            self.run_policy('basic',[http.origin('/page','one',headers=['Vary: Cookie']),
                                    http.origin('/page','two',headers=['Vary: Cookie']),
                                    http.origin('/page','other',headers=['Vary: Cookie'])],
                [http.get('/page','one',['Cookie: campaign_id=one'],cache='MISS'),
                 http.get('/page','two',['Cookie: campaign_id=two'],cache='MISS'),
                 http.get('/page','other',['Cookie: campaign_id=one'],cache='MISS',host='other.test'),
                 http.get('/page','other',['Cookie: campaign_id=two'],cache='HIT',host='other.test')],
                config={'cookie_policies':choices()})

    def test_login_and_cart_remain_private_even_with_shared_choice(self):
        for cookie in ('wordpress_logged_in_hash=secret', 'wp_woocommerce_session_hash=session'):
            self.run_policy('basic',[http.origin('/page','private')],
                [http.get('/page','private',['Cookie: '+cookie],cache='PASS')],
                config={'cookie_policies':choices('shared',cookie.split('=')[0])})


if __name__ == '__main__': unittest.main()
