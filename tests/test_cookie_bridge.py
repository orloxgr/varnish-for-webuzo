"""Native adapter journal protocol; actual HTTP authentication belongs to shared tests."""
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import cookie_bridge as bridge


def settings(action='shared'):
    return {'schemaVersion':1,'rules':[dict(id='custom:site',match=dict(kind='exact',value='site_choice'),description='Local choice',action=action)]}


def site(enabled=False,url=None):
    return dict(id='a'*32,domain='example.test',names=['example.test','www.example.test'],token='b'*64,
                cookie_policies=settings(),cookie_integration=dict(enabled=enabled,url=url or 'https://example.test'+bridge.cookie_control.PATH))


class NativeBridgePlan(unittest.TestCase):
    def test_defaults_upgrade_syncs_concrete_bundle_and_preserves_explicit_site_choice(self):
        before={'cookie_defaults_digest':'previous','sites':{'a'*32:site(True)}}
        after=copy.deepcopy(before);after['cookie_defaults_digest']='current'
        operations=bridge.plan(before,after)
        self.assertEqual(len(operations),1)
        snapshot=operations[0]['policy']
        self.assertEqual(snapshot,bridge.cookie_control.materialized_snapshot(None,settings()))
        self.assertGreater(len(snapshot['central']['rules']),2000)
        self.assertEqual(snapshot['site'],settings())
        self.assertTrue(all(rule['action'] in ('shared','variant','private') for scope in ('central','site') for rule in snapshot[scope]['rules']))

    def test_editorial_bundle_version_change_does_not_resync_application(self):
        before={'cookie_defaults_version':'old','cookie_defaults_digest':'same','sites':{'a'*32:site(True)}}
        after=copy.deepcopy(before);after['cookie_defaults_version']='new'
        self.assertEqual(bridge.plan(before,after),[])

    def test_disabled_connection_never_instantiates_an_http_client(self):
        before={'sites':{'a'*32:site()}}; after=copy.deepcopy(before);after['sites']['a'*32]['cookie_policies']=settings('variant')
        with patch.object(bridge.cookie_control,'Client') as client:
            self.assertEqual(bridge.plan(before,after),[])
        client.assert_not_called()

    def test_disabled_connections_skip_full_projection_but_still_disconnect(self):
        before={'sites':{'a'*32:site(True)}}
        after=copy.deepcopy(before);after['sites']['a'*32]['cookie_integration']['enabled']=False
        with patch.object(bridge.cookie_execution.cookie_admin,'executable',side_effect=AssertionError('Unneeded projection')):
            planned=bridge.plan(before,after)
            self.assertEqual([item['kind'] for item in planned],['disconnect'])
            self.assertEqual(planned[0]['policy'],bridge.cookie_control.snapshot())
            self.assertEqual(bridge.plan(after,copy.deepcopy(after)),[])

    def test_connected_sites_reuse_identical_inputs_without_losing_scoped_changes(self):
        sites={}
        for index in range(48):
            entry=site(True);entry['id']=format(index,'032x');sites[entry['id']]=entry
        before={'sites':sites};after=copy.deepcopy(before)
        after['sites'][format(17,'032x')]['cookie_policies']=settings('private')
        actual=bridge.cookie_execution.cookie_admin.executable
        with patch.object(bridge.cookie_execution.cookie_admin,'executable',wraps=actual) as projection:
            planned=bridge.plan(before,after)
        self.assertEqual(projection.call_count,2)
        self.assertEqual([item['site'] for item in planned],[format(17,'032x')])
        self.assertEqual(planned[0]['policy']['site'],settings('private'))

    def test_enable_and_disable_apply_then_restore_application_baseline(self):
        before={'sites':{'a'*32:site()}}; after={'sites':{'a'*32:site(True)}}
        enabled=bridge.plan(before,after)
        self.assertEqual(len(enabled),1)
        self.assertEqual(enabled[0]['policy']['site'],settings())
        disabled=bridge.plan(after,before)
        self.assertEqual(len(disabled),1)
        self.assertEqual(disabled[0]['policy'],bridge.cookie_control.snapshot())
        self.assertEqual(disabled[0]['configuration'],after['sites']['a'*32]['cookie_integration'])

    def test_endpoint_switch_clears_old_then_applies_new_owned_host(self):
        before={'sites':{'a'*32:site(True)}}
        after={'sites':{'a'*32:site(True,'https://www.example.test'+bridge.cookie_control.PATH)}}
        operations=bridge.plan(before,after)
        self.assertEqual(len(operations),2)
        self.assertEqual(operations[0]['policy'],bridge.cookie_control.snapshot())
        self.assertIn('www.example.test',operations[1]['configuration']['url'])
        self.assertNotEqual(operations[0]['request_id'],operations[1]['request_id'])
        self.assertEqual(bridge.client_for(operations[1]).host,'www.example.test')

    def test_unowned_endpoint_or_arbitrary_path_is_rejected_before_request(self):
        for value in ('https://other.test'+bridge.cookie_control.PATH,'https://example.test/admin','https://example.test'+bridge.cookie_control.PATH+'?x=1'):
            with self.subTest(url=value),self.assertRaises(ValueError):
                bridge.configuration(dict(enabled=True,url=value),site())

    def test_explicit_resync_inspects_application_even_if_local_snapshot_is_unchanged(self):
        config={'sites':{'a'*32:site(True)}}
        self.assertEqual(bridge.plan(config,copy.deepcopy(config)),[])
        forced=bridge.plan(config,copy.deepcopy(config),force_sites=('a'*32,))
        self.assertEqual(len(forced),1)
        self.assertEqual(forced[0]['policy']['site'],settings())

    def test_journal_precedes_remote_mutation_and_lost_commit_reply_is_rolled_back(self):
        before={'sites':{'a'*32:site(False)}};after={'sites':{'a'*32:site(True)}}
        journal={'cookie_operations':bridge.plan(before,after)}; saved=[]; active=['c'*64]; calls=[]
        original=bridge.cookie_control.Client
        class Client(original):
            def call(self,operation):
                calls.append((operation,self.request_id))
                if operation=='status': self.base_digest=active[0]
                elif operation=='prepare':
                    assert saved[-1]['cookie_operations'][0]['phase']=='preparing'
                    assert saved[-1]['cookie_operations'][0]['base_digest']==active[0]
                elif operation=='commit':
                    assert saved[-1]['cookie_operations'][0]['phase']=='committing'
                    active[0]=self.target_digest
                    raise bridge.cookie_control.ControlError('Lost commit reply')
                elif operation=='rollback':
                    assert active[0]==self.target_digest
                    active[0]=self.base_digest
                    return {'rollbackState':'restored','activeDigest':active[0]}
                return {'capabilities':{'scopedCookiePolicies':True}}
        persist=lambda value:saved.append(copy.deepcopy(value))
        with patch.object(bridge.cookie_control,'Client',Client):
            bridge.prepare(journal,persist)
            with self.assertRaises(bridge.cookie_control.ControlError):bridge.commit(journal,persist)
            self.assertEqual(journal['cookie_operations'][0]['phase'],'committing')
            bridge.rollback(journal,persist)
        self.assertEqual(active[0],'c'*64)
        self.assertEqual(journal['cookie_operations'][0]['phase'],'rolled-back')
        self.assertEqual(len({identity for _,identity in calls}),1)

    def test_failed_rollback_remains_recoverable_without_new_identity(self):
        item=bridge.plan({'sites':{'a'*32:site(False)}},{'sites':{'a'*32:site(True)}})[0]
        item.update(base_digest='c'*64,phase='committing');journal={'cookie_operations':[item]}
        identity=item['request_id']; original=bridge.cookie_control.Client
        class Client(original):
            def call(self,operation): raise bridge.cookie_control.ControlError('Rollback unavailable')
        with patch.object(bridge.cookie_control,'Client',Client),self.assertRaises(bridge.cookie_control.ControlError):
            bridge.rollback(journal,lambda value:None)
        self.assertEqual(item['phase'],'committing');self.assertEqual(item['request_id'],identity)

    def test_metadata_only_inventory_does_not_contact_application(self):
        before={'sites':{'a'*32:site(True)}};after=copy.deepcopy(before)
        after['sites']['a'*32]['cookie_policies']['rules'][0]['description']='Updated label'
        self.assertEqual(bridge.plan(before,after),[])

    def test_same_application_url_switch_prepares_new_digest_after_disconnect_and_rolls_back(self):
        before={'sites':{'a'*32:site(True)}}
        after={'sites':{'a'*32:site(True,'https://www.example.test'+bridge.cookie_control.PATH)}}
        journal={'cookie_operations':bridge.plan(before,after)};saved=[];active=['c'*64];calls=[]
        original=bridge.cookie_control.Client
        class Client(original):
            def call(client,operation):
                calls.append((client.host,operation))
                if operation=='status':client.base_digest=active[0]
                elif operation=='prepare':
                    self.assertEqual(client.base_digest,active[0])
                    self.assertEqual(saved[-1]['cookie_operations'][0 if client.host=='example.test'else 1]['phase'],'preparing')
                elif operation=='commit':
                    self.assertEqual(client.base_digest,active[0]);active[0]=client.target_digest
                elif operation=='rollback':
                    self.assertEqual(active[0],client.target_digest);active[0]=client.base_digest
                    return {'rollbackState':'restored','activeDigest':active[0]}
                return {'capabilities':{'scopedCookiePolicies':True}}
        persist=lambda value:saved.append(copy.deepcopy(value))
        with patch.object(bridge.cookie_control,'Client',Client):
            bridge.prepare(journal,persist)
            self.assertEqual(journal['cookie_operations'][1]['phase'],'deferred')
            self.assertNotIn(('www.example.test','status'),calls)
            bridge.commit(journal,persist)
            self.assertEqual(journal['cookie_operations'][1]['base_digest'],journal['cookie_operations'][0]['target_digest'])
            bridge.rollback(journal,persist)
        self.assertEqual(active[0],'c'*64)
        self.assertLess(calls.index(('example.test','commit')),calls.index(('www.example.test','status')))

    def test_superseded_remote_write_is_preserved_and_abort_can_finish(self):
        item=bridge.plan({'sites':{'a'*32:site(False)}},{'sites':{'a'*32:site(True)}})[0]
        item.update(base_digest='c'*64,phase='committing');journal={'cookie_operations':[item]}
        with patch.object(bridge.cookie_control.Client,'call',return_value={'rollbackState':'superseded','activeDigest':'d'*64}):
            bridge.rollback(journal,lambda value:None)
        self.assertEqual(item['phase'],'rolled-back')
        self.assertEqual(bridge.preserved_newer(journal),[dict(site='a'*32,state='superseded',active_digest='d'*64)])

    def test_unprepared_deferred_operation_is_not_rolled_back(self):
        item=bridge.plan({'sites':{'a'*32:site(False)}},{'sites':{'a'*32:site(True)}})[0]
        item['phase']='deferred'
        with patch.object(bridge.cookie_control.Client,'call') as call:
            bridge.rollback({'cookie_operations':[item]},lambda value:None)
        call.assert_not_called()

    def test_lost_native_alias_is_revoked_without_requesting_its_new_owner(self):
        old=site(True,'https://www.example.test'+bridge.cookie_control.PATH)
        current=copy.deepcopy(old);current['names']=['example.test']
        current['cookie_integration'],revoked=bridge.cookie_control.reconcile_integration(old['cookie_integration'],current['domain'],current['names'])
        self.assertTrue(revoked);self.assertFalse(current['cookie_integration']['enabled'])
        with patch.object(bridge.cookie_control,'Client') as client:
            self.assertEqual(bridge.plan({'sites':{'a'*32:old}},{'sites':{'a'*32:current}}),[])
        client.assert_not_called()

    def test_disabled_saved_endpoint_does_not_block_unrelated_inventory(self):
        config={'sites':{'a'*32:site(False,'not configured')}}
        with patch.object(bridge.cookie_control,'Client') as client:
            self.assertEqual(bridge.plan(config,copy.deepcopy(config)),[])
        client.assert_not_called()


if __name__=='__main__':unittest.main()
