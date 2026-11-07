"""Settings, site-local VCL and cache-budget recovery boundaries."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import cache_size
import engine
import fragments
import native
import policy
import service
import state

@unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid()==0,'Disposable Linux/root tests')
class Settings(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir='/var/lib',prefix='wvw-settings-')
        self.root=Path(self.temp.name)
        self.patches=[patch.object(state,'ROOT',self.root),patch.object(engine,'SETTINGS',self.root/'settings.json'),patch.object(service,'UNIT',self.root/'service.unit')]
        for p in self.patches:p.start()
        self.previous=dict(installed=True,memory_mb=256,sites={})
        state.save(engine.SETTINGS,self.previous);state.write(service.UNIT,service.unit(256).encode())
    def tearDown(self):
        for p in reversed(self.patches):p.stop()
        self.temp.cleanup()
    def test_unchanged_size_does_not_restart_or_create_journal(self):
        with patch.object(service,'restart') as restart:self.assertFalse(cache_size.resize(self.previous,256,engine.SETTINGS))
        restart.assert_not_called();self.assertFalse(cache_size.journal_path().exists())
    def test_resize_changes_only_own_unit_and_persists_budget(self):
        with patch.object(service,'restart') as restart:self.assertTrue(cache_size.resize(self.previous,384,engine.SETTINGS))
        restart.assert_called_once_with(384)
        self.assertEqual(engine.settings()['memory_mb'],384);self.assertEqual(service.UNIT.read_text(),service.unit(384))
        self.assertFalse(cache_size.journal_path().exists())
    def test_failed_resize_restores_previous_budget_and_restarts_it(self):
        with patch.object(service,'restart',side_effect=[RuntimeError('Injected startup failure'),None]) as restart:
            with self.assertRaisesRegex(RuntimeError,'previous size was restored'):cache_size.resize(self.previous,384,engine.SETTINGS)
        self.assertEqual(restart.call_args_list[0].args,(384,));self.assertEqual(restart.call_args_list[1].args,(256,))
        self.assertEqual(engine.settings(),self.previous);self.assertEqual(service.UNIT.read_text(),service.unit(256));self.assertFalse(cache_size.journal_path().exists())
    def test_interrupted_resize_is_recovered_from_durable_journal(self):
        updated=dict(self.previous,memory_mb=384)
        state.save(cache_size.journal_path(),dict(previous=self.previous,next=updated))
        state.save(engine.SETTINGS,updated);state.write(service.UNIT,service.unit(384).encode())
        with patch.object(service,'restart') as restart:cache_size.recover(engine.SETTINGS)
        restart.assert_called_once_with(256);self.assertEqual(engine.settings(),self.previous)
    def test_recovery_failure_keeps_journal_for_next_request(self):
        with patch.object(service,'restart',side_effect=RuntimeError('Injected unavailable daemon')):
            with self.assertRaisesRegex(RuntimeError,'recovery is pending'):cache_size.resize(self.previous,384,engine.SETTINGS)
        self.assertTrue(cache_size.journal_path().exists())
    def test_independent_unit_and_invalid_size_are_never_overwritten(self):
        service.UNIT.write_text('# independent administrator unit\n')
        for value in (384,0,-1,True,'384',1.5):
            with self.subTest(value=value),patch.object(service,'restart') as restart,self.assertRaises(ValueError):cache_size.resize(self.previous,value,engine.SETTINGS)
            restart.assert_not_called()
        self.assertEqual(service.UNIT.read_text(),'# independent administrator unit\n');self.assertFalse(cache_size.journal_path().exists())
    def test_usage_reads_only_own_instance_and_distinguishes_process_memory(self):
        counters={name:{'value':value} for name,value in [('SMA.s0.g_bytes',1048576),('SMA.s0.g_space',267386880),('MAIN.cache_hit',12)]}
        with patch.object(native,'run',side_effect=[json.dumps({'counters':counters}),'123456789']) as run:result=service.usage(self.previous)
        self.assertEqual(run.call_args_list[0].args,('/usr/bin/varnishstat','-n',service.CACHE,'-1','-j'))
        self.assertEqual(result['used_bytes'],1048576);self.assertEqual(result['process_bytes'],123456789);self.assertIsNone(result['passes'])
    def test_missing_native_counters_are_reported_as_unavailable(self):
        with patch.object(native,'run',return_value='{}'),self.assertRaisesRegex(RuntimeError,'counters are unavailable'):service.usage(self.previous)
    def test_site_vcl_cannot_read_secrets_escape_scope_or_run_code(self):
        values=['import std;', 'include "/etc/passwd";', 'C{system("id");}C', '} return (hash);', 'call vcl_recv;',
                'set req.http.Host = "another.test";', 'set req.http.X-WV-Site = "another";',
                'set req.http.X-User-Leak = req.http.X-WV-Origin;', 'set req.http.X-User-Leak = req.http.x-wv-origin;',
                'set req.http.X-User-Leak = req.http.X-Webuzo-Varnish-Token;', 'return (synth(200));']
        for value in values:
            with self.subTest(value=value),self.assertRaises(ValueError):fragments.validate(value,'recv')
        with self.assertRaises(ValueError):fragments.validate('set beresp.http.Cache-Control = "public";','backend_response')
    def test_supported_vcl_remains_inside_site_scope_and_before_response_checks(self):
        site=dict(id='a'*32,domain='example.test',names=['example.test'],enabled=True,error='',token='b'*64,ttl=300,bypass=[],
            recv_vcl='if (req.url ~ "^/private/") { return (pass); }',backend_vcl='set beresp.ttl = 60s;')
        content=policy.render({site['id']:site},'e'*64,'f'*64)
        self.assertIn('if (req.http.X-WV-Site == "'+'a'*32+'") { if',content)
        self.assertIn('set req.http.X-WV-Mode = "PASS"; return ( pass ) ;',content)
        response=content[content.index('sub vcl_backend_response {'):]
        self.assertLess(response.index('set beresp.ttl = 60s'),response.index('beresp.http.Set-Cookie'))
        self.assertLess(response.index('beresp.http.Set-Cookie'),response.index('beresp.ttl > 300s'))
    def test_pass_annotation_does_not_rewrite_a_string_literal(self):
        result=fragments.validate('set req.http.X-User-Note = "return ( pass ) ;"; return (pass);','recv',mark_pass=True)
        self.assertIn('"return ( pass ) ;"',result)
        self.assertEqual(result.count('X-WV-Mode'),1)
    def test_normal_status_contains_no_connection_key(self):
        site=dict(id='a'*32,domain='example.test',enabled=True,error='',token='b'*64,uid=1000,gid=1000,home='/home/example')
        with patch.object(engine,'inventory',return_value={site['id']:site}),patch.object(service,'installed',return_value=True),patch.object(service,'running',return_value=True):result=engine.status()
        self.assertNotIn('b'*64,json.dumps(result));self.assertNotIn('home',result['sites'][0])
    def test_adding_empty_vcl_defaults_does_not_purge_another_account(self):
        first=dict(id='a'*32,domain='first.example.test',names=['first.example.test'],enabled=True,error='',token='b'*64,ttl=300,bypass=[])
        second=dict(first,id='c'*32,domain='second.example.test',names=['second.example.test'],token='d'*64)
        previous=dict(installed=True,sites={first['id']:first,second['id']:second},gateway='e'*64,origin='f'*64)
        updated=copy.deepcopy(previous)
        for site in updated['sites'].values():site.update(recv_vcl='',backend_vcl='')
        updated['sites'][first['id']]['recv_vcl']='if (req.url == "/members/") { return (pass); }'
        with patch.object(engine,'JOURNAL',self.root/'transaction.json'),patch.object(engine,'plans',return_value=[]),patch.object(service,'ACTIVE',self.root/'active.vcl'),patch.object(service,'load',return_value=('old','new')),patch.object(service,'admin'),patch.object(service,'write_vcl'),patch.object(service,'prune'),patch.object(engine,'reload_servers'),patch.object(service,'purge') as purge:
            engine.apply(previous,updated)
        purge.assert_called_once_with(updated['sites'][first['id']])
    def test_central_basic_rules_invalidate_only_sites_assigned_to_basic(self):
        first=dict(id='a'*32,domain='first.example.test',names=['first.example.test'],enabled=True,error='',token='b'*64,ttl=300,bypass=[],profile='basic')
        second=dict(first,id='c'*32,domain='second.example.test',names=['second.example.test'],token='d'*64,profile='wordpress')
        previous=dict(installed=True,sites={first['id']:first,second['id']:second},gateway='e'*64,origin='f'*64)
        updated=copy.deepcopy(previous);updated['profile_rules']={'basic':{'recv_vcl':'if (req.url == "/members/") { return (pass); }','backend_vcl':''}}
        with patch.object(engine,'JOURNAL',self.root/'transaction.json'),patch.object(engine,'plans',return_value=[]),patch.object(service,'ACTIVE',self.root/'active.vcl'),patch.object(service,'load',return_value=('old','new')),patch.object(service,'admin'),patch.object(service,'write_vcl'),patch.object(service,'prune'),patch.object(engine,'reload_servers'),patch.object(service,'purge') as purge:
            engine.apply(previous,updated)
        purge.assert_called_once_with(updated['sites'][first['id']])

if __name__=='__main__':unittest.main()
