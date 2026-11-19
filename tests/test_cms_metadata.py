"""Actual configured routes, static PHP parsing and account-scoped SQL reads."""
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import cms_inventory
import cms_metadata


class Metadata(unittest.TestCase):
    def test_literal_parser_ignores_comments_interpolation_and_conflicting_values(self):
        constants,variables,entries=cms_metadata.settings(r'''<?php
        // define('DB_PASSWORD','not-the-password');
        define('DB_PASSWORD','real\\password\'value');
        define('DB_HOST',"$dynamic_host");
        $table_prefix='wp_';
        public $db = 'joomla';
        /* public $db = 'wrong'; */
        $conflict='one'; $conflict='two';
        return ['database_name'=>'prestashop','irrelevant'=>getenv('SECRET')];
        ''')
        self.assertEqual(constants['DB_PASSWORD'],"real\\password'value")
        self.assertNotIn('DB_HOST',constants)
        self.assertNotIn('conflict',variables)
        self.assertEqual(variables,dict(table_prefix='wp_',db='joomla'))
        self.assertEqual(entries['database_name'],'prestashop')
        self.assertNotIn('irrelevant',entries)

    def test_actual_woo_hierarchy_home_outside_core_and_plain_page_ids(self):
        def query(statement):
            if 'options`' in statement:return [dict(name='home',value='https://example.test/el'),dict(name='woocommerce_cart_page_id',value='7'),dict(name='woocommerce_checkout_page_id',value='8')]
            if 'ID=7 ' in statement:return [dict(id=7,slug='καλάθι',parent=0)]
            if 'ID=8 ' in statement:return [dict(id=8,slug='pay',parent=9)]
            if 'ID=9 ' in statement:return [dict(id=9,slug='orders',parent=0)]
            self.fail(statement)
        row=cms_metadata.aliases(dict(cms='wordpress',base='/wordpress'),query,'wp_',['example.test'])
        self.assertIn('/el/%CE%BA%CE%B1%CE%BB%CE%AC%CE%B8%CE%B9',row['private_paths'])
        self.assertIn('/el/orders/pay',row['private_paths'])
        self.assertEqual(row['private_queries'],[dict(name='page_id',value='7',base='/el'),dict(name='page_id',value='8',base='/el')])

    def test_joomla_actual_menu_aliases_languages_and_itemids(self):
        def query(statement):
            if 'languages`' in statement:return [dict(language='el-GR',sef='el'),dict(language='en-GB',sef='en')]
            return [dict(id=12,path='members/customer',link='index.php?option=com_users&view=profile',language='*'),
                    dict(id=13,path='news',link='index.php?option=com_content&view=article&id=13',language='el-GR')]
        row=cms_metadata.aliases(dict(cms='joomla',base='/cms'),query,'j_',['example.test'])
        self.assertEqual(row['private_paths'],['/cms/el/members/customer','/cms/en/members/customer','/cms/members/customer'])
        self.assertEqual(row['private_queries'],[dict(name='Itemid',value='12',base='/cms')])

    def test_prestashop_localized_personal_rewrites(self):
        row=cms_metadata.aliases(dict(cms='prestashop',base='/store'),lambda statement:[dict(page='my-account',path='mon-compte',language='fr')],'ps_',['example.test'])
        self.assertEqual(row['private_paths'],['/store/fr/mon-compte','/store/mon-compte'])

    def test_native_database_transport_drops_root_and_exposes_no_password_argument(self):
        account=SimpleNamespace(pw_uid=1234,pw_gid=1234,pw_dir='/home/customer')
        site=dict(owner='customer',uid=1234,gid=1234,home='/home/customer')
        connection=dict(host='localhost',user='root',password='private-password',database='database',prefix='wp_')
        with patch.object(cms_inventory.pwd,'getpwnam',return_value=account),patch.object(cms_inventory.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout='{"value":"safe"}\n')) as run:
            result=cms_inventory.query(connection,site,"SELECT JSON_OBJECT('value','safe')")
        self.assertEqual(result,[dict(value='safe')])
        command=run.call_args.args[0]
        self.assertNotIn('private-password',' '.join(command))
        self.assertEqual(command[1],'--no-defaults')
        self.assertEqual(run.call_args.kwargs['user'],1234)
        self.assertEqual(run.call_args.kwargs['group'],1234)
        self.assertEqual(run.call_args.kwargs['extra_groups'],[])
        self.assertIn('START TRANSACTION READ ONLY;',command[-1])
        with self.assertRaisesRegex(ValueError,'SELECT'):cms_inventory.query(connection,site,'UPDATE anything SET x=1')

    def test_failed_refresh_preserves_configured_routes_only_for_same_native_root(self):
        row=dict(cms='wordpress',base='/blog',private_paths=['/blog/personal-cart'],private_queries=[])
        previous=dict(path='/home/site/public_html',cms_installations=[row])
        site=dict(path=previous['path'],names=['example.test'])
        with patch.object(cms_inventory.cms_discovery,'discover',side_effect=lambda *_: [dict(cms='wordpress',base='/blog')]),patch.object(cms_inventory.cms_metadata,'connection',side_effect=OSError):
            records,notices,_=cms_inventory.discover(site,previous)
            self.assertEqual(records,[row]);self.assertIn('last discovered',notices[0])
            records,_,_=cms_inventory.discover(dict(site,path='/home/other/public_html'),previous)
            self.assertNotIn('private_paths',records[0])


if __name__=='__main__':unittest.main()
