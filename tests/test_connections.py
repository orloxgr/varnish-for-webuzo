"""Application connection fields and the loopback-only HTTP bridge."""
import copy
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import connections


class Connections(unittest.TestCase):
    def test_port_cannot_be_impersonated_by_unprivileged_accounts(self):
        with patch.object(Path,'read_text',return_value='1024'):
            self.assertEqual(connections.port(82),82)
            for value in (0,-1,1024,6081,True,'82',1.5):
                with self.subTest(value=value),self.assertRaises(ValueError):connections.port(value)
        with patch.object(Path,'read_text',return_value='0'),self.assertRaisesRegex(ValueError,'privileged binding'):
            connections.port(82)

    def test_occupied_port_does_not_change_configuration(self):
        config={}
        with patch.object(Path,'read_text',return_value='1024'),patch.object(socket,'socket') as listener:
            listener.return_value.__enter__.return_value.bind.side_effect=OSError('busy')
            with self.assertRaisesRegex(ValueError,'already in use'):connections.prepare({},config,82)
        self.assertEqual(config,{})

    def test_existing_owned_connection_keeps_its_identity(self):
        previous=dict(installed=True,control_port=82,control_marker='a'*32);config=copy.deepcopy(previous)
        with patch.object(Path,'read_text',return_value='1024'),patch.object(socket,'socket') as listener:
            connections.prepare(previous,config,82)
        listener.assert_not_called();self.assertEqual(config,previous)

    def test_bridge_is_loopback_only_and_keeps_existing_site_authentication(self):
        with patch.object(Path,'read_text',return_value='1024'):
            text=connections.render(dict(control_port=82,control_marker='a'*32))
        self.assertIn('listen 127.0.0.1:82;',text)
        self.assertIn('^(HEAD|PURGE|BAN)$',text)
        self.assertIn('proxy_set_header Host $http_host;',text)
        self.assertIn('frontend.sock:',text)
        self.assertNotIn('admin.secret',text)
        self.assertNotIn('X-WV-Gateway',text)
        self.assertIn('X-UltraCache-Token $wv_control_token;',text)
        self.assertIn('set $wv_control_token $http_x_webuzo_varnish_token;',text)

    def test_connection_fields_match_the_application_and_only_one_site(self):
        site=dict(domain='example.test',names=['example.test'],enabled=True,profile='ultracache',token='b'*64)
        with patch.object(connections,'available',return_value=True):
            result=connections.details(site,dict(control_port=82))
        self.assertEqual(result['mode'],'HTTP')
        self.assertEqual(result['endpoint'],'http://127.0.0.1:82')
        self.assertEqual(result['header'],'X-Webuzo-Varnish-Token')
        self.assertEqual(result['key'],site['token'])
        self.assertTrue(result['ready'])
        self.assertNotIn('socket',result)


if __name__=='__main__':unittest.main()
