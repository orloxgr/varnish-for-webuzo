"""Hosting timeout inheritance and removal of administrative job deadlines."""
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import native
import policy
import routing
import timeouts


class HostingTimeouts(unittest.TestCase):
    def test_native_overrides_are_not_replaced_with_our_old_values(self):
        dump='''# configuration file /usr/local/apps/nginx/etc/nginx.conf:
http {
    proxy_read_timeout 10m;
}
# configuration file /usr/local/apps/nginx/etc/conf.d/proxy.conf:
proxy_connect_timeout 300s;
proxy_read_timeout 300s;
proxy_send_timeout 300s;
# configuration file /var/webuzo-data/nginx/custom/domains/example.test.conf:
proxy_read_timeout 2h;
# configuration file /etc/varnish-for-webuzo/origins.conf:
proxy_connect_timeout 2s;
proxy_read_timeout 120s;
proxy_send_timeout 120s;
'''
        self.assertEqual(timeouts.discover(dump),dict(connect=300000,read=7200000,send=300000))
        self.assertEqual(timeouts.discover(dump.replace('proxy_read_timeout 120s;','proxy_read_timeout 99d;')),timeouts.discover(dump))

    def test_missing_settings_use_native_nginx_defaults(self):
        self.assertEqual(timeouts.discover('# configuration file /native/nginx.conf:\nhttp {}'),dict(connect=60000,read=60000,send=60000))

    def test_existing_short_native_connection_allowance_is_preserved(self):
        self.assertEqual(timeouts.discover('# configuration file /native/proxy.conf:\nproxy_connect_timeout 500ms;')['connect'],500)

    def test_native_time_units_and_millisecond_precision(self):
        for value,expected in [('300',300000),('1m30s',90000),('1s250ms',1250),('"1h 30m"',5400000),('3d',259200000)]:
            with self.subTest(value=value):self.assertEqual(timeouts.duration(value),expected)
        self.assertEqual(timeouts.seconds(1250),'1.25s')

    def test_malformed_or_injectable_values_do_not_enter_configuration(self):
        for value in ['5s;return 200','1.5s','$variable','infinity','-5s']:
            with self.subTest(value=value),self.assertRaises(ValueError):timeouts.duration(value)
        for values in [dict(connect=True,read=1,send=1),dict(connect=0,read=1,send=1),dict(connect=1,read=1,send='30s'),{},None]:
            with self.subTest(values=values),self.assertRaises(ValueError):timeouts.validate(values)
        with self.assertRaises(ValueError):timeouts.discover('not a configuration dump')

    def test_outer_proxy_allows_the_origin_phases_and_native_fallback_is_preserved(self):
        values=dict(connect=4500,read=900000,send=600000)
        text=routing.domain(dict(id='a'*32,names=['example.test'],bypass=[]),'b'*64,values)
        self.assertIn('proxy_read_timeout 2109s;',text)
        self.assertIn('proxy_read_timeout 900s;',text)
        origin=routing.origins('c'*64,values)
        self.assertIn('proxy_connect_timeout 4.5s;',origin)
        self.assertIn('proxy_read_timeout 900s;',origin)
        self.assertIn('proxy_send_timeout 600s;',origin)

    def test_varnish_includes_native_allowances_for_pass_and_miss(self):
        source=policy.render({},'e'*64,'f'*64,{'proxy_timeouts':dict(connect=300000,read=900000,send=300000)})
        self.assertIn('.first_byte_timeout = 1500s;',source)
        self.assertIn('.between_bytes_timeout = 900s;',source)
        self.assertIn('set sess.idle_send_timeout = 900s;',source)
        self.assertIn('if (sess.send_timeout < 2100s)',source)
        self.assertIn('set sess.send_timeout = 2100s;',source)

    def test_administrative_process_waits_for_completion_and_keeps_full_error(self):
        message='original diagnostic\n'*1000
        with patch.object(subprocess,'run',return_value=subprocess.CompletedProcess([],1,'',message)) as run:
            with self.assertRaises(RuntimeError) as failure:native.run('example-command')
        self.assertIsNone(run.call_args.kwargs['timeout'])
        self.assertEqual(str(failure.exception),message)


if __name__=='__main__':unittest.main()
