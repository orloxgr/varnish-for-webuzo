"""Native ESI attribute processing, scoped private fragments and service upgrade."""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import service
import lifecycle
import state
import cache_size
import test_profiles as http


@unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid() == 0, 'Linux/root fixture')
class ServiceFeatures(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir='/var/lib', prefix='wvw-esi-')
        self.path = Path(self.temp.name) / 'service.unit'
        self.patch = patch.object(service, 'UNIT', self.path)
        self.patch.start()
        self.original = service.unit(8192).replace(' -p feature=+esi_ignore_other_elements', '').encode()
        self.path.write_bytes(self.original)

    def tearDown(self):
        self.patch.stop()
        self.temp.cleanup()

    def test_upgrade_persists_flag_and_updates_runtime_without_restart(self):
        with patch.object(service, 'running', return_value=True), patch.object(service.native, 'run') as run, patch.object(service, 'admin') as admin:
            service.configure_esi(8192)
            self.assertEqual(self.path.read_text(), service.unit(8192))
            self.assertIn('-s malloc,8192m', self.path.read_text())
            run.assert_called_once_with('systemctl', 'daemon-reload')
            admin.assert_called_once_with('param.set', 'feature', '+esi_ignore_other_elements')
            run.reset_mock(); admin.reset_mock()
            service.configure_esi(8192)
            run.assert_not_called()
            admin.assert_called_once_with('param.set', 'feature', '+esi_ignore_other_elements')

    def test_native_failure_restores_previous_unit(self):
        with patch.object(service, 'running', return_value=True), patch.object(service.native, 'run') as run, patch.object(service, 'admin', side_effect=RuntimeError('Native parameter failed')):
            with self.assertRaisesRegex(RuntimeError, 'Native parameter failed'):
                service.configure_esi(8192)
            self.assertEqual(self.path.read_bytes(), self.original)
            self.assertEqual([call.args for call in run.call_args_list], [('systemctl', 'daemon-reload'), ('systemctl', 'daemon-reload')])

    def test_stopped_service_is_not_started(self):
        with patch.object(service, 'running', return_value=False), patch.object(service.native, 'run') as run, patch.object(service, 'admin') as admin:
            service.configure_esi(8192)
            self.assertEqual(self.path.read_text(), service.unit(8192))
            run.assert_called_once_with('systemctl', 'daemon-reload')
            admin.assert_not_called()

    def test_unmanaged_unit_and_wrong_cache_size_are_not_replaced(self):
        for content in (b'Administrator unit', self.original.replace(b'malloc,8192m', b'malloc,4096m')):
            self.path.write_bytes(content)
            with patch.object(service.native, 'run') as run, patch.object(service, 'admin') as admin:
                with self.assertRaisesRegex(ValueError, 'owned service unit was changed'):
                    service.configure_esi(8192)
                self.assertEqual(self.path.read_bytes(), content)
                run.assert_not_called(); admin.assert_not_called()

    def test_native_activation_updates_only_an_already_installed_service(self):
        root = self.path.parent
        panel = SimpleNamespace(pw_uid=1000, pw_gid=1000, pw_name='webuzo')
        with patch.object(state, 'ROOT', root), patch.object(state, 'RUN', root / 'run'), \
             patch.object(lifecycle, 'TMP', root / 'tmpfiles.conf'), \
             patch.object(lifecycle.pwd, 'getpwnam', return_value=panel), \
             patch.object(lifecycle.pwd, 'getpwall', return_value=[panel]), \
             patch.object(lifecycle.grp, 'getgrgid', return_value=SimpleNamespace(gr_mem=[])), \
             patch.object(service, 'configure_esi') as configure, patch.object(cache_size, 'recover') as recover:
            lifecycle.install()
            configure.assert_not_called(); recover.assert_not_called()
            state.save(root / 'settings.json', dict(installed=True, memory_mb=8192))
            lifecycle.install()
            recover.assert_called_once_with(root / 'settings.json')
            configure.assert_called_once_with()


@unittest.skipUnless(shutil.which('varnishtest'), 'native varnishtest required')
class NonceEsi(unittest.TestCase):
    run_policy = http.NativeProfiles.run_policy

    def test_startup_flags_compose_all_contexts_with_private_visitor_fragments(self):
        startup = next(line.split('=', 1)[1] for line in service.unit(8192).splitlines() if line.startswith('ExecStart=/'))
        tokens = shlex.split(startup)
        flag = tokens[tokens.index('-p') + 1]
        paths = {context: '/?ultracache_esi=nonce&esi_scope=private&context=' + context + '&sig=fixture'
                 for context in ('js', 'json', 'attribute')}
        tags = {context: '<esi:include src="' + path.replace('&', '&amp;') + '"/>' for context, path in paths.items()}

        def body(values):
            return ('<html><script>window.nonce=\'' + values['js'] + '\';</script>' +
                    '<script type="application/json">{"nonce":"' + values['json'] + '"}</script>' +
                    "<input value='" + values['attribute'] + "'></html>")

        origins = [http.origin('/nonce-parent', body(tags), headers=[
            'Surrogate-Control: ESI/1.0', 'X-UltraCache-ESI-Shared-Parent: 1'])]
        requests = []
        for index, visitor in enumerate(('A', 'B', 'A')):
            values = {context: visitor + str(index) + context for context in paths}
            for context, path in paths.items():
                origins.append(http.origin(path, values[context], mime='text/plain', headers=[
                    'Set-Cookie: fragment_cookie=must-not-reach-browser'],
                    expect=['expect req.http.Cookie == "wp_woocommerce_session_demo=' + visitor + '"',
                            'expect req.http.X-ESI-Private-Request == "1"',
                            'expect req.http.X-ESI-Original-Cookie == <undef>']))
            requests += [http.get('/nonce-parent', body(values), headers=[
                'Cookie: wp_woocommerce_session_demo=' + visitor + '; ultracache_esi_optin=1; unrelated=do-not-forward'],
                cache='MISS' if index == 0 else 'HIT'), 'expect resp.http.Set-Cookie == <undef>']
        self.run_policy('ultracache', origins, requests, varnish_args='-arg "-p ' + flag + '"')

    def test_runtime_feature_update_is_additive_and_effective_without_restart(self):
        source = http.program('ultracache')
        tag = '<esi:include src="/?ultracache_esi=nonce&amp;esi_scope=private"/>'
        parent = "<html><input value='" + tag + "'></html>"
        origins = '\n'.join([
            http.origin('/parent', parent, headers=['Surrogate-Control: ESI/1.0']),
            http.origin('/?ultracache_esi=nonce&esi_scope=private', 'newnonce', mime='text/plain')]).removeprefix('accept\n')
        script = ('varnishtest "Add ESI attribute feature without resetting other flags"\nserver s1 {\n' + origins +
                  '\n} -start\nvarnish v1 -arg "-p feature=+esi_remove_bom" -vcl {\n' + source +
                  '\n} -start\nvarnish v1 -cliok "param.set feature +esi_ignore_other_elements"\n' +
                  'varnish v1 -cliexpect "esi_remove_bom" "param.show feature"\n' +
                  'client c1 {\n' + http.get('/parent', "<html><input value='newnonce'></html>") +
                  '\n} -run\nserver s1 -wait\n')
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'runtime.vtc'; path.write_text(script)
            result = subprocess.run(['varnishtest', '-t', '15', str(path)], capture_output=True, text=True, timeout=25)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_cold_private_parent_with_set_cookie_still_composes_esi(self):
        fragment = '/?ultracache_esi=cart&esi_scope=private'
        tag = '<esi:include src="/?ultracache_esi=cart&amp;esi_scope=private"/>'
        origins, requests = [], []
        for visitor in ('A', 'B'):
            origins += [http.origin('/cold', '<html>native-nonce-' + visitor + tag + '</html>',
                cache='private, no-store', headers=[
                    'Surrogate-Control: content=ESI/1.0, no-store',
                    'Set-Cookie: wp_woocommerce_session_demo=' + visitor + '; Path=/']),
                http.origin(fragment, 'empty-cart', mime='text/plain',
                    expect=['expect req.http.Cookie == <undef>'])]
            requests += [http.get('/cold', '<html>native-nonce-' + visitor + 'empty-cart</html>', cache='PASS'),
                'expect resp.http.Set-Cookie == "wp_woocommerce_session_demo=' + visitor + '; Path=/"']
        self.run_policy('ultracache', origins, requests)


if __name__ == '__main__':
    unittest.main()
