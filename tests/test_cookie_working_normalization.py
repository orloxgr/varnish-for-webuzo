"""Compare native working-header normalization with the existing VCL bytes."""
import contextlib
import os
import random
import shutil
import unittest
from unittest.mock import patch

from cookie_admin import _tidy
from test_cookie_delivery import proxy


@unittest.skipUnless(shutil.which('varnishd'), 'Actual native Varnish required')
class CookieWorkingNormalization(unittest.TestCase):
    def exercise(self, disabled=False):
        def transform(source):
            branches = []
            for field in ('remaining', 'variant'):
                header = 'X-SCP-Admin-' + field.title()
                operation = ('cookie_handoff.cookie_remainder_normalize();\n' if field == 'remaining' else
                    'cookie_handoff.cookie_variant_begin();\n'
                    'cookie_handoff.cookie_variant_append(req.http.X-Test-Input);\n'
                    'cookie_handoff.cookie_variant_finish();\n')
                branches.append('if (req.url == "/normalize/' + field + '") {\n'
                    'set req.http.' + header + ' = req.http.X-Test-Input;\n'
                    + operation +
                    'set req.http.X-Test-Native = req.http.' + header + ';\n'
                    'if (req.http.' + header + ' ~ "^") { set req.http.X-Test-Native-Present = "1"; }\n'
                    'else { set req.http.X-Test-Native-Present = "0"; }\n'
                    'set req.http.' + header + ' = req.http.X-Test-Input;\n'
                    + _tidy(header) + '\n'
                    'set req.http.X-Test-Legacy = req.http.' + header + ';\n'
                    'set req.http.X-Test-Legacy-Names = regsuball(req.http.X-Test-Input, "=[^;]*", "");\n'
                    'set req.http.X-Test-Legacy-Names = regsuball(req.http.X-Test-Legacy-Names, ";[[:blank:]]*", ", ");\n'
                    'if (req.http.' + header + ' ~ "^") { set req.http.X-Test-Legacy-Present = "1"; }\n'
                    'else { set req.http.X-Test-Legacy-Present = "0"; }\n'
                    'return (synth(200, "Normalization fixture"));\n}')
            marker = 'sub vcl_recv {'
            self.assertGreaterEqual(source.count(marker), 1)
            source = source.replace(marker, marker + '\n' + '\n'.join(branches), 1)
            marker = 'sub vcl_synth {'
            self.assertGreaterEqual(source.count(marker), 1)
            return source.replace(marker, marker + '\n'
                'if (req.url ~ "^/normalize/") {\n'
                'set resp.http.X-Test-Native = req.http.X-Test-Native;\n'
                'set resp.http.X-Test-Legacy = req.http.X-Test-Legacy;\n'
                'set resp.http.X-Test-Native-Present = req.http.X-Test-Native-Present;\n'
                'set resp.http.X-Test-Legacy-Present = req.http.X-Test-Legacy-Present;\n'
                'set resp.http.X-Test-Native-Names = cookie_handoff.cookie_diagnostic_names(req.http.X-Test-Input, true);\n'
                'set resp.http.X-Test-Legacy-Names = req.http.X-Test-Legacy-Names;\n'
                'return (deliver);\n}', 1)

        cases = ['', ' ', ';', ';\t', 'a=', ' a=1 ; ', ';a=1;; b=2; ',
            'a=1;\t\tb=2', 'a=1; ;b=2', 'a=\xa0;\tb=é ',
            'a="x y"; b=2', ';; a=1 ; ; \tb=2 ;;', 'a=' + 'x'*6144 + '; b=2']
        rng = random.Random(1020)
        alphabet = 'abc012= ;\t,_-:/'
        cases += [''.join(rng.choice(alphabet) for _ in range(rng.randrange(1, 95))) for _ in range(96)]
        module = os.environ.get('SCP_TEST_COOKIE_DISABLED_MODULE')
        if disabled and not module:
            self.skipTest('A separately built disabled-engine module is required')
        env = patch.dict(os.environ, {'SCP_TEST_COOKIE_MODULE': module}) if disabled else contextlib.nullcontext()
        with env, proxy('basic', lambda path, headers: ('unexpected-origin', []), transform=transform,
                daemon_parameters=('http_max_hdr=64',)) as get:
            for field in ('remaining', 'variant'):
                for value in cases:
                    status, fields, _ = get('/normalize/' + field, extra={'X-Test-Input': value})
                    headers = {k.lower(): v for k, v in fields}
                    self.assertEqual(status, 200)
                    self.assertEqual(headers.get('x-test-native'), headers.get('x-test-legacy'), repr(value))
                    self.assertEqual(headers.get('x-test-native-present'), headers.get('x-test-legacy-present'), repr(value))
                    self.assertEqual(headers.get('x-test-native-names'), headers.get('x-test-legacy-names'), repr(value))

    def test_normal_module_matches_legacy_delimiter_bytes(self):
        self.exercise()

    def test_disabled_engine_basic_matches_legacy_delimiter_bytes(self):
        self.exercise(disabled=True)
