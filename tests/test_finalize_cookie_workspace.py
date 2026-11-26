"""Normal browser cookies and thirteen private placements at native defaults.

Synthetic values only. The trusted producer actor qualifies native ownership,
not application identity. No installed service or workspace parameter changes.
"""
from contextlib import contextmanager
import json
import os
import re
import shutil
import subprocess
import unittest
from unittest.mock import patch

import test_reuse_full_runtime as reuse
from test_backend_header_budget import BROWSER
from test_cold_public_selection import choices
from test_cookie_delivery import proxy
from test_request_workspace import retained


@unittest.skipUnless(shutil.which('varnishd') and os.environ.get('SCP_EXPERIMENTAL_REUSE_TEST') == '1',
                     'Explicit matching-source native module required')
class FinalizeCookieWorkspace(unittest.TestCase):
    def test_original_cookie_classification_survives_cookie_free_finalizer_and_thirteen_placements(self):
        original_envelope = reuse.envelope
        original_seal = reuse.seal_recipe
        original_body = reuse.BODY
        body = original_body.replace('</html>',
            ('<esi:include src="'+reuse.ADAPTIVE.replace('&', '&amp;')+'"/>')*10+'</html>')
        meta = [(name, '13' if name == 'X-UltraCache-ESI-Private-Count' else value)
                for name, value in reuse.META]
        shared = ('cmplz_banner-status', 'cmplz_consented_services', 'cmplz_functional', 'cmplz_id',
                  'cmplz_marketing', 'cmplz_policy_id', 'cmplz_preferences', 'cmplz_statistics')
        browser = {name: value for name, value in BROWSER.items()
                   if name not in ('Pragma', 'Cache-Control', 'Referer')}
        browser['User-Agent'] += ' '+('b'*(125-len(browser['User-Agent'])-1))
        browser['Accept'] += ',application/x-fixture-'+('a'*(135-len(browser['Accept'])-23))
        self.assertEqual((len(browser['User-Agent']), len(browser['Accept'])), (125, 135))

        def envelope(*args, **kwargs):
            result = json.loads(original_envelope(*args, **kwargs))
            next(row for row in result['renderedFragments'] if row['url'] == reuse.ADAPTIVE)['occurrences'] = 11
            return json.dumps(result)

        def seal(value):
            next(row for row in value['fragments'] if row['url'] == reuse.ADAPTIVE)['occurrences'] = 11
            return original_seal(value)

        @contextmanager
        def browser_proxy(*args, **kwargs):
            original_transform = kwargs.pop('transform')
            def transform(source):
                source = original_transform(source)
                return source.replace('sub scp_admin_cookie_rules {', 'sub scp_admin_cookie_rules {\n'
                    'if (req.esi_level == 0 && req.http.Cookie) { std.log("fixture-cookie-classification"); }', 1)
            kwargs.update(transform=transform, policies=choices(*[(name, 'shared') for name in shared]),
                          site_settings={'cms_installations': [{'cms': 'wordpress', 'base': '/'}]})
            with proxy(*args, **kwargs) as get:
                requests = []
                def request(path, cookie=None, extra=None):
                    fields = {**browser, **(extra or {})}
                    if cookie:
                        # Match the retained ordinary owner Cookie wire length,
                        # preserving exact caller identity and public fixtures.
                        cookie += '; '+retained(1678-len(cookie)-2)
                        self.assertEqual(len(cookie), 1678)
                        marker = str(len(requests)+1)
                        requests.append(marker); fields['X-Fixture-Workspace'] = marker
                    result = get(path, cookie, fields)
                    if result[0] != 200:
                        trace = subprocess.check_output(['varnishlog', '-n', str(get.instance), '-d',
                            '-i', 'Error,VCL_Error,LostHeader'], text=True)
                        self.fail(str(result[:2])+'\n'+trace)
                    return result
                for name, value in vars(get).items(): setattr(request, name, value)
                yield request
                for marker in requests:
                    trace = subprocess.check_output(['varnishlog', '-n', str(get.instance), '-d', '-g', 'request',
                        '-q', 'ReqHeader:X-Fixture-Workspace == "'+marker+'"', '-i', 'VCL_Log'], text=True)
                    self.assertEqual(trace.count('fixture-cookie-classification'), 1,
                        'The same original Cookie must be classified once across finalization\n'+trace)
                errors = subprocess.check_output(['varnishlog', '-n', str(get.instance), '-d',
                    '-i', 'Error,VCL_Error,LostHeader'], text=True)
                self.assertFalse(re.search(r'\b(?:Error|VCL_Error|LostHeader)\s', errors), errors)

        with patch.object(reuse, 'BODY', body), patch.object(reuse, 'META', meta), \
             patch.object(reuse, 'envelope', envelope), patch.object(reuse, 'seal_recipe', seal), \
             patch.object(reuse, 'proxy', browser_proxy):
            reuse.NativeFullReuse().run_full_actor(anonymous_nonce=True, diagnostic_only=False)


if __name__ == '__main__': unittest.main()
