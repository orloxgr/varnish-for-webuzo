"""Native-only upgrades must change generated VCL so reconciliation activates them."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'shared'))
import cookie_catalogue


class NativePolicyIdentity(unittest.TestCase):
    def test_event_authority_and_sdk_only_changes_force_generated_policy_activation(self):
        catalogue = cookie_catalogue.load_catalogue()
        with tempfile.TemporaryDirectory(prefix='native-policy-identity-') as folder:
            root = Path(folder)
            names = ('native_build.py', 'native/cookie_handoff.c', 'native/mutation_backend.c',
                'native/reuse_authority.c', 'native/delivery_reuse_engine.c', 'native/engine/exact/cache_objhead.h',
                'native/engine/exact/cache_pool.h', 'native/engine/exact/VSC_main.h', 'native/engine/exact/engine.json')
            for name in names:
                path = root/name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(name.encode())
            with patch.object(cookie_catalogue, '__file__', str(root/'cookie_catalogue.py')):
                before = cookie_catalogue.render_policy('vcl 4.1;', catalogue)
                for name in names:
                    path = root/name; original = path.read_bytes(); path.write_bytes(original+b' changed')
                    after = cookie_catalogue.render_policy('vcl 4.1;', catalogue)
                    with self.subTest(source=name):
                        self.assertNotEqual(before.splitlines()[0], after.splitlines()[0])
                        self.assertEqual(before.splitlines()[1:], after.splitlines()[1:])
                    path.write_bytes(original)
                # New included native sources must not require updating a second
                # generation list, nor can removed/replaced files retain identity.
                extra = root/'native/new_compiled_helper.c'; extra.write_bytes(b'new native source')
                self.assertNotEqual(before, cookie_catalogue.render_policy('vcl 4.1;', catalogue))
                extra.unlink()
                self.assertEqual(before, cookie_catalogue.render_policy('vcl 4.1;', catalogue))


if __name__ == '__main__': unittest.main()
