"""Only addon-owned retired service resources are removed after activation."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import lifecycle,native,state


@unittest.skipUnless(sys.platform.startswith('linux') and hasattr(os,'geteuid') and os.geteuid()==0,'Native Linux root ownership')
class Retirement(unittest.TestCase):
    def test_owned_unit_configuration_source_and_bytecode_are_removed_without_new_worker(self):
        with tempfile.TemporaryDirectory(dir='/var/lib') as tmp:
            root=Path(tmp);unit=root/'cms.service';source=root/'addon';private=root/'state'
            private.mkdir();(private/'cms-sessions.json').write_text('{}');(private/'cms-sessions.json').chmod(0o600)
            unit.write_text('Description=Varnish for Webuzo CMS session resolver\nExecStart=/usr/bin/python3 -I -B /usr/local/webuzo/plugins/varnish-for-webuzo/shared/cms_session_server.py --config /var/lib/varnish-for-webuzo/cms-sessions.json\n')
            names=('src/cms_resolver.py','shared/cms_sessions.py','shared/cms_session_server.py','shared/native/joomla_forms.h','src/__pycache__/cms_resolver.cpython-312.pyc')
            for name in names:
                p=source/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('obsolete')
            with patch.object(state,'ROOT',private),patch.object(native,'run') as run:
                lifecycle.retire_cms_helper(unit=unit,source=source)
                self.assertEqual(run.call_args_list[0].args,('systemctl','disable','--now','varnish-for-webuzo-cms'))
                self.assertEqual(run.call_args_list[1].args,('systemctl','daemon-reload'))
                lifecycle.retire_cms_helper(unit=unit,source=source)
                self.assertEqual(run.call_count,2)
            self.assertFalse(unit.exists());self.assertFalse((private/'cms-sessions.json').exists())
            self.assertTrue(all(not (source/name).exists() for name in names))

    def test_independent_unit_is_unchanged(self):
        with tempfile.TemporaryDirectory(dir='/var/lib') as tmp:
            root=Path(tmp);unit=root/'cms.service';unit.write_text('Description=Independent application\n')
            with patch.object(state,'ROOT',root),patch.object(native,'run') as run:
                with self.assertRaisesRegex(ValueError,'independent service'):
                    lifecycle.retire_cms_helper(unit=unit,source=root/'addon')
                run.assert_not_called()
            self.assertTrue(unit.exists())


if __name__=='__main__':unittest.main()
