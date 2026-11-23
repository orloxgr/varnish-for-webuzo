"""Release metadata must agree before any ZIP is created or replaced."""
import importlib.util
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('package_builder', ROOT / 'tools/build.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)
PLUGIN = 'varnish-for-webuzo'


class PackageVersions(unittest.TestCase):
    def test_windows_checkout_native_header_receipts_survive_the_actual_zip(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);self.fixture(root)
            records=list((ROOT/'shared/native/engine').glob('*/engine.json'))
            self.assertTrue(records)
            for source in records:
                target=root/source.parent.relative_to(ROOT);target.mkdir(parents=True)
                for original in source.parent.iterdir():
                    if original.is_file():
                        raw=original.read_bytes().replace(b'\r\n',b'\n')
                        (target/original.name).write_bytes(raw.replace(b'\n',b'\r\n'))
            with patch.object(builder,'ROOT',root):archive=builder.build()
            with zipfile.ZipFile(archive) as bundle:
                for source in records:
                    prefix=PLUGIN+'/'+source.parent.relative_to(ROOT).as_posix()+'/'
                    record=json.loads(bundle.read(prefix+'engine.json'))
                    expected={'cache_objhead.h':record['objheadSha256'],
                        'cache_pool.h':record['poolHeader']['sha256'],
                        'VSC_main.h':record['counterHeader']['sha256'],
                        'cache_transport.h':record['transportHeader']['sha256']}
                    for name,digest in expected.items():
                        with self.subTest(header=name):
                            raw=bundle.read(prefix+name)
                            self.assertNotIn(b'\r\n',raw)
                            self.assertEqual(hashlib.sha256(raw).hexdigest(),digest)

    def test_packaged_text_has_git_line_endings_and_binary_assets_are_unchanged(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);self.fixture(root)
            entry=root/(PLUGIN+'.php')
            entry.write_bytes(entry.read_bytes().replace(b'\r\n',b'\n').replace(b'\n',b'\r\n'))
            assets=root/'panel';assets.mkdir()
            binary=b'\x89PNG\r\n\x00\r\n';(assets/'icon.png').write_bytes(binary)
            native=root/'shared/native';native.mkdir(parents=True)
            for name in ('cookie_handoff.c','cookie_handoff.vcc'):(native/name).write_bytes(b'Native source\r\n')
            with patch.object(builder,'ROOT',root):archive=builder.build()
            with zipfile.ZipFile(archive) as bundle:
                self.assertNotIn(b'\r\n',bundle.read(PLUGIN+'/'+PLUGIN+'.php'))
                self.assertEqual(bundle.read(PLUGIN+'/panel/icon.png'),binary)
                for name in ('cookie_handoff.c','cookie_handoff.vcc'):
                    self.assertEqual(bundle.read(PLUGIN+'/shared/native/'+name),b'Native source\n')

    def test_repository_metadata_agrees(self):
        self.assertEqual(builder.package_version(), json.loads((ROOT / 'info.json').read_text())['version'])

    def fixture(self, root, header='1.2.3'):
        (root / 'info.json').write_text(json.dumps(dict(version='1.2.3')), encoding='utf-8')
        (root / (PLUGIN + '.php')).write_text('<?php\n/*\nVersion: ' + header + '\n*/\n', encoding='utf-8')
        for name in ('LICENSE', 'README.md', 'UPSTREAM'):
            (root / name).write_text('Fixture source', encoding='utf-8')
        wordpress = root / 'wordpress'
        wordpress.mkdir()
        (wordpress / 'varnish-cache-for-webuzo.php').write_text('<?php\n/*\nVersion: 0.1.0\n*/\n')
        (wordpress / 'readme.txt').write_text('Fixture connector')

    def test_zip_filename_and_both_metadata_sources_agree(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.fixture(root)
            with patch.object(builder, 'ROOT', root):
                archive = builder.build()
            self.assertEqual(archive.name, PLUGIN + '-1.2.3.zip')
            with zipfile.ZipFile(archive) as bundle:
                info = json.loads(bundle.read(PLUGIN + '/info.json'))
                header = bundle.read(PLUGIN + '/' + PLUGIN + '.php').decode()
                self.assertEqual(info['version'], '1.2.3')
                self.assertIn('Version: ' + info['version'], header.splitlines())

    def test_mismatch_cannot_overwrite_an_existing_package(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.fixture(root, '1.2.2')
            (root / 'dist').mkdir()
            archive = root / 'dist' / (PLUGIN + '-1.2.3.zip')
            archive.write_bytes(b'existing package')
            with patch.object(builder, 'ROOT', root), self.assertRaisesRegex(ValueError, 'must match info.json'):
                builder.build()
            self.assertEqual(archive.read_bytes(), b'existing package')

    def test_missing_header_stops_before_creating_dist(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.fixture(root)
            (root / (PLUGIN + '.php')).write_text('<?php\n/* No version */\n')
            with patch.object(builder, 'ROOT', root), self.assertRaisesRegex(ValueError, 'must match info.json'):
                builder.build()
            self.assertFalse((root / 'dist').exists())


if __name__ == '__main__':
    unittest.main()
