"""Normal build auto-detects verified upstream ABI; no manual feature flag."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

@unittest.skipUnless(sys.platform.startswith('linux'),'Native builder uses Linux file locking')
class NativeReuseBuildReceipt(unittest.TestCase):
    def fixture(self,root):
        spec=importlib.util.spec_from_file_location('normal_reuse_builder',Path(__file__).resolve().parents[1]/'shared/native_build.py')
        b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
        include=root/'include';(include/'cache').mkdir(parents=True)
        revision='1'*40;vendor=root/'engine';private=vendor/revision;private.mkdir(parents=True)
        (include/'vmod_abi.h').write_text('#define VMOD_ABI_Version "Varnish verified '+revision+'"\n')
        for name in ('cache.h','cache_int.h'):(include/'cache'/name).write_text('actual-exported-layout-'+name)
        (include/'waiter').mkdir();(include/'waiter/waiter.h').write_text('actual-waited-layout')
        header=b'actual-qualified-upstream-interface';(private/'cache_objhead.h').write_bytes(header)
        pool=b'qualified-pool';(private/'cache_pool.h').write_bytes(pool)
        counters=b'qualified-generated-counters';(private/'VSC_main.h').write_bytes(counters)
        transport=b'qualified-transport';(private/'cache_transport.h').write_bytes(transport)
        record=dict(revision=revision,objheadSha256=hashlib.sha256(header).hexdigest(),
            poolHeader=dict(sha256=hashlib.sha256(pool).hexdigest()),
            counterHeader=dict(sha256=hashlib.sha256(counters).hexdigest()),
            transportHeader=dict(sha256=hashlib.sha256(transport).hexdigest()),
            installedHeaders={name:hashlib.sha256((include/name).read_bytes()).hexdigest()
                for name in ('cache/cache.h','cache/cache_int.h','waiter/waiter.h')})
        (private/'engine.json').write_text(json.dumps(record))
        b.ENGINE_INTERFACES=vendor
        return b,include,private,header
    def test_normal_build_automatically_enables_matching_interface_without_environment_flags(self):
        with tempfile.TemporaryDirectory() as folder:
            b,include,private,header=self.fixture(Path(folder))
            with patch.dict('os.environ',{},clear=True):self.assertEqual(b.native_reuse_source(include)[0],header)
    def test_unknown_or_patched_engine_keeps_old_producer_fallback_without_fake_abi_match(self):
        with tempfile.TemporaryDirectory() as folder:
            b,include,private,header=self.fixture(Path(folder))
            original=(include/'vmod_abi.h').read_text()
            (include/'vmod_abi.h').write_text('/* old '+('1'*40)+' */\n#define VMOD_ABI_Version "Varnish different '+('2'*40)+'"\n')
            self.assertIsNone(b.native_reuse_source(include))
            (include/'vmod_abi.h').write_text(original)
            (include/'cache/cache.h').write_text('different actual exported layout')
            self.assertIsNone(b.native_reuse_source(include))
    def test_changed_waiter_layout_and_tampered_private_pool_never_use_guessed_offsets(self):
        with tempfile.TemporaryDirectory() as folder:
            b,include,private,header=self.fixture(Path(folder))
            path=include/'waiter/waiter.h';original=path.read_bytes();path.write_bytes(original+b'changed')
            self.assertIsNone(b.native_reuse_source(include))
            path.write_bytes(original);path=private/'cache_pool.h';path.write_bytes(path.read_bytes()+b'changed')
            with self.assertRaisesRegex(RuntimeError,'pool differs from verified source'):b.native_reuse_source(include)
    def test_tampered_bundled_source_is_an_install_error_not_a_guessed_interface(self):
        with tempfile.TemporaryDirectory() as folder:
            b,include,private,header=self.fixture(Path(folder))
            (private/'cache_objhead.h').write_bytes(header+b'changed')
            with self.assertRaisesRegex(RuntimeError,'differs from verified source'):b.native_reuse_source(include)
    def test_real_packaged_interface_has_independent_upstream_git_blob_provenance(self):
        root=Path(__file__).resolve().parents[1]/'shared/native/engine'
        records=list(root.glob('*/engine.json'));self.assertTrue(records)
        for path in records:
            r=json.loads(path.read_text());raw=(path.parent/'cache_objhead.h').read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(),r['objheadSha256'])
            self.assertEqual(hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),r['upstreamGitBlob'])
            self.assertIn('/'+r['revision']+'/',r['sourceUrl'])
            self.assertIn(b'SPDX-License-Identifier: BSD-2-Clause',raw)
            pool=(path.parent/'cache_pool.h').read_bytes()
            self.assertEqual(hashlib.sha256(pool).hexdigest(),r['poolHeader']['sha256'])
            self.assertEqual(hashlib.sha1(b'blob '+str(len(pool)).encode()+b'\0'+pool).hexdigest(),r['poolHeader']['upstreamGitBlob'])
            self.assertIn('/'+r['revision']+'/',r['poolHeader']['sourceUrl'])
            self.assertEqual(hashlib.sha256((path.parent/'VSC_main.h').read_bytes()).hexdigest(),r['counterHeader']['sha256'])
            self.assertEqual(hashlib.sha256((path.parent/'cache_transport.h').read_bytes()).hexdigest(),r['transportHeader']['sha256'])
            transport=(path.parent/'cache_transport.h').read_bytes()
            self.assertEqual(hashlib.sha1(b'blob '+str(len(transport)).encode()+b'\0'+transport).hexdigest(),r['transportHeader']['upstreamGitBlob'])

if __name__=='__main__':unittest.main()
