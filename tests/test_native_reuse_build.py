"""Experimental internal-engine builds require explicit matching receipts."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


@unittest.skipUnless(sys.platform.startswith('linux'),'Native builder uses Linux file locking')
class NativeReuseBuildReceipt(unittest.TestCase):
    def test_default_is_off_and_explicit_source_receipt_must_match_revision_and_layout(self):
        spec=importlib.util.spec_from_file_location('qualified_reuse_builder',Path(__file__).resolve().parents[1]/'shared/native_build.py')
        builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
        with tempfile.TemporaryDirectory(prefix='owned-reuse-receipt-') as temporary:
            root=Path(temporary);include=root/'include';private=root/'source'
            (include/'cache').mkdir(parents=True);private.mkdir()
            revision='1'*40
            (include/'vmod_abi.h').write_text('Varnish qualified '+revision)
            for name in ('cache.h','cache_int.h'):(include/'cache'/name).write_text('matching-layout-'+name)
            header=b'qualified-private-header'
            (private/'cache_objhead.h').write_bytes(header)
            record={'revision':revision,'objheadSha256':hashlib.sha256(header).hexdigest(),
                'installedHeaders':{name:hashlib.sha256((include/name).read_bytes()).hexdigest()
                    for name in ('cache/cache.h','cache/cache_int.h')}}
            receipt=private/'engine.json';receipt.write_text(json.dumps(record))
            with patch.dict(os.environ,{},clear=True):
                self.assertIsNone(builder.experimental_reuse_source(include))
            with patch.dict(os.environ,{'SCP_EXPERIMENTAL_REUSE_ENGINE_SOURCE':str(private)}):
                self.assertEqual(builder.experimental_reuse_source(include)[0],header)
                (include/'vmod_abi.h').write_text('Varnish different '+'2'*40)
                with self.assertRaisesRegex(RuntimeError,'revision differs'):builder.experimental_reuse_source(include)
                (include/'vmod_abi.h').write_text('Varnish qualified '+revision)
                (private/'cache_objhead.h').write_bytes(header+b'changed')
                with self.assertRaisesRegex(RuntimeError,'header differs'):builder.experimental_reuse_source(include)
                (private/'cache_objhead.h').write_bytes(header)
                (include/'cache/cache.h').write_text('changed layout')
                with self.assertRaisesRegex(RuntimeError,'layout differs'):builder.experimental_reuse_source(include)
