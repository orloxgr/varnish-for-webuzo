"""Existing signed batch membership selects bodies, never client-supplied URIs."""
import ctypes
import hashlib
import json
import unittest

import test_fragment_batch_wire as original
from test_delivery_envelope import CC


@unittest.skipUnless(CC, 'C compiler required; skipped is not qualification')
class FragmentSubsetWire(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        original.FragmentBatchWire.setUpClass.__func__(cls)
        cls.lib.delivery_fragment_batch_request.argtypes = [ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p)]
        cls.lib.delivery_fragment_batch_request.restype = ctypes.c_int
        cls.lib.delivery_fragment_batch_operation.argtypes = [ctypes.c_char_p]
        cls.lib.delivery_fragment_batch_operation.restype = ctypes.c_int
        cls.lib.delivery_fragment_batch_select.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
        cls.lib.delivery_fragment_batch_select.restype = ctypes.c_int

    @classmethod
    def tearDownClass(cls):
        original.FragmentBatchWire.tearDownClass.__func__(cls)

    batch = original.FragmentBatchWire.batch

    def request(self, uri):
        token, subset = ctypes.c_void_p(), ctypes.c_void_p()
        accepted = self.lib.delivery_fragment_batch_request(uri.encode(), ctypes.byref(token), ctypes.byref(subset))
        try:
            if not accepted:
                self.assertFalse(token); self.assertFalse(subset)
                return None
            return ctypes.string_at(token).decode(), ctypes.string_at(subset).decode() if subset else None
        finally:
            self.lib.delivery_manifest_free(token); self.lib.delivery_manifest_free(subset)

    def test_query_decodes_values_once_and_rejects_ambiguous_operations(self):
        self.assertEqual(self.request('/index.php?ultracache_fragment_delivery=a.b&ultracache_fragment_subset=0%2C2'), ('a.b', '0,2'))
        self.assertEqual(self.request('/index.php?ultracache_fragment_subset=1&ultracache_fragment_delivery=a%2Eb'), ('a.b', '1'))
        self.assertEqual(self.request('/index.php?ultracache_fragment_delivery=a.b&ultracache_fragment_subset=0%252C2'), ('a.b', '0%2C2'))
        for query in ('ultracache_fragment_subset=1',
            'ultracache_fragment_delivery=a.b&ultracache_fragment_subset=',
            'ultracache_fragment_delivery=a.b&ultracache_fragment_delivery=a.b',
            'ultracache_fragment_delivery=a.b&ultracache_fragment_subset=0&ultracache_fragment_subset=1',
            'ultracache_fragment_delivery=a.b&other=1',
            'ultracache_fragment_delivery=a.b&',
            'other=1&ultracache_fragment_delivery=a.b'):
            uri = '/index.php?'+query
            self.assertTrue(self.lib.delivery_fragment_batch_operation(uri.encode()), query)
            self.assertIsNone(self.request(uri), query)
        self.assertFalse(self.lib.delivery_fragment_batch_operation(b'/index.php?ordinary=1'))

    def test_only_original_selected_row_and_occurrences_match_subset_digest(self):
        value = original.payload(); wire = original.token(value)
        batch = self.batch(wire); result = ctypes.c_void_p(); output = ctypes.c_void_p(); length = ctypes.c_size_t()
        try:
            self.assertTrue(self.lib.delivery_fragment_batch_select(batch, wire, b'1'))
            response = dict(schemaVersion=2, requestId='123', originalUrl=original.REQUEST,
                requestDigest=hashlib.sha256(b'ultracache-fragment-delivery-subset-v1\n'+wire+b'\n1').hexdigest(),
                renderedFragments=[dict(value['fragments'][1], html='selected-body')], failedFragments=[])
            raw = json.dumps(response).encode()
            self.assertTrue(self.lib.delivery_fragment_envelope_parse_v1(raw, len(raw), b'123', original.REQUEST.encode(), batch, ctypes.byref(result)))
            self.assertTrue(self.lib.delivery_fragment_results_json(batch, result, ctypes.byref(output), ctypes.byref(length)))
            self.assertEqual(json.loads(ctypes.string_at(output, length.value))['results'],
                [dict(url=original.ADAPTIVE, status=200, html='selected-body', cacheScope='none')])
            self.lib.delivery_fragment_results_free(result); result = ctypes.c_void_p()
            response['renderedFragments'].append(dict(value['fragments'][0], html='unselected'))
            raw = json.dumps(response).encode()
            self.assertFalse(self.lib.delivery_fragment_envelope_parse_v1(raw, len(raw), b'123', original.REQUEST.encode(), batch, ctypes.byref(result)))
        finally:
            self.lib.delivery_manifest_free(output); self.lib.delivery_fragment_results_free(result)
            self.lib.delivery_fragment_batch_free(batch)

    def test_noncanonical_or_outside_indices_reject_without_legacy_fallback(self):
        wire = original.token(original.payload())
        for subset in ('', '2', '1,0', '0,0', '00', '01', '-1', '+1', ' 1', '1 ',
                       '0,', ',1', '0,,1', '0%2C1', '9999999999999999999999999999999999999'):
            batch = self.batch(wire)
            try:
                self.assertFalse(self.lib.delivery_fragment_batch_select(batch, wire, subset.encode()), subset)
            finally:
                self.lib.delivery_fragment_batch_free(batch)

    def test_missing_selector_preserves_legacy_digest_and_full_membership(self):
        wire = original.token(original.payload()); batch = self.batch(wire); result = ctypes.c_void_p()
        try:
            self.assertTrue(self.lib.delivery_fragment_batch_select(batch, wire, None))
            raw = json.dumps(original.envelope(wire)).encode()
            self.assertTrue(self.lib.delivery_fragment_envelope_parse_v1(raw, len(raw), b'123', original.REQUEST.encode(), batch, ctypes.byref(result)))
        finally:
            self.lib.delivery_fragment_results_free(result); self.lib.delivery_fragment_batch_free(batch)


if __name__ == '__main__': unittest.main()
