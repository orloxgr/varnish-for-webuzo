"""Portable strict optional admission grammar; parsing is never authority."""
import copy
import ctypes
import json
import unittest
import test_fragment_batch_wire as batch
from test_reuse_cookie_inputs import declaration


@unittest.skipUnless(batch.CC, 'An actual C compiler is required')
class FragmentReuseWire(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        batch.FragmentBatchWire.setUpClass.__func__(cls)
        cls.lib.delivery_fragment_admission_parse.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_void_p)]
        cls.lib.delivery_fragment_admission_free.argtypes = [ctypes.c_void_p]

    @classmethod
    def tearDownClass(cls):
        batch.FragmentBatchWire.tearDownClass.__func__(cls)

    def value(self):
        row = dict(descriptor='1'*64, url=batch.PRIVATE, cache=dict(key='2'*64, ttl=60, tags=''),
            bodyValidUntil=2000000000, inputs=declaration(), inputBinding='3'*64,
            identity=dict(identityState='anonymous', identityInputs=declaration(), identityBinding='4'*64,
                owner=None, tags=[], validUntil=2000000000), authority=[])
        return dict(version=1, cookieValidUntil=2000000000, fragments=[row])

    def parse(self, value):
        raw = json.dumps(value).encode() if not isinstance(value, bytes) else value
        result = ctypes.c_void_p()
        ok = self.lib.delivery_fragment_admission_parse(raw, len(raw), ctypes.byref(result))
        self.assertEqual(bool(ok), bool(result))
        self.lib.delivery_fragment_admission_free(result)
        return ok

    def test_complete_render_and_identity_inputs_are_both_required(self):
        self.assertEqual(self.parse(self.value()), 1)
        for key in ('inputs', 'inputBinding', 'identity', 'authority', 'bodyValidUntil'):
            with self.subTest(missing=key):
                value = self.value(); del value['fragments'][0][key]
                self.assertEqual(self.parse(value), 0)
        for key, replacement in (('version', 2), ('cookieValidUntil', 0), ('fragments', [])):
            value = self.value(); value[key] = replacement
            self.assertEqual(self.parse(value), 0)

    def test_duplicate_rows_unknown_fields_and_uncovered_identity_tags_reject(self):
        value = self.value(); value['fragments'].append(copy.deepcopy(value['fragments'][0]))
        self.assertEqual(self.parse(value), 0)
        value = self.value(); value['browserCookie'] = 'never-authority'
        self.assertEqual(self.parse(value), 0)
        value = self.value(); value['fragments'][0]['identity']['tags'] = ['5'*64]
        self.assertEqual(self.parse(value), 0)
        raw = json.dumps(self.value()).encode().replace(b'"version": 1', b'"version": 1, "version": 1')
        self.assertEqual(self.parse(raw), 0)
