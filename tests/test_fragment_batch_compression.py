"""Scoped native memory admission, separate from the application's outer HMAC."""
import base64
import copy
import ctypes
import hashlib
import hmac
import json
import struct
import unittest
import zlib
from pathlib import Path

import test_fragment_batch_wire as batch_wire
from test_fragment_batch_wire import payload, envelope, token
from test_delivery_envelope import CC

SECRET = b'fixture-only'
KEY = hmac.digest(SECRET, b'ultracache-delivery-reuse-key-v1', 'sha256')
SCOPE = '/shop/'

def compressed_token(value, *, secret=SECRET, scope=SCOPE, raw_length=None, packed=None, flag=1):
    raw = value if isinstance(value, bytes) else json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode()
    if packed is None:
        stream = zlib.compressobj(6, zlib.DEFLATED, -15)
        packed = stream.compress(raw) + stream.flush()
    length = struct.pack('!Q', len(raw) if raw_length is None else raw_length)
    lp = lambda data: struct.pack('!I', len(data)) + data
    key = hmac.digest(secret, b'ultracache-delivery-reuse-key-v1', 'sha256')
    message = lp(b'ultracache-fragment-batch-deflate-v1') + lp(scope.encode()) + length + packed
    mac = hmac.digest(key, message, 'sha256') if flag else bytes(32)
    frame = bytes([flag]) + length + mac + packed
    return b'z1_' + base64.urlsafe_b64encode(frame).rstrip(b'=') + b'.' + b'c'*64

@unittest.skipUnless(CC, 'C compiler and zlib development files required')
class CompressedFragmentBatch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        batch_wire.FragmentBatchWire.setUpClass.__func__(cls)
        cls.lib.delivery_fragment_batch_parse_scoped.argtypes = [ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
        cls.lib.delivery_fragment_batch_parse_scoped.restype = ctypes.c_int
    @classmethod
    def tearDownClass(cls): batch_wire.FragmentBatchWire.tearDownClass.__func__(cls)

    def batch(self, wire, key=KEY, scope=SCOPE):
        out = ctypes.c_void_p()
        key_buffer = ctypes.create_string_buffer(key) if key is not None else None
        accepted = self.lib.delivery_fragment_batch_parse_scoped(wire, len(wire), key_buffer,
            scope.encode() if scope is not None else None, ctypes.byref(out))
        if not accepted: self.assertFalse(out)
        return out

    def accepted(self, wire, **kwargs):
        batch = self.batch(wire, **kwargs)
        try: return bool(batch)
        finally: self.lib.delivery_fragment_batch_free(batch)

    def test_exact_cross_language_vector_and_original_opaque_digest(self):
        vector = json.loads((Path(__file__).parent/'fixtures/fragment-batch-compression-v1.json').read_text())
        self.assertEqual(KEY.hex(), vector['reuseKeyHex'])
        wire = compressed_token(vector['rawJsonUtf8'].encode(), packed=bytes.fromhex(vector['deflateHex']))
        self.assertEqual(wire.split(b'.')[0].decode(), vector['firstPart'])
        self.assertTrue(self.accepted(wire))
        # The original token, not expanded JSON, remains the producer digest.
        batch = self.batch(wire); result = ctypes.c_void_p()
        value = envelope(wire); value['failedFragments'] = []
        raw = json.dumps(value).encode()
        try:
            self.assertTrue(self.lib.delivery_fragment_envelope_parse_v1(raw, len(raw), b'123',
                b'/shop/index.php?ultracache_fragment_delivery=public-token', batch, ctypes.byref(result)))
            self.lib.delivery_fragment_results_free(result); result = ctypes.c_void_p()
            value['requestDigest'] = hashlib.sha256(vector['rawJsonUtf8'].encode()).hexdigest()
            raw = json.dumps(value).encode()
            self.assertFalse(self.lib.delivery_fragment_envelope_parse_v1(raw, len(raw), b'123',
                b'/shop/index.php?ultracache_fragment_delivery=public-token', batch, ctypes.byref(result)))
        finally:
            self.lib.delivery_fragment_results_free(result); self.lib.delivery_fragment_batch_free(batch)

    def test_native_key_scope_and_flags_are_checked_before_output_allocation(self):
        wire = compressed_token(payload())
        for kwargs in (dict(key=b'x'*32), dict(key=None), dict(scope='/other/'), dict(scope=None)):
            with self.subTest(kwargs=kwargs): self.assertFalse(self.accepted(wire, **kwargs))
        for flag in (0, 2, 255): self.assertFalse(self.accepted(compressed_token(payload(), flag=flag)))
        # A forged huge size has no valid MAC; it cannot request that allocation.
        first = wire.split(b'.')[0][3:]; frame = bytearray(base64.urlsafe_b64decode(first+b'='*(-len(first)%4)))
        frame[1:9] = struct.pack('!Q', 2**63)
        forged = b'z1_' + base64.urlsafe_b64encode(frame).rstrip(b'=') + b'.' + b'c'*64
        self.assertFalse(self.accepted(forged))
        self.assertFalse(self.accepted(compressed_token(payload(), raw_length=2**64-1)))

    def test_exact_raw_length_stream_end_and_no_trailing_or_wrapped_streams(self):
        raw = json.dumps(payload(), separators=(',', ':')).encode()
        stream = zlib.compressobj(6, zlib.DEFLATED, -15); packed = stream.compress(raw)+stream.flush()
        for data in (packed[:-1], packed+b'x', packed+packed, b'not-deflate', zlib.compress(raw), b''):
            with self.subTest(data=data[:20]): self.assertFalse(self.accepted(compressed_token(raw, packed=data)))
        for length in (0, len(raw)-1, len(raw)+1):
            self.assertFalse(self.accepted(compressed_token(raw, raw_length=length)))

    def test_existing_json_and_descriptor_validation_still_runs(self):
        for value in (dict(payload(), sourceUrl='https://outside.test/'), dict(payload(), fragments=[]),
            dict(payload(), schemaVersion=2), dict(payload(), extra='not-allowed')):
            self.assertFalse(self.accepted(compressed_token(value)))
        raw = json.dumps(payload(), separators=(',', ':')).encode()
        self.assertFalse(self.accepted(compressed_token(raw.replace(b'"schemaVersion":1', b'"schemaVersion":1,"schemaVersion":1'))))
        self.assertTrue(self.accepted(token(payload()), key=None, scope=None), 'Legacy v1 does not require a new key')

    def test_trusted_payload_above_header_size_has_no_new_fixed_decoded_cap(self):
        value = copy.deepcopy(payload())
        value['fragments'] = [dict(url='/?ultracache_esi='+str(i)+'a'*50000, occurrences=1) for i in range(3)]
        wire = compressed_token(value)
        self.assertLess(len(wire), 2000)
        self.assertTrue(self.accepted(wire))

if __name__ == '__main__': unittest.main()
