"""Portable actual public-tuple codec; no provider resolution is fabricated."""
import base64
import copy
import ctypes
import json
import unittest
from test_delivery_envelope import CC, DeliveryEnvelope
from test_delivery_envelope import DocumentPointer
from test_public_selection import SelectionPointer, sample, NATIVE, WORDPRESS, URL
from test_public_source import source_sample


class Cookie(ctypes.Structure): pass
Cookie._fields_ = [('next', ctypes.POINTER(Cookie)), ('name', ctypes.c_void_p), ('value', ctypes.c_void_p)]
class Projection(ctypes.Structure):
    _fields_ = [('bucket', ctypes.c_char_p), ('locale', ctypes.c_char_p), ('language', ctypes.c_char_p),
        ('cookies', ctypes.POINTER(Cookie))]
Pointer = ctypes.POINTER(Projection)
RULES = b'variant\texact\tbrandCurrency\nvariant\texact\tcmp_language\nvariant\texact\toptional\nshared\texact\ttracking\nprivate\texact\towner\n'


def actual():
    return dict(version=1, bucket='actual-provider-bucket', locale='el_GR', language='el', cookieValues=[
        dict(name='brandCurrency', valueBase64=base64.b64encode(b'EUR').decode()),
        dict(name='cmp_language', valueBase64=base64.b64encode(b'el%2DGR+raw').decode()),
        dict(name='optional', valueBase64=None)])


@unittest.skipUnless(CC, 'C compiler required; skipped is not acceptance')
class PublicProjection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        DeliveryEnvelope.setUpClass.__func__(cls)
        cls.lib.delivery_public_projection_parse.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(Pointer)]
        cls.lib.delivery_public_projection_parse.restype = ctypes.c_int
        cls.lib.delivery_public_projection_header_parse.argtypes = cls.lib.delivery_public_projection_parse.argtypes
        cls.lib.delivery_public_projection_header_parse.restype = ctypes.c_int
        cls.lib.delivery_public_projection_header.argtypes = [Pointer]
        cls.lib.delivery_public_projection_header.restype = ctypes.c_void_p
        cls.lib.delivery_public_projection_free.argtypes = [Pointer]
        cls.lib.delivery_public_projection_free.restype = None
        cls.lib.delivery_public_projection_equal.argtypes = [Pointer, Pointer]
        cls.lib.delivery_public_projection_equal.restype = ctypes.c_int
        cls.lib.delivery_public_projection_cookie.argtypes = [Pointer, ctypes.c_char_p]
        cls.lib.delivery_public_projection_cookie.restype = ctypes.c_void_p
        cls.lib.delivery_public_projection_candidate.argtypes = [Pointer, ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
        cls.lib.delivery_public_projection_candidate.restype = ctypes.c_int
        cls.lib.delivery_projected_selection_parse.argtypes = [ctypes.c_void_p, ctypes.c_size_t]+[
            ctypes.c_char_p]*4+[ctypes.c_int, ctypes.POINTER(SelectionPointer), ctypes.POINTER(DocumentPointer), ctypes.POINTER(Pointer)]
        cls.lib.delivery_projected_selection_parse.restype = ctypes.c_int
        cls.lib.delivery_selection_free.argtypes = [SelectionPointer]
        cls.lib.delivery_selection_free.restype = None
    tearDownClass = classmethod(DeliveryEnvelope.tearDownClass.__func__)

    def parse(self, value, *, header=False):
        data = json.dumps(value, ensure_ascii=True).encode() if isinstance(value, dict) else value
        pointer = Pointer()
        function = self.lib.delivery_public_projection_header_parse if header else self.lib.delivery_public_projection_parse
        accepted = function(data, len(data), ctypes.byref(pointer))
        if not accepted: self.assertFalse(pointer)
        self.addCleanup(self.lib.delivery_public_projection_free, pointer)
        return pointer if accepted else None

    def string_result(self, pointer):
        if not pointer: return None
        try: return ctypes.string_at(pointer)
        finally: self.lib.delivery_manifest_free(pointer)

    def envelope(self, value, role):
        data = json.dumps(value).encode()
        selected = SelectionPointer(); document = DocumentPointer(); resolved = Pointer()
        accepted = self.lib.delivery_projected_selection_parse(data, len(data), b'42', URL.encode(),
            NATIVE.encode(), WORDPRESS.encode(), role, ctypes.byref(selected), ctypes.byref(document), ctypes.byref(resolved))
        try:
            if not accepted:
                self.assertFalse(selected); self.assertFalse(document); self.assertFalse(resolved)
                return None
            return (bool(selected), bool(document), bool(resolved))
        finally:
            self.lib.delivery_selection_free(selected)
            self.lib.delivery_private_document_free(document)
            self.lib.delivery_public_projection_free(resolved)

    def test_actual_values_roundtrip_without_url_decoding_or_invented_defaults(self):
        p = self.parse(actual()); self.assertTrue(p)
        self.assertEqual(p.contents.locale, b'el_GR')
        self.assertEqual(self.string_result(self.lib.delivery_public_projection_cookie(p, RULES)),
            b'brandCurrency=EUR; cmp_language=el%2DGR+raw')
        header = self.string_result(self.lib.delivery_public_projection_header(p))
        self.assertEqual(json.loads(base64.b64decode(header, validate=True)), actual())
        restored = self.parse(header, header=True)
        self.assertEqual(self.lib.delivery_public_projection_equal(p, restored), 1)

    def test_key_order_whitespace_unicode_and_json_escaping_do_not_change_tuple(self):
        value = actual(); value.update(bucket='πραγματική "τιμή"', locale='', language='')
        raw = json.dumps(value, ensure_ascii=True, indent=2).replace('"bucket"', '"b\\u0075cket"').encode()
        first = self.parse(value); second = self.parse(raw)
        self.assertEqual(self.lib.delivery_public_projection_equal(first, second), 1)
        header = self.string_result(self.lib.delivery_public_projection_header(first))
        self.assertEqual(json.loads(base64.b64decode(header)), value)

    def test_null_empty_and_omitted_are_distinct_actual_states(self):
        missing = actual(); missing['cookieValues'].pop()
        empty = actual(); empty['cookieValues'][-1]['valueBase64'] = ''
        a, b, c = self.parse(actual()), self.parse(missing), self.parse(empty)
        self.assertEqual(self.lib.delivery_public_projection_equal(a, b), 0)
        self.assertEqual(self.lib.delivery_public_projection_equal(a, c), 0)
        self.assertTrue(self.string_result(self.lib.delivery_public_projection_cookie(c, RULES)).endswith(b'optional='))

    def test_no_guess_when_projection_is_empty(self):
        value = actual(); value.update(bucket='', locale='', language='', cookieValues=[])
        p = self.parse(value)
        self.assertEqual(self.string_result(self.lib.delivery_public_projection_cookie(p, RULES)), b'')

    def test_unknown_duplicate_missing_fields_types_and_unsorted_names_rejected(self):
        for key in actual():
            value = actual(); value.pop(key)
            with self.subTest(missing=key): self.assertIsNone(self.parse(value))
        for key, invalid in [('version', True), ('version', '1'), ('version', 2), ('bucket', None),
                ('locale', 0), ('language', []), ('cookieValues', {})]:
            value = actual(); value[key] = invalid
            with self.subTest(key=key): self.assertIsNone(self.parse(value))
        value = actual(); value['extra'] = True; self.assertIsNone(self.parse(value))
        value = actual(); value['cookieValues'].reverse(); self.assertIsNone(self.parse(value))
        value = actual(); value['cookieValues'].insert(1, value['cookieValues'][0]); self.assertIsNone(self.parse(value))
        raw = json.dumps(actual()).replace('"bucket":', '"b\\u0075cket":"duplicate","bucket":')
        self.assertIsNone(self.parse(raw.encode()))

    def test_base64_and_literal_cookie_wire_remain_strict(self):
        for encoded in ('RVV=', 'RVVS\n', 'RVVS=', '!!', base64.b64encode(b'x; owner=A').decode(),
                base64.b64encode(b'x\x00hidden').decode(), base64.b64encode(b'x\r\n').decode()):
            value = actual(); value['cookieValues'][0]['valueBase64'] = encoded
            with self.subTest(encoded=encoded): self.assertIsNone(self.parse(value))
        value = actual(); value['cookieValues'][0]['name'] = 'bad=name'
        self.assertIsNone(self.parse(value))
        self.assertIsNone(self.parse(b'notbase64', header=True))

    def test_literal_database_names_keep_their_real_public_variant_choices(self):
        names = sorted(['Auth0:state', 'Crisp/session', 'CMP language', 'όνομα'])
        value = actual(); value['cookieValues'] = [dict(name=name, valueBase64='eA==') for name in names]
        rules = ''.join('variant\texact\t'+name+'\n' for name in names).encode()
        p = self.parse(value)
        self.assertEqual(self.string_result(self.lib.delivery_public_projection_cookie(p, rules)),
            '; '.join(name+'=x' for name in names).encode())
        for invalid in (' leading', 'trailing ', '\u00a0leading', 'trailing\u2003', 'bad;name', 'bad=name', 'bad"name', 'bad{name}', 'bad\x7fname'):
            changed = actual(); changed['cookieValues'] = [dict(name=invalid, valueBase64='eA==')]
            with self.subTest(name=invalid): self.assertIsNone(self.parse(changed))

    def test_only_active_variant_rows_can_become_source_or_effective_visitor_cookie(self):
        for name in ('tracking', 'owner', 'unrecognized'):
            value = actual(); value['cookieValues'] = [dict(name=name, valueBase64='eA==')]
            p = self.parse(value)
            with self.subTest(name=name): self.assertIsNone(self.string_result(self.lib.delivery_public_projection_cookie(p, RULES)))
        p = self.parse(actual()); out = ctypes.c_void_p()
        self.assertEqual(self.lib.delivery_public_projection_candidate(p,
            b'owner=actual; tracking=original; optional=deleted; brandCurrency=USD; cmp_language=old', RULES, ctypes.byref(out)), 1)
        self.assertEqual(self.string_result(out.value), b'owner=actual; tracking=original; brandCurrency=EUR; cmp_language=el%2DGR+raw')
        # An actual input Variant cannot disappear merely because the producer
        # omitted its row; a deletion/known absence must be explicit null.
        value = actual(); value['cookieValues'].pop(); p = self.parse(value); out = ctypes.c_void_p()
        self.assertEqual(self.lib.delivery_public_projection_candidate(p, b'optional=keep', RULES, ctypes.byref(out)), 0)
        self.assertFalse(out.value)

    def test_resolved_only_is_an_exclusive_bound_outcome_for_resolver_or_changed_parent(self):
        value = dict(schemaVersion=1, requestId='42', originalUrl=URL, resolvedPublic=actual())
        self.assertEqual(self.envelope(value, 2), (False, False, True))
        self.assertEqual(self.envelope(value, 1), (False, False, True))
        self.assertIsNone(self.envelope(value, 0))
        for key, invalid in [('requestId', 'other'), ('originalUrl', '/wrong/'), ('schemaVersion', 2)]:
            changed = copy.deepcopy(value); changed[key] = invalid
            with self.subTest(key=key): self.assertIsNone(self.envelope(changed, 2))
        for key, extra in [('selectedPublic', sample()['selectedPublic']), ('cookieUpdates', []),
                ('bodyBase64', ''), ('privateDocument', {})]:
            changed = copy.deepcopy(value); changed[key] = extra
            with self.subTest(extra=key): self.assertIsNone(self.envelope(changed, 2))

    def test_matching_projected_snapshot_requires_typed_tuple_in_explicit_role(self):
        for role, factory in [(0, sample), (1, source_sample)]:
            value = factory()
            with self.subTest(role=role):
                self.assertIsNone(self.envelope(value, role))
                value['selectedPublic']['resolvedPublic'] = actual()
                self.assertEqual(self.envelope(value, role), (True, False, False))
                self.assertIsNone(self.envelope(value, 2))
                value['resolvedPublic'] = actual()
                self.assertIsNone(self.envelope(value, role))


if __name__ == '__main__': unittest.main()
