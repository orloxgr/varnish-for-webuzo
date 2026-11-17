# Cookie policy validation

`tests/test_cookie_settings.py` verifies that old enabled provider-delivery
settings cannot reactivate native `_fbp` generation, are ignored by inventory
and rendering, and cannot be changed through the removed action.

`tests/test_cookie_provider.py` exercises `_fbp` with the same central
Shared / Variant / Private rules as other cookies, with real native HTTP:

- Shared: different values reuse the public object.
- Variant: values use separate objects and repeat visits HIT their own object.
- Private: requests pass to the origin.
- Consent cookies and old provider headers cannot mint an identifier.
- Personal ESI fragments remain private while their public parent can HIT.

`tests/test_cookie_delivery.py` covers multiple origin Set-Cookie fields,
renewals, deletions and attributes; private ESI children cannot overwrite parent
cookie fields. Fixture-only header operations check the repeated-field transport
without introducing an application-specific cookie generator.

The common native HTTP matrix runs through each panel's generated VCL, with
source manifests and case hashes in the parity report. See
[Testing](TESTING.md) for the current completed run and its scope.
