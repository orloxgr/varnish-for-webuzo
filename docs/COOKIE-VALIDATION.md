# Cookie delivery validation

The 0.5.0 integration uses reviewed cookie catalogue `2026.11.16.4` and the
same compiler, delivery generator, VCL template and HTTP parity cases as Varnish
for Hestia. Recognition data is separate from executable policy.

## Native shared policy

Both native adapters passed the same 89 HTTP cases with identical source hashes
and result reports. The complete Webuzo Python suite passed all 189 tests.
A focused 26-test subset covers delivery, multiple
Set-Cookie fields, deletion and renewal attributes, exact consent, Meta's hold
state, application ownership, forged headers, configuration validation, ESI
session isolation and private downstream responses.

The packaged PHP files passed native lint, the panel passed its eight rejection
checks, and release metadata/package tests passed after the version change.

The final shared VCL SHA256 is
`e294ee05b9c2bd8898d1077148d62ff59111a3c77ab690c90de8fe95bcac3770`.
The reviewed catalogue SHA256 is
`02ff6264f45a6d20f85e24fa0ca6b1b7d8f4e130711969427575ed2c735581b5`.

## Actual WordPress integration

The dedicated Webuzo lab uses native Nginx, the addon's Varnish instance and
Webuzo's Apache/PHP backend. Application tests use actual WordPress,
WooCommerce 11.2.2, Facebook for WooCommerce 3.7.8, Real Cookie Banner 5.4.3
and WordPress Consent API 2.1.0. The application matrix ran on UltraCache
3.13.13-dev.1287; dev.1288 adds manual diagnostics/export and preserves these
cache, ESI, static and cookie-policy contracts.

| Case | Observed result |
| --- | --- |
| Two new visitors with an actual accepted RCB service decision | Identical public HTML from Varnish HIT; different cookies issued by the actual Meta SDK through its private endpoint |
| Existing Meta cookie | Public HIT, original identifier preserved and no endpoint reissue |
| Real RCB interface | No Meta cookie before consent; acceptance issues it; revocation deletes it; the next visit remains cookie-free |
| Endpoint origin and consent | Missing/foreign Origin rejected; a visitor without consent receives no Meta cookie |
| Two real WooCommerce carts | Shared parent HIT for A/B/A; each assembled mini-cart contains only its own product |
| Session-bound WordPress nonces | Each session validates its own nonce; the other visitor's nonce is rejected |
| Native Warm action | Three public image buckets prepared and refilled to Varnish HIT, without response cookies |
| Original/WebP/AVIF and browser Accept variants | Correct bucket HIT, including explicit AVIF refusal; equivalent browser Accept shares the warmed variant |
| Stored parent files | Signed ESI includes, no personal Meta identifiers and no private cart items |
| Basic instead of UltraCache VCL | Public Varnish HIT and independent application-provider cookie delivery |
| Apache Static without the application's Varnish integration | HTML served directly by Apache, with cookie delivery still handled by the provider endpoint; outer Varnish honors the origin's zero shared lifetime |

The public image-bucket checks verify the application's native bucket headers
and distinct stored representations. Functional language/currency Cookie/Vary
separation is covered separately by the native shared HTTP cases.

## Deployment scope

All runtime changes and requests above were confined to the dedicated lab.
The native Webuzo plugin-manager upload could not be repeated because the lab
panel license had expired. The actual generated VCL, owned service lifecycle,
native package/module handling, WordPress settings and HTTP paths were tested
through their native implementations. No license or Webuzo core files were
modified.
