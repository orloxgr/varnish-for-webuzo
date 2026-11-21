# Prepared fallback diagnostics — Hestia 0.23.1 / Webuzo 0.12.2

An HTTP200/HIT parent can contain a renderer's fallback. The existing WordPress
Debug control now lets a cooperating UltraCache producer report that outcome on
its successful authenticated prepare response using the existing
`X-UltraCache-ESI-Error-Contained: 1` header. No schema1 envelope field or VMOD
function was added. Older producers that omit the marker add no new diagnostic.

The native module accepts one exact marker, keeps a boolean only in the current
request's continuation, and consumes the captured response header. After the
complete envelope and owner binding validate, it writes one VCL_Log line:

```text
UltraCache prepare degraded: contained renderer fallback
```

The native transaction provides correlation; the message contains no cookies,
tokens, URLs or renderer output. It is not a browser header or a shared-object
field. The WordPress Debug setting controls emission by the application; no
second native control or background task is introduced. Existing HTTP-failure
logs and prepare rejection remain unchanged. See the
[normative contract](CONTRACT.md#debug-only-prepared-fallback-diagnostic).

## Native qualification

Each adapter passed 17 native/source-boundary checks and one additional actual
request-snapshot recovery regression, without failures, errors or skips:

- Absent, zero, malformed and duplicate markers add no diagnostic, while a
  caller's request marker is removed before reaching the provider.
- A successful marked prepare logs once per owner. Repeated fragment positions
  retain their output and authentic cookies; the next unmarked request does not
  inherit a diagnostic from the parent or another visitor.
- Actual prepare HTTP409/500, malformed JSON and incorrect request binding still
  fail; they cannot produce a degraded-success log.
- A valid privateDocument retains its application status and body, while a valid
  public-selection protocol envelope can carry the optional diagnostic.
- Snapshot recovery after an owned parent purge retains the prepared content,
  avoids another origin render, and does not duplicate the log.
- Existing child HTTP-error containment, ordinary endpoint behavior,
  Basic/generic ESI behavior and authorization boundaries remain qualified.

The paired adapters use byte-identical common native sources, VCL and contract.
The qualified isolated module's SHA-256 is
`4e580a04229837811e63042448a8410503a370afd827a134e257b7d8dc046ff2`.
Installers build their own module against the installed engine and headers;
this test binary is not distributed.

## Actual WordPress wire acceptance

Ten additional wire cases passed on a real isolated WordPress/WooCommerce
FPM fixture using the common qualified module and Hestia candidate VCL:

- Debug ON healthy delivery: parent HTTP200/HIT, no degraded diagnostic.
- Debug ON real renderer exception: fallback HTTP200/HIT, exactly one fixed
  degraded diagnostic.
- Debug OFF same fallback: HTTP200/HIT, no new degraded diagnostic.
- Actual WordPress HTTP500, a failed SQL query with a WordPress500 response, and
  a missing registered fragment: backend500 becomes rejected prepare/native503,
  with no degraded-success log or WordPress error page embedded in the cart.
- No response-only diagnostic marker reaches the browser; following healthy
  requests recover normally.

These are isolated application and native checks, not production rollout or a
separate full Webuzo/FPM deployment acceptance. The Webuzo adapter has the paired
native qualification above. The broader UltraCache recovery/performance fixes
and their application release remain separately owned and audited. No production
apply, purge, restart, configuration change or load test was performed.
