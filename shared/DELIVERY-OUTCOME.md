# Request-owned prepared private delivery outcome

Parent cache observation and prepared private fragment delivery are separate.
An HTTP 200/HIT does not establish that a personal renderer completed normally.
The existing Debug-only `X-UltraCache-ESI-Error-Contained: 1` aggregate continues
to control its optional fixed VSL diagnostic; it is not an always-on health bit.

The normal native capability/probe path advertises
`X-UltraCache-VCL-Delivery-Outcome-Version: 1`. A compatible application which has
verified that declaration returns one internal header on a successful bound
prepare, complete public-selection envelope or complete private document:

- `X-UltraCache-Delivery-Outcome: verified` after all required prepared rendering
  and complete envelope encoding succeed without contained fallback.
- `X-UltraCache-Delivery-Outcome: degraded` when a known renderer fallback was
  contained, independently of WordPress Debug.

An incomplete selection-only stage is not verified fragment delivery. Native
selection parsing requires its complete fragment list, exact occurrence count
and header/publication bindings. Ordinary preparation checks the expected parent
manifest/count and request/URL ownership. Real failed HTTP responses and rejected
envelopes keep their existing failure paths.

Capture consumes the producer header into the existing owner continuation. Only
after complete validation and final delivery can
`cookie_handoff.delivery_outcome(PRIV_TOP)` expose verified or degraded.
`PRIV_TOP` is the same request-owned storage as the existing continuation, not a
visitor database or shared cached object. Missing, malformed, duplicate or
contradictory fields yield unverified. Verified alongside the Debug fallback
marker is contradictory.

The VCL removes client, ordinary origin and cached copies, then creates the final
top-level `X-UltraCache-Delivery-Outcome` from the getter. Basic does not gain ESI
or an outcome header. UltraCache without a completed prepare reports unverified;
the page remains deliverable. Private documents keep their real HTTP status.

The outcome concerns required **prepared private fragments** or the complete
owned document. It does not certify later ordinary public ESI subrequests.
Helper-free/late private ESI has no completed prepare verdict. Warm-up reporting
must keep parent HIT separate from verification of required private fragments.

Qualification uses isolated Varnish 9.1 and real HTTP/VSL: seven outcome methods
and seven existing prepare diagnostic/recovery methods pass per adapter, without
skips. These cover Debug OFF/ON, strict fields, failed/bad-bound/incomplete
prepares, private documents, public selection, actual capability headers and
forged client/origin/cached verdicts. Actual WordPress/provider acceptance and
full panel installation are additional scopes.

The separately negotiated observed-issuer contract also reports the completed
cookie-only operation with zero private fragments. Its final work-required flag
lets warm-up require the same verified outcome; see `COOKIE-ONLY-DELIVERY.md`.
An ordinary unmarked plain HIT remains unverified by this prepare-specific
mechanism and does not gain an application call.
