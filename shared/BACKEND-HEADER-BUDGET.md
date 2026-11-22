# UltraCache backend header budget

The UltraCache adapter discards completed CMS routing and selection scratch
headers before constructing the authenticated prepare request. The native policy
hint is consumed before its scratch field is removed. Client/application fields,
credentials, cookie transport and native representation/Vary inputs are retained.
Basic routing is unchanged. No Varnish parameter is changed.

The returning-browser path also drops the backend copies of the original ESI
cookie carrier, ESI opt-in and request-only PASS marker before constructing the
prepare envelope. Their top-request originals remain available for composition
and final response diagnostics. The Warm support scratch field is removed once
its capability hint has been emitted. No actual Cookie, application field,
credential or representation input is removed by this cleanup.

The regression includes a negotiated guest/Warm registration with the captured
Edge navigation header shape, one diagnostic marker and a returning
WooCommerce-shaped cookie context. The live unmarked navigation succeeded; the
additional marker exposed this existing header-count boundary.
It reproduces credential LostHeader/503 on the preceding source at the normal
64-entry header limit and verifies cold selection followed by a parent HIT on the
cleanup. An overlapping load/use/discard of the unchanged native module retains
the registry epoch, current declarations and exact cached objects for both the
guest site and a second Basic site. This is a shared VCL activation, without a
service restart, namespace bump or purge; it still activates new code globally.

Varnish counts header entries separately from workspace bytes. With
`http_max_hdr=64`, five entries are reserved for the HTTP start line, leaving 59
header entries. Exhausting these entries can also report `out of workspace (bo)`.
The native module now distinguishes resource exhaustion from an actual second
prepare attempt, and reports a capture-association allocation failure separately.
The repeated-operation guard remains active. Failure never retries the provider.

## Isolated qualification

`tests/test_backend_header_budget.py` runs actual ephemeral Varnish daemons with
`http_max_hdr=64`, an ordinary desktop browser/proxy header set and a declared
mock producer. It verifies:

- Cold public selection and two warm private batches deliver the correct visitor
  fragments with exactly one application operation per visit.
- Original application fields and Cookie reach the mock producer, completed
  scratch fields are absent, and representation/Vary inputs remain available.
- An injected real second prepare call is rejected before application work.
- Restoring the obsolete scratch fields to the prepare peak reproduces a
  LostHeader/resource failure, without application work or a false repeated-
  prepare diagnostic.

The same tests pass with Hestia and Webuzo VCL and their shared native module.
An additional isolated negative control using the earlier core VCL reproduced
503/LostHeader with the same browser fixture before any origin request.
Representation and cold-selection regressions are qualified separately. These
are native mock-producer checks, not a claim of live WordPress acceptance or
production deployment. This correction does not repair missing application
publication manifests; that is a separate producer issue.
