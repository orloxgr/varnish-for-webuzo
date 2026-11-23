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

## Covered projected selection and retained consent cookies

Active mutation coverage, execution-drain negotiation and public-source
projection add their own authenticated context to a cold prepare. The native
module removes four backend-only storage carriers before stamping that context:
`X-SCP-Vary-Accept`, `X-SCP-Vary-Accept-Language`, `X-SCP-Vary-Cookie` and
`X-SCP-Vary-ESI-Cookie`. This applies only to the owned `D_PREPARE` phase, whose
response is an uncacheable typed envelope. Their actual representation inputs
remain on the owning request and continuation. Ordinary origin and recovery
fetches keep their Vary inputs. The application negotiation markers and signed
mutation context remain intact.

After fixing that backend peak, the projected multi-phase fixture exposed a
second failure in the client workspace: each restore allocated another copy of
the unchanged original Cookie and URL. Restore now reuses an exactly identical
single header and unchanged URL. Changed or duplicate headers still use normal
replacement; absent and empty values remain distinct.

`test_backend_mutation_header_budget.py` exercises both stages with a synthetic
2315-byte consent Cookie, full browser fields, real native signed-coverage
verification and an explicitly mock resolver/source/application. Both the
ordinary navigation and the Pragma/Referer case use unchanged `http_max_hdr=64`,
96 KiB client/backend workspaces and 8 KiB/32 KiB request limits. A separate
ordinary authenticated POST verifies exact Cookie, Authorization, URL/query,
Content-Type and encoded form-body preservation with one backend execution.
These fixtures qualify native transport behavior, not real WordPress or browser
acceptance. The earlier header-capacity negative control remains active.

## Large Variant values through the complete continuation

The active-coverage fixture additionally exercises a6144-byte incoming Cookie.
The historical245-method run on770309a did not cover that size: the older
workspace loop covered600/1200/1800/2400 bytes. Its passing result must not be
reported as6144-byte acceptance.

Variant groups now accumulate on the existing request task, with the same VCL
selectors and rule order. Delimiter normalization remains at each original rule
boundary; moving it to the end can change a later selector's leading-blank
behavior. Normalization and name extraction use temporary owned heap buffers,
then emit only the needed final header/name bytes. Begin/reset/finalization free
the task buffers; allocation/overflow failures remain explicit.

The existing authorized continuation also retains its native capture of the
original Cookie and ordered Variant instead of duplicating them as scratch
headers. Reuse still requires the original phase/site/host/URL authorization and
exact Cookie equality, preserving absence/empty distinctions and excluding ESI
children. Identical unique Vary headers remain in place across that same resume;
changed or duplicate headers take normal replacement. Applying the selected
Variant uses the existing header restoration owner once. Cookie diagnostics
materialize names under the existing predicate, without copying full values
into another request header merely to remove them again.

No action, priority, cookie value, request limit, workspace size, worker count or
TTL changes. Normal and disabled-engine modules share these helpers.
`test_cookie_working_normalization.py` compares native normalization and names
against the original VCL operations, including empty/delimiter/Latin1/random
inputs and a large value. These are explicitly native mock-application checks;
matching real WordPress/browser and normal installer acceptance remain separate.
