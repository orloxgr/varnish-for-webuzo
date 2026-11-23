# Source-only public parent, first native gate

Private feature-branch protocol. This is not a released application feature or
evidence of actual WordPress/provider/SQL acceptance.

The existing authenticated public-selection declaration optionally includes
`X-UltraCache-Public-Selection-Public-Source-Version: 1`. Its accepted capability
is `X-UltraCache-VCL-Public-Selection-Public-Source-Version: 1`. There is no new
key, endpoint, service, table, queue, or manual product setting.

For an eligible cold document without configured unresolved Variant resolvers,
the existing native continuation performs a source-only `public-select` request.
It generates `X-UltraCache-Delivery-Public-Source-Version: 1` and
`X-UltraCache-Delivery-Public-Source-Role: parent-v1`. Client copies do not select
this subphase. Its actual backend URI and `Delivery-Original-URL` are the
canonical cache-significant source URI. The actual HTTP Cookie contains only
existing policy-resolved Variant inputs; an empty projection means no Cookie
header. Shared and private visitor state and Authorization are not source inputs.
The original visitor URI, cookies, conditionals and encoding remain separately
owned by that continuation. The URI/projection is applied **before** the ordinary
execution context is signed. A source execution retains the ordinary independent
execution-drain lifecycle; it never attaches a private reuse candidate.

The source responds with the existing authenticated selection envelope:

```json
{
  "schemaVersion": 1,
  "requestId": "native request identifier",
  "originalUrl": "/actual-canonical-source/",
  "selectedPublic": {
    "policyDigest": "native policy SHA256",
    "wordpressPolicyDigest": "WordPress policy SHA256",
    "publicSource": {"version": 1, "role": "parent-v1"},
    "manifest": "actual publication identity",
    "occurrences": 3,
    "publicParent": {
      "generation": "exact body SHA256",
      "bodyBase64": "actual public snapshot bytes",
      "freshRemaining": 120
    },
    "headers": ["existing validated publication headers"]
  }
}
```

Optional `cookieDelivery: true` must still match its existing publication header.
It declares a lifecycle requirement, not completion of personal delivery. There
are no `cookieUpdates`, `renderedFragments`, private recipe or cache claims in a
source outcome. Its public body retains actual ESI/head/inline/module structure;
it is not an expanded guest document. Existing identity, policy, count, body
digest, header and freshness checks remain mandatory. Source Set-Cookie fields
are discarded and never replayed to the visitor. The source does not emit or
require a final `Delivery-Outcome: verified`.

An application which declines before its business handler emits **bodyless409**,
`Content-Length: 0`, `X-UltraCache-Delivery-Public-Source-Version: 1`, and
`X-UltraCache-Delivery-Public-Source-Outcome: unavailable`. Native discards that
source, restores the real visitor and makes its ordinary personal request once.
A corrupt envelope or untyped raw source response is a protocol error; it is
never forwarded as the public or personal result. Producer-side REST/admin/action
guards must run before the actual handler, so refusal cannot repeat business work.

Only the next real personal `public-select` can complete the delivery. Its actual
publication manifest and body generation must match the captured source and its
deadline cannot exceed the source's original deadline. A typed private-document
outcome remains private. This first gate retains the original cold lookup key and
does not accept an unexplained changed Variant tuple. Ordinary warm HITs therefore
perform no public-source work. Source diagnostics are request-local, never part
of the cached parent's stored headers.

The first gate above does not infer required currency/locale/provider resolution
from an empty projection. Its separately negotiated extension is below. Old
producers and Basic keep their existing behavior. Actual Blocks and final
application-level correctness require separate composed acceptance.

## Explicit actual public projection

This private extension additionally negotiates
`X-UltraCache-Public-Selection-Public-Source-Projection-Version: 1` and its
`X-UltraCache-VCL-Public-Selection-Public-Source-Projection-Version: 1` echo.
It preserves the normal initial lookup, including configured resolver names;
a valid complete native HIT invokes no resolver, source, prepare or finalizer.
On a genuine cold MISS, the SAME `public-select` owner runs:

1. `Source-Role: resolver-v1` on the real visitor's original URI and Cookie,
   before any template/business handler. This is an actual application resolver,
   not a synthetic provider choice. There is no expected projection to invent.
2. `Source-Role: parent-v1` on the canonical public source URI with actual
   Variant-only Cookie. The exact tuple is encoded as padded base64 JSON in
   `X-UltraCache-Delivery-Public-Source-Projection`.
3. Actual personal `public-select` on the original visitor URI with its private
   inputs and the actual resolver-issued Variant updates. It carries the expected
   projection but no Source-Role. The original raw wire remains separately owned.

All three requests carry
`X-UltraCache-Delivery-Public-Source-Projection-Version: 1`. Source roles also
carry `X-UltraCache-Delivery-Public-Source-Version: 1`. The agreed tuple is:

```json
{
  "version": 1,
  "bucket": "actual application bucket",
  "locale": "actual locale",
  "language": "actual language",
  "cookieValues": [{"name": "actual literal Variant name", "valueBase64": "cmF3LXZhbHVl"}]
}
```

All three identity fields are strings, including actual empty strings. Rows are
sorted unique literal names. Canonical base64 encodes exact raw Cookie bytes;
`null` means actual known absence/deletion and differs from empty or omitted.
JSON object key order/whitespace do not change identity; duplicate keys, including
escaped duplicate names, are rejected. Public cookie names use the existing
Cookie Database literal grammar, including interior spaces, colons, slashes and
Unicode. Controls, delimiters and leading/trailing whitespace are disallowed;
every row must also have an active Variant policy. Private consumed-input/PHP
ambiguity checks retain their existing distinct contract. No provider allowlist,
global mutation, locale/currency guess or fabricated browser cookie is used.

Resolver-only success has `Source-Version: 1`, `Source-Outcome: resolved`, and
EXACTLY `schemaVersion`, `requestId`, `originalUrl`, `resolvedPublic` in the outer
selection envelope. There is no body, snapshot, private recipe or separate
cookieUpdates field. Its actual cookieValues are merged through the existing
request-owned visitor candidate; real issuer Set-Cookie headers are retained.
A matching source snapshot has `Source-Outcome: captured` and MUST include
`selectedPublic.resolvedPublic`, as must the actual personal selected snapshot.
The typed tuple, publication and body must all match; an old body cannot be
relabeled with a new choice. Existing URL/Cookie/Vary dimensions remain the cache
key authority; the tuple does not introduce an unproven request-to-variant map.
Changed actual Variant values rejoin the normal key for those actual values,
never alias the unresolved original/empty key or introduce a manifest-only key
that repeats source work on every warm lookup.

A parent which measures a different tuple before its template returns the same
top-level resolvedPublic-only outcome. Its cookies are NOT visitor issuance.
Native re-enters the real original-visitor resolver once for actual issuer work,
then retries the pure source. Those two finite internal transitions reserve only
their own request's restart headroom, like the existing finalizer, without any
global resource/timeout setting. Repeated instability enters one real private
personal fallback using authenticated
`X-UltraCache-Delivery-Public-Source-Fallback: unstable-public-projection`, without
Source-Role or expected-projection values. Only an actual privateDocument or raw
private response may complete it; no shared snapshot/private reuse is admitted.
The explicit fallback reason is not feature-goal acceptance. Actual resolver and
personal issuer headers retain chronological order; pure source cookies are
discarded. Private reuse evidence/finalization uses the real effective visitor
Cookie, while final original-route ownership still uses the preserved raw URI.

A typed `409 / unavailable` pure source supplied no completed public-parent
provenance. The same real personal execution therefore receives the existing
fallback header with reason `public-source-unavailable`, without Source-Role or
expected projection. It must return a genuine privateDocument or an actual raw
private response; a claimed selectedPublic cannot replace the missing source.
No empty success, extra business callback, shared write or inferred anonymous
parent is created. A source still being processed must use this explicit decline
instead of binding a raw intermediate body to a later optimized publication.
