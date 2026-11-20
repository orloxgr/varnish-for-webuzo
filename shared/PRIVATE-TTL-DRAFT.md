# Scoped private TTL: isolated native candidate (#955)

Status: no positive-private-TTL capability is advertised. The isolated native
lookup/fill candidate below requires native qualification and an authenticated
application claim producer. Existing published private delivery remains TTL 0. This document does not claim runtime equivalence or
introduce new controls, cookies, sessions, credentials or classification rules.

## Evidence and boundary

Native source baseline is the installed fixture revision:
https://github.com/varnish/varnish/commit/ffd36e9db9a1ec2bf6637deda180a87d40a13d0f
(Varnish 9.1, VRT 22.2), not the differently versioned Vinyl archive.
The current request-owned prepare/replay pipeline can produce correct private
content, but synthetic child responses are not native cached objects. Merely
changing their Cache-Control or retaining rendered bytes in PRIV_TOP does not
implement positive TTL. Re-rendering everything in prepare before using a
cached copy would also miss the performance/lifecycle objective.

## Authority required from the application

The authenticated prepare runs the real provider lifecycle once and validates
the signed public manifest, original representation, current user/session and
renderer context. Only then may the application authorize a private partition.
Cookie presence or a request hash is never authenticated identity. A registered
TTL 0 renderer remains request-local and executes once per distinct occurrence
URL; no new automatic conversion is inferred from the cookie catalogue.

A candidate per-fragment claim needs these independent dimensions:

| Claim | Authority / purpose |
| --- | --- |
| Site/tenant | Immutable adapter site scope plus canonical host; prevents collisions between accounts. |
| Fragment/context/representation | Exact signed renderer URL/context and public representation digest. |
| Identity partition | Opaque application-authenticated partition for the actual user/session. If no stable verified identity exists, stay TTL 0. No shared default anonymous private key. |
| Mutable-state generation | Authoritative provider generation for cart/history/login/logout/session/nonce state; changes make earlier objects unreachable. |
| Permitted expiry | Existing renderer TTL and actual nonce/session validity bounds; do not extend them or reset source lifetime on replay. |
| Invalidation tags | Existing application invalidation dimensions, scoped to the same site/identity/generation. No cross-tenant/global purge as a substitute. |

The partition/claim must arrive only from a validated owned application
operation. It is never accepted from browser headers or serialized into shared
parent HTML/include URLs. An opaque digest is still sensitive metadata and must
not appear in client diagnostics or reusable public objects.

## Candidate native execution shape

Use native Varnish fragment objects and its TTL/expiry/invalidation machinery,
not a second VMOD global private-content cache. The client-side ESI lookup may
hash only the verified request-owned claim plus immutable site and exact URL.
Strip all externally supplied partition/expiry/generation fields before lookup.
Every final assembled browser response remains private/no-store.

On private-fragment HIT, reuse the native object's body only if all identity,
generation, representation and expiry dimensions match. No stored Set-Cookie
may be replayed: authentic provider fields still belong to the current parent
prepare/delivery. On MISS, expiry or invalidation, obtain the actual renderer
output without a second provider bootstrap/issuer execution for this top-level
request, then store only that private fragment in the verified partition.

The MISS body source and renderer-admission timing remain the implementation
gap. The current prepare JSON always renders all private-capable output before
the ESI lookup; this cannot be presented as efficient positive-TTL reuse. A
VMOD virtual backend can feed already authorized request-owned output through
normal native fetch storage, but an application/native handshake is still
needed to skip rendering on an actual private HIT without trusting stale
cookie-derived identity. Do not close #955 by removing PASS/no-store or adding
TTL headers. Any extended wire must be agreed with the UC provider code and
retain standalone operation.

## Acceptance required

Native objects must demonstrably HIT across distinct top-level requests for
the same owner, with renderer execution counters unchanged before expiry, then
render once after expiry. Two anonymous sessions, two logged-in users and
changed cookie names/values must not collide. Test login/logout, session renewal
and deletion, cart add/remove/quantity/empty, Recently Viewed updates, nonce
expiry with actual REST actions, multiple fragments/TTLs, targeted invalidation,
concurrency, abort/retry/error and forged claims. Check no personal cookies or
partition values in public parent objects, client headers or another owner's
response. TTL 0 remains the comparison baseline. These tests are not yet run.

## Executable isolated candidate wire

The same prepare/bootstrap may perform a lookup at the configured native HTTP
cache-control endpoint before rendering a private fragment. Method
`UC-PRIVATE-GET`, exact fragment URI, correct canonical Host/scheme, existing
`X-UltraCache-Token`, and `X-UltraCache-Private-Key: <64 lowercase hex>` are
required. The existing adapter site-secret gate plus loopback control-source
ACL authorize entry; cookies cannot authorize it. Basic, disabled sites,
wrong credentials/forwarded remote sources cannot enter. The read-only method
becomes GET inside the private hash namespace. A MISS/expired object returns
404 from Varnish without any origin fetch. HIT returns its body with literal
`Cache-Control: private, no-store`, no Set-Cookie, and whole remaining seconds
in `X-UltraCache-Private-Remaining`. The application validates response success
and uses actual HIT bytes without executing the renderer. Failures/MISS must
render only in the already-running original prepare context, not another WP
request. Positive TTL is for providers with an authoritative current
identity/state/expiry claim, never a default cookie-presence identity.

The existing `renderedFragments` entry may additionally contain:

```json
{"cache":{"key":"<64 lowercase keyed application digest>","ttl":30,"tags":"existing application tags"}}
```

All three fields are required when cache metadata is present. Positive TTL is
an integer representable by native VCL; embedded controls/CRLF in tags and
malformed/duplicate/unknown claim fields reject the complete envelope. TTL 0
uses the original entry without cache metadata. The existing exact URL, HTML
bytes and occurrences stay required: retained HIT bytes are also the recovery
source if native eviction/invalidation occurs between lookup and ESI delivery.
On an authenticated cache HIT the application uses only the remaining native
lifetime in the returned claim, not the configured original TTL.

Private ESI children with an owned claim use the disjoint namespace
site+canonical host+exact signed URI+opaque key. They can HIT across top-level
requests. On MISS, the same native virtual backend/source used for public
request snapshots supplies only the request-owned prepared fragment bytes.
Native Varnish stores/evicts/expires that object; the VMOD has no persistent
private body cache. The refill's TTL subtracts time since prepare response
receipt and has no new grace/keep. It is re-applied after custom VCL and before
storage, independent of site aggressive mode. Existing immutable object
site/host/URL metadata permit scoped native invalidation. Provider Set-Cookie
stays owned by the current parent prepare and is never stored on these
objects. Browser responses and authenticated read responses remain private.
Keys/internal object markers/tags are stripped from delivered responses.

This candidate deliberately **does not emit**
`X-UltraCache-Delivery-Private-Cache-Version: 1`. Caller and origin echoes of
that reserved declaration are stripped. A producer must gate optional claims
on a qualified capability before sending them to older strict parsers.
The new native mock fixture demonstrates the intended before-render lookup,
independent owner objects, native expiry, no issuer-cookie replay and failed
lookup without origin access; it is not real WP/provider acceptance and has
not yet run on a native engine for this checkpoint. Existing TTL 0, standalone
UltraCache, actual login/session validation and Basic behavior stay separate.
