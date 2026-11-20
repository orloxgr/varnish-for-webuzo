# Scoped private TTL: native/app design, not implemented (#955)

Status: no positive-private-TTL capability is advertised. Current private
delivery remains TTL 0. This document does not claim runtime equivalence or
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
