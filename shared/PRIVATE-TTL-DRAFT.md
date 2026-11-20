# Scoped private TTL: isolated native candidate (#955)

Status: native lookup/fill/negotiation and selected actual WP/Woo claim flows
have exact qualification evidence below. Broader first-cold visitor-copy and
provider lifecycle completion remain separate goal requirements. This isolated
source is not a release or a universal claim-provider compatibility claim. It
introduces no new controls, cookies, sessions or classification authority.


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

The new native mock fixture demonstrates the before-render lookup, independent
owner objects, native expiry, no issuer-cookie replay and failed lookup without
origin access. Root qualified exact Hestia `550620a` against installed native
Varnish 9.1/VRT 22.2: 12 tests executed, zero skips, including the original ten
continuation tests and the two private lookup/fill fixtures. DSO SHA256
`9ba1b59357fcf6f45ada31baefd3c2658bf8f50b65e4c2c33a1ab3e59b5433c5`.
This is mock transport evidence, not real WP/provider identity acceptance.
Existing TTL 0, standalone UltraCache, actual login/session validation and
Basic behavior stay separate.

## Feature-version negotiation, without a new control

The implemented native wire declares
`X-UltraCache-Delivery-Private-Cache-Version: 1` only on a native-owned
`Phase: prepare` backend request and the existing internal signed
`ultracache_esi_probe_private_fragment` backend branch. There is no manual
VCL-init call, hidden enabling flag, new configuration field/UI or extra probe.
Basic, ordinary parent/public/private children and parent-snapshot recovery
stay silent. Browser copies cannot activate it; origin echoes are removed
before storage/delivery. This is capability metadata, not identity/authority.

Old UltraCache ignores the unfamiliar declaration and keeps its original
strict envelope. The new application producer requires both the existing
validated stored probe observation and the live prepare version before using
optional cache claims. Deployment is kept separate: root installed the combined candidate only in
its owned WP fixture after the producer existed. Actual user/session/state
checks and independent renderer/storage audits are required there. Mock lookup/fill success is not a reason to claim real
identity/state/provider/expiry acceptance or publish/release it prematurely.

`test_declaration_uses_existing_probe_and_owned_prepare_only` checks the actual
wire and spoof/echo stripping against a mock origin. Basic's fixture checks
ordinary requests stay silent and that its valid site token cannot enter
private lookup. Root compiled exact Hestia `f09eaad` against native
Varnish 9.1/VRT 22.2 and executed all 13 then-current tests with zero skips
(68.486 seconds). DSO SHA256
`c6f126bb85bfebe2925fb579626bb612aff7f95a7f0ba496140a0098139dbdf6`.
This separately qualifies the negotiation delta; it is not an actual WP
claim-provider or release acceptance claim.

### Native object eviction after a successful private lookup

A separate fixture purges the actual native private object after lookup HIT
returns but before the parent prepare JSON completes. The ESI child must use
the request-owned retained HIT bytes to refill that same authorized namespace,
without another renderer call or origin child fetch, with the current prepare's
authentic cookie exactly once. A subsequent lookup must HIT the refill with
its remaining budget. This fault case is not implied by ordinary HIT/expiry
success. Root verified the C/VCL/build inputs of `d59918f` are byte-identical
to `f09eaad`, reused the same DSO above, and executed the four private fixtures
plus one selected continuation case: five passed, zero skips, 18.717 seconds.
The private fixture counts actual mock renderer function calls independently
of cached HTML. Real WP claims require independent application-side execution
audit too; a counter embedded in cached HTML cannot prove renderer skipping.

## Combined actual application checkpoint reported by the Lab owner

Root qualified exact Hestia `34934bb` on installed Varnish 9.1/VRT 22.2:
all 16 then-current native tests executed, zero skips, 87.424 seconds. This
comprises ten continuation, four scoped private TTL and two personal-copy
transport test methods (including their aggressive/public-ESI subcases). The
C/build inputs and DSO remain byte-identical to the qualified `f09eaad`
SHA256 above. The source owner did not operate the Lab in parallel.

Actual UltraCache `1c03c7f8` with that native private wire passed a 31-visit
owned browser/application actor with independent append-only renderer audit
and current-owner read-only uncached REST counters. Those counters, rather
than values embedded in cached HTML, verify actual lookup-before-render reuse.
The accepted cases include actual WP owners A/B, actual Woo sessions A/B, real
TTL expiry, targeted fragment/context URL purge with sibling preservation,
owner A state mutation preserving B, after-render issuers/state mutations
remaining uncached, eviction after lookup without rerender, new/invalid Woo
session first request staying TTL 0 with provider-owned cookie replacement,
cart add/remove, logout/invalidated auth, renderer error retry and recovery.
URL purge deliberately invalidates all partitions of that fragment/context;
per-owner state generation makes only that owner's old partition unreachable.
No new owner-purge control or schema is claimed.

The root audit observed 687 authenticated lookup requests: 214 native HIT and
473 local 404, with no lookup-origin fetch or stored-cookie replay. Its three
owned public publications contained none of the observed personal renderer
bodies, 317 observed opaque private keys, 58 observed cookie values or
ephemeral delivery headers. This is a bounded fixture/storage audit, not a
proof about all future provider output. Independent installed-source audit
matched 3492 files. Broad first-cold application rendering/collector separation
was not implemented by this checkpoint and is not closed by private TTL.

Webuzo shares the same native and policy bytes, but adapter/runtime evidence
remains separate: do not present Hestia fixture execution as actual Webuzo
panel/CLI qualification. Its disposable native harness now accepts the shared
fixtures' site_settings argument; the Webuzo generated-policy native run is
still an independent acceptance item.
