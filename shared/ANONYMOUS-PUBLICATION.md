# Complete anonymous publication - protocol 1

Tracking: UltraCache issue #1006. Protocol 1 is agreed by the producer and native
owners and implemented through the native application's existing connection and
publication lifecycle. Each panel adapter records its own qualification and
release status. Existing private delivery validation remains intact. Basic is
outside this extension.

## Required result and scope

After ordinary Warm, two independent new anonymous visitors get complete HTML,
empty-cart markup and usable guest nonces from Varnish, with no origin request,
prepare or origin-backed ESI during HTML delivery. A public-parent HIT followed
by a WordPress prepare does not meet this result.

Protocol 1 is deliberately the agreed first-visit scope: the original top-level
request has **zero Cookie fields and zero Authorization fields**. Present-empty,
duplicate or subsequently stripped fields do not count as absent. Capture that
fact at initial ingress, before any cookie-policy/protocol normalization, and
retain it as native-owned state. Browser-supplied guest/work markers cannot set
it. Only an ordinary GET document, already admitted by existing host, route,
method and privacy rules, may select this projection.

A request with any Cookie/Authorization field keeps the existing path, including
its saved Shared/Variant/Private actions. This is a representation selection,
not a new cookie classification, forced Private choice or second cookie list.
There is no new panel setting. An application advertises support through its
existing connection/capability lifecycle only when it can produce this guest
representation under its actual public context. This version does not infer an
unresolved provider context from absent cookies or silently choose a currency.

## Existing owners and negotiation

Reuse the existing authenticated capabilities operation, application scope
registry, adapter site/host boundary and native registry-lifetime epoch. Keep
ordinary public-selection and prepare schemas/behavior unchanged unless this
extension is negotiated. The new declarations are exact single fields:

Producer capabilities registration, together with the existing enabled/scope,
WordPress policy and resolver-name fields:

```
X-UltraCache-Public-Selection-Guest-Version: 1
X-UltraCache-Public-Selection-Guest-Policy: <64 lowercase hex>
```

The guest policy is a producer-owned digest of the actual guest publication
format, applicable renderer/nonce dependencies and cookie-issuer disposition,
in addition to its effective application policy. It contains no visitor values.
A declaration update without these fields removes previous guest support while
retaining ordinary cooperation. A read-only capabilities query never changes
registration. Enabled 0 removes both for the exact application scope. Existing
longest-scope matching applies; a child scope cannot inherit parent guest proof.

A supporting native replies, and advertises on ordinary origin operations:

```
X-UltraCache-VCL-Guest-Publication-Version: 1
```

An exact authenticated capabilities query additionally returns the accepted
producer guest policy, only when that exact scope is registered:

```
X-UltraCache-VCL-Guest-Publication-Policy: <64 lowercase hex>
```

A producer must not emit the new outcome to an old native consumer. Native must
not interpret a marker on an ordinary origin response as authenticated guest
registration. Duplicate/invalid negotiation fields are rejected, not merged.

## Lookup and owned cold fill

At initial lookup, native selects a distinct `guest-v1` object namespace only
when the absent-header fact, active scope declaration and ordinary request rules
agree. Add the accepted guest policy, both effective policy identities and native
registry epoch to that namespace. Keep host, canonical URL, scheme, representation,
functional query and ordinary Variant/Vary dimensions. Do not rewrite the URL or
Cookie. All other requests use the existing namespace and continuation.

Guest lookup occurs without PHP. On a cold guest MISS use the existing original-
route public-selection entry and its original request ID/URL/credential/scope/
policy binding. Add these native-owned request fields:

```
X-UltraCache-Delivery-Guest-Publication-Version: 1
X-UltraCache-Delivery-Guest-Publication-Policy: <accepted producer guest policy>
X-UltraCache-Delivery-Guest-Publication-Canonical-URL: <native canonical relative URI>
```

The canonical field is the exact native COPY used for cache hashing, preserving
unknown/repeated/encoded functional query bytes and omitting only the existing
native tracking parameters. The raw original URL remains unchanged. The producer
uses this owned field for its public issuer ticket identity rather than its own
potentially different query normalizer. The existing origin epoch hint carries
the current registry epoch. The producer
checks both negotiated fields, literal absent Cookie/Authorization and the full
existing authenticated original-route entry before doing guest publication work.
A browser copy of either field cannot authorize this operation. No new shared
credential or user-provided key is introduced.

If an owned guest cold selection returns the existing selectedPublic or
privateDocument outcome instead, preserve its actual validated current-request
behavior; do not put a private-capable parent into the guest-complete cache.
A guest outcome on a non-guest selection, ordinary prepare/recovery, or stateful
request is a protocol error. A failed guest fill must not turn an unresolved
private count into zero or serve the other representation's body.

## Exact producer envelope

Reuse HTTP 200, `application/vnd.ultracache.delivery+json`, private/no-store outer
transport and the existing public-selection version marker. Add exactly one:

```
X-UltraCache-Delivery-Guest-Publication-Version: 1
```

Use a separate negotiated outcome, **guestPublic**, never relabel an existing
selectedPublic or privateDocument result. Envelope keys are exactly:

```json
{
  "schemaVersion": 1,
  "requestId": "<exact native-owned decimal ID>",
  "originalUrl": "<exact original relative URI>",
  "guestPublic": {
    "policyDigest": "<native policy: 64 lowercase hex>",
    "wordpressPolicyDigest": "<registered WP policy: 64 lowercase hex>",
    "guestPolicyDigest": "<accepted guest policy: 64 lowercase hex>",
    "registryEpoch": "<current native registry epoch: 64 lowercase hex>",
    "scope": "/shop/",
    "manifest": "<producer-signed guest publication token>",
    "sourceManifest": "<signed source publication token>",
    "sourceGeneration": "<source publication body SHA-256>",
    "resolvedOccurrences": 13,
    "publicParent": {
      "generation": "<complete guest body SHA-256>",
      "bodyBase64": "<complete UTF-8 HTML bytes, base64>",
      "freshRemaining": 1234
    },
    "headers": ["Content-Type: text/html; charset=UTF-8"],
    "cookieDelivery": "none"
  }
}
```

`cookieDelivery` is the exact enum `none` or `deferred`. Numbers are nonnegative
integers, not strings/floats/bools; source occurrences may be zero. Scope equals
the exact selected registration. Unknown/duplicate keys and contradictory outer
markers are rejected. The signed guest token binds source token/generation,
original application URL/context, guest policy, complete guest body digest,
resolved occurrence count, issuer disposition and actual validity. It is opaque
to native; it must not be usable as an ordinary private-prepare token.

The producer owns the transformation: resolve all source occurrences, including
repeated contexts, nonce attributes and public fragments, into complete guest
bytes during normal publication/Warm or that owned cold selection. Keep using
the existing captured publication and collector; no second local HTML cache,
SQL table or native visitor/body database. `resolvedOccurrences` records the
actual original source coverage; it is not a fabricated private count of zero.
The source publication and its stateful fragment/token bindings remain intact.

Native verifies exact owned request/URL/scope/epoch/policy bindings; body digest;
strict public-header grammar; and that this complete representation has no
remaining ESI includes, prepare/cookie-only work marker or visitor Set-Cookie.
Neither outer Set-Cookie nor Set-Cookie2 is accepted for guestPublic: real cookie
work belongs to the separate owning browser request. Public headers may include
normal HTML content type, public tags, applicable Vary/CSP and validators, never
credentials, request IDs, hop-by-hop fields or derived length/encoding/date/age.
Do not advertise ESI parsing for this complete body. Native trusts the authenticated
producer's source-to-guest publication claim just as it trusts a declared public
application response; it cannot independently prove WP nonce semantics or verify
an opaque producer HMAC. Tests must establish that producer claim in practice.

Freshness is no greater than the actual remaining source publication lifetime
and the real validity of embedded nonce material. No new fixed TTL, grace-based
nonce extension or full-lifetime reset. The native body snapshot director stores
only the complete guest object and its ordinary metadata under the guest key.
It does not retain an owning visitor continuation as public state. Cached native
metadata retains a fixed-size digest of the opaque guest manifest, never the
full token in an HTTP field. The complete signed token stays in the transient
owned selection and is not passed to legacy prepare/selection getters. Existing
site/URL/tag/publication invalidation covers guest and stateful namespaces.

On guest HIT, return this object directly. Do not call delivery_deliver to start
prepare, create an empty fake prepared batch, or report per-visitor private
`verified` from a cached field. Expose a distinct nonsecret observation
`X-UltraCache-Guest-Publication: 1` created from validated native state; retain
ordinary HIT reporting. A validated complete guest response omits the irrelevant
private Delivery-Outcome entirely; it does not report unverified as though an
expected private operation failed. Existing prepared private Delivery-Outcome
keeps its meaning, and a forged guest marker cannot suppress that verdict.

## Ordinary Warm primes both public projections

A complete guest object does not replace the existing private-capable public
parent. Once a visitor acquires a cookie, the original request predicate selects
that existing parent namespace. Ordinary application Warm must therefore refill
both through its current refill pipeline, for each applicable representation.
It must not create a dummy cookie/session, toggle scope registration, or wait
for the first real stateful visitor to fill the second object.

Supporting native advertises `X-UltraCache-VCL-Warm-Projection-Version: 1` on the
existing capabilities reply and ordinary origin hints. A negotiated application
keeps its ordinary absent-cookie guest refill and adds a parent refill to the
same normal stage. The latter is an ordinary GET on the actual public route,
with the actual representation Accept header, and exactly one of each:

```
X-UltraCache-Warm-Projection: parent-v1
X-UltraCache-Warm-Projection-Authorization: v1:<lowercase HMAC-SHA256>
```

The key is the existing scoped connection secret. Message bytes, LF separators
and no trailing LF:

```
ultracache-warm-projection-v1
parent-v1
GET
<native ingress Host: adapter lowercase/port normalization>
<exact raw relative request URI, including original query bytes>
<effective forwarded scheme: http or https>
<actual Accept header, or empty string if absent>
<exact longest matching registered application scope>
<current native policy digest>
<accepted WordPress policy digest>
<accepted guest policy digest>
<current native registry epoch>
```

The accepted authenticated capabilities/registration reply also returns
`X-UltraCache-VCL-Public-Selection-Canonical-Host`, the exact adapter-normalized
native ingress host. Store it as `selection.canonicalHost` and sign Warm using
that accepted value. If an older adapter omits the receipt, retain the existing
application hostname-only fallback. The receipt changes neither adapter host
normalization nor proof verification; an exact-authority Lab vhost can therefore
bind its real host and port without a test-only application override. Request,
backend and ordinary response copies of this field are scrubbed.

The native ingress fact must still be literal absent Cookie and Authorization.
Capture selector/proof as native-owned request state before scrubbing both HTTP
fields. Verify against the native adapter-owned site key and current actual
registration before guest selection. Use a constant-time digest comparison.
Duplicate, invalid or mismatched requested selectors cannot choose the parent.
Neither raw key nor request proof is forwarded to the application or stored in
the cache. The proof selects only the existing parent representation for this
owning refill request; all route, cookie-policy and private-delivery rules still
apply. It never changes the scope declaration, guest eligibility of other
requests, native epoch, source publication or cookie policy. It adds no origin
work to guest HITs, no session, persistent registry, queue, user control or timer.

An adapter supplies the credential map to the shared `compile_rules` call from
the same actual site configuration used by its existing delivery authorization.
It does not derive a credential from incoming fields. Unsupported old native
continues its existing refill behavior; do not send an unauthenticated marker as
a substitute for negotiated support. Acceptance includes ordinary Warm followed
by both complete guest HIT and first real stateful parent HIT, with the actual
visitor's independently verified private fragments, plus normal purge/clear and
Warm restoring both objects.

Only the final owning authenticated refill response exposes
`X-UltraCache-Warm-Projection: parent-v1`, from native-owned request state after
scrubbing client/origin copies. It has no Guest-Publication marker. This is never
cached object metadata and is absent on ordinary guest or stateful deliveries.
The producer checks this observation plus successful HTTP/cache outcome; a
module ignoring the selector cannot be counted as a successful parent refill.

## Nonces and independent cookie creation

Guest nonce output must be actual WordPress output valid for the declared guest
identity and action. A pattern marked private does not prove different anonymous
bytes. Custom nonce_user_logged_out identity, session-dependent token or other
real state retains its owning private path. The producer qualifies the actual
supported dependencies and verifies nonce use, not merely equality of two samples.
Native neither invents WP nonces nor removes an ordinary private slot's binding.

Cookie issuance cannot reuse an ordinary prepare URL directly: that protocol
requires native-owned request identity and a site credential, neither of which
belongs in browser HTML. Never relax that authentication.

For deferred cookie work the producer inserts its own same-origin browser code
and a **distinct signed public guest-issuer entry ticket** in the complete HTML.
That ticket is not a native credential, ordinary prepare token or authorization
to render private fragments. It binds original route/application scope, guest
policy/source publication, only the actual observed permitted issuer work and
an expiry no later than the publication's existing validity. It grants only the
anonymous side effects already available from visiting that page.

The browser performs one separate same-origin credentialed POST outside the HTML
critical path. It appends the operation pair to the current real browser route,
preserving that visitor's raw tracking and functional query bytes. It does not
reuse a cached publisher's raw route or reserialize unrelated query pairs.

For this private POST, native removes exactly one literal reserved operation
pair from a COPY, then applies the very same native tracking canonicalizer used
for ordinary HTML keys. Duplicate operation pairs receive no stamp. Actual
req.url/URI stays unchanged. The private origin request receives exactly:

```
X-UltraCache-Guest-Issuer-Version: 1
X-UltraCache-Guest-Issuer-Canonical-URL: <native canonical relative URI>
X-UltraCache-Guest-Issuer-Authorization: v1:<lowercase HMAC-SHA256>
```

The HMAC key is the existing scoped connection secret, which is never sent on
this browser-shaped POST. Exact message bytes, with newline separators and no
trailing newline, are:

```
ultracache-guest-issuer-v1
POST
<lowercase(trim(final forwarded HTTP Host)), including any explicit port>
<actual raw request URI including the reserved operation pair>
<native canonical relative URI>
```

The producer calculates hash_hmac('sha256', message, existing_connection_secret)
and compares the `v1:`-prefixed result with hash_equals. Sign the actual forwarded
origin Host, not an unrelated private selector. Even a phpinfo-like endpoint that
echoes request fields sees only a request-bound proof, never a reusable purge or
prepare credential. The proof cannot move to another method, host, raw URI or
canonical identity. Public ticket validity supplies its existing expiry; there
is no new timer, replay database or per-HIT work.

The producer verifies this proof and compares the canonical field directly with
its signed ticket. No duplicated tracking allowlist or
application normalizer can discard an unknown functional key for authorization.
Native strips forged ingress and echoed response fields. This stamp grants no
prepare identity; Delivery-Authorization remains separate. The producer still
verifies ticket HMAC, origin, scope, guest policy, expiry and allowed issuer work.
No field or credential is returned in the browser response.

Use the original route plus the reserved operation query key
`ultracache_guest_cookie_delivery`, whose value is the signed entry ticket. The
producer validates the ticket and restores its exact original route context;
this key cannot route an arbitrary URL. Native's existing non-GET rules pass the
request privately; its response is never cached. The producer may factor and
reuse the current original-route issuer capture/lifecycle internally, but this
entry executes only issuer work, not the private fragment prepare. It returns
204 with original repeated Set-Cookie fields and no-store on success. Existing
cookies, consent, renewal/deletion and provider errors remain application-owned.
No cached cookie values, native identifier generation, issuer-name special cases
or site secret are exposed. The producer must enforce its normal same-origin
browser endpoint checks and reject non-POST operations.

A truly empty guest cart need not acquire a WooCommerce session just to display
empty markup. Real state-changing actions establish state through their existing
application lifecycle. If cookieDelivery is none, there is no background issuer
request. A deferred operation is not a new daemon, queue or persistent worker.

## Acceptance before implementation is declared complete

Normal Warm then two independent fresh jars: complete document HTTP 200/HIT,
correct empty cart and usable real guest nonces, zero WordPress bootstraps and
zero origin/ESI backend links during HTML delivery, in ORIG/WebP/AVIF. Count cookie
issuer requests separately and prove HTML does not wait for them. Then exercise
actual cart/session/login and custom guest identity, proving existing private
ownership and no cross-user bytes. Include absent versus present-empty headers,
forged guest markers, exact subfolder/host scope, policy overrides, duplicates,
malformed bindings/digests, genuine nonce rollover, ordinary local clear/Warm,
publication replacement and same-build registry restart/autoregistration. Public
cache must contain no issuer fields, visitor values or request-owned fragments.
# Optional Shared-cookie input evidence (version 1)

The native capabilities response and authenticated application-selection upstream
advertise `X-UltraCache-VCL-Guest-Inputs-Version: 1`. A supporting producer may
append `guestPublic.guestInputs` without changing the original no-Cookie guest
ingress or legacy envelope:

```json
{"version":1,"privateOccurrences":0,"recipe":{"digest":"<canonical SHA-256>","inputs":{"cookieNames":[],"cookiePrefixes":[],"phpMaxInputVars":1000},"fragments":[]}}
```

`recipe` is the existing private-reuse canonical wire, including actual PHP
parser context, actual provider exact/prefix selectors, descriptor identity and
expanded private occurrence multiplicity. The producer binds `recipe.digest`
as `guestInputsDigest` in the same signed guest manifest. `privateOccurrences`
must equal the recipe total and cannot exceed `resolvedOccurrences`, which also
counts public includes. An empty recipe describes a truly empty expanded private
closure; missing/unknown claims cannot be treated as empty. Malformed or duplicate
optional declarations disable this extension while retaining an otherwise valid
legacy no-Cookie guest publication. Older producers can omit it entirely.

Only requests whose original Cookie pairs all have an explicit effective Shared
action may look up the existing guest namespace as candidates. Before delivery,
native matches the actual cached object's complete marker and manifest digest,
the existing site/host/scope/policy/epoch owner, and its remaining publication
lifetime. Its ORIGINAL Cookie is projected through the publication's actual typed
provider inputs and must equal the original empty-guest projection. An unrelated
Shared analytics cookie can reuse the complete body immediately. A Shared Woo,
authentication or other provider input that changes presence/value retains the
stateful route; present-empty is not absence. Private, Variant and unclassified
cookies do not enter this extended candidate namespace.

Evidence is hash-indexed publication metadata under the existing declaration
owner, keyed by the guest namespace and actual manifest digest, not visitor values
or identities. Identical authenticated registration preserves it; changed policy,
scope, epoch, object provenance or expiry prevents its use. No full recipe is put
in an HTTP metadata header. No additional service, per-HIT PHP operation, cookie
issuance, TTL/resource setting or manual configuration is introduced.

A candidate MISS, missing evidence or unequal input projection takes one exact
request-owned native restart into ordinary stateful selection. It never forwards
a Cookie-bearing request to the legacy no-Cookie guest producer and never removes
the original Cookie. Only that original site/host/URL/method can resume across the
existing adapter gateway. An unproven candidate cannot expose guest headers/body.

Native mock transport tests cover this contract and remain distinct from actual
WordPress/provider/browser acceptance with the matching producer.
