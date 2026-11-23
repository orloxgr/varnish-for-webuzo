# Private reuse finalization wire v1

Experimental shared producer/consumer grammar. This freezes content framing for
the existing authenticated delivery/finalization owner. It does not advertise
general reuse, introduce a REST route, move private bodies out of Varnish, or
claim a completed zero-PHP delivery path. The actual composed all-HIT request
must avoid every PHP/prepare/finalization call; finalization belongs only to a
real MISS/refill whose original application execution has actually drained.

## Envelope position and complete shape

The ordinary prepare retains its existing `schemaVersion:1`, `requestId`,
`originalUrl`, complete rendered fragments and existing cache/HTML fields.
The separate protocol-only finalization returns a metadata-only envelope with
exactly `schemaVersion:1`, `requestId`, `originalUrl`, and **top-level `reuse`**
whose object is shown below. It does not repeat rendered HTML. An ordinary
prepare can retain a candidate in its existing owner; candidate data cannot
install reusable admission or personal provenance.

```json
{
  "version": 1,
  "context": {
    "siteId": "<32 lowerhex>", "canonicalHost": "example.test", "scope": "/",
    "epoch": "<64 lowerhex>", "incarnation": "<64 lowerhex>",
    "scopeRevision": "<64 lowerhex>",
    "nativePolicy": "<64 lowerhex>", "wordpressPolicy": "<64 lowerhex>",
    "reusePolicy": "<64 lowerhex>", "publicationDigest": "<64 lowerhex>",
    "representation": "<64 lowerhex>", "recipeDigest": "<64 lowerhex>"
  },
  "recipe": {
    "digest": "<64 lowerhex>",
    "inputs": {"cookieNames": [], "cookiePrefixes": [], "phpMaxInputVars": 1000},
    "fragments": [
      {"descriptor": "<64 lowerhex>", "url": "/?ultracache_esi=...",
       "provider": "<actual stable provider id>", "occurrences": 1}
    ]
  },
  "admission": {
    "binding": "<64 lowerhex>", "validUntil": 1795400000,
    "cookieWork": {"state": "none", "validUntil": 1795400000},
    "fragments": [
      {
        "descriptor": "<same recipe descriptor>", "url": "/?ultracache_esi=...",
        "cache": {"key": "<existing cache.key64>", "ttl": 120, "tags": "<existing tags field>"},
        "bodyValidUntil": 1795400000,
        "identity": {
          "identityState": "personal",
          "identityInputs": {"cookieNames": [], "cookiePrefixes": [], "phpMaxInputVars": 1000},
          "identityBinding": "<64 lowerhex>", "owner": "<64 lowerhex>",
          "tags": ["<64 lowerhex>"], "validUntil": 1795400000
        },
        "authority": [
          {"tag": "<64 lowerhex>", "revision": "<64 lowerhex>", "generation": "<64 lowerhex>"}
        ]
      }
    ]
  }
}
```

All displayed numbers are illustrative, not defaults/ceilings. JSON member
ordering/valid escaping/whitespace do not affect content identity. Unknown or
duplicate fields, malformed types/UTF-8, NUL/control-bearing names and relative
URI violations reject the full extension, with no partial admission installed.
Existing ordinary delivery/fallback remains separate. The context is supplied
by accepted native ownership, never guessed from headers supplied by a browser.

`publicationDigest` is SHA-256 of the **exact signed manifest token bytes**
extracted by the existing `delivery_manifest_token`: raw query percent decoding,
literal `+` preserved. Do not base64-decode/re-encode the token or serialize its
JSON before hashing. This is the same token identity already used by the native
publication-conflict binding, not SHA-256 of the public HTML bytes.

`representation` is a native-provided opaque digest of the actually selected
parent representation. The producer echoes it; it must not derive one from
user-agent guesses, arbitrary Accept normalization or caller cookies. Actual
native Vary and selected representation still govern which parent was hit.

## Descriptor identity and canonical recipe digest

`LP(x)` is U32 big-endian byte length + exact bytes. `U64(n)` is unsigned
64-bit big-endian. The domain strings below are exact ASCII. All hashes are
SHA-256 with lowercase hexadecimal output.

```text
descriptor = SHA256(
    LP("ultracache-private-descriptor-v1") + LP(relativeURL) + LP(provider)
)
```

This intentionally binds the exact existing signed relative child URI and
provider. Cross-parent logical-descriptor reuse is not inferred from similar
paths. URI normalization/decoding/query sorting does not occur here.

Recipe input declarations use the already qualified complete sorted/deduplicated
`cookieNames`, `cookiePrefixes` and **actual** `phpMaxInputVars`. Canonical
`declarationFrame` is the existing `ultracache-cookie-inputs-v1` projection frame
with those declarations and an empty Cookie wire, hence zero matching groups.
It contains declaration metadata only, no visitor identity/cookie values.

```text
recipeFrame =
    LP("ultracache-private-recipe-v1")
    LP(declarationFrame)
    U32(numberOfDistinctDescriptors)
    for each descriptor in ascending ASCII-hex order:
        LP(descriptor) LP(relativeURL) LP(provider) U64(occurrences)
recipe.digest = SHA256(recipeFrame)
context.recipeDigest = recipe.digest
```

Every descriptor/URI is unique; counts are positive and their sum equals the
parent's actual private occurrence count. Recipe `inputs` is the complete
normalized union of the real consumed renderer/claim inputs. A missing claim,
TTL-0 provider, unsupported dependency or incomplete occurrence set cannot be
silently omitted to label a partially cached document reusable.

## Binding MACs (existing qualified domains, unchanged)

Let `reuseKey` be the raw 32-byte HMAC-SHA256 of the original accepted site
credential bytes with message ASCII `ultracache-delivery-reuse-key-v1`.
The credential is not hex decoded and is never placed in metadata.

The admission `binding` is the already qualified page-input binding:

```text
lowercase_hex(HMAC-SHA256(reuseKey,
    LP("ultracache-delivery-reuse-binding-v1")
    LP(siteId) LP(canonicalHost) LP(scope) LP(epoch)
    LP(nativePolicy) LP(wordpressPolicy) LP(reusePolicy)
    LP(publicationDigest) LP(representation) LP(recipeDigest)
    LP(actual recipe-input projection frame)
))
```

Each personal or explicit anonymous `identityBinding` uses the separate existing cross-route domain:

```text
lowercase_hex(HMAC-SHA256(reuseKey,
    LP("ultracache-private-identity-binding-v1")
    LP(siteId) LP(canonicalHost) LP(scope) LP(epoch)
    LP(nativePolicy) LP(wordpressPolicy) LP(reusePolicy)
    LP(actual identity-input projection frame)
))
```

Both frames include actual PHP parsing budget, consumed raw occurrences and
absent selectors as already specified in `PRIVATE-REUSE-INPUTS-DRAFT.md`.
The effective final cookie projection must be the one the producer actually
approved for the next request, including real provider issuance/changes.
The binding MACs are lookup/provenance bindings, not signatures granting
arbitrary owner, expiry, key or generation metadata. All those fields must
arrive together in the authenticated, current, native-owned finalization.

## Personal provenance and authority coverage

Only `identityState:"personal"` installs a revoke map. A complete recipe may
also contain an explicitly authenticated `identityState:"anonymous"` fragment,
such as an actual UID0 nonce. Its identity still has all six fields:
`identityState`, complete `identityInputs`, seven-field `identityBinding`,
`owner:null`, `tags:[]`, and the actual `validUntil`; `authority` is exactly `[]`.
The full descriptor, URL, cache claim, body deadline and occurrence coverage
remain required. Input MAC, HSH body, freshness and current scope checks apply
unchanged. An absent selector by itself never proves anonymous semantics.

This per-document anonymous fact installs no owner/tag/revoke map and grants no
known-empty or cross-route actor coverage. Personal rows retain their nonempty
owner/tag/CAS requirements. Existing separately qualified guest publication
remains the no-cookie public HTML path.

`owner` and `identity.tags` are raw64 opaque provider-validated owner identities;
the owner itself must be in the unique nonempty tag set. `validUntil` is the
actual identity/session/renewal deadline. `identityInputs` remain distinct from
renderer-only inputs. Multiple validated owners consuming the same input frame
must coexist; one provider cannot overwrite another owner's revoke provenance.
There is no hardcoded native Woo/WordPress/YITH cookie list.

For personal rows, `authority` contains one unique current native CLEAN
`{tag,revision,generation}` ACK for **every** identity tag, with no missing/extra
tag. Anonymous rows require both the identity-tag and authority sets empty. The accepted scope
must currently be READY, with matching epoch/incarnation/scope revision and
effective native/WP/reuse policies. Pending provider writers or matching native
execution fences prevent publication/admission. A clean grant must follow the
agreed fresh authoritative state read and actual original-execution drain;
neither NONE receipts nor successful final headers grant CLEAN.

## Deadlines and cookie work

Absolute `validUntil` values are positive integer Unix seconds from actual
provider/identity/nonce validity; no configured artificial TTL is introduced.
The admission deadline is no later than every required identity/body/dependency
deadline and `cookieWork.validUntil`. Existing `cache.ttl` remains the actual
positive remaining renderer descriptor TTL. Every fragment also carries its
original absolute `bodyValidUntil`; protocol delay cannot turn the retained
relative TTL into a fresh lifetime. A replay, metadata refill, cache
HIT or object pin never restarts either lifetime. Native also bounds reuse by
each private HSH object's actual original expiry and actual selected parent
freshness. Parent or one required private dependency missing/expired/busy means
the complete all-HIT path does not qualify.

`cookieWork.state:"none"` is the producer's truthful complete no-current-cookie-
work approval for this admission, valid only until its actual stated boundary.
It is retained from the original agreed reuse proposal. It is not inferred
merely from an old cache descriptor, missing Set-Cookie header or a Shared
cookie policy. Real issuance/renewal/provider work requires the ordinary
selective MISS/refill/finalization path, never cached replay of another visitor's
Set-Cookie. This version has no partial cookie-work state that grants reuse.

## Native storage and last admission barrier

Recipe and per-binding admission are typed metadata in the existing native
cache namespace/lifetime. Actual private bytes remain the existing HSH private
fragment objects. The existing registry retains only typed authority and
revoke-only identity provenance; no raw Cookie/frame values, private HTML or
alternate application body store are added there.

Before prepare, an actual parent HIT discovers its current cached recipe, derives
the binding from actual consumed inputs and resolves the cached admission.
Native pins and materializes **all** required existing HSH private objects before
headers, then rechecks current policies/scope/tag revisions+generations/deadlines
under the same barrier as mutation fencing. Missing metadata/dependency or an
uncertain identity enters ordinary selective fill. Unknown absence is not a
zero-writer grant. A full composed HIT invokes no PHP, prepare, helper, protocol
finalization, new browser Ajax or provider read.

On real MISS/refill, the existing delivery owner performs actual producer
work, then its separate authenticated protocol-only finalization after real
execution drain. That phase must not recursively get a mutation context, and
cannot change/replay the original business status/body/Set-Cookie. Publication
into native metadata cache and the final pre-header path are implementation
gates, not claims made by this grammar document.

## Active original execution: `delivery-reuse-context`

Use the existing authenticated per-site control transport, exact application
scope and the **actual signed backend context's** identities:

```text
X-UltraCache-Operation: delivery-reuse-context
X-UltraCache-Private-Request-Id: <signed backend requestId64>
X-UltraCache-Private-Challenge: <signed backend challenge64>
X-UltraCache-Private-Epoch: <signed backend epoch64>
X-UltraCache-Private-Incarnation: <signed backend incarnation64>
X-UltraCache-Delivery-Reuse-Recipe: <actual canonical proposed recipeDigest64>
```

If present, `X-UltraCache-Delivery-Request` and
`X-UltraCache-Delivery-Original-URL` must match the joined actual delivery owner.
The caller cannot select another owner via those optional fields. Native joins
the backend task's privately retained request/challenge to its own handoff key,
then finds the live delivery continuation under the existing registry lock.
An ordinary original backend with no delivery continuation can receive only an
unqualified seven-field provenance base. Ended/unknown/mismatched execution,
current-policy change, wrong epoch/incarnation or changed sealed recipe is not
accepted. The first canonical recipe proposal is retained as request-local
metadata; an identical retry is idempotent. It is not an admission installation.

The accepted JSON retains the existing native scope context and adds:

```json
{
  "requestId": "<actual signed backend requestId64>",
  "challenge": "<actual signed backend challenge64>",
  "recipeDigest": "<sealed proposed64>",
  "deliveryRequestId": "<actual opaque delivery id, only if joined>",
  "provisional": true,
  "contextState": "unqualified",
  "parentIdentitySource": "none",
  "cachedFragments": []
}
```

Cold selection has no actual selected parent yet and returns no invented
publication/representation. A hot-parent fill returns
`contextState:"parent-bound"`, `parentIdentitySource:"native-selected-parent"`
and `publicationDigest` / `representation` captured from the actual selected
native parent before prepare. Both cases remain `provisional:true`: the final
current-parent/authority comparison is still mandatory before installation.
`cachedFragments:[]` truthfully means this stage has reserved no reusable HIT
bytes; selective native reservation is a later owner integration, not a grant.

The native representation is lowercase SHA-256 over:

```text
LP("ultracache-native-representation-v1")
LP(actual selected parent native hash digest bytes)
LP(actual selected parent's packed Vary bytes, or empty)
```

The digest is captured while that actual parent object is owned by the current
native request; a later control caller does not dereference a borrowed object
pointer. Shared/irrelevant cookies do not invent another representation, while
actual native Vary remains effective. The producer echoes this opaque digest;
it does not reconstruct internal Vary bytes or infer a future representation.

While original raw input is still request-local, the producer persists
`inputEvidence`, using the existing **seven-field cross-route identity MAC
primitive over the complete recipe.inputs projection**, and the individual
identityBindings/actual claims/fingerprints. No raw Cookie/frame/HTML is written
to the execution row. A parent-bound original can additionally compute the
full ten-field page binding then. A cold candidate stays unqualified. In the
later protocol-only finalization the native owner still has its request-local
wire/effective updates, verifies retained inputEvidence and derives the actual
full binding after the parent exists; signatures alone cannot qualify stale
body/state. This late finalization API/storage step remains an integration gate.

Native publication-only recovery and prepared private virtual sources do not
execute the application and cannot recursively create mutation contexts. That
exclusion uses actual owned phases/source claims, never an incoming skip header.

## Protocol-only finalization phase/interface

This interface is frozen for parallel producer/consumer implementation; the
native phase/cache-publication state machine is not yet enabled or advertised.
It is an internal phase of the **existing delivery owner**, not a new REST route,
browser request, service or private body store. The actual origin method is GET
and the URI is the original application URI, preserving the existing delivery
semantics and early handler path. Existing generated adapter authorization is
used. The producer must recognize the authenticated phase before normal static
page delivery, canonical redirect, provider bootstrap, sessions or issuers.

```text
X-UltraCache-Delivery-Version: 1
X-UltraCache-Delivery-Phase: reuse-finalize
X-UltraCache-Delivery-Authorization: <existing per-site protocol credential>
X-UltraCache-Delivery-Request: <current native delivery id>
X-UltraCache-Delivery-Original-URL: <actual original URI>
X-UltraCache-Delivery-Public-Selection-Scope: <exact registered scope>
X-UltraCache-Delivery-Reuse-Version: 1
X-UltraCache-Delivery-Reuse-Recipe: <sealed canonical recipe64>
X-UltraCache-Private-Request-Id: <original signed backend execution64>
X-UltraCache-Private-Challenge: <original signed backend challenge64>
```

No new `X-UltraCache-Mutation-Context` is issued for this actual native-owned
phase. No raw Cookie/frame is sent to or persisted by the finalization owner.
The original execution IDs identify the retained SQL candidate; the delivery ID
identifies the still-owned native front request. They are distinct identities.
The handler proves original PHP/provider drain and settles the actual intent /
native execution records; response/header completion never substitutes for it.
It snapshots actual native revisions **before** independent committed-provider
reads, compares actual persisted fingerprints with original body/claim evidence,
then publishes exact dependency generations by revision CAS. Unchanged CLEAN
generation publication is idempotent. A changed fingerprint, pending original
execution, stale CAS or incomplete no-cookie-work closure declines this attempt.
CLI/cron/native auth writes outside the signed HTTP owner still require their
own observation/invalidation integration; hook registration alone is not proof.

On acceptance, respond 200 with:

```text
Content-Type: application/vnd.ultracache.reuse+json
Cache-Control: private, no-store
X-UltraCache-Delivery-Reuse-Outcome: finalized
X-UltraCache-Delivery-Reuse-Fresh-Remaining: <positive actual remaining seconds>
```

There must be no Set-Cookie/Set-Cookie2 or unrelated provider/bootstrap output.
`Fresh-Remaining` is the floor of the actual minimum admission/cookie-work/body /
identity/dependency deadline minus current time, not a new configured TTL. The
controlled native metadata-cache phase can cache this private namespace using
that explicit lifetime, while the origin's no-store prevents an upstream HTTP
cache from storing protocol JSON under the ordinary public URI. Body absolute
deadlines and actual HSH expiry remain mandatory checks, never reset by the
relative header. The response body is exactly:

```json
{
  "schemaVersion": 1,
  "requestId": "<current native delivery id>",
  "originalUrl": "<original URI, echoed for this owner only>",
  "reuse": {"version": 1, "context": {}, "recipe": {}, "admission": {}}
}
```

The placeholders use the full strict objects defined above. Request ID/URI bind
the first response to its owner; later native cache reads validate the reusable
inner context/publication/representation/recipe/input binding rather than
requiring another request's serial or replacing the incoming URI. They do not
rewrite browser URLs or discard tracking functionality.

On an unavailable/pending/changed candidate, respond 204, empty body,
`Cache-Control: private, no-store` and
`X-UltraCache-Delivery-Reuse-Outcome: declined`. Unexpected protocol errors also
create no admission. This is an optional cache-publication attempt: a failure
must preserve the already-produced original application body/status/Set-Cookie,
not turn a successful business action into a cache exception. Retained durable
work is reconciled from actual evidence, never silently expired.

Typed metadata is mapped into the existing native private-object namespace:

```text
metadataKey = SHA256(
    LP("ultracache-private-admission-object-v1")
    LP(siteId) LP(canonicalHost) LP(scope) LP(epoch)
    LP(nativePolicy) LP(wordpressPolicy) LP(reusePolicy)
    LP(publicationDigest) LP(representation) LP(recipeDigest) LP(binding)
)
metadataURI = "/__ultracache-native/reuse-v1/" + metadataKey
HSH parts = "ultracache-private-v1", siteId, canonicalHost, metadataURI, metadataKey
```

Use the existing engine `HSH_AddString` plus null separator convention for those
five parts, exactly as private fragment objects already do. Only an actual owned
native metadata phase can populate/read that namespace; external requests or
spoofed headers do not select it. Require the normal private-object marker and
an additional typed metadata marker, no Set-Cookie, actual freshness and full
inner context/authority/deadline validation. Registry discovery retains only
non-authoritative recipe/input declarations and revoke provenance, never HTML.
This cache-key definition freezes lookup/write agreement; actual publication
and full pre-header composed-HIT actors remain implementation gates.

## Original optional candidate and compact finalization proof

The original authenticated prepare/public-selection may add exactly this top-level
member only when native issued `X-UltraCache-Delivery-Reuse-Candidate-Version: 1`:

```json
{"reuseCandidate":{"version":1,"requestId":"<original mutation64>",
"challenge":"<original challenge64>","recipe":"<complete recipe object>",
"inputEvidence":"<seven-field full recipe-input MAC>"}}
```

`inputEvidence` covers the original incoming raw Cookie wire, before application
slashing. It does not sign an inferred future/effective cookie value. Issuance or
updates that alter consumed inputs need separate producer proof; original evidence
is never silently substituted. Candidate mismatch discards only the optional
optimization. It grants no admission or personal provenance.

The native-owned protocol-only request adds
`X-UltraCache-Delivery-Reuse-Context` containing standard base64 of JSON:

```json
{"version":1,"requestId":"<original64>","challenge":"<original64>",
"deliveryRequestId":"<native serial>","context":"<12-field context object>",
"binding":"<full page-input MAC64>","inputEvidence":"<original evidence64>",
"proof":"<lowerhex HMAC64>"}
```

The strings standing for objects above are illustrative placeholders, not wire
string types. The context has the exact 12 fields in the initial grammar order.
No raw Cookie/frame/HTML or full recipe is put in this header. `scopeRevision`
is the pre-settlement observation; final metadata uses the actual settled native
revision. Epoch/incarnation, ten binding dimensions and recipe stay unchanged.

```text
proof = lowercase_hex(HMAC-SHA256(reuseKey,
    LP("ultracache-private-finalize-context-v1") LP("GET") LP(actualOriginalURI)
    LP(requestId) LP(challenge) LP(deliveryRequestId)
    LP(siteId) LP(canonicalHost) LP(scope) LP(epoch) LP(incarnation) LP(scopeRevision)
    LP(nativePolicy) LP(wordpressPolicy) LP(reusePolicy)
    LP(publicationDigest) LP(representation) LP(recipeDigest)
    LP(binding) LP(inputEvidence)
))
```

Independent Python frame/header vectors are in
`tests/fixtures/private_reuse_finalize_v1.json`; C generates byte-identical headers.
The actual URI includes tracking/query bytes unchanged. An authenticated compact
context alone is still not a CLEAN grant or completed reusable delivery.

## Owned experimental native implementation status

The opt-in matching-engine consumer now implements the actual late finalization
phase, metadata storage in the existing HSH namespace, non-authoritative hashed
recipe discovery, input-bound metadata lookup, and all-private-object pin/copy
before the final scope/tag revision/generation barrier. Default builds and public
capability responses still do not advertise general delivery reuse.

`tests/test_reuse_full_runtime.py` qualifies this engine flow with an explicitly
MOCK trusted producer: complete composed HIT has zero origin/prepare/finalizer
calls; unrelated Shared input does not split it; a missing required private HSH
object and tag revocation both require ordinary fill. Both personal/personal
and mixed personal-cart/anonymous-nonce recipes are exercised, with complete
coverage and no fabricated anonymous revoke map. This is not evidence of
actual WordPress identity, provider persistence/drain or cookie-work closure.
Those proofs must come from the real producer before general acceptance.

Anonymous fragments may depend on mutable content. They retain `owner:null`,
but their existing `identity.tags` and matching `authority` rows may contain
content dependencies. Every listed dependency still needs exact current native
revision/generation authority, and every identity input/binding/lifetime gate
remains. Anonymous content dependencies never enter visitor identity/revoke maps.
The metadata object key uses the v2 admission namespace so pre-change admissions
cannot satisfy the new implementation's lookup. This changes no wire envelope,
control endpoint or public capability advertisement. Native mock-producer tests
cover mutable anonymous content, dirty/wrong authority, same-generation mutation
fencing, interleaved personal owners and absence of anonymous revoke-map entries;
actual application comment mutation coverage remains producer acceptance.

The original response's genuine repeated provider cookies survive an optional
finalization decline; protocol-only cookies are never replayed. Metadata failure
cannot change completed original provider work. Exactly two added, owned restart
transitions preserve the original request's recovery headroom; they add no global
request timeout or application lifetime cap.

`cookieWork.none` covers lifecycle work REQUIRED by the actual cached document /
recipe and its providers, with their real renewal/expiry bounds. It is not a
blanket prohibition of unrelated Shared tracking issuers. Native does not infer
none from missing Set-Cookie, synthesize an issuer value or silently substitute
an effective consumed-cookie projection for the original evidence.

Generic revoke-only personal maps are now installed only after full accepted
finalization. They retain declaration schemas, seven-field identity MACs, opaque
owner/tag identities and actual identity-validity boundaries, never raw Cookie,
frames or bodies. Multiple owners sharing one input binding coexist. A matching
later backend prearms those exact tag revisions before application dispatch;
original execution fences remain until explicit actual-drain retirement. Response
headers, receipts or native task fini cannot retire them. Tag publication/retire
checks those fences too. Unknown execution still invalidates only its own scope;
a positive mapping or Shared policy cannot infer known-empty/full arbitrary
cross-route actor coverage. Actual external mutation/content invalidation coverage
and producer application acceptance remain separate gates.

Finalized metadata is bounded by the minimum of its provided freshness, the
actual original native body grants and the public parent. The admission keeps
the provider's natural body/identity/cookie deadlines as upper bounds and only
shortens effective deadlines; it never estimates clock skew, adds tolerance or
restarts a body TTL. Exact original body keys/tags, current scope/dependencies,
input bindings and all-object/final revision barriers remain mandatory. The
existing HSH metadata object carries this capped lifetime; future reads also
bound the parsed record by that object's actual expiry. No pending object,
post-delivery hook or second PHP approval is added. Tests use a deliberately
later absolute provider deadline, prove first-fill origin-free reuse, verify
native expiry still requires fresh work and reject changed keys/tags or already
expired natural evidence.
