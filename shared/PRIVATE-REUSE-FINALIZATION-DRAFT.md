# Private reuse finalization wire v1

Experimental shared producer/consumer grammar. This freezes content framing for
the existing authenticated delivery/finalization owner. It does not advertise
general reuse, introduce a REST route, move private bodies out of Varnish, or
claim a completed zero-PHP delivery path. The actual composed all-HIT request
must avoid every PHP/prepare/finalization call; finalization belongs only to a
real MISS/refill whose original application execution has actually drained.

## Envelope position and complete shape

Retain the existing delivery envelope `schemaVersion:1`, `requestId`,
`originalUrl`, complete rendered fragments and existing cache/HTML fields. Add
optional **top-level `reuse`** only on the negotiated authenticated finalization
response. An ordinary prepare can retain a candidate in its existing owner;
candidate data cannot install reusable admission or personal provenance.

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

Each personal `identityBinding` uses the separate existing cross-route domain:

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

Only `identityState:"personal"` installs a map in this initial version. No
UID0/no-session, absent-selector, missing-identity or Shared-action inference
creates an anonymous/known-empty map. Existing separately qualified guest
publication remains the no-cookie public HTML path.

`owner` and `identity.tags` are raw64 opaque provider-validated owner identities;
the owner itself must be in the unique nonempty tag set. `validUntil` is the
actual identity/session/renewal deadline. `identityInputs` remain distinct from
renderer-only inputs. Multiple validated owners consuming the same input frame
must coexist; one provider cannot overwrite another owner's revoke provenance.
There is no hardcoded native Woo/WordPress/YITH cookie list.

`authority` contains one unique current native CLEAN `{tag,revision,generation}`
ACK for **every** identity tag, with no missing/extra tag. The accepted scope
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
