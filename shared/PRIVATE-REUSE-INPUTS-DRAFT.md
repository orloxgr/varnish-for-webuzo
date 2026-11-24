# Reusable delivery input framing v1 candidate

This is deterministic input/metadata parsing and MAC construction, not an
admission, generation authority or enabled fast path. No generated VCL calls
these functions and no producer capability is advertised by this stage.

## Complete declarations and PHP projection

`recipe.inputs` has two required arrays, `cookieNames` and `cookiePrefixes`,
plus required `phpMaxInputVars`, the nonnegative U32 actual effective PHP
runtime setting. There is no guessed PHP default or addon quota. Declarations
include names currently absent and prefixes currently matching nothing.
Selectors are nonempty cookie tokens, byte-sorted and
deduplicated within each array. Unknown/duplicate JSON fields are rejected.
This is a declaration of consumed inputs, not an observed-name inventory.

The lexical parser splits on semicolons, strips leading ASCII spaces/HTAB from each
pair, splits at the first equals sign and preserves raw name/value bytes and
every matching occurrence. Names are not percent-decoded. Values are not
percent-decoded or form-plus-decoded by the projection; the binding covers the
wire input from which the application obtains its native values.

For matching only, declaration dots become underscores. A wire name's prefix
before the first `[` is normalized with dot/space to underscore, matching the
qualified PHP flat-key projection. Every matching wire occurrence is included.
A matching bare name or non-token name, including arrays/brackets or space
aliases, reports `DELIVERY_REUSE_INPUT_AMBIGUOUS`. The application request can
continue through ordinary preparation. This result does not change the existing
Shared/Variant/Private decision. Invalid HTTP control bytes similarly leave the
projection unqualified rather than creating a new cookie policy.

Before discarding an array-like wire name as unrelated, the parser also checks
PHP's unmatched-first-bracket fallback. For example `auth[session` can become
the flat PHP key `auth_session`. If that fallback matches a declared name or
prefix, the input is ambiguous and uses ordinary prepare. Unrelated malformed
names remain outside the binding. This closes a separate coverage gap found
during independent review; it is not covered merely by the original dot-alias
vectors. The PHP variable-registration source explains this fallback:
https://raw.githubusercontent.com/php/php-src/PHP-8.3/main/php_variables.c

Groups are byte-sorted by normalized PHP name. Occurrences inside each group
retain their original wire order, binding native duplicate/alias precedence.
Unrelated inputs and the relative order of different groups do not split the
binding. An absent prefix which later gains a matching input changes the frame.
Empty value remains distinguishable from absence.

## Binary frame

`LP(x)` is U32 big-endian byte length followed by exact bytes. Counts are U32
big-endian. These are the representation's encoding bounds, not addon request
or lifetime limits. Allocation and arithmetic overflow fail without truncation.

```
LP("ultracache-cookie-inputs-v1")
U32(actual phpMaxInputVars)
U32(cookieNames count), LP(each complete declared name)
U32(cookiePrefixes count), LP(each complete declared prefix)
U32(group count)
for each normalized PHP-name group:
    LP(normalized name), U32(occurrence count)
    for each occurrence in original order:
        LP(raw wire name), LP(raw wire value)
```

No matches still encodes the complete declarations and zero groups.

PHP's actual Cookie parsing token count runs before input selection. Empty,
whitespace-only and empty-name pairs do not consume a token; unrelated and bare
tokens do. A declared consumed input after the actual runtime budget reports
`DELIVERY_REUSE_INPUT_RUNTIME`, using ordinary prepare rather than a reusable
admission. Unrelated tail tokens after an already consumed input do not change
its binding or cause a blanket block. No PHP/server setting is changed.

## Binding MAC and accepted context

Derived key is the raw 32 bytes of
`HMAC-SHA256(siteSecret, ASCII "ultracache-delivery-reuse-key-v1")`.
The lowercase-hex binding is HMAC-SHA256 with that key over:

```
LP("ultracache-delivery-reuse-binding-v2")
LP(siteId), LP(canonicalHost), LP(scope), LP(epoch)
LP(nativePolicy), LP(wordpressPolicy), LP(reusePolicy)
LP(representation), LP(recipeDigest)
LP(binary projection frame)
```

All nine context values must come from authenticated accepted native state.
The framing function preserves them exactly; it neither normalizes them nor
turns caller-supplied values into authority. The producer receives the actual
adapter-owned siteId through the future authenticated reuse context, rather than
guessing it. The MAC selects a previously authorized input admission; the MAC
alone never proves application identity, provider freshness or no cookie work.

Existing purpose-separated portable HMAC code is reused; no new crypto ABI or
browser credential is introduced. Temporary derived key/message buffers are
cleared when this helper releases them. Cookie values remain request-local and
are not logged or stored in public recipe metadata.

Public generation is a publication/fill identity, not a private fragment
lifetime. Rebuilding it does not change this MAC. Exact recipe, representation,
owner inputs, policy, tag revisions and expiry remain required. Original
producer/finalization proofs continue to bind their selected publication.

## Strict recipe metadata stage

The separate draft recipe parser accepts exactly `digest`, `inputs`, `fragments`.
Each fragment has exactly `descriptor` (lowercase SHA-256-shaped identity),
`url` (literal relative URI), `provider` and positive `occurrences`. Descriptor
and URI duplicates are rejected and the occurrence sum must equal the native
parent's supplied expected count. Malformed/unknown/duplicate fields reject the
whole recipe, without partial output.

`digest` now has the checked canonical descriptor/recipe framing frozen in
`PRIVATE-REUSE-FINALIZATION-DRAFT.md`. The parser recomputes every exact-URI /
provider descriptor and the complete order-independent recipe digest. Four
independent synthetic Python/C recipe vectors qualify that framing. Authenticated
metadata cache publication, pre-prepare discovery and admission remain separate
integration gates; a valid digest alone grants no authority.

## Executed parity scope

`tests/fixtures/private_reuse_cookie_inputs_v1.json` contains only synthetic
inputs from an actual PHP-FPM 8.3.37 parser plus production projection/binding
helper run. All 29 cases match in native C: exact binary frame for qualified
cases, actual PHP MACs, and the same ambiguous-input eligibility result for the
negative cases, including consumed input beyond the actual parsing budget.
Independent Python HMAC agrees as well. The earlier 21-case pre-budget frame is
historical development evidence, not the current wire contract.

Additional portable checks cover every accepted-context dimension and secret,
strict declaration and recipe metadata schemas, occurrence coverage, forbidden
controls and randomized unrelated-input/prefix order. These qualify byte
agreement only. Real application claims, cached authorization, mutation barriers,
restart recovery and zero-application delivery remain separate open gates.

The negotiated recipe must carry the producer's actual effective runtime
metadata and its accepted policy identity. The primitive does not obtain or
advertise those values itself, publish a cache admission, or replace producer
identity/state validation. A matching frame/MAC alone cannot authorize reuse.

The producer combines renderer declarations with the inputs actually consumed
by identity/cache-claim validation, including absent inputs. For example, a
provider may depend on an authentication cookie even when its old rendering
transport used only a session prefix. Those provider-specific declarations stay
in the application owner. The native implementation remains generic and does
not insert a cookie-name override or alter terminal Private choices.

## Separate identity binding for revoke-only owner provenance

Provider-validated `identityInputs` use the **same complete declaration and
actual PHP-budget projection framing** as above, independently from renderer
inputs. The raw32 key remains `ultracache-delivery-reuse-key-v1` derived from
the original accepted site-secret bytes. The identity MAC message is exactly:

```
LP("ultracache-private-identity-binding-v1")
LP(siteId), LP(canonicalHost), LP(scope), LP(epoch)
LP(nativePolicy), LP(wordpressPolicy), LP(reusePolicy)
LP(binary identity projection frame)
```

The scope is the exact accepted **raw scope**, not its SHA digest. The last three
page-admission dimensions (`publicationDigest`, `representation`, `recipeDigest`)
are absent. Method/URL are absent too, so a validated identity binding can select
its revoke-only owner mapping on a different ordinary POST route. No raw cookie
value becomes a global mapping key or public metadata field.

`delivery_reuse_identity_binding` implements this portable MAC. Its context
struct shares the existing ten fields, but only the first seven are read or
required. It does not validate provider identity, install a mapping or grant
cached private delivery. Identity input declarations and `identityBinding`,
`owner64`, complete raw64 tags and the actual provider `validUntil` must be
received together through authenticated admission, never client headers. The
binding alone does not authenticate arbitrary owner/tag/deadline metadata.

The intended native map is existing-registry-owned provenance for revocation,
not a second private-body cache. Scope/policy/incarnation resets withdraw those
entries. Unknown/ambiguous/expired identity provenance does not become a known
empty owner set. UID0/no-session has no personal owner inferred merely from
absent selectors; any explicit anonymous attestation remains a producer/schema
integration decision. Provider names and cookie selectors stay application-owned.

`tests/fixtures/private_identity_binding_v1.json` provides 23 independent Python
HMAC vectors over previously qualified actual PHP projection frames, explicitly
labelled as **not yet actual PHP identity-MAC output**. Native C matches the exact
frames/MACs; all seven context dimensions and identity changes alter the MAC,
while page-admission dimensions do not. The current portable input suite passes
39 tests without skips. Authenticated serialization, actual PHP identity-MAC
parity, mapping installation and targeted pre-dispatch use remain separate gates.
