# Experimental request-bound mutation wire, version 1

This codec is not backend execution ownership or delivery admission. It is
unhooked: no mutation capability is advertised, no site settings or installed
services change, and general private-fragment reuse remains off. Application
status, body and Set-Cookie must survive any cache-transport failure unchanged.

The native owner issues a context for one actual application execution; the
application may return a **revoke-only** receipt. No receipt grants CLEAN,
generation publication, completed persistence or execution drain. A response
header may precede a later provider write. The durable intent remains pending
until its actual persistence, native ACK and execution/recovery proof qualify.

## Context: native to application

Header name: `X-UltraCache-Mutation-Context`. Its value is standard padded
base64 of UTF-8 JSON with exactly these fields:

```json
{
  "schemaVersion": 1,
  "siteId": "<32 lowercase hex>",
  "canonicalHost": "<accepted native canonical host>",
  "scopeDigest": "<64 lowercase hex>",
  "epoch": "<64 lowercase hex>",
  "incarnation": "<64 lowercase hex>",
  "nativePolicy": "<64 lowercase hex>",
  "wordpressPolicy": "<64 lowercase hex>",
  "reusePolicy": "<64 lowercase hex>",
  "requestId": "<64 lowercase hex>",
  "challenge": "<64 lowercase hex>",
  "proof": "<64 lowercase hex>"
}
```

`requestId` and `challenge` are **two independent native-generated random
32-byte values**, lowercase hex encoded. They are never serial counters, browser
input, transaction IDs, or stable identity bindings. Their lifetime is the owned
backend execution. `scopeDigest` is SHA-256 of the exact accepted application
scope bytes (including slash boundaries); it is not a guessed document root.
The remaining metadata comes from the accepted native registry and immutable
backend site binding. No raw cookies, URL, or site secret is copied into JSON.

The application validates schema, lexical shapes, its accepted connection's
site/host/scope, negotiated policy/epoch/incarnation and the HMAC proof. Its
actual request method and actual original URI must be the same bytes the
native owner signed for that application execution. Do not use a normalized
cache-key URI or reconstruct query parameters. No method-case conversion,
percent decoding, query sorting or tracking removal occurs. URI is a nonempty
origin-form string starting `/`, with no control/space/DEL or fragment `#`;
method is a nonempty HTTP token. Existing panel/native host validation remains
the authority; the codec only checks it is nonempty and has no control/space/DEL.

`LP(x)` is a U32 big-endian **byte** length followed by the exact bytes of `x`.
The secret is used as its original accepted bytes, without hex decoding.

```text
key = HMAC-SHA256(siteSecret, ASCII("ultracache-mutation-key-v1"))  # raw 32 bytes
requestFrame =
    LP("ultracache-mutation-request-v1")
    LP(siteId) LP(canonicalHost) LP(scopeDigest) LP(epoch) LP(incarnation)
    LP(nativePolicy) LP(wordpressPolicy) LP(reusePolicy)
    LP(requestId) LP(challenge) LP(actualMethod) LP(actualOriginalURI)
proof = lowercase_hex(HMAC-SHA256(key, requestFrame))
```

Native strips browser-supplied context/receipt headers before generating its
own. A producer must not treat an unsigned/request-mismatched context as an
invalidation success. Native must retain the owner and expected proof privately;
an echoed proof alone is not authenticated backend ownership.

## Receipt: application to native owner

Header name: `X-UltraCache-Mutation-Receipt`, standard padded base64 UTF-8 JSON:

```json
{
  "schemaVersion": 1,
  "state": "dirty",
  "transactions": [{"tag": "<64 lowercase hex>", "transaction": "<64 lowercase hex>"}],
  "mac": "<64 lowercase hex>"
}
```

Exactly these four fields are accepted. Pair objects have exactly `tag` and
`transaction`. JSON member order/whitespace/valid escapes are irrelevant;
duplicate or unknown fields, noncanonical schema numbers, malformed UTF-8,
noncanonical base64 and duplicate pairs are rejected. `schemaVersion` is the
integer 1, not boolean, string, decimal or exponent notation. No receipt count
or output-byte product cap is introduced; normal allocator, U32 framing and
actual engine header capacity still apply.

Three states exist:

* `none`: empty transaction list; this execution reports no observed mutation.
  It is **not** permission to reuse, recover a scope, erase pending intents or
  publish a generation. Unknown observers/provenance must not manufacture it.
* `dirty`: nonempty list of actual durable intent `(tag, transaction)` pairs.
  These revoke/keep dirty. They do not mean persistence or execution completed.
* `scope`: empty list; unknown mutation provenance requires own-scope UNBOUND.
  It does not affect other registered sites/scopes.

```text
orderedPairs = byte_sort_unique(pairs, primary=tag, secondary=transaction)
responseFrame =
    LP("ultracache-mutation-response-v1") LP(requestProof) LP(state)
    U32(numberOfPairs)
    for each pair: LP(tag) LP(transaction)
mac = lowercase_hex(HMAC-SHA256(key, responseFrame))
```

The 64-character request proof is framed as ASCII hex, not decoded binary.
Pairs are MACed in byte order regardless of received list order; identical
tags with different transaction IDs are valid overlapping writers. Native
compares the MAC without an early-exit byte comparison, against its privately
retained context proof. Replaying a receipt under another request ID,
challenge, method, URI, site, scope, epoch or policy fails verification.
The same-owner duplicate receipt needs idempotent lifecycle handling; this
codec alone is not a replay ledger.

## Integration gates still open

Trusted identity-input to tag mapping, targeted pre-dispatch fencing, actual
producer/native cross-layer actors, unknown-execution drain/recovery and final
admission are separate work.
Invalid/missing expected receipt or backend/client loss must revoke the owned
authority without cancelling the application write or changing its response.
No time-based implicit CLEAN or synchronous-success claim on failed transport.

## Reproducible vectors and checks

`tests/fixtures/private_mutation_wire_v1.json` contains four wholly synthetic
contexts: dirty POST, multiple tags/writers under a subdirectory, observed-none
GET and unknown-scope POST. It includes raw LP frame hex, key hex, request proof,
both JSON/base64 headers and response MAC. The independent Python `hashlib` /
`hmac` oracle in `tests/test_mutation_wire.py` checks the portable C codec using
the standard library, not its C framing or MAC helpers.

Thirteen local portable C actor tests passed without skips: independent vectors,
all context dimensions and cross-request replay, strict schema/duplicate fields,
unique sorted pairs, NONE/SCOPE/DIRTY constraints, large receipt handling and
input corruption. Native authority ACK-GC has separate real-daemon tests. These
results do not claim real provider drain, owned backend integration or the
complete zero-PHP cached-delivery path.

## Isolated native backend ownership stage

`mutation_backend.c` extends the existing backend `PRIV_TASK` and registry
lifetime. **Production VCL does not call these functions** and no mutation
capability is advertised. Only the isolated `test_mutation_backend.py` VCL
transform invokes them. Participating scope registration and the matching-source
experimental native build are both required.

`mutation_backend_start` strips incoming context/receipt fields and resolves the
accepted immutable site, host, longest registered application boundary and
native/WP/reuse policies. It allocates two independent random request IDs and
signs the actual backend method/URI. The site credential comes from generated
adapter-owned VCL and is removed before the origin request. The new header is
heap-owned by that existing backend task, with native header-capacity checks;
no workspace-allocation failure or cache RPC error turns into an application
exception. Temporary key/header buffers are released/cleared by the owner.

Until authenticated personal identity maps are installed, this isolated actor
explicitly has **unknown provenance**, so it unbinds only its own scope before
dispatch. It does not pretend to be the final known-owner path. Healthy known
owners will use targeted tag fences, not this emergency scope path. No anonymous
or known-empty map is inferred from absent input selectors.

`mutation_backend_response` verifies only the privately retained current request
proof, checks the registry context again, applies DIRTY pairs idempotently under
the existing lock, and strips both transport fields before cache/browser headers.
It never closes a writer, publishes a generation or changes application status,
body, Set-Cookie, streaming or checkout behavior. Completed transaction receipts
do not reopen the writer. The native ACK operation now returns 409
`receipt-outstanding` while any owned backend in that scope could still return
a receipt: its completed idempotency record remains intact even if the original
begin RPC outcome was unknown. This defers metadata GC, not current content
generation or business writes.

Missing/invalid expected receipt, stale context, backend error or unresolved
backend-task finalization retains an own-scope unknown-execution marker. A native
task ending does not prove PHP/provider writes ended. Control responses with such
metadata include:

```json
{"unsettledExecutions":[{"requestId":"<64hex>","challenge":"<64hex>",
  "live":false,"awaitingReceipt":false,"unknown":true}]}
```

If creating the owned context itself failed, `lostExecutionContext:true` is
reported instead. Existing scopes without executions retain the prior JSON
shape. `private-authority-recover` rejects `execution-unsettled` while these
markers exist, including when a caller merely sends `Private-Drained: 1`.
The actual-drain operation described below is experimental. The complete
actual-producer integration, targeted prearm and reusable admission are still
open, so this stage cannot be enabled in production. There is no expiry,
implicit cleanup-to-CLEAN or guessed process-death shortcut.

Five actual native HTTP actors passed: signed POST preserving a 201/body and
two real Set-Cookie fields; cross-request receipt replay preserving the actual
202/body/cookie; missing receipt isolating `/shop/` from clean `/blog/`; ACK-GC
deferral while a completed transaction's receipt is delayed; and backend loss
retaining an unknown execution with recovery refused. The full qualification
also reran existing authority, portable input/identity/receipt and explicit
engine-receipt tests. No real SQL/provider drain or cached-body admission is
inferred from these mock-producer HTTP actors.

## `private-execution-drained`: exact ended-execution retirement

This eighth literal control operation uses the same authenticated per-site
PURGE `/__ultracache-vcl-contract-v2` transport. In addition to the existing
accepted application scope and exact observed epoch/incarnation, send:

```text
X-UltraCache-Operation: private-execution-drained
X-UltraCache-Private-Scope-Revision: <current observed scopeRevision>
X-UltraCache-Private-Request-Id: <exact native requestId64>
X-UltraCache-Private-Challenge: <exact native challenge64>
X-UltraCache-Private-Drained: 1
```

The authenticated producer must first obtain independent actual PHP/runtime
and actual provider-connection drain proof for **that requestId/challenge**.
Every authentic execution, including NONE and unavailable-provider/RPC cases,
is producer-owned durable work, separate from provider DIRTY transactions.
Response headers, `_dirty=false`, socket closure, native task end, a successful
status, or a timeout are not that proof. Native checks the exact marker, current
scope revision and that its backend task is nonlive and no longer awaiting a
receipt; the trusted producer attests the independent application drain.

On success the response is accepted JSON with `reason: "execution-drained"`,
echoed `requestId` and `challenge`, normal accepted native context and any
remaining `unsettledExecutions`. Only the exact matching marker is removed.
This operation never sets scope READY, makes a tag CLEAN, closes a provider
transaction, clears `lostExecutionContext`, or removes another scope's marker.
The existing explicit authority-recover and fresh generation-publish gates
remain separate. Scope revision does not rotate merely for marker removal.

Malformed/missing lexical fields or `Drained != 1` return 400. Stale scope
revision returns 409 `scope-revision-changed`; unknown request returns 409
`execution-unavailable`; wrong challenge returns 409
`execution-challenge-changed`; a live/awaiting backend returns 409
`execution-active`. A repeated retirement of an already removed ID is unknown,
with no effect on another owner. After an uncertain ACK the producer can
reobserve that exact marker's absence; no implicit CLEAN follows either way.

Backend-task finalization sets `live=false` and `awaitingReceipt=false` because
that native owner can no longer return a receipt. Its `unknown=true` marker
remains until the independent attestation above. Thus backend loss remains
recoverable after real drain, without equating backend end with application
completion or retaining impossible future receipt permission indefinitely.

The protocol-only finalization phase is separate from the original business
execution. It must not recursively create another mutation context. Current
real-origin fixture hooks only its exact owned Woo actor route; the eventual
general integration must distinguish a genuinely native-owned finalization
phase, never a browser-supplied skip header.
