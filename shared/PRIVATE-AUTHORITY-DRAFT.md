# Private authority control candidate

Executable experimental metadata stage. General cached-delivery reuse remains
OFF: no recipe/admission discovery, zero-prepare capability or backend receipt
transport is advertised by this stage. Native HTTP actors use a mock producer's
durable-state attestations; they are not real database persistence proof.

## Registration and existing authentication

Use the existing local/site-token authenticated
`PURGE /__ultracache-vcl-contract-v2`, `X-UltraCache-Contract: 2`. The adapter
assigns the immutable native site id and authenticates the token before the
common control function. Basic cannot register the experimental authority.

In the existing `capabilities` registration, after normal public-selection scope
registration, include:

```
X-UltraCache-Public-Selection-Reuse-Version: 1
X-UltraCache-Public-Selection-Reuse-Policy: <64 lowercase hex>
```

The exact application scope is the existing
`X-UltraCache-Public-Selection-Scope`, with trailing slash. The native policy
comes from compiled effective cookie rules, not a supplied policy header.
Registration must match the accepted WordPress policy for that exact scope.

Only an explicitly enabled matching-engine experimental DSO advertises
`X-UltraCache-VCL-Private-Authority-Version: 1`. This is NOT
`X-UltraCache-VCL-Delivery-Reuse-Version`. Production/default builds do not
enable authority registration or general reuse.

New scope metadata has an opaque incarnation and scope revision and starts
UNBOUND. Repeated identical registration preserves metadata. Policy changes and
disable/enable transitions revoke readiness without discarding outstanding
writers. A new native registry epoch starts with no clean authority. Context
creation never treats missing metadata as a zero-writer clean grant.

## Common headers and responses

All operations use `X-UltraCache-Operation` and the exact registered
`X-UltraCache-Public-Selection-Scope`. Context discovery is authenticated and
does not require a previously known incarnation. Mutating operations require:

```
X-UltraCache-Private-Epoch: <native epoch64>
X-UltraCache-Private-Incarnation: <scope incarnation64>
```

Replies have HTTP 200 on acceptance, 400 for malformed schema, 409 for stale or
unavailable authority, and 503 for native allocation/identity failure. The JSON
body is request-owned and emitted without a product response-size cap:

```json
{
  "schemaVersion": 1,
  "accepted": true,
  "reason": "observed",
  "epoch": "<64>",
  "siteId": "<adapter owned>",
  "canonicalHost": "<accepted host>",
  "scope": "/shop/",
  "incarnation": "<64>",
  "scopeRevision": "<64>",
  "scopeState": "unbound",
  "nativePolicy": "<64>",
  "wordpressPolicy": "<64>",
  "reusePolicy": "<64>",
  "tag": "<64>",
  "revision": "<tag revision64>",
  "state": "unbound",
  "remainingMutations": 0
}
```

Tag fields are omitted for a scope-only context. A currently valid clean tag
also has `generation`. A transaction reply adds `transaction`, `lease`, `active`
and, after commit, `committedRevision`. `scopeState` and tag state are separate:
neither tag bytes nor a stored generation can authorize reuse under an UNBOUND
scope. Error replies use accepted:false and a fixed machine-readable reason.
All operation bodies are JSON/private/no-store and contain no cookie values.

## Literal operations

### `private-authority-context`

Optional `X-UltraCache-Private-Tag: <raw64>`. Observes current scope; when a tag
is supplied and missing it creates only a fresh UNBOUND slot and opaque revision.
Repeated observation does not rotate revision or make any state CLEAN.

### `private-authority-recover`

```
X-UltraCache-Private-Scope-Revision: <observed scopeRevision>
X-UltraCache-Private-Drained: 1
```

Explicit authenticated producer assertion AFTER durable-intent and actual
execution/drain proof. Native refuses active transactions and stale scope
revision. It makes the scope ready while old tag generations remain UNBOUND;
it does not resurrect cached authority. An already-ready matching recovery
retry is idempotent. Real proof belongs to the producer; this header is not a
native observation of SQL. Uncertain backend execution markers/receipt recovery
will additionally gate this operation when that next stage is wired.

### `private-mutation-begin`

```
X-UltraCache-Private-Tag: <raw64>
X-UltraCache-Private-Transaction: <producer random64 idempotency id>
X-UltraCache-Private-Expected-Revision: <observed tag revision64>
```

Creates an outstanding native lease, rotates the tag revision and revokes that
tag before ACK. Same transaction retries return the existing active/completed
record and never reopen a completed writer. Multiple writers remain distinct.
Reply includes native `lease`; no producer generation is installed.
For a new transaction, expected revision must match the observed tag. This
prevents a delayed old begin from reopening a writer after explicit ACK metadata
cleanup. On 409, a producer may reobserve/retry its durable intent; this cache
notification failure does not itself cancel the application mutation.

### `private-mutation-commit`

Same tag/transaction plus `X-UltraCache-Private-Lease: <native lease64>`.
Closes only its own active lease and leaves the tag UNBOUND until a separate
fresh publication. Other outstanding writers remain dirty. A delayed completed
commit retry neither rotates a newer revision nor revokes a newer clean
generation. Unknown lease is 409, never inferred success.

### `private-generation-publish`

```
X-UltraCache-Private-Tag: <raw64>
X-UltraCache-Private-Scope-Revision: <observed scopeRevision>
X-UltraCache-Private-Expected-Revision: <observed tag revision>
X-UltraCache-Private-Generation: <actual producer generation64>
```

Required sequence: observe native epoch/incarnation/scope/tag revisions, THEN
check durable intents and read fresh authoritative provider state, THEN publish
CAS of exactly those observed revisions. Native requires ready scope, no active
tag writers and matching revisions. A stale sequence retries all steps, never
attaches an old state read to a newer revision. Only this explicit operation
grants a tag generation; ordinary fills/context/fragment lookup never do.
Generations describe actual provider dependencies/tags, not fragment cache keys
or aggregate recipe keys. Two different fragment bodies may share an owner tag.
After all scope/active-writer/current-revision checks, publishing the identical
already-CLEAN generation preserves its existing revision. Different generations,
UNBOUND/post-write publication and stale CAS retain the normal fencing checks;
same-generation requests never bypass an outstanding writer or stale revision.

### `private-mutation-ack`

Same completed tag/transaction/lease. The producer calls this only AFTER its
native ACK has been durably recorded in the existing SQL outbox owner. It
rotates the tag CAS revision before removing completed receipt metadata, without
an arbitrary timeout. Current clean state/content generation remain intact. This
also fences a completed-begin retry reobserved after a newer publication; delayed
replay cannot reopen the writer after its record is gone. Active records
cannot be discarded. The backend receipt stage must additionally defer removal
while a native execution can still return the same transaction receipt; it is
not yet wired here. Unknown old commit remains non-authoritative after cleanup.

### `private-tag-retire`

Tag plus `X-UltraCache-Private-Expected-Revision`. Refuses stale revision or
unacknowledged transaction records. Removes this explicit authority slot;
subsequent context creates a different UNBOUND revision. It does not delete
public parents or assume that a body cache eviction authorizes reuse.

## Qualification

Seven actual native HTTP actors passed through the real adapter control gate:
UNBOUND-only observation, explicit recovery/fresh publish, overlapping writers,
stale publication and delayed/duplicate commit, ACK/tag retirement, scope
isolation/bad token, restart epoch, no old tag resurrection after scope
recovery, and WordPress-policy replacement without forgetting an old writer.
These are transport/CAS/lifecycle tests with synthetic tags and mock
producer attestations. SQL persistence/drain, owned response receipts, targeted
pre-dispatch identity fences and complete cached-delivery admission remain
separate integration gates.
