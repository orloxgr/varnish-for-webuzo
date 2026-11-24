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
revision. It preserves the already-fenced current namespace revision and makes
the scope ready while old tag generations remain UNBOUND;
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
An originating V2 backend may also send the existing
`X-UltraCache-Private-Request-Id` and `X-UltraCache-Private-Challenge` fields.
Both must identify the exact current live execution awaiting its receipt. A new
transaction retains that immutable receipt owner; the reply echoes top-level
`requestId` and `challenge`. Retries cannot replace that owner. CLI/recovery
calls without an execution retain the unbound transaction and its conservative
receipt guard; they do not invent an owner or retroactively bind an old record.
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
cannot be discarded. A bound transaction defers removal while its exact origin
can still return a receipt, or a pending legacy receipt cannot be excluded.
Unrelated V2 executions do not defer its GC: V2 DIRTY requires an existing
transaction and cannot recreate a discarded pair. Unbound transactions retain
the scope-wide receipt guard. Neither GC nor receipt verification attests PHP/SQL
drain or grants namespace readiness. Unknown old commit remains
non-authoritative after cleanup.

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


## Scope-wide writer fencing for unknown owners (experimental implementation)

This additive extension uses the existing opt-in experimental authority owner.
Default builds do not enable it. The pinned mixed-delivery fixture `2b85cc2`
remains unchanged and predates these operations. Positive delivery qualification
alone does not cover unsigned writers or control-channel outages.

### Existing signed HTTP coverage and the separate CLI gap

When the actual `mutation_backend_start` hook participates in the currently
registered application scope, it unbinds that scope under the registry lock
BEFORE backend dispatch. It retains the real execution/challenge and, where
available, prearms validated personal tags. Missing identity, response loss,
invalid receipt or failure of a later PHP control call cannot restore readiness.
Native task/response completion does not prove application drain. Recovery
requires the independently attested exact execution drain and durable producer
state. This coverage requires the actual hook on the real dispatch path; a
client-supplied signed-looking header is not a substitute. It covers this
native consumer/scope, not other consumers or bypassing application entry points.

An unsigned CLI/cron/direct provider execution has no such native dispatch
owner. `before('',0)` local uncertainty does not revoke an existing native tag.
A database journal row alone is not visible to a zero-PHP native HIT. An unknown
owner must therefore fence the REAL registered scope, without inventing an
owner, cookie tag, empty identity or CLEAN state.

### Existing control owner, typed scope transactions

Use the same authenticated `PURGE /__ultracache-vcl-contract-v2`, scope registry,
lock, epoch/incarnation checks, producer durable journal and transaction/lease
lifecycle. Add a scope-owned transaction list to the existing `reuse_scope`;
reuse transaction machinery instead of creating a second authority/datastore.
Literal operations:

* `private-scope-mutation-begin`: exact registered scope, epoch/incarnation,
  `X-UltraCache-Private-Scope-Revision`, and producer random64
  `X-UltraCache-Private-Transaction`. No `Private-Tag` is accepted. On a NEW
  transaction, CAS the observed scope revision, retain its active lease and
  unbind/rotate the scope revision BEFORE ACK. All old personal authority
  bindings and admission records fail their current-scope checks immediately.
  Allocate transaction/lease first, or leave the scope UNBOUND on failure;
  allocation failure never returns a positive fence acknowledgement.
* `private-scope-mutation-commit`: same exact epoch/incarnation, transaction
  and native lease, plus explicit `Private-Drained: 1` attesting independently
  established actual writer/provider drain. Close ONLY this scope writer,
  rotate scope revision and leave it UNBOUND. Do not require the begin-time
  scope revision: another overlapping scope writer may legitimately rotate it.
  No owner generation, READY state or reusable body is granted.
* `private-scope-mutation-ack`: same completed transaction/native lease, only
  after its native commit acknowledgement is durably recorded by the existing
  producer journal. Refuse active records. Rotate the scope CAS revision BEFORE
  collecting the completed idempotency record. This fences delayed begin
  frames, including ones observed before collection. Producer journal terminal
  state forbids reobserving/reopening an already-ACKed old transaction ID.

Begin retries for a retained active/completed transaction return that record
without reopening it. Duplicate completed commit does not revoke a newer state.
Each writer has its own lease; one writer cannot retire another. All three
operations reject tag headers, stale epoch/incarnation, foreign scope and wrong
lease. Same-site sibling/nested application scopes remain distinct. Scope-only
context includes the typed outstanding scope writers so recovery cannot confuse
them with personal tags or native backend executions. The authenticated context
always contains `scopeMutations:[]` or the actual retained records:
`{transaction,lease,active,committedRevision?}`. A top-level scope transaction reply
also contains `transactionKind:"scope"`. Accepted operation reasons are
`scope-mutation-recorded`, `scope-mutation-committed` and
`scope-mutation-acknowledged`; recovery refuses retained records with
`scope-mutation-unsettled`. Begin always requires a valid scope-revision field,
but a retained idempotent retry can use its original now-stale revision.

Existing `private-authority-recover` must additionally reject every retained
scope writer until its explicit drain/commit/durable ACK lifecycle completes,
as well as existing active tag writers, unknown/live native executions and lost
execution context. Recovery still CASes the current scope revision and is an
authenticated producer attestation AFTER independent committed reads and checks
of all actual in-flight/durable intents. It never resurrects old tag generations;
subsequent fresh provider reads/publish must bind the new scope revision.
Registration, policy changes and disable/re-enable retain outstanding scope
writers. Native restart creates a new UNBOUND epoch: old leases cannot be
transplanted; terminal old-epoch drain and producer reconciliation are required.
No timeout, TTL or status string retires uncertainty.

### Producer ordering, including partial failures

Before the FIRST unknown raw/business SQL write, the producer must commit an
ownerless but real scope intent in its EXISTING independent durable journal.
Then obtain and durably record the native scope-begin ACK/lease before a covered
unsigned write starts. The journal keeps the original native connection/scope,
epoch/incarnation and transaction identity; it does not fabricate a provider
owner. Actual SQL failure still goes through writer drain/rollback settlement.
Application/provider work can outlive a response/shutdown hook, so neither is
sufficient evidence of drain. A lost begin ACK is uncertainty: retry the same
transaction and reconcile the actual native record, never invent a lease or ACK.
A lost commit/ACK leaves retained state for explicit reconciliation.

For a participating signed HTTP execution, its already-installed native scope
fence protects delivery even when a later producer control notification fails.
The durable journal must still precede business writes so unrelated recovery
cannot ignore that writer. Unsigned writers need the explicit scope transaction;
calling recover after the fact cannot retroactively protect earlier HITs.

### True control outage while business writes continue

If a write continues while NO mutation/fence signal reaches this native owner,
the owner cannot distinguish changed SQL from unchanged SQL on a native-only
HIT. A pending SQL outbox, request-local uncertainty, diagnostic status or short
TTL provides eventual detection at best, not immediate coherence. The negative
actors demonstrating CLEAN/old generation after changed SQL remain valid until
this ordering/communication gap is closed.

The required contract is therefore one of these explicit, real arrangements:

* Every write has an already-ACKed scope/native-execution fence before its first
  visible database mutation, and READY recovery waits for actual drain.
* If the WordPress HTTP client alone fails while native is reachable, an
  independently functioning synchronous transport may install the SAME existing
  authority-owner scope fence and return its genuine ACK. This is another
  transport to the same authority, not a second cache/journal or a fake success.
* If writes must continue through a true loss of every control transport, a
  native-visible coherence mechanism must be on the write/commit path and gate
  admission before changed data becomes visible. An asynchronous changefeed or
  eventual retry alone leaves a stale interval. Such a mechanism has not been
  implemented or qualified here.

No cache notification error silently cancels the business operation in this
design. If neither prior fence nor actual independent coherence channel exists
and the business write continues, that execution is explicitly NOT qualified
for coherent private reuse. Do not enable general reuse on a claimed coverage
contract that permits that uncovered path. Report the concrete gap; do not hide
it behind a guessed owner/tag, renewed generation, TTL, lease expiry or status.

Scope suspension gates the composed private-reuse authority. It is not a claim
that unrelated public/guest HTML has been purged. Writes affecting public
publication/content require the existing real publication invalidation contract
as well, or a separately specified scope gate for those namespaces.

### Required native and real-producer qualification before implementation acceptance

Exercise unknown unsigned write after a real composed HIT; overlapping writers;
begin/commit/ACK loss and retry; delayed begin across ACK collection; wrong
lease/epoch/scope; allocation failure; policy replacement/restart; outstanding
signed backend plus unsigned writer; and an attempted concurrent recovery while
any real writer still runs. No old admission may resume after recovery without
fresh provider generation/publication checks. Repeat the actual Hestia negative
raw-write and HTTP-client-failure actors. A true total-control-outage/business-
write-continues actor must remain NOT qualified until a real coherence channel
is demonstrated. These are explicit tests for this extension, not evidence
provided by the existing mixed-recipe HIT checkpoint.


## Recovery preserves a successfully fenced namespace

Real unbind and scope transactions rotate the scope revision before an accepted
fence. Recovery only transitions that already-fenced namespace to READY, after
its existing exact current-revision CAS, retained scope/tag writer checks,
execution/hold/lost-context checks and explicit actual-drain attestation. It does
not rotate it a second time. A fresh source body's original authority namespace
therefore remains the same after recovery. Initially UNBOUND scopes already
have a newly generated incarnation/revision and no old CLEAN authority.

Old tag generations remain bound to their preceding scope revision, so READY
cannot resurrect them; fresh independent provider read/publish is still needed.
Scope begin/commit/ACK and policy invalidation retain their real rotations.
ACK collection still rotates BEFORE forgetting the transaction ID, so a delayed
old begin/recover/publish frame stays fenced across recovery. Overlapping writer
rotations invalidate earlier source claims: neither metadata nor recovery may
relabel an original body into a newer namespace.

A failed native revision generation is handled explicitly. The scope remains
UNBOUND with a pending revision fence, and replies expose no valid old
`scopeRevision`. An authenticated control observation can retry generation of
the replacement revision; while that fails, control returns503
`scope-revision-unavailable`, and no READY/body namespace can be granted.
Successful repair is only a new invalidation fence, not recovery or fresh tag
publication. Subsequent recovery CASes/preserves that real replacement. This is
actual identity-generation failure handling, with no timer, expiry-based cleanup
or fabricated namespace. Qualification uses a separately built, explicitly
altered fault source; the product has no test fault header/switch.
