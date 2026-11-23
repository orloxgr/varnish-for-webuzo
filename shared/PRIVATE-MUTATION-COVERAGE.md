# Supported native-provider mutation coverage (proposed wire v2)

This extends the existing registered scope, signed mutation execution, SQL
journal and exact execution-drain operation. It is not another coordinator,
cookie policy or UI control. Version 1 stays unchanged. This draft is not an
implementation/acceptance claim until both native and PHP actors qualify it.

## Negotiation

The existing registration declaration optionally adds `coverageVersion:1` and
`coveragePolicy:<lowercase hex64>`. Request headers:

- `X-UltraCache-Public-Selection-Coverage-Version: 1`
- `X-UltraCache-Public-Selection-Coverage-Policy: <hex64>`

The accepted capabilities/registration receipt echoes:

- `X-UltraCache-VCL-Public-Selection-Coverage-Version: 1`
- `X-UltraCache-VCL-Public-Selection-Coverage-Policy: <hex64>`

The policy identifies the implemented supported native-provider mutation
contract. Package version, cookie presence, a revoke-only owner-map match, a
URL pattern and a response NONE are not coverage. Runtime-selected handlers,
stores and installed callbacks must still satisfy that contract for the actual
execution. Unsupported selections use the real unknown/scope path. Absence of
negotiation produces the original v1 context and behavior.

## Exact context framing

`LP(s)` means u32 big-endian byte length followed by the exact UTF-8 bytes.
`U32(n)` is an unsigned four-byte big-endian integer. Hex strings are ASCII.
No URL, Cookie or JSON normalization is applied. Duplicate JSON keys, including
escaped duplicates, are rejected. Standard canonical padded base64 is retained.

The mutation key remains the raw 32-byte HMAC-SHA256 of
`ultracache-mutation-key-v1` with the actual site credential as key.

Schema 2 adds exactly `coverageVersion` (integer 1) and `coveragePolicy` (hex64)
to the original ten context fields, schemaVersion and proof: fourteen fields
in total. The original ten fields remain in this order:

`siteId, canonicalHost, scopeDigest, epoch, incarnation, nativePolicy,
wordpressPolicy, reusePolicy, requestId, challenge`.

The context proof is lowercase hex HMAC-SHA256 with the mutation key over:

`LP("ultracache-mutation-request-v2") + LP(each original context field) +
U32(1) + LP(coveragePolicy) + LP(actual method) + LP(actual raw URI)`.

The existing native mutation-context header carries this JSON. The context
must match the actual accepted scope's coverage version/policy as well as the
existing site, host, scope digest, epoch/incarnation and policies. A v1 frame
cannot be upgraded to v2 by adding unproved fields.

## Exact response receipt framing

Schema 2 has exactly seven fields: `schemaVersion:2`, `state`, `transactions`,
`coverageVersion:1`, `coveragePolicy`, `coverage`, `mac`.

`state` and canonical unique sorted `{tag,transaction}` pairs keep their v1
meaning. `coverage` is exactly `qualified` or `unknown`. SCOPE requires UNKNOWN;
NONE and DIRTY do not imply QUALIFIED. The coverage policy must equal the
authenticated original execution's value.

Receipt MAC input:

`LP("ultracache-mutation-response-v2") + LP(original context proof) +
U32(1) + LP(coveragePolicy) + LP(coverage) + LP(state) + U32(pair count) +
LP(each tag) + LP(each transaction)`.

This is a response-time observation. It cannot close a still-running PHP
execution, attest later SQL completion or publish a reusable body. Streaming,
early headers, fastcgi_finish_request and shutdown are not actual drain.

## Exact post-drain completion

The existing `private-execution-drained` operation still requires exact scope,
epoch/incarnation, requestId/challenge, scope revision and `Drained:1`.
For a v2 execution it additionally carries:

- `X-UltraCache-Private-Coverage-Version: 1`
- `X-UltraCache-Private-Coverage-Policy: <hex64>`
- `X-UltraCache-Private-Coverage-Result: qualified|unknown`
- `X-UltraCache-Private-Coverage-Proof: <hex64>`

Completion proof uses the same raw mutation key over:

`LP("ultracache-mutation-completion-v2") + LP(original context proof) +
LP(original requestId) + LP(original challenge) + U32(1) +
LP(original coveragePolicy) + LP(coverage result)`.

The native owner compares these bytes against its retained ORIGINAL execution,
not an incoming caller's substituted policy/proof. The existing authenticated
control channel remains required. Invalid/missing completion never preserves
old authority as a successful covered close. A conservative explicit UNKNOWN
close may retire only the actually drained execution while invalidating the
scope; it cannot become qualified or resurrect the previous scope revision.

Before sending QUALIFIED, the producer must:

1. Prove the exact original runtime ended, capture the immutable independent
   SQL session set after that event and wait for actual disappearance.
2. Reread the current original journal incarnation/revision and every relevant
   owner/scope intent, including writes appended after the response receipt.
3. Settle genuine exact-owner writes through their native commits/durable ACKs.
4. Refuse qualified closure on a generic scope mutation, unsupported selected
   provider, failed prewrite fence or failed original coverage observation.

Original proof/policy and runtime bindings are stored in the existing execution
row. Raw Cookie, session IDs, private HTML and raw URI are not added to SQL.
Completion does not reread/execute a provider or infer facts from an empty list.

## Supported-provider meaning and native holds

Coverage is for the actual supported native APIs/integrations, not a proof of
all arbitrary third-party PHP or direct SQL. Core token storage uses its actual
native manager and before-metadata observers. Woo uses the actual tracked stock
handler and real write methods, including CLI/cron and both migration owners.
YITH uses the actual compatible wrapped store and installed object/delete/meta
observers. Recognized typed raw operations retain exact owner fences; genuinely
unknown API writes use durable scope transactions before business SQL.

A negotiated covered dispatch creates its exact native temporary hold before
origin work. The hold itself does not rotate the permanent scope revision.
Only its valid current-policy receipt plus exact actual post-drain completion
can remove that execution's hold while preserving unrelated owner generations.
Overlapping executions cannot close each other. Known writes dirty only their
real owner tags. Unknown scope writes, bad/missing coverage, unsupported stores,
loss or unverifiable closure convert to durable UNBOUND/revision rotation.
Late completion cannot reverse that invalidation. Fresh reads/publication
remain necessary after a real mutation. A receipt never grants body admission.

Native delivery/admission while holds overlap must be tested separately; do
not hide a recurring PHP path or a global refill storm behind the word HOLD.
Required actors include unchanged interleaved A/B across formats, mutations of
A preserving B, concurrent readers/writers, late/destructor writes, early flush,
replacement SQL sessions, lost replies, unknown stores/raw operations,
restart/policy changes and actual normal bootstrap. All prior cookie lifecycle,
nonce, content dependency and no-leak requirements remain applicable.

The experimental native read path now distinguishes HELD complete plans from
MISS. Its finite admission cut and native waiting-list ownership are specified
in [PRIVATE-HELD-READS.md](PRIVATE-HELD-READS.md). This explicitly changes read
ordering from global quiescence to a complete pinned snapshot blocked by exact
pre-existing executions. Publication/recovery readiness and execution hold
retirement retain their existing rules. A newer execution never becomes
qualified by being excluded from an earlier read's blocker set.

True loss of every coherence channel while business SQL continues is not
resolved by this wire. A local journal/outbox alone does not notify native HITs;
that gap remains explicitly unqualified until a real channel/order is proven.


## Native experimental consumer notes

V2 is negotiated only through the existing authenticated scope registration.
Legacy v1 and the production/default disabled path remain unchanged. Registered
coverage is not inferred from owner maps. A covered dispatch skips speculative
personal-map revocation on a read: real supported-provider prewrite transactions
must revoke actual tags. Its retained execution holds the original scope
revision, policy, challenge/proof and purpose key until exact completion.

The existing `scopeState` vocabulary remains `ready|unbound`: a temporarily
held scope reports `unbound` with `temporaryHolds`, while its permanent
`scopeRevision` is unchanged. Its retained execution records expose accepted
coverage version/policy and response-time `receiptQualified` on the authenticated
control channel. This is not an actual-drain assertion or a new capability that
enables general delivery reuse.

Native-only composed admission and generation publication refuse a held scope.
A genuine qualified completion removes only its own ended execution and never
sets READY. If the base scope was ready and its revision is unchanged, unrelated
authority remains usable once all holds close. Initially UNBOUND scopes still
need explicit actual recovery/fresh publication. A scope transaction, policy
change, missing/bad receipt or completion makes old authority durably UNBOUND;
qualified completion cannot reverse that. The caller must explicitly retire a
genuinely drained uncertain execution with signed UNKNOWN, then perform the
existing recovery protocol. Failed proof does not retire the execution.

Portable C parity checks both the independent native Python vectors and the
producer's four Python-generated cases, including IPv6 authority and raw query
bytes. Actual-native mock actors separately exercise these engine barriers.
Real installed-provider/SQL/drain and multi-visitor browser acceptance remain
Root integration gates. No production service or pinned earlier fixture is
changed by these source changes.
