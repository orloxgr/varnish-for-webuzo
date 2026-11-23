# Multi-fragment native resolution candidate

Not frozen, negotiated, enabled in production VCL or released. This is the
consumer-side lifecycle stage of cached private composition, not a completed
zero-application delivery feature. Application authority remains a separate
producer/native protocol and must be qualified before enabling any fast path.

## Existing ownership and storage

`delivery_reuse.c` is included by the existing continuation. Its dynamic list
holds independent native object references per authenticated descriptor, owned
by that same top request and released by the existing `delivery_fini`. It does
not use the fixed-capacity engine request object stash, add a global private
body cache, create a helper service or change the public parent object pointer.

The current entry requires an existing ready continuation whose complete
rendered descriptor claims have already passed the existing authenticated
envelope parser. It therefore STILL requires prepare. Later admission/context
work will supply authenticated metadata before prepare; that does not exist in
this stage. These experimental methods do not advertise reuse negotiation.

The agreed producer input-declaration direction is
`recipe.inputs={"cookieNames":[...],"cookiePrefixes":[...],"phpMaxInputVars":1000}`,
where the example integer is replaced by actual effective producer runtime
metadata, never a consumer default. It includes complete
declarations including absent names and prefixes which currently match nothing.
It is not an observed-cookie-name list. Proposed binding groups every matching
wire occurrence by normalized PHP flat name, sorts groups by bytes and preserves
occurrence order inside a group. Ambiguous/unqualified matching syntax uses
ordinary prepare without reuse and does not become a Private cookie policy.
The portable projection/metadata/MAC owner is specified separately in
`PRIVATE-REUSE-INPUTS-DRAFT.md`. It now matches actual PHP wire/MAC vectors; this
does not add admission or a pre-prepare entry to the native object resolver.

The resolver hashes the actual existing private namespace: domain, native site,
host, exact fragment URI and authenticated cache key. It respects the actual
native hash lookup's Vary/ban/freshness decisions, checks the private-object
marker and rejects response-cookie objects. It never treats cookie presence
as identity, changes cookie decisions or authorizes arbitrary caller keys.

Missing, expired, active-fetch and unclaimed dependencies remain missing. The
lookup does not dispatch an origin fetch or park the main request on a busy
dependency. Its temporary native MISS reservation is explicitly withdrawn.
An all-HIT result describes pinned bodies only, not current authority.

Optional materialization copies all selected HIT bodies into the existing
request-local fragment list atomically; existing prepared bytes for MISSes are
unchanged. A copy failure leaves all prepared fragment bytes unchanged. No
cached cookie fields are replayed. Retained/refilled HIT data uses the minimum
of the original native absolute expiry and the current producer claim; a new
prepare or refill cannot reset that original deadline.

Pinning only keeps bytes alive. It is NOT a generation barrier, admission lease
or permission to republish revoked content. The final pre-header authority
recheck/linearization and durable mutation failure/restart protocol are OPEN.

## Explicit engine-source dependency

The installed development package does not provide the HSH declarations used
by this experiment. An exported executable symbol is not a supported SDK
contract. Default builds leave the implementation OFF and the methods report
unavailable; generated production VCL has no caller in either build mode.

For an isolated qualified build, explicitly supply the absolute directory in
`SCP_EXPERIMENTAL_REUSE_ENGINE_SOURCE`. That directory contains the unmodified
matching official engine-source `cache_objhead.h` and an `engine.json` receipt:

```json
{
  "revision": "<40 lowercase hex matching installed strict ABI>",
  "objheadSha256": "<sha256 of the source header>",
  "installedHeaders": {
    "cache/cache.h": "<sha256 of the qualified installed layout>",
    "cache/cache_int.h": "<sha256 of the qualified installed layout>"
  }
}
```

The builder verifies revision, private-header digest and installed layouts,
includes both header and receipt in the module identity, and records the
receipt beside the built DSO. It does not download source, guess prototypes,
reuse a stale DSO after a receipt change or silently enable the implementation
when an installed package changes. An enabled candidate needs requalification
against its exact engine revision. The production build/distribution contract
for this private engine dependency is not frozen yet.

## Qualification scope

`test_private_reuse_resolver.py` uses a mock authenticated producer and actual
native private objects in the existing continuation. It deliberately records
the continuing prepare calls. Its isolated VCL is the only caller of the new
methods. Real provider identity, selective producer execution, zero-PHP HITs,
multi-writer authority, failed persistence and restart recovery require their
own actors and cannot be inferred from these tests.

Current first-stage one-object feasibility included actual concurrent PURGE,
natural expiry, Vary mismatch and a busy dependency. Those observations are
not a substitute for the full multi-descriptor/authority acceptance suite.

The executed multi-object qualification adds 14 distinct descriptors (15 body
occurrences), successive request cleanup beyond the engine stash capacity,
mixed HIT/MISS, two synthetic owners, unclaimed fragments, original expiry after
BAN/materialized refill, actual browser-connection abort after headers with
pending-owner count returning to zero, and an actual default-build Basic request
which reports the resolver unavailable. Build-receipt checks reject changed
engine revision, private header or installed layout. Mock preparation still
executes on each retained visit; no zero-PHP result is inferred from a HIT count.
