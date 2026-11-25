# Event-driven native test contracts (#1047)

This cleanup changes tests only. It does not restore the withdrawn universal
application hold, execution-drain dispatcher, scope-mutation protocol, observation
census, or their signed v2 coverage grammar. Historical protocol documents under
`shared/` remain historical; no test negotiates those protocols as current APIs.

## Retired actors and their current coverage

| Removed test contract | Current assertions retained |
| --- | --- |
| `test_mutation_coverage_runtime.py` / `test_mutation_coverage_wire.py` and v2 producer fixture | Event v1 HMAC/schema vectors stay in `test_mutation_wire.py`; exact request signatures and phases stay in backend, public-source and projected-source actors. Ordinary in-flight/missing-receipt requests do not gate complete HITs in `test_event_invalidation_runtime.py`. Actual owner writes still invalidate only their dependency. |
| `test_execution_drain_runtime.py` / `test_execution_drain_wire.py` and dispatcher fixture | The removed dispatcher has no current completion authority. Metadata retry/decline/exhaustion, exact original ownership, no cookie replay and actual fragment expiry remain in `test_reuse_full_runtime.py`. Signed delivery context, phase/URL authentication and invalid candidate rejection remain in `test_reuse_delivery_context.py`, `test_delivery_authorization.py` and native codec tests. |
| `test_scope_mutation.py` / `test_authority_recovery_revision.py` | Supported tag BEGIN/COMMIT/ACK, overlapping real writers, delayed replay rejection, policy/epoch replacement, scope isolation, authentication and explicit generation publication remain in `test_reuse_authority.py`. Removed scope-writer/whole-scope RNG-fault fixtures are retired, not silently represented as current tag tests. |
| Held-reader branches in `test_reuse_full_runtime.py` | Complete mixed personal/anonymous nonce composition, owner/Accept interleaving, public resolver registration, anonymous mutable-content invalidation, wrong revision/generation/key/tags, actual body lifetime, native LRU and pending finalization tests remain. Held waiters, VCL-held-reference accounting, pinned read cuts and fabricated drain timeouts are removed with the protocol. |

`test_retired_hold_contracts.py` verifies that removed control operations are
rejected without application execution or authority changes. It does not emulate
their former implementation. Identity observation rejects retired census domains.

## Receipt ownership and real writes

The mock producer must register a real tag event before returning a DIRTY receipt.
A signed receipt cannot create a writer. Request/challenge replay and foreign
receipts remain rejected while the application response and its own cookies remain
intact. Unknown/missing receipts and upstream EOF do not invent a global hold or
clear a real pending tag event.

ACK may collect a completed event while its backend response is still in flight.
The late receipt cannot resurrect that collected event. The active receipt-owner
tests cover valid retained receipts, GC during overlapping requests and stale
receipt rejection, without asserting that GC waits for whole-PHP completion.

## Validation scope

Run changed actors against the matching-source native module with
`SCP_EXPERIMENTAL_REUSE_TEST=1` and `SCP_TEST_COOKIE_MODULE` set. Their `proxy()`
creates its own temporary origin and Varnish daemon; it never reloads the installed
service. Targeted batches are sufficient for this tests-only change; a complete
matrix, real WordPress/SQL, browser, nonce-renewal or LiteSpeed Enterprise acceptance
claim is outside this test fixture's evidence.

The package build excludes `tests/`. The existing 0.13.21 product ZIP must remain
byte-identical; this cleanup requires no version bump or replacement product ZIP.

Validated on 2026-11-25 with the existing matching-source Varnish 9.1 module:

- 44 distinct changed/dependent native HTTP tests passed: authority 9,
  observation 1, retired controls 1, backend 5, receipt ownership 3, normal
  generated boundary 2, and full private/anonymous reuse 23.
- All 13 retained independent v1 mutation codec tests passed.
- The 112 remaining Python test files parse; direct test-module imports no
  longer reference deleted suites.
- Initial failures from obsolete scope-state/diagnostic expectations and a
  phase-inappropriate fixture helper were corrected and only the failed cases
  rerun. They were fixture failures, not a production change. A first runner
  import failure was corrected by using a separate cachelab-accessible directory,
  without changing permissions on another task's fixture.
- No tests were skipped in these batches. This is targeted validation, not the
  complete repository matrix or an application acceptance claim.
- All 136 packaged source files still match the existing 905001-byte 0.13.21
  ZIP, SHA-256
  `68b9c0fa844a9d835b5d979843cf5404c4b2e7dcb9d0f55f4a9f6f9f05059f80`.
