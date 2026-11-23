# Original execution drain dispatch, version 1

This extends the existing producer early metadata/reconciliation owner. It does
not schedule a native worker, maintain another queue or introduce a body recipe.
The producer's original durable execution journal is its outbox. The normal
path is one producer-owned asynchronous dispatch after the original response;
next-HTML reconciliation is recovery, not a recurrent approval of native HITs.

Registration adds `X-UltraCache-Public-Selection-Execution-Drain-Version: 1`
alongside accepted coverage version 1 and its policy. The accepted echo is
`X-UltraCache-VCL-Public-Selection-Execution-Drain-Version: 1`. Only negotiated
covered origin executions receive `X-UltraCache-VCL-Execution-Drain-Version: 1`.
An attached reuse candidate retains its existing finalizer ownership.

The existing authenticated local `PURGE /__ultracache-vcl-contract-v2` operation
is `private-execution-drain-dispatch`. It carries the existing site token,
`X-UltraCache-Public-Selection-Scope`, and
`X-UltraCache-Delivery-Execution-Drain-Context`. The latter is canonical padded
base64 containing strict JSON with exactly these members:

```
schemaVersion: 1
dispatchId: 64 lowercase hexadecimal characters
target: original raw relative URI
context: {
  siteId, canonicalHost, scope, epoch, incarnation,
  nativePolicy, wordpressPolicy, reusePolicy,
  coverageVersion: 1, coveragePolicy
}
execution: { requestId, challenge }
proof: 64 lowercase hexadecimal characters
```

Duplicate decoded member names, missing/extra members and invalid types fail.
No delivery serial exists for an ordinary REST/Ajax execution. `dispatchId` is
an opaque producer dispatch identity, not an authority or completion grant.

The raw key is HMAC-SHA256 of actual site credential bytes with the existing
purpose `ultracache-mutation-key-v1`. LP means a four-byte big-endian byte length
followed by the bytes. The proof frame is:

```
LP("ultracache-execution-drain-dispatch-v1") + LP("GET") + LP(target) + LP(dispatchId)
+ LP(siteId) + LP(canonicalHost) + LP(scope) + LP(epoch) + LP(incarnation)
+ LP(nativePolicy) + LP(wordpressPolicy) + LP(reusePolicy)
+ U32(1) + LP(coveragePolicy) + LP(requestId) + LP(challenge)
```

The native control gate validates the owning site, longest application scope,
epoch/incarnation and retained original execution when present. A retired
marker retry is allowed only as authenticated producer journal reconciliation;
absence of a marker never proves the journal ended. The producer independently
validates the exact original journal identity, target, policy and proof.

The same native client-task/handoff owns the backend GET. It sends only the
adapter's required routing inputs plus `X-UltraCache-Delivery-` headers:
`Version: 1`, `Phase: execution-drain`, `Execution-Drain-Version: 1`,
`Original-URL: target`, `Public-Selection-Scope`, `Authorization` and unchanged
`Execution-Drain-Context`. Browser/control/recipe/cookie/authentication headers
are removed. Only this native owner skips public selection and new mutation
tracking; an incoming phase header cannot create that state.

The producer early entry terminates without normal providers, rendering or
issuers. It independently observes actual original PHP and SQL drain, settles
the existing intents and sends the existing exact signed completion-v2 RPC.
Pending, unknown or failed execution remains retained. The native dispatch
never closes a hold itself or rotates a namespace.

Response is bodyless HTTP 204, `Cache-Control: no-store`,
`X-UltraCache-Execution-Drain-Version: 1` and
`X-UltraCache-Execution-Drain-Outcome: settled|pending|unavailable`.
This outcome is diagnostic only. An invalid/non-204 response is abandoned;
ordinary application HTML is never returned as a metadata result. Completion
authority remains exclusively the existing authenticated completion-v2 owner.

Portable parity uses the independent Python frame and actual PHP synthetic
fixture. Native runtime actors mock the producer/drain and do not establish
actual WordPress/SQL settlement or composed-body acceptance by themselves.
