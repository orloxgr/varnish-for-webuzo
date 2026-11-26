# Authenticated public-parent Warm

The existing authenticated capability response advertises
`X-UltraCache-VCL-Warm-Delivery-Version: 1`. A client must observe this capability
on its accepted endpoint before selecting the public-only path.

The request remains a normal GET of the exact trusted public URL, with its real
public cookie context and actual Accept header. It sends:

- `X-UltraCache-Warm-Projection: parent-v1`
- `X-UltraCache-Warm-Delivery: public-parent-only`
- `X-UltraCache-Warm-Projection-Authorization: v1:<HMAC-SHA256 hex>`

The existing site credential signs these newline-separated values, with no
trailing newline:

```text
ultracache-warm-projection-v2
parent-v1
public-parent-only
GET
host
raw URL
scheme
actual Accept
scope
native policy
WordPress policy
guest policy
registry epoch
```

Each placeholder is the existing accepted native value, without another URL or
Accept normalization. The authorization field retains its original `v1:` wire
encoding; the canonical signed message is domain-separated as v2. Native captures
the opt-in once, rejects duplicates and unsupported values, authenticates it and
removes it from the request forwarded to PHP. Adding, removing or changing the
opt-in invalidates its HMAC. Private/authenticated visitor bypass still precedes
this public Warm operation.

Without the delivery opt-in, native accepts the original canonical message:
`ultracache-warm-projection-v1`, `parent-v1`, `GET`, followed by the same nine
request/policy fields above. That request keeps normal personal parent delivery;
it does not enter the public-only or paired-fill path.

An opted-in cold owner retains the verified pure source while the application
executes its real anonymous guest compilation. A valid COMPLETE envelope must bind
back to that source and actual context. The existing snapshot backend stores the
guest and ESI parent as two ordinary native objects. It does not invent personal
admissions or replay source/resolver cookies. Each object's original deadline,
policy, generation and invalidation rules remain effective.

The final parent response retains `X-UltraCache-Warm-Projection: parent-v1` and emits
`X-UltraCache-Warm-Delivery: public-parent-only` only after actual native parent
delivery. It returns the exact raw source body, including ESI directives. Personal
work reports `X-UltraCache-Delivery-Outcome: not-executed` and private cache status
`NOT-APPLICABLE`.

`X-UltraCache-Warm-Guest: populated` additionally means this same owner completed
a genuine COMPLETE guest cache insertion. It is absent on hot parent requests
that did not perform that insertion, and on failed guest fills. It never replaces
the client's subsequent ordinary guest GET/HIT and complete-body verification.
The client also verifies the parent's exact body/context and a fresh real HIT.
