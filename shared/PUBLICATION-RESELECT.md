# Publication conflict reselection (candidate)

A native cached parent A can briefly outlive the application publication it
names. A local cache clear, replacement or provider-triggered publication change
can therefore make the next old prepare token fail before WordPress providers
run. This candidate adds one explicit same-owner transition into current public
selection; it does not relax publication validation or replay consumed work.

## Negotiated early response

Only an owned ordinary prepare advertises
`X-UltraCache-VCL-Publication-Reselect-Version: 1`. A compatible producer may
return HTTP 409 before bootstrap/provider work with the following single fields:

- `X-UltraCache-Delivery-Conflict-Version: 1`
- `X-UltraCache-Delivery-Conflict: publication-binding-mismatch` or
  `public-publication-unavailable`
- `X-UltraCache-Delivery-Request`: the exact native request identity
- `X-UltraCache-Delivery-Original-URL`: the exact original URL
- `X-UltraCache-Delivery-Manifest-SHA256`: SHA-256 of the supplied manifest token

The response has explicit `Content-Length: 0`. The native HTTP parser must
confirm no body; Content-Encoding, Transfer-Encoding, Set-Cookie and Set-Cookie2
prevent this transition. Generic errors and parent-snapshot/public-select
responses never grant a new provider operation. The producer must emit proof
only at its authenticated early conflict exits, not from a general error helper.

## Native ownership

The continuation retains its original PRIV_TOP owner, URL, host, adapter site,
Cookie, Accept, encoding and conditional fields. It retires only A through the
supported std.ban interface, matching the original adapter site, object host,
canonical URL and exact old deliveryPrepare pointer. Ban operands are quoted and
escaped; this is not a site-wide purge or mutation of engine object pointers.

The next restart re-runs native route/auth/cookie rules and resolves the current
registered application scope and policy. A distinct backend association/request
identity enters the existing original-route public-select parser. Its complete
B snapshot, manifest, body digest, metadata, cookie projection and private work
must pass the usual checks. A's headers, body, deadline and recovery flags are
not carried into B. Current registry removal and insufficient restart budget
reject the transition. The normal selection entry still rejects arbitrary
restarts or an existing continuation.

Exactly one conflict transition is available to this top request. There is no
retry following a successful prepare, private document, cookie side effect,
fragment render or later error. If providers retire A during a successful
prepare, the current request may finish its already captured A without minting
a new fresh lifetime; only the following request can independently select B.
Basic never enters this protocol.

This is an unpublished source candidate. Actual producer integration and native
regression results must be qualified before release. No production changes are
part of this source change.
