# Publication conflict reselection

A native cached parent A can briefly outlive the application publication it
names. A local cache clear, replacement or provider-triggered publication change
can therefore make the next old prepare token fail before WordPress providers
run. This protocol adds one explicit same-owner transition into current public
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

## Registry lifetime and restarts

Application declarations live in the native child process. The public selection
epoch identifies that actual registry lifetime, incorporating the native build
identity and native entropy at its first VCL load. A new child/registry gets a
new 64-hex epoch even with the same build. Overlapping VCL loads sharing the
registry retain its epoch and declarations; discarding its last VCL clears both.
Initialization failure rejects the candidate VCL rather than reporting an old or
empty registry identity. The existing authenticated application synchronization
can therefore notice a fresh registry without a manual reset or declaration.

A source-only native baseline reproduced the previous defect: a new manager had
an empty registry but advertised the exact same build-only epoch. This made a
persisted application registration appear current. No WordPress special case or
relaxation of registry authorization is used to recover from that condition.

## Coordinated qualification - 22 November 2026

Coordinated versions: Varnish for Webuzo **0.12.7**, Varnish for Hestia **0.23.6**,
and UltraCache **3.13.13-dev.1323**. The application correction was qualified from
producer runtime `e42727f6` with acceptance tests `469ea3c7`. The native runtime
was qualified from Webuzo `37d493a` and Hestia `2f2df56`; release metadata and
this qualification record do not change those runtime bytes.

Both adapters passed 33 native methods with zero skips, including seven
publication-conflict methods, 18 malformed-proof subcases, concurrent visitor
ownership, restart/overlap registry lifetime and existing delivery, cookie-only,
representation and header-budget regressions. Hestia also passed source-identity,
seven compatibility methods and a C-only reload check. Webuzo passed 59 additional
profile and preset methods.

Actual WordPress integration passed on both adapters:

- Same-build restart creates an empty registry with a new epoch; the ordinary
  application Warm restores registration without manual declaration or Redetect.
  The first anonymous visit then returns HTTP 200/HIT in ORIG, WebP and AVIF.
- All five publication lifecycle scenarios, 11 cookie lifecycle visits, real
  WordPress nonce verification and two independent cart owners passed in all
  three representations. Recovery executes one application bootstrap without
  replaying private-provider work. Plain warmed HTML remains a HIT with zero
  WordPress bootstraps.
- A genuinely missing local publication can pass through a cold collector
  transition while its body/pointer changes. Its captured response receives no
  new freshness. The observed sequence converged MISS/PASS/MISS/HIT, all HTTP 200
  with verified delivery. This differs from the completed-Warm first-HIT test.

The normal Webuzo ZIP upload and activation also passed on the disposable panel:
all installed archive files matched, the active VCL matched its startup file,
the module build receipt matched the installed source and local engine SDK,
and hosting settings were preserved. The full root Cookie Policies response
remained valid JSON with 2,305 unique rows and both independent profile actions.
No production deployment was performed during qualification.

After upgrading both the native adapter and WordPress companion, use the normal
UltraCache cache clear and warm-up. This correction introduces no new timer,
TTL extension, persistent store or background worker. The exact actor that
invalidated the original production publication has not been established.
