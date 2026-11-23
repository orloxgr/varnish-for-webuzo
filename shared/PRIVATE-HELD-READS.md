# Pinned cache reads during covered execution overlap

Experimental implementation on the existing UltraCache native delivery owner.
This changes **read admission ordering** explicitly. It does not change cookie
classification, application URLs, scope/tag mutation authority, provider TTLs,
execution completion or the supported-provider coverage contract.

## Read cut, not global quiescence

The previous boolean lookup treated a temporary covered execution hold as an
ordinary cache MISS and immediately ran another personal prepare. A pending
read now has three outcomes: complete HIT, actual MISS, or HELD complete plan.

For HELD, the same registry critical section captures the native execution
sequence and pins the complete, otherwise-valid current public parent,
metadata record and all private body objects. It materializes every private
dependency before releasing the lock. This is the request's admission cut.
No partial plan is held, and no dependency is fetched after an unobserved write
to manufacture a purported earlier snapshot.

Only covered executions already present at this cut block that pinned read.
They must still produce their exact, independently proven completion. A new
execution starting after the cut cannot extend this finite blocker set. This
is ordinary snapshot-read ordering for overlapping requests; it does **not**
declare a newer request read-only or qualified because of its URI or method.

An earlier writer with unsupported coverage, an unconfirmed prewrite fence,
missing receipt, late/destructor write or lost drain remains a blocker or
invalidates the old authority. It cannot be excluded by the cut. Newer real
writes may be ordered after the pinned read, but their observed tag/scope
invalidations still reject the old plan at final validation. This is not the
old global zero-holds predicate under a new name: publication/recovery and
diagnostic readiness retain that predicate, while read admission is cut-local.

## Existing native engine ownership

The same PRIV_TOP continuation owns one internal HSH busy reservation. Two
finite VCL restarts stage its own lookup and restore the original parent. The
request enters the engine's actual LOOKUP/HSH_BUSY waiting list, which releases
its worker. No worker sleep, condition-variable wait, VCL restart polling, PHP
reconciliation per HTML request, helper daemon or replacement renderer is used.
Exactly two restart slots are added once, preserving all pre-existing protocol
recovery/reselection/finalization headroom.

The existing worker pool's waiter monitors a nonblocking notification socket
owned by that continuation. Actual exact retirement or real authority changes
signal it; native RUSH scheduling then withdraws the HSH reservation. An event
whose original blockers remain pending simply rearms the same waiter at its
original deadline. New backend reads do not extend that deadline or blocker set.
API execution and control/drain/finalization do not wait behind an HTML reader.

The cache-only scheduling deadline is the minimum of **0.5 seconds**, matching
the existing producer execution-observation budget, the existing public-parent,
metadata/private-body/admission deadlines and the request's send-timeout budget.
The internal 0.5-second budget is explicit: it avoids silently parking HTML for
an inherited 1,500-second server budget after a lost drain dispatch. It does not
change any application/session timeout, worker limit, provider TTL or retention.
Normal short executions wake the same zero-origin cached plan; exceeding this
optional observation budget retains HELD/unknown coherence facts and uses real
fallback. Time never grants CLEAN or changes an ordinary busy read into a MISS.
A deadline/error withdraws the reservation and follows genuine original prepare
or refusal. It never drops an execution hold or sends an empty success response.
Missing independent drain cannot create an immortal reservation. On a native
wake, the existing transport's poll/reset state or a non-consuming HTTP/1 socket
EOF check detects a disconnected reader; that request is refused without
executing a provider. Even with no original drain event, the bounded waiter
reclaims its reservation/association/pins while the original execution remains
unresolved. Cancellation and VCL ownership use the original request lifetime and a retained VCL reference;
there is no new durable coherence owner or background queue.

After waking, the original parent is selected again. Before exposing headers
or bodies, the engine rechecks the same scope/policies/epoch/incarnation,
discovery, input bindings, actual tag revisions/generations, original object
identities and all natural deadlines. A real change causes genuine fallback.
Pinned bytes alone never authorize delivery, and expiry never extends a grant.

## Engine interface and qualification scope

The experimental interface currently matches native Varnish 9.1 source commit
`ffd36e9db9a1ec2bf6637deda180a87d40a13d0f`. The build validates the installed
cache/cache_int/waiter layouts and bundled upstream object-head/pool/transport interfaces.
The generated counter header needed by the private pool layout records its
upstream source/generator hashes. Unknown or altered interfaces retain the
ordinary producer path; private layout offsets are never guessed.

Native actors use real HSH objects, HTTP requests, actual engine waiting-list membership,
worker disembark/wake, signed exact coverage completion and current-object
checks, with a MOCK trusted provider. They do not establish actual WordPress,
SQL provider coverage, browser usability or production acceptance. Those remain
separate combined gates, including the uninstrumented browser actor.
