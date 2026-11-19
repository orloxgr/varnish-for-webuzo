# Aggressive public HIT validation — 0.10.0

Acceptance completed for the user-approved pure-VCL aggressive mode on the
disposable Webuzo and Hestia labs. No customer server was changed or public
release published by this validation.

The former Joomla runtime resolver/token system is removed. Its earlier
0.9.x validation and guarantees no longer describe this implementation.
Opt-in HTML, including existing Joomla tokens, is deliberately unchanged.

## Native policy and request lifecycle

Webuzo passed 36 focused methods covering aggressive mode, CMS paths/metadata,
explicit cookie choices, deployment lifecycle and cookie-handoff cleanup/native
module replacement. A later six-method run verified the final retirement code,
activation ordering and POST/PUT/PATCH/DELETE PASS before a warm public object.
Five package/version checks and JavaScript syntax validation also passed.

Both Basic and UltraCache warmed a public page containing actual JSON and hidden
form token markup. The test then stopped and closed the origin TCP listener and
confirmed connection refusal. Different PHP/Joomla session cookies and tracking
values still received HIT with exactly the original HTML, no Set-Cookie replay
and only the initial full, unmodified URL/Cookie request reaching the origin.
There was no CMS helper or token provider in the generated VCL/native API.

The final shared HTTP suite passed all 115 scenarios in each adapter. Strict
comparison checked 34 byte-identical common files, all current VCL/native/CMS
source fingerprints and identical successful results. Coverage includes original
tracking/functional query behavior, explicit Variant precedence, known private
CMS routes, response-cookie ownership, and existing UltraCache personal ESI.
Hestia additionally passed 36 focused methods and its complete native upgrade
from a running former CMS helper, preserving PID/tokens and restoring its lab
baseline afterward.

## Native Webuzo ZIP upgrade and installed route

The native plugin uploader activated 0.10.0 on the disposable VM. An actually
running former CMS unit/socket was provisioned as the upgrade fixture. After
successful helper-free VCL activation, the native upgrade disabled the unit and
removed its unit/configuration/socket/worker sources and bytecode. The Varnish
manager PID, purge tokens, selected profiles, enabled states and durations were
preserved, with no pending transaction. The final fixed cleanup was also verified
from a newly running former-helper fixture in one successful native activation.
Cleanup uses native Webuzo ownership rules for its panel-managed plugin tree;
no panel/vendor permissions or source files were changed.

Through the installed native panel API, Basic and UltraCache were each saved
with aggressive enabled and TTL 90000; a new status read confirmed persistence.
The real installed Nginx/Varnish/PHP route then produced MISS/HIT/HIT for different
tracking URLs and PHP sessions, leaving JSON/hidden-form HTML unchanged and
returning response cookies only to the fetching visitor. The temporary endpoint
was removed and all original site selections restored. Final resource checks
again confirmed no helper, no pending transaction and the original PID/tokens.

Private validation artifacts are retained outside the distributed ZIP. The addon
does not claim per-session Joomla token reconstruction or hidden session-state
classification; these were explicitly removed from the opt-in policy.

## CMS discovery exclusions — 0.10.1

The subsequent Webuzo adapter passed 32 focused methods covering CMS directory
exclusions, metadata queries, route matching and native activation. Excluded
subtrees are pruned before marker/configuration reads; an unsuccessful refresh
cannot restore their retained routes or cookie descriptors. Unchanged native
document roots do not trigger repeated discovery during automatic reconciliation.
New or changed roots are attempted once, while explicit Refresh sites and native
addon activation request a fresh scan. Configuration applies exclusions before
the selected-site scan. The shared discovery implementation matches Hestia byte
for byte. These changes do not alter the visitor VCL or add a runtime helper.
