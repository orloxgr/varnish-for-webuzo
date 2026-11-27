# Changelog

Historical release and implementation notes, moved from the former README.
Entries describe their version's state; later releases can resolve the remaining
work mentioned in an earlier entry. For current behavior and installation, see
[README](README.md).

## 0.13.27-dev.9 — 2026-11-27

- Negotiate activated fragment subsets while preserving the full signed ticket,
  original occurrence counts and shared ESI/Ajax body identities. Reject invalid
  selectors before preparation without executing inactive fragments.
- Reuse a complete admitted private fragment set entirely through native cache
  objects, without PHP, SQL or an external helper on a qualified HIT. Bind both
  actual identity and complete render inputs, deadlines and mutation generations.
- Learn exact full-ticket acceptance only after authenticated application
  validation. Missing objects, changed inputs, pending writers and revoked
  sessions retain the ordinary selected preparation path without cookie replay.
- Keep parent and fragment participation independent. Optional receipt storage
  failure preserves completed results; storage OFF and teardown revoke reuse.
- Qualify the shared implementation with the normal UltraCache WordPress
  `3.13.13-dev.1431` ZIP on both panel adapters, including real sessions,
  overlapping subsets, zero-PHP private HITs and actual session revocation.

## 0.13.27-dev.8 — 2026-11-27

- Omit the redundant internal cache-key URL from the uncacheable fragment
  prepare request. Keep the owning request, signed original URL, manifest,
  authorization and subsequent native fragment object identities unchanged.
- Verify actual default-Nginx preparation of a larger compressed batch without
  changing request, header or workspace limits.

## 0.13.27-dev.7 — 2026-11-26

- Retain large outbound delivery URL and manifest header lines on their existing
  backend task, freeing them after unsetting their HTTP references on completion,
  retry or abort. Preserve response-receive workspace without changing limits.
- Reproduce the former intermittent large-batch overflow with a coalesced origin
  response; verify the same request succeeds with unchanged protocol values.

## 0.13.27-dev.6 — 2026-11-26

- Support negotiated self-contained compressed fragment batches, using the
  existing registered scope key to authenticate memory admission before inflate.
- Preserve the application's separate signature, exact descriptor URIs, request
  digest, cache keys, authority checks and legacy uncompressed ticket handling.
- Require exact raw length, complete DEFLATE input and checked allocation bounds;
  keep server request/header/workspace settings unchanged.
- Own zlib development/runtime dependencies and include its version and flags
  in the native build receipt. Qualify the shared synthetic wire vector and
  large-plan single-prepare handling with invalid native MAC rejection.

## 0.13.27-dev.5 — 2026-11-26

- Recognize anonymous fragment identity separately from product/content
  dependencies. Tagged anonymous output requires the existing nonempty
  authority closure and current content revision/generation before release.
- Advertise scoped `Fragment-Anonymous-Authority` support only for registered
  fragment delivery. Older native transports retain their previous contract.
- Verify native reuse, rejection of a hot body after a real dependency mutation,
  fresh-generation refill, personal isolation and storage OFF behavior.

## 0.13.27-dev.4 — 2026-11-26

- Add read-only `cacheScope` to successful fragment results: `anonymous`,
  `private` or `none`, after existing native storage and final authority checks.
- Keep producer input, identity, cache policy, cookie handling and failures
  unchanged. Storage OFF reports request-local output rather than retention.
- Verify actual anonymous/private native reads, storage OFF and writer retirement
  without exposing cache keys or authority in browser results.

## 0.13.27-dev.3 — 2026-11-26

- Route canonical fragment GETs through fragment handling instead of document
  public selection, including browser Ajax requests with `Accept: text/html`
  inside an active registered parent scope.
- Preserve origin signature/scope validation, ordinary ingress and cookie
  decisions, fragment-cache OFF, HTTP freshness and exact URL invalidation.
- Verify registered public Ajax MISS/HIT and exact fragment purge without
  retiring sibling fragments or the parent. Native module/ABI is unchanged.

## 0.13.27-dev.2 — 2026-11-26

- Preserve the verified original cookie classification across the cookie-free
  native finalizer return, avoiding repeated full-cookie regex allocations.
- Keep existing site, host, URI, restart and input identity checks. Changed or
  duplicate cookies and client-supplied reuse markers cannot authorize reuse.
- Reproduce the previous workspace exhaustion with ordinary browser headers,
  a 1,678-byte synthetic Cookie and thirteen private placements. Keep native
  workspace defaults, private components and cache policy unchanged.

## 0.13.27-dev.1 — 2026-11-26

- Development candidate for coordinated UltraCache fragment-delivery acceptance;
  this is not a production release.
- Reuse the same individual native fragment objects across ESI and browser
  batches, with authenticated application preparation, current mutation
  authority and sanitized request-local JSON delivery.
- Keep parent delivery and fragment storage independent. Echo the accepted
  parent flag; full connection retirement omits the fragment declaration.
- Admit explicitly declared stateless anonymous fragments under the current
  scope authority, while personal fragments retain their dependency checks.
- Preserve canonical object keys, provider lifetimes and saved cookie choices.
  Normal activation/update or Refresh sites rebuilds the native module and
  reconciles the shipped policy for all existing enabled sites.

## 0.13.26 — 2026-11-26

- Share public HTML across WordPress admin preference cookies (`wp-settings-`,
  `wp-settings-time-`, `wp_lang`) and the Complianz saved bookkeeping snapshots
  (`cmplz_saved_categories`, `cmplz_saved_services`) in both profiles.
- Bundle source-reviewed reasons in the existing catalogue and generator.
  Preserve original cookies, saved site/central choices, authentication and
  actual consent selectors; `cmplz_id` remains Variant.

## 0.13.25 — 2026-11-26

- Use one verified resolver/source capture in authenticated Warm to populate the
  ordinary ESI parent and a genuinely compiled COMPLETE guest as separate native
  objects through the existing request-owned snapshot backend.
- Preserve each object's own source, context, generation and remaining lifetime.
  Personal visitor delivery and anonymous guest claims keep their normal owners.
- Negotiate the public-only Warm opt-in through an advertised capability and a
  v2 canonical HMAC message. Clients using the original signed `parent-v1` request
  retain normal personal delivery and its original verification contract.
- Report genuine guest population separately; the application still verifies
  an ordinary guest GET/HIT and the exact public parent body.

## 0.13.24 — 2026-11-26

- Refill authenticated UltraCache `parent-v1` Warm requests without personal
  composition: cold fills use the verified request-owned public-source snapshot,
  and hot parents require no private prepare or ESI child requests.
- Return the exact public parent bytes with a request-owned
  `X-UltraCache-Warm-Delivery: public-parent-only` marker. Private work is reported
  as not executed; no personal admission or provider cookie replay is inferred.
- Preserve stored ESI capability, ordinary visitor composition, actual public
  contexts, source lifetime, cookie policy and invalidation.

## 0.13.23 — 2026-11-25

- Remove image-codec-specific HTML cache carriers. Unified UltraCache HTML uses
  one native object across image Accept differences; genuine origin Vary remains
  authoritative, including cookie/locale contexts and HTTP compression.
- Pair the unified HTML integration with UltraCache 3.13.13-dev.1384 publications.
- Keep projection v1 with canonical `html` identity, exact Warm authentication,
  private owner bindings and native representation digests unchanged.

## 0.13.22 — 2026-11-25

- Remove the redundant cookie database status panel and its exclusive actions.
- Add source privacy checks in CI and before packaging.
- Reorganize product documentation and retire the unused independent cookie
  recognition downloader. Reviewed cookie data and defaults remain bundled.

## 0.13.21

Records the exact native finalization acceptance or rejection
reason under the existing masked Debug log. A delivered FILL does not by itself
mean a reusable personal admission was published. Cookies, keys, lifetime,
invalidation and the original response behavior are unchanged. This is
diagnostic support for UltraCache #1054, not a claim that its initial browser
failure is fixed.

## 0.13.20

Connects the existing authenticated complete-guest recipe
to discovery for its exact source parent after Warm. An existing valid private
admission and its bodies can then be looked up without a new prepare just to
learn that declaration. Missing owner admission still requires a real fill;
input, authority, body and lifetime checks remain unchanged. This uses the
existing UltraCache guest-input contract, with no new endpoint or setting.

## 0.13.19

Separates private content invalidation from completed-event
ACK bookkeeping. The existing CAS revision still fences delayed retries; the
matching producer can use stable `contentRevision` for private cache namespaces.
Actual writes and changed generations continue to invalidate cached content.

## 0.13.18

Lets the existing authenticated parent Warm fill active
public Variant Cookie contexts. It keeps the same HMAC/request bindings and
ordinary Private/Authorization routing.

## 0.13.17

Extends complete guest publications to active public Variant
tuples through the existing authenticated resolver/source projection. Original
private provider inputs remain separate; literal no-Cookie guest evidence stays
optional. This integration candidate requires the matching UltraCache producer.

## 0.13.16

Reports request-owned private cache HIT/FILL separately from
correct fragment delivery. UltraCache WordPress dev.1365 uses this diagnostic
to verify Warm readiness without changing ordinary cache admission.

## 0.13.15

Preserves the original public lookup tuple when an actual
issuer selects a different publication tuple. Publication and private input
validation retain their original identities.

## 0.13.14

Settles the original private fragment producer after its
authenticated parent snapshot completes. The next complete HIT no longer needs
an extra prepare/finalize cycle solely because its first fill recovered a parent.
Existing publication, owner, input and provider validation remain unchanged.

## 0.13.13

Keeps verified publication reselection on the ordinary
projected public cache key. It separates that lookup namespace from cold
input validation, so a replacement does not require repeated prepare/reselection.
Owner, nonce, policy and original-producer proof checks are unchanged. Runtime
qualification for this change is tracked in UltraCache #1049.

## 0.13.12

, paired with UltraCache WordPress dev.1360, keeps unchanged
private fragment admissions reusable across public HTML rebuilds. The private
input MAC and admission key retain the exact recipe, representation, owner
inputs and policy but omit unrelated public generation. Original fill proofs
still bind their publication; actual tag invalidation and expiry remain in
force. This does not establish completion of the full live acceptance goal.

## 0.13.11

Also permits the existing authenticated `UC-PRIVATE-GET` operation through the normal loopback application connector and uses the adapter's existing site/source gate for private lookups over Unix sockets. This repairs a real WordPress lookup returning 405 and a direct Unix lookup returning 403.

## 0.13.10

Removes whole-application execution holds from private cache reuse. Actual owner/content tag events invalidate only their dependents; valid complete deliveries do not wait for unrelated backend requests. The native/WordPress producer contract uses signed schema 1.

## 0.13.9

Serves existing public source maps through the existing Nginx
static handler. Missing files retain the original dynamic fallback and query
string. This prevents those static responses from entering the WordPress
mutation receipt boundary; it does not retire existing unknown executions or
resolve directory error responses that lack an application receipt.

## 0.13.8

Correlates a missing or rejected native mutation receipt with
its actual backend transaction using an opaque execution ID and fixed failure
reason in the existing VSL error channel. No cookies, credentials or request
proofs are logged. Failure handling and reuse authority are unchanged.

## 0.13.7

Binds provider mutation receipt cleanup to its actual native
execution owner. Unrelated V2 requests no longer delay that cleanup; the
original pending receipt and legacy/unbound callers retain their required
barriers. A stale V2 DIRTY receipt cannot recreate a collected transaction.
Pair with UltraCache WordPress **3.13.13-dev.1348**. This does not resolve missing
producer journals or by itself prove complete zero-PHP personal cache HITs.

## 0.13.6

Offers explicit identity, exact execution/transaction and counted
quiescence observations through the existing authenticated native control path.
Mutation receipts no longer need to transfer a full scope census on every call.
Native readiness, pending writers, invalidation and complete legacy replies remain
unchanged. Pair with UltraCache WordPress **3.13.13-dev.1338**.

## 0.13.5

Preserves the canonical public cookie lookup key across the
existing private-fragment continuation. Returning from prepare rejoins the same
public parent instead of creating a second MISS from cookie-pair ordering.
Cookie choices, public freshness and Basic profile behavior are unchanged.

## 0.13.4

Preserves browser Cache-Control, Pragma and Expires on bound,
application-approved UltraCache public selections and complete guest snapshots.
Their actual remaining publication lifetime controls shared storage through the
existing application approval path. Surrogate privacy, authentication, cookie
and publication-binding checks remain in force; Basic and legacy sources keep
their existing policy.

## 0.13.3

Adds one failure-only VSL diagnostic for an UltraCache prepare
continuation rejection. It reports a fixed stage, role and first parser failure,
without request values, cookies, credentials or body content. Existing acceptance,
fallbacks and protocol remain unchanged.

## 0.13.2

Separates the UltraCache application's storage approval from
the browser's cache headers and aligns the first projected Variant lookup with
publication. The existing serializer produces a request-owned hash input without
rewriting large classification/Vary headers during continuations. Raw Cookie,
saved choices, Basic behavior and native resource limits remain unchanged. Pair
with WordPress UltraCache **3.13.13-dev.1329** for preserved browser cache headers.
See [application policy](docs/application-cache-policy-1022.md) and
[projected lookup](docs/projected-variant-lookup-1023.md).

## 0.13.1

The 0.13 development work also corrects backend header-slot exhaustion and repeated client
workspace copying during covered UltraCache public-selection continuations.
Only four internal storage carriers are omitted from owned, uncacheable prepare
fetches; their representation inputs remain on the original request and native
continuation. Restoring an already identical original header or URL no longer
allocates another copy. Application Cookie, Authorization, form bodies and the
negotiated execution/coverage protocol are preserved. No Varnish limits, cache
lifetimes or saved settings are changed. See [backend header budget](shared/BACKEND-HEADER-BUDGET.md).

It reuses prewarmed complete guest pages across Shared cookies
when the application's declared provider inputs still match the guest context.
Stateful visitors can reuse qualified private fragments through native cache
objects, preserving their actual provider identity and current publication.
Covered work in progress retains its completion requirements; actual changes,
invalidations and natural expiry use the application path.

The reviewed cookie catalogue **2026.11.23.1** exposes
`ultracache_esi_optin` as a normal Shared default in both profiles, with the
existing Shared / Variant / Private controls. Saved choices remain authoritative.
Diagnostic stage records use the existing masked native Debug channel and
remain off by default. The raw Warm/source-capture fix is included.

## 0.12.11

Routes existing UltraCache raw Warm/source-capture GETs to
its application before guest cache lookup. A hot guest object can no longer
replace the fresh render and dependency registry required by normal Warm.
Application runtime authentication remains authoritative; raw responses do not
replace cached guest HTML. Basic and ordinary visitor cache lookup are unchanged.

## 0.12.10

Reduces request-workspace copying in the cookie policy
compiler and reuses its result only for a native-owned continuation with the
same original Cookie. This addresses retained-browser cookie requests failing
during the internal restart. Cookie actions, raw origin cookies and native
Varnish limits remain unchanged. The native module is unchanged, allowing the
normal overlapping VCL activation to retain registrations and existing objects.
See [request workspace](shared/REQUEST-WORKSPACE.md).

## 0.12.9

Releases completed backend-only cookie, routing and Warm
carriers before adding authenticated UltraCache transport headers. This fixes a
returning-browser header-count boundary without dropping application fields or
changing Varnish parameters, cookie choices, lifetimes or saved panel settings.
The authenticated capabilities response now explicitly advertises the existing
publication-reselection protocol. Same-module overlapping VCL activation retains
the registry and cached objects. See [backend header budget](shared/BACKEND-HEADER-BUDGET.md)
and [publication reselection](shared/PUBLICATION-RESELECT.md).

## 0.12.8

Adds complete anonymous HTML publication to the UltraCache
profile. After the normal warm-up, a new visitor with no Cookie or Authorization
header can receive the complete page, empty-cart markup and usable guest nonces
from Varnish without an application request or origin-backed ESI during HTML
delivery. Any required real cookies are issued separately by the application
after page load, independently for each browser.

Normal warm-up also primes the existing private-capable public parent through
an authenticated, request-bound projection. Acquiring a cookie therefore does
not leave that representation cold. Requests carrying cookies keep their saved
Shared, Variant and Private choices and existing private-fragment delivery.
Basic, cache lifetimes and panel settings are unchanged.

Use the coordinated **UltraCache 3.13.13-dev.1324 or newer**. Upgrade both
components, then use UltraCache's normal cache clear and warm-up to replace old
publications and fill both representations. See the [anonymous publication
contract](shared/ANONYMOUS-PUBLICATION.md) and [qualification and update notes](docs/ANONYMOUS-VALIDATION.md).

## 0.12.7

Corrects stale publication conflicts and application
registration after a Varnish restart in the UltraCache profile. An authenticated
early conflict can select the current public publication once within the same
visitor request, before application providers run. It retires only the exact
stale parent and preserves visitor ownership and once-only provider work. The
registration epoch follows the actual registry lifetime, so the normal application
warm-up can restore registration after a same-build restart. Basic and cache
lifetimes are unchanged. See [publication conflict reselection](shared/PUBLICATION-RESELECT.md).
Use the coordinated WordPress companion **UltraCache 3.13.13-dev.1323 or newer**,
then run its normal cache clear and warm-up after upgrading both components.

## 0.12.6

Lets an unrestricted `Accept: */*` document reuse the warmed
original HTML representation. The origin's Accept header, other negotiated
representations and existing public-response/privacy checks are preserved.
See [wildcard document representations](shared/WILDCARD-DOCUMENT-REPRESENTATIONS.md).
For the separate footer-cookie publication correction, use UltraCache
**3.13.13-dev.1322 or newer** and renew older publications through its normal
cache clear and warm-up after upgrading both components.

## 0.12.5

Applies CMS cookie choices through the ordinary scoped
resolver and reports the current request's prepared private fragment outcome
separately from parent cache HIT. The outcome works with WordPress Debug off;
the optional Debug-only VSL diagnostic remains separate. See [CMS choices](shared/CMS-COOKIE-CHOICES.md)
and the [delivery outcome contract](shared/DELIVERY-OUTCOME.md).

UltraCache prepare requests clear completed routing/selection scratch before
adding their authenticated transport fields, retaining ordinary browser headers
and native Vary inputs at the default 64-entry HTTP header limit. Resource
exhaustion and a real repeated prepare now have distinct diagnostics.
See [backend header budget](shared/BACKEND-HEADER-BUDGET.md).

Cookie Policies uses the low-memory native response bridge from the standalone
0.12.3 fix. The complete editor response is delivered without expanding it into
PHP arrays and encoding it again; the panel's PHP memory limit is unchanged.
The editor has separate Basic and UltraCache action filters; when both are
selected, rows must match both profile choices.

The native loader also fixes false VCL-load failures when compilation takes
longer than ten seconds. The addon waits for the native load result, checks the
complete VCLI status frame and verifies the registered generation before the
normal apply can activate it. Real errors retain the working policy and expose
only a safe category/status; original diagnostics remain root-private at
`/var/lib/varnish-for-webuzo/last-vcl-error.json`.
See [load validation and scope](docs/VCL-LOAD-VALIDATION.md).

Registered UltraCache applications now prepare their public representation on
an eligible cold MISS even without resolver-cookie variants. Plain warm HITs
retain zero backend work. See [cold public selection](shared/COLD-PUBLIC-SELECTION.md).

Observed server-cookie publications can negotiate a separate
[cookie-only delivery contract](shared/COOKIE-ONLY-DELIVERY.md). A marked HIT
reuses public HTML and executes its actual application issuer once per visitor,
including its real consent and lifecycle decisions. Original cookie fields stay
request-owned. Unmarked plain pages keep their zero-backend path; Basic keeps
its existing best-effort behavior without ESI. Existing old WordPress publications
need the application's normal capability redetection, cache clear and warm-up
after both compatible components are upgraded. A native addon update does not
rebuild an old local application snapshot. See the [qualification record](shared/COOKIE-WARM-VALIDATION.md).

The UltraCache profile adds request-owned pre-header cookie
delivery, scoped private-fragment TTL, actual application-private documents and
public-fragment TTL/error containment. **Basic stays best effort without ESI.**
Cookie Database remains the sole cookie classification authority. Profiles provide
independent cookie choices and [application-scoped public selection](shared/PUBLIC-SELECTION.md),
including actual provider context before lookup and private streaming/range
delivery. Common bundle `2026.11.21.1` keeps personal commenter, YITH, Recently
Viewed, cart/session and User Switching defaults Private in Basic and Shared in the integrated UC
profile; manual choices still win. The [current qualification record](shared/COOKIE-WARM-VALIDATION.md)
separates native, application and installation checks; [earlier evidence](shared/ESI-VALIDATION.md)
remains the historical record for 0.22.0/0.11.0.
