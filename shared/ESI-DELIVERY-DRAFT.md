# UltraCache delivery continuation: design draft

Status: **isolated candidates, not release/full-goal acceptance**. The Hestia
original-URI continuation checkpoint `35b1111` passed its native mock fixture;
real application/provider acceptance and Webuzo native qualification remain
separate. Scoped private TTL and its version handshake now have an isolated
native implementation/qualification; see PRIVATE-TTL-DRAFT.md for exact
checkpoints and the remaining actual application acceptance boundary.
Related UltraCache issues: #955, #956, #957, #958, #959. Native acceptance must
precede release or activation.

## Implemented transport revision 2

On an internal UltraCache private ESI backend request the VCL sets
`X-UltraCache-ESI-Transport-Version: 2`, along with the existing
`X-ESI-Private-Request: 1` and `X-ESI-Request-Level: 1` markers. It strips every
incoming transport-version value in receive, and sets the version afresh in
backend-fetch. Ordinary parent/public-child backend requests have no version
header. A version string is a capability report, not authentication.

The request-local candidate carrier contains only these case-sensitive names:
`esi_session`, `woocommerce_items_in_cart`, `woocommerce_cart_hash`,
`wp_woocommerce_session_*`, `woocommerce_recently_viewed`,
`wordpress_logged_in_*`. Raw values and their order are retained. They never
enter a public object or its include URL. All public children have Cookie
removed. Native adapters reject cross-site ESI before transport.

These are transport candidates, not a second classification list. The
application verifies the existing signed fragment descriptor, selects only the
renderer-declared cookie names/prefixes and validates actual WordPress login
cookies. Authenticated identity is never accepted from a shared descriptor.
The signed private capability probe must observe revision 2 before the plugin
emits renderers requiring the added history/auth transport; older VCL retains
the plugin's native fallback. The proxy does not add a background probe.

Cookie policy sees the original protocol-marker names before transport cleanup.
An explicit Private choice still PASSes, and an explicit Variant still hashes
its value. Only unhandled marker pairs are omitted from the internal protocol
remainder; ordinary parent backend requests remove these protocol markers
there. The existing raw signed source collector retains its original wire.

Private children still always PASS. Positive private TTL, cookie issuance on a
parent HIT, and generic arbitrary renderer-cookie transport are not revision 2.

## Why ordinary child delivery cannot issue parent cookies

Parent `vcl_deliver` precedes ESI body insertion; parent HTTP headers have
already been sent when children run. Capturing a late child Set-Cookie in
`PRIV_TOP` does not make it deliverable in those earlier headers. Disabling
streaming alone is not a qualified solution. The current handoff owns only
top-level fetching-client fields, with separate backend/client `PRIV_TASK`
association and finalization. It has no HIT issuer or preflight API.

References: https://www.varnish.org/docs/users-guide/esi/ and
https://www.varnish.org/docs/reference/vmod/ .

## Native pre-header continuation v1: candidate source (#956)

This code runs only for the UltraCache profile. Basic remains a best-effort
HTTP cache without ESI composition or a prepare operation. This draft is not
native/compiler/browser acceptance and must not be deployed as qualified code.

### Minimal application wire

An otherwise cacheable origin-approved ESI parent supplies:

- `X-UltraCache-ESI-Shared-Parent: 1`
- `X-UltraCache-ESI-Private-Count: N` (all private-capable occurrences, including
  anonymous adaptive nonces and repeated includes)
- `X-UltraCache-Delivery-Prepare: /index.php?ultracache_delivery=<signed-manifest>`
  (use the actual installation subdirectory; same-host relative metadata pointer).
  This pointer transports the token and is **never requested** by the application
  prepare transaction.

The manifest must bind the original public route/representation and the full
set of private-capable include URLs, signed contexts and occurrence counts.
It must contain no visitor identity, cookie values or private output. Public
snapshot approval remains distinct from a fresh personalized render.

Before serving an eligible **GET HIT**, native request-owned state saves the
original URL, Host, complete original Cookie, encoding and conditional/range
headers. It restarts into prepare at **the exact original d.url**, retaining
its original path, duplicate query parameters, percent escapes and plus signs,
and always PASSes that request. No internal parameter is appended to its query.
PHP/plugin bootstrap and `filter_input` therefore see the real original inputs
from the start, without reconstructing `$_SERVER`/`$_GET` later.
The native backend hook sets these headers afresh:

```http
X-UltraCache-Delivery-Version: 1
X-UltraCache-Delivery-Phase: prepare
X-UltraCache-Delivery-Manifest: <decoded-once ASCII signed token>
X-UltraCache-Delivery-Request: <request-owned decimal handle>
X-UltraCache-Delivery-Original-URL: /original/path?original=query
X-UltraCache-Delivery-Authorization: <existing native per-site application/purge credential>
Cookie: <unchanged complete original request Cookie>
```

Manifest extraction contract: native reads exactly one nonempty **literal**
`ultracache_delivery` query value from the metadata pointer. Duplicate matching
parameters and malformed percent escapes are rejected. It percent-decodes that
value exactly once using raw URL semantics (`+` remains `+`), and requires a
nonempty printable-ASCII token without spaces or controls. For example,
`signed%2Bmanifest%252Ftoken` becomes the header value `signed+manifest%2Ftoken`.
Other pointer query metadata is not forwarded or used as application input.
The UC verifier consumes the header verbatim: **no second urldecode**. The whole
original metadata pointer remains request-owned for final parent binding.
The native pointer/token never replaces the actual application request URL.

All browser copies are stripped. The request handle only associates the two
native tasks; it is not a session, credential or authentication proof. The
application must verify its signed manifest, original-route binding and trusted
proxy entry point. Headers alone do not authenticate direct access to origin.
Direct untrusted calls must be refused, not treated as approved continuations.
The Hestia and Webuzo adapters populate Authorization from the active
UltraCache site's existing token only after `delivery_backend()` proves the
native-owned prepare association. Missing credentials stop before origin.
Incoming Authorization and Manifest are removed in receive/backend-fetch;
native sets Manifest only on its owned prepare. Origin echoes are
removed before storage and again before client delivery. The token is never
taken from parent metadata, client input or an ESI URL. UC must compare it with
the actually configured matching per-site credential using constant-time
comparison, in addition to validating the manifest and original route.

Connection-mode acceptance is explicit: HTTP purge mode can use that existing
site token. UC's native admin/CLI mode instead retains the native admin secret
byte-for-byte; that is **not** the adapter's per-site token. This candidate does
not forward a global admin secret to origin, generate a key, add UI or create
a reverse configuration bridge. Local/admin/CLI integration must possess and
verify an already configured matching per-site application credential before
enabling delivery admission. Support for those connections remains open until
that path is implemented and tested; the version header alone cannot close it.

The existing signed private capability probe can observe
`X-UltraCache-Delivery-Version: 1` separately from transport revision 2 and
adaptive nonce revision 1. No new UI/probe/background worker is introduced.

The application recognizes the authenticated internal prepare in advanced-cache
and skips the public-cache read while permitting real WordPress bootstrap under
the unchanged route/query. At the normal WP hook it completes signed manifest,
representation, registry and original-URL validation before issuing the envelope.
`originalUrl`, the native Original-URL header and actual request URI must agree.
The endpoint executes the real provider lifecycle under that original route,
then renders **every private-capable include in the manifest**, even when an
adaptive nonce currently uses anonymous identity. It renders each distinct URL
once and reuses its output for repeated occurrences. Identity and consent are
resolved by the actual application/provider, not by rewriting a proxy Cookie
jar. Return status 200, identity encoding, private/no-store headers, authentic
repeated `Set-Cookie` fields and this UTF-8 JSON body:

```json
{
  "schemaVersion": 1,
  "requestId": "123",
  "originalUrl": "/article?public=1",
  "renderedFragments": [
    {
      "url": "/index.php?ultracache_esi=<signed-private>&esi_scope=private",
      "html": "<div>actual provider output</div>",
      "occurrences": 2
    },
    {
      "url": "/index.php?ultracache_esi=<signed-adaptive>&esi_identity=wordpress",
      "html": "actual identity-bound nonce output",
      "occurrences": 1
    }
  ]
}
```

URLs must be the exact relative URLs emitted in the parent's ESI attributes
(after HTML entity decoding), with no foreign host or fragment. `html` is final
renderer output, not a request to execute the renderer again. Nested private
ESI inside that output is not implemented by this synthetic replay path.
The sum of positive occurrence counts must equal the parent's Private-Count;
duplicate URL entries, duplicate JSON keys, unexpected schema properties,
mismatched request/route binding and invalid URL forms are rejected. The UC
producer must additionally verify that the manifest's complete URL set was
rendered; the proxy cannot inspect a signed opaque application descriptor.
No `childContexts`/effective Cookie substitution API is needed for this wire:
all private-capable results are already rendered against actual provider state.

### Native ownership and control flow

`shared/native/delivery_continuation.c` extends the existing cookie_handoff
module. Its VFP is registered using the installed engine's `VRT_AddFilter` API.
The prepare response uses `beresp.filters = "uc_delivery_capture"`, TTL/grace/
keep zero, uncacheable delivery and `beresp.do_stream = false`. Its full body
is captured during fetch, **before prepare vcl_deliver**; no late ESI child
header aggregation is attempted. Repeated provider Set-Cookie fields are copied
verbatim without comma splitting, expiry rewriting or name reclassification.
The prepare fetch's private transient object is never a reusable parent object.

Backend/client association uses the existing locked handoff table. Continuation
ownership is PRIV_TOP so it survives the two trusted restarts and is visible to
ESI children; ordinary MISS handoff retains its existing PRIV_TASK reset path.
The capture filter retains an integer backend association, not a client pointer,
so client abort removes the table entry before private state is freed. Completed
capture and envelope validation precede restoration/restart of the parent route.
Native restart bounds apply. Retries cannot repeat an owned prepare operation,
and connection retry is disabled for that operation.

On return, only the same selected parent identity and signed manifest/count may
be delivered. The examined Vinyl 9.1 `cnt_deliver` source stashes objects across
restart, but the actual installed Varnish 9.1 reports a different revision/VRT
API; that source review does not establish the installed lifetime. Native
retention/eviction qualification remains open. The candidate does not swap
engine object pointers or call uninstalled private HSH APIs. The original baseline returned pre-header 503 on post-prepare MISS/replacement.
The gated source extension below can recover the same UC public publication;
missing/replaced application publication and request-owned replay remain open.
A private/full-origin PASS still cannot silently rerun provider work.

Before final parent headers are sent, the authentic provider fields are appended
only to this visitor's response. The browser response is private/no-store while
the public parent remains internally reusable. ESI children matching a prepared
URL are private synthetic bodies from PRIV_TOP; repeated occurrences reuse the
same output. An unprepared private/adaptive child cannot silently rerun origin.
Ordinary public children keep their existing cookie-free path. Initial MISS,
HEAD, private/full-origin PASS, pages without the signed contract and Basic do
not initiate this HIT continuation. The existing MISS provider-delivery path is
preserved; its application lifecycle still needs combined acceptance.

There is no additional fixed byte-size or fragment-count product limit in the
native continuation. Existing UC output/parent-fragment settings remain the
application authority, including their existing 0/unlimited semantics. Native
capture uses overflow-checked size_t arithmetic and actual allocation failure;
occurrence counts use representable native integers with checked exact sums.
Neither path silently truncates output. The portable parser accepts only this
fixed schema, with no recursive general JSON values. Failure is explicit before
successful parent delivery where detectable; native/error/abort/retry/eviction
fixtures and actual provider semantics remain mandatory acceptance.

### APIs verified from primary 9.1 source

Official release: https://vinyl-cache.org/releases/rel9.1.0.html
(source archive https://vinyl-cache.org/downloads/vinyl-cache-9.1.0.tgz).
Examined `cache_filter.h`, `cache_fetch_proc.c`, `cache_fetch.c`,
`cache_req_fsm.c`, `cache_vrt_priv.c`, `cache_vrt_var.c`, `vrt.h` and `vrt_obj.h`:
VRT_AddFilter/RemoveFilter, VFP init/pull/VFP_Suck,
non-streaming fetch completion, deliver-to-restart before transmit, PRIV_TOP
lifetime and VRT_l_resp_body with a magic-initialized blob. The installed
matching development headers/ABI are still authoritative at compilation.

The first real installed-9.1 build of candidate `14fe805` failed before tests:
`vjsn.h` was absent from the development package. An archive header is not proof
of an installed VMOD API. The revised candidate removes that dependency:
`delivery_envelope.c/.h` is our bounded, standard-C delivery-v1 schema parser,
with strict JSON/UTF-8, Unicode escapes/surrogate pairs, decoded duplicate-key
checks, exact bindings, URL validation and all-or-nothing fragment ownership.
There is no third-party JSON library, fabricated engine header or added package.
The normal native builder copies, hashes and compiles this source with the VMOD;
policy source identity and adapter-parity receipts also include it.
`tests/test_delivery_envelope.py` compiles and executes that actual portable C
parser independently of Varnish. Such component tests do not qualify the rest of
the VMOD; the corrected full native build and continuation tests remain pending.

### Native compile/runtime checkpoint and source correction

The coordinated installed-Varnish 9.1 build of `37db2b9` passed. Its five mock
continuation tests ran without skips, but only Basic passed; HIT paths disconnected.
A retained single-case diagnostic identified a child panic in `http_ForceField`:
that API only accepts METHOD/PROTO, not HTTP_HDR_URL. Both prepare and restore
URL changes now use the public `VRT_l_req_url(ctx, NULL, TOSTRAND(url))` setter,
with workspace-owned URL text and the macro-initialized STRANDS argument.
The coordinated targeted rerun and all five mock continuation tests then passed
for `68dbcce`, zero skips (suite 26.760 s). Covered repeated Set-Cookie/replay,
invalid binding/schema/count/duplicate rejection, 24 concurrent owners, Basic
nonparticipation and the explicit post-prepare-MISS 503 guard. That guard is not
completed recovery. This is native mock transport/lifecycle evidence for that
exact old pointer-route checkpoint, not actual WP/provider equivalence.
The newer unchanged-original-URI/Manifest-header Hestia candidate `35b1111`
also compiled and passed its five adapted native tests, zero skips, in 27.485 s.
Private DSO SHA256:
`de0638ce23a27fc1d9062d69e3795035455c7169d583219020045b5b1369d768`.
This checkpoint covers the exact URI/query and Manifest extraction/spoof/echo
wire in the mock origin fixture. It does not qualify the new UC bridge's real
WP bootstrap/filter_input/provider behavior or Webuzo's native adapter merely
because common sources match. The retained diagnostic identified actual engine revision
`ffd36e9db9a1ec2bf6637deda180a87d40a13d0f`, VRT API 22.2. The Vinyl 9.1 archive
review above is not a substitute for this installed engine's headers or exact
object-lifetime implementation; parent-retention/restart qualification remains
open alongside seamless parent recovery.

## Gated public-publication recovery: source candidate only

The exact installed revision above confirms Req_StashObjcore on deliver restart,
but exposing an object to a new hash lookup after purge is a different operation.
The candidate does not import private HSH prototypes or swap cached object refs.
Instead, an application that actually implements an early snapshot-only path may
explicitly confirm this on its authenticated prepare response:

```http
X-UltraCache-Delivery-Recovery: public-snapshot-v1
```

The native prepare/private capability request declares
`X-UltraCache-Delivery-Recovery-Version: 1`; this version alone is not application
readiness. Older bridges without the response confirmation cannot enter the new
phase. This prevents an unsupported phase from accidentally running the ordinary
WP/provider lifecycle a second time.

On a post-prepare parent MISS, native uses the existing owner association for one
backend GET at the exact original URI, carrying the same Manifest, Authorization,
Request and Original-URL fields, but `Phase: parent-snapshot`. The UC early reader
must return the existing atomic public publication only, after normal public-cache
selection/guards and exact signed locator/representation/body-generation/fragment
set binding. It must not bootstrap WordPress, invoke a provider, rebuild a template
or issue cookies. It must refuse missing/mismatched publications without falling
through to ordinary application execution.

A successful snapshot response returns status 200, the original approved public
ESI body/metadata, exact Prepare pointer and Private-Count, its **remaining** allowed
fresh/stale lifetime, no Set-Cookie, and these bound proof fields:

```http
X-UltraCache-Delivery-Recovery: public-snapshot-v1
X-UltraCache-Delivery-Request: <same owned request handle>
X-UltraCache-Delivery-Original-URL: <same original path/query>
```

Native validates the response before removing ephemeral fields from storage and
client delivery. Its normal fetch/ESI parser then processes the public parent;
prepared private fragments and authentic provider cookie fields are reused from
PRIV_TOP. A replacement object with the exact generation-bound signed locator
and count can be used when the application has confirmed this contract. A changed
locator queues at most one authenticated snapshot attempt, within native restart
bounds. Wrong binding, any Set-Cookie, missing publication or failed snapshot is
an explicit error, never a second provider invocation.

This is **not full seamless recovery**: if the selected UC publication itself is
gone/changed after prepare, the early reader cannot reconstruct it. Request-owned
capture of the exact public body before side effects and replay through the native
fetch pipeline is still being designed. A compact signed locator with URL/public
representation, body generation and fragment-set digest avoids putting a large
fragment URL list in HTTP headers; the full list remains in the existing public
publication metadata. No new store/worker or artificial size/count limit is added.

The source also fixes an existing prepared-parent guard that could block an
ordinary **public** child MISS/PASS: parent-refetch guards now apply only at ESI
level 0. Missing private/adaptive prepared children retain their dedicated refusal;
ordinary public children remain cookie-free on their normal fetch path.
A new native-only test performs a real purge of its disposable parent during
prepare, expects one snapshot-only recovery fetch, the already prepared private
output/cookies, and a fresh public child fetch. The coordinated `daef370` native
build and all six mock continuation tests passed, zero skips, in 29.924 s;
DSO SHA256 `3c0e86c8ddaa9cef46eba0f7b669816b7e89799648d73c35311d4782d9cbff2c`.
This is exact-checkpoint mock evidence, not a real application-publication loss
test or qualification of newer staged source. It was not run by this source chat. Existing
mock tests without recovery confirmation retain the baseline guarded behavior.

### Request-owned public snapshot: isolated memory-backend candidate

An optional prepare-envelope `publicParent` is now accepted by the portable
source parser with exactly these fields:

```json
{"generation":"<64 lowercase SHA256 hex>","bodyBase64":"<canonical PHP base64_encode identity bytes>","freshRemaining":0}
```

It contains the exact public publication bytes, not a personalized fresh render.
The authenticated UC early reader must verify the selected publication's signed
locator, representation, fragment set and body generation before provider side
effects. The native parser validates the generation's syntax and exact Base64
bytes; it does not replace that application signature/body-generation check.
There are no application-supplied responseHeaders; the design keeps the selected
public parent headers and remaining native lifetime separately before prepare.
The replay TTL is bounded by the selected object's remaining TTL and the
authenticated prepare response's `freshRemaining`, subtracting elapsed time.
The refill grants no new grace/keep. Zero freshness permits only the current
delivery; it must not reset cache lifetime.

This isolated source now emits
`X-UltraCache-Delivery-Request-Snapshot-Version: 1` on its owned prepare and
existing signed private probe. An authenticated prepare may confirm
`X-UltraCache-Delivery-Recovery: request-snapshot-v1` only with a valid
`publicParent`. Old `public-snapshot-v1` origin recovery remains compatible.
This declaration is a qualification candidate, not a release readiness claim.

For request-snapshot recovery, a native VCL-owned director supplies the saved
public headers plus the request-owned public bytes. The `uc_request_snapshot`
source filter feeds the ordinary native `esi` filter, allowing prepared private
children to synthesize their existing result and public children to retain
normal routing. There is no HTTP origin recovery call, provider execution,
object-reference replacement or persistent body/visitor cache. The handoff
table contains only request-owned associations; cleanup/abort removes them
before freeing the body. Native backend reads use an integer key under the
same lock, never a retained client pointer.

`test_request_snapshot_survives_publication_loss_without_an_origin_recovery_fetch`
purges the actual disposable parent during prepare, removes the mock
publication, checks authentic headers/prepared fragments/public child, and
checks that zero freshness cannot refill a fresh object. Another case rejects
readiness without a valid body. Root qualified the original eight cases at
`0c684e1` on native Varnish 9.1/VRT 22.2, zero skips. The private native module
SHA256 was `0836c4272e33ba146e11b1d83342f56e412ec2f3480c32363e361baa67a8702e`.
Root then qualified the initial-publication-MISS delta's ten-case suite at
`1ff2026`, zero skips, and the positive VSL source delta at `03b5b18`.
Actual root-owned WP/Woo runs also exercised proxy purge and simultaneous
application-publication/proxy purge during prepare, retained current public
generation/correct visitor cookies once, then new-generation cold/refill/HIT.
These are exact narrow paths, not proof of every initial-MISS provider lifecycle.
The virtual fetch design requires the actual installed `cache_int.h` http_conn
structure; that is an explicit internal, strict-ABI dependency, not a public-only
API claim or permission to fabricate an engine header. No private HSH prototypes
or cache-object pointer swaps are used. Narrow after-prepare publication loss
has the evidence above; generic fresh-body/initial-MISS lifecycle requirements
remain distinct. Missing/changed publication before prepare must be rejected
before provider side effects; a request snapshot cannot invent those bytes.

## Positive private TTL is a separate admission contract

See `PRIVATE-TTL-DRAFT.md` for the scoped native-object design and explicit
renderer-admission gap; it is not an implementation or positive-TTL capability.
Retain TTL 0. A positive value needs an authenticated native private partition
binding site, fragment, signed context/representation, verified user/session
identity and mutable-state generation. A missing identity must not collapse all
anonymous visitors into one private key. Changed cart/session/logout/nonce
state must invalidate or advance only the affected partition. Existing exact
URL/host purge does not provide this session-generation contract by itself.

Never enable storage merely by removing private/no-store or forwarding a TTL
header. Browser responses containing personal content remain private; private
fragment objects must not replay personal Set-Cookie. Cookie Database choices
remain the only classification authority, independent of transport/admission.

## Adaptive nonce identity revision 1: candidate wire contract (#957)

Revision 2 alone does not solve anonymous-parent -> logged-in visitor reuse.
A cached `wordpress-nonce-public` include still requests a public child; that
child correctly discards Cookie and generates a UID-0 nonce. Adding an auth
cookie to the private carrier cannot change that include's semantics.

The application signs descriptor `wordpress-nonce-adaptive` with context
`{action, identity: 'wordpress'}` and emits `esi_identity=wordpress` alongside
the existing `ultracache_esi=<signed-descriptor>` query argument. It verifies
that the selector matches that signed claim, and refuses the selector on an
ordinary public/private fragment. VCL sees a routing selector, not the opaque
descriptor's verified contents. The descriptor never contains a user ID.

- An action declared private additionally uses `esi_scope=private`, always
  taking the existing private PASS path even without any identity cookie.
- For a public action, a request-local `wordpress_logged_in_*` or
  `wp_woocommerce_session_*` candidate makes this adaptive child private PASS.
  The application validates the actual identity/session, selects the declared
  cookies and renders the appropriate nonce. Cookie presence is only a routing
  candidate; it is not a validated user or a new cookie classification rule.
- Without either identity candidate the adaptive child is cookie-free, uses
  the public nonce/action TTL and can reuse its anonymous fragment object.
  Ordinary public fragments remain cookie-free for every visitor. History,
  tracking and `esi_session` alone do not select authenticated nonce identity.
- Receive strips incoming `X-UltraCache-ESI-Adaptive-Nonce-Version` and
  `X-SCP-Adaptive-Nonce`. Backend-fetch generates
  `X-UltraCache-ESI-Adaptive-Nonce-Version: 1` only for internal private children
  (including the existing signed private capability probe) or adaptive children.
  It never appears on an ordinary parent/public child merely because the
  browser supplied it. The internal routing scratch is removed before origin.
- Capability observation is separate from transport revision 2; it adds no
  request or UI control. Older VCL must use the native application fallback.
  A declared version is not native acceptance or positive-private-TTL support.

The application registers this descriptor as **private-capable** and includes
each adaptive occurrence in the parent's existing
`X-UltraCache-ESI-Private-Count`. That count must be positive even when the
parent was produced for an anonymous visitor and that occurrence currently
renders a public nonce. The existing parent `vcl_deliver` therefore marks the
assembled browser response private/no-store **before** headers are sent. The
parent object remains internally reusable across visitors.

A separate adaptive counter is unnecessary for correctness with that invariant.
Reusing privateCount also marks the anonymous assembled browser delivery
private/no-store, conservatively; it does not disable Varnish parent HITs or
the anonymous public fragment's internal TTL. An origin declaring privateCount
zero while inserting an identity-adaptive include would violate this contract.
Existing old parents containing `wordpress-nonce-public` cannot gain adaptive
identity merely by upgrading the carrier; regenerate/invalidate them when the
application starts emitting the new descriptor.

Required acceptance is one unchanged stored parent reused by anonymous, user A
and user B, with successful real WordPress REST actions for the respective
owner and cross-user rejection. A nonce string, cookie marker or passing
fragment transport test alone does not establish this behavior.

## Acceptance still required

### Admission is distinct from privateCount

In the current candidate, a top-level UltraCache opt-in requests composition
independently of Woo cookie names. For that request:

| Native phase | Existing admission condition |
| --- | --- |
| Cold backend response | Otherwise cacheable, `X-UltraCache-ESI-Shared-Parent: 1`, and `beresp.do_esi` enabled. |
| Warm object | `X-UltraCache-ESI-Shared-Parent: 1` or the existing `X-UltraCache-Woo-Async-Parent: 1`. |

`privateCount` controls final downstream privacy only. It does not substitute
for those admission checks. The application must generalize shared-parent
approval beyond its Woo-mini-cart-only producer for qualified registered
private widgets/adaptive templates. A positive count by itself never proves
that the rest of a fresh personalized render is public. Public-only approved
ESI parents should explicitly send privateCount zero.

An already-public stored snapshot and a new personalized origin render are
different provenance cases. In particular, an opt-in cold response without ESI
still fails the current cold admission check even if it is an already-public
snapshot. Do not fabricate ESI or shared-parent approval merely to bypass that
check. General non-ESI snapshot admission/provenance is a remaining #959 review;
adaptive nonce revision 1 does not change that behavior or prove it correct.

### Combined execution

Additional native regression prepared after actual WP Sourcebuster evidence:
an approved ESI parent with real `Vary: Cookie` warms without Cookie, then must
remain the same object for seven default-Shared Sourcebuster cookies, different
Shared values and no Cookie again. The internal ESI vary carrier must be absent
for all empty resolved remainders, rather than present-but-empty only when the
browser sent Shared cookies. Shared fixture case
`Approved ESI Cookie Vary shares the no-cookie object across all Shared Sourcebuster values`
uses one parent generation, a real public ESI child and increasing parent HIT
counts. This narrow canonicalization does not reclassify Private/Variant cookies
or change their nonempty key dimensions. Native regression execution is pending;
the earlier continuation mock parent omitted Cookie Vary and did not cover it.

The following are explicit open acceptance items, not consequences of preserving
the existing code or of an earlier transport/adaptive-nonce checkpoint:

| Case | Required evidence | Current candidate limitation |
| --- | --- | --- |
| Initial parent MISS; provider first creates/renews/deletes a cookie inside a private child | Real WP/Woo/provider execution with issuer counters, original repeated fields in the **first parent response headers**, correct child content and browser session on revisit; two independent visitors and consent denial. | The existing MISS handoff captures only fields available from the top-level origin fetch. It does not prove delivery of a cookie first created after parent headers in an ESI child. The mock fixture's cold children issue no cookie and cannot cover this gap. |
| Provider bootstrap and repeated private renderers on MISS and HIT | Actual provider bootstrap and each distinct stateful renderer execute the required lifecycle once; repeated occurrences reuse output, with no duplicate issuer side effect and no personal data in the public parent. | HIT preflight has candidate replay code only. Initial MISS may need request-local pre-render handoff within normal WP execution; that mechanism is not implemented or inferred from HIT capture. |
| Parent expiry, purge or replacement after prepare | Native fault injection between prepare and resumed delivery; valid final page and visitor cookies, no repeated provider/issuer work, no cross-request leakage and correct cleanup. | The request-owned snapshot source now has native mock and narrow actual WP/Woo after-prepare purge/recovery evidence above. Missing publication before prepare must reject before side effects; generic new-body/first-cold lifecycle remains separate, not inferred from this recovery. |
| Positive private fragment TTL | Native identity/state partitioning, actual reuse before expiry, refresh on expiry/state changes and targeted invalidation; two visitors/two users with no cookie or content replay across owners. | An isolated native lookup/fill + application claim producer exists; see PRIVATE-TTL-DRAFT.md for exact native evidence. Actual independent renderer/state/storage audits remain required. TTL 0, a header or a counter embedded in cached HTML alone is not positive-private-cache acceptance. |
| Prepare entry proof across HTTP and native admin/CLI/local connections | Matching existing per-site application credential, signed manifest/original-route checks, forged public-origin rejection and no credential in URLs/shared objects/client responses; actual endpoint acceptance in each supported mode. | Per-site backend-only header is prepared in the adapters. HTTP configuration can match it; an admin secret is a different credential and is not forwarded as a substitute. Non-HTTP credential/admission and native endpoint verification remain open. |

Do not hide the initial-MISS case behind a 503 or treat it as covered by the
temporary post-prepare eviction guard. Any first-MISS handoff must use actual
application/provider lifecycle and request-local output, preserve standalone
UltraCache, and remain specific to UltraCache ESI rather than changing Basic.
An existing parent-HIT/adaptive-nonce browser success must identify its exact
source checkpoint; it does not qualify a later continuation VMOD or these open
cookie-lifecycle and private-TTL paths.

Both adapters, actual current UltraCache and native Varnish: MISS/HIT/HIT,
two anonymous visitors and two logged-in users, empty/new/active/deleted
sessions, Recently Viewed history updates, consent denial, multiple Set-Cookie
fields/attributes, repeated fragments with one provider execution, nonce action
success after state changes, TTL 0/positive/expiry, targeted invalidation,
spoofed headers, prepare failures, eviction/restart/abort and no-JavaScript
composition. These are pending requirements, not claims of completed tests.

### Initial native MISS from an early existing public publication

The application's normal early publication reader may emit the ephemeral
`X-UltraCache-Delivery-Parent-Source: public-snapshot-v1` only when it serves
already stored public bytes before WordPress/provider bootstrap, with no
Set-Cookie. It is not UC publication metadata, a fresh WP response marker,
or a declaration for the prepare/parent-snapshot endpoints. Native receive
and backend-fetch remove caller copies. Backend-response captures proof
before cookie detachment and only when the actual origin has no Set-Cookie.
The public marker and internal marker are removed before browser delivery.

An otherwise cacheable approved ESI parent with positive privateCount and
bound Prepare may start the existing pre-header continuation on this proven
MISS as well as on a HIT. It uses the same selected object/request ownership,
two-restart prepare and parent-loss recovery. It does not add a preliminary
restart or repeat the early reader's provider work (there was none). Native
MISS/PASS after a fresh WP bootstrap remains a separate initial-MISS issuer
contract; do not emit this proof to conceal that gap.

Candidate fixtures verify the first parent response contains actual prepare
cookies and prepared private output, no cold child/provider replay, and that
a browser spoof or origin Set-Cookie prevents first-MISS preparation. These
new cases require native execution; prior tenets of HIT/recovery acceptance
do not automatically qualify them. Basic stays outside this path.

### First-cold personal visitor copy: pre-aggressive native invariant

The application may retain finalized PUBLIC bytes for its existing collector
and publication, then render distinct private fragments once in the same real
WP/provider context and inline them only into the visitor delivery copy. The
collector must never receive that visitor copy. This native guard is not proof
of that application-side split or of first-cold provider lifecycle completion.

Existing response metadata identifies that actual personal copy: exact
`X-UltraCache-Cacheable: 0`, a positive canonical
`X-UltraCache-ESI-Private-Count`, and no
`X-UltraCache-ESI-Shared-Parent: 1` approval. Only for the UltraCache profile,
before aggressive override or response-cookie detachment, native VCL marks
this response uncacheable and forces private/no-store. Its derived internal
marker prevents aggressive storage override; the normal aggressive scratch
cleanup still runs. All original repeated Set-Cookie fields stay attached,
even if every name is Shared in Cookie Database. This is actual body provenance
and does not change cookie classification, add a cookie list or add a control.

The guard preserves an existing `ESI/1.0` Surrogate-Control token for remaining
PUBLIC includes while adding no-store. Thus a fully composed personal response
is delivered literally, or public includes are composed by the existing ESI
path without caching the personal parent. Uncacheable parent delivery cannot
start another pre-header prepare, so no second provider bootstrap is added.
The application omits Parent-Source proof and Shared-Parent approval on this
fresh personal copy; approved stored public bytes keep their existing path.
Basic remains best effort, without ESI or this UC metadata rule.

`test_cold_personal_delivery.py` covers anonymous first response, another Shared
cookie visitor, mixed response cookies, exact attributes, literal personal
body/no cross-visitor replay, aggressive off/on, remaining real public ESI,
no second prepare, and Basic's unchanged public-cache behavior. Caller and
origin copies of the derived scratch marker cannot enable the guard. Root
qualified exact Hestia `34934bb`: all 16 native methods (including these two
and their four UC subcases) passed, zero skips, 87.424 seconds, using the
byte-identical `f09eaad` native DSO documented in PRIVATE-TTL-DRAFT.md. Actual
cold WP collector/visitor-copy separation and genuine renderer-only issuer
cookies remain root's combined application/browser/storage acceptance.

### Webuzo gateway ingress on an owned continuation restart

The root-owned generated-policy run of frozen Webuzo `358898b` executed 16
native tests but failed (18 subfailures, primarily 403 before prepare). The
focused native trace confirmed valid initial gateway authentication followed
by request-header removal, vcl_deliver restart, then top-level ingress 403
before any provider prepare. Hestia's separately qualified paths remain valid
at their exact checkpoints; this Webuzo failure is not hidden by common-byte
parity or a skipped/relaxed assertion.

The candidate fix keeps the normal Webuzo gateway comparison and removes its
request copy exactly as before. It does not retain a raw gateway header or
authorize a positive restart count alone. Only UltraCache may use the read-only
`delivery_resume_authorized(PRIV_TOP, adapterSite)` fallback: native owned
queued/return/recovery-queued phase, its exact expected restart, top-level GET,
no failed state, the stored immutable adapter site, canonical Host and exact
original URI must all match. The site was captured from native adapter-assigned
X-SCP-Site when the already authorized parent began its continuation. No
client header or another request can create/reuse that native PRIV_TOP grant.
The predicate advances no state; the existing delivery_recv still performs
the single owned transition after ingress. Basic cannot use the fallback.

The gateway is stripped from every backend request and origin/client echo.
The Webuzo-only `test_continuation_gateway.py` verifies valid continuation,
wrong/missing initial gateway and forged client phase/site/association denial,
no gateway forwarded to ordinary/prepare/public-child origin, no client echo,
and no cross-request authentication reuse. Independent restart fault cases
change site, host, URI or the expected native restart and require 403 before
any origin/provider execution.
The shared C/API changed for this proof; a matching rebuilt DSO and native
Hestia/Webuzo reruns are required. This new fix is not yet native-qualified.

### Actual application-private complete document (candidate)

An authenticated original-route prepare may discover actual private application
state which belongs to the complete native template, rather than its selected
fragments. The application must decide this before rendering those fragments.
For example, a pending WooCommerce notice is application state, not evidence
from the presence or name of a cookie. Native VCL contains no Woo-specific
cookie override or second cookie classification list.

The existing signed private probe and an owned prepare advertise
`X-UltraCache-Delivery-Private-Document-Version: 1`. Caller copies, ordinary
backend requests and origin/browser echoes are stripped. This is a capability
of the matching native implementation, not a new configuration switch. The
application requires both its effective stored probe and the live prepare
version before consuming state or rendering a complete private template.

In the same authenticated prepare bootstrap, the application captures finalized
identity HTML from the original native route, including its ordinary template,
widgets, nonces and provider/session shutdown output. Its own ESI tokenization
is disabled for this one private document; the native server does not execute
any ESI instructions inside it. No renderer/provider runs during JSON encoding.
The response uses the existing envelope binding but an exclusive outcome:

```json
{"schemaVersion":1,"requestId":"<owned request>","originalUrl":"<exact original URL>","privateDocument":{"status":200,"contentType":"text/html; charset=UTF-8","bodyBase64":"<canonical base64 identity bytes>"}}
```

`privateDocument` cannot coexist with renderedFragments, publicParent, fragment
cache claims or public-snapshot recovery readiness. Duplicate/unknown fields,
misbound request/URL, noncanonical base64, non-HTML or control-bearing content
types, noninteger status, and status outside 200..599 fail the complete outcome.
The native parser decodes the exact bytes, including embedded NUL/UTF-8; it
does not impose a new product-specific body limit. Status 204/304 yields no
response body. Other final statuses, including redirects and errors, retain
their actual application status and body.

After the complete outcome validates, native state restores and revalidates
the same top-level GET, adapter site, canonical Host, original URI and expected
restart. It synthesizes that private document immediately. There is no further
parent lookup/refetch, recovery, publication, native object store, private TTL
claim or public TTL refresh. The selected public parent remains available to
other visitors and later requests after the private state is consumed.

Fresh end-to-end headers from this prepare, including CSP, Link, language and
Location, accompany its exact body. Cached-parent CSP/validators are never
reused. JSON transport headers, validators, cache/encoding/length metadata,
hop-by-hop fields (including Connection-nominated fields), and native internal
delivery/ESI diagnostics are excluded. Content-Type comes from the document
outcome. Private/no-store is mandatory. Authentic repeated provider Set-Cookie
fields are appended once before headers, without comma splitting, minting or
storage. Generic and adapter diagnostics report PASS and the actual application
reason when available.

For an ordinary full-application MISS, a nonempty trusted-origin
`X-UltraCache-Application-Private` reason also marks the actual complete body
private before aggressive override or cookie detachment, even with zero private
fragments and all cookies classified Shared. Caller copies cannot establish it.
Native code removes Shared-Parent/Parent-Source approval from that personal
response. This remains distinct from a cookie's Shared/Variant/Private action.
The prepare fallback itself requires an approved parent with an existing bound
prepare; it does not inspect application state on arbitrary public HITs.

**Basic remains best effort without ESI.** Neither the complete-document
continuation nor the application-private metadata guard is called for Basic.
Receiving UltraCache metadata cannot enable those paths or change Basic's
ordinary cache policy.

`test_private_document.PrivateDocument` adds seven native transport methods:
exact bytes/fresh headers/cookie ownership and unchanged public parent; actual
status/no-body status handling; malformed/mixed/misbound refusal; zero-fragment
application-private protection before aggressive; Basic without ESI; existing
probe/owned-prepare-only declaration; and exclusion of recovery readiness.
Portable parser tests execute locally. Native transport, exact engine ABI,
real WP template/notice consumption and browser/storage acceptance require
root-owned matching-DSO runs; this draft is not a claim that they passed.

The first root native run of Hestia `1a51b2b` built the DSO but rejected the
generated VCL before traffic: a common empty custom diagnostics sub and its
adapter implementation were both emitted. Custom VCL subs cannot be extended
using duplicate definitions. The common empty definition is removed; the
complete adapter owns the single definition. The shared authorization rendering
suite now asserts exactly one definition and one call for both adapters. No
WordPress proxy was loaded with the failed generation. These corrected sources
still require the root native rerun; a source assertion is not runtime proof.

The corrected Hestia `f7ed39f` compiled and ran all 23 native methods: 22
passed. The remaining fixture used an invalid unquoted origin entity-tag and
compared its untransformed literal with the native ESI/gzip-delivered validator
only after private delivery. The corrected fixture emits a valid quoted tag,
observes an actual public HIT before any private-document outcome, requires
that validator to identify the exact expected public generation (with optional
native weakening), then requires byte-for-byte equality on the later public
HIT. Its CSP and composed body are likewise checked before/after. It does not
permit an arbitrary changed validator or claim that the failed assertion proved
parent mutation. Root native rerun is still required for complete acceptance.
