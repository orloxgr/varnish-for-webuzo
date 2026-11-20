# UltraCache delivery continuation: design draft

Status: transport revision 2 and adaptive nonce revision 1 have **candidate
source implementations, without native acceptance**. The pre-header
continuation now has **candidate source only**; positive private TTL remains
**unimplemented and unadvertised**.
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
  (use the actual installation subdirectory; same-host absolute path only).

The manifest must bind the original public route/representation and the full
set of private-capable include URLs, signed contexts and occurrence counts.
It must contain no visitor identity, cookie values or private output. Public
snapshot approval remains distinct from a fresh personalized render.

Before serving an eligible **GET HIT**, native request-owned state saves the
original URL, Host, complete original Cookie, encoding and conditional/range
headers. It restarts to the prepare target and always PASSes that request.
The native backend hook sets these headers afresh:

```http
X-UltraCache-Delivery-Version: 1
X-UltraCache-Delivery-Phase: prepare
X-UltraCache-Delivery-Request: <request-owned decimal handle>
X-UltraCache-Delivery-Original-URL: /original/path?original=query
X-UltraCache-Delivery-Authorization: <existing native per-site application/purge credential>
Cookie: <unchanged complete original request Cookie>
```

All browser copies are stripped. The request handle only associates the two
native tasks; it is not a session, credential or authentication proof. The
application must verify its signed manifest, original-route binding and trusted
proxy entry point. Headers alone do not authenticate direct access to origin.
Direct untrusted calls must be refused, not treated as approved continuations.
The Hestia and Webuzo adapters populate Authorization from the active
UltraCache site's existing token only after `delivery_backend()` proves the
native-owned prepare association. Missing credentials stop before origin.
Incoming Authorization is removed in receive/backend-fetch; origin echoes are
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

The endpoint executes the real provider lifecycle under the original route,
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
engine object pointers or call uninstalled private HSH APIs. If the object expires, is
purged or replaced, a parent MISS/PASS or different selected object returns 503
**before parent headers**, rather than running the full provider lifecycle a
second time. Seamless recovery of an evicted parent is not implemented.

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
This source correction requires a new targeted native run; the earlier compile
is not a runtime pass. The diagnostic identified actual engine revision
`ffd36e9db9a1ec2bf6637deda180a87d40a13d0f`, VRT API 22.2. The Vinyl 9.1 archive
review above is not a substitute for this installed engine's headers or exact
object-lifetime implementation; parent-retention/restart qualification remains
open alongside seamless parent recovery.

## Positive private TTL is a separate admission contract

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

The following are explicit open acceptance items, not consequences of preserving
the existing code or of an earlier transport/adaptive-nonce checkpoint:

| Case | Required evidence | Current candidate limitation |
| --- | --- | --- |
| Initial parent MISS; provider first creates/renews/deletes a cookie inside a private child | Real WP/Woo/provider execution with issuer counters, original repeated fields in the **first parent response headers**, correct child content and browser session on revisit; two independent visitors and consent denial. | The existing MISS handoff captures only fields available from the top-level origin fetch. It does not prove delivery of a cookie first created after parent headers in an ESI child. The mock fixture's cold children issue no cookie and cannot cover this gap. |
| Provider bootstrap and repeated private renderers on MISS and HIT | Actual provider bootstrap and each distinct stateful renderer execute the required lifecycle once; repeated occurrences reuse output, with no duplicate issuer side effect and no personal data in the public parent. | HIT preflight has candidate replay code only. Initial MISS may need request-local pre-render handoff within normal WP execution; that mechanism is not implemented or inferred from HIT capture. |
| Parent expiry, purge or replacement after prepare | Native fault injection between prepare and resumed delivery; valid final page and visitor cookies, no repeated provider/issuer work, no cross-request leakage and correct cleanup. | The temporary pre-header 503 prevents duplicate execution but is **not completed recovery or full-goal acceptance**. Seamless recovery remains open. |
| Positive private fragment TTL | Native identity/state partitioning, actual reuse before expiry, refresh on expiry/state changes and targeted invalidation; two visitors/two users with no cookie or content replay across owners. | #955 remains unimplemented. TTL 0 or a declared positive header is not evidence of positive private caching. |
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
