# UltraCache delivery continuation: design draft

Status: transport revision 2 and adaptive nonce revision 1 have **candidate
source implementations, without native acceptance**. The pre-header
continuation and positive private TTL remain **unimplemented and unadvertised**.
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

## Proposed native pre-header continuation (wire not frozen)

1. An origin-approved parent advertises a nonpersonal, signed delivery
   descriptor as object metadata. It binds the canonical host, original page
   path/query and provider operations using UltraCache's existing signing
   mechanism. It contains no visitor ID, credentials or cookie values. No
   prepare request is introduced for ordinary pages without this contract.
2. Before committing the chosen parent's headers, native request-owned state
   retains the original GET URL, host/site, scheme, method, original Cookie,
   selected parent representation and descriptor. An internal restart routes
   **GET** to the same site's WordPress front controller with
   `?ultracache_delivery=<signed-descriptor>` (preserving the site's subdirectory).
   Proposed request headers are `X-UltraCache-Delivery-Version: 1`,
   `X-UltraCache-Delivery-Phase: prepare`,
   `X-UltraCache-Delivery-Request: <opaque request handle>` and
   `X-UltraCache-Delivery-Original-URL: <original path/query>`.
   All incoming copies are stripped. Native-owned state, not browser headers,
   authorizes a continuation. The endpoint must verify descriptor, target,
   phase and the trusted internal route. Direct public requests are refused.
3. The prepare transaction always PASSes and returns `private,no-store`.
   UltraCache executes the actual necessary provider hooks, consent checks and
   state updates once, without running the whole parent template. The proxy
   creates no application cookie, session, signature or user identity.
4. Real repeated Set-Cookie fields are retained verbatim in the originating
   request's native handoff: attributes, empty values, expiration, renewal and
   deletion remain intact. They are never flattened/comma-split or stored in a
   reusable object. Existing MISS handoff and this continuation share one
   ownership implementation; an internal phase cannot erase pending fields.
5. Proposed private prepare-body envelope is JSON with `schemaVersion: 1`,
   `requestId`, `originalUrl`, `childContexts` and `renderedFragments`.
   `childContexts` maps an existing signed fragment descriptor to its effective
   request Cookie header after the provider operation; it includes new actual
   session values and omits provider-deleted values. `renderedFragments` holds
   any stateful renderer output already executed in this phase. The endpoint
   filters each context to that renderer's declared needs. Native code validates
   the envelope's request/target binding and retains it only for this request.
   No context, envelope or body is put into shared parent metadata.
6. The native continuation restores the original request and does a fresh
   parent lookup before delivery. The real cookie fields are attached to this
   final response before headers are committed. Private children use their
   corresponding effective child context, not a stale copy from the original
   browser request. Where a renderer had to execute before headers, its result
   is consumed from the request-local result, rather than executing it twice.
   This requires an explicit native API; VCL alone does not parse that envelope
   or retrieve arbitrary child bodies before parent delivery.

HEAD must not perform GET page-view mutations. The continuation must preserve
native restart bounds, handle cache eviction between phases and never use a
client-supplied done flag as proof that provider work occurred. Failure before
headers must select an explicit private origin fallback or an error; no
uncompleted personalized response may be presented as a successful shared HIT.
Abort, error and task finalization release all request-owned state. A provider
operation must not be repeated by restart/retry within that request; concurrent
requests still require the provider's normal session/transaction semantics.

Cookie header reconstruction cannot be a blind name substitution: browser
Cookie lacks Domain/Path attributes and may contain duplicate names. The
application's per-renderer effective context is required; a generic proxy-only
jar built from those names would guess at application identity. Validate this
with same-name/different-path, newly issued and expired session acceptance.

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

Both adapters, actual current UltraCache and native Varnish: MISS/HIT/HIT,
two anonymous visitors and two logged-in users, empty/new/active/deleted
sessions, Recently Viewed history updates, consent denial, multiple Set-Cookie
fields/attributes, repeated fragments with one provider execution, nonce action
success after state changes, TTL 0/positive/expiry, targeted invalidation,
spoofed headers, prepare failures, eviction/restart/abort and no-JavaScript
composition. These are pending requirements, not claims of completed tests.
