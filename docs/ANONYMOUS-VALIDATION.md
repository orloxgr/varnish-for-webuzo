# Complete anonymous publication qualification - Webuzo 0.12.8

## Result and scope

The UltraCache profile can serve complete warmed anonymous documents with no
application bootstrap or origin-backed ESI during HTML delivery. Eligibility is
the native-owned original absence of both Cookie and Authorization fields.
Present-empty fields are not absence. Existing cookie-bearing requests retain
their actual policy and private-delivery lifecycle.

Application-issued cookies are delivered through a separate private browser POST
after the document loads. The application owns identifiers, consent, attributes,
renewal and deletion. Native never shares an issuer's cookie values between
visitors. The POST carries a request-bound native HMAC rather than a reusable
site credential. The authenticated ordinary warm-up primes both the complete
guest projection and the existing private-capable public parent.

Basic behavior, cookie classifications, origin freshness, nonce validity and
panel controls are unchanged. This release does not add a daemon, visitor
database, queue, session factory or fixed cache-lifetime override.

## Native evidence

The runtime freeze is commit `12eef3e8160b5ea9c1f50888added43a7ea02fc2`.
It was built against the installed Varnish 9.1 SDK in an owned isolated Webuzo
lab prefix. The source/SDK build signature is
`b8dbaa3bcedaf383031d96b140e8ebb3ba8a16ccd736e9a4d551a1e6492fc952`.
An independent reference fixture rebuilt the same source with a different
compiler, producing the same source/SDK signature and a different expected ELF
digest. Native libraries must be built locally against the installed SDK.

The projection implementation passed 40 unique methods without skips:
six Warm projection methods, thirteen guest-publication methods, six issuer
context methods, seven existing delivery-outcome methods and eight portable
guest-envelope/HMAC methods. After the final request-owned parent response
observation was added, all six Warm and seven existing outcome methods passed
again on the final module. The final frozen archive's 198 files matched the
tested source bytes. Installation metadata and release documentation do not
change that runtime freeze.

Coverage includes first stateful parent HIT after warm-up; independent guest
and parent namespaces; exact URL purge of both; unchanged scope registry and
epoch; all three image representations; request/registration HMAC bindings;
duplicate and forged selectors; preserved private routes and cookie choices;
and absence of credentials or visitor cookies from the public object. Basic
does not advertise or consume the Warm projection capability.

## Actual application evidence

The UltraCache owner qualified the paired producer with this exact native
runtime in an owned isolated WordPress/WooCommerce reference fixture using the
Webuzo compiler. These are actual application/browser results, separate from
the native mock-transport tests:

- Normal Warm, then two new anonymous browsers across ORIG, WebP and AVIF:
  complete HTTP 200/HIT documents, usable guest nonces, zero WordPress
  bootstraps, and zero origin or ESI backend links during HTML.
- Two actual browser cookie-issuer operations: successful private 204 responses,
  independent cookie values and usable form nonces after HTML delivery.
- Independent WooCommerce carts: add, quantity change, remove, then normal
  clear/Warm with stateful public-parent HIT and correct visitor-owned output.
- Real YITH wishlist transitions: two visitors, ten page visits and four
  mutations, with correct separate state and parent HIT throughout the repeated
  acceptance run.
- Actual shortened WordPress nonce lifetime and aging: old nonces fail,
  refreshed nonces work, and the next warmed document is a zero-bootstrap HIT.
- Same-build Varnish restart: the registry epoch changes while the guest policy
  remains unchanged; normal Warm restores registration and both representations,
  followed by six zero-bootstrap guest HITs and repeated cookie delivery.

One earlier YITH run had a later parent MISS. The retained VSL records show that
the exact object was invalidated by an UltraCache host-wide BAN immediately
before that lookup. It was not TTL expiry, LRU eviction or a guest-key change.
The original caller of that broad invalidation remains unattributed in
[UltraCache issue #1006](https://github.com/orloxgr/ultracache-dev/issues/1006).
No cookie policy or lifetime was changed to hide that finding.

These results do not constitute production qualification of another panel's
adapter. No customer server was changed during qualification.

## Updating

1. Install the Webuzo 0.12.8 ZIP through the native Webuzo plugin manager.
   Existing installations use the normal activation/reconciliation lifecycle to
   build the native module for their installed SDK and apply the shipped policy.
2. Update WordPress to the coordinated UltraCache 3.13.13-dev.1324 or newer.
3. Run UltraCache's normal cache clear and warm-up after both upgrades.

No new panel setting, cookie override or extra warm-up queue is required. Keep
the site's UltraCache profile selected for this application integration. Basic
continues to operate independently without it.
