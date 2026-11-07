# WooCommerce session-only caching investigation

On 8 November 2026, a candidate policy allowed `wp_woocommerce_session_*`
without `woocommerce_items_in_cart` or `woocommerce_cart_hash` to share public
product HTML. The candidate was exercised on a disposable Ubuntu/Webuzo VM
with WooCommerce 11.2.2 and Storefront 4.6.2, through Nginx, Varnish and Apache/PHP.

## Results

The candidate passed 14 of 16 integration assertions. Empty guest sessions got
MISS followed by HIT on a product, while normal cart cookies, write requests,
cart/checkout/account pages and authenticated customers bypassed the cache.
Two separate carts and a coupon remained independent.

Two cases failed:

1. **A WooCommerce notice became shared HTML.** An empty guest session was given
   a unique notice using the real `wc_add_notice()` function. The product template
   rendered it with no `Set-Cookie` and no private cache-control header. The
   candidate stored that response. A second guest with a different valid empty
   session received the first guest's notice as HIT, with the same HTML hash.
   No cart marker cookies were present in either request.
2. **A surviving session could represent a nonempty cart.** Removing only the
   browser-session cart markers left the persistent WooCommerce session and its
   real cart intact. A warm shared product returned empty-cart document HTML
   without reaching WordPress. A direct uncached cart inspection still found
   the original product. Front-end fragment refresh may subsequently repair the
   displayed cart; the test does not claim that the stored cart was deleted.

The notice case was also reproduced with Varnish disabled on the disposable
site and native Webuzo/Nginx caching enabled: guest A received MISS, guest B
received HIT containing A's unique notice. This describes the tested lab
configuration; it is not a finding about every Webuzo installation.

## Policy decision

The candidate relaxation was withdrawn. Cart marker cookies and the persistent
WooCommerce session cookie are classified separately in the source, but both
continue to bypass shared HTML. UltraCache's existing explicitly approved ESI
flow remains a separate case.

The absence of cart marker cookies does not certify that a session is empty or
that product HTML is independent of it. Likewise, an absence of `Set-Cookie`
and private cache-control headers is insufficient for those guest sessions.

Ordinary anonymous product pages without private cookies still get MISS/HIT
without an additional WordPress integration. More aggressive sharing needs
application cooperation that covers both origin responses and warm cache hits.
An origin-only eligibility header cannot handle a later session change on a
HIT, because that request does not execute WordPress. The design must account
for notices, restored carts and customer-dependent content, in addition to
mini-cart fragments, before it can replace the session bypass.

## Regression checks

`tests/test_profiles.py` exercises the actual VCL with distinct guest cookies,
cart markers, a warm anonymous object and unmarked personal origin HTML.

`tests/woocommerce_runtime.py` uses real WooCommerce sessions, a temporary
product, Storefront notice rendering, an actual add-to-cart POST, lost cart
marker cookies and an independent second hosting account. Its temporary
callback only initializes or inspects the synthetic guest sessions and creates
the notice through WooCommerce. It does not replace the product template or
its output. The runner removes its product and callback and restores the
original site profile.

On a disposable server with WooCommerce and Storefront already active on the
first site, and two enabled addon sites on different accounts:

```sh
python3 tests/woocommerce_runtime.py --disposable \
  --address TEST_SERVER_IP \
  --sites first.example.test second.example.test \
  --php /path/to/site/php --wp /path/to/wp-cli
```

The fixture creates an exclusively named temporary file in the first site's
real `wp-content/mu-plugins` directory. Existing plugins are left in place.
No factory Webuzo, Nginx, Apache or PHP/FPM settings are modified by the runner.
