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

## Reproduction through ordinary guest endpoints

A subsequent test reproduced a cross-visitor error using only WooCommerce's
existing public HTTP endpoints. No MU-plugin, custom callback, direct session
write or direct `wc_add_notice()` call was used. Setup created two ordinary
catalog products: a stock-managed product with one unit and a separate target
product with a new, cold URL.

The unauthenticated guest A sent this sequence with its own cookie jar:

1. `POST /?wc-ajax=add_to_cart`, with `product_id=STOCK_ID` and `quantity=1`.
2. Repeat the same request. WooCommerce rejected the addition because the only
   available unit was already in A's cart. The JSON response reported an error
   and a product URL; the stock notice remained pending in A's session.
3. `POST /?wc-ajax=remove_from_cart`, using the item key supplied by A's normal
   mini-cart response. WooCommerce removed the last product and deleted the two
   cart marker cookies. The persistent session and pending notice survived.
4. `GET TARGET_PRODUCT_URL` as A, before another request consumed the notice.
5. `GET TARGET_PRODUCT_URL` as a completely new guest B, with no cookies.

With native Webuzo/Nginx caching on the lab site, step 4 returned MISS and step
5 returned HIT with identical HTML. Both contained the stock error saying that
the shopper already had one unit in their cart, although B had never added any
product. Neither product response set cookies or declared private cache control.

The requests were sequenced by an HTTP client. A browser's front-end error
handler may immediately follow the returned product URL and consume the notice
before step 3, so the result is not a claim that the same sequence of ordinary
mouse clicks works on every theme. It demonstrates a visitor-controlled request
sequence without installing or changing application code. This sequence has
not been run against a production customer site.

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

`tests/woocommerce_runtime.py` uses the guest-only stock-error sequence above,
two temporary products, Storefront notice rendering, lost cart marker cookies
and an independent second hosting account. It installs no callback and writes
no PHP fixture into either site. The runner removes its catalog products and
restores the original site profile. With the retained session bypass, A's real
error stays in an uncached response and B receives clean public HTML.

On a disposable server with WooCommerce and Storefront already active on the
first site, and two enabled addon sites on different accounts:

```sh
python3 tests/woocommerce_runtime.py --disposable \
  --address TEST_SERVER_IP \
  --sites first.example.test second.example.test \
  --php /path/to/site/php --wp /path/to/wp-cli
```

No factory Webuzo, Nginx, Apache or PHP/FPM settings are modified by the runner.
