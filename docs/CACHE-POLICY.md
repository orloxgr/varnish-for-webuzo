# Cache policy

Basic caches WordPress/WooCommerce and supports other sites on a best-effort
basis. UltraCache uses the same application rules and adds ESI/async-cart
integration. Both presets use the complete bundled `shared/cache-policy.vcl`. That source
contains the common application, lookup-key, privacy, ESI and representation
rules; the panel adapter supplies host/backend/token isolation.

## Public reads

Anonymous public pages, products, searches, REST GET and AJAX GET responses can
be stored and reused. REST paths, `s=`, `ref=` and `XMLHttpRequest` are not
blanket exclusions. Functional query strings remain part of the cache key.
Named campaign parameters are removed only from a separate internal lookup key.
The original request URL is preserved for the origin and browser analytics. Referral parameters are retained;
referral responses that set cookies reach the origin on every request.

## Personal requests

WordPress authentication, previews, administration, nonces, known private
sessions, WooCommerce cart/account/checkout routes and cart mutations bypass
shared caching. Store API cart/checkout also bypasses cache. This includes
subdirectory WordPress installs and the query-based REST dispatcher.

The UltraCache request opt-in and response ESI/async-parent handshake apply
only to sharing parent HTML for cart/session requests. They are not required
to cache an ordinary anonymous public response. ESI personal fragments are
fetched separately for each delivery. Login-cookie requests still bypass;
there is no automatic extraction of personal HTML from arbitrary themes.

## Representations

The original Accept header reaches the application. JSON, XML, dynamic HTML
and functional Cookie variations retain real Vary matching. Unquoted
grammar-equivalent Accept whitespace is normalized in a separate key. Simple
Accept and Accept-Language lists also share case-insensitive tokens and equivalent
quality notation: an omitted q equals q=1, and q=0.900 equals q=0.9. Order and
different qualities remain distinct. Media parameters, quoted values and
nonstandard syntax retain their differences. Original request headers still reach
the application, and public Vary headers are restored for downstream clients.
Missing and explicitly empty Accept/Cookie/language headers remain distinct
native variants. This works in Basic without UltraCache or a WordPress plugin.

For stored public UltraCache HTML, including page-cache ESI parents, the origin
contract consists of `X-Ultra-Cache-Source: apache-static` (or `X-UltraCache-Source`)
or an actual `X-Ultra-Cache: HIT` from the PHP page-cache reader, together with
`X-UltraCache-Cacheable: 1`, and `X-UltraCache-Variant: orig|webp|avif`.
The response must also be a cacheable public HTML 200 without Set-Cookie.
For HTML navigation requests, this identifies an object whose Accept
dimensions are explicit AVIF/WebP support. Warmup and browser headers with
the same support reuse the object despite incidental media-type differences.
Explicit codec q=0 refusals remain separate. Unusual codec parameters keep raw
matching. Missing or client-supplied response-contract headers do not enable
this optimization.

Static and dynamic HTML both use an analytics-only Cookie variant key.
Functional/unknown cookies, including locale, consent and currency, are retained.
The stored HTML contract does not remove those Cookie differences. A dynamic
`X-Ultra-Cache: STORE` response keeps its original Accept variation. Other
dimensions, including Accept-Language, are preserved. The original Vary is restored for
the browser and downstream caches. Client-supplied internal variant headers
are never trusted.

## Results

`X-Webuzo-Varnish` reports HIT, MISS or PASS; UltraCache's `X-Cache` agrees.
`X-Webuzo-Varnish-Reason` reports a request exclusion, origin privacy/cookies,
status/freshness, `cached-response`, or `fetch-required`. A MISS means this
request needed a fetch; the header does not claim to distinguish eviction,
purge, expiry and a never-fetched representation. Native Varnish logs contain
that transaction detail.

Origin responses with private/no-store/no-cache instructions, Set-Cookie, Vary `*`,
or incomplete standalone bodies are not stored. Error statuses follow native/origin
freshness rather than a separate addon status veto. Site/account, hostname
and HTTP/HTTPS boundaries and scoped invalidation remain independent of presets.

## Freshness and grace

Both presets use origin/native Varnish freshness without an addon TTL ceiling.
Saved former per-site cap values do not affect the generated policy. Basic no
longer forces grace to zero: origin stale-while-revalidate is retained. No new
fallback lifetime is configured by the addon. The active Varnish default_ttl
applies when the origin supplies no freshness. Neither preset forces a keep
duration. Uncacheable metadata uses the running Varnish uncacheable_ttl parameter
without resetting grace/keep. Additional administrator response VCL can
explicitly set ttl/grace/keep. Private responses remain uncacheable.

## Invalidation

Exact PURGE normalizes a separate copy with the same key function, and scopes
the invalidation to the site, host and canonical lookup URL. HTTP and HTTPS
remain Vary representations of that URL and are invalidated together. Soft
purge uses the same hash and retains native grace/revalidation behavior.
Regex/exact/batch BAN expressions target canonical lookup URL metadata; they
do not target whichever raw tracking URL first populated the object. Site-wide
Clear cache continues to cover the selected site and its aliases.

The browser retains its complete tracking URL. A cache HIT does not execute
PHP landing handlers; server-side attribution that must run on every visit
needs its normal separate tracking request or before-cache integration. The
addon does not inject or modify WordPress application code.

## Native ESI parser

The owned Varnish service enables `+esi_ignore_other_elements` so approved ESI
includes are processed inside HTML attributes as well as inline JavaScript and
JSON. Activation of an existing addon installation or **Refresh sites** adds the
flag to the owned startup unit and the running parser without restarting or
flushing Varnish. Existing runtime feature flags remain enabled; a stopped
service is not started by this update.

Objects parsed before this parser setting was enabled need their normal
invalidation and refetch before attribute includes are processed. This does not
change ESI parent admission, fragment cookie scope, private/no-store behavior or
any cache lifetime.
