# Shared cache policy contract

`cache-policy.vcl` is shipped byte-for-byte in each distribution. It contains
Basic/UltraCache request, privacy, ESI, representation and key policy. It imports
nothing from another checkout or network resource. The adapter imports `std`
and `purge`, `header`, and `blob` in the complete VCL and defines
host/backend/token isolation. `header` comes from the ABI-matching official
`varnish-modules` package; duplicate Set-Cookie fields are never comma-joined.

## Local cookie catalogue

### Recognition snapshot updates

`cookie_recognition.py` updates recognition data only. Adapters supply an
addon-owned persistent directory and bundled `recognition.json` path to
`status(directory, bundled)`, `configure(directory, bundled, automatic)` and
`update(directory, bundled, force=False)`. `database()` returns the local data.
Status reads never fetch or wait on the updater lock. Configuration and downloads
use their own lock and atomic combined settings/status/database record; downloads
must not hold an adapter's Varnish/site operation lock. Default automatic=true;
scheduled calls respect it, manual force=true works regardless of the preference.

Adapters schedule one daily check and expose administrator-only configuration,
Update now and status, with native authorization/CSRF and escaped output. A check
reads the fixed original repository's commit, then that pinned commit's CSV and
Apache-2.0 license via verified HTTPS without redirects. The data retains the
bundled records schema plus upstream CSV SHA256 and license text. It is never
executed or compiled into policy. Failure keeps the prior data and reports its
stage. The digest is byte identity, not an independent signature.

Input safety bounds are 32 MiB CSV, 1 MiB revision/license, 100,000 records and
128 columns per row and 256 KiB characters per field. Column count is checked
before constructing CSV row arrays. Strict UTF-8/CSV and column/wildcard/control checks
reject malformed input while preserving valid Unicode and optional metadata.
An upstream recognition update must not change cache/consent/issuance behavior,
reload VCL, purge/warm pages or make requests during visitor traffic.

The shared `cookie-policies.json` is the reviewed execution catalogue, schema 1.
`cookie_catalogue.py` validates it and expands `@@COOKIE_PATTERN_<consumer>@@`
markers when the adapter generates a complete standalone VCL. The three current
consumers are `varnishPrivate`, `varnishCart`, and `varnishTrackingIgnore`.
Exact and prefix cookie names are case-sensitive and escaped as literal PCRE.
No recognition category grants an executable policy or a cookie issuer.

The catalogue distinguishes HTML effect, key role, issuer, independent-delivery
support, consent, and cookie attributes. An unsupported independent issuer does
not disable an existing cookie's request policy. Unknown cookies keep existing
HTTP behavior. Removing tracking variation never removes those cookies from
the origin request and never grants permission to replay personal Set-Cookie.

`cookie-recognition/recognition.json` is an attributed, revision-pinned Open
Cookie Database snapshot for recognition only. Its Apache-2.0 license is shipped
alongside it. It is not read by the VCL compiler or during an HTTP request. Do
not replace executable rules with a category-derived allowlist. All distributed
copies of the reviewed catalogue and compiler must agree at release time;
installed servers neither import another checkout nor contact a lookup service.

## Independent Meta cookie delivery

`cookie_delivery.py` supplies the common per-site configuration and request
assignment generator. Default configuration is
`{"fbp":{"enabled":false,"consent_cookie":"cmplz_marketing","consent_value":"allow","domain":""}}`.
An empty domain is host-only. An explicit parent domain must belong to the same
hosting account. A site setting does not authorize a cookie for an unrelated
alias. The host-only subdomain index is computed from the actual request host,
including wildcard aliases. The current exact consent cookie/value is evaluated
for each delivery. This adapter is suitable only where that exact pair expresses
the required permission; service/revision-based CMPs keep their actual API owner.

Adapters call `recv_configuration(value, hostname, owned_domains)` only after
`scp_init`, inside the authenticated route. The shared init discards forged
configuration and application approval headers. No visitor values are part of
site settings. The shared backend hook removes delivery scratch before origin.

On a cacheable public HTML delivery, the Basic policy can issue a missing `_fbp`
independently. UltraCache additionally requires clean, public origin metadata:
`X-UltraCache-Cookie-Policy: <catalogue version>`,
`X-UltraCache-Cookie-Delivery: proxy-fbp`, and `X-UltraCache-Cacheable: 1`.
`provider-endpoint-fbp` means the application's provider/CMP API owns delivery,
including when Basic is selected. Basic needs no application metadata when no
such integration is present. The native issuer also honors the actual Meta
provider hold conditions stored in the catalogue; a hold does not bypass HTML.
These response metadata contain no individual identifier and do not represent
the current visitor's consent. Browser headers never supply approval.

For an origin-approved shared ESI parent, `Vary: Cookie` uses a second internal
functional remainder without the catalogue's private cart carrier cookies.
Original cookies still reach the origin and private children; ordinary objects
retain their full functional Vary. This keeps personal session IDs out of the
approved public parent's variant key while language/other functional dimensions
remain distinct. Adapters use a new cache namespace for these key semantics.

The existing `X-UltraCache-ESI-Private-Count` determines downstream privacy of an
assembled response. A positive count makes only the final delivery private;
the template remains shared and keeps producing HITs with separate fragments.
For older approved parents without a count, Shared-Parent:1 is the legacy
private-parent declaration. An explicit zero retains public-only ESI response
caching. No general ESI PASS, retention limit, or raw Cookie removal is added.

The native value uses Meta's documented four-part identifier, timestamp in
milliseconds and random integer in its provider range. The actual Meta SDK
accepts it and may add its own fifth provenance appendix at the next origin
request. The proxy never invents that SDK appendix. It preserves every existing
cookie and all original Set-Cookie fields, including provider normalization,
renewal and deletion. New values are created only in `vcl_deliver` and appended
with the native header API; no personal value is stored in a shared object.
The lifetime is 90 days, path `/`, SameSite=Lax and Secure on HTTPS.
When a delivery gains a personal cookie, its response-only Cache-Control and
Surrogate-Control prevent downstream caches replaying that identifier. The
stored public object retains its original policy and still serves other HITs.

A cold Basic origin response that sets a cookie retains normal uncacheable
delivery. This does not add a hidden origin refill or promise that a cold MISS
is a HIT. UltraCache retains its existing explicit clean refill/handoff to fill
public HTML. Once a public object exists, new consenting visitors can receive a
HIT and a distinct personal cookie without executing origin PHP. Application
browser/private-endpoint delivery covers its direct-origin and static HIT paths.

Value-free diagnostics are `X-Cache-Cookie-Names`, `X-Cache-Cookie-Role`,
`X-Cache-Cookie-Policy` (catalogue version), and `X-Cache-Cookie-Delivery`.
Names report the actual matched private/cart cookie or functional Vary names.
Malformed raw Cookie text is never reflected as a name. Diagnostics do not
change caching and never contain cookie values, session tokens or credentials.

## Calls and trusted inputs

1. At the start of `vcl_recv`, call `scp_init` before accepting client metadata.
   It removes forged `X-SCP-*` inputs and inherited ESI carrier/approval headers. The private carrier is
   recovered from req_top when needed.
   Authenticate/dispatch the site, validate ESI same-site scope and choose backend
   in the adapter. Set `req.http.X-SCP-Profile` from the trusted site selection
   (`basic` or `ultracache`) before disabled/custom bypasses.
2. Apply explicit administrator bypasses, then call `scp_recv`. It can return PASS. Otherwise the adapter
   returns hash. It does not strip tracking URL arguments or analytics cookies
   from the origin request. UltraCache's existing opt-in marker-cookie transport
   is internal ESI protocol, not analytics-cookie filtering.
3. In `vcl_pass`, call `scp_pass` (also for administrator/request bypasses).
4. In `vcl_hash`, call `scp_key`, then hash the adapter cache namespace, immutable
   site scope, host and `req.http.X-SCP-Key-URL`. No profile/scheme hash dimension:
   scheme is `Vary: X-Forwarded-Proto`. Refresh namespace once for this policy.
5. In `vcl_hit`, handle authenticated soft purge first, then call `scp_hit`.
6. In `vcl_backend_fetch`, call `scp_backend_fetch`.
7. In `vcl_backend_response`, apply explicit administrator response rules, assign
   immutable site/host metadata, and set `X-Cache-Object-URL` from
   `bereq.http.X-SCP-Key-URL`. Then call `scp_backend_response`; return deliver.
8. In `vcl_deliver`, call `scp_deliver`; copy `resp.http.X-SCP-Result` and
   `X-SCP-Result-Reason` to panel-specific response headers, then remove both
   scratch outputs and the adapter site/object metadata. The common hook restores
   public Vary and supplies X-Cache/Hits; it removes its other response scratch.

`X-SCP-*` is internal. Site VCL editors must not allow callers to modify it.
Do not expose the internal Cookie/Accept/Accept-Language Vary keys in downstream responses.
The common policy owns all request/response privacy and retention decisions;
remove duplicate panel-specific versions of those rules.

## Keys and invalidation

`scp_key` normalizes a copy only, leaving `req.url` untouched. It removes named
utm_*, gclid/dclid/fbclid/msclkid/gbraid/wbraid/igshid arguments. All functional
arguments, including search, ref, language, currency, duplicate values and their
order remain. The Cookie variant ignores only known analytics IDs; unknown,
referral, language and consent cookies remain. The public stored-HTML response
contract can collapse equivalent HTML image capabilities. It accepts origin
Apache-static provenance or an actual `X-Ultra-Cache: HIT`, with the existing
public/cacheable/variant/no-Set-Cookie checks. This includes stored ESI parents;
new dynamic `STORE` responses retain raw Accept variation. Static and dynamic
HTML both retain functional Cookie variation; only analytics IDs are omitted.

Both presets normalize simple `Accept` and `Accept-Language` lists in internal
Vary keys without requiring application metadata or a plugin. Case-insensitive
media/language tokens, insignificant spacing and equivalent q weights share
variants. Absent quality and q=1 are equivalent; fractional trailing zeros and
zero notation are canonicalized. Preference order, different weights, actual
language/media differences and absent versus empty headers remain distinct.
Media parameter values, quoted values and nonstandard syntax are not subjected
to this additional normalization. Original request headers reach the origin,
temporary normalization scratch is removed before the fetch, and downstream
Vary retains the public header names. These rules neither admit private content
nor block a request with different syntax.

For exact URL PURGE, call `scp_key` on the authenticated original purge URL and
BAN within the adapter site scope by `X-Cache-Object-URL == X-SCP-Key-URL`.
Soft PURGE must use the same `vcl_hash`. Exact/batch/regex BAN expressions select
**canonical lookup URLs** in X-Cache-Object-URL, not the original tracking URL of
whichever visitor filled the object. Do not try to normalize arbitrary regex
source with the URL normalizer. The producer can use exact PURGE with any
tracking URL; regex BAN selectors target the documented canonical URL space.
HTTP and HTTPS remain separate Vary representations of one purgeable URL.

Tracking remains visible to browser analytics. Code executed in PHP on every
landing requires its own tracking request/before-cache integration; a HIT never
executes that PHP. There is no automatic application-code injection here.

## Verification

Run the same shared parity fixtures against both native generated adapters.
SHA checks are development/release checks only. They are not runtime or installer
requirements and never require another repository to exist on the server.

The explicit development command `tools/compare-policy.py --other CHECKOUT`
compares the policy, HTTP cases and runner byte-for-byte. Optional
`--left-report JSON --right-report JSON` also verifies that both native runs
used those exact sources and completed every shared case. It is never imported
or invoked by the installed plugin or installer.
