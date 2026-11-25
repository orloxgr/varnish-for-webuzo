# Configuration guide

Current controls and detailed behavior. See [README](../README.md) for installation
and profile selection, [Cookie policies](COOKIE-ADMIN.md) for the editor, and
[Changelog](../CHANGELOG.md) for historical release notes.

## Cache behavior

**Server cache** controls the shared cache size in MiB. Applying a different size restarts this plugin's service and empties its cache for all enabled sites. Applying the current size does not restart it. The selected size survives plugin upgrades and service restarts. Failed or interrupted changes have a durable recovery record that restores the previous budget before another panel operation.

**Show memory usage** reads an on-demand snapshot from the native counters of this Varnish instance: cache bytes used/free, configured budget, hits, misses and passes. Total service memory is shown separately because it includes connection and processing overhead in addition to stored objects.

Public responses with a positive cache lifetime are eligible regardless of content type, including HTML, CSS, JavaScript, JSON and redirects. Unknown request cookies reach the origin; functional query strings remain in the cache key and declared `Vary` fields keep representations separate. Authorization, write requests and known private sessions bypass shared cache. Origin private/no-store/no-cache instructions and standalone partial/304 bodies are not stored; responses setting only Shared cookies retain cacheable public HTML, while Variant, Private and unclassified response cookies keep the response outside shared storage; normal conditional and range delivery from complete cached objects remain available. Cache lifetime and grace follow the origin response and native Varnish policy. The addon imposes no per-site TTL ceiling and does not disable grace for Basic. Administrators can use additional response VCL for an explicit site-specific policy.

## Cookies and shared HTML

Use **Cookie policies** to choose **Shared**, **Variant** or **Private** for a
cookie, centrally or per site. This includes `_fbp`, with the same controls as
other cookies. The table controls cache variation; it does not generate cookies.
The website or its provider owns cookie creation, consent, renewal and deletion.

When a cacheable public response sets only Shared cookies, the native handoff
removes those fields before storing the HTML and delivers the exact original
fields only to the visitor who caused that fetch. Duplicate fields, attributes,
renewals and deletions are preserved. Their values never enter the shared object.
Warm HITs use the provider's existing browser or application delivery path.
UltraCache private ESI fragments retain their session and downstream privacy
handling.

The shared cookie catalogue also supplies value-free response diagnostics:
`X-Cache-Cookie-Names`, `X-Cache-Cookie-Role` and `X-Cache-Cookie-Policy`.
They identify the applied rule without exposing cookie values.
Unknown cookies keep the existing HTTP policy.
See the [shared contract](../shared/CONTRACT.md) for integration details.
The [validation results](COOKIE-VALIDATION.md) describe the native cookie
and ESI checks.

## VCL profiles and new sites

**Enable aggressive caching** is an opt-in setting in each site's existing
Basic/UltraCache row. It starts disabled and does not migrate old choices.
When enabled, eligible anonymous 200 HTML uses the selected **Aggressive HTML
lifetime** (initially 86400 seconds) instead of generic origin private/no-store,
Pragma or Expires prohibitions. No smaller addon TTL is imposed. The origin's
browser policy is restored on delivery; this setting changes server storage.
Aggressive caching does not change cookie actions. The same bundled and saved
per-profile choices apply, including Private defaults for `PHPSESSID` and
`__Secure-PHPSESSID`. CMS-discovered opaque names are no longer silently Shared;
ordinary rules and functional Vary handling apply. The independent HTTP override
and private routes/actions remain active. PrestaShop session defaults are visible,
editable Private rows rather than a second CMS cookie veto.

**Refresh sites** discovers WordPress/WooCommerce, Joomla, Drupal, Magento and
PrestaShop inside native document roots. Known private paths and query actions
apply automatically, including language prefixes and installation subfolders.
Read-only CMS metadata adds actual WooCommerce page aliases/IDs, Joomla menu
aliases/Itemids and PrestaShop personal-page rewrites. Magento's configured
administrator frontName is read as data. Customer PHP is never executed for
discovery. SQL runs under the hosting UID, using application credentials.
Failed metadata refreshes retain previously discovered routes for the same
document root and display a notice. Additional bypass paths cover custom routes.
Per-site CMS discovery exclusions skip retired directories before configuration
reads or database access. Automatic reconciliation reuses discovery for unchanged
normalized document roots; **Refresh sites** explicitly retries discovery.

Aggressive public HIT executes entirely inside Varnish. There is no CMS helper
service, request-time database lookup, PHP token provider or Joomla HTML filter.
The recognized Joomla session-cookie name is read statically on panel refresh.
Its opaque value does not force PASS in aggressive mode; known login markers,
private actions and explicit administrator Private/Variant choices still apply.
HTML, including Joomla token values, is left unchanged. This is an explicit
best-effort public-page override, without per-session token/auth reconstruction.
Application-specific corrections remain explicit site choices. The separate
Joomla application plugin is not part of this server addon.

Each site has one profile selected in its own row:

| Profile | Behavior |
| --- | --- |
| **Basic** | WordPress/WooCommerce caching and best-effort support for other sites. Public pages, products, searches, REST and AJAX reads can HIT. Login, private sessions, checkout and cart actions bypass cache. |
| **UltraCache** | Compatible UltraCache WordPress integration: public publication and cookie delivery, ESI composition and native reuse of valid personal fragments. A warm, valid complete response can HIT without WordPress preparation; genuine missing or invalidated state refills through the application. |

**VCL profiles β†’ Default for new sites** selects the profile assigned when a new site is first saved from the panel inventory. It starts as **Basic**. Changing this default does not change the profiles already assigned to existing sites or enable new sites automatically.

**Central profile VCL templates** shows the two built-in presets and their shared policy and lets the administrator add request/response rules to each profile. Central Basic rules apply to every site using Basic, including new sites. Applying central rules validates them with Varnish and invalidates enabled sites using that profile; other profiles keep their cache and site-specific additions.

No profile installs WordPress plugins. Basic works without an application companion. **Select UltraCache only when the compatible UltraCache WordPress plugin is installed, active and configured on that site.** Its publication, cookie-delivery and private-fragment contracts require the application companion; the separate purge connector does not provide them. Its advanced invalidation contract is **ultracache-webuzo-v2**, available through the local HTTP connection or protected Unix socket using that site's token. The existing WordPress connector continues to clear the whole selected site's cache with every profile.

Both presets use the same application exclusions and lookup-key normalization from the bundled **shared/cache-policy.vcl**. The same complete policy source is used by the Hestia integration; each package is self-contained. Functional queries, including search and `ref`, remain in the cache key. A public GET is not bypassed just because it uses REST or XMLHttpRequest. Authentication headers, application nonces, Store API cart/checkout and private response headers remain protected. Campaign parameters such as `utm_source`, `gclid` and `fbclid` are omitted only from a separate lookup key. The original URL and analytics cookies still reach the application on a fetch. Functional search, referral, language and currency values remain in the key.

For identified UltraCache stored public HTML, including page-cache HIT ESI parents, equivalent browser Accept headers share an image-capability variant without rewriting the Accept header sent to the origin. Static and dynamic responses both retain functional Cookie variation; only known analytics IDs are omitted from the internal Cookie variant key. Simple Accept and Accept-Language lists share equivalent case, whitespace and quality notation in internal variant keys, without rewriting origin headers. Real preference order, different weights and parameter values remain separate. Other Vary dimensions and the original downstream Vary header remain intact. See [Cache policy](CACHE-POLICY.md) and the [shared integration contract](../shared/CONTRACT.md).

`X-Webuzo-Varnish` reports HIT, MISS or PASS. `X-Webuzo-Varnish-Reason` identifies a request exclusion, an origin privacy/freshness instruction, a cached response or a required fetch. In UltraCache, `X-Cache` reports the same outcome.

Add URL prefixes under **Additional bypass paths** for customized checkout/account pages, protected downloads and private application directories. These exclusions also send matching static files through the application. Public static extensions are CSS, JavaScript, common images, fonts, audio and video. Dotfile paths and standard WooCommerce protected upload directories are excluded from direct static serving. Apache-only access rules for other protected asset directories should be represented in the bypass list.

Direct static serving rejects symbolic links whose owner differs from the target's owner, including links into other hosting accounts. Missing assets reach the application; permission and symlink denials do not fall through to Apache.

If Varnish is unavailable, GET/HEAD page requests fall back to the native Apache backend without a second Nginx page cache. Write requests are not automatically replayed after an upstream failure.

## Static files and browser cache

**Browser cache defaults** sets the central browser policy;
**Browser cache** in a site's row opens its override. Sites use the central
settings until an explicit override is saved, and can return to inheritance at
any time. Settings survive refreshes and plugin upgrades.

**Restore defaults** immediately applies the factory browser policy to all enabled
sites: 30 days for ordinary assets and one year for versioned assets. It clears
custom browser-cache patterns and per-site browser-cache overrides, so all sites
use the central defaults. VCL profiles, additional VCL, bypass paths and other
settings are preserved. No additional Save or Refresh is needed after restoring.

Existing public static files receive one `Cache-Control` field. Ordinary assets
default to `public, max-age=2592000` (30 days). Declared versioned assets default
to `public, max-age=31536000, immutable` (one year). Both lifetimes are configurable
in seconds; zero produces `no-cache` so a stored copy must be revalidated. Disabling
browser cache headers stops the addon's `Cache-Control` field for that scope.
Native `ETag` and `Last-Modified` validators remain available, including on 304
and range responses. HTML, private responses, errors and application fallbacks
do not receive this static policy. Browser policy changes do not restart Varnish
or clear its cached HTML.

Custom versioned URL patterns start empty. Declare only paths whose filenames
change whenever their contents change, for example `/assets/app-{hash}.js`.
`{hash}` matches 16β€“128 hexadecimal characters, and `*` matches within one path
segment. These are literal URL patterns, not Nginx directives or arbitrary regex.
Neither a `?ver=` query nor an undeclared hexadecimal-looking filename is assumed
immutable. For UltraCache's standard uploads directory, the preset for its
content-versioned main CSS bundles is
`/wp-content/uploads/ultracache/css-bundles/bundle-*-{hash}.css`.
The **UltraCache** VCL profile adds this pattern automatically. It uses the site's
effective versioned lifetime and respects disabled browser headers, central
inheritance and site overrides. The automatic pattern is shown in the site's
browser-cache controls; it does not replace custom patterns or create an override.
Saving another VCL profile removes only the automatic addition. A manually added
copy remains a custom rule. **Refresh sites** reconciles this preset for UltraCache-profile sites. The preset assumes the standard uploads
path; custom uploads paths can be declared manually. Other files retain the
ordinary lifetime unless declared separately.

The Nginx asset location also supplies MIME mappings for the supported public
types, including JavaScript modules (`mjs`), AVIF sequences (`avifs`), WebAssembly
(`wasm`) and web manifests. No global MIME table or Webuzo factory file is changed.
The Apache HTML cache rewrites and application response policies remain in the
native backend; Nginx does not interpret `.htaccess` files.

Changing the policy or purging Varnish cannot remove copies already stored in
visitors' browsers. Replacing a versioned file requires a new URL.

## Site VCL and connection details

Open **VCL & connection** in the site's own row to view its selected profile VCL, edit additional site rules and access its connection details. **Save & Apply** checks the profile and additions with the native Varnish compiler before activating them. A successful site change invalidates only that site's cache; a rejected policy leaves the previous rules active.

The site editor supports `if`/`else`, request `return (pass)`, `X-User-*` headers, response `ttl`/`grace`/`keep`, and `regsub`/`regsuball`. The rules run inside that site's scope. Imports, includes, inline C, backend selection, internal credentials and site identity are outside the editing scope. Private/cookie response checks remain effective.

Request example:

```vcl
if (req.url ~ "^/members/") { return (pass); }
```

Response example:

```vcl
if (bereq.url ~ "^/news/") { set beresp.ttl = 60s; }
```

**Show connection information** displays the server's **HTTP endpoint**, **host**, **port**, **site Host header**, **authentication header** and **site purge token**. An application sends the site's host in `Host` and its token in `X-Webuzo-Varnish-Token`. These server connection values are independent of the WordPress plugin and selected cache profile. The application must support the documented authentication and invalidation protocol; merely supporting some Varnish integration does not establish compatibility. No Varnish administration secret is needed.

The endpoint defaults to `http://127.0.0.1:82`. New setup and **Refresh sites** provision it; **Server cache β†’ Local HTTP connection port β†’ Save connection port** allows changing it if another service uses that port. Only loopback is bound. Purge/BAN operations require the selected site's token; a read-only HEAD response identifies the Varnish listener without invalidating objects. The port must be privileged under the existing operating-system bind policy so another hosting user cannot impersonate it while Nginx is stopped. The addon does not change that policy. Port conflicts or a failed listener startup leave the previous configuration in place.

HTTP `PURGE /path?query` invalidates that exact URL across the site's HTTP/HTTPS and Vary representations. `BAN` accepts the scoped host/URL or host/HTML expressions described by the control VCL; arbitrary administration commands are not exposed. `X-Purge: soft` requests soft invalidation of the selected cache key; `X-Forwarded-Proto` selects its public HTTP/HTTPS scheme where the profile hashes by scheme. The existing versioned application contract remains available as an additional protocol. Applications prewarm by making normal GET requests to the public site URLs, subject to the site's normal caching rules.

The key is masked initially, with reveal/copy controls, and is excluded from the normal status response. It authorizes cache clearing only for that site and its aliases. The separate WordPress connector continues to read its provisioned Unix-socket credential automatically.

## Webuzo integration

Request timeouts follow the loaded Webuzo/Nginx proxy configuration, including
longer domain overrides. The addon derives additional time for its intermediate
proxy layers instead of imposing its former 2/120-second proxy settings and
60-second backend response wait. **Refresh sites** reconciles the loaded hosting timeout policy. This does not restart Varnish or
clear cached pages solely for a timeout change. The panel shows the saved hosting
allowances. See [runtime settings](LIMITS.md) for the exact derived values and
remaining native deadlines.

The plugin adds delimited pointers to Webuzo's documented custom domain/global include files. Its own snippets live under `/etc/varnish-for-webuzo`; private state lives under `/var/lib/varnish-for-webuzo`. Generated vhosts, factory templates and Webuzo source files are not edited. Existing unrelated custom configuration is preserved.

Disabling a domain restores its native routing. **Remove Varnish setup**, or deactivating the plugin, removes its include pointers, site credentials and service unit, stops its Varnish instance, and clears that instance's dedicated cache runtime through systemd. Sites return to native Webuzo handling. Distribution packages and saved administrator preferences remain available for a later setup. Rebuilds and restarts use the same native extension points.
