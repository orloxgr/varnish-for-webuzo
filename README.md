# Varnish for Webuzo

Version **0.13.2** separates the UltraCache application's storage approval from
the browser's cache headers and aligns the first projected Variant lookup with
publication. The existing serializer produces a request-owned hash input without
rewriting large classification/Vary headers during continuations. Raw Cookie,
saved choices, Basic behavior and native resource limits remain unchanged. Pair
with WordPress UltraCache **3.13.13-dev.1329** for preserved browser cache headers.
See [application policy](docs/application-cache-policy-1022.md) and
[projected lookup](docs/projected-variant-lookup-1023.md).

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

Version **0.12.11** routes existing UltraCache raw Warm/source-capture GETs to
its application before guest cache lookup. A hot guest object can no longer
replace the fresh render and dependency registry required by normal Warm.
Application runtime authentication remains authoritative; raw responses do not
replace cached guest HTML. Basic and ordinary visitor cache lookup are unchanged.

Version **0.12.10** reduces request-workspace copying in the cookie policy
compiler and reuses its result only for a native-owned continuation with the
same original Cookie. This addresses retained-browser cookie requests failing
during the internal restart. Cookie actions, raw origin cookies and native
Varnish limits remain unchanged. The native module is unchanged, allowing the
normal overlapping VCL activation to retain registrations and existing objects.
See [request workspace](shared/REQUEST-WORKSPACE.md).

Version **0.12.9** releases completed backend-only cookie, routing and Warm
carriers before adding authenticated UltraCache transport headers. This fixes a
returning-browser header-count boundary without dropping application fields or
changing Varnish parameters, cookie choices, lifetimes or saved panel settings.
The authenticated capabilities response now explicitly advertises the existing
publication-reselection protocol. Same-module overlapping VCL activation retains
the registry and cached objects. See [backend header budget](shared/BACKEND-HEADER-BUDGET.md)
and [publication reselection](shared/PUBLICATION-RESELECT.md).

Version **0.12.8** adds complete anonymous HTML publication to the UltraCache
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

Version **0.12.7** corrects stale publication conflicts and application
registration after a Varnish restart in the UltraCache profile. An authenticated
early conflict can select the current public publication once within the same
visitor request, before application providers run. It retires only the exact
stale parent and preserves visitor ownership and once-only provider work. The
registration epoch follows the actual registry lifetime, so the normal application
warm-up can restore registration after a same-build restart. Basic and cache
lifetimes are unchanged. See [publication conflict reselection](shared/PUBLICATION-RESELECT.md).
Use the coordinated WordPress companion **UltraCache 3.13.13-dev.1323 or newer**,
then run its normal cache clear and warm-up after upgrading both components.

Version **0.12.6** lets an unrestricted `Accept: */*` document reuse the warmed
original HTML representation. The origin's Accept header, other negotiated
representations and existing public-response/privacy checks are preserved.
See [wildcard document representations](shared/WILDCARD-DOCUMENT-REPRESENTATIONS.md).
For the separate footer-cookie publication correction, use UltraCache
**3.13.13-dev.1322 or newer** and renew older publications through its normal
cache clear and warm-up after upgrading both components.

Version **0.12.5** applies CMS cookie choices through the ordinary scoped
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

Cache public HTTP responses with Varnish while Nginx handles HTTPS and serves existing public images, styles, scripts and fonts directly. Application profiles add WordPress and WooCommerce integration. Cache misses and private requests go to the site's native Apache/PHP backend.

## Installation

1. Upload the Webuzo ZIP in **Admin > Plugins > Add New**, then activate it.
2. Open **Varnish Cache** and click **Install & set up Varnish**. Setup installs Varnish and its matching official modules from the signed repository for the installed Ubuntu release and creates a separate `varnish-for-webuzo` service. Its initial cache size is 256 MiB; change it under **Server cache**. Existing supported Varnish instances and their configuration are preserved; an older shared binary is not upgraded while another instance is running.
3. Choose a profile, enable the desired domains and click **Save & Apply**. New domains start disabled and receive the central default profile, initially **Basic**, when you refresh the site list.
4. Use **Clear cache** to clear that site's cached pages, including its aliases and HTTP/HTTPS variants.

For WordPress administrators, install the separate WordPress connector ZIP and use **Tools β†’ Varnish Cache**. The Webuzo plugin provisions a site credential under the hosting account's private `.varnish-for-webuzo` directory when saving an enabled site. It does not install WordPress plugins automatically. The connector needs PHP POSIX and cURL with Unix socket support, and uses WordPress filesystem/HTTP functions to send a scoped local purge. It never receives a panel password, general API key or command-execution capability.

WordPress must run as its hosting account and be able to read that account's private home directory. Credential provisioning refuses a directory located inside any of the account's document roots.

Automatic package setup detects the installed Ubuntu codename and native package architecture. The official repository must publish matching signed metadata and a package index for that combination. The supported topology is Webuzo Nginx reverse proxy with Apache on local ports 8081/8082. Website traffic and the separate WordPress connector use Unix sockets in protected directories. Applications can also connect through a loopback-only Nginx HTTP listener, which forwards authenticated purge requests to the same Varnish socket. Hosting accounts cannot replace the sockets or bind the privileged HTTP connection port under the required system policy. The authenticated Varnish administration interface uses local port 6086; setup refuses an occupied port. Nginx remains responsible for certificates; the HTTPS bridge connects to Apache's native HTTPS virtual host.

The installer verifies the upstream signing key and signed release metadata, scopes the key to the official repository with APT Signed-By, and checks that the APT candidate comes from the matching release and architecture. It does not pin a Varnish version or branch. A compatible existing binary is checked by compiling the actual addon policy and is retained. Sources owned by the addon are reconciled with the installed OS release during service setup or **Refresh sites**; independent sources are preserved. There is no background OS-upgrade action or automatic service replacement. The package and signed update repository remain installed after removing the setup so normal OS package updates can maintain the dependency.

Both Varnish manager and cache worker run as the dedicated `webuzo-varnish` system user, with no Linux capabilities and no access to hosting homes. Its cache runtime is separate from the root-private panel state. Only the short-lived native Webuzo configuration worker performs administrative changes.

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
See the [shared contract](shared/CONTRACT.md) for integration details.
The [validation results](docs/COOKIE-VALIDATION.md) describe the native cookie
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

Upgrading retires the addon-owned former CMS service/configuration and removed
runtime sources after the helper-free VCL has been successfully activated.

Each site has one profile selected in its own row:

| Profile | Behavior |
| --- | --- |
| **Basic** | WordPress/WooCommerce caching and best-effort support for other sites. Public pages, products, searches, REST and AJAX reads can HIT. Login, private sessions, checkout and cart actions bypass cache. |
| **UltraCache** | The Basic policy plus origin-approved ESI and async-cart parents. Personal fragments are fetched separately; the shared parent can HIT. |

**VCL profiles β†’ Default for new sites** selects the profile assigned when a new site is first saved from the panel inventory. It starts as **Basic**. Changing this default does not change the profiles already assigned to existing sites or enable new sites automatically.

**Central profile VCL templates** shows the two built-in presets and their shared policy and lets the administrator add request/response rules to each profile. Central Basic rules apply to every site using Basic, including new sites. Applying central rules validates them with Varnish and invalidates enabled sites using that profile; other profiles keep their cache and site-specific additions.

No profile installs WordPress plugins. Basic uses HTTP behavior without a companion application plugin. UltraCache also works as a public-page policy without a plugin; ESI composition needs the origin's ESI handshake. Its advanced invalidation contract is **ultracache-webuzo-v2**, available through the local HTTP connection or protected Unix socket using that site's token. The existing WordPress connector continues to clear the whole selected site's cache with every profile.

Both presets use the same application exclusions and lookup-key normalization from the bundled **shared/cache-policy.vcl**. The same complete policy source is used by the Hestia integration; each package is self-contained. Functional queries, including search and `ref`, remain in the cache key. A public GET is not bypassed just because it uses REST or XMLHttpRequest. Authentication headers, application nonces, Store API cart/checkout and private response headers remain protected. Campaign parameters such as `utm_source`, `gclid` and `fbclid` are omitted only from a separate lookup key. The original URL and analytics cookies still reach the application on a fetch. Functional search, referral, language and currency values remain in the key.

For identified UltraCache stored public HTML, including page-cache HIT ESI parents, equivalent browser Accept headers share an image-capability variant without rewriting the Accept header sent to the origin. Static and dynamic responses both retain functional Cookie variation; only known analytics IDs are omitted from the internal Cookie variant key. Simple Accept and Accept-Language lists share equivalent case, whitespace and quality notation in internal variant keys, without rewriting origin headers. Real preference order, different weights and parameter values remain separate. Other Vary dimensions and the original downstream Vary header remain intact. See [Cache policy](docs/CACHE-POLICY.md) and the [shared integration contract](shared/CONTRACT.md).

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
copy remains a custom rule. Existing UltraCache-profile sites receive the preset
on **Refresh sites** after an upgrade. The preset assumes the standard uploads
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
60-second backend response wait. After updating an existing installation, click
**Refresh sites** to apply the timeout policy. This does not restart Varnish or
clear cached pages solely for a timeout change. The panel shows the saved hosting
allowances. See [runtime settings](docs/LIMITS.md) for the exact derived values and
remaining native deadlines.

The plugin adds delimited pointers to Webuzo's documented custom domain/global include files. Its own snippets live under `/etc/varnish-for-webuzo`; private state lives under `/var/lib/varnish-for-webuzo`. Generated vhosts, factory templates and Webuzo source files are not edited. Existing unrelated custom configuration is preserved.

Disabling a domain restores its native routing. **Remove Varnish setup**, or deactivating the plugin, removes its include pointers, site credentials and service unit, stops its Varnish instance, and clears that instance's dedicated cache runtime through systemd. Sites return to native Webuzo handling. Distribution packages and saved administrator preferences remain available for a later setup. Rebuilds and restarts use the same native extension points.

## Cookie recognition database

Open **Cookie policies** to choose how individual cookies affect shared HTML.
The administrator manages central rules and site overrides. Hosting account
users open **Security → Cookie cache policies** for their own sites.

The spreadsheet supports search, action/source filters, cell editing, new rows,
Excel paste, bulk changes, CSV export and 20/50/100/500/All rows per page.
Every bundled cookie has an active Shared, Variant or Private default. **Reset**
removes the choice in the current scope: a site inherits central rules and a
central row returns to the bundled default. Metadata updates preserve choices.

- **Shared HTML:** ignore this cookie's variation while preserving the cookie
  in the browser and origin request.
- **Public variant:** use the cookie value to select separate cached content.
- **Private:** bypass shared caching for requests carrying the cookie.

Site rules take precedence over central rules; within a scope, exact names take
precedence over the longest matching prefix. Core authentication/session/cart
handling and application private/no-store responses remain authoritative.
**Why / precedence** opens a full-width explanation of the actual behavior,
source and applicable protections. Internal IDs are hidden. New recognition
entries without a bundled rule are marked as proposals; **Use this proposal**
adds an explicit choice to the draft. **Save & Apply** activates the rules.
Only affected enabled sites are invalidated; ordinary policy changes do not
restart Varnish. Rules saved while a site is disabled apply once it is enabled.

For sites running UltraCache, the optional **UltraCache connection** also applies
these choices inside WordPress. Configure the same site token in UltraCache,
using a compatible build with bundled-cookie policy support, enable the
connection and save. Ordinary HTTP purge is independent of this optional
policy synchronization. The connection uses only that site's control
endpoint; no panel password or Varnish administration key is needed. A retained
panel can synchronize UltraCache even when its Varnish setup is disabled.
Updating an already configured addon reapplies its current setup automatically;
fresh installation still requires the administrator to set up the service.

The panel shows the bundled recognition record count, reviewed rule count and
source revision. Recognition data and executable defaults are updated together
with the plugin. Existing central and per-site choices are preserved. Old
downloaded snapshots are not consumed, and no daily download job is created.

## Development

Build: `python3 tools/build.py`.

Run backend tests as root on a disposable Linux host: `python3 -m unittest discover -s tests -v`. The tests use isolated temporary state. Runtime integration checks must also cover real HTTP/HTTPS, static assets, cache exclusions, purge isolation, service failure, native rebuilds and plugin deactivation.

Verification results and runtime test instructions: [Testing](docs/TESTING.md).

Based on [varnish-for-hestia](https://github.com/orloxgr/varnish-for-hestia). Author: [Byron Iniotakis](https://www.iniotakis.com). GPL-3.0-or-later.

This project is an independent third-party integration. It is not affiliated with, endorsed, sponsored, or supported by Webuzo or Softaculous. The Webuzo name is used only to describe compatibility with the hosting platform.

Cookie policies use two independent Basic and UltraCache columns, each with
Shared HTML, Public variant or Private and its own inherited/reset behavior.
Commenter cookies default to Private in Basic and Shared in UltraCache; all other
paired defaults are identical. Existing choices remain explicit in both columns.
Connected WordPress receives the selected profile as the existing concrete signed
snapshot; standalone WordPress uses the UltraCache column.
