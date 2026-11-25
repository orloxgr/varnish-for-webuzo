# Varnish for Webuzo

A Webuzo panel addon that puts Varnish in front of Apache for cached public
responses, while Nginx handles HTTPS and serves existing public static files.
Manage sites, cache profiles, purge access, browser caching and cookie policies
from Webuzo without editing its factory templates or generated virtual hosts.

## Installation

1. Download the Webuzo ZIP from [Releases](https://github.com/orloxgr/varnish-for-webuzo/releases).
2. Upload it in **Webuzo Admin > Plugins > Add New** and activate it.
3. Open **Varnish Cache > Install & set up Varnish**.
4. Click **Refresh sites**, select the profile for each domain, enable the domains
   you want to cache, then click **Save & Apply**. Start with **Basic** unless the
   site's compatible UltraCache WordPress integration is ready.
5. Visit a public page twice, or warm it through the application. Inspect
   `X-Webuzo-Varnish` for `MISS`, `HIT` or `PASS`.

The supported web stack is **Webuzo Nginx reverse proxy + Apache**. Automatic
package setup uses the matching signed Varnish repository for the installed
Ubuntu release and architecture. Setup creates a dedicated Varnish service;
its initial cache allocation is **256 MiB**, configurable under **Server cache**.
New domains start disabled and inherit the central default profile, initially Basic.

No WordPress plugin is installed automatically. **UltraCache requires the
compatible WordPress plugin**, configured as described below. The optional
separate WordPress purge connector serves a different purpose.

## Basic and UltraCache profiles

| | Basic | UltraCache |
| --- | --- | --- |
| Intended use | Standard WordPress/WooCommerce caching; HTML sites and other CMSs on a best-effort basis | WordPress sites using a compatible, active UltraCache plugin |
| WordPress companion required | No | **Yes: UltraCache** |
| Public pages | Cache eligible public HTTP responses | Cache application-approved public publications and complete guest pages |
| Personal content | Private requests and sessions go to the application | The application identifies the public parent and personal fragments; valid cached composition can be delivered by Varnish |
| Cookies | Central/site Shared, Variant and Private choices | Independent choices for the same cookies, integrated with application-owned cookie and fragment delivery |

### Basic

Basic is the normal WordPress/WooCommerce-ready profile. It caches eligible public
pages, products, searches and public REST/AJAX reads. It also supports ordinary
HTML sites and other applications without requiring UltraCache.

Known login, administration, account, cart, checkout and payment actions retain
their private application path. Authentication, private sessions, functional
query parameters, response privacy headers and representation variation are
handled by the cache policy. Merely having a query string or an AJAX/REST URL
does not automatically exclude a public response.

Basic does **not** identify arbitrary personal HTML or reconstruct application
forms and tokens. If the application makes a response private, sets an
unclassified/private response cookie or requires personal processing, a PASS is
expected. Use the optional aggressive setting only as an explicit site decision.

### UltraCache

**Select this profile only when the compatible
[UltraCache WordPress plugin](https://github.com/orloxgr/UltraCache) is installed,
active and configured on that site.** The separate **Varnish Cache for Webuzo**
purge connector is not UltraCache and does not satisfy this requirement.

The UltraCache profile adds application-aware delivery:

- **Public publications and guest pages:** the application supplies the actual
  cacheable representation. After normal warm-up, qualified guest HTML can be
  served directly by Varnish.
- **Public HTML with personal fragments:** UltraCache identifies the common
  parent and the actual private content, such as supported cart and nonce
  fragments. Varnish composes the response without sharing another visitor's state.
- **Native private reuse:** when the publication, owner, dependencies and cached
  bodies remain valid, the complete response can HIT without another WordPress
  prepare. Missing, expired or invalidated content refills through the application.
- **Real cookie delivery:** creation, renewal, deletion and consent decisions
  remain with the application. Another visitor's cookie fields are not replayed
  from a shared HTML object.
- **Application-driven invalidation and warm-up:** compatible application
  controls can invalidate affected content and refill the required representations.

Configure the site's connection using **VCL & connection > Show connection
information**, verify UltraCache's capabilities, then use its normal cache clear
and warm-up. Use a WordPress build compatible with the installed addon; an older
plugin that merely exposes a Varnish purge setting is not sufficient.

**Without the matching UltraCache plugin, these publication, cookie-delivery and
private-fragment contracts are unavailable. The integration can fall back to the
application or fail its delivery checks; select Basic instead.** The addon cannot
infer and safely split personal HTML on its own.

## What the addon manages

### Request routing and CMS paths

Existing public CSS, JavaScript, images, fonts, media and source maps are served
by Nginx. Eligible dynamic requests go through Varnish to the native Apache/PHP
backend. Nginx page caching is disabled on the addon's Varnish route, avoiding a
second HTML cache in that path. Missing static files retain application fallback.

**Refresh sites** discovers installations in Webuzo document roots, including
WordPress/WooCommerce, Joomla, Drupal, Magento and PrestaShop. Known private
routes/actions include discovered aliases, language prefixes and subdirectories.
Use **Additional bypass paths** for custom private URLs and protected assets.

### Cookie policies

The editor provides **separate Basic and UltraCache columns**, centrally and per
site. Site choices override central choices; Reset returns to the inherited rule.

- **Shared HTML:** omit this cookie's variation from shared HTML selection while
  preserving its real browser/application delivery.
- **Public variant:** use its value to select a separate public representation.
- **Private:** use private processing rather than shared public HTML.

The editor supports search, independent profile filters, bulk editing, Excel
paste, CSV export and 20/50/100/500/All rows per page. Hosting users can manage
their own sites under **Security > Cookie cache policies**.

**Reviewed recognition data and cache defaults are bundled with the addon. They
are updated by installing a new plugin version, with saved central and site
choices preserved. There is no separate cookie database download/update action.**
Provider descriptions use the licensed
[Open Cookie Database](https://github.com/jkwakman/Open-Cookie-Database).

### Cache lifetime and aggressive mode

Normal storage follows the application's freshness and native Varnish policy,
without an addon-imposed per-site TTL ceiling. Functional URL/cookie variants
remain distinct; named campaign parameters affect only a separate lookup key,
while the original URL reaches the application on a fetch.

Per-site **Enable aggressive caching** is an explicit override for eligible
anonymous HTML, using the chosen aggressive lifetime. It can override generic
origin no-cache/private instructions, while retaining private route/action and
cookie policy handling. It does not redesign application forms or session tokens.

### Browser cache and server controls

Central browser-cache defaults and per-site overrides set **30 days** for ordinary
static assets and **one year with immutable** for declared content-versioned
assets. Both are configurable. UltraCache's standard hashed CSS bundle pattern
is supplied automatically for that profile. **Restore defaults** applies the
factory browser policy and clears browser-cache overrides.

The panel exposes cache allocation, native usage/hit/miss/pass counters,
per-profile and per-site VCL additions, and connection information. VCL changes
are checked before activation; a rejected candidate leaves the working policy active.

### Purge access and the optional WordPress connector

**Show connection information** provides the local HTTP endpoint (initially
`http://127.0.0.1:82`), site Host header, token/header details and supported purge
operations. Compatible applications use authenticated exact-URL PURGE, scoped BAN
and soft invalidation. Prewarming uses normal GET requests to public URLs.
Applications receive site-scoped access, not Varnish administration credentials.

For manual clearing from WordPress without UltraCache, install the separate
**Varnish Cache for Webuzo** ZIP and open **Tools > Varnish Cache**. It reads its
provisioned local site credential and requires PHP POSIX plus cURL Unix-socket
support. It clears the selected site's cache and aliases, without a panel password.

## Webuzo lifecycle

The addon uses Webuzo's documented custom include points and its own configuration
under `/etc/varnish-for-webuzo`; it does not patch Webuzo source, factory templates
or generated vhosts. Saved settings are retained across plugin updates and native
rebuilds. HTTP/HTTPS host and account boundaries remain site-scoped.

Disabling a domain restores native routing. Removing the setup or deactivating
the addon removes its routing/service integration and returns sites to Webuzo.
Distribution packages and saved preferences remain available for later setup.

## Documentation

- [Configuration guide](docs/CONFIGURATION.md): controls, static files, profiles,
  VCL editing, connections and lifecycle details.
- [Cookie policies](docs/COOKIE-ADMIN.md) and [cache behavior](docs/CACHE-POLICY.md).
- [Changelog](CHANGELOG.md), [development guide](docs/DEVELOPMENT.md) and
  [validation records](docs/TESTING.md).

Based on [varnish-for-hestia](https://github.com/orloxgr/varnish-for-hestia).
Author: [Byron Iniotakis](https://www.iniotakis.com). GPL-3.0-or-later.
This is an independent third-party integration, not affiliated with, endorsed,
sponsored or supported by Webuzo or Softaculous.
