# Varnish for Webuzo

Cache public WordPress pages with Varnish while Nginx handles HTTPS and serves public images, styles, scripts and fonts directly. Cache misses and private requests go to the site's native Apache/PHP backend.

## Installation

1. Upload the Webuzo ZIP in **Admin → Plugins → Add New**, then activate it.
2. Open **Varnish Cache** and click **Install & set up Varnish**. Setup installs Varnish 9.1 LTS from its official signed repository and creates a separate `varnish-for-webuzo` service. Its initial cache size is 256 MiB; change it under **Server cache**. Existing supported Varnish instances and their configuration are preserved; an older shared binary is not upgraded while another instance is running.
3. Choose a profile, enable the desired domains and click **Save & Apply**. New domains start disabled and receive the central default profile, initially **Basic**, when you refresh the site list.
4. Use **Clear cache** to clear that site's cached pages, including its aliases and HTTP/HTTPS variants.

For WordPress administrators, install the separate WordPress connector ZIP and use **Tools → Varnish Cache**. The Webuzo plugin provisions a site credential under the hosting account's private `.varnish-for-webuzo` directory when saving an enabled site. It does not install WordPress plugins automatically. The connector needs PHP POSIX and cURL with Unix socket support, and uses WordPress filesystem/HTTP functions to send a scoped local purge. It never receives a panel password, general API key or command-execution capability.

WordPress must run as its hosting account and be able to read that account's private home directory. Credential provisioning refuses a directory located inside any of the account's document roots.

Automatic setup supports Ubuntu 24.04. The supported topology is Webuzo Nginx reverse proxy with Apache on local ports 8081/8082. Website traffic and the separate WordPress connector use Unix sockets in protected directories. Applications can also connect through a loopback-only Nginx HTTP listener, which forwards authenticated purge requests to the same Varnish socket. Hosting accounts cannot replace the sockets or bind the privileged HTTP connection port under the required system policy. The authenticated Varnish administration interface uses local port 6086; setup refuses an occupied port. Nginx remains responsible for certificates; the HTTPS bridge connects to Apache's native HTTPS virtual host.

The installer verifies the upstream signing key, scopes it to the official repository with APT Signed-By, and selects the 9.1 LTS package branch. Existing APT sources are preserved. The package and signed update repository remain installed after removing the setup so normal OS package updates can maintain the dependency.

Both Varnish manager and cache worker run as the dedicated `webuzo-varnish` system user, with no Linux capabilities and no access to hosting homes. Its cache runtime is separate from the root-private panel state. Only the short-lived native Webuzo configuration worker performs administrative changes.

## Cache behavior

**Server cache** controls the shared cache size in MiB. Applying a different size restarts this plugin's service and empties its cache for all enabled sites. Applying the current size does not restart it. The selected size survives plugin upgrades and service restarts. Failed or interrupted changes have a durable recovery record that restores the previous budget before another panel operation.

**Show memory usage** reads an on-demand snapshot from the native counters of this Varnish instance: cache bytes used/free, configured budget, hits, misses and passes. Total service memory is shown separately because it includes connection and processing overhead in addition to stored objects.

Only successful public HTML responses are eligible for caching. Authorization, write requests and private sessions bypass shared cache. Responses containing cookies, private/no-store/no-cache instructions, or errors are not cached. The per-site lifetime is an upper limit; shorter origin lifetimes remain effective unless an additional response VCL rule sets a different lifetime within that limit.

## VCL profiles and new sites

Each site has one profile selected in its own row:

| Profile | Behavior |
| --- | --- |
| **Basic** | Conservative default: all cookies and query strings bypass cache, together with common WordPress and shop private paths. This retains the behavior of sites configured before named profiles were introduced. |
| **WordPress** | Excludes login, dashboard, APIs, editors, previews and private/session cookies. Unrelated cookies can share public pages and remain available to the origin on a miss. |
| **WooCommerce** | WordPress policy plus cart, checkout, customer-account and WooCommerce action exclusions. Cart/session cookies bypass cache. |
| **UltraCache** | WordPress/WooCommerce policy with marketing-parameter normalization, origin-approved ESI and authenticated exact/batch/HTML/host/soft invalidation. A cart request can share an ESI parent only after the explicit request opt-in and origin response approval; its private fragments execute separately for each visitor. |

**VCL profiles → Default for new sites** selects the profile assigned when a new site is first saved from the panel inventory. It starts as **Basic**. Changing this default does not change the profiles already assigned to existing sites or enable new sites automatically.

**Central profile VCL templates** shows the four built-in VCL files and lets the administrator add request/response rules to each profile. Central Basic rules apply to every site using Basic, including new sites. Applying central rules validates them with Varnish and invalidates enabled sites using that profile; other profiles keep their cache and site-specific additions.

No profile installs WordPress plugins. Basic, WordPress and WooCommerce use HTTP behavior without a companion application plugin. UltraCache also works as a public-page policy without a plugin; ESI composition needs the origin's ESI handshake. Its advanced invalidation contract is **ultracache-webuzo-v2**, available through the local HTTP connection or protected Unix socket using that site's token. The existing WordPress connector continues to clear the whole selected site's cache with every profile.

Add URL prefixes under **Additional bypass paths** for customized checkout/account pages, protected downloads and private application directories. These exclusions also send matching static files through the application. Public static extensions are CSS, JavaScript, common images, fonts, audio and video. Dotfile paths and standard WooCommerce protected upload directories are excluded from direct static serving. Apache-only access rules for other protected asset directories should be represented in the bypass list.

Direct static serving rejects symbolic links whose owner differs from the target's owner, including links into other hosting accounts. Missing assets reach the application; permission and symlink denials do not fall through to Apache.

If Varnish is unavailable, GET/HEAD page requests fall back to the native Apache backend without a second Nginx page cache. Write requests are not automatically replayed after an upstream failure.

## Static files and browser cache

After upgrading, click **Refresh sites** to apply the current Nginx templates to
enabled sites. **Browser cache defaults** sets the central browser policy;
**Browser cache** in a site's row opens its override. Sites use the central
settings until an explicit override is saved, and can return to inheritance at
any time. Settings survive refreshes and plugin upgrades.

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
`{hash}` matches 16–128 hexadecimal characters, and `*` matches within one path
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

The site editor supports `if`/`else`, request `return (pass)`, `X-User-*` headers, response `ttl`/`grace`/`keep`, and `regsub`/`regsuball`. The rules run inside that site's scope. Imports, includes, inline C, backend selection, internal credentials and site identity are outside the editing scope. Private/cookie response checks and the site's maximum lifetime remain effective.

Request example:

```vcl
if (req.url ~ "^/members/") { return (pass); }
```

Response example:

```vcl
if (bereq.url ~ "^/news/") { set beresp.ttl = 60s; }
```

**Show connection information** displays the server's **HTTP endpoint**, **host**, **port**, **site Host header**, **authentication header** and **site purge token**. An application sends the site's host in `Host` and its token in `X-Webuzo-Varnish-Token`. These server connection values are independent of the WordPress plugin and selected cache profile. The application must support the documented authentication and invalidation protocol; merely supporting some Varnish integration does not establish compatibility. No Varnish administration secret is needed.

The endpoint defaults to `http://127.0.0.1:82`. New setup and **Refresh sites** provision it; **Server cache → Local HTTP connection port → Save connection port** allows changing it if another service uses that port. Only loopback is bound. Purge/BAN operations require the selected site's token; a read-only HEAD response identifies the Varnish listener without invalidating objects. The port must be privileged under the existing operating-system bind policy so another hosting user cannot impersonate it while Nginx is stopped. The addon does not change that policy. Port conflicts or a failed listener startup leave the previous configuration in place.

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

## Development

Build: `python3 tools/build.py`.

Run backend tests as root on a disposable Linux host: `python3 -m unittest discover -s tests -v`. The tests use isolated temporary state. Runtime integration checks must also cover real HTTP/HTTPS, static assets, cache exclusions, purge isolation, service failure, native rebuilds and plugin deactivation.

Verification results and runtime test instructions: [Testing](docs/TESTING.md).

Based on [varnish-for-hestia](https://github.com/orloxgr/varnish-for-hestia). Author: [Byron Iniotakis](https://www.iniotakis.com). GPL-3.0-or-later.

This project is an independent third-party integration. It is not affiliated with, endorsed, sponsored, or supported by Webuzo or Softaculous. The Webuzo name is used only to describe compatibility with the hosting platform.
