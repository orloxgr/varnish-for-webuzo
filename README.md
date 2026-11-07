# Varnish for Webuzo

Cache public WordPress pages with Varnish while Nginx handles HTTPS and serves public images, styles, scripts and fonts directly. Cache misses and private requests go to the site's native Apache/PHP backend.

## Installation

1. Upload the Webuzo ZIP in **Admin → Plugins → Add New**, then activate it.
2. Open **Varnish Cache** and click **Install & set up Varnish**. Setup installs Varnish 9.1 LTS from its official signed repository and creates a separate `varnish-for-webuzo` service. Its initial cache size is 256 MiB; change it under **Server cache**. Existing supported Varnish instances and their configuration are preserved; an older shared binary is not upgraded while another instance is running.
3. Enable the desired domains and click **Save & Apply**. New domains start disabled and appear when you refresh the site list.
4. Use **Clear cache** to clear that site's cached pages, including its aliases and HTTP/HTTPS variants.

For WordPress administrators, install the separate WordPress connector ZIP and use **Tools → Varnish Cache**. The Webuzo plugin provisions a site credential under the hosting account's private `.varnish-for-webuzo` directory when saving an enabled site. It does not install WordPress plugins automatically. The connector needs PHP POSIX and cURL with Unix socket support, and uses WordPress filesystem/HTTP functions to send a scoped local purge. It never receives a panel password, general API key or command-execution capability.

WordPress must run as its hosting account and be able to read that account's private home directory. Credential provisioning refuses a directory located inside any of the account's document roots.

Automatic setup supports Ubuntu 24.04. The supported topology is Webuzo Nginx reverse proxy with Apache on local ports 8081/8082. Nginx, Varnish and the WordPress connector communicate over Unix sockets in protected directories. Hosting accounts cannot replace those sockets even while the service is stopped. The authenticated Varnish administration interface uses local port 6086; setup refuses an occupied port. Nginx remains responsible for certificates; the HTTPS bridge connects to Apache's native HTTPS virtual host.

The installer verifies the upstream signing key, scopes it to the official repository with APT Signed-By, and selects the 9.1 LTS package branch. Existing APT sources are preserved. The package and signed update repository remain installed after removing the setup so normal OS package updates can maintain the dependency.

Both Varnish manager and cache worker run as the dedicated `webuzo-varnish` system user, with no Linux capabilities and no access to hosting homes. Its cache runtime is separate from the root-private panel state. Only the short-lived native Webuzo configuration worker performs administrative changes.

## Cache behavior

**Server cache** controls the shared cache size in MiB. Applying a different size restarts this plugin's service and empties its cache for all enabled sites. Applying the current size does not restart it. The selected size survives plugin upgrades and service restarts. Failed or interrupted changes have a durable recovery record that restores the previous budget before another panel operation.

**Show memory usage** reads an on-demand snapshot from the native counters of this Varnish instance: cache bytes used/free, configured budget, hits, misses and passes. Total service memory is shown separately because it includes connection and processing overhead in addition to stored objects.

Only successful public HTML responses are eligible for caching. Cookies, Authorization, query strings, write requests, the WordPress dashboard/login/REST endpoints, and standard WooCommerce cart/checkout/account paths bypass the cache. Responses containing cookies, private/no-store/no-cache instructions, or errors are not cached. The per-site lifetime is an upper limit; shorter origin lifetimes remain effective.

Add URL prefixes under **Additional bypass paths** for customized checkout/account pages, protected downloads and private application directories. These exclusions also send matching static files through the application. Public static extensions are CSS, JavaScript, common images, fonts, audio and video. Dotfile paths and standard WooCommerce protected upload directories are excluded from direct static serving. Apache-only access rules for other protected asset directories should be represented in the bypass list.

Direct static serving rejects symbolic links whose owner differs from the target's owner, including links into other hosting accounts. Missing assets reach the application; permission and symlink denials do not fall through to Apache.

If Varnish is unavailable, GET/HEAD page requests fall back to the native Apache backend without a second Nginx page cache. Write requests are not automatically replayed after an upstream failure.

## Site VCL and connection details

Expand a domain under **Site VCL and connection details** to edit its request and response rules. **Validate & Apply VCL** checks the rules with the native Varnish compiler before activating them. A successful change invalidates only that site's cache; a rejected policy leaves the previous rules active.

The site editor supports `if`/`else`, request `return (pass)`, `X-User-*` headers, response `ttl`/`grace`/`keep`, and `regsub`/`regsuball`. The rules run inside that site's scope. Imports, includes, inline C, backend selection, internal credentials and site identity are outside the editing scope. Private/cookie response checks and the site's maximum lifetime remain effective.

Request example:

```vcl
if (req.url ~ "^/members/") { return (pass); }
```

Response example:

```vcl
if (bereq.url ~ "^/news/") { set beresp.ttl = 60s; }
```

**Show connection information & purge key** displays the site's URL, aliases, local Unix socket, PURGE method and authentication header. The key is masked initially, with reveal/copy controls, and is excluded from the normal status response. It authorizes cache clearing only for that site and its aliases. Remote TCP purges are not enabled. The WordPress connector reads its provisioned credential automatically; no manual copying of the key is required.

## Webuzo integration

The plugin adds delimited pointers to Webuzo's documented custom domain/global include files. Its own snippets live under `/etc/varnish-for-webuzo`; private state lives under `/var/lib/varnish-for-webuzo`. Generated vhosts, factory templates and Webuzo source files are not edited. Existing unrelated custom configuration is preserved.

Disabling a domain restores its native routing. **Remove Varnish setup**, or deactivating the plugin, removes its include pointers, site credentials and service unit, stops its Varnish instance, and clears that instance's dedicated cache runtime through systemd. Sites return to native Webuzo handling. Distribution packages and saved administrator preferences remain available for a later setup. Rebuilds and restarts use the same native extension points.

## Development

Build: `python3 tools/build.py`.

Run backend tests as root on a disposable Linux host: `python3 -m unittest discover -s tests -v`. The tests use isolated temporary state. Runtime integration checks must also cover real HTTP/HTTPS, static assets, cache exclusions, purge isolation, service failure, native rebuilds and plugin deactivation.

Verification results and runtime test instructions: [Testing](docs/TESTING.md).

Based on [varnish-for-hestia](https://github.com/orloxgr/varnish-for-hestia). Author: [Byron Iniotakis](https://www.iniotakis.com). GPL-3.0-or-later.

This project is an independent third-party integration. It is not affiliated with, endorsed, sponsored, or supported by Webuzo or Softaculous. The Webuzo name is used only to describe compatibility with the hosting platform.
