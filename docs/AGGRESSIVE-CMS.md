# Aggressive caching and CMS routes

Implementation goal: identical anonymous-page cache behavior in the Webuzo and
Hestia adapters, with the same shared source and native HTTP assertions.

## Site settings

`aggressive` is a boolean, absent means false. `aggressive_ttl` is a positive
integer in seconds, absent means 86400. The removed historical `ttl` setting is
not read or migrated. Existing sites are not opted in during installation.

The opt-in overrides origin cache restrictions for otherwise eligible HTTP 200
HTML responses. It does not override request PASS decisions or explicit Private
cookie choices. Browser Cache-Control, Surrogate-Control, Pragma and Expires are
saved separately and restored at delivery. The request URL and cookies are not
rewritten to implement shared tracking/session lookup keys. Set-Cookie fields
remain owned by the fetching visitor through the existing native handoff.

`X-Cache-Mode` reports the selected standard/aggressive policy. Existing result
and reason headers continue to distinguish HIT, MISS and individual PASS causes.

## CMS descriptors

`cms_routes.normalize()` accepts a list of descriptors:

```json
[{"cms":"wordpress","base":"/wordpress","private_paths":["/el/καλάθι"],
  "private_queries":[{"name":"page_id","value":"123"}]}]
```

CMS values: wordpress, joomla, drupal, magento, prestashop. Paths are URL paths,
not filesystem paths or regular expressions. Configured private aliases and
query identities also work outside the core installation directory (for example
WordPress core at /wordpress with its public home at /). Standard routes are
selected by the longest matching installation base and support language prefixes.

The Webuzo adapter discovers CMS markers only beneath native panel document
roots. It does not execute site PHP. Discovery runs on install/reconcile and when
saving a site's configuration, rather than on every status request. The ordinary
custom bypass textarea remains available for site-specific prefixes.

## In-progress integration, not a release checklist completion claim

Native Varnish 9.1 tests cover public pages in both profiles; known private paths
and query actions; Greek/encoded configured aliases; distinct visitors' cookie
handoffs; request spoof isolation; explicit Private/login/cart exclusions; and
selected aggressive TTL with unchanged browser policy.

Still required before release: database-backed configured alias discovery,
real guest/auth classification for opaque Joomla sessions, examination of
session-bound form tokens, adapter lifecycle/UI verification, the full regression
suite, and current-source behavioral parity with Hestia. A cookie name alone
does not distinguish a guest Joomla session from an authenticated one.
