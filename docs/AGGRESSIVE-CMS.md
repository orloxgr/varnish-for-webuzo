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
roots. It does not execute site PHP. Discovery runs on installation/update,
explicit **Refresh sites**, and after saving a site's configuration. Automatic
reconciliation scans only new or changed document roots, compared with normalized
paths. A failed attempt is not repeated every minute; explicit refresh retries it.
Per-site **Exclude directories from CMS detection** accepts literal URL-relative
directory paths. Each excluded subtree is pruned before configuration reads or
database access; `/` disables discovery for that site. Exclusions also remove
retained routes and cookie descriptors when a refresh fails. The ordinary
custom bypass textarea remains available for site-specific prefixes.

## Public HIT without additional backend work

The opt-in preserves original Joomla HTML and tokens. It no longer reconstructs
opaque-session authentication, scans response bodies, injects token ESI or calls
an application token provider. Known private paths/actions and cookie markers
still match in VCL. The panel discovers the Joomla cookie name statically with
`cms_cookies.joomla_name`; runtime visitors never execute this Python module.

The CMS helper service and worker sources are removed. Successful native upgrade
retires owned legacy unit/configuration/code; it does not retain a disabled worker.
Public HIT must keep working when its already-warmed origin has been stopped.
Original Set-Cookie fields remain owned by the fetching visitor. Existing private
UltraCache ESI is unchanged and is not claimed to be zero-backend composition.

See AGGRESSIVE-VALIDATION.md for the current-source acceptance results.
