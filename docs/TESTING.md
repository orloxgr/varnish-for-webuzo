# Verification

Verified on 7 November 2026 with Ubuntu 24.04, Webuzo 4.9.1, Varnish 9.1 LTS, Apache/PHP-FPM, WordPress and WooCommerce.

On 8 November 2026, the backend suite and actual WooCommerce session regression
checks were extended and rerun. The session-only caching candidate was rejected
after a cross-visitor notice was reproduced. A subsequent guest-only stock-error
sequence reproduced the issue through existing public WooCommerce endpoints,
without a custom application callback. See [WooCommerce sessions](WOOCOMMERCE-SESSIONS.md)
for the experiment, native Nginx comparison and policy decision.

| Check | Result |
| --- | --- |
| Backend boundaries, repository verification, profiles, VCL, cache-budget recovery and hosting timeout inheritance | 77 tests passed |
| Isolated generated proxies with 125-second GET/POST, streaming and warm cache | 4 checks passed; slow responses completed in 125.03 seconds and POST executed once |
| Timeout refresh on the native Webuzo stack | Native factory hashes and Varnish manager PID preserved |
| Native profiles/settings integration after timeout changes | 29 profile and 24 settings checks passed |
| Real WooCommerce session isolation with Storefront | 18 checks passed with the retained session bypass: anonymous HIT, guest-only stock errors, cart/session PASS, lost cart markers and second-account isolation |
| Native panel permissions, CSRF, forged actors and unexpected uploads | 8 checks passed |
| Fresh package/service setup through the Webuzo panel | Passed |
| Varnish manager and worker run without root or effective Linux capabilities | Passed |
| HTTP/HTTPS HTML MISS → HIT and independent static delivery | Passed |
| Cookies, Authorization, queries, writes, private responses, Set-Cookie and errors | Bypass/no stored private response verified |
| WordPress login/REST and actual WooCommerce cart, checkout and account pages | PASS verified |
| Site purge across aliases and HTTP/HTTPS, preserving another account's cache | Passed |
| Another account's token or a public HTTP PURGE | Rejected |
| Credential storage inside a document root | Rejected; private storage accepted with mode 0600 |
| WordPress administrator POST and nonce | Passed; anonymous and invalid-nonce requests rejected |
| Offline Unix socket impersonation by a hosting user | Rejected by directory permissions |
| Credential disclosure through a generic HTTP transport or fake HTTP response | No token supplied; fake success rejected |
| Static symlink into another account | 403, without application fallback |
| Unicode/percent-encoded bypass paths | Passed for static and dynamic routing |
| HEAD and alias handling | Passed |
| Varnish stopped | Static delivery continues; GET/HEAD fall back to Apache; writes are not replayed |
| New native account/domain | Discovered disabled, enabled through the panel, then MISS/HIT verified |
| Native vhost rebuild, Nginx restart and Varnish restart | Passed |
| Full VM reboot | Service started automatically; both accounts retained HTTP/HTTPS HITs and unprivileged processes |
| Native Nginx/proxy/Apache factory configuration hashes | Unchanged |
| Disable/re-enable a domain | Native routing restored; only that site's cache invalidated |
| Remove setup and immediately reinstall | Passed; native routes restored, credentials/unit/runtime removed |
| Webuzo version upgrade | No newer release available: installed/latest were both 4.9.1 |
| Cache-size change and no-op | Actual manager restart and storage argument verified; unchanged budget keeps the same manager |
| Cache-size failure/interruption recovery | Previous unit and settings restored; failed recovery retains its journal |
| Native memory snapshot | Own-instance used/free cache counters and separate service memory verified |
| Site-local request/response VCL | Compiler validation, selected-site invalidation and other-account cache preservation verified |
| Invalid VCL / internal credential access / arbitrary code | Rejected; invalid native regex leaves active policy and settings intact |
| Custom response lifetime with private responses / Set-Cookie | Responses remain uncacheable |
| Connection information and site key | Scoped local capability verified; key excluded from normal status |
| Native plugin ZIP upgrade with custom settings | Nondefault cache size, site VCL, site profiles, central Basic rules, default profile and enabled sites retained |
| Four named profiles and central Basic default | Basic, WordPress, WooCommerce and UltraCache execute distinct native VCL; new inventory inherits the default and existing assignments are preserved |
| Central profile edits | Native compiler validates additions; only enabled sites assigned to that profile are invalidated |
| UltraCache ESI | Shared parent and separate per-visitor private cart fragments verified, including the native Apache/PHP route |
| ESI boundaries and client headers | Cross-account includes rejected; client-supplied internal ESI headers cleared |
| UltraCache local invalidation | Authenticated Unix contract, HTTP/HTTPS exact purge, malformed-expression rejection and cross-account denial verified |
| Site interface | One site entry with inline profile, VCL and connection controls; no second site list |

On 9 November 2026, the 0.3.2 local HTTP connection changes passed all 89 backend
tests and eight native panel rejection checks. Native Varnish tests cover exact
URL invalidation across all four profiles and HTTP/HTTPS, read-only discovery,
wrong-site token rejection, occupied ports and listener-startup rollback.

An application running as a hosting account also exercised the installed HTTP
endpoint: targeted PURGE returned 200, the changed page became a MISS with its
new content, the next public GET was a HIT, and an unrelated URL remained a HIT.
Using that site's token against another account was rejected. The native panel
connection fields, masked token and copy/reveal controls were checked in a browser.

On 10 November 2026, the 0.3.3 browser-cache changes passed all 94 backend tests
and eight native panel rejection checks. The generated Nginx configuration was
exercised with successful GET/HEAD, 304 validators, range responses, fingerprinted
and ordinary assets, query versions, MIME types, failed requests and application
fallbacks. A second integration run on two native Webuzo accounts passed 39
checks over HTTP/HTTPS, including per-site overrides, inheritance, disable/zero
lifetimes, persistence after refresh and rejection of malformed settings. Warm
HTML objects, the Varnish manager PID and Webuzo factory-file hashes were preserved.
Browser tests saved central settings and a site override through the native panel,
verified persistence after reload and restored inheritance without JavaScript errors.

## Reproduce

The timeout regression harness starts isolated Nginx and Varnish processes on
loopback, with private temporary configuration and cache. It exercises the actual
generated domain and origin proxy snippets, slow GET and POST responses delayed
125 seconds, streaming, absence of POST replay and a subsequent cache HIT. The
isolated engine is deliberately started with one-second response defaults so
that passing also requires the generated VCL overrides to take effect:

```sh
python3 tests/timeouts_runtime.py --disposable
```

`--delay` changes only the test fixture's delay; it never changes hosting limits.
The default exceeds both the former 60-second Varnish and 120-second proxy timers.

Backend checks on a disposable Linux server:

```sh
python3 -m unittest discover -s tests -v
/usr/local/emps/bin/php tests/test_panel.php
```

The browser-policy integration runner uses two enabled disposable sites. It
creates assets as their hosting users, applies central settings and site overrides,
checks actual native responses, and restores the original browser settings:

```sh
python3 tests/browser_cache_runtime.py --disposable --self-signed \
  --address TEST_SERVER_IP --sites first.example.test second.example.test
```

The runtime harness needs two enabled disposable WordPress domains on separate accounts, with HTTP and HTTPS available. It creates temporary fixtures as the hosting users, stops/restarts the plugin's Varnish instance, invokes a native vhost rebuild and restores the selected sites' original settings. Replace the address and domain placeholders below. `--self-signed` applies only to the test client's certificate checks.

```sh
python3 tests/runtime.py --disposable --self-signed --address TEST_SERVER_IP --sites first.example.test second.example.test
```

The runtime harness covers cache behavior, HTTP/HTTPS, static assets, private requests, purge isolation, spoofed headers, outages, rebuilds and restarts. Additional native integration checks exercised actual WordPress nonce/capability handling, WooCommerce pages, protected socket permissions, new-account provisioning and removal/reinstallation.

Settings integration checks use the same two disposable sites. They create temporary PHP fixtures as the hosting users, apply site-local VCL, test native compiler rejection, resize the shared cache and restore the original VCL and budget afterwards:

```sh
python3 tests/settings_runtime.py --disposable --address TEST_SERVER_IP --sites first.example.test second.example.test
```

Profile integration checks exercise all four policies through native Nginx → Varnish → Apache/PHP, including private ESI fragments, central Basic edits, defaults, purge authentication and account isolation. They restore the original profiles/defaults and remove their temporary PHP fixtures:

```sh
python3 tests/profiles_runtime.py --disposable --address TEST_SERVER_IP --sites first.example.test second.example.test
```

Actual WooCommerce session checks require WooCommerce and Storefront active on
the first disposable site. The runner creates and removes two catalog products,
uses existing guest endpoints, and restores the original profile:

```sh
python3 tests/woocommerce_runtime.py --disposable --address TEST_SERVER_IP \
  --sites first.example.test second.example.test \
  --php /path/to/site/php --wp /path/to/wp-cli
```
