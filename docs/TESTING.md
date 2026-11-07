# Verification

Verified on 7 November 2026 with Ubuntu 24.04, Webuzo 4.9.1, Varnish 9.1 LTS, Apache/PHP-FPM, WordPress and WooCommerce.

| Check | Result |
| --- | --- |
| Backend boundaries, repository verification, VCL and cache-budget recovery | 39 tests passed |
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
| Native plugin ZIP upgrade with custom settings | Nondefault cache size, site VCL and enabled sites retained |

## Reproduce

Backend checks on a disposable Linux server:

```sh
python3 -m unittest discover -s tests -v
/usr/local/emps/bin/php tests/test_panel.php
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
