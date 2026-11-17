# Verification

## Recognition database updates

The isolated Python entrypoint is tested directly with `-I -B`, without an
import wrapper. The native systemd check runs the unmodified `recognition.py`
entrypoint with only its state directory redirected to disposable storage.
It downloaded 2,288 records with exit status 0, while automatic updates were
disabled and the cache-operation lock was held. VCL, cache settings and the
Varnish PID remained unchanged. The entrypoint regression and related updater
and lifecycle suite pass 31 Linux/root checks.

Run `python3 -B -m unittest discover -s tests -p 'test*recognition.py' -v`
as root on a disposable Linux host. The tests cover administrator-only actions,
fixed upstream URLs, rejected redirects, strict CSV validation, atomic updates,
last-good retention, automatic/manual selection and owned timer lifecycle.
Upstream input safety bounds are 32 MiB per CSV, 1 MiB per metadata/license
response, 100,000 records, 128 columns and 256 KiB per CSV field. These bounds apply to
downloads, not website requests or cache operations.

Native Lab checks also exercised an isolated systemd worker against the actual
upstream, manual update with automatic updates disabled, the independent cache
lock and retention after a download failure. The cache settings, active VCL and
Varnish PID remained unchanged. The panel fixture checks that update responses
preserve unsaved site edits and render upstream messages as text. The Webuzo
panel itself requires an active Webuzo license for a native upload/UI test.

## 0.4.6 — 16 November 2026

The Webuzo adapter passes all 75 native shared-policy runs across 39 scenarios.
Independent baseline Basic tests reproduced extra MISSes from equivalent Accept
case and q notation without UltraCache headers or a WordPress plugin. The new
common cases verify equivalent Accept/Accept-Language reuse in both profiles.

Six additional scenarios cover case, whitespace and equivalent q spelling;
real weight/order/language/media differences; case-sensitive parameter and
quoted values; nonstandard syntax; combined Vary with Cookie; original origin
headers; spoofed scratch headers; and absent, empty and wildcard language keys.
Internal keys do not appear in downstream Vary or response headers.

- Policy SHA-256: `b18c2dd20dfe0b0b2a36ceb395456f5d454edb367e6b1c79edfd51f11eaffcc3`.
- Cases SHA-256: `afc4e48bd1252445928de137b7c7d46a7d513932fd97ba169af3b5eecd77e694`.
- Policy, integration contract, cases and runner are byte-identical to Hestia.

This verification used isolated native processes and the actual Webuzo renderer.
No production configuration or installed service was changed, and no broader
backend audit was repeated. Cookie ordering is unchanged by this update.

## 0.4.5 — 16 November 2026

Focused nonce-ESI verification used the Webuzo VCL renderer and native
varnishtest in an isolated lab source tree. Eight new checks pass, together with
14 existing cache-size/settings tests. No broader audit was repeated.

- The actual startup parameter composes nonce includes in inline JavaScript,
  JSON and HTML attributes. One shared parent serves A/B/A with separately
  refetched private fragments and the expected visitor-specific values.
- Private children receive only the permitted session cookie, and their
  Set-Cookie response never leaks into the shared parent response.
- A native runtime parameter update preserves an existing `esi_remove_bom`
  feature. Owned-unit changes persist without restart, restore the previous file
  on native failure, and refuse unrelated units or a mismatched cache budget.
- The native activation hook configures only an already installed service;
  enabling the flag never starts a stopped service.
- A cold private/no-store parent with `Surrogate-Control: content=ESI/1.0,
  no-store` and its own WooCommerce Set-Cookie composes an ESI mini-cart while
  remaining PASS. The shared policy needs no change for this case.

These are native HTTP fixtures, not additional actual WordPress nonce signature
or browser validation. Existing installed lab service PIDs were unchanged; no
production configuration or installed service was changed. Existing
objects parsed before the feature is enabled need normal invalidation/refetch.

## 0.4.4 — 16 November 2026

All 147 Webuzo backend tests pass, together with 63 shared native HTTP cases.
New cases cover stored PHP page-cache HITs, warmed ESI parents with different
browser Accept headers and separate private fragments, dynamic STORE variation,
and rejection of a HIT marker when the response sets a session cookie.

An isolated real WordPress/UltraCache test used Apache, PHP-FPM, the Webuzo
VCL renderer, Varnish and Edge. WordPress Warm filled all three orig/webp/avif
ESI parent variants. The first different browser Accept, AVIF q=0 and original
image requests all HIT; two independent browser contexts received the rendered
ESI fragment on a HIT. Login and cart requests remained PASS. Temporary
processes, WordPress fixture, database and database user were removed; existing
service PIDs remained unchanged. No production service was changed.

The installed Webuzo panel ZIP-upgrade test remains unavailable due to the lab
license. After upgrading the package, **Refresh sites** applies the new VCL to
an existing installation. The Hestia port is coordinated separately; these
results describe the Webuzo adapter and renderer.

## 0.4.3 — 15 November 2026

The shared HTTP policy is byte-identical in Webuzo and Hestia. The common
native suite completes all 56 runs in both integrations using the same policy,
cases and runner. The explicit development comparison verifies identical report
contents and full case coverage, not only matching source files.

- Shared policy SHA-256: `7cea910fa4e05a4d874fb01f8ca51c28fe1e56d1af503ce219d0bc8d529edefb`.
- Shared cases SHA-256: `38bb8fd00002b6d81aae491072df3eb12bea93fb5ebd130fca4ec2dde11be797`.
- Webuzo full suite: 146 tests passed in 154.027 seconds.
- Hestia full suite: 143 tests passed in 206.169 seconds, reported by that integration and paired with its identical native parity report.
- Generated isolated Nginx/Varnish/origin chain: both presets passed, including
  tracking URL/Cookie HIT, complete origin URL/Cookie preservation and real
  functional Cookie variation. PHP lint and Python compilation passed.

The common suite covers tracking/analytics reuse, functional query and Cookie
variation, static HTML locale isolation, browser/warmup Accept/q=0, dynamic
Accept OWS and quoted parameters, absent/empty headers, native processing of a
large Accept header, exact/soft/batch invalidation with canonical metadata,
HTTP/HTTPS and host scope, WordPress subdirectories, private login/cart/ESI
bodies, public ESI fragment reuse and query values containing private path or
tracking-like text. The large-header case raises native test-instance parsing
allowances; the installed services' limits are not changed.

Neither the production server nor the installed Webuzo VM plugin was changed.
The native Webuzo ZIP-upgrade/panel test remains unavailable due to the lab
license. Runtime/installer operation never requires another repository, report
or remote policy checksum.

## 0.4.2 — 15 November 2026

All 146 backend/native-Varnish tests pass (145.480 seconds). The isolated
generated Nginx/Varnish/origin runner passes for both presets, and the panel
entrypoint passes PHP lint.

Repository selection tests cover release/architecture and candidate origin,
resumable owned-source changes from noble to resolute, independent source
preservation, modified-file refusal and unavailable/invalid signed metadata.
Actual official InRelease signatures were verified with gpgv for noble and
resolute, for their amd64 and arm64 package indexes. Isolated APT indexes selected
9.1.0-2~noble and 9.1.0-2~resolute. The noble install simulation required no package
changes. The installed Varnish compiled the generated policy successfully.
These checks did not change installed APT sources or packages. They are not
a completed Ubuntu 24.04-to-26.04 OS upgrade or an ARM service deployment.

Native Varnish tests verify configurable uncacheable_ttl=37, grace=41 and keep=23
without addon overrides, public 404/410 MISS then HIT, native 500/503 PASS,
explicit administrator TTLs for public errors, private error isolation, and
per-visitor Set-Cookie without rewriting ordinary origin Cache-Control.

## 0.4.1 — 15 November 2026

All 126 backend/native-Varnish tests pass. The Chromium panel fixture confirms
five site columns, no lifetime controls, and no TTL field in Save requests.
The lifetime-cap regression checks run the generated VCL with obsolete saved
300-second cap values and confirm that both presets retain an origin s-maxage
of 86400 seconds and stale-while-revalidate of 60 seconds. A separate real
Varnish sequence expires a one-second object, delivers the old body immediately
as HIT within the origin grace window, refreshes it in the background, and
then delivers the new body as HIT. Inventory reads do not migrate saved state.
The panel no longer has a lifetime cap input or an origin-policy checkbox.

## 0.4.0 — 15 November 2026

The full backend suite passes 125 tests on Linux with native Varnish 9.1,
including the two presets, public REST/search/AJAX/referral reuse, campaign-key
invalidation, Accept negotiation and q=0, real Cookie variations, private
sessions, two-visitor ESI fragments and scoped purge. Eight PHP panel rejection
checks also pass. Python 3.9 syntax and panel JavaScript syntax checks pass.

The isolated generated Nginx → Varnish → HTTP-origin runner exercises both
presets without changing the installed Webuzo services or configuration. It
verifies warmup/browser Accept reuse, tracking-cookie reuse, authenticated body
separation and public REST/search/referral AJAX HITs. An actual Chromium run
starts with a warmed page, hovers to create a tracking cookie, refreshes and
retains HIT in both presets. Separate browser contexts receive their own
personal response with PASS. Fixtures are synthetic HTTP application responses.

Native panel ZIP upgrade and native inventory integration remain unverified for
this version: the disposable Webuzo panel reports an expired license, including
after its official license refresh. Its installed plugin was not upgraded.

Run the isolated generated chain on a disposable Linux machine:

```sh
python3 tests/presets_runtime.py --disposable
```

## Earlier verification

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

The 0.3.4 automatic UltraCache browser preset and 30-day ordinary asset default passed all 95 backend tests and
eight native panel rejection checks. Real Nginx responses and a native panel run
verified automatic CSS-bundle immutable headers on UltraCache, ordinary headers
after switching profiles, preservation of custom patterns and central inheritance,
custom versioned lifetimes, disabled browser headers, and display of the automatic
pattern without JavaScript errors.

The 0.3.5 Restore defaults button passed all 96 backend tests and eight native
panel rejection checks. A native browser test seeded a 24-hour central policy
and custom site overrides, clicked Restore defaults once, and verified immediate
30-day static headers on both accounts, one-year versioned defaults, removal of
browser overrides/custom patterns, preservation of profiles/VCL/other settings,
and persistence after reload. No extra Save or Refresh was used.

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

Profile integration checks exercise both presets through native Nginx → Varnish → Apache/PHP, including private ESI fragments, central Basic edits, defaults, purge authentication and account isolation. They restore the original profiles/defaults and remove their temporary PHP fixtures:

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

## Cookie policy administration

The cookie-policy implementation passed its targeted Linux/root/native methods
and all 89 shared native Varnish parity cases on both profiles. These cover
current account ownership, central/site precedence, inherited resets,
shared HTML, public variants, private handling, complete source composition,
runtime drift, candidate rejection, application transaction rollback and
preservation of newer application writes.

The licensed Webuzo panel was also exercised through real administrator and
hosting-account sessions, using its actual native inventory and panel-owned IPC.
Checks included Excel paste, central Save, site override Save, reload, Reset,
renamed-row metadata restoration, inherited-source display, and refusal of a
foreign WordPress endpoint. Text edits are saved before field blur. Additional
backend checks cover native hostname reassignment and recovery after a failed
native rollback. Temporary choices were removed afterwards.

Actual Nginx → Varnish → Apache/PHP requests confirmed shared-cookie traffic
changing from MISS/MISS to MISS/HIT, separate public variants, private PASS with
downstream no-store, failed candidate preservation and an unchanged Varnish PID.
The integration runner restored its settings and VCL and removed its PHP fixtures.

The optional signed UltraCache endpoint has separate application-level checks;
the native transport tests do not substitute for testing that WordPress package.

Runtime generation identity is covered by `tests/test_runtime_identity.py`.
The native test starts an isolated Varnish with a policy exceeding its default
CLI reply size, confirms the source dump is truncated, and performs two actual
engine applies. The first adopts the boot policy through compile/load/use;
the second keeps the same generation without another load, source dump or
restart. Owned generation names carry their source digest; missing, older or
external identities are adopted through the normal transaction path.

## Concrete bundled policies

The current shared matrix passes 91 native HTTP cases. Both panel implementations
use the same 25 shared files. It includes an unconnected origin returning empty
policy settings: Alice and Bob must each fetch their own representation, then
Alice must reuse only hers. An expected contract must be a real digest before
origin policy-only variation can be trusted.

The native Webuzo renderer was exercised with 48 different site overrides while
emitting the bundled defaults once. Tracking values share HTML; consent and
currency choices retain their public variants; private sessions remain private.
Additional checks cover fingerprint-based invalidation and synchronization,
editorial changes without unnecessary purge, recognition-only proposals,
inherited Reset metadata, and current account ownership.

An actual Webuzo panel run passed 28 checks using real administrator/hosting
sessions, session CSRF, native inventory, panel-owned IPC and Nginx → Varnish →
Apache/PHP. It verified central Private, site Shared, Reset back to central,
currency variants, all bundled choices and refusal of a submitted actor. Original
settings were restored, the PHP fixture removed and the native PID preserved.
Browser inspection of that real panel confirmed three actions, hidden internal
IDs, equal-height fields and the full-width explanation row.

The v8 native lookup namespace retires objects produced by older admission
behavior. A separate warm-object test deliberately models the historical empty
header producer: a guard-only VCL replacement can still HIT an old merged object;
v8 makes that object unreachable and restores Alice/Bob variation without purge
or restart. Webuzo's normal unconnected wrapper already omits the empty header;
the injected producer is explicitly a reproduction fixture.

Addon activation now reconciles an existing service through the normal
transaction after releasing the provisioning lock. A fresh activation provisions
the panel without implicitly installing Varnish. Native lifecycle tests verify
that separation, lock ordering and propagation of a failed existing-policy apply.

## Reconciliation projection reuse

`tests/test_cookie_execution.py`, the native bridge tests and
`PolicyTransactions` cover operation-local reuse of identical resolved cookie
policies. Changed inputs, including in-place edits, receive a new projection;
a later operation starts with an empty memo. Disabling a connection still queues
its signed disconnect before skipping irrelevant apply projections. Existing
scope, fingerprint, purge and rollback checks remain in place.

An isolated same-VM comparison using 48 sites produced identical tuples for all
96 projections: 2.610 seconds before and 0.026 seconds after. Disabled connection
planning fell from 2.614 seconds to less than 0.001 seconds. The coordinator's
unchanged-state comparison fell from 7.986 seconds to 0.049 seconds with VCL
rendering and service operations mocked; these are comparison costs, not total
panel opening times. Both versions performed no load or purge for that state.
The targeted projection, bridge, transaction and lifecycle run passed 37 tests.
