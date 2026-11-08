# Runtime limits and defaults

Audited on 8 November 2026 against the addon source and its Varnish 9.1.0
instance on the disposable Webuzo VM. Values below are observed lab settings
or explicit source constants, not a measurement of a production installation.
The request-timeout section reflects the subsequent hosting-inheritance fix,
tested on the same VM. Other values remain the observed audit settings.

## Request processing

| Setting | Value | Owner and effect |
| --- | --- | --- |
| Nginx upstream connection timeout | Native Webuzo allowance | Read from the loaded Nginx configuration; 300 seconds on the lab. The former addon 2-second override is removed. |
| Origin/fallback Nginx read timeout | Native Webuzo allowance | Inactivity between reads; 300 seconds on the lab. The former addon 120-second override is removed. |
| Nginx upstream send timeout | Native Webuzo allowance | Inactivity between writes; 300 seconds on the lab. No independent addon constant. |
| Front Nginx read timeout | Derived from upstream phases | `2 × connect + 2 × send + read`; 1,500 seconds on the lab. Allows the intervening Varnish/origin bridge to finish its native connection, sending and response-wait phases. |
| Varnish backend connect timeout | Native Webuzo connection allowance | 300 seconds on the lab, replacing the inherited 3.5-second default for these backends. |
| Varnish backend first-byte timeout | `connect + send + read` | 900 seconds on the lab, replacing the inherited 60-second default and allowing the origin bridge's phases. |
| Varnish backend between-bytes timeout | Native Webuzo read allowance | 300 seconds on the lab; not an overall WordPress execution budget. |
| Varnish client idle timeout | 5 seconds | Observed default, for an idle connection/receiving request headers. |
| Varnish idle send timeout | Native Webuzo read allowance | 300 seconds on the lab, for delivery to the front Nginx. |
| Varnish total response timeout | At least the front proxy allowance | Raises a shorter engine/session budget; never lowers a larger one. The engine default is 600 seconds; the lab policy raises it to 1,500 seconds. This remains a finite Varnish total-response deadline, not unlimited streaming. |
| Backend idle connections | 60 seconds | Observed default; unused connection lifetime, not request processing time. |
| Failed upstream retry | Disabled in Nginx | Addon `proxy_next_upstream off`. Its separate failure route can fall back to Apache for GET/HEAD. Writes are not replayed. |

`PASS` skips shared caching but still traverses Varnish. WordPress login,
dashboard, AJAX and write requests therefore remain subject to the proxy and
Varnish backend timeouts. The current site VCL editor cannot change backend
timeouts: its writable response fields are TTL, grace, keep and `X-User-*`.

Setup, Refresh sites and successful policy/settings changes inspect `nginx -T`,
without modifying native files. The addon selects the widest explicitly loaded
native `proxy_connect_timeout`, `proxy_read_timeout` and `proxy_send_timeout`,
including longer domain overrides. Its own generated files are excluded, so
old 2/120-second overrides and derived outer values do not feed back into the
next calculation. Where no native directive exists, Nginx's documented 60-second
default is used. Invalid/unreadable configuration aborts before a policy is changed.

The saved allowances are visible in the panel. Existing installations need
**Refresh sites** once after updating the addon; this reloads the owned VCL and
proxy snippets without restarting Varnish or purging solely for a timeout change.
Subsequent native timeout edits are picked up on the next apply/refresh; this
is not a background watcher. Apache, PHP/FPM, browser and other hosting timeouts
remain independent. This fix does not promise requests of unlimited duration.

## Cache lifetime and memory

| Setting | Value | Effect |
| --- | --- | --- |
| Initial shared cache budget | 256 MiB | Addon default for all enabled sites together. Editable in the panel; minimum 1 MiB and no addon-defined upper cap. |
| Initial site maximum TTL | 300 seconds | Addon default, editable per site. This caps a longer lifetime; it does not establish a fallback TTL. |
| Fallback TTL | 120 seconds | Observed `default_ttl`, used when the origin and VCL supply no lifetime. Raising the site's maximum alone does not raise this fallback. |
| Basic/WordPress/WooCommerce grace | 0 seconds | Addon VCL override, so expired pages do not receive a stale-serving grace window by default. |
| UltraCache grace | Origin/runtime-derived | The runtime default is 10 seconds; origin cache-control and custom response VCL can influence it. |
| UltraCache keep | 5 minutes | Addon default window for retaining expired objects for conditional revalidation; not an extra fresh TTL. Other profiles retain the runtime default of zero unless customized. |
| Uncacheable marker lifetime | 120 seconds | Addon VCL creates uncacheable metadata, not cached private/error HTML. Subsequent responses still reach the origin and a cacheable response can replace the marker. |
| Whole-service memory ceiling | Not explicitly configured | Observed systemd `MemoryMax=infinity`. Cache storage is not the process's complete memory use. |
| Uncacheable streaming buffer | `transit_buffer=0` | Observed Varnish default: no limit on read-ahead for an uncacheable streaming fetch. This can consume memory outside the regular cache budget. |
| Short-lived object threshold | 10 seconds | Observed `shortlived`; transient storage is separate from normal cache storage. |

The addon sets no maximum HTML body size and no separate static-file size cap.
Static assets normally bypass Varnish and are served by Nginx. The observed
`fetch_maxchunksize=0.25G` is an allocation-chunk limit, not a 256 MiB object-size
limit. Upload/body limits can still come from the hosting stack: the lab's
unmodified Nginx configuration has `client_max_body_size 200M`.

The site lifetime accepts integers from 1 to 2,147,483,647 seconds. The upper
bound is an integer/implementation constraint, not a subscription or usage cap.

## HTTP parsing, concurrency and ESI

These are observed Varnish defaults; the addon supplies no `-p` overrides:

| Parameter | Value |
| --- | --- |
| Individual request header | 8 KiB |
| Total request headers | 32 KiB |
| Individual response header | 8 KiB |
| Total response headers | 32 KiB |
| Header count | 64 |
| Client/backend workspace | 96 KiB each |
| Thread pools | 2 |
| Threads per pool | Minimum 100, maximum 5,000 |
| Waiting queue per pool | 20 requests |
| ESI nesting depth | 5 |
| Restart/retry maximum | 4 each; a ceiling, not a directive to perform four retries |
| LRU allocation eviction limit | `nuke_limit=50` |

The addon sets `LimitNOFILE=131072`. The lab inherited systemd `TasksMax=7026`,
so the nominal Varnish thread-pool ceiling is not an independently guaranteed
10,000 usable workers. There is no addon quota on sites, accounts, cache clears
or requests per second.

There are protocol and security-policy exclusions: only status-200 HTML is
eligible for shared page storage; private cookies, authorization, write
requests, error responses and origin privacy instructions remain protected.
Basic additionally bypasses every cookie and query string. WordPress and
WooCommerce apply their documented private route/cookie exclusions instead;
UltraCache also normalizes selected marketing parameters. These are explicit
profile policies, not limits imposed by the Varnish engine.
The VCL editor intentionally permits a scoped subset of VCL instead of arbitrary
code, backend changes, imports or access to internal credentials.

## Panel, installation and purge operations

| Setting | Value | Scope |
| --- | --- | --- |
| Panel JSON input | 64 KiB | Explicit PHP limit, including submitted custom VCL. Not a website upload limit. |
| Additional bypass path length | 4,096 characters | Addon configuration validation per prefix, not a global limit on public URLs. |
| Private backend IPC input | 1 MiB | Secondary transport guard; normal panel requests hit the smaller PHP limit first. |
| Private credential payload | 64 KiB | Account provisioning and WordPress connector credential parsing. |
| Large worker response threshold | 32,000 bytes | Switches to a private response file; does not truncate the result. |
| Ordinary subprocess timeout | No addon wall-clock deadline | Waits for the command to finish; native service/tool deadlines can still apply. The former 120-second timeout is removed. |
| APT operations | No addon wall-clock deadline | The former 600-second kill timer is removed. APT's own connection/retry behavior remains effective. |
| Signing-key download/GPG | 30 seconds | Dependency setup. |
| Account credential helper | 15 seconds | Provisioning/removal subprocess. |
| Varnish readiness wait | 15 seconds | Addon polls the child after start/restart. |
| Varnish admin CLI | 10 seconds | Addon `varnishadm` operation timeout. |
| WordPress purge request | 10 seconds | WordPress connector HTTP timeout on the protected local socket. |
| Error output shown by `native.run` | Complete selected diagnostic stream | The former last-3,000-character truncation is removed. |

Automatic dependency setup currently supports Ubuntu 24.04 and pins Varnish to
the 9.1 patch branch. The downloaded signing key must match the pinned verified
hash; a legitimate upstream signing-key rotation requires an explicit addon
update. An independently running Varnish instance blocks automatic replacement
of its shared binary.

There is no periodic connection-test requirement, trial expiration, site-key
expiration or license-based usage limit. Normal WordPress nonces and Webuzo
panel sessions still have their own authentication lifetimes.

## Follow-up priorities

1. Retain visibility of inherited hosting allowances and their derived proxy
   budgets. The engine's finite total response deadline and native PHP/Apache
   settings still matter for exceptionally long operations or streams.
2. Expose fallback TTL separately from maximum TTL, and make grace behavior
   clear. A larger maximum alone does not extend headerless page caching.
3. Provide a capacity view covering cache storage, transient/processing memory,
   workspaces, thread queues and systemd task limits. Budget selection should
   reflect the server and workload rather than assume 256 MiB is sufficient.
4. Surface HTTP header limits and correlate them with real overflow/error
   counters before changing them. A larger workspace does not automatically
   increase the separate header-size limits.
5. Review the panel input limit and administrative command deadlines; preserve
   complete diagnostics and use tracked background work where duration varies.

Reference: [Varnish Software tuning guide](https://docs.varnish-software.com/book/operations/tuning-varnish/).
The installed instance's `varnishadm param.show` values take precedence over
numbers quoted in general or older documentation.
