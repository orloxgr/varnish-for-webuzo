# Runtime limits and defaults

Source inventory updated on 15 November 2026 against the working tree for
0.4.3. Runtime numbers labelled observed come from the earlier Varnish 9.1.0
audit on the disposable Webuzo VM; they are not current production measurements.
This inventory records the current controls and labels removed overrides.
The site TTL cap, Basic grace reset, UltraCache keep override, literal marker
lifetime, blanket error-status veto and package branch pin have been removed.

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
dashboard and write requests therefore remain subject to the proxy and
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
| Site TTL ceiling | None | The addon does not cap the origin response lifetime. Saved former ceiling values are not used. |
| Fallback TTL | 120 seconds | Observed native `default_ttl`, used when the origin and VCL supply no lifetime. There is no addon site maximum. |
| Basic grace | Origin/runtime-derived | No addon override; stale-while-revalidate remains available when the response policy permits it. |
| UltraCache grace | Origin/runtime-derived | The runtime default is 10 seconds; origin cache-control and custom response VCL can influence it. |
| Keep, both presets | Origin/runtime/administrator-derived | No forced addon value. The former UltraCache five-minute override is removed. |
| Uncacheable marker lifetime | `param.uncacheable_ttl` | Follows native Varnish configuration, without an addon literal TTL or grace/keep resets. This metadata does not contain cached private/error HTML. |
| Whole-service memory ceiling | Not explicitly configured | Observed systemd `MemoryMax=infinity`. Cache storage is not the process's complete memory use. |
| Uncacheable streaming buffer | `transit_buffer=0` | Observed Varnish default: no limit on read-ahead for an uncacheable streaming fetch. This can consume memory outside the regular cache budget. |
| Short-lived object threshold | 10 seconds | Observed `shortlived`; transient storage is separate from normal cache storage. |

The addon sets no maximum HTML body size and no separate static-file size cap.
Static assets normally bypass Varnish and are served by Nginx. The observed
`fetch_maxchunksize=0.25G` is an allocation-chunk limit, not a 256 MiB object-size
limit. Upload/body limits can still come from the hosting stack: the lab's
unmodified Nginx configuration has `client_max_body_size 200M`.

Browser asset lifetimes accept integers from zero to 2,147,483,647 seconds.
This is an explicit addon validation ceiling, separate from Varnish HTML TTL.
Browser defaults are 2,592,000 seconds (30 days) for ordinary assets and
31,536,000 seconds (365 days) for declared content-versioned assets.

## Explicit cache-policy exclusions

The source currently adds these decisions beyond numeric engine defaults:

| Rule | Effect and reason |
| --- | --- |
| Status below 200 or standalone 206/304 | Body-integrity exclusions remain. The addon no longer imposes a blanket 400+ veto: origin/native freshness applies. Native Varnish 9.1 still assigns a non-positive TTL to 500/503 unless an administrator explicitly changes it. |
| `Set-Cookie` on the response | Uncacheable; prevents replaying one visitor's cookie to another. The addon does not remove the cookie to force storage. |
| Origin `private`, `no-store`, `no-cache`, `Pragma: no-cache`, `Surrogate-Control: no-store`, `Vary: *`, or non-positive TTL | Uncacheable. These are origin instructions/representation boundaries, not subscription restrictions. |
| Authorization, private WordPress cookies, WooCommerce session/cart cookies and private application actions | PASS. An UltraCache-approved shared ESI parent is the explicit exception for supported cart/session handling. |
| Site bypass paths and administrator VCL | May explicitly force PASS or set TTL/grace/keep. They are administrator configuration, not hidden addon quotas. |
| Accept normalization | No addon length/item cutoff. Native HTTP parsing/workspace limits still apply. Explicit q=0, quoted parameters, absent/empty headers and functional Cookie variations retain their semantics. |

Uncacheable metadata now follows `param.uncacheable_ttl`, as the native 9.1
builtin VCL does. The addon does not reset its grace or keep. These markers do
not share a private response body or prevent a later cacheable response from
replacing them.

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

Complete public responses with a positive native TTL can be stored, including
HTML, JSON/XML and public redirects. Authentication, private sessions, private
WordPress/WooCommerce actions and origin privacy instructions bypass shared
cache. Public REST, searches, AJAX reads and functional query strings do not
cause blanket bypasses. Both presets share this application policy.

## Panel, installation and purge operations

| Setting | Value | Scope |
| --- | --- | --- |
| Panel JSON input | 64 KiB | Explicit PHP limit, including submitted custom VCL. Not a website upload limit. |
| Panel JSON nesting | 32 levels | Explicit PHP decoder depth for submitted settings. Response decoding uses 512 levels. |
| Additional bypass path length | 4,096 characters | Addon configuration validation per prefix, not a global limit on public URLs. |
| Private backend IPC input | 1 MiB | Secondary transport guard; normal panel requests hit the smaller PHP limit first. |
| Private credential payload | 64 KiB | Account provisioning and WordPress connector credential parsing. |
| Large worker response threshold | 32,000 bytes | Switches to a private response file; does not truncate the result. |
| Ordinary subprocess timeout | No addon wall-clock deadline | Waits for the command to finish; native service/tool deadlines can still apply. The former 120-second timeout is removed. |
| APT operations | No addon wall-clock deadline | The former 600-second kill timer is removed. APT's own connection/retry behavior remains effective. |
| Signing-key download/GPG | 30 seconds | Dependency setup. |
| Signing-key download size | 65,537 bytes read | Only a key matching the pinned SHA-256 digest is accepted. |
| Account credential helper | 15 seconds | Provisioning/removal subprocess. |
| Account credential helper diagnostic | First 500 characters | Explicit remaining error truncation in `src/credentials.py`. |
| Varnish readiness wait | 15 seconds | Addon polls the child after start/restart. |
| Varnish admin CLI | 10 seconds | Addon `varnishadm` operation timeout. |
| HTTP connection probe/readiness | 1 second per probe; 10-second polling window | Determines whether the local control endpoint is ready. Not a website request timeout. |
| WordPress purge request | 10 seconds | WordPress connector HTTP timeout on the protected local socket. |
| Error output shown by `native.run` | Complete selected diagnostic stream | The former last-3,000-character truncation is removed. |

Automatic dependency setup detects the installed Ubuntu codename and native
package architecture. Signed release metadata must match that codename and
contain a matching architecture index. APT selects the package; the candidate
must come from that official suite/architecture. There is no version/branch pin.
An existing binary is checked by compiling the addon policy, rather than by
a fixed version string. During explicit setup, addon-owned sources follow the
installed OS release on explicit setup or Refresh sites; independently managed
sources remain unchanged. No background OS-upgrade watcher is installed.
The downloaded signing key must match the pinned verified
hash; a legitimate upstream signing-key rotation requires an explicit addon
update. An independently running Varnish instance blocks automatic replacement
of its shared binary.

The local HTTP control port must be from 1 to 1023 **and** require privileged
binding under the host's current policy. This prevents a hosting user from
impersonating the endpoint and collecting other accounts' tokens. The private
admin listener is separate on loopback port 6086. Tokens, site scopes, CSRF,
root-only panel access, non-following file operations and service sandboxing
are access/security boundaries, not cache quotas.

The dedicated service identity must currently have a UID from 1 to 999, the
expected dedicated group, `/nonexistent` home and non-login shell; it may not
be shared with other users. The numeric UID range is an installer assumption
in addition to the actual dedicated-identity requirement. Existing owned unit
content must exactly match the generated unit before changes/removal.

The site VCL editor accepts a restricted language: conditions, custom
`X-User-*` headers, request PASS, and response TTL/grace/keep. Arbitrary imports,
backend definitions and changes to cross-site routing/security fields are not
accepted. This is an intentional site-local editing boundary.

Versioned browser asset patterns accept literal ASCII URL paths, `*` within
one path segment and `{hash}` matching 16 to 128 hexadecimal characters, with
a supported public asset extension. A shorter/different fingerprint does not
break asset delivery; it gets the ordinary asset lifetime instead of the
declared immutable lifetime. The static asset extension allowlist and private
upload-path exclusions govern direct Nginx delivery.

There is no periodic connection-test requirement, trial expiration, site-key
expiration or license-based usage limit. Normal WordPress nonces and Webuzo
panel sessions still have their own authentication lifetimes.

## Follow-up priorities

### Requirement versus addon choice

Shared policy convergence uses Hestia 0.15.1, commit
`a7261d90349b300d767af33e7f2051e01a004a42`, as its upstream baseline.
The complete shared/cache-policy.vcl is now bundled unchanged in each integration.
The Hestia removal list concerned cache policy and package selection; this
document also inventories the Webuzo panel, transport and helper controls.

| Item | Classification and current result |
| --- | --- |
| Site/account/host boundaries, scoped purge credentials and private sessions | Required to provide shared hosting caching without exposing another tenant or visitor's state. Retained. |
| Origin privacy, Set-Cookie and real representation negotiation | Required correctness/privacy policy. Retained. Neither integration needs to rewrite every ordinary Set-Cookie response to private/no-store just to keep it out of Varnish. Webuzo already preserved those ordinary origin headers. |
| Five-minute site TTL cap and forced Basic grace zero | Addon choices, not Varnish requirements. Removed before this change. |
| Literal uncacheable marker TTL, grace/keep resets | Redundant addon overrides. Removed; native `param.uncacheable_ttl` applies, as in Hestia. A marker is not a cached private body. |
| Forced UltraCache keep five minutes | Optional retention tuning, not a correctness requirement or fresh-TTL cap. Removed, as in Hestia. |
| Blanket 400+ response veto | Additional addon policy, not an engine requirement. Removed, as in Hestia. Native freshness decisions still apply: tested 404/410 HIT and native 500/503 PASS unless explicit administrator TTLs override freshness. Private error bodies remain uncacheable. |
| Fixed OS codename and package version selection | Installer implementation choices. Webuzo now detects the Ubuntu codename/architecture and verifies matching signed metadata and APT candidate, with a real policy-compile compatibility check. Hestia's current installer still names Ubuntu resolute/amd64. |
| Metadata signature and package-removal checks | Dependency authenticity and service-preservation boundaries. Retained. The signing-key hash is a deliberate trust pin, not a Varnish version restriction. |
| Finite HTTP inactivity timeouts | Networking/resource policy. Their values are not inherent cache requirements. Webuzo inherits hosting allowances and raises intermediate budgets so the extra proxy does not impose a shorter one. |
| Administrative 10/15/30-second deadlines and 500-character diagnostic truncation | Addon UX/implementation choices, not Varnish requirements. Still present; they must not be presented as essential engine/security constraints. |
| 64-KiB/1-MiB input bounds and JSON depth | Defensive resource bounds with addon-selected values, not Varnish requirements. They affect configuration/credentials, not public page size or cache HIT eligibility. |
| 4,096-character bypass prefixes, UID 1–999 and browser lifetime integer ceiling | Addon validation assumptions, not intrinsic Varnish constraints. Still present. Non-root dedicated service ownership is the actual identity/security requirement, independently of the UID range. |
| Restricted VCL editor | Deliberate site-local product editing scope; Varnish itself supports more VCL. Still present. |
| 256-MiB initial storage budget | Addon starting value, adjustable without an addon maximum. Storage capacity is necessary; that particular number is not. |

### Remaining work

1. Retain visibility of inherited hosting allowances and their derived proxy
   budgets. The engine's finite total response deadline and native PHP/Apache
   settings still matter for exceptionally long operations or streams.
2. Make native fallback TTL and grace behavior visible without reintroducing
   an independent addon maximum TTL.
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
