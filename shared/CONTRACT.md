# Shared cache policy contract

`cache-policy.vcl` is included byte-for-byte in each distribution. It contains
Basic/UltraCache request, privacy, ESI, representation and key policy. It imports
nothing from another checkout or network resource. The adapter imports `std`
and `purge` in the complete VCL and defines host/backend/token isolation.

## Calls and trusted inputs

1. At the start of `vcl_recv`, call `scp_init` before accepting client metadata.
   It removes forged `X-SCP-*` inputs and inherited ESI carrier/approval headers. The private carrier is
   recovered from req_top when needed.
   Authenticate/dispatch the site, validate ESI same-site scope and choose backend
   in the adapter. Set `req.http.X-SCP-Profile` from the trusted site selection
   (`basic` or `ultracache`) before disabled/custom bypasses.
2. Apply explicit administrator bypasses, then call `scp_recv`. It can return PASS. Otherwise the adapter
   returns hash. It does not strip tracking URL arguments or analytics cookies
   from the origin request. UltraCache's existing opt-in marker-cookie transport
   is internal ESI protocol, not analytics-cookie filtering.
3. In `vcl_pass`, call `scp_pass` (also for administrator/request bypasses).
4. In `vcl_hash`, call `scp_key`, then hash the adapter cache namespace, immutable
   site scope, host and `req.http.X-SCP-Key-URL`. No profile/scheme hash dimension:
   scheme is `Vary: X-Forwarded-Proto`. Refresh namespace once for this policy.
5. In `vcl_hit`, handle authenticated soft purge first, then call `scp_hit`.
6. In `vcl_backend_fetch`, call `scp_backend_fetch`.
7. In `vcl_backend_response`, apply explicit administrator response rules, assign
   immutable site/host metadata, and set `X-Cache-Object-URL` from
   `bereq.http.X-SCP-Key-URL`. Then call `scp_backend_response`; return deliver.
8. In `vcl_deliver`, call `scp_deliver`; copy `resp.http.X-SCP-Result` and
   `X-SCP-Result-Reason` to panel-specific response headers, then remove both
   scratch outputs and the adapter site/object metadata. The common hook restores
   public Vary and supplies X-Cache/Hits; it removes its other response scratch.

`X-SCP-*` is internal. Site VCL editors must not allow callers to modify it.
Do not expose the internal Cookie/Accept Vary key in downstream responses.
The common policy owns all request/response privacy and retention decisions;
remove duplicate panel-specific versions of those rules.

## Keys and invalidation

`scp_key` normalizes a copy only, leaving `req.url` untouched. It removes named
utm_*, gclid/dclid/fbclid/msclkid/gbraid/wbraid/igshid arguments. All functional
arguments, including search, ref, language, currency, duplicate values and their
order remain. The Cookie variant ignores only known analytics IDs; unknown,
referral, language and consent cookies remain. The public stored-HTML response
contract can collapse equivalent HTML image capabilities. It accepts origin
Apache-static provenance or an actual `X-Ultra-Cache: HIT`, with the existing
public/cacheable/variant/no-Set-Cookie checks. This includes stored ESI parents;
new dynamic `STORE` responses retain raw Accept variation. Static and dynamic
HTML both retain functional Cookie variation; only analytics IDs are omitted.

For exact URL PURGE, call `scp_key` on the authenticated original purge URL and
BAN within the adapter site scope by `X-Cache-Object-URL == X-SCP-Key-URL`.
Soft PURGE must use the same `vcl_hash`. Exact/batch/regex BAN expressions select
**canonical lookup URLs** in X-Cache-Object-URL, not the original tracking URL of
whichever visitor filled the object. Do not try to normalize arbitrary regex
source with the URL normalizer. The producer can use exact PURGE with any
tracking URL; regex BAN selectors target the documented canonical URL space.
HTTP and HTTPS remain separate Vary representations of one purgeable URL.

Tracking remains visible to browser analytics. Code executed in PHP on every
landing requires its own tracking request/before-cache integration; a HIT never
executes that PHP. There is no automatic application-code injection here.

## Verification

Run the same shared parity fixtures against both native generated adapters.
SHA checks are development/release checks only. They are not runtime or installer
requirements and never require another repository to exist on the server.

The explicit development command `tools/compare-policy.py --other CHECKOUT`
compares the policy, HTTP cases and runner byte-for-byte. Optional
`--left-report JSON --right-report JSON` also verifies that both native runs
used those exact sources and completed every shared case. It is never imported
or invoked by the installed plugin or installer.
