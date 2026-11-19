# Shared cache policy contract

`cache-policy.vcl` and its explicit `vcl/*.vcl` source modules are shipped
byte-for-byte in each distribution. `vcl_source.py` expands them into one complete
runtime program before compilation (see `VCL-ARCHITECTURE.md`). They contain
Basic/UltraCache request, privacy, ESI, representation and key policy. They import
nothing from another checkout or network resource. The adapter imports `std`
and `purge`, `header`, and `cookie_handoff` in the complete VCL and defines
host/backend/token isolation. `header` comes from the ABI-matching official
`varnish-modules` package; duplicate Set-Cookie fields are never comma-joined.

## Local cookie catalogue

### Anonymous aggressive HTML and CMS routing

`aggressive.py`, `cms_routes.py`, `cms_discovery.py`, `cms_metadata.py` and
`cms_cookies.py` are common panel-independent source. The adapter supplies native
document roots and static CMS/cookie descriptors during panel reconciliation.
Aggressive mode is per-site and default OFF. It stores eligible public 200 HTML
despite generic origin Cache-Control/Surrogate-Control/Pragma/Expires restrictions,
using the selected TTL without a lower addon cap. Original browser policy is
restored at delivery. Known private routes/actions, authentication/cart markers
and explicit administrator Private/Variant choices retain precedence.

Public HIT performs only Varnish work. There is no CMS helper service, session
database lookup, PHP/HTTP token provider, body inspection or Joomla token ESI.
Generic PHP and recognized Joomla session cookies are Shared in aggressive mode;
their original values still reach the origin on a MISS/PASS. Tracking affects
only the internal key, never the original URL. Functional query values remain
part of the key. CMS discovery/configuration SQL happens only in panel actions.

The opt-in treats allowed HTML as common. Joomla HTML, scripts, forms and token
values are stored and delivered unchanged; the addon does not infer hidden
authentication state inside opaque sessions or generate visitor-specific tokens.
Application-specific problems are addressed with explicit site rules or a future
application integration. No automatic replacement admission gate is introduced.

Original response Set-Cookie fields are detached before shared storage and
returned only to the fetching visitor. A warm HIT does not contact the origin to
issue another visitor's cookie. Existing UltraCache private ESI remains dynamic;
aggressive mode adds no new fragments or requests.

### Reviewed database lifecycle

Recognition descriptions, assessments and concrete executable defaults ship
in the same reviewed plugin version. Installed panels do not schedule upstream
recognition downloads or consume downloaded-only snapshots. Existing local
snapshots remain untouched for rollback. Explicit central/site choices retain
precedence when bundled defaults change. The shared recognition downloader is
a development/import helper; raw upstream categories never activate policy.

The shared `cookie-policies.json` is the reviewed execution catalogue, schema 1.
`cookie_catalogue.py` validates it and expands `@@COOKIE_PATTERN_<consumer>@@`
markers when the adapter generates a complete standalone VCL. The three current
consumers are `varnishPrivate`, `varnishCart`, and `varnishTrackingIgnore`.
Exact and prefix cookie names are case-sensitive and escaped as literal PCRE.
No recognition category grants an executable policy or a cookie issuer.

The catalogue distinguishes HTML effect, key role, issuer, independent-delivery
support, consent, and cookie attributes. An unsupported independent issuer does
not disable an existing cookie's request policy. Unknown cookies keep existing
HTTP behavior. Removing tracking variation never removes those cookies from
the origin request and never grants permission to replay personal Set-Cookie.

`cookie-recognition/recognition.json` is an attributed, revision-pinned Open
Cookie Database snapshot. Its Apache-2.0 license is shipped alongside it. It is
consumed by the cookie administrator table, together with the per-record
`cookie-assessments.json`. It is not read during a visitor HTTP request. Versioned editorial defaults and validated explicit snapshots become generated
VCL choices; newly downloaded recognition rows cannot change executable defaults. Do
not replace executable rules with a category-derived allowlist. All distributed
copies of the reviewed catalogue and compiler must agree at release time;
installed servers neither import another checkout nor contact a lookup service.

### Explicit administrator choices (schema 1)

`cookie_admin.py` is shared unchanged. Settings are
`{"schemaVersion":1,"rules":[{"id":"ocd:source-id|policy:reviewed-id|custom:uuid",
"match":{"kind":"exact|prefix","value":"literal-name"},
"description":"plain text","action":"shared|variant|private"}]}`.
Names are case-sensitive escaped literals; a prefix is not arbitrary regex.
Legacy literal colon/slash/brackets/Unicode/internal spaces are supported.
Reject empty names, leading/trailing whitespace, controls/DEL and ; = " { }.
These are Cookie/VCL injection boundaries, not limits on work size.
Saved names/choices are snapshots: upstream metadata changes do not rewrite them.
An upstream description is retained by the updater when available. Assessments
are explicitly reviewed or inferred; external categories do not grant execution.

The API is `normalize(value)`, `table(database,catalogue,central=None,site=None)`,
`resolve(central=None,site=None)`, `executable(central=None,site=None)` and
`compile_vcl(central=None,site=None)`. `table` includes the proposal separately
from the actual action, origin/scope, inherited action, local snapshot, confidence
and reason. Recognition rows and their bundled executable choices are versioned together.
New names outside the versioned bundle are `scope=recognition, active_rule=false`
with a concrete proposal, never falsely labelled as applied. A local choice
activates them through the ordinary save transaction.
All bundled rows have concrete executable decisions; confidence is
an evidence label, not an activation switch. Reset removes the local snapshot.
Legacy stored `automatic` is accepted for rollback compatibility, but `concrete`
resolves it to an identical/covering default, otherwise Variant. A prefix never
uses its first child's decision. New editors offer only the three concrete actions.

`cookie_defaults.py` builds the defaults from pinned `cookie-assessments.json`
and the reviewed catalogue. The generated `cookie-defaults.json` is the identical
schema-1 rule snapshot for independent consumers, with version/sourceRevision
metadata outside the inner settings. `materialize(central)` flattens admin choices
above defaults; `active(central,site)` resolves site above that snapshot. Within
scope sort exact first, longest UTF-8 byte length first, literal name then ID.
Empty internal pair/variant headers are unset after normalization: an empty
header must not add a hash dimension that an authenticated soft purge cannot
address. Anonymous and Shared-only visitors reuse the same public object.
Prefix coverage uses a trie; bundled exact names compile into disjoint action
groups. Prefix action groups exclude more-specific overlapping selectors of
a different action, preserving nested exceptions without per-record blocks. Adapters emit
`defaults_vcl()` once at top level and call `compile_vcl(...,chain_defaults=True)`
for explicit site/admin choices. The latter initializes a working header, consumes
explicit pairs first, calls the common defaults on the remainder, then finalizes
once. Thus even different per-site overrides never duplicate the entire bundle.
Identical local dispatch bodies can additionally be grouped by site identity.

Native state records `cookie_defaults_version` for display and a metadata-free
`cookie_defaults_digest` from `cookie_defaults.fingerprint()` for execution.
A changed executable bundle synchronizes connected applications and invalidates
site caches transactionally; a text/version-only edit does not.
Keep descriptions/IDs out of the effective digest. Upstream recognition updates
still cannot change this version or activate new category-derived rules.

Site rules precede central choices, which precede bundled defaults; within a scope exact matches precede longest
prefixes. Higher matches consume pairs from an internal copy so a lower broad
prefix cannot undo a specific choice. Contradictory equal matches in one scope
are rejected. Core authentication, cart/ESI contracts, request credentials and
origin private/no-store decisions remain authoritative. Shared response cookies use the request-owned handoff below.

The adapter passes a site-scoped dispatcher body into
`shared_policy(admin_rules='')` / `render_policy(source,catalogue,admin_rules='')`.
It executes in `scp_admin_cookie_rules` after core request privacy. Shared removes
matching pairs from internal Cookie variation, never the real origin Cookie.
Variant selects actual cookie pairs, including every matched prefix pair, and
`scp_cookie_hash` adds their values to lookup even without origin Vary. Call that
helper only in `vcl_hash`, not from `scp_key` (also used by authenticated PURGE).
Downstream deliveries advertise Vary: Cookie for configured public variants and
private selectors, including the no-cookie public representation. An outer cache
must not answer a later private-cookie request from the anonymous object before
it reaches the native guard. This signal does not add unrelated cookies to the
internal key. Private returns pass and marks downstream delivery no-store.

`scp_init` rejects forged admin scratch. Backend hooks remove it before origin.
Diagnostics expose rule ID, scope, action and cookie name, never a personal
value. A matching later private rule reports its actual private cause. Adapters
compare the metadata-free executable projection to invalidate changed site scope;
description/ID-only edits do not require cache invalidation. They retain their
native account authorization, CSRF and transactional load/use/rollback.

### Application-owned public Cookie variation

An independent WordPress cache must expose `Vary: Cookie` for its public variants
to generic proxies. Our native adapter can avoid varying on unrelated automatic
cookies only with a matching explicitly connected contract:

- `cookie_control.cache_contract(configuration,host,aliases,central,site)` returns
  the effective digest for every explicitly connected policy, including
  the materialized defaults and all admin/site choices; disabled connections return empty.
- The native site route assigns that value to `X-SCP-Cookie-Contract` after init.
- The origin emits `X-UltraCache-Cookie-Settings: <effective digest>` and
  `X-UltraCache-Cookie-Vary: policy-only` only when it owns the entire Cookie Vary
  decision. Pre-existing/third-party Cookie Vary must not receive that marker.

For that exact match the internal Cookie Vary dimension is removed: explicit
selected cookie pairs already participate in `scp_cookie_hash`. Downstream
delivery still includes the origin's `Vary: Cookie`. A valid different origin
digest retains literal native `Vary: Cookie`: an older Shared or tracking-ignore
projection cannot describe a newer application policy. These representations
still cache normally. Unknown/mixed provenance and Basic without the optional
connection retain the existing functional Cookie Vary handling.
Origin private/no-store remains authoritative, Shared response fields use the
request-owned handoff, and the
original request Cookie reaches the application unchanged. Incoming browser
copies of all three contract headers are discarded by init. The application
derives its markers from its stored signed policy and source-response provenance,
never from a request header. Static deliveries must preserve the actual source's
provenance; they cannot simply stamp every cached file as policy-only.

## Common cookie handling; provider-owned issuance

All cookie names, including `_fbp`, use the same Shared/Variant/Private rules.
The native proxy does not generate cookie identifiers or turn a cache action
into consent. The former per-site Meta issuer/configuration is retired.
Applications/providers own cookie creation, renewal, deletion and actual consent.
`cookie_admin.response_rules()` uses the same ordered site > central > bundled
choices and exact/prefix resolution as requests, with core authentication/cart
privacy first. An otherwise public, fresh response can cache only if every
Set-Cookie name resolves to Shared. Mixed Private/Variant/unknown names retain
the original uncached response. No cookie values enter generated rules.

The common `cookie_handoff` VMOD binds a backend task to its originating client
MISS using an internal identity removed before the origin request. It copies
complete original fields into that client task’s temporary memory, removes them
before object storage, and appends them only to that client’s response. Task
finalization frees pending fields on delivery or abort; concurrent requests do
not share this state. Background fills discard their non-client Shared fields.
Private ESI children do not promote cookies into a shared parent response.
Deliveries containing original Set-Cookie remain downstream private/no-store;
the stored public HTML retains its public freshness.

Build `shared/native/*.c`/`.vcc` with `native_build.build()` against the installed
native `varnish-dev` ABI, before publishing a VCL that imports it. Build identity
covers both source files and native ABI. Atomic library replacement preserves
running VMOD mappings; source changes get a new generated VMOD identity. Native
startup rebuilds against matching updated headers before loading the durable
VCL. This dependency does not select a newer engine during addon installation.

On warm HITs, actual browser/provider or private application endpoints continue
to own identifier creation and consent. The Meta/WooCommerce provider endpoint
is one existing integration, rather than a special native generator or form.

For an origin-approved shared ESI parent, `Vary: Cookie` uses the internal
functional remainder without private cart carrier cookies. Original cookies
still reach the origin/private children; ordinary objects retain functional
Vary. `X-UltraCache-ESI-Private-Count` determines downstream privacy: a delivery
containing private fragments is private/no-store, while public-only ESI keeps
normal public caching. The generic private-delivery helper remains available.

Value-free diagnostics are `X-Cache-Cookie-Names`, `X-Cache-Cookie-Role` and
`X-Cache-Cookie-Policy`. They report actual matched rules without cookie values,
session tokens or credentials. There is no native provider-issuance diagnostic.

## Calls and trusted inputs

Private PHP-session source GETs use the existing raw collector transport. When
`X-UltraCache-Warm-Source: raw-v1`, `X-UltraCache-Internal-Request: 1`,
`X-UltraCache-Warm: 1`, `X-UltraCache-Session-Source-Kind: native|observed` and
`X-UltraCache-Session-Source: v1:<64 lowercase hex>:<64 lowercase hex>:<64 lowercase hex>:<64 lowercase hex>`
all match, `scp_recv` returns PASS before profile-specific cookie transport or
cache lookup. The original URL, cookies and source headers reach the origin.
This bounded shape is routing only: it does not authenticate the request, grant
public HTML eligibility or trust a PHP session. UltraCache still verifies its
purpose-bound MAC and one-use observation owner. An invalid MAC of the same shape
also reaches the application for refusal; its response cannot fill a shared object.
Other requests, including ordinary request `Cache-Control: no-store`, retain their
existing handling. No generic PHPSESSID Shared choice or native state gate is added.

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
Do not expose the internal Cookie/Accept/Accept-Language Vary keys in downstream responses.
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

Both presets normalize simple `Accept` and `Accept-Language` lists in internal
Vary keys without requiring application metadata or a plugin. Case-insensitive
media/language tokens, insignificant spacing and equivalent q weights share
variants. Absent quality and q=1 are equivalent; fractional trailing zeros and
zero notation are canonicalized. Preference order, different weights, actual
language/media differences and absent versus empty headers remain distinct.
Media parameter values, quoted values and nonstandard syntax are not subjected
to this additional normalization. Original request headers reach the origin,
temporary normalization scratch is removed before the fetch, and downstream
Vary retains the public header names. These rules neither admit private content
nor block a request with different syntax.

For exact URL PURGE, call `scp_key` on the authenticated original purge URL and
BAN within the adapter site scope by `X-Cache-Object-URL == X-SCP-Key-URL`.
Soft PURGE must use the same `vcl_hash`. Exact/batch/regex BAN expressions select
**canonical lookup URLs** in X-Cache-Object-URL, not the original tracking URL of
whichever visitor filled the object. Do not try to normalize arbitrary regex
source with the URL normalizer. The producer can use exact PURGE with any
tracking URL; regex BAN selectors target the documented canonical URL space.
HTTP and HTTPS remain separate Vary representations of one purgeable URL.

Tracking remains visible to browser analytics. Code executed in PHP on every
landing requires its own tracking request/before-cache integration; a HIT does
not execute the cached main-page PHP route. Joomla's private token provider may
separately execute its native core component on a parent HIT. The addon does
not inject or modify application source code.

## Verification

Run the same shared parity fixtures against both native generated adapters.
SHA checks are development/release checks only. They are not runtime or installer
requirements and never require another repository to exist on the server.

The explicit development command `tools/compare-policy.py --other CHECKOUT`
compares the policy, HTTP cases and runner byte-for-byte. Optional
`--left-report JSON --right-report JSON` also verifies that both native runs
used those exact sources and completed every shared case. It is never imported
or invoked by the installed plugin or installer.
