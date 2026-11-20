# Request-owned public publication selection

Tracking: #966, #968. Agreed with the authorized native owner on 20 November
2026. This describes the next implementation, not an executed runtime result.
The existing prepare/recovery protocol and its source-manifest validation remain
unchanged. The actual WCML counter is recorded in COOKIE-PARITY-ALIGNMENT.md.

## Purpose and ownership

A country-driven first visit has no incoming currency cookie. Only the real
application provider can resolve that visitor's currency. Selecting an already
warmed USD object before that resolution serves the wrong price to a EUR visitor.
An existing USD cookie can also become invalid in the provider's current country.

The new entry executes the actual original WordPress route before final public
lookup. It resolves the provider context, reads the correct existing public
snapshot or builds a cold target through the normal engine, and prepares its
private fragments in that same PHP operation. The final native delivery reuses
these results instead of bootstrapping the provider again. This is public HTML
HIT with one provider/bootstrap operation, not a zero-PHP request. A warm target
does not require rendering its template again.

WordPress and native policies remain independent. Native Shared/Variant/Private
comes only from the active selected-profile native matcher. WordPress keeps its
own local choices, publication context and policy identity. Neither policy
replaces the other. No provider cookie veto list or fourth action is introduced.
Basic retains incoming-cookie behavior without pretending to run WP integrations.

## Negotiation

Reuse the existing authenticated HTTP contract: `PURGE`,
`X-UltraCache-Contract: 2`, `X-UltraCache-Operation: capabilities`, the real site
Host, and the existing `X-UltraCache-Token` credential. This capabilities
operation does not invalidate cache. Add these request headers:

```
X-UltraCache-Public-Selection-Version: 1
X-UltraCache-Public-Selection-Enabled: 1
X-UltraCache-Public-Selection-Scope: <normalized relative frontend base, e.g. / or /shop/>
X-UltraCache-Public-Selection-WordPress-Policy: <WP effective digest>
X-UltraCache-Public-Selection-Cookies: <comma-separated exact resolver names>
```

These names declare actual installed resolver metadata, never cookie values.
Scope is mandatory on both registration and removal: `/` is explicit, never an
implicit registration fallback. It comes from the application's stable configured
frontend base, not a request-dependent language-filtered home URL, core siteurl
or administration path. It has a leading and trailing slash, no query/fragment,
backslash, dot segment or repeated slash. Matching is literal (no decoding),
ignores the query, and uses the longest registered scope. `/shop` belongs to
`/shop/` for its normal canonical redirect; `/shopper/` does not.

Enabled 0 unregisters only the exact site/host/scope. An ordinary capabilities
request with no declaration does not modify any registration. Such a read-only
probe may supply Scope alone to query an exact application; without Scope it
reads root metadata. This read-only compatibility default cannot register a root
application. No panel cookie-integration flag is required.

Enabled 1 means the existing connected/cache-enabled application participates,
independently of whether a resolver is currently installed. An empty Cookies
list is valid application metadata with Actions `{}`. That boundary shadows an
ancestor declaration without a provider operation, cookie action or additional
cache bypass. Provider absence must not remove a participating child and expose
it to the parent's WP policy. Activation/settings/update flows establish the
boundary before relying on a first child frontend request. Enabled 0 is for
retiring cooperation (including moving or deactivating), not provider inactivity.

The authenticated capabilities response advertises:

```
X-UltraCache-VCL-Public-Selection-Version: 1
X-UltraCache-VCL-Public-Selection-Epoch: <native DSO build identity>
X-UltraCache-VCL-Public-Selection-Native-Policy: <active native digest>
X-UltraCache-VCL-Public-Selection-WordPress-Policy: <accepted WP digest>
X-UltraCache-VCL-Public-Selection-Scope: <accepted exact frontend base>
X-UltraCache-VCL-Public-Selection-Actions: <JSON exact name to effective action>
```

Actions use the existing generated matcher, including the current Shared
behavior for names with no matching rule. Omitting an unmatched name cannot
create a new unresolved-state veto. Activate when a declared name has actual
native Variant behavior. Recompute native actions after policy changes.

The accepted Scope and WP digest are both absent if no exact registration exists
for the queried scope; an empty names list still has an accepted Scope/digest.
Registration contains site/host/scope, names and WP identity only. It survives ordinary
VCL reload in module-global state. DSO build identity participates in the cache
namespace; a new DSO cannot deliver old warmed objects before registration.
Normal origin requests advertise capability, epoch and current native policy
before PHP bootstrap, allowing existing connection/settings/capability flows to
register when needed. No new scan, cron, timer or manual step.

## Original-route entry

Preserve the actual GET route, URI, Host and raw incoming Cookie. Send:

```
X-UltraCache-Delivery-Version: 1
X-UltraCache-Delivery-Phase: public-select
X-UltraCache-Delivery-Public-Selection-Version: 1
X-UltraCache-Delivery-Request: <owned decimal request ID>
X-UltraCache-Delivery-Original-URL: <exact original URI>
X-UltraCache-Delivery-Authorization: <existing site credential>
X-UltraCache-Delivery-Policy: <current native digest>
X-UltraCache-Delivery-WordPress-Policy: <registered WP digest>
X-UltraCache-Delivery-Public-Selection-Scope: <selected exact frontend base>
X-UltraCache-Delivery-Public-Selection-Actions: <current native actions JSON>
```

There is no old source-manifest header: the first request may have no selected
object. Validate the new entry's method, exact URL, credential, versions, request
ID, mandatory exact application Scope and both policy bindings separately; do
not weaken the old validator. Scope is native-owned request metadata and must
match the application's configured frontend base before provider execution.
Client copies of owned-entry/reply Scope headers are discarded. The selected
JSON outcome is unchanged: request ID/URL/two policy identities bind its result
to that scoped original-route operation.

The new original-route operation preserves the client's Range and If-Range for
actual download/resume handling. It still captures a complete selected-public
JSON response before any client range filter; the original Range is restored
for final native publication delivery. If-None-Match, If-Modified-Since,
If-Match and If-Unmodified-Since remain withheld during this preparation. The
old prepare/recovery operation's conditional-header behavior is unchanged.

## Response

Use HTTP 200, `application/vnd.ultracache.delivery+json`, private/no-store outer
headers and `X-UltraCache-Delivery-Public-Selection-Version: 1`. Actual repeated
provider Set-Cookie headers remain in the owning-request handoff only.

The envelope has schemaVersion 1, requestId, originalUrl and exactly one outcome:

```
selectedPublic: {
  policyDigest: <native digest>,
  wordpressPolicyDigest: <WP digest>,
  cookieUpdates: [{name: <exact name>, valueBase64: <raw wire value or null>}],
  manifest: <signed target publication token>,
  occurrences: <nonnegative integer>,
  publicParent: {
    generation: <SHA-256 of target body>,
    bodyBase64: <actual target snapshot>,
    freshRemaining: <nonnegative remaining seconds>
  },
  headers: [<target public header lines>],
  renderedFragments: [<existing exact fragment objects>]
}
```

Alternatively use the existing privateDocument outcome, preserving actual
private/redirect/error behavior. A private/no-store publication never becomes
selectedPublic merely because a token exists. Zero private fragments and ESI
OFF are valid in the new public outcome. The old parser stays strict.

In the new entry only, a complete private response may carry the real legal
Content-Type, including non-HTML output. The old prepare parser remains
HTML-only. Entry eligibility follows HTML navigation Accept, with absent or
`*/*` accepted for CLI, rather than a filename blacklist. If the actual origin
returns a non-protocol response such as a directly visited static resource,
preserve its real status/type/body and owning headers as request-only delivery.
This non-protocol fallback uses ordinary private, uncached native streaming,
without capturing the complete body in a continuation or running PHP again.
It has no response byte cap or filename blacklist. Genuine raw HTML ESI uses
the ordinary existing child path, not the prepared-fragment protocol. The
explicit JSON privateDocument outcome keeps its existing bounded-by-request
lifetime capture/synthetic delivery semantics, without a product byte-size cap.
An origin that declares the selection protocol but has malformed JSON or
bindings remains a transport error; never substitute an unrelated cached page.
Browser Cache-Control no-store/no-cache/max-age=0 or Pragma does not itself
disable server lookup. The separately authenticated raw session-source operation
still reaches the real application (#975).

Public headers include exactly one HTML Content-Type, one relative
X-UltraCache-Delivery-Prepare whose once-decoded token equals manifest, and one
X-UltraCache-ESI-Private-Count equal to occurrences, including zero. Preserve
target public tags, applicable Vary and CSP. For actual ESI include its normal
Surrogate-Control/shared-parent metadata; otherwise do not claim ESI parsing.
Exclude personal cookies, authentication fields, request credentials/IDs,
hop-by-hop fields and generated Content-Length/Encoding/Date/Age. Freshness
comes from the target's remaining lifetime, never an old parent or new full TTL.

## Selection and final delivery

Cookie updates are real provider-resolved values. Null means resolved absence;
an omitted entry means unchanged. Native accepts updates only for its actual
Variant choices, then replaces/removes those names in a request-owned logical
copy and runs the normal native projection. It preserves original Cookie for
all provider execution. WordPress keys its own target through its own policy.

The selected native key adds the exact signed target manifest as public
publication identity, preserving host/URL, native cookie Variant projection and
all other existing dimensions. This replicates that particular WP publication
without requiring equal policies. Native Shared does not become native Variant
when WordPress separately selects a different public publication.

A target HIT must match its exact target manifest and fragment count. A cold
target is filled from the already captured bytes through the existing owned
snapshot director, using target public headers and remaining deadline. Do not
reuse the old parent's metadata or run PHP a second time. Remove internal raw
Cookie Vary only for this authenticated selected-publication replica; retain
downstream Vary:Cookie and all other legitimate Vary dimensions.

## Acceptance still required

- Cold/warm first US/USD and DE/EUR visits in both orders, target cold and warm.
- A/B/A visitors; existing currency invalidated by country; real Ajax switching.
- Native provider cookie creation/renewal/deletion, no duplicate invocation.
- All three independent policy actions; no extra native variant from Shared.
- ESI ON/OFF, zero fragments, mini-cart/nonces and local WordPress cache behavior.
- Forged request/header/name/value/ID/site/URL/policy/token/generation/count.
- Concurrent publication replacement, exact URL/tag purge, expiry, disappearance,
  abandoned request and reload: no old-price fallback or freshness extension.
- Separate Hestia/Webuzo acceptance with the same qualified native DSO.
- Mandatory normalized scope, root/child/sibling registrations with independent
  WP policies, longest literal boundary, bare-base redirect, exact removal,
  metadata-only empty resolver child and ordinary same-DSO reload.
- Non-protocol first bytes before origin EOF, exact streamed owner response,
  aborted streaming request and handoff cleanup; malformed claimed protocol
  remains an error and never enters raw passthrough.

No runtime parity is claimed until both sides implement and pass these cases.

## Native candidate details

The native policy identity is SHA-256 of its actual ordered action/kind/name
matcher. It includes the selected profile and effective automatic mode/CMS
rules through that matcher, without requiring equality with the independent
WordPress identity. No cookie value is included in negotiation state.

The old HIT/prepare owner phase and parser are unchanged. The new pre-hash
operation owns the original receive phase, then resumes final lookup once.
A raw non-protocol origin response retains its actual status, MIME type, bytes
and fresh owner headers on a private streaming PASS. A claimed selection response with
invalid JSON/binding remains a transport failure. The new private document
alternative accepts actual non-HTML MIME types; the old prepare alternative
retains its HTML grammar.

Explicit HTML Accept is eligible. For absent/wildcard Accept, an actual browser
script/style/image fetch destination avoids unnecessary application preparation;
a CLI request without browser metadata remains eligible. There is no filename
blacklist. Browser Cache-Control/Pragma do not trigger a native bypass; the
separate signed/shaped raw session-source operation remains uncached.

Selected public objects preserve target headers, tags and remaining freshness.
Only final client delivery is private/no-store, including zero-fragment replies
without Set-Cookie, so downstream caches cannot skip provider re-resolution.
Runtime application and proxy acceptance is tracked separately from portable
parser/build checks; mock resolver tests do not establish WCML correctness.

## Bundled WCML choices, 2026.11.20.6

The common bundle adds exactly two literal cookie choices:
`wcml_client_currency` and `wcml_client_currency_language`, both Variant in
Basic and UltraCache. No `wcml_` prefix or cookie-specific native resolver is
introduced. Basic uses incoming cookie values only; it cannot resolve a first
visitor's location. UltraCache can use the application's authenticated,
scoped public resolver through the generic protocol above. Saved central/site
choices still override each profile independently.

The standalone defaults artifact gains two rows (2278 to 2280); all existing
rows/actions are unchanged. The catalogue also aligns retired metadata with the
common WP artifact: it removes four unused WordPress consumer flags and replaces
the obsolete independent Meta delivery/transports/attributes description with
provider-owned metadata. These fields do not drive native cookie actions or
issuer generation. Every existing catalogue action and all three native
consumer flags remain unchanged. Assessment metadata advances its version only;
its 2288 source records and actions are unchanged. The editor has 2295 rows.

Normalized LF common artifacts:

- defaults.json: `8672979eae27a37ec987ba32c464026827881c355e6f05ae94e83ccebcb0518b`
- catalogue.json: `a61c8a489bf9222e1d44dd1b7992c6fda87434393f939882ee69f47b6fc335ec`

Native default tests use the shipped choices without injected prototype rules.
Their mock resolver coverage is separate from actual WP/WCML/FPM qualification.

## Bundled Aelia choices, 2026.11.20.7

The next common bundle adds four exact Variant choices in both profiles:
`aelia_cs_selected_currency`, `aelia_customer_country`, `aelia_customer_state`
and `aelia_tax_exempt`. The [vendor's dynamic caching documentation](https://aelia.freshdesk.com/support/solutions/articles/3000042591)
lists these four currency/location/tax key dimensions. All 2280 previous defaults
and 48 catalogue rows are unchanged; totals become 2284 and 52. Assessment source
records/actions are unchanged, with only the version advanced. The editor has
2299 rows. Shared/Variant/Private and each profile's reset retain normal central
and site precedence. There is no broad Aelia prefix, new native protocol,
fabricated provider cookie, geolocation logic or first-visit bypass.

Basic uses the actual incoming cookie dimensions. UltraCache's existing scoped
protocol can use values supplied by an installed application's real provider;
these native changes do not implement that provider. Without the commercial
package, source review and declared HTTP fixtures are best-effort evidence only,
not actual Aelia geolocation, pricing, tax or cookie-issuer runtime acceptance.

Normalized LF common artifacts:

- defaults.json: `a750180711d7d299a4086c56eb2986c5f0368bf20902faa27359ab921baf3b9f`
- catalogue.json: `95ec1d215fb13eb040fb7d2d1eabf7a9df35442a13d6ad135cbc464dc56f4a81`

## YITH profile defaults, 2026.11.20.8

This bundle changes only the exact and prefix `yith_wcwl_session_` choices:
UltraCache Private becomes Shared; Basic remains Private. The application must
provide its actual private embedded-table/button/nonce integration for shared
parent composition. Basic has no such application fragment contract and retains
its previous behavior. Dedicated private wishlist routes remain application
decisions. Native does not introduce a YITH-specific transport, VCL rule or
additional cookie veto. Existing central/site Shared/Variant/Private choices
remain authoritative, and resetting one column inherits that profile's default.

The native exact rule is generated from assessment record
`7bbc4d04-8776-45f3-85dc-c474d5907b24`; its UltraCache action mirrors the common
exact rule. That is the only changed assessment-record field. Other assessment
records, all other defaults, catalogue metadata, rule counts (2284/52) and editor
row count (2299) are unchanged; version metadata advances to `.8`. The common
catalogue prefix retains its previous role/consumer metadata, which cannot
override the actual profile action. Mock-origin native tests qualify actions
and inheritance only, not actual YITH REST mutations, table privacy, native
nonce ageing or ESI-off application fallback. Those require separate WP tests.

Normalized LF common artifacts:

- defaults.json: `91b91be2dc72586cd4fd928cc906aca21a4bbc2703848bc4504eb738880824d8`
- catalogue.json: `8a9eca3ea5b0523e2369ab9cfe8704bbf394e96eb956b519427653dde19b695e`

## Basic personal history boundary, 2026.11.20.9

Only the exact `woocommerce_recently_viewed` Basic action changes from Shared
to Private. UltraCache/WP remains Shared. A normal WooCommerce Recently Viewed
widget without the WP private-fragment integration can put visitor history in
the full HTML; the actual Basic counterexample reused visitor A's widget for
visitor B. Basic now sends requests carrying this cookie to the application,
and an origin response setting that Private cookie remains private. The UC
application integration continues to share its public parent and deliver the
personal widget/cookie through its existing owned path.

This is the ordinary visible profile default. It does not add a hidden cookie
veto, provider check, first-visit bypass, VCL exception or transport change.
Saved Shared/Variant/Private choices keep their usual authority, including an
explicit Basic Shared choice. Reset inherits Basic Private or UC Shared.

All other 2284-row default/catalogue metadata and every UltraCache action stay
unchanged. Assessment record `15b17bfb-d0ef-4806-b2fa-b319185bc3aa` mirrors the
single Basic action change; its other fields and every other source record are
unchanged. Version metadata advances to `.9`, with 52 catalogue policies and
2299 editor rows. Native HTTP fixtures separately test Basic owner isolation,
UC shared parent/owner-only response-cookie handoff, all three saved actions and
independent reset. Actual WooCommerce widget/issuer proof is separate app/Lab
acceptance.

Normalized LF common artifacts:

- defaults.json: `f78381d3c606867fee6a49f10509d8a5552c6fbb18e0ff7d973861607a18f85b`
- catalogue.json: `206ce788a7939b7f790e2de5e9be04a277170b3932930ea05343060d0aa65dfa`

## Basic WooCommerce cart boundary, 2026.11.20.10

Only three Basic choices change from Shared to Private: exact
`woocommerce_items_in_cart`, exact `woocommerce_cart_hash`, and prefix
`wp_woocommerce_session_`. Every UltraCache/WP action remains Shared/unchanged.
Actual WooCommerce AJAX/session issuance without UC integrations demonstrated
that a regular queryless page can include a personal mini-cart: a second cart
visitor reused the first visitor's full-page HTML under the earlier Basic
Shared defaults. Basic now sends these cookie-bearing requests to the actual
application; responses setting those Private cookies remain private too.

The UC application retains its existing public parent/private mini-cart and
owned issuer delivery. There is no new native VCL, transport, hidden cookie
veto, provider test or overlay. Saved Shared/Variant/Private choices still win;
reset restores Basic Private or UC Shared for each selector independently.

All other common rows and metadata, every UC action, 2284 defaults/52 catalogue
policies and 2299 editor rows stay unchanged. Three matching assessment records
mirror only the Basic action change (items `f1e0e5b1-d7a1-4afc-80b6-1ba4430c237f`,
hash `8a23f0ad-722d-4d91-9ef8-52528e903a4f`, session
`8f50fe5d-20dc-4811-b118-e49d52a0fc35`), plus version `.10`. Native plain-origin
tests qualify all three request defaults, each declared response cookie field,
manual actions/reset and UC owner-only MISS handoff without replay on HIT.
Actual Woo AJAX issuance and mini-cart privacy remain separately recorded
WordPress/Lab acceptance.

Normalized LF common artifacts:

- defaults.json: `c09c05d668ceb096797c77aea1239e4c74570baaa3f515dd90182cb610be4448`
- catalogue.json: `2ff0592056aaad278d6304cb48aa95d5f9babcf7b1d088173723bed0ae66ab1b`
