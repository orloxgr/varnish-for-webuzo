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
X-UltraCache-Public-Selection-WordPress-Policy: <WP effective digest>
X-UltraCache-Public-Selection-Cookies: <comma-separated exact resolver names>
```

These names declare actual installed resolver metadata, never cookie values.
Enabled 0 unregisters. An ordinary capabilities request with no declaration
does not modify registration. No panel cookie-integration flag is required.

The authenticated capabilities response advertises:

```
X-UltraCache-VCL-Public-Selection-Version: 1
X-UltraCache-VCL-Public-Selection-Epoch: <native DSO build identity>
X-UltraCache-VCL-Public-Selection-Native-Policy: <active native digest>
X-UltraCache-VCL-Public-Selection-WordPress-Policy: <accepted WP digest>
X-UltraCache-VCL-Public-Selection-Actions: <JSON exact name to effective action>
```

Actions use the existing generated matcher, including the current Shared
behavior for names with no matching rule. Omitting an unmatched name cannot
create a new unresolved-state veto. Activate when a declared name has actual
native Variant behavior. Recompute native actions after policy changes.

Registration contains site/host, names and WP identity only. It survives ordinary
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
X-UltraCache-Delivery-Public-Selection-Actions: <current native actions JSON>
```

There is no old source-manifest header: the first request may have no selected
object. Validate the new entry's method, exact URL, credential, versions, request
ID and both policy bindings separately; do not weaken the old validator.

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

No runtime parity is claimed until both sides implement and pass these cases.

## Native candidate details

The native policy identity is SHA-256 of its actual ordered action/kind/name
matcher. It includes the selected profile and effective automatic mode/CMS
rules through that matcher, without requiring equality with the independent
WordPress identity. No cookie value is included in negotiation state.

The old HIT/prepare owner phase and parser are unchanged. The new pre-hash
operation owns the original receive phase, then resumes final lookup once.
A raw non-protocol origin response retains its actual status, MIME type, bytes
and fresh owner headers as a private document. A claimed selection response with
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
