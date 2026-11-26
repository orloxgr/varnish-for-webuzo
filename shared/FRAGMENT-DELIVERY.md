# Registered fragment delivery, protocol v1

This optional UltraCache operation delivers registered private/adaptive fragments
without a parent document. It reuses the existing continuation, provider claims,
native private objects, virtual source and mutation authority. Public fragments
continue to use their existing signed canonical GET URL. ESI/Ajax is delivery
metadata and never a new object-key dimension.

The native mock producer tests qualify transport and storage only. Actual
WordPress provider/owner, frontend initialization and standalone SQL acceptance
belong to the matching WordPress implementation. Do not infer those from a native
HIT or the presence of a capability header.

## Registration and independent storage control

Only the existing authenticated capabilities operation may register:

```http
X-UltraCache-Fragment-Delivery-Version: 1
X-UltraCache-Fragment-Delivery-Route: /shop/index.php
X-UltraCache-Fragment-Caching-Enabled: 1
```

The exact index route belongs to the already registered application scope and
immutable native site/host. The existing private authority registration remains
required. The accepted response echoes the values with `X-UltraCache-VCL-` in
place of `X-UltraCache-`. All three fields are required when declaring this new
operation. The application must exercise its probe before marking it effective.

Caching OFF bypasses retained public fragment GETs, authenticated private reads,
private object dispatch and retained private/complete-guest reuse. Prepared
bytes may still be delivered request-locally. Parent HTML caching, actual
provider lifetimes, canonical URLs and cookie policy choices remain independent.
Truly unnegotiated legacy scopes keep their previous storage behavior.

`X-UltraCache-Public-Selection-Enabled` remains the parent-delivery flag only.
An accepted metadata scope echoes it exactly as
`X-UltraCache-VCL-Public-Selection-Enabled: 0|1`. A valid complete fragment-v1
declaration explicitly keeps the same metadata/authority owner participating
even when parent delivery is 0 or fragment storage is 0. This does not send or
infer parent 1. Discovery of an unregistered scope emits no accepted parent flag.

Parent 0 bypasses retained HTML/XHTML parents, normal public selection, complete
guest selection and parent fast reuse. Individual registered fragments remain
independent. Non-HTML objects keep their existing origin/cache policy. An ordinary
request Accept cannot expose a hot HTML parent while delivery is 0. Toggling only
the parent or fragment storage flag does not rotate private authority or restart
individual object lifetimes; actual policy/connection changes still revoke it.

For **full teardown/connection retirement**, WordPress sends parent 0 and omits
ALL fragment declaration fields (version, route and storage flag). This retains
the old metadata removal, private authority disable/key wipe/revision advance.
No accepted parent/fragment tuple remains. Retaining fragment-v1 fields would
explicitly retain participation, so changing only the parent flag is not teardown.
Legacy parent 0 requests without fragment-v1 retain their previous behavior.

Applications must require the accepted parent echo together with the accepted
fragment tuple before claiming independent operation. Older proxies that reject
parent 0 plus fragment participation must not be worked around by silently sending
parent 1. Use an explicit supported fallback. No new UI control, registry, batch
schema or object namespace is introduced by this lifecycle separation.

## Public request

```http
GET /shop/index.php?ultracache_fragment_delivery=<payload>.<mac>
```

Exactly one query value is accepted, raw-URL-decoded once. Token framing is the
existing unpadded base64url JSON plus lowercase HMAC64 format. WordPress signs
with purpose `fragment-delivery-v1`. Native parsing alone never authenticates
this public token or an owner. WordPress independently verifies every inner
registered descriptor and the current visitor's actual session/provider state.

The payload has exactly `schemaVersion:1`, relative `sourceUrl`, existing public
`context`, and a nonempty `fragments` array of `{url,occurrences}` records. URLs
are the exact existing `ultracache_get_varnish_esi_fragment_url()` outputs,
including their home URL path. Only the batch route uses `site_url('/index.php')`.
Rows are unique by exact URI; occurrences are positive, overflow-checked integers.
WordPress emits sorted rows. Native compares the exact requested URI/count set,
not just the total. No second URL decoding or URI rewriting is performed.

The existing context fields are strings: `policy`, `bucket`, `cookies`, `locale`,
`language`. `cookies` is the existing public-cookie variant SHA256, not an object
or private cookie values. No owner, partition, private key or control credential
is part of public request metadata. Source URL is render context, not a fetch
instruction, and a parent body/snapshot is not required.

`requestDigest` is lowercase SHA256 of these exact bytes:

```text
ultracache-fragment-delivery-v1\n<decoded-once ASCII token>
```

The browser sends actual same-origin credentials for private batches. Public
fragment GETs use cookie-free bootstrap, including browser `credentials: omit`.
The loader owns occurrence-to-DOM mapping and deduplicates requests/rendering.

## Authenticated producer operation

Native captures the original request and adds backend-only existing delivery
version/request/original-URL/manifest/authorization fields, using the explicit
new `fragment-prepare` phase. It adds:

```http
X-UltraCache-Fragment-Delivery-Version: 1
X-UltraCache-Fragment-Delivery-Request-Digest: <requestDigest>
X-UltraCache-Fragment-Caching-Enabled: 1
X-UltraCache-Delivery-Private-Cache-Version: 1
```

WordPress must use its dedicated batch entry validator, not the old parent
snapshot validator or a forged ESI request level. Actual provider context,
identity and generation authorize lookup-before-render through existing
`UC-PRIVATE-GET`. This method remains authenticated, lookup-only, and MISS404
never fetches an origin. A private batch still requires one application authority
operation; a body HIT does not mean zero PHP. No full-page issuer render is
implicitly enabled by this operation.

## Strict producer schema 2

The response MIME is
`application/vnd.ultracache.fragment-delivery+json; version=1`, with the fragment
version response header, private/no-store, and the following exact members:

- `schemaVersion`: integer 2.
- `requestId`, `originalUrl`, `requestDigest`: match the owning native task.
- `renderedFragments`: existing `{url,html,occurrences,cache?}` records.
- `failedFragments`: `{url,occurrences,status,code}` records.
- Optional `authority`: required exactly when positive-TTL successes exist.

Success and failure arrays form the exact disjoint requested set, with exact
occurrences. Empty requested batches, unknown/duplicate members, extra/missing
URIs and numerical overflow reject the operation. The old schema1 parser is
unchanged. No fabricated cookie-delivery flag or parent snapshot enters this
mode. Personal cache claims remain exactly `{key,ttl,tags}`. An explicitly
stateless anonymous claim uses `{key,ttl,tags:"",identityState:"anonymous"}`
in this fragment schema2 only. TTL0 omits the cache member; a native HIT carries
only its original remaining lifetime.

Authority has exactly:

```json
{
  "scope": "/shop/",
  "epoch": "<hex64>",
  "incarnation": "<hex64>",
  "scopeRevision": "<hex64>",
  "nativePolicy": "<hex64>",
  "wordpressPolicy": "<hex64>",
  "reusePolicy": "<hex64>",
  "fragments": [
    {"url":"<canonical fragment URI>","authority":[
      {"tag":"<hex64>","revision":"<hex64>","generation":"<hex64>"}
    ]}
  ]
}
```

Every personal positive claim has exactly one nonempty, duplicate-free dependency
closure from the same provider claim, including its owner/session and mutable state.
Only an explicit `cache.identityState:"anonymous"` with empty cache tags uses
`authority:[]` for that exact URL. This is a trusted producer declaration of
stateless output, never inferred from missing owner, tags or dependencies. The
producer must use its existing trusted-anonymous dependency read and verified
scope-authority publication. Anonymous claims still require the complete current
scope/epoch/incarnation/scopeRevision/policy tuple above; empty per-URL authority
does not mean absent authority. An anonymous claim with actual dependencies, an
unmarked claim with empty dependencies, or any other identity state is rejected.
No TTL0/error claim may have an authority entry. The producer emits the existing
stable content revision in `revision`; native also preserves the old revision
compatibility semantics. No new parent publication, recipe or identity-binding
fields are invented for this per-request authenticated mode.

The common scope/tag validator runs under the existing writer lock before fill
and at final release: actual site/host/scope and compiled native policy, current
epoch/incarnation/policies/scope revision, clean bound tags, no active writer,
current revision and generation. The producer still uses the existing native
observe → actual durable state read → generation-publish CAS lifecycle. Neither
an opaque key nor a list of tags creates clean authority. Explicit stateless
claims run the same scope namespace checks under that lock before native fill
and final release; scope or connection revocation also retires hot anonymous
claims. They use the same individual native object key/store and lifetimes,
without an invented owner/tag or another cache. Parent schema1 does not accept
the new identity-state member.

## Storage and browser projection

Each admitted object uses `ultracache-private-v1` + native site + canonical host
+ exact existing fragment URI + existing application key. A finite native-owned
cursor dispatches normal hash/fetch/storage to the existing prepared virtual
source. Only its exact additional transitions are reserved with checked
arithmetic. No global restart setting, arbitrary batch cap, fake ESI level,
experimental HSH-as-fill or second body store is involved. Ordinary document
MISS cookie-handoff initialization must not replace this source owner.

A writer retiring a staged item makes that item unavailable; its body never
enters final output. Final JSON uses tracked HTML byte lengths, including NUL
and Unicode, and contains only:

```json
{"schemaVersion":1,"results":[
  {"url":"<canonical URI>","status":200,"html":"actual output"},
  {"url":"<another URI>","status":409,"error":{"code":"state-conflict"}}
]}
```

It is JSON/private/no-store/nosniff, never a cached batch object. Only authentic
Set-Cookie from the current operation may be appended, after final validation.
No saved cookie, private claim, tag, infrastructure token or internal envelope
is projected. A whole transport/protocol failure is503; signed input failures
are400/404 and policy/context conflicts409. Valid batch responses use HTTP200
with explicit per-item error statuses. The loader must preserve these failures.

V1 successes are HTTP200, including genuinely empty output. There is no implicit
204 or redirect success. Error statuses are400–599; fixed codes are
`fragment-disabled`, `context-unavailable`, `renderer-unavailable`,
`renderer-failed`, `fragment-redirect`, `state-conflict`. Redirects are not followed
or stored as successful fragment HTML.

Standalone uses the same WP route, renderer, claims and response with its existing
SQL owner. It must not silently create a SQL-only Ajax cache beside native-only
ESI for the same descriptor. Missing native support requires an explicit common
backend/delivery fallback. The independent cookie-delivery control is unrelated
to this transport's registration or storage policy.
