# Source-only public parent, first native gate

Private feature-branch protocol. This is not a released application feature or
evidence of actual WordPress/provider/SQL acceptance.

The existing authenticated public-selection declaration optionally includes
`X-UltraCache-Public-Selection-Public-Source-Version: 1`. Its accepted capability
is `X-UltraCache-VCL-Public-Selection-Public-Source-Version: 1`. There is no new
key, endpoint, service, table, queue, or manual product setting.

For an eligible cold document without configured unresolved Variant resolvers,
the existing native continuation performs a source-only `public-select` request.
It generates `X-UltraCache-Delivery-Public-Source-Version: 1` and
`X-UltraCache-Delivery-Public-Source-Role: parent-v1`. Client copies do not select
this subphase. Its actual backend URI and `Delivery-Original-URL` are the
canonical cache-significant source URI. The actual HTTP Cookie contains only
existing policy-resolved Variant inputs; an empty projection means no Cookie
header. Shared and private visitor state and Authorization are not source inputs.
The original visitor URI, cookies, conditionals and encoding remain separately
owned by that continuation. The URI/projection is applied **before** the ordinary
execution context is signed. A source execution retains the ordinary independent
execution-drain lifecycle; it never attaches a private reuse candidate.

The source responds with the existing authenticated selection envelope:

```json
{
  "schemaVersion": 1,
  "requestId": "native request identifier",
  "originalUrl": "/actual-canonical-source/",
  "selectedPublic": {
    "policyDigest": "native policy SHA256",
    "wordpressPolicyDigest": "WordPress policy SHA256",
    "publicSource": {"version": 1, "role": "parent-v1"},
    "manifest": "actual publication identity",
    "occurrences": 3,
    "publicParent": {
      "generation": "exact body SHA256",
      "bodyBase64": "actual public snapshot bytes",
      "freshRemaining": 120
    },
    "headers": ["existing validated publication headers"]
  }
}
```

Optional `cookieDelivery: true` must still match its existing publication header.
It declares a lifecycle requirement, not completion of personal delivery. There
are no `cookieUpdates`, `renderedFragments`, private recipe or cache claims in a
source outcome. Its public body retains actual ESI/head/inline/module structure;
it is not an expanded guest document. Existing identity, policy, count, body
digest, header and freshness checks remain mandatory. Source Set-Cookie fields
are discarded and never replayed to the visitor. The source does not emit or
require a final `Delivery-Outcome: verified`.

An application which declines before its business handler emits **bodyless409**,
`Content-Length: 0`, `X-UltraCache-Delivery-Public-Source-Version: 1`, and
`X-UltraCache-Delivery-Public-Source-Outcome: unavailable`. Native discards that
source, restores the real visitor and makes its ordinary personal request once.
A corrupt envelope or untyped raw source response is a protocol error; it is
never forwarded as the public or personal result. Producer-side REST/admin/action
guards must run before the actual handler, so refusal cannot repeat business work.

Only the next real personal `public-select` can complete the delivery. Its actual
publication manifest and body generation must match the captured source and its
deadline cannot exceed the source's original deadline. A typed private-document
outcome remains private. This first gate retains the original cold lookup key and
does not accept an unexplained changed Variant tuple. Ordinary warm HITs therefore
perform no public-source work. Source diagnostics are request-local, never part
of the cached parent's stored headers.

An explicit typed `resolvedPublic` resolver/reselection extension is agreed but
not implemented by this checkpoint. Required currency/locale/provider resolution
is not inferred from an empty projection. Existing configured resolver routes,
old producers and Basic keep their existing behavior. Actual Blocks and final
application-level correctness require separate composed acceptance.
