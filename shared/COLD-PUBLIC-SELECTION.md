# Registered cold public selection

UltraCache registrations with an empty resolver-cookie boundary or only Shared
resolver-cookie actions prepare on an actual eligible public MISS. Active
provider Variant resolvers keep their existing earlier receive-stage selection.
Basic, unregistered requests, private routes/actions and explicit Private cookie
requests do not enter this cold operation. Existing diagnostic and document
request eligibility rules remain the same.

The cold operation uses the existing original-route public-selection protocol:
request/URL/site/policy binding, signed manifest, complete public snapshot and
rendered occurrence coverage must all validate. An incomplete or contradictory
response fails; it is never accepted as a successful cached page.

A non-resolver cold publication joins the ordinary URL and explicit Variant key.
Its manifest binds the render but does not introduce a separate lookup namespace.
Native retains the original generated Variant projection and checks canonical
before/after equivalence, so an application cannot silently change a non-resolver
Variant during the cold operation. An absent Variant header remains absent after
restart. This also preserves CMP Variant A/B/A reuse independently of cookie
header order.

A plain warm HIT needs no application operation. A parent with prepared private
slots uses its existing single original-route prepare per visitor, including
grouped render contexts and request-owned provider cookies. The cold operation
does not invent issuers and does not itself execute a server-side cookie issuer
on future zero-fragment warm HITs. That requires a separately negotiated contract
for a publication which actually observed such a source cookie.

Native qualification uses a declared mock application in
`tests/test_cold_public_selection.py`; actual WordPress/provider/browser
acceptance remains separate. The stopped-origin plain-HIT fixture verifies zero
backend work, while the private-parent fixture verifies one prepare for two
contexts and three slots. Existing public-selection scope, invalidation,
continuation, owner-binding and outcome regressions also remain applicable.

## Representation metadata on selected public snapshots

The producer must rebuild its normal owned Vary contract when stored source
headers intentionally omit it. Include actual image-bucket/cacheability and
cookie-policy ownership fields with the public parent. Different representation
contexts retain different signed manifests even when HTML bytes are identical.
Missing Accept Vary can select another bucket's parent and must never be worked
around by relaxing the manifest/publication binding.

An authenticated native selected-public snapshot is actual public artifact
provenance even when freshly created. Semantic image-Accept projection accepts
that native-owned source alongside actual page-cache HIT/apache-static sources,
while retaining Cacheable:1, known bucket, public storage and no Set-Cookie checks.
The producer does not fabricate an inner HIT. Ordinary origin STORE and client
markers cannot claim this provenance. Equivalent browser Accept forms reuse the
appropriate warmed bucket with its original signed prepare pointer.
