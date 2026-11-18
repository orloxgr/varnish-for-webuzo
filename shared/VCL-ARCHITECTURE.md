# Modular source, self-contained runtime

`cache-policy.vcl` is the source coordinator. Its modules cover:
core entry points, request cookies/diagnostics, downstream response privacy,
HTTP admission/privacy, representations, UltraCache ESI, aggressive HTML and
CMS route policy. Existing subroutines
keep their responsibilities and explicit call order. `profiles/control.vcl`
continues to own the native control protocol.

`vcl_source.expand()` resolves these owned files during generation, before
reviewed cookie-name substitution. Both panel adapters publish a single complete
VCL program. There are no runtime VCL file references. Aggressive admission,
cookie keys and CMS route matching run inside Varnish. Its public HIT has no
CMS service, session SQL, token provider, body filter or additional HTTP calls.
Static cookie/CMS discovery is performed by the panel adapter during refresh.

This choice preserves the existing transactional deployment: the content digest
covers all expanded module bytes, `vcl.load` compiles the whole program before
`vcl.use`, and the durable active file and retained generations contain all code
needed for startup, restore and rollback. Module-only edits change the digest.
An old generation does not depend on a newer code directory or mutable include.
Cleanup therefore continues to track native VCL generations rather than a second
graph of runtime include files. It also avoids exposing other sites' purge tokens
through a new readable source bundle. Normal changes require no service restart.

Native includes remain a Varnish capability. They would add bundle publication,
path rewriting, manifest/restore and reference-aware cleanup here without making
the current renderers simpler: both already generate host/token/backend/site-rule
code dynamically. Source modules provide the maintainability benefit while the
existing single-program publication provides the complete immutable artifact.

The module split itself changes no policy. Cookie administrator rules are a
separate change and must be verified by real request/response behavior.

The cookie delivery source module also uses the common request-owned
`cookie_handoff` VMOD. Its small native source is built for the installed engine
ABI; it is a runtime dependency like the official header module, not a VCL
include or a cookie-value store. The per-client handoff is finalized with the
request. A native pre-start build refreshes it after engine package upgrades.
