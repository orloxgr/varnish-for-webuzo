# Modular source, self-contained runtime

`cache-policy.vcl` is the source coordinator. It explicitly lists six modules:
core entry points, request cookies/diagnostics, downstream response privacy,
HTTP admission/privacy, representations and UltraCache ESI. Existing subroutines
keep their responsibilities and explicit call order. `profiles/control.vcl`
continues to own the native control protocol.

`vcl_source.expand()` resolves these owned files during generation, before
reviewed cookie-name substitution. Both panel adapters publish a single complete
VCL program. There are no runtime file references or visitor-time database reads.

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
