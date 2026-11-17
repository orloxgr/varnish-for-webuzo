# Cookie policy integration

## Existing execution path

| Responsibility | Webuzo execution point |
| --- | --- |
| Request privacy and cookie roles | `shared/cache-policy.vcl`, called by `src/policy.py` through `scp_recv` |
| Response admission and Set-Cookie | `scp_backend_response`, preserving origin private/no-store decisions |
| URL and representation keys | `scp_key`, called from native `vcl_hash` |
| Private fragments and nonces | UltraCache shared ESI subroutines; Basic remains independent |
| Independent Meta delivery | `shared/cookie_delivery.py` generates per-host settings; common delivery subroutines execute them |
| Reviewed recommendations | `shared/cookie-policies.json`, validated by `shared/cookie_catalogue.py` |
| Recognition metadata | `shared/cookie_recognition.py`, local persistent snapshot and bundled fallback |
| Native site ownership | `src/native.py::collect`, Webuzo users/domains inventory and Unix identity |
| Settings and rollback | `src/engine.py`, root-private settings and transaction journal |
| Deployment | `src/service.py`, complete candidate VCL, native load/use, retained active startup VCL |

Recognition categories alone do not grant a cache rule or a cookie issuer.
The spreadsheet uses shared assessed recommendations and explicit saved choices.

## Native account boundary

The administrator opens the existing Varnish panel. Hosting account users open
**Security → Cookie cache policies**. The native Webuzo session supplies actor
and administrator status; neither field is accepted from an HTTP payload.
The trusted panel-owned IPC remains the only root-worker entry point.

Account requests are restricted to cookie-policy read/save operations. The
backend checks current native site ownership for every requested site. Global
policy and service controls remain administrator operations. Account responses
contain only the account's own sites and its effective policy view, without
credentials, server paths or other accounts' settings.

## Publication model

Shared VCL source modules are composed into one complete candidate by the
Webuzo renderer. This retains the existing single-file native load/use,
startup, rollback and generation cleanup model. No runtime include path or
external metadata lookup is introduced. A source-module change is included in
the complete rendered text before native compilation.

Cookie-policy saves use the existing native transaction and compile the actual
candidate before activation. They preserve site routing/profile, browser cache,
delivery preferences and updater state. Cache invalidation is scoped to enabled
sites whose effective executable policy changes.

The sheet displays cookie name, description, Shared/Variant/Private action and
the source of that choice. Internal row identifiers stay in saved snapshots;
they are not a visible column. **Why / precedence** opens a full-width explanation
with the selected action, applied behavior, provider evidence and any overriding
login, session or cart protection. Unsaved edits are labelled until applied.
Reset removes the choice from the current scope and restores its inherited rule.
CSV exports Cookie, Description and Action columns, which can be pasted back
without exposing internal IDs. Pasting an existing literal match updates its
existing local choice rather than creating conflicting duplicate rules.

Sites with identical local cookie snapshots share one compiled rule body in the
native VCL. Their host and cache identities remain separate.

## Optional WordPress connection

Each site can explicitly connect its UltraCache cookie-policy endpoint. The
native domain inventory restricts the URL to the site's canonical hostname or
aliases and the fixed `/wp-json/ultracache/v1/cookie-policy-control` path. The
existing site purge token authenticates both request and response. Normal
inventory reads do not contact WordPress; an explicit Save also checks for
application drift when the local snapshot is unchanged.

If the native inventory removes a connection's hostname from the site, that
persisted connection is disabled without contacting its former endpoint. A new
explicit enabled connection is still validated against current site ownership.

The root-private transaction journal records request identity and digests before
remote preparation. The adapter prepares the application, compiles a complete
VCL candidate, commits the application, activates the candidate and invalidates
the affected site before saving its settings. A failed operation restores the
previous native policy and rolls back the same application transaction. A newer
application write is preserved and reported, rather than overwritten during
recovery. The private rollback record contains site IDs and digests, not tokens
or cookie values.

Disabling a connection clears its managed application snapshot before
disconnecting. Changing the endpoint first clears the old endpoint, then obtains
a fresh base digest and prepares the new one; both URLs may belong to the same
WordPress installation. If Varnish setup is disabled, the retained panel performs
the application transaction without starting Varnish or changing routing.

The shared `cache_contract` helper binds every explicitly connected policy,
including Shared-only and empty policies, to the expected application digest.
An origin `Vary: Cookie` marked as coming only
from that matching policy uses the explicit policy internally; unrelated
cookie values do not fragment it. Public responses include downstream `Vary: Cookie`
for private selectors even when the selected cookie is absent, so downstream
caches recheck the cookie before reusing public HTML. Requests with that private
cookie still pass to the application with private/no-store responses. Mixed,
unconnected or unknown origin policies retain their existing handling. A valid
different origin policy digest preserves literal Cookie Vary, so an older
Shared or tracking-ignore rule cannot merge newer application variants. These
responses remain cacheable with ordinary MISS/HIT behavior. Incoming
visitor-supplied contract headers are cleared before native scope is assigned.

## Native WordPress integration verification

The development integration was exercised through authenticated native Webuzo
admin and account-owner sessions, the plugin's registered WordPress control
endpoint, and Nginx → Varnish → Apache/PHP. The WordPress runtime advertised its
actual selected consumers; the fixture did not register a replacement endpoint
or override capabilities. Native LiteSpeed and Nginx HTML caching were not used.

- Central and site Saves produced matching native and signed application snapshots.
- EUR and USD HTML each gave MISS → HIT across different visitor and unrelated
  cookie values. Returning to EUR reused its existing object.
- A private-only selector retained public HIT and downstream `Vary: Cookie` when
  absent; its presence gave PASS with private/no-store delivery.
- The real owner CLI status/reset cleared managed application rules and invalidated
  an already warm native object. Explicit panel Save reapplied unchanged choices.
- A real filesystem permission failure during HTML retirement reported its
  authenticated error code, retained the recovery journal, and kept the previous
  runtime, settings and process. Restoring permissions and saving from a fresh
  native owner session completed the product's recovery and retired the old HTML.
- Native ZIP reinstallation while connected preserved settings, runtime, signed
  application state and the Varnish process. Disconnect cleared the application
  snapshot.

The connected functional and recovery runs passed 21 and 15 checkpoints. They
restored the original application root, settings and active/startup VCL, removed
their temporary database tables and left no pending transaction. No Varnish
restart was needed during these operations.

A further 16-checkpoint native-worker run discarded a real authenticated
WordPress commit reply and verified rollback of that same durable transaction.
It also sent SIGKILL immediately after the actual native `vcl.use` completed:
the application commit and activation intent remained journaled, the candidate
was observable through HTTP, and the previous saved settings remained intact.
A fresh account-owner panel Save recovered the previous VCL and signed
application policy without restarting Varnish. The original application and
all native state were restored afterward with no pending journal.

Tar-only development deployments must invalidate the affected PHP-FPM OPcache
entries: an overlay can change file contents while preserving an archive mtime.
The fixture invalidated its plugin and drop-in files through PHP-FPM before
testing the normal endpoint; it did not modify endpoint or capability behavior.
