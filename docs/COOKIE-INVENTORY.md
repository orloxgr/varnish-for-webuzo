# Cookie policy inventory

This records the existing mechanisms before adding independent cookie delivery.
It is an implementation inventory, not a declaration of provider support.

| Concern | Existing Webuzo mechanism | Extension point |
| --- | --- | --- |
| Shared HTML lookup | `shared/cache-policy.vcl`, called by `src/policy.py` for Basic and UltraCache | Keep one shared policy and panel-specific host/backend/token adapters |
| Private request cookies | `scp_private_cookie_recv` excludes login, PHP sessions and personalized extensions | Generate recognition from the agreed versioned catalogue; retain current behavior for unknown cookies |
| Cart/session requests | `scp_cart_cookie_recv` permits an UltraCache opt-in ESI candidate, otherwise passes | Keep existing cart isolation and application-approved shared parents |
| Tracking cookies | `scp_cookie_variation` omits named analytics IDs only from the internal `Vary: Cookie` key | Replace duplicated recognition with catalogue-generated rules; preserve raw origin cookies |
| URL tracking | `scp_key` normalizes a copy for hashing and invalidation | Preserve the original URL for the origin and browser |
| Response cookies | `scp_response_privacy` marks responses containing any `Set-Cookie` uncacheable | Introduce independent supported-provider delivery before admitting public HTML; never store a visitor's cookie in the shared object |
| Multiple response cookies | Native HTTP forwarding preserves individual fields, attributes and deletions | Never comma-collect `Set-Cookie` or replace the whole field set to add one cookie |
| ESI | Existing UltraCache public parents and private child requests, with an allowlisted session carrier | Extend the existing transport; keep child cookies out of shared parent delivery |
| Nonces | Native ESI processing, including script, JSON and attribute contexts | Keep application session binding and existing ESI support |
| Origin representation | Existing normalized Accept/language keys and functional-cookie variation | Preserve actual language/currency/consent differences; no complete cookie header or tracking ID in the public key |
| Trust | `scp_init` clears scratch/ESI approvals; adapter selects site/profile and authenticates gateway/control requests | New browser-supplied policy/delivery headers must be discarded too |
| Administration | `engine.inventory`, `engine.status`, `configure`, and site details in `panel/app.js` | Per-site provider/consent settings and value-free diagnostics, using existing transaction validation |
| Diagnostics | `X-Webuzo-Varnish`, profile and reason headers | Add cookie names/policy/delivery decisions without cookie values or identifiers |

`src/cookie_policy.py` previously also contained private/cart/session name lists.
Those duplicates are now removed. `shared/cookie-policies.json` provides the
reviewed roles, and the shared `cookie_catalogue.py` compiler expands the VCL
patterns when generating a configuration. The panel displays this generated VCL.
The separate recognition snapshot supplies descriptions only; its categories do
not grant caching or issuance permission.

The baseline had no CMP integration or independent provider-cookie issuer. The
new per-site editor uses the shared Meta delivery configuration, with an exact
consent-cookie predicate checked on each request. Application-owned CMP APIs
retain service/revision-based decisions through the provider endpoint contract.
The clean-refill/handoff, Apache Static, drop-in and browser fallback mechanisms
belong to the UltraCache application inventory. A static HIT can skip PHP;
application cooperation cannot assume that PHP runs for every page delivery.

The native `cookie` VMOD parses request cookies. It does not provide independent
manipulation of repeated response fields. The bundled `std.collect` must not be
used to flatten `Set-Cookie`: an Expires attribute itself contains a comma.
See the official [std module reference](https://www.varnish.org/docs/reference/vmod_std/)
and [cookie module reference](https://www.varnish.org/docs/reference/vmod_cookie.html).

`tests/test_cookie_delivery.py` checks real native HTTP fields, including
multiple cookies, exact attributes, renewal, deletion and the ESI child boundary.
These baseline tests establish preservation; they do not establish independent
provider delivery, consent support or cacheability of an unknown provider.

## Native response-field transport

The official `varnish-modules` package supplies the `header` VMOD. Its
`header.append` and `header.remove` APIs can add a delivery field and remove
only a specifically selected cookie while retaining other fields byte-for-byte.
The native primitive tests exercise this with an Expires comma, deletion,
HttpOnly, Secure, different paths and independent values across MISS/HIT/HIT.
The test identifiers are fixtures; these tests do not claim Meta integration.

`repository.ensure_cookie_modules` compiles the actual APIs before asking APT
for anything. If needed, it selects the official package for the current suite
and architecture using the existing authenticated repository workflow. The
installed engine version is kept explicit in the module-only APT transaction;
that path does not restart a service or replace the engine. Fresh setup installs
the engine and modules together. Native plugin activation prepares the module
only for an already configured Varnish setup; an explicit site refresh checks
it again before applying generated policy. This prevents a missing module from
being misreported as an incompatible running cache engine.

The dedicated lab installed the native module package with the existing service
PIDs unchanged. Both native HTTP field tests and lifecycle/repository/ESI
regressions passed. Provider/CMP delivery remains work to verify before publication. The shared
catalogue compiler is integrated, and its native parity is checked separately
from the independent cookie-delivery primitive.
