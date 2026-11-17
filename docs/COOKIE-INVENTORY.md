# Cookie policy inventory

| Concern | Webuzo execution point |
| --- | --- |
| Shared HTML lookup | Common Basic/UltraCache policy through `src/policy.py` |
| Cookie choices | Shared / Variant / Private table, with site overrides over central and bundled rules |
| Private sessions and carts | Common private-state roles and application-approved UltraCache ESI parents |
| Tracking URLs and cookies | Separate lookup dimensions; original URL and Cookie reach the origin |
| Origin Set-Cookie | Shared-only fields use the request-owned native handoff; original values and attributes never enter shared objects |
| Cookie creation and consent | Origin application/provider; no native per-cookie issuer |
| ESI delivery privacy | Common private-delivery helper prevents downstream caching of an assembled personal response |
| Ownership and persistence | Native Webuzo inventory, root-private settings and recoverable transactions |
| Diagnostics | Applied cookie names, roles, rule and scope without cookie values |

`_fbp` uses the common table. Old provider-delivery settings are not read by
inventory or VCL generation, and the former provider action is not accepted.
The application/provider owns IDs and consent behavior.

The `header` VMOD remains part of the common header transport. Repeated
`Set-Cookie` fields are not flattened: an Expires attribute can contain a comma.
Native tests cover exact field preservation, targeted header operations and
private ESI child boundaries. Fixture-only appended cookie values exercise
transport primitives rather than a native cookie issuer.

`repository.ensure_cookie_modules` checks actual APIs against the installed
engine before choosing matching modules from the authenticated OS repository.
Existing engine ownership and service lifecycle remain separate from policy
compilation.

`repository.ensure_cookie_handoff` installs headers matching the existing engine
and builds `shared/native` with `shared/native_build.py`. A build receipt covers
the source, builder and native ABI. The owned service pre-start command checks
it before startup; the cache process retains its unprivileged service identity.
