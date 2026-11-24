# Projected Variant first-lookup identity

Tracked by https://github.com/orloxgr/ultracache-dev/issues/1023 under #1006.

The grouped cookie classifier preserves wire order in X-SCP-Admin-Variant.
Projected publication already uses delivery_selection_projection(), which sorts
names and retains the first duplicate. The initial registered/projected lookup
could therefore use a different key from the publication just stored by its cold
continuation. A final HIT header did not reveal the three repeated application
calls that had preceded that final delivery.

vmod_selection_begin now applies that same existing codec before initial lookup
for a registered projected public source. It updates the request-owned
classified_variant snapshot after successful header replacement so continuation
restoration cannot reintroduce the old order. An already matching key does not
consume another header copy. The raw Cookie delivered to the application is
untouched. No alias cache, cookie-specific rule, policy choice, TTL, resource
setting or protocol was added. Basic, unregistered and nonprojected paths keep
their original lookup behavior.

Native old/new comparison in an isolated owned Lab:

- Both old modules failed three of five new cases, including repeated grouped
  values, duplicate first-value semantics and an active 6144-byte value. The
  unexpected count was six application calls instead of the original three.
- The changed Webuzo renderer/module passed 15 methods and Hestia passed 12,
  including the five new cases, existing projected/private source behavior and
  representation/nonprojected controls. No failures or skips occurred in the
  changed runs.
- Changed, absent and present-empty values remained distinct; permutations
  reused the complete matching body without additional origin calls.
- Separate builds produced the same signature
  9b2e49a54e84ffc0556d828bfe94924faebbf29e8faa17131d4e590edd04b168
  and module SHA256
  d2e7170f1c66b86e76338338564457857fc05fc35a91b719772eebbc951ccc3e.

These use an explicitly declared mock application and actual native HTTP/VCL,
not WordPress/provider/browser or LiteSpeed Enterprise execution. Private local
receipts are projected-variant-result.json and hestia-projected-variant-result.json
under the #1006 evidence directory. Normal current-package Clear/Warm/browser
acceptance, release artifacts and production proof remain separate gates.
