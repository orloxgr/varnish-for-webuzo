# Aggressive HTTP caching and cookie choices

Aggressive mode changes its existing anonymous HTML HTTP-origin policy only.
It does not rewrite cookie decisions or introduce another set of cookie defaults.
Bundled and saved Basic/UltraCache Shared, Public variant and Private actions use
the same resolver in native requests, response handoff, the editor and connected
application snapshots.

The removed mode-specific decisions were:

- `PHPSESSID` and `__Secure-PHPSESSID`: mode-forced Shared now uses the existing
  bundled Private default in both profiles. Explicit Shared/Variant/Private
  choices remain authoritative.
- Each statically discovered, supported Joomla 32-hex cookie name formerly passed
  as `automatic_shared`: no automatic Shared rule remains. A selected action is
  honored; otherwise ordinary functional Vary and response-cookie rules apply.
  No blanket rule for all 32-hex cookie names is added.

Normal upgrade records a cookie-rule revision on native site state. Previously
aggressive sites invalidate their old replicas once; unrelated non-aggressive
sites do not gain an extra invalidation. Repeated apply is idempotent. This is
upgrade bookkeeping, not a control, visitor classifier or additional scope.

Existing aggressive HTTP-origin behavior, private routes/actions, Basic without
ESI and original cookie forwarding remain separate. A zero-backend public-HIT
fixture must choose Shared cookies explicitly when its provider uses cookies
whose ordinary defaults are Private.
