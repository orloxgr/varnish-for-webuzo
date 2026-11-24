# Application storage approval and browser cache headers

Tracked by https://github.com/orloxgr/ultracache-dev/issues/1022 under #1006.

The UltraCache profile now consumes the existing origin
X-UltraCache-Cacheable: 1 and positive X-UltraCache-Surrogate-TTL as its shared
HTML storage decision. Ordinary browser Cache-Control/Pragma/Expires fields
are preserved with the existing stash/restoration owner. Aggressive is not
enabled or required, Basic is unchanged, and upstream Age is subtracted from
the application lifetime. Explicit application/surrogate refusals and the active
response-cookie choices keep their existing owners. Cookie values remain
request-owned and are not replayed from a public object.

Seven new native cases passed; the old VCL reproduced three failures. Five
shared HTTP assertions passed through both Webuzo and Hestia renderers, plus
selected existing private ESI/Ajax and explicit-policy tests. The old aggressive
test's cart-cookie assertion was inconsistent with the existing separate profile
choices; the baseline reproduced it and the corrected assertion passed.

The first Hestia parity attempt loaded an older installed native module. Its
test adapter now honors SCP_TEST_COOKIE_MODULE; the follow-up passed. Failed
first receipts are retained. No single broad all-green run or real LiteSpeed
Enterprise run is claimed.

This source increment is not a release, production deployment, or completion of
the full Warm/private-cache/browser goal. The matching WordPress change preserves
browser fields in public publications and normal generated drop-in delivery.
