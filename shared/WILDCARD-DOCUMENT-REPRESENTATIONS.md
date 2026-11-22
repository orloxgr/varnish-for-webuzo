# Original HTML for unrestricted document Accept

UltraCache issue #1004 exposed two independent boundaries. The application lost
actual footer-cookie work when its collector filtered personal response fields.
Separately, a normal warm populated the original-image HTML representation under
canonical HTML Accept, while an ordinary `Accept: */*` document used another Vary
key. Correct cookie issuance alone did not restore that visitor's first HIT.

The shared representation receiver now recognizes absent Accept or a sole,
unrestricted, full-quality wildcard on a document request as accepting original
HTML. It does not rewrite the origin's Accept header. Response normalization
still requires the existing approved public HTML publication, correct image
variant and privacy guards. Other preferences, codec refusals, unusual parameters
and non-document destinations retain existing handling. Both native products
carry identical shared VCL; the C module and wire protocol do not change.

Qualification on Varnish 9.1.0: the new warmed-original wildcard test reproduced
HTTP 200/MISS on published code before the correction. Native representation,
cookie-only and 64-header-budget tests pass (13 per adapter). Hestia's independent
application compatibility passes 7 tests; Webuzo's profile/preset suite passes
59 tests. Test renderers accept the existing `SCP_TEST_COOKIE_MODULE` override
for varnishtest as well as the HTTP harness, selecting the exact qualified module.

The combined real WordPress 7.1.5 / PHP-FPM 8.3.37 / Webuzo 0.12.5 source Lab
passed normal warm plus first ordinary HIT on wildcard and ORIG/WebP/AVIF,
independent visitors, cookie renewal/deletion/recreation and a plain issuer-free
HIT with zero backend work. This used a separate owned native daemon and the
WordPress collector correction, not an installation or shared-service reload.

Release pairing: Webuzo **0.12.6**, Hestia **0.23.5**, and UltraCache
**3.13.13-dev.1322 or newer** for the separate footer-cookie application fix.
Older WordPress publications need normal cache clear and warm-up after both
components are upgraded. The native correction does not rebuild an old
application publication or reconstruct cookie values from a shared object.

Qualification evidence is retained in the private Lab record for UltraCache
issue #1004. These focused results do not claim completion of the broader
WordPress audit. No production or shared service configuration was changed.
