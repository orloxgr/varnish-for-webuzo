# Aggressive public HIT validation — 0.10.0

Acceptance in progress for the user-approved pure-VCL aggressive mode.

The former Joomla runtime resolver/token system is removed. Its earlier
0.9.x validation and guarantees no longer describe this implementation.
Opt-in HTML, including existing Joomla tokens, is deliberately unchanged.

Required evidence: public MISS/HIT with original URL/cookies, recognized session
and tracking key reuse, explicit Private/Variant precedence, known CMS route and
write-request PASS, unchanged original browser policy and selected TTL, owned
response cookies, retained UltraCache private ESI, helper-free upgrade cleanup,
and a warm HIT with the actual origin TCP listener closed. Current-source
Webuzo/Hestia shared parity must also pass before completion.
