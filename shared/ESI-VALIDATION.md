# Qualified UltraCache delivery contract

Release pair: **Varnish for Hestia 0.22.0 / Varnish for Webuzo 0.11.0**.
Validation completed on 2026-11-20. Release commits add metadata/documentation
to the following qualified sources; their runtime policy/module sources remain
identical.

| Component | Exact qualified source |
| --- | --- |
| Hestia native adapter | `d46684c5b1974e7f27a46a26787cf4e88b4c3d94` |
| Webuzo native adapter | `993b69cc338c94b51b1d8642bb9fd58d2c0a98f4` |
| UltraCache production | `db493cf1` / `3.13.13-dev.1309` |
| Actual engine | Varnish 9.1.0, `ffd36e9db9a1ec2bf6637deda180a87d40a13d0f`, VRT 22.2 |
| UltraCache ZIP SHA256 | `e9d7f9efac3667cd36f051a3a048181f468f2b73ce7c2768a5249e1d1690fafe` |
| Qualified native library SHA256 | `40056c566d98d6355b427661aa7b5adb3cfaf78ba3be4182114050f18e022bcb` |

The library digest identifies the qualified build, not a binary shipped to
other servers. The installer builds from source against the installed engine's
matching headers, strict VRT ABI and internal http_conn layout. An unchanged
receipt may reuse that same build; changed engine/header/source inputs require
a matching rebuild. Other engine ABIs are not covered by this runtime receipt.

## Compatibility and behavior

- **Basic remains best effort without ESI.** It does not use UltraCache's
  continuation, private-document or certified fragment rules.
- Cookie Database remains the single Shared/Variant/Private classification
  authority. No new cookie veto, provider-specific issuer or consent override
  is introduced. Original application/provider/session ownership remains intact.
- The existing signed private probe and backend-owned original-route prepare
  carry negotiated delivery, request-snapshot, private-cache and private-document
  capabilities. No new UI/control or general authentication channel is added.
- Existing schemaVersion1 renderedFragments and optional publicParent are
  supported. The mutually exclusive privateDocument carries status, contentType
  and exact bodyBase64. It is accepted only within the bound native request;
  fresh application headers accompany its private/no-store body. Top-level
  redirects/errors and bodyless204/304 retain their correct HTTP semantics.
- Prepared private fragments run once per distinct context. Authentic repeated
  Set-Cookie fields are delivered once before parent headers, without being
  stored in a shared object. Public parent recovery uses its bound publication
  or request-owned snapshot without rerunning providers or refreshing public TTL.
- Application-authorized private-fragment TTL uses scoped native objects with
  no stale grace/keep; TTL0 stays request-local. Actual application state and
  approved claims own identity/invalidation, rather than cookie presence alone.
- Certified public fragments retain their parsed HTTP freshness, including
  Age/Date deductions, with zero grace/keep. Aggressive mode cannot replace
  their declared TTL, TTL0 or contained-error no-store.
- Non200/non204 responses from signed UltraCache ESI child endpoints are empty,
  noncacheable child deliveries. Native backend status remains in VSL; no raw
  error body/cookies enter the public parent. Siblings/tail and subsequent
  recovery remain available. Application fallback200 is separate and preserved.
  Direct endpoint status/body and complete private documents are not converted
  to empty success responses. Generic ESI retains its prior behavior; global
  onerror flags are unchanged.
- Older application capabilities and incomplete fragment metadata retain their
  previous paths. New app behavior requires its effective stored probe and live
  negotiated native capability; these releases do not claim new functionality
  from an older native module. UltraCache standalone operation remains supported.

## Execution evidence

These are distinct checks, not results inferred from generated source alone.

| Layer | Result |
| --- | --- |
| Native Hestia HTTP/VCL suite | 37/37 methods, zero skips, 240.946 seconds |
| Native Webuzo HTTP/VCL suite | 39/39 methods, zero skips, 262.930 seconds; includes gateway restart isolation |
| Actual WordPress HTTP503 actor from the final UltraCache ZIP | Five no-JavaScript visits; exactly two actual origin503 responses and two native containment events |
| Final combined WordPress/WooCommerce browser regression | 100 no-JavaScript visits with independent provider/template observations, request-owned recovery wire checks and source/storage isolation audit |
| Final ZIP application checks | All 459 production files match the installed ZIP; four native application component suites; 47 full WordPress unused-session cases; 372 PHP syntax checks |

Earlier focused execution also covered native notice consumption/fresh template
CSP, private/public fragment expiry and context invalidation, cold cookie
issuance/renewal/deletion, multiple visitors, actual Woo mutations, nonce aging
with real accepted/rejected actions, session serialization, Store Notice cookie
choices, and standalone/Ajax mini-cart fallback. Those focused results retain
their own application checkpoints in the central issue evidence; they are not
silently counted as new methods of the final native suites above.

Native wire fixtures use both adapters' actual generated policy, not hosting
panel deployment. The combined WordPress browser acceptance used the Hestia
adapter. This does not claim that Webuzo panel/CLI installation or another
engine version was deployed and exercised in that same browser run.

Source comparison with LiteSpeed Cache WordPress 7.9.2 informed the design.
No execution equivalence with a licensed LiteSpeed Enterprise server is claimed.
The central [UltraCache acceptance issue](https://github.com/orloxgr/ultracache-dev/issues/953)
and related issues955–959 retain implementation, failed receipts, corrected
qualification and application boundaries. The [delivery design history](ESI-DELIVERY-DRAFT.md)
and [private TTL history](PRIVATE-TTL-DRAFT.md) retain intermediate checkpoints;
their historical pending notices are superseded by this exact final receipt.

Publication does not apply configuration to a live server. Update the panel
addon through its normal installer/uploader and use the matching UltraCache
release when enabling these negotiated features.
