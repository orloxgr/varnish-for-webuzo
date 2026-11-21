# Cookie and warm-up qualification

This records completed native tests and actual application runs in disposable
labs. It is not a production deployment. Publication of a compatible release
pair is gated on normal ZIP installation and runtime/source verification.

## Native checks

Common sources are identical across Hestia and Webuzo. Native tests use owned
loopback origins and disposable Varnish processes, not shared hosting services.
The module is compiled against installed Varnish 9.1 headers/toolchain; neither
source ZIP distributes a native binary.

The lab module SHA-256 is
`5a1a1126025d7fe3422ef59a3ce7771beffb5e3cfb26a42854dd3a026622d2ce`.
This identifies that lab build, not the expected checksum on another machine.
Installation verifies its own mapped DSO against its native build receipt.

| Unique methods | Hestia | Webuzo |
| --- | --- | --- |
| Cookie-only native HTTP | 5 passed | 5 passed |
| Portable real-C envelope/selection | 50 passed | 50 passed |
| Cold/selection/continuation/outcome/aggressive/CMS regression | 66 passed | 66 passed |
| Image publication/Accept projection | 3 passed | 3 passed |

No skipped method is counted as passed. The last narrow representation VCL
change leaves all native C/builder bytes unchanged. Its final source was tested
with all three image methods and 19 cold/cookie-only/outcome regression methods
per adapter. The earlier 66-method run covers the other unchanged native paths.
Mocks qualify native transport; they do not replace real application acceptance.

## Corrected causes

- CMS cookie vetoes became ordinary visible, editable Private defaults.
- Legacy Hestia cookie bypasses migrate to visible site Private choices,
  preserving tokens, profile actions, newer choices and scoped inheritance.
- Aggressive mode no longer forces PHP or opaque Joomla cookies Shared. Its
  independent HTTP-origin override remains, with one-time invalidation of old
  aggressive replicas.
- Registered non-resolver applications prepare only a real eligible cold MISS,
  then reuse the ordinary URL/Variant key. Plain warm HITs need no PHP call.
- Prepared delivery reports a request-owned verified/degraded/unverified result
  independently of Debug and the public parent's HIT status.
- A signed observed-issuer boolean supports actual owner-cookie operations on
  public HITs with zero private fragments, without generating provider values.
- Selected publications retain actual Vary/cacheability/bucket/cookie-ownership
  metadata. Authenticated fresh snapshots can reuse equivalent Accept forms
  without inventing an inner page-cache HIT or relaxing publication binding.

## Actual application checks

Coordinated WordPress/WooCommerce runs qualify healthy private delivery and real
fallback/HTTP failures separately from public-parent caching. Actual YITH React
add/remove flows use two owners, native mutations and correct wishlist contents.
Real Cookie Banner exercises accept, deny and revoke with isolated cookie jars.

A real WordPress footer issuer qualifies create, repeat without issuance, renew,
delete and recreate for two owners on the same public HIT object, preserving
original attributes and duplicate cookie names at distinct paths. Its zero-slot
fixture excludes Woo's otherwise always-present private context. The marked
full-template producer costs about 165-185 ms PHP in that lab; an unmarked plain
control has no PHP bootstrap or cookie work. These are separate cost classes.

The actual final Hestia and Webuzo VCLs both qualify normal HTML+CSS warm-up with
3/3 HIT and ten first independent visits across orig/webp/avif, Chrome/Firefox
Accept forms, encoding forms and unmatched/Shared cookies. Each bucket retains
its own object and signed prepare pointer, with verified private delivery and
correct cart counts. The cooperating producer rebuilds its normal Vary contract;
missing representation metadata is not repaired by weakening native binding.

Application tracking and final package evidence:
https://github.com/orloxgr/ultracache-dev/issues/999 and
https://github.com/orloxgr/ultracache-dev/issues/1000.

## Installation and privacy

Normal Webuzo plugin ZIP upload and activation are checked in a disposable
installation. Readback compares every installed ZIP file, actual active VCL and
mapped module/build receipt; normal capability probes and full 2305-row admin
and own-account JSON responses are checked too. Exact final artifact hashes and
installation receipts accompany the release notes.

The Hestia isolated JSON/HTML memory probe completed 2305 rows under a 128 MiB
PHP limit with a 68 MiB peak. It excludes the complete Hestia framework and does
not claim a full-panel or production memory acceptance result.

Public artifacts contain source, runtime templates and documentation; they omit
lab data, credentials, state, visitor values and native binaries. Static scanner
findings were reviewed as public signing-key fingerprints or inert test data.
No production purge, restart, load test or server tuning is part of this record.

## Upgrade

After upgrading both compatible components, use normal application capability
redetection, clear its old cache and warm the desired pages. An old unmarked
publication cannot prove a source cookie was issued and stays zero-backend until
normal republication. The optional purge-after-plugin-updates setting is not
assumed to be enabled. Local overrides and authentication tokens are preserved.
