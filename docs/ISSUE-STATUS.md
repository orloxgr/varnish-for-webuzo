# Historical native issue reconciliation

Reviewed on 25 November 2026 against maintained `main`, the qualified Webuzo
0.13.21 release and the coordinated acceptance of its compatible WordPress
producer. The six previously open native issues no longer describe outstanding
work in this implementation.

| Issue | Current disposition and evidence |
| --- | --- |
| [#2: retained VCL after ZIP upgrade](https://github.com/orloxgr/varnish-for-webuzo/issues/2) | Fixed by the native pass-mode loader, complete reply-frame validation, exact generation verification and root-private diagnostics. See [load qualification](VCL-LOAD-VALIDATION.md), `src/vcl_cli.py`, `src/service.py` and `tests/test_vcl_load.py`. The coordinated current release also completed normal installation/refresh acceptance. |
| [#12: retained-cookie request workspace](https://github.com/orloxgr/varnish-for-webuzo/issues/12) | The compiler/continuation now avoids repeated Cookie, URL and Variant copies and retains the original request-owned inputs. Current native header/working-normalization tests and retained-browser acceptance cover this path without increasing Varnish limits. See [request workspace](../shared/REQUEST-WORKSPACE.md) and the later large-Variant section of [header qualification](../shared/BACKEND-HEADER-BUDGET.md). |
| [#13: cached personal composition without prepare](https://github.com/orloxgr/varnish-for-webuzo/issues/13) | Delivered through the current native reusable recipe/admission and actual cached fragment objects. Qualified valid repeated compositions require no WordPress prepare; missing, expired or revoked dependencies use the real fill path. See `shared/native/delivery_reuse_runtime.c` and `tests/test_reuse_full_runtime.py`. |
| [#14: private HTTP transport and scoped invalidation](https://github.com/orloxgr/varnish-for-webuzo/issues/14) | The generated Nginx control endpoint permits authenticated `UC-PRIVATE-GET`, with native scope/provenance checks and owner/provider-tag invalidation. The original 405/403 inconsistency is fixed. See `src/connections.py`, `src/policy.py`, `shared/native/reuse_authority.c` and the current control/invalidation tests. |
| [#15: pre-header private resolution](https://github.com/orloxgr/varnish-for-webuzo/issues/15) | Current request-owned native resolution and retained object lifetimes allow valid composition before main headers. Selective real fills and generation/owner checks preserve missing-body, invalidation and failure handling. The coordinated acceptance includes actual body eviction/refill and subsequent complete native HIT. See `shared/native/delivery_continuation.c`, `shared/native/delivery_reuse_runtime.c` and `tests/test_reuse_delivery_context.py`. |
| [#16: covered cold backend header slots](https://github.com/orloxgr/varnish-for-webuzo/issues/16) | Completed internal storage carriers are removed only from the owned uncacheable prepare transport; application fields and representation inputs are preserved. Identical original headers/URL are reused rather than copied on every continuation. See [header qualification](../shared/BACKEND-HEADER-BUDGET.md), `tests/test_backend_mutation_header_budget.py` and `tests/test_cookie_working_normalization.py`. |

The original issues include historical design proposals. Their functional goals
were qualified through the current implementation; withdrawn universal
execution-hold/drain mechanisms were retired rather than presented as completed
features. Real expiry, mutation, private responses and genuine cache misses
remain normal application work, not unresolved versions of these defects.

This documentation review used existing source, maintained regressions and the
recorded coordinated release acceptance. It did not run new production browser
or WordPress experiments, and it does not claim deployment on every server.
