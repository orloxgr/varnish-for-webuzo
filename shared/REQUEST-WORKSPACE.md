# Cookie policy request workspace

Cookie classification previously maintained two identical accumulated Variant
lists, repeatedly normalized already canonical strings and classified the same
Cookie again after an owned UltraCache continuation restart. Unsetting the old
headers does not reclaim the Varnish request workspace occupied by their bytes.
These allocations could therefore exhaust the request workspace before a
previously cached response was delivered, independently of HTTP header slots.

The compiler now maintains the ordered Variant accumulator once, avoids empty
separator concatenation and normalizes only strings which need normalization.
The resolved remainder is already canonical before it becomes a Vary input.
The scope, exact/prefix precedence, raw Cookie and Shared/Variant/Private
decisions remain the same.

For an UltraCache continuation, reuse additionally requires the existing native
phase/restart/site/host/URL ownership proof and exact equality with the classified
raw Cookie. Initial client headers, ordinary restarts, changed cookies and ESI
children cannot supply that proof. Selection may replace the public Variant key;
the original classification is restored before the next current selection.
Completed classification scratch releases its header slots before continuation
ingress. The temporary reuse fields never reach the origin. Basic does not
allocate a continuation snapshot.

No native module, registry policy, cache namespace, Varnish parameter or lifetime
changes. Existing requests stay with their original VCL; overlapping activation
uses the same native module and does not require a service restart or purge.

## Qualification scope

`tests/test_request_workspace.py` uses an isolated native Varnish daemon, the
normal request workspace and the 64-entry HTTP header limit. It uses public
cookie provider names with invented values, not customer credentials or cookies.
It covers 600, 1200, 1800 and 2400-byte retained-cookie contexts, cold selection
and the subsequent parent HIT, independently rendered visitor fragments, exact
origin Cookie forwarding, attempted client forgery and a changed Cookie on an
owned restart. There must be no LostHeader, workspace or VCL error records.

This is bounded native regression evidence, not a claim that arbitrary cookie
sizes or arbitrarily many explicit Variant rules fit a finite engine workspace.
Larger synthetic Variant-heavy payloads can still exhaust the engine workspace;
the addon does not introduce a new cookie limit or change the engine's limits.
