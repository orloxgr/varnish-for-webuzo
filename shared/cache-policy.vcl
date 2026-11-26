# Shared source coordinator for Basic and UltraCache. GPL-3.0-or-later.
# Explicit order. Expanded before publication into a self-contained runtime VCL.
# See VCL-ARCHITECTURE.md and CONTRACT.md.

include "vcl/core.vcl";
include "vcl/cookies.vcl";
include "vcl/cookie-delivery.vcl";
include "vcl/http-cache.vcl";
include "vcl/cms-routes.vcl";
include "vcl/aggressive.vcl";
include "vcl/representations.vcl";
include "vcl/public-selection.vcl";
include "vcl/reuse-control.vcl";
include "vcl/fragment-delivery.vcl";
include "vcl/ultracache-esi.vcl";
include "vcl/ultracache-private.vcl";
