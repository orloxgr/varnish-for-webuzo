# Shared core policy. GPL-3.0-or-later.

sub scp_init {
    cookie_handoff.reset();
    unset req.http.X-SCP-Cookie-Handoff;
    unset req.http.X-UltraCache-Delivery-Parent-Source;
    unset req.http.X-SCP-Delivery-Public-Snapshot;
    unset req.http.X-SCP-Personal-Delivery;
    unset req.http.X-SCP-Private-Key;
    unset req.http.X-SCP-Private-Lookup;
    unset req.http.X-SCP-Site;
    unset req.http.X-UltraCache-Delivery-Authorization;
    unset req.http.X-UltraCache-Delivery-Manifest;
    unset req.http.X-UltraCache-Delivery-Recovery-Version;
    unset req.http.X-UltraCache-Delivery-Request-Snapshot-Version;
    unset req.http.X-UltraCache-Delivery-Private-Cache-Version;
    unset req.http.X-UltraCache-Delivery-Recovery;
    unset req.http.X-SCP-Cookie-Contract;
    unset req.http.X-UltraCache-Cookie-Settings;
    unset req.http.X-UltraCache-Cookie-Vary;
    unset req.http.X-SCP-Admin-Remaining;
    unset req.http.X-SCP-Admin-Applied;
    unset req.http.X-SCP-Admin-Keep;
    unset req.http.X-SCP-Admin-Matched;
    unset req.http.X-SCP-Admin-Filtered;
    unset req.http.X-SCP-Admin-Variant;
    unset req.http.X-SCP-Admin-Has-Variant;
    unset req.http.X-SCP-Admin-Rule;
    unset req.http.X-SCP-Admin-Scope;
    unset req.http.X-SCP-Admin-Action;
    unset req.http.X-SCP-Profile;
    unset req.http.X-SCP-CMS;
    unset req.http.X-SCP-CMS-Path;
    unset req.http.X-SCP-CMS-Query;
    unset req.http.X-SCP-Aggressive;
    unset req.http.X-SCP-Aggressive-TTL;
    unset req.http.X-SCP-Private-Check;
    unset req.http.X-SCP-Reason;
    unset req.http.X-SCP-Pass;
    unset req.http.X-SCP-Key-URL;
    unset req.http.X-SCP-Query;
    unset req.http.X-SCP-Key-Path;
    unset req.http.X-SCP-Key-Query;
    unset req.http.X-SCP-Vary-Cookie;
    unset req.http.X-SCP-Vary-ESI-Cookie;
    unset req.http.X-SCP-Vary-Accept;
    unset req.http.X-SCP-Vary-Accept-Language;
    unset req.http.X-SCP-Normalize-Value;
    unset req.http.X-SCP-HTML-Accept;
    unset req.http.X-SCP-Fbp-Enabled;
    unset req.http.X-SCP-Fbp-Consent;
    unset req.http.X-SCP-Fbp-Domain;
    unset req.http.X-SCP-Fbp-Index;
    unset req.http.X-SCP-Fbp-New;
    unset req.http.X-SCP-Cookie-Name;
    unset req.http.X-SCP-Cookie-Role;
    unset req.http.X-UltraCache-Cookie-Policy;
    unset req.http.X-UltraCache-Cookie-Delivery;
    unset req.http.X-SCP-Accept-Check;
    unset req.http.X-ESI-Private-Request;
    unset req.http.X-ESI-Request-Level;
    unset req.http.X-ESI-Original-Cookie;
    unset req.http.X-UltraCache-ESI-Transport-Version;
    unset req.http.X-UltraCache-ESI-Adaptive-Nonce-Version;
    unset req.http.X-SCP-Adaptive-Nonce;
    unset req.http.X-UltraCache-ESI-Candidate;
    unset req.http.X-UltraCache-ESI-Cookie-Check;
    unset req.http.X-UltraCache-ESI-Opt-In;
    unset req.http.X-UltraCache-ESI-Shared-Parent;
}

# Normalize a COPY for hashing/invalidation. Never change req.url.
sub scp_recv {
    std.collect(req.http.Cookie, "; ");
    # This shape routes a private collector request, never authenticates it.
    # The origin owns MAC/one-use validation. Preserve all original cookies,
    # including ESI markers, by passing before profile-specific transport.
    if (req.http.X-UltraCache-Session-Source && req.method == "GET" &&
        req.http.X-UltraCache-Warm-Source == "raw-v1" &&
        req.http.X-UltraCache-Internal-Request == "1" && req.http.X-UltraCache-Warm == "1" &&
        req.http.X-UltraCache-Session-Source-Kind ~ "^(native|observed)$" &&
        req.http.X-UltraCache-Session-Source ~ "^v1:[0-9a-f]{64}:[0-9a-f]{64}:[0-9a-f]{64}:[0-9a-f]{64}$") {
        set req.http.X-SCP-Reason = "ultracache-private-session-source";
        return (pass);
    }
    if (req.url ~ "[?]") { set req.http.X-SCP-Query = regsub(req.url, "^[^?]*[?]", ""); }
    if (req.http.X-SCP-Profile == "ultracache") { call scp_ultracache_recv; }
    call scp_common_recv;
}
sub scp_pass {
    if (req.esi_level == 0 && req.http.X-SCP-Profile == "ultracache" && cookie_handoff.delivery_guard()) {
        return (synth(503, "Prepared parent unavailable"));
    }
    set req.http.X-SCP-Pass = "1";
}
sub scp_hit {
    if (req.http.X-SCP-Profile == "ultracache") { call scp_private_hit; }
    if (req.http.X-SCP-Profile == "ultracache") { call scp_ultracache_hit; }
}
sub scp_backend_fetch {
    cookie_handoff.bind(bereq.http.X-SCP-Cookie-Handoff);
    unset bereq.http.X-SCP-Cookie-Handoff;
    unset bereq.http.X-UltraCache-Delivery-Parent-Source;
    unset bereq.http.X-SCP-Delivery-Public-Snapshot;
    unset bereq.http.X-SCP-Personal-Delivery;
    unset bereq.http.X-UltraCache-Delivery-Authorization;
    unset bereq.http.X-UltraCache-Delivery-Manifest;
    unset bereq.http.X-UltraCache-Delivery-Recovery-Version;
    unset bereq.http.X-UltraCache-Delivery-Request-Snapshot-Version;
    unset bereq.http.X-UltraCache-Delivery-Private-Cache-Version;
    unset bereq.http.X-UltraCache-Delivery-Recovery;
    unset bereq.http.X-SCP-Private-Check;
    unset bereq.http.X-SCP-Admin-Remaining;
    unset bereq.http.X-SCP-Admin-Applied;
    unset bereq.http.X-SCP-Admin-Keep;
    unset bereq.http.X-SCP-Admin-Matched;
    unset bereq.http.X-SCP-Admin-Filtered;
    unset bereq.http.X-SCP-Admin-Variant;
    unset bereq.http.X-SCP-Admin-Has-Variant;
    unset bereq.http.X-SCP-Admin-Rule;
    unset bereq.http.X-SCP-Admin-Scope;
    unset bereq.http.X-SCP-Admin-Action;
    unset bereq.http.Surrogate-Capability;
    unset bereq.http.X-SCP-Fbp-Enabled;
    unset bereq.http.X-SCP-Fbp-Consent;
    unset bereq.http.X-SCP-Fbp-Domain;
    unset bereq.http.X-SCP-Fbp-Index;
    unset bereq.http.X-SCP-Fbp-New;
    unset bereq.http.X-SCP-Cookie-Name;
    unset bereq.http.X-SCP-Cookie-Role;
    if (bereq.http.X-SCP-Profile == "ultracache") { call scp_ultracache_backend_fetch; }
    unset bereq.http.X-SCP-Adaptive-Nonce;
}
sub scp_backend_response {
    if (bereq.http.X-SCP-Profile == "ultracache") { call scp_private_backend_response; }
    unset beresp.http.X-SCP-Delivery-Public-Snapshot;
    unset beresp.http.X-SCP-Personal-Delivery;
    if (bereq.http.X-SCP-Profile == "ultracache") {
        # Only the application's early publication reader may declare this:
        # no WP/provider ran and no issuer fields can be discarded/repeated.
        # Capture before response-cookie detachment or any local rewriting.
        if (beresp.http.X-UltraCache-Delivery-Parent-Source == "public-snapshot-v1" &&
            !beresp.http.Set-Cookie && beresp.status == 200) {
            set beresp.http.X-SCP-Delivery-Public-Snapshot = "1";
        }
        if (cookie_handoff.delivery_recovery_response()) {}
    }
    unset beresp.http.X-UltraCache-Delivery-Parent-Source;
    # An origin echo must never put the backend-only credential in an object.
    unset beresp.http.X-UltraCache-Delivery-Authorization;
    unset beresp.http.X-UltraCache-Delivery-Manifest;
    unset beresp.http.X-UltraCache-Delivery-Request;
    unset beresp.http.X-UltraCache-Delivery-Original-URL;
    unset beresp.http.X-UltraCache-Delivery-Phase;
    unset beresp.http.X-UltraCache-Delivery-Version;
    unset beresp.http.X-UltraCache-Delivery-Recovery-Version;
    unset beresp.http.X-UltraCache-Delivery-Request-Snapshot-Version;
    unset beresp.http.X-UltraCache-Delivery-Private-Cache-Version;
    unset beresp.http.X-SCP-Reason;
    unset beresp.http.X-SCP-Client-Vary;
    unset beresp.http.X-SCP-Result;
    unset beresp.http.X-SCP-Result-Reason;
    std.collect(beresp.http.Cache-Control);
    std.collect(beresp.http.Surrogate-Control);
    std.collect(beresp.http.Vary);
    if (beresp.http.Vary != "*") {
        if (!beresp.http.Vary) { set beresp.http.Vary = "X-Forwarded-Proto"; }
        else if (beresp.http.Vary !~ "(?i)(^|,)[[:blank:]]*X-Forwarded-Proto[[:blank:]]*(,|$)") {
            set beresp.http.Vary = beresp.http.Vary + ", X-Forwarded-Proto";
        }
    }
    if (bereq.http.X-SCP-Profile == "ultracache") { call scp_ultracache_personal_response; }
    call scp_aggressive_backend_response;
    call scp_shared_response_cookies;
    call scp_response_privacy;
    if (bereq.http.X-SCP-Profile == "ultracache") { call scp_ultracache_backend_response; }
    # Static and dynamic responses both retain functional Cookie variation.
    # Only resolved Shared pairs are omitted from the internal Cookie key.
    call scp_representation_response;
    call scp_response_variants;
}
sub scp_deliver {
    call scp_private_deliver;
    unset resp.http.X-SCP-Personal-Delivery;
    unset resp.http.X-UltraCache-Delivery-Authorization;
    unset resp.http.X-UltraCache-Delivery-Manifest;
    unset resp.http.X-UltraCache-Delivery-Recovery;
    unset resp.http.X-UltraCache-Delivery-Recovery-Version;
    unset resp.http.X-UltraCache-Delivery-Request-Snapshot-Version;
    unset resp.http.X-UltraCache-Delivery-Private-Cache-Version;
    if (req.http.X-SCP-Profile == "ultracache") { call scp_ultracache_deliver; }
    unset resp.http.X-UltraCache-Delivery-Parent-Source;
    unset resp.http.X-SCP-Delivery-Public-Snapshot;
    cookie_handoff.deliver();
    if (req.http.X-SCP-Aggressive == "1") { set resp.http.X-Cache-Mode = "aggressive"; }
    else { set resp.http.X-Cache-Mode = "standard"; }
    call scp_aggressive_deliver;
    if (req.http.X-SCP-Pass == "1" || obj.uncacheable) {
        set resp.http.X-SCP-Result = "PASS";
        if (req.http.X-SCP-Reason) { set resp.http.X-SCP-Result-Reason = req.http.X-SCP-Reason; }
        else if (resp.http.X-SCP-Reason) { set resp.http.X-SCP-Result-Reason = resp.http.X-SCP-Reason; }
        else { set resp.http.X-SCP-Result-Reason = "origin-uncacheable"; }
    } else if (obj.hits > 0) {
        set resp.http.X-SCP-Result = "HIT";
        set resp.http.X-SCP-Result-Reason = "cached-response";
    } else {
        set resp.http.X-SCP-Result = "MISS";
        set resp.http.X-SCP-Result-Reason = "fetch-required";
    }
    set resp.http.X-Cache = resp.http.X-SCP-Result;
    unset resp.http.X-Cache-Cookie-Delivery;
    # Original provider fields reach only this visitor, regardless of name.
    if (resp.http.Set-Cookie) { call scp_private_delivery; }
    if (req.http.X-SCP-Profile == "ultracache" &&
        (resp.http.X-UltraCache-ESI-Private-Count ~ "^[1-9][0-9]*$" ||
         (!resp.http.X-UltraCache-ESI-Private-Count && resp.http.X-UltraCache-ESI-Shared-Parent == "1"))) {
        # The reusable template declares private-capable occurrences, including
        # adaptive nonces. Protect delivery before ESI selects current identity.
        call scp_private_delivery;
    }
    unset resp.http.X-Cache-Hits;
    if (resp.http.X-Cache == "HIT") { set resp.http.X-Cache-Hits = obj.hits; }
    if (resp.http.X-SCP-Client-Vary) { set resp.http.Vary = resp.http.X-SCP-Client-Vary; }
    set resp.http.Vary = regsuball(resp.http.Vary,
        "(?i)(^|,)[[:blank:]]*X-SCP-Vary-Cookie[[:blank:]]*(?=,|$)", "\1Cookie");
    set resp.http.Vary = regsuball(resp.http.Vary,
        "(?i)(^|,)[[:blank:]]*X-SCP-Vary-ESI-Cookie[[:blank:]]*(?=,|$)", "\1Cookie");
    set resp.http.Vary = regsuball(resp.http.Vary,
        "(?i)(^|,)[[:blank:]]*X-SCP-Vary-Accept[[:blank:]]*(?=,|$)", "\1Accept");
    set resp.http.Vary = regsuball(resp.http.Vary,
        "(?i)(^|,)[[:blank:]]*X-SCP-Vary-Accept-Language[[:blank:]]*(?=,|$)", "\1Accept-Language");
    unset resp.http.X-SCP-Vary-Accept;
    unset resp.http.X-SCP-Vary-Accept-Language;
    unset resp.http.X-SCP-Normalize-Value;
    unset resp.http.X-SCP-Client-Vary;
    unset resp.http.X-SCP-Reason;
    unset resp.http.X-SCP-Key-URL;
    unset resp.http.X-SCP-Profile;
    unset resp.http.X-SCP-Vary-Cookie;
    unset resp.http.X-SCP-Vary-ESI-Cookie;
    unset resp.http.X-SCP-HTML-Accept;
    unset resp.http.X-UltraCache-ESI-Shared-Parent;
    unset resp.http.X-UltraCache-ESI-Candidate;
    unset resp.http.X-UltraCache-ESI-Opt-In;
    call scp_cookie_diagnostics;
    # Explicit public variants are keyed internally even without origin Vary.
    # Private selectors require the same downstream signal for their absent
    # public response, before an outer cache could skip our private guard.
    # Tell downstream caches about Cookie without adding unrelated Cookie
    # dimensions to Varnish's own lookup. Include the no-cookie representation.
    if (req.http.X-SCP-Admin-Has-Variant == "1" && resp.http.Vary != "*" &&
        resp.http.Vary !~ "(?i)(^|,)[[:blank:]]*Cookie[[:blank:]]*(,|$)") {
        if (resp.http.Vary) { set resp.http.Vary = resp.http.Vary + ", Cookie"; }
        else { set resp.http.Vary = "Cookie"; }
    }
    if (req.http.X-SCP-Admin-Action == "private") { call scp_private_delivery; }
}
