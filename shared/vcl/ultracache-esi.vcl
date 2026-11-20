# Shared ultracache-esi policy. GPL-3.0-or-later.

sub scp_ultracache_recv {
# Browser copies never authorize a continuation. The native PRIV_TOP phase
# restores prepare/parent state and answers already-rendered private children.
unset req.http.X-UltraCache-Delivery-Version;
unset req.http.X-UltraCache-Delivery-Phase;
unset req.http.X-UltraCache-Delivery-Request;
unset req.http.X-UltraCache-Delivery-Original-URL;
unset req.http.X-SCP-Delivery-State;
set req.http.X-SCP-Delivery-State = cookie_handoff.delivery_recv();
if (req.http.X-SCP-Delivery-State == "1") { return (pass); }
if (req.http.X-SCP-Delivery-State == "2") { return (synth(200, "OK")); }
if (req.http.X-SCP-Delivery-State == "-1") { return (synth(503, "Delivery continuation failed")); }
unset req.http.X-SCP-Delivery-State;
# Private/session ESI transport.
if (req.esi_level == 0) {
    # Capture the request-side UltraCache opt-in before removing its
    # marker cookie from the request forwarded to the origin.
    if (req.http.Cookie ~ "(^|;[[:blank:]]*)ultracache_esi_optin=1(?:;|$)") {
        set req.http.X-UltraCache-ESI-Opt-In = "1";
        # Explicit composition opt-in, independent of cookie classification.
        set req.http.X-UltraCache-ESI-Candidate = "1";
    }

    # Transport candidates only: these names never grant Shared/Variant/Private.
    # The signed renderer definition selects its own subset at the endpoint;
    # WordPress validates the actual logged-in cookie, never a cached user ID.
    # Preserve raw values and order. Public children still receive no cookies.
    set req.http.X-ESI-Original-Cookie = regsuball(req.http.Cookie,
        {"(^|;)(?![[:blank:]]*(?:esi_session|woocommerce_items_in_cart|woocommerce_cart_hash|wp_woocommerce_session_[^=;[:blank:]]+|woocommerce_recently_viewed|wordpress_logged_in_[^=;[:blank:]]+)=)[^;]*"}, "");
    set req.http.X-ESI-Original-Cookie = regsuball(req.http.X-ESI-Original-Cookie, "^[;[:blank:]]+|[;[:blank:]]+$", "");
    set req.http.X-ESI-Original-Cookie = regsuball(req.http.X-ESI-Original-Cookie, ";[[:blank:]]*", "; ");
    if (req.http.X-ESI-Original-Cookie == "") { unset req.http.X-ESI-Original-Cookie; }


} else {
    # Routing declaration only. UltraCache must verify that esi_identity agrees
    # with its signed wordpress-nonce-adaptive descriptor/context; an appended
    # selector cannot authorize an ordinary fragment or assert a user identity.
    if (req.http.X-SCP-Query ~ "(^|&)ultracache_esi=[^&]+(?:&|$)" &&
        req.http.X-SCP-Query ~ "(^|&)esi_identity=wordpress(?:&|$)") {
        set req.http.X-SCP-Adaptive-Nonce = "1";
        set req.http.X-ESI-Request-Level = "1";
        if (cookie_handoff.delivery_guard()) { return (synth(503, "Prepared fragment missing")); }
    }
    if (
        (req.http.X-SCP-Query ~ "(?i)(^|&)esi_scope=private(?:&|$)" &&
         req.http.X-SCP-Query ~ "(?i)(^|&)(ultracache_esi|ultracache_esi_probe_private_fragment)=") ||
        (req.http.X-SCP-Adaptive-Nonce == "1" &&
         req_top.http.X-ESI-Original-Cookie ~ {"(^|;[[:blank:]]*)(wordpress_logged_in_|wp_woocommerce_session_)[^=;[:blank:]]+="})
    ) {
        set req.http.X-ESI-Private-Request = "1";
        set req.http.X-ESI-Request-Level = "1";
        set req.http.X-SCP-Reason = "private-esi-fragment";
        if (cookie_handoff.delivery_guard()) { return (synth(503, "Prepared fragment missing")); }

        if (req_top.http.X-ESI-Original-Cookie) {
            set req.http.Cookie = req_top.http.X-ESI-Original-Cookie;
        } else {
            unset req.http.Cookie;
        }

        return (pass);
    }

    # Ordinary public children and anonymous adaptive nonces are cookie-free.
    unset req.http.Cookie;
}

# Varnish ESI works with identity/gzip origin responses.
if (req.http.Accept-Encoding) {
    if (
        req.url ~ "(?i)\.(avif|gif|gz|ico|jpeg|jpg|mp3|mp4|ogg|ogv|pdf|png|svg|webm|webp|woff|woff2|zip)(\?.*)?$"
    ) {
        unset req.http.Accept-Encoding;
    } else if (req.http.Accept-Encoding ~ "(?i)(^|,)[[:blank:]]*gzip[[:blank:]]*;[[:blank:]]*q[[:blank:]]*=[[:blank:]]*0([.]0*)?[[:blank:]]*(,|$)") {
        unset req.http.Accept-Encoding;
    } else if (req.http.Accept-Encoding ~ "(?i)(^|,)[[:blank:]]*gzip[[:blank:]]*(;|,|$)") {
        set req.http.Accept-Encoding = "gzip";
    } else {
        unset req.http.Accept-Encoding;
    }
}


}

# An explicitly opted-in composition request needs an origin-approved parent.
# This is the ESI application contract, not another cookie classification list.
sub scp_ultracache_hit {
# UltraCache composition candidates may reuse only origin-approved parents.
# Saved Private cookie choices have already passed before this lookup.
if (
    req.http.X-UltraCache-ESI-Candidate == "1" &&
    obj.http.X-UltraCache-ESI-Shared-Parent != "1" &&
    obj.http.X-UltraCache-Woo-Async-Parent != "1"
) {
    set req.http.X-SCP-Reason = "unapproved-private-parent";
    return (pass);
}
}
sub scp_ultracache_backend_fetch {
unset bereq.http.X-SCP-Delivery-State;
unset bereq.http.X-UltraCache-Delivery-Version;
unset bereq.http.X-UltraCache-Delivery-Phase;
unset bereq.http.X-UltraCache-Delivery-Request;
unset bereq.http.X-UltraCache-Delivery-Original-URL;
if (cookie_handoff.delivery_backend()) {
    # Native state preserved the actual original Cookie and route. No generic
    # Cookie rewriting or provider retry may happen on this private operation.
    set bereq.retry_connect = false;
} else {
# Advertise generic ESI capability to any compatible application.
set bereq.http.Surrogate-Capability = "varnish=ESI/1.0";
unset bereq.http.X-UltraCache-ESI-Transport-Version;
unset bereq.http.X-UltraCache-ESI-Adaptive-Nonce-Version;
if (bereq.http.X-ESI-Private-Request == "1") {
    # Set only by this carrier, never inherited from the browser or parent.
    # Revision 2 does not advertise private TTL or preflight cookie issuance.
    set bereq.http.X-UltraCache-ESI-Transport-Version = "2";
    set bereq.http.X-UltraCache-Delivery-Version = "1";
}
if (bereq.http.X-ESI-Private-Request == "1" || bereq.http.X-SCP-Adaptive-Nonce == "1") {
    # The existing signed private probe can observe this capability without
    # another request. It is separate from extended cookie transport revision 2.
    set bereq.http.X-UltraCache-ESI-Adaptive-Nonce-Version = "1";
}
# Protocol markers are removed only after cookie policy has run. A saved
# Private/Variant choice on those names must not disappear before resolution.
# The existing signed raw-source collector retains its original cookie wire.
if (bereq.http.X-ESI-Private-Request != "1" &&
    bereq.http.X-SCP-Reason != "ultracache-private-session-source") {
    set bereq.http.Cookie = regsuball(bereq.http.Cookie,
        "(^|;[[:blank:]]*)(esi_session|ultracache_esi_optin)=[^;]*", "");
    set bereq.http.Cookie = regsuball(bereq.http.Cookie, "^[;[:blank:]]+|[;[:blank:]]+$", "");
    set bereq.http.Cookie = regsuball(bereq.http.Cookie, ";[[:blank:]]*", "; ");
    if (bereq.http.Cookie == "") { unset bereq.http.Cookie; }
}


# Never expose internal scratch/cookie-carrier headers to the origin.
# X-UltraCache-ESI-Candidate intentionally remains: the plugin uses it
# to decide whether it can safely approve a shared ESI parent response.
unset bereq.http.X-ESI-Original-Cookie;
unset bereq.http.X-UltraCache-ESI-Cookie-Check;
unset bereq.http.X-UltraCache-ESI-Opt-In;
unset bereq.http.X-UltraCache-ESI-Shared-Parent;
}
}
sub scp_ultracache_backend_response {
    if (cookie_handoff.delivery_capture()) {
        # A private transient fetch object is discarded at the prepare restart.
        # Its complete body must be captured before vcl_deliver can resume.
        call scp_mark_uncacheable;
        set beresp.ttl = 0s;
        set beresp.grace = 0s;
        set beresp.keep = 0s;
        set beresp.do_stream = false;
        set beresp.filters = "uc_delivery_capture";
        set beresp.http.Cache-Control = "private, no-store";
        set beresp.http.Surrogate-Control = "no-store";
        return (deliver);
    }
    if (bereq.http.X-ESI-Private-Request == "1") {
        set beresp.http.X-SCP-Reason = "private-esi-fragment";
        call scp_mark_uncacheable;
        set beresp.http.Cache-Control = "private, no-store";
        set beresp.http.Surrogate-Control = "no-store";
        return (deliver);
    }
    # Compose ESI for this delivery, retaining the common privacy decision.
    if (beresp.status == 200 && beresp.http.Content-Type ~ "(?i)^text/html" &&
        beresp.http.Surrogate-Control ~ "(?i)ESI/1[.]0") {
        set beresp.do_esi = true;
        unset beresp.http.Surrogate-Control;
    }
    if (bereq.http.X-UltraCache-ESI-Candidate == "1") {
        if (beresp.uncacheable || beresp.http.X-UltraCache-ESI-Shared-Parent != "1" || !beresp.do_esi) {
            unset beresp.http.X-UltraCache-ESI-Shared-Parent;
            if (!beresp.http.X-SCP-Reason) {
                set beresp.http.X-SCP-Reason = "unapproved-private-parent";
            }
            set beresp.http.Cache-Control = "private, no-store";
            call scp_mark_uncacheable;
        }
    }
}

sub scp_ultracache_deliver {
    if (req.esi_level == 0 && req.method == "GET" && obj.hits > 0 &&
        req.http.X-SCP-Pass != "1" && !obj.uncacheable && resp.status == 200 &&
        resp.http.X-UltraCache-ESI-Shared-Parent == "1" &&
        resp.http.X-UltraCache-ESI-Private-Count ~ "^[1-9][0-9]*$" &&
        resp.http.X-UltraCache-Delivery-Prepare) {
        set req.http.X-SCP-Delivery-State = cookie_handoff.delivery_deliver(
            resp.http.X-UltraCache-Delivery-Prepare,
            std.integer(resp.http.X-UltraCache-ESI-Private-Count, 0));
    } else {
        set req.http.X-SCP-Delivery-State = cookie_handoff.delivery_deliver("", 0);
    }
    if (req.http.X-SCP-Delivery-State == "1") { return (restart); }
    if (req.http.X-SCP-Delivery-State == "-1") { return (synth(503, "Delivery continuation failed")); }
    unset req.http.X-SCP-Delivery-State;
    unset resp.http.X-UltraCache-Delivery-Prepare;
    unset resp.http.X-UltraCache-Delivery-Version;
    unset resp.http.X-UltraCache-Delivery-Phase;
    unset resp.http.X-UltraCache-Delivery-Request;
    unset resp.http.X-UltraCache-Delivery-Original-URL;
}

sub vcl_synth {
    if (req.http.X-SCP-Profile == "ultracache" && cookie_handoff.delivery_synth()) {
        return (deliver);
    }
}

# Keep raw Accept at the origin. Only an identified public stored HTML object
# can substitute its known image-capability dimensions for the raw header.
