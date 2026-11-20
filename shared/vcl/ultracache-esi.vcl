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
if (req.http.X-SCP-Delivery-State == "3") {
    unset req.http.X-SCP-Aggressive;
    unset req.http.X-SCP-Aggressive-TTL;
    return (hash);
}
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
    obj.http.X-UltraCache-Woo-Async-Parent != "1" && !cookie_handoff.selection_manifest()
) {
    set req.http.X-SCP-Reason = "unapproved-private-parent";
    return (pass);
}
}
sub scp_ultracache_backend_fetch {
if (bereq.http.X-SCP-Private-Key) {
    if (!cookie_handoff.delivery_private_backend()) {
        return (error(503, "Prepared private source unavailable"));
    }
    set bereq.backend = cookie_handoff.delivery_private_backend();
    unset bereq.http.Cookie;
    unset bereq.http.Authorization;
    unset bereq.http.Accept-Encoding;
    unset bereq.http.X-SCP-Aggressive;
    unset bereq.http.X-SCP-Aggressive-TTL;
    return (fetch);
}
unset bereq.http.X-SCP-Delivery-State;
unset bereq.http.X-UltraCache-Delivery-Version;
unset bereq.http.X-UltraCache-Delivery-Phase;
unset bereq.http.X-UltraCache-Delivery-Request;
unset bereq.http.X-UltraCache-Delivery-Original-URL;
if (cookie_handoff.delivery_backend()) {
    call scp_delivery_authorization;
    if (!bereq.http.X-UltraCache-Delivery-Authorization) {
        return (error(503, "Delivery credential unavailable"));
    }
    # Native state preserved the actual original Cookie and route. No generic
    # Cookie rewriting or provider retry may happen on this private operation.
    set bereq.retry_connect = false;
    if (cookie_handoff.delivery_local_backend()) {
        set bereq.backend = cookie_handoff.delivery_local_backend();
        # This is a refill of the selected publication's remaining budget,
        # not a fresh origin render eligible for a new aggressive lifetime.
        unset bereq.http.X-SCP-Aggressive;
        unset bereq.http.X-SCP-Aggressive-TTL;
    }
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
    set bereq.http.X-UltraCache-Delivery-Recovery-Version = "1";
    set bereq.http.X-UltraCache-Delivery-Request-Snapshot-Version = "1";
    # Reuse the existing signed private capability probe; no new probe or
    # manual enablement. Ordinary private/public children stay silent.
    if (bereq.http.X-SCP-Query ~ "(^|&)ultracache_esi_probe_private_fragment=[^&]+(?:&|$)") {
        set bereq.http.X-UltraCache-Delivery-Private-Cache-Version = "1";
        set bereq.http.X-UltraCache-Delivery-Private-Document-Version = "1";
    }
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
sub scp_delivery_authorization {
    # Filled from native adapter-owned site credentials, never a request field.
    # This sub is called only after the native task association proves prepare.
    @@DELIVERY_AUTHORIZATION@@
}
sub scp_ultracache_public_fragment_response {
    # The application verifies its signed endpoint before emitting this existing
    # public fragment contract. A query or client/scratch header alone is no proof.
    # Keep native HTTP freshness (including Age/Date); never restart the TTL.
    if (bereq.http.X-SCP-Query ~ "(^|&)ultracache_esi=[^&]+(?:&|$)" &&
        bereq.http.X-ESI-Private-Request != "1" &&
        beresp.status == 200 && beresp.http.Content-Type ~ "(?i)^text/html(?:;|$)" &&
        beresp.http.X-UltraCache-ESI-Scope == "public" &&
        beresp.http.X-UltraCache-ESI-Fragment ~ "^[a-z0-9_-]+$" &&
        beresp.http.X-UltraCache-ESI-TTL ~ "^(0|[1-9][0-9]*)$" &&
        beresp.http.X-UltraCache-Cacheable ~ "^[01]$") {
        set beresp.http.X-SCP-Public-Fragment = "1";
        # The fragment API declares TTL only, never a stale/retention window.
        set beresp.grace = 0s;
        set beresp.keep = 0s;
    }
}
sub scp_ultracache_personal_response {
    # Existing metadata identifies the visitor copy, never the public collector
    # bytes. This is actual body provenance, not a cookie classification rule.
    if ((beresp.http.X-UltraCache-Application-Private && beresp.http.X-UltraCache-Application-Private != "") ||
        (beresp.http.X-UltraCache-Cacheable == "0" &&
        beresp.http.X-UltraCache-ESI-Private-Count ~ "^[1-9][0-9]*$" &&
        beresp.http.X-UltraCache-ESI-Shared-Parent != "1")) {
        set beresp.http.X-SCP-Personal-Delivery = "1";
        set beresp.http.X-UltraCache-Cacheable = "0";
        unset beresp.http.X-UltraCache-ESI-Shared-Parent;
        unset beresp.http.X-UltraCache-Delivery-Parent-Source;
        unset beresp.http.X-SCP-Delivery-Public-Snapshot;
        set beresp.http.Cache-Control = "private, no-store";
        # Preserve an existing ESI/1.0 token for remaining PUBLIC includes.
        if (!beresp.http.Surrogate-Control) {
            set beresp.http.Surrogate-Control = "no-store";
        } else if (beresp.http.Surrogate-Control !~ "(?i)(^|[[:space:],])no-store([[:space:],=]|$)") {
            set beresp.http.Surrogate-Control = beresp.http.Surrogate-Control + ", no-store";
        }
        call scp_mark_uncacheable;
    }
}
sub scp_ultracache_fragment_http_response {
    # An endpoint failure may precede application success metadata entirely.
    # Never retain that error/redirect as a reusable fragment. Direct endpoint
    # requests keep their actual status/body; only native ESI children omit it.
    if (bereq.http.X-SCP-Query ~ "(^|&)(ultracache_esi|ultracache_esi_probe_private_fragment)=[^&]+(?:&|$)" &&
        beresp.status != 200 && beresp.status != 204) {
        set beresp.http.X-SCP-Reason = "ultracache-fragment-http-failure";
        set beresp.http.Cache-Control = "private, no-store";
        set beresp.http.Surrogate-Control = "no-store";
        set beresp.grace = 0s;
        set beresp.keep = 0s;
        call scp_mark_uncacheable;
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
    if (bereq.http.X-UltraCache-ESI-Candidate == "1" && !cookie_handoff.selection_local()) {
        if (beresp.uncacheable || beresp.http.X-UltraCache-ESI-Shared-Parent != "1" || !beresp.do_esi) {
            unset beresp.http.X-UltraCache-ESI-Shared-Parent;
            if (!beresp.http.X-SCP-Reason) {
                set beresp.http.X-SCP-Reason = "unapproved-private-parent";
            }
            set beresp.http.Cache-Control = "private, no-store";
            call scp_mark_uncacheable;
        }
    }
    if (cookie_handoff.delivery_local_source()) {
        # Set explicit filters after do_esi has been decided. The first is a
        # request-owned byte source, not a connection reader or another cache.
        set beresp.do_stream = false;
        set beresp.grace = 0s;
        set beresp.keep = 0s;
        if (beresp.do_esi) { set beresp.filters = "uc_request_snapshot esi"; }
        else { set beresp.filters = "uc_request_snapshot"; }
    }
}

sub scp_ultracache_deliver {
    if (req.esi_level > 0 && resp.status != 200 && resp.status != 204 &&
        req.http.X-SCP-Query ~ "(^|&)(ultracache_esi|ultracache_esi_probe_private_fragment)=[^&]+(?:&|$)") {
        # Only this native child, not an external request or full private
        # document, becomes an empty delivery. Preserve the original status
        # in the native log; never embed a backend error page into its parent.
        set req.http.X-SCP-Fragment-HTTP-Failure = resp.status;
        return (synth(200, "UltraCache fragment unavailable"));
    }
    if (req.esi_level == 0 && req.method == "GET" &&
        (obj.hits > 0 || resp.http.X-SCP-Delivery-Public-Snapshot == "1") &&
        req.http.X-SCP-Pass != "1" && !obj.uncacheable && resp.status == 200 &&
        resp.http.X-UltraCache-ESI-Shared-Parent == "1" &&
        resp.http.X-UltraCache-ESI-Private-Count ~ "^[1-9][0-9]*$" &&
        resp.http.X-UltraCache-Delivery-Prepare) {
        set req.http.X-SCP-Delivery-State = cookie_handoff.delivery_deliver(
            resp.http.X-UltraCache-Delivery-Prepare,
            std.integer(resp.http.X-UltraCache-ESI-Private-Count, 0), true);
    } else {
        set req.http.X-SCP-Delivery-State = cookie_handoff.delivery_deliver(
            resp.http.X-UltraCache-Delivery-Prepare,
            std.integer(resp.http.X-UltraCache-ESI-Private-Count, 0), false);
    }
    if (req.http.X-SCP-Delivery-State == "1") { return (restart); }
    if (req.http.X-SCP-Delivery-State == "2") { return (synth(200, "Private document")); }
    if (req.http.X-SCP-Delivery-State == "-1") { return (synth(503, "Delivery continuation failed")); }
    unset req.http.X-SCP-Delivery-State;
    unset resp.http.X-UltraCache-Delivery-Prepare;
    unset resp.http.X-UltraCache-Delivery-Version;
    unset resp.http.X-UltraCache-Delivery-Phase;
    unset resp.http.X-UltraCache-Delivery-Request;
    unset resp.http.X-UltraCache-Delivery-Original-URL;
}

# The complete adapter defines scp_private_document_diagnostics exactly once.
# Custom VCL subroutines cannot be extended through repeated definitions.
sub vcl_backend_error {
    if (bereq.http.X-SCP-Profile == "ultracache" &&
        bereq.http.X-SCP-Query ~ "(^|&)(ultracache_esi|ultracache_esi_probe_private_fragment)=[^&]+(?:&|$)") {
        # The default backend-error object must not retain a failed fragment
        # and delay recovery after the next actual upstream request succeeds.
        set beresp.ttl = 0s;
        set beresp.grace = 0s;
        set beresp.keep = 0s;
        set beresp.uncacheable = true;
        set beresp.http.Cache-Control = "private, no-store";
        set beresp.http.Surrogate-Control = "no-store";
    }
}
sub vcl_synth {
    if (req.http.X-SCP-Profile == "ultracache" && req.esi_level > 0 &&
        req.http.X-SCP-Fragment-HTTP-Failure ~ "^[1-5][0-9][0-9]$") {
        std.log("UltraCache signed child HTTP failure " + req.http.X-SCP-Fragment-HTTP-Failure);
        unset req.http.X-SCP-Fragment-HTTP-Failure;
        set resp.http.Cache-Control = "private, no-store";
        set resp.http.Surrogate-Control = "no-store";
        set resp.http.X-UltraCache-ESI-Error-Contained = "1";
        set resp.http.X-Cache = "PASS";
        set resp.body = "";
        return (deliver);
    }
    if (req.http.X-SCP-Profile == "ultracache" && cookie_handoff.delivery_synth()) {
        if (req.esi_level == 0) {
            set resp.http.X-Cache = "PASS";
            call scp_private_document_diagnostics;
        }
        return (deliver);
    }
}

# Keep raw Accept at the origin. Only an identified public stored HTML object
# can substitute its known image-capability dimensions for the raw header.
