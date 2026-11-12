# UltraCache for Webuzo: addon-owned Varnish policy, independent of application installation.
# Adapted from UltraCache VCL (GPL-3.0-or-later).
# Host/backend/purge isolation is provided by the immutable compiler envelope.
# The request/response ESI handshake is evaluated as HTTP behavior only.

sub wvw_ultracache_recv {
# Private/session ESI transport.
if (req.esi_level == 0) {
    # Drop spoofed internal ESI transport headers from clients.
    unset req.http.X-ESI-Private-Request;
    unset req.http.X-ESI-Request-Level;
    unset req.http.X-ESI-Original-Cookie;
    unset req.http.X-UltraCache-ESI-Candidate;
    unset req.http.X-UltraCache-ESI-Cookie-Check;
    unset req.http.X-UltraCache-ESI-Opt-In;
    unset req.http.X-UltraCache-ESI-Shared-Parent;

    # Capture the request-side UltraCache opt-in before removing its
    # marker cookie from the request forwarded to the origin.
    if (req.http.Cookie ~ "(?i)(^|;[ ]*)ultracache_esi_optin=1(?:;|$)") {
        set req.http.X-UltraCache-ESI-Opt-In = "1";
    }

    # Build the private-fragment carrier from allowlisted cookies only.
    # Never copy the complete browser Cookie header into an ESI subrequest.
    if (req.http.Cookie ~ "(?i)(^|;[ ]*)esi_session=") {
        set req.http.X-ESI-Original-Cookie = regsub(
            req.http.Cookie,
            "(?i)^.*?(?:^|;[ ]*)(esi_session=[^;]*).*$",
            "\1"
        );
    }

    if (req.http.Cookie ~ "(?i)(^|;[ ]*)woocommerce_items_in_cart=") {
        if (req.http.X-ESI-Original-Cookie) {
            set req.http.X-ESI-Original-Cookie = req.http.X-ESI-Original-Cookie + "; " + regsub(
                req.http.Cookie,
                "(?i)^.*?(?:^|;[ ]*)(woocommerce_items_in_cart=[^;]*).*$",
                "\1"
            );
        } else {
            set req.http.X-ESI-Original-Cookie = regsub(
                req.http.Cookie,
                "(?i)^.*?(?:^|;[ ]*)(woocommerce_items_in_cart=[^;]*).*$",
                "\1"
            );
        }
    }

    if (req.http.Cookie ~ "(?i)(^|;[ ]*)woocommerce_cart_hash=") {
        if (req.http.X-ESI-Original-Cookie) {
            set req.http.X-ESI-Original-Cookie = req.http.X-ESI-Original-Cookie + "; " + regsub(
                req.http.Cookie,
                "(?i)^.*?(?:^|;[ ]*)(woocommerce_cart_hash=[^;]*).*$",
                "\1"
            );
        } else {
            set req.http.X-ESI-Original-Cookie = regsub(
                req.http.Cookie,
                "(?i)^.*?(?:^|;[ ]*)(woocommerce_cart_hash=[^;]*).*$",
                "\1"
            );
        }
    }

    if (req.http.Cookie ~ "(?i)(^|;[ ]*)wp_woocommerce_session_[^=; ]+=") {
        if (req.http.X-ESI-Original-Cookie) {
            set req.http.X-ESI-Original-Cookie = req.http.X-ESI-Original-Cookie + "; " + regsub(
                req.http.Cookie,
                "(?i)^.*?(?:^|;[ ]*)((?:wp_woocommerce_session_[^=; ]+)=[^;]*).*$",
                "\1"
            );
        } else {
            set req.http.X-ESI-Original-Cookie = regsub(
                req.http.Cookie,
                "(?i)^.*?(?:^|;[ ]*)((?:wp_woocommerce_session_[^=; ]+)=[^;]*).*$",
                "\1"
            );
        }
    }

    # Remove UltraCache-only marker cookies from the origin request.
    if (req.http.Cookie ~ "(?i)(^|;[ ]*)(esi_session|ultracache_esi_optin)=") {
        set req.http.Cookie = regsuball(
            req.http.Cookie,
            "(?i)(^|;[ ]*)(esi_session|ultracache_esi_optin)=[^;]*",
            ""
        );
        set req.http.Cookie = regsuball(req.http.Cookie, "^[; ]+|[; ]+$", "");
        set req.http.Cookie = regsuball(req.http.Cookie, ";[ ]*;", ";");

        if (req.http.Cookie == "") {
            unset req.http.Cookie;
        }
    }
} else {
    unset req.http.X-ESI-Private-Request;
    unset req.http.X-ESI-Request-Level;
    unset req.http.X-UltraCache-ESI-Candidate;
    unset req.http.X-UltraCache-ESI-Cookie-Check;
    unset req.http.X-UltraCache-ESI-Opt-In;
    unset req.http.X-UltraCache-ESI-Shared-Parent;

    if (
        req.url ~ "(?i)([?&])esi_scope=private(?:&|$)" &&
        req.url ~ "(?i)([?&])(ultracache_esi|ultracache_esi_probe_private_fragment)="
    ) {
        set req.http.X-ESI-Private-Request = "1";
        set req.http.X-ESI-Request-Level = "1";
        set req.http.X-WV-Mode = "PASS";

        if (req_top.http.X-ESI-Original-Cookie) {
            set req.http.Cookie = req_top.http.X-ESI-Original-Cookie;
        } else {
            unset req.http.Cookie;
        }

        return (pass);
    }

    # Public ESI fragments never inherit visitor cookies.
    unset req.http.Cookie;
}

# Never cache authenticated, upgraded or non-read-only requests.
if (req.http.Authorization) {
    set req.http.X-WV-Mode = "PASS";
    return (pass);
}

if (req.http.Upgrade) {
    set req.http.X-WV-Mode = "PASS";
    return (pass);
}

if (req.method != "GET" && req.method != "HEAD") {
    set req.http.X-WV-Mode = "PASS";
    return (pass);
}

# Certificate validation requests must reach the origin.
if (
    req.url ~ "^/\.well-known/acme-challenge/" ||
    req.url ~ "^/\.well-known/pki-validation/"
) {
    set req.http.X-WV-Mode = "PASS";
    return (pass);
}

# Legacy AJAX requests.
if (req.http.X-Requested-With ~ "(?i)^XMLHttpRequest$") {
    set req.http.X-WV-Mode = "PASS";
    return (pass);
}

# WordPress administration, authentication, cron, comments and APIs.
if (
    req.url ~ "(?i)^/wp-admin(?:/|\?|$)" ||
    req.url ~ "(?i)^/wp-login\.php(?:\?|$)" ||
    req.url ~ "(?i)^/wp-cron\.php(?:\?|$)" ||
    req.url ~ "(?i)^/wp-comments-post\.php(?:\?|$)" ||
    req.url ~ "(?i)^/xmlrpc\.php(?:\?|$)" ||
    req.url ~ "(?i)^/wp-json(?:/|\?|$)"
) {
    set req.http.X-WV-Mode = "PASS";
    return (pass);
}

# WordPress previews, editors, REST requests and search pages.
if (
    req.url ~ "(?i)(\?|&)(preview|preview_id|preview_nonce|customize_changeset_uuid|elementor-preview|et_fb|vc_editable|rest_route|s|nocache)="
) {
    set req.http.X-WV-Mode = "PASS";
    return (pass);
}

# Keep standard WooCommerce private paths safe without any application plugin.
# Other/localized paths follow the origin's private/no-store cache policy.
if (
    req.url ~ "(?i)^/(cart|checkout|my-account|wc-api)(/|[?]|$)" ||
    req.url ~ "(?i)(\?|&)(add-to-cart|wc-ajax|wc-api)="
) {
    set req.http.X-WV-Mode = "PASS";
    return (pass);
}

# Affiliate/referral requests may set visitor-specific cookies.
if (req.url ~ "(?i)(\?|&)ref=") {
    set req.http.X-WV-Mode = "PASS";
    return (pass);
}

# Remove common marketing parameters without changing application parameters.
if (
    req.url ~ "(?i)(\?|&)(utm_[a-z0-9_]+|gclid|dclid|fbclid|msclkid|gbraid|wbraid|igshid)="
) {
    set req.url = regsuball(
        req.url,
        "(?i)([?&])(utm_[a-z0-9_]+|gclid|dclid|fbclid|msclkid|gbraid|wbraid|igshid)=[^&]*",
        "\1"
    );
    set req.url = regsuball(req.url, "\?&", "?");
    set req.url = regsuball(req.url, "&&+", "&");
    set req.url = regsuball(req.url, "[?&]+$", "");
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

# Application exclusions, rather than a list of permitted tracking cookies.
# Unknown cookies remain available to the origin on a miss. Cart cookies
# require explicit request opt-in and response approval for an ESI parent.
call wvw_private_cookie_recv;
call wvw_cart_cookie_recv;

# Static assets are shared and do not need browser cookies.
# HTML/HTM are intentionally excluded because they may be dynamic rewrites.
if (
    req.url ~ "(?i)\.(avif|bmp|css|eot|gif|ico|jpeg|jpg|js|map|mp3|mp4|ogg|ogv|pdf|png|svg|ttf|webm|webp|woff|woff2|zip)(\?.*)?$"
) {
    unset req.http.Cookie;
    return (hash);
}

# Preserve the client's exact content negotiation, including JSON/XML APIs,
# image formats, quality values and an absent Accept header. Native Vary: Accept
# keeps representations separate without assuming a particular application.

return (hash);
}

sub wvw_ultracache_hit {
# Cart/session requests may reuse only an origin-approved ESI or async
# cart parent. Async approval is stored by an anonymous fetch; a private
# cold miss still needs the existing ESI backend handshake.
if (
    req.http.X-UltraCache-ESI-Candidate == "1" &&
    obj.http.X-UltraCache-ESI-Shared-Parent != "1" &&
    obj.http.X-UltraCache-Woo-Async-Parent != "1"
) {
    set req.http.X-WV-Mode = "PASS";
    return (pass);
}
}

sub wvw_ultracache_backend_fetch {
# Advertise generic ESI capability to any compatible application.
set bereq.http.Surrogate-Capability = "varnish=ESI/1.0";

# Never expose internal scratch/cookie-carrier headers to the origin.
# X-UltraCache-ESI-Candidate intentionally remains: the plugin uses it
# to decide whether it can safely approve a shared ESI parent response.
unset bereq.http.X-ESI-Original-Cookie;
unset bereq.http.X-UltraCache-ESI-Cookie-Check;
unset bereq.http.X-UltraCache-ESI-Opt-In;
unset bereq.http.X-UltraCache-ESI-Shared-Parent;
}

sub wvw_ultracache_backend_response {
# Use protocol as a secondary Vary key so normal exact PURGE still
# removes every scheme/Accept/encoding variant in the same object head.
if (beresp.http.Vary != "*") {
    if (!beresp.http.Vary) {
        set beresp.http.Vary = "X-Forwarded-Proto";
    } else if (beresp.http.Vary !~ "(?i)(^|,)[[:blank:]]*X-Forwarded-Proto[[:blank:]]*(,|$)") {
        set beresp.http.Vary = beresp.http.Vary + ", X-Forwarded-Proto";
    }
}
# Private ESI fragments must execute for every delivery and must never be stored.
if (bereq.http.X-ESI-Private-Request == "1") {
    call wvw_mark_uncacheable;
    set beresp.http.Cache-Control = "private, no-store";
    set beresp.http.Surrogate-Control = "no-store";
    return (deliver);
}

# WooCommerce ESI handshake.
#
# The request is allowed to hash while its real WooCommerce cookies are
# still sent to the origin. Varnish stores/reuses a shared parent only
# when UltraCache explicitly confirms that the parent is non-personalized.
if (bereq.http.X-UltraCache-ESI-Candidate == "1") {
    if (
        beresp.http.X-UltraCache-ESI-Shared-Parent == "1" &&
        beresp.status == 200 &&
        beresp.http.Content-Type ~ "(?i)^text/html" &&
        beresp.http.Surrogate-Control ~ "(?i)ESI/1[.]0"
    ) {
        # Approval is valid only when the response itself has no normal
        # private/no-store signal or Set-Cookie header.
        if (
            beresp.http.Set-Cookie ||
            beresp.http.Cache-Control ~ "(?i)(private|no-cache|no-store)" ||
            beresp.http.Pragma ~ "(?i)no-cache" ||
            beresp.http.Vary == "*"
        ) {
            unset beresp.http.X-UltraCache-ESI-Shared-Parent;
            call wvw_mark_uncacheable;
            return (deliver);
        }

        set beresp.do_esi = true;
        unset beresp.http.Surrogate-Control;
    } else {
        # No approval: preserve correct WooCommerce behavior. If an older
        # UltraCache version emitted ESI markup, compose it for this one
        # delivery but never store/reuse the parent response.
        if (
            beresp.status == 200 &&
            beresp.http.Content-Type ~ "(?i)^text/html" &&
            beresp.http.Surrogate-Control ~ "(?i)ESI/1[.]0"
        ) {
            set beresp.do_esi = true;
            unset beresp.http.Surrogate-Control;
        }

        unset beresp.http.X-UltraCache-ESI-Shared-Parent;
        call wvw_mark_uncacheable;
        return (deliver);
    }
}

# Never store authentication, rate-limit or backend-error responses.
if (
    beresp.status == 401 ||
    beresp.status == 403 ||
    beresp.status == 429 ||
    beresp.status >= 500
) {
    call wvw_mark_uncacheable;
    return (deliver);
}

# Respect the origin application's cache policy.
if (
    beresp.http.Set-Cookie ||
    beresp.http.Cache-Control ~ "(?i)(private|no-cache|no-store)" ||
    beresp.http.Pragma ~ "(?i)no-cache" ||
    beresp.http.Vary == "*"
) {
    call wvw_mark_uncacheable;
    return (deliver);
}

# Enable ESI only when the origin explicitly requests it.
if (
    beresp.status == 200 &&
    beresp.http.Content-Type ~ "(?i)^text/html" &&
    beresp.http.Surrogate-Control ~ "(?i)ESI/1[.]0"
) {
    set beresp.do_esi = true;
    unset beresp.http.Surrogate-Control;
}

# Store object-side metadata for efficient ban-lurker processing. These
# headers are removed in vcl_deliver and are never exposed to clients.
set beresp.http.X-Cache-Object-Host = bereq.http.host;
set beresp.http.X-Cache-Object-URL = bereq.url;

# Varnish derives grace from the origin Cache-Control
# stale-while-revalidate value emitted by UltraCache Automation. Keep
# remains a smaller, independent conditional-revalidation window.
# Default keep is set before the site-local section in the compiler envelope.

# Continue through mandatory envelope policy.
}

sub wvw_ultracache_deliver {
if (req.http.X-WV-Mode == "PASS") {
    set resp.http.X-Cache = "PASS";
} else if (obj.hits > 0) {
    set resp.http.X-Cache = "HIT";
    set resp.http.X-Cache-Hits = obj.hits;
} else {
    set resp.http.X-Cache = "MISS";
}

# Internal handshake headers are stored for VCL decisions only.
unset resp.http.X-UltraCache-ESI-Shared-Parent;
unset resp.http.X-UltraCache-ESI-Candidate;
unset resp.http.X-UltraCache-ESI-Opt-In;
unset resp.http.X-Cache-Object-Host;
unset resp.http.X-Cache-Object-URL;
}
