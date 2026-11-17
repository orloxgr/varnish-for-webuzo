# Shared ultracache-esi policy. GPL-3.0-or-later.

sub scp_ultracache_recv {
# Private/session ESI transport.
if (req.esi_level == 0) {
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
    if (
        req.http.X-SCP-Query ~ "(?i)(^|&)esi_scope=private(?:&|$)" &&
        req.http.X-SCP-Query ~ "(?i)(^|&)(ultracache_esi|ultracache_esi_probe_private_fragment)="
    ) {
        set req.http.X-ESI-Private-Request = "1";
        set req.http.X-ESI-Request-Level = "1";
        set req.http.X-SCP-Reason = "private-esi-fragment";

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

# An explicitly opted-in cart/session visitor may reuse a warmed public async
# parent approved by the origin. Its private cart is fetched separately. A
# private cold miss still requires the existing ESI backend handshake.
sub scp_ultracache_hit {
# WooCommerce ESI candidates may reuse only objects explicitly approved
# by UltraCache. Anonymous/non-approved objects are bypassed so a normal
# WooCommerce site can never receive an empty shared cart parent.
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
sub scp_ultracache_backend_response {
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

# Keep raw Accept at the origin. Only an identified public stored HTML object
# can substitute its known image-capability dimensions for the raw header.
