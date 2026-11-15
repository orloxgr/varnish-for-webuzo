# Shared HTTP cache policy for Basic and UltraCache. GPL-3.0-or-later.
# This file is shipped unchanged in each panel integration. No remote imports.
# Integration contract: shared/CONTRACT.md. Requires std and native Varnish params.

sub scp_init {
    unset req.http.X-SCP-Profile;
    unset req.http.X-SCP-Reason;
    unset req.http.X-SCP-Pass;
    unset req.http.X-SCP-Key-URL;
    unset req.http.X-SCP-Query;
    unset req.http.X-SCP-Key-Path;
    unset req.http.X-SCP-Key-Query;
    unset req.http.X-SCP-Vary-Cookie;
    unset req.http.X-SCP-Vary-Accept;
    unset req.http.X-SCP-HTML-Accept;
    unset req.http.X-SCP-Accept-Check;
    unset req.http.X-ESI-Private-Request;
    unset req.http.X-ESI-Request-Level;
    unset req.http.X-ESI-Original-Cookie;
    unset req.http.X-UltraCache-ESI-Candidate;
    unset req.http.X-UltraCache-ESI-Cookie-Check;
    unset req.http.X-UltraCache-ESI-Opt-In;
    unset req.http.X-UltraCache-ESI-Shared-Parent;
}

# Normalize a COPY for hashing/invalidation. Never change req.url.
sub scp_key {
    set req.http.X-SCP-Key-URL = req.url;
    if (req.url ~ "[?]") {
        set req.http.X-SCP-Key-Path = regsub(req.url, "[?].*$", "");
        set req.http.X-SCP-Key-Query = regsub(req.url, "^[^?]*[?]", "");
        if (req.http.X-SCP-Key-Query ~ "(?i)(^|&)(utm_[a-z0-9_]+|gclid|dclid|fbclid|msclkid|gbraid|wbraid|igshid)=") {
            set req.http.X-SCP-Key-Query = regsuball(req.http.X-SCP-Key-Query,
                "(?i)(^|&)(utm_[a-z0-9_]+|gclid|dclid|fbclid|msclkid|gbraid|wbraid|igshid)=[^&]*", "\1");
            set req.http.X-SCP-Key-Query = regsuball(req.http.X-SCP-Key-Query, "&&+", "&");
            set req.http.X-SCP-Key-Query = regsuball(req.http.X-SCP-Key-Query, "^&+|&+$", "");
            set req.http.X-SCP-Key-URL = req.http.X-SCP-Key-Path;
            if (req.http.X-SCP-Key-Query != "") {
                set req.http.X-SCP-Key-URL = req.http.X-SCP-Key-URL + "?" + req.http.X-SCP-Key-Query;
            }
        }
    }
    unset req.http.X-SCP-Key-Path;
    unset req.http.X-SCP-Key-Query;
}

sub scp_recv {
    std.collect(req.http.Cookie, "; ");
    if (req.url ~ "[?]") { set req.http.X-SCP-Query = regsub(req.url, "^[^?]*[?]", ""); }
    if (req.http.X-SCP-Profile == "ultracache") { call scp_ultracache_recv; }
    call scp_common_recv;
}

sub scp_private_cookie_recv {
    if (req.http.Cookie ~ {"(^|;[[:blank:]]*)(wordpress_logged_in_[^=;[:blank:]]*|wordpress_sec_[^=;[:blank:]]*|wp\-postpass_[^=;[:blank:]]*|comment_author_[^=;[:blank:]]*|PHPSESSID|woocommerce_recently_viewed|yith_wcwl_session_[^=;[:blank:]]*|yith_woocompare_[^=;[:blank:]]*)="}) {
        set req.http.X-SCP-Reason = "private-session-cookie"; return (pass);
    }
}

sub scp_cart_cookie_recv {
    if (req.http.Cookie ~ {"(^|;[[:blank:]]*)(woocommerce_items_in_cart|woocommerce_cart_hash|wp_woocommerce_session_[^=;[:blank:]]*)="}) {
        if (req.http.X-SCP-Profile == "ultracache" && req.http.X-UltraCache-ESI-Opt-In == "1") {
            set req.http.X-UltraCache-ESI-Candidate = "1";
        } else { set req.http.X-SCP-Reason = "woocommerce-session-cookie"; return (pass); }
    }
}

sub scp_pass { set req.http.X-SCP-Pass = "1"; }

sub scp_hit {
    if (req.http.X-SCP-Profile == "ultracache") { call scp_ultracache_hit; }
}

sub scp_backend_fetch {
    unset bereq.http.Surrogate-Capability;
    if (bereq.http.X-SCP-Profile == "ultracache") { call scp_ultracache_backend_fetch; }
}

sub scp_mark_uncacheable {
    set beresp.ttl = param.uncacheable_ttl;
    set beresp.uncacheable = true;
}

sub scp_backend_response {
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
    call scp_response_privacy;
    if (bereq.http.X-SCP-Profile == "ultracache") { call scp_ultracache_backend_response; }
    # Static and dynamic responses both retain functional Cookie variation.
    # Only known analytics IDs are omitted from the internal Cookie key.
    call scp_representation_response;
    call scp_response_variants;
}

sub scp_deliver {
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
    unset resp.http.X-Cache-Hits;
    if (resp.http.X-Cache == "HIT") { set resp.http.X-Cache-Hits = obj.hits; }
    if (resp.http.X-SCP-Client-Vary) { set resp.http.Vary = resp.http.X-SCP-Client-Vary; }
    set resp.http.Vary = regsuball(resp.http.Vary,
        "(?i)(^|,)[[:blank:]]*X-SCP-Vary-Cookie[[:blank:]]*(?=,|$)", "\1Cookie");
    set resp.http.Vary = regsuball(resp.http.Vary,
        "(?i)(^|,)[[:blank:]]*X-SCP-Vary-Accept[[:blank:]]*(?=,|$)", "\1Accept");
    unset resp.http.X-SCP-Vary-Accept;
    unset resp.http.X-SCP-Client-Vary;
    unset resp.http.X-SCP-Reason;
    unset resp.http.X-SCP-Key-URL;
    unset resp.http.X-SCP-Profile;
    unset resp.http.X-SCP-Vary-Cookie;
    unset resp.http.X-SCP-HTML-Accept;
    unset resp.http.X-UltraCache-ESI-Shared-Parent;
    unset resp.http.X-UltraCache-ESI-Candidate;
    unset resp.http.X-UltraCache-ESI-Opt-In;
}

# Basic HTTP/WordPress/WooCommerce policy, also used by UltraCache.
# A public read is not private merely because it is search, REST or AJAX.
sub scp_common_recv {
    if (req.http.Authorization) {
        set req.http.X-SCP-Reason = "authorization";
        return (pass);
    }
    if (req.http.Upgrade) {
        set req.http.X-SCP-Reason = "protocol-upgrade";
        return (pass);
    }
    if (req.method != "GET" && req.method != "HEAD") {
        set req.http.X-SCP-Reason = "request-method";
        return (pass);
    }
    if (req.url ~ "^/[.]well-known/(acme-challenge|pki-validation)/") {
        set req.http.X-SCP-Reason = "certificate-validation";
        return (pass);
    }
    if (req.http.X-WP-Nonce || req.http.Cart-Token || req.http.Nonce ||
        req.http.X-WC-Store-API-Nonce ||
        req.http.X-SCP-Query ~ "(?i)(^|&)(_wpnonce|_ajax_nonce|consumer_key|consumer_secret)=") {
        set req.http.X-SCP-Reason = "application-credentials";
        return (pass);
    }
    if (req.url ~ "(?i)^/([^?]*/)?(wp-admin(?:/|[?]|$)|wp-login[.]php(?:[?]|$)|xmlrpc[.]php(?:[?]|$)|wp-cron[.]php(?:[?]|$)|wp-comments-post[.]php(?:[?]|$))") {
        set req.http.X-SCP-Reason = "wordpress-private-route";
        return (pass);
    }
    if (req.http.X-SCP-Query ~ "(?i)(^|&)(preview|preview_id|preview_nonce|customize_changeset_uuid|elementor-preview|et_fb|vc_editable|nocache)=" ||
        req.http.X-SCP-Query ~ "(?i)(^|&)context=edit(&|$)") {
        set req.http.X-SCP-Reason = "preview-or-private-action";
        return (pass);
    }
    if (req.url ~ "(?i)^/([^?]*/)?(cart|checkout|my-account|wc-api)(/|[?]|$)" ||
        req.http.X-SCP-Query ~ "(?i)(^|&)(add-to-cart|remove_item|undo_item|wc-ajax|wc-api|apply_coupon|remove_coupon|order_again|cancel_order|pay_for_order|download_file)=" ||
        req.http.X-SCP-Query ~ "(?i)(^|&)key=wc_order_") {
        set req.http.X-SCP-Reason = "woocommerce-private-action";
        return (pass);
    }
    # Store API reads can carry cart/notices state even without mutation.
    # Public products and other REST reads retain normal HTTP caching.
    if (req.url ~ "(?i)^/([^?]*/)?wp-json/(wc/store/v[0-9]+/(cart|checkout|order)|wp/v[0-9]+/(users/me|settings))(/|[?]|$)" ||
        req.http.X-SCP-Query ~ "(?i)(^|&)rest_route=(/|%2f)(wc(/|%2f)store(/|%2f)v[0-9]+(/|%2f)(cart|checkout|order)|wp(/|%2f)v[0-9]+(/|%2f)(users(/|%2f)me|settings))(/|%2f|&|$)") {
        set req.http.X-SCP-Reason = "private-rest-context";
        return (pass);
    }
    call scp_private_cookie_recv;
    call scp_cart_cookie_recv;

    call scp_representation_recv;
    call scp_cookie_variation;
}

sub scp_cookie_variation {
    # The origin still receives the complete Cookie header. Only an explicit
    # Vary: Cookie is keyed by the functional remainder, without analytics IDs.
    # Unknown/consent/referral/language cookies are retained, never whitelisted.
    unset req.http.X-SCP-Vary-Cookie;
    if (req.http.Cookie) {
        set req.http.X-SCP-Vary-Cookie = regsuball(req.http.Cookie, {"(^|;[[:blank:]]*)(_ga|_ga_[^=;[:blank:]]*|_gid|_gat|_gat_[^=;[:blank:]]*|_gcl_au|_fbp|_fbc|__utma|__utmb|__utmc|__utmt|__utmv|__utmz|sbjs_migrations|sbjs_current|sbjs_current_add|sbjs_first|sbjs_first_add|sbjs_udata|sbjs_session)=[^;]*"}, "");
        set req.http.X-SCP-Vary-Cookie = regsuball(req.http.X-SCP-Vary-Cookie, "^[;[:blank:]]+|[;[:blank:]]+$", "");
        set req.http.X-SCP-Vary-Cookie = regsuball(req.http.X-SCP-Vary-Cookie, ";[[:blank:]]*", "; ");
        if (req.http.Cookie != "" && req.http.X-SCP-Vary-Cookie == "") { unset req.http.X-SCP-Vary-Cookie; }
    }
}

sub scp_response_privacy {
    # The reason is stored only on uncacheable decisions; no private body is
    # retained. Mandatory origin privacy cannot be overridden by local TTLs.
    if (beresp.http.Surrogate-Control ~ "(?i)(^|[[:space:],])(no-store|private)([[:space:],=]|$)") {
        set beresp.http.X-SCP-Reason = "origin-surrogate-control";
        # ESI can consume Surrogate-Control. Preserve its privacy decision for
        # downstream caches as well as this Varnish instance.
        set beresp.http.Cache-Control = "private, no-store";
    } else if (beresp.http.Set-Cookie) {
        set beresp.http.X-SCP-Reason = "origin-set-cookie";
    } else if (beresp.http.Cache-Control ~ "(?i)(^|[[:space:],])(private|no-cache|no-store)([[:space:],=]|$)" ||
               beresp.http.Pragma ~ "(?i)(^|[[:space:],])no-cache([[:space:],=]|$)") {
        set beresp.http.X-SCP-Reason = "origin-cache-policy";
    } else if (beresp.http.Vary ~ "(^|,)[[:blank:]]*[*][[:blank:]]*(,|$)") {
        set beresp.http.X-SCP-Reason = "origin-vary-star";
    } else if (beresp.status < 200 || beresp.status == 206 || beresp.status == 304) {
        set beresp.http.X-SCP-Reason = "origin-status";
    } else if (beresp.ttl <= 0s) {
        set beresp.http.X-SCP-Reason = "origin-no-freshness";
    }
    if (beresp.http.X-SCP-Reason) { call scp_mark_uncacheable; }
}

sub scp_response_variants {
    if (!beresp.uncacheable && beresp.http.Vary ~ "(?i)(^|,)[[:blank:]]*Accept[[:blank:]]*(,|$)") {
        set beresp.http.Vary = regsuball(beresp.http.Vary,
            "(?i)(^|,)[[:blank:]]*Accept[[:blank:]]*(?=,|$)", "\1X-SCP-Vary-Accept");
    }
    if (!beresp.uncacheable && beresp.http.Vary ~ "(?i)(^|,)[[:blank:]]*Cookie[[:blank:]]*(,|$)") {
        set beresp.http.Vary = regsuball(beresp.http.Vary,
            "(?i)(^|,)[[:blank:]]*Cookie[[:blank:]]*(?=,|$)", "\1X-SCP-Vary-Cookie");
    }
}

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

# Keep raw Accept at the origin. Only an identified public static HTML object
# can substitute its known image-capability dimensions for the raw header.
sub scp_representation_recv {
    std.collect(req.http.Accept);
    if (req.http.Accept) { set req.http.X-SCP-Vary-Accept = req.http.Accept; }
    if (req.http.Accept && req.http.Accept !~ {"["]"}) {
        set req.http.X-SCP-Vary-Accept = regsuball(req.http.X-SCP-Vary-Accept, "[[:blank:]]*,[[:blank:]]*", ",");
        set req.http.X-SCP-Vary-Accept = regsuball(req.http.X-SCP-Vary-Accept, "[[:blank:]]*;[[:blank:]]*", ";");
        set req.http.X-SCP-Vary-Accept = regsuball(req.http.X-SCP-Vary-Accept, "^[[:blank:]]+|[[:blank:]]+$", "");
    }
    if (req.http.Accept ~ "(?i)^[[:blank:]]*text/html[[:blank:]]*(;[[:blank:]]*q[[:blank:]]*=[[:blank:]]*1([.]0*)?[[:blank:]]*)?(,|$)") {
        # Match the origin's explicit codec support and q=0 rules. Unusual
        # media parameters retain raw Vary matching rather than being guessed.
        set req.http.X-SCP-Accept-Check = regsuball(req.http.Accept,
            "(?i)(^|,)[[:blank:]]*image/(avif|webp)[[:blank:]]*(;[[:blank:]]*q[[:blank:]]*=[[:blank:]]*(0([.][0-9]+)?|1([.]0+)?)[[:blank:]]*)?(?=,|$)", "\1");
        if (req.http.X-SCP-Accept-Check ~ "(?i)(^|,)[[:blank:]]*image/(avif|webp)(;|[[:blank:]]|,|$)") {
            unset req.http.X-SCP-Accept-Check;
            return;
        }
        set req.http.X-SCP-HTML-Accept = "html";
        if (req.http.Accept ~ "(?i)(^|,)[[:blank:]]*image/avif[[:blank:]]*(;|,|$)" &&
            req.http.Accept !~ "(?i)(^|,)[[:blank:]]*image/avif[[:blank:]]*;[^,]*q[[:blank:]]*=[[:blank:]]*0([.]0*)?[[:blank:]]*(;|,|$)") {
            set req.http.X-SCP-HTML-Accept = req.http.X-SCP-HTML-Accept + ";avif";
        }
        if (req.http.Accept ~ "(?i)(^|,)[[:blank:]]*image/webp[[:blank:]]*(;|,|$)" &&
            req.http.Accept !~ "(?i)(^|,)[[:blank:]]*image/webp[[:blank:]]*;[^,]*q[[:blank:]]*=[[:blank:]]*0([.]0*)?[[:blank:]]*(;|,|$)") {
            set req.http.X-SCP-HTML-Accept = req.http.X-SCP-HTML-Accept + ";webp";
        }
    }
    unset req.http.X-SCP-Accept-Check;
}

sub scp_representation_response {
    std.collect(beresp.http.Vary);
    # This contract identifies the application's prebuilt anonymous HTML files,
    # not arbitrary dynamic HTML that merely declares itself public/cacheable.
    if (bereq.http.X-SCP-HTML-Accept && !beresp.uncacheable &&
        beresp.status == 200 && beresp.http.Content-Type ~ "(?i)^text/html(;|$)" &&
        (beresp.http.X-Ultra-Cache-Source == "apache-static" || beresp.http.X-UltraCache-Source == "apache-static") &&
        beresp.http.X-UltraCache-Cacheable == "1" &&
        beresp.http.X-UltraCache-Variant ~ "^(orig|webp|avif)$" &&
        (beresp.http.X-UltraCache-Variant != "avif" || bereq.http.X-SCP-HTML-Accept ~ ";avif") &&
        (beresp.http.X-UltraCache-Variant != "webp" || bereq.http.X-SCP-HTML-Accept ~ ";webp") &&
        beresp.http.Cache-Control ~ "(?i)(^|,)[[:blank:]]*public([[:blank:]]*,|[[:blank:]]*$)" &&
        !beresp.http.Set-Cookie &&
        beresp.http.Cache-Control !~ "(?i)(private|no-cache|no-store)" &&
        beresp.http.Vary !~ "(^|,)[[:blank:]]*[*][[:blank:]]*(,|$)") {
        if (beresp.http.Vary ~ "(?i)(^|,)[[:blank:]]*Accept[[:blank:]]*(,|$)") {
            set beresp.http.X-SCP-Client-Vary = beresp.http.Vary;
            set beresp.http.Vary = regsuball(beresp.http.Vary,
                "(?i)(^|,)[[:blank:]]*Accept[[:blank:]]*(?=,|$)", "\1X-SCP-HTML-Accept");
            set beresp.http.Vary = regsuball(beresp.http.Vary, ",[[:blank:]]*,", ",");
            set beresp.http.Vary = regsuball(beresp.http.Vary, "^[[:blank:],]+|[[:blank:],]+$", "");
            if (beresp.http.Vary == "") { unset beresp.http.Vary; }
        }
    }
}
