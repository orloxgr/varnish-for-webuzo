# Shared HTTP cache policy for Basic and UltraCache. GPL-3.0-or-later.
# This file is shipped unchanged in each panel integration. No remote imports.
# Integration contract: shared/CONTRACT.md. Requires std, header, blob and native params.

sub scp_init {
    unset req.http.X-SCP-Profile;
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
    if (req.http.Cookie ~ {"@@COOKIE_PATTERN_varnishPrivate@@"}) {
        set req.http.X-SCP-Cookie-Name = regsub(req.http.Cookie, {"^.*?@@COOKIE_PATTERN_varnishPrivate@@.*$"}, "\2");
        set req.http.X-SCP-Cookie-Role = "private";
        set req.http.X-SCP-Reason = "private-session-cookie"; return (pass);
    }
}

sub scp_cart_cookie_recv {
    if (req.http.Cookie ~ {"@@COOKIE_PATTERN_varnishCart@@"}) {
        set req.http.X-SCP-Cookie-Name = regsub(req.http.Cookie, {"^.*?@@COOKIE_PATTERN_varnishCart@@.*$"}, "\2");
        set req.http.X-SCP-Cookie-Role = "private-fragment";
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
    unset bereq.http.X-SCP-Fbp-Enabled;
    unset bereq.http.X-SCP-Fbp-Consent;
    unset bereq.http.X-SCP-Fbp-Domain;
    unset bereq.http.X-SCP-Fbp-Index;
    unset bereq.http.X-SCP-Fbp-New;
    unset bereq.http.X-SCP-Cookie-Name;
    unset bereq.http.X-SCP-Cookie-Role;
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
    call scp_cookie_delivery;
    if (req.http.X-SCP-Profile == "ultracache" &&
        (resp.http.X-UltraCache-ESI-Private-Count ~ "^[1-9][0-9]*$" ||
         (!resp.http.X-UltraCache-ESI-Private-Count && resp.http.X-UltraCache-ESI-Shared-Parent == "1"))) {
        # The object is a reusable ESI template, but this assembled delivery
        # contains private fragments. Only its downstream response is private.
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
}

sub scp_cookie_diagnostics {
    unset resp.http.X-Cache-Cookie-Names;
    unset resp.http.X-Cache-Cookie-Role;
    if (req.http.X-SCP-Cookie-Name) {
        set resp.http.X-Cache-Cookie-Names = req.http.X-SCP-Cookie-Name;
        set resp.http.X-Cache-Cookie-Role = req.http.X-SCP-Cookie-Role;
    } else if (resp.http.Vary ~ "(?i)(^|,)[[:blank:]]*Cookie[[:blank:]]*(,|$)" &&
               req.http.X-SCP-Vary-Cookie ~ {"^[[:blank:]]*[!#$%&'*+.^_`|~0-9A-Za-z-]+=[^;]*(;[[:blank:]]*[!#$%&'*+.^_`|~0-9A-Za-z-]+=[^;]*)*$"}) {
        # Validate pair syntax first: malformed Cookie text without '=' must not
        # be reflected as a supposed cookie name. Values are always removed.
        set resp.http.X-Cache-Cookie-Names = regsuball(req.http.X-SCP-Vary-Cookie, "=[^;]*", "");
        set resp.http.X-Cache-Cookie-Names = regsuball(resp.http.X-Cache-Cookie-Names, ";[[:blank:]]*", ", ");
        set resp.http.X-Cache-Cookie-Role = "public-variant";
    } else if (req.http.Cookie ~ {"@@COOKIE_PATTERN_varnishTrackingIgnore@@"}) {
        set resp.http.X-Cache-Cookie-Names = regsub(req.http.Cookie, {"^.*?@@COOKIE_PATTERN_varnishTrackingIgnore@@.*$"}, "\2");
        set resp.http.X-Cache-Cookie-Role = "tracking-ignored-for-variation";
    }
    if (resp.http.X-Cache-Cookie-Delivery && !resp.http.X-Cache-Cookie-Names) {
        set resp.http.X-Cache-Cookie-Names = "_fbp";
        set resp.http.X-Cache-Cookie-Role = "independent-cookie";
    }
    if (resp.http.X-Cache-Cookie-Names) {
        set resp.http.X-Cache-Cookie-Policy = "@@COOKIE_POLICY_VERSION@@";
    }
}

sub scp_private_delivery {
    set resp.http.Cache-Control = "private, no-store";
    set resp.http.Surrogate-Control = "no-store";
}

# Personal values are created in deliver, after lookup, and never written to a
# stored object or origin header. The original provider Set-Cookie always wins.
# Four-part _fbp is accepted by Meta's real ParamBuilder; it may add its own
# provenance appendix on a later origin request. We never invent that appendix.
sub scp_cookie_delivery {
    unset resp.http.X-Cache-Cookie-Delivery;
    unset resp.http.X-Cache-Cookie-Policy;
    if (req.http.X-SCP-Fbp-Enabled != "1" || req.esi_level > 0) { return; }
    set resp.http.X-Cache-Cookie-Policy = "@@COOKIE_POLICY_VERSION@@";
    if (header.get(resp.http.Set-Cookie, {"^[[:blank:]]*_fbp="})) {
        call scp_private_delivery;
        set resp.http.X-Cache-Cookie-Delivery = "fbp:origin-provider";
        return;
    }
    # An available application provider API owns complex consent decisions even
    # when the site selects Basic. Absence of this optional contract does not
    # make Basic depend on a WordPress plugin.
    if (resp.http.X-UltraCache-Cookie-Delivery == "provider-endpoint-fbp") {
        set resp.http.X-Cache-Cookie-Delivery = "fbp:provider-endpoint";
        return;
    }
    if (req.http.X-SCP-Fbp-Consent != "1") {
        set resp.http.X-Cache-Cookie-Delivery = "fbp:consent-not-granted";
        return;
    }
    @@FBP_PROVIDER_HOLD@@
    if (req.http.Cookie ~ {"(^|;[[:blank:]]*)_fbp=[^;[:blank:]]+"}) {
        set resp.http.X-Cache-Cookie-Delivery = "fbp:existing-preserved";
        return;
    }
    if (req.method != "GET" || resp.status != 200 ||
        resp.http.Content-Type !~ "(?i)^text/html([;[:blank:]]|$)" ||
        req.http.X-SCP-Pass == "1" || obj.uncacheable) {
        set resp.http.X-Cache-Cookie-Delivery = "fbp:origin-private-or-non-html";
        return;
    }
    if (req.http.X-SCP-Profile == "ultracache") {
        if (resp.http.X-UltraCache-Cookie-Policy != "@@COOKIE_POLICY_VERSION@@" ||
            resp.http.X-UltraCache-Cacheable != "1") {
            set resp.http.X-Cache-Cookie-Delivery = "fbp:origin-approval-required";
            return;
        }
        if (resp.http.X-UltraCache-Cookie-Delivery != "proxy-fbp") {
            set resp.http.X-Cache-Cookie-Delivery = "fbp:issuer-not-approved";
            return;
        }
    }
    set req.http.X-SCP-Fbp-New = "_fbp=fb." + req.http.X-SCP-Fbp-Index + "." +
        std.integer(real=std.real(time=now) * 1000) + "." +
        std.integer(real=std.random(0, 2147483647)) +
        "; Max-Age=@@FBP_MAX_AGE@@; Path=@@FBP_PATH@@; SameSite=@@FBP_SAME_SITE@@@@FBP_HTTP_ONLY@@";
    if (req.http.X-SCP-Fbp-Domain != "") {
        set req.http.X-SCP-Fbp-New = req.http.X-SCP-Fbp-New + "; Domain=" + req.http.X-SCP-Fbp-Domain;
    }
    @@FBP_SECURE_VCL@@
    header.append(resp.http.Set-Cookie, req.http.X-SCP-Fbp-New);
    # This delivery now contains one visitor's identifier. Keep the stored
    # public object reusable, but prevent downstream caches replaying its cookie.
    call scp_private_delivery;
    unset req.http.X-SCP-Fbp-New;
    set resp.http.X-Cache-Cookie-Delivery = "fbp:independent";
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
    unset req.http.X-SCP-Vary-ESI-Cookie;
    if (req.http.Cookie) {
        set req.http.X-SCP-Vary-Cookie = regsuball(req.http.Cookie, {"@@COOKIE_PATTERN_varnishTrackingIgnore@@[^;]*"}, "");
        set req.http.X-SCP-Vary-Cookie = regsuball(req.http.X-SCP-Vary-Cookie, "^[;[:blank:]]+|[;[:blank:]]+$", "");
        set req.http.X-SCP-Vary-Cookie = regsuball(req.http.X-SCP-Vary-Cookie, ";[[:blank:]]*", "; ");
        if (req.http.Cookie != "" && req.http.X-SCP-Vary-Cookie == "") { unset req.http.X-SCP-Vary-Cookie; }
        # Prepare a second lookup dimension without personal carrier values.
        # Only an approved public ESI parent can choose this dimension below.
        set req.http.X-SCP-Vary-ESI-Cookie = regsuball(req.http.X-SCP-Vary-Cookie,
            {"@@COOKIE_PATTERN_varnishCart@@[^;]*"}, "");
        set req.http.X-SCP-Vary-ESI-Cookie = regsuball(req.http.X-SCP-Vary-ESI-Cookie, "^[;[:blank:]]+|[;[:blank:]]+$", "");
        set req.http.X-SCP-Vary-ESI-Cookie = regsuball(req.http.X-SCP-Vary-ESI-Cookie, ";[[:blank:]]*", "; ");
        if (req.http.X-SCP-Vary-ESI-Cookie == "") { unset req.http.X-SCP-Vary-ESI-Cookie; }
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
        if (bereq.http.X-SCP-Profile == "ultracache" && beresp.do_esi &&
            beresp.http.X-UltraCache-ESI-Shared-Parent == "1") {
            set beresp.http.Vary = regsuball(beresp.http.Vary,
                "(?i)(^|,)[[:blank:]]*Cookie[[:blank:]]*(?=,|$)", "\1X-SCP-Vary-ESI-Cookie");
        } else {
            set beresp.http.Vary = regsuball(beresp.http.Vary,
                "(?i)(^|,)[[:blank:]]*Cookie[[:blank:]]*(?=,|$)", "\1X-SCP-Vary-Cookie");
        }
    }
    if (!beresp.uncacheable && beresp.http.Vary ~ "(?i)(^|,)[[:blank:]]*Accept-Language[[:blank:]]*(,|$)") {
        set beresp.http.Vary = regsuball(beresp.http.Vary,
            "(?i)(^|,)[[:blank:]]*Accept-Language[[:blank:]]*(?=,|$)", "\1X-SCP-Vary-Accept-Language");
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

# Keep raw Accept at the origin. Only an identified public stored HTML object
# can substitute its known image-capability dimensions for the raw header.
sub scp_normalize_quality {
    # Called only for complete simple negotiation lists: case-insensitive tokens
    # and valid q weights, with no media parameter values or quoted strings.
    # Preserve order and every different weight; normalize equivalent notation.
    set req.http.X-SCP-Normalize-Value = std.tolower(req.http.X-SCP-Normalize-Value);
    set req.http.X-SCP-Normalize-Value = regsuball(req.http.X-SCP-Normalize-Value,
        ";q=1([.]0*)?(?=,|$)", "");
    set req.http.X-SCP-Normalize-Value = regsuball(req.http.X-SCP-Normalize-Value,
        ";q=0([.]0*)?(?=,|$)", ";q=0");
    set req.http.X-SCP-Normalize-Value = regsuball(req.http.X-SCP-Normalize-Value,
        "(;q=0[.][0-9]*[1-9])0+(?=,|$)", "\1");
}

sub scp_representation_recv {
    std.collect(req.http.Accept);
    if (req.http.Accept) { set req.http.X-SCP-Vary-Accept = req.http.Accept; }
    if (req.http.Accept && req.http.Accept !~ {"["]"}) {
        set req.http.X-SCP-Vary-Accept = regsuball(req.http.X-SCP-Vary-Accept, "[[:blank:]]*,[[:blank:]]*", ",");
        set req.http.X-SCP-Vary-Accept = regsuball(req.http.X-SCP-Vary-Accept, "[[:blank:]]*;[[:blank:]]*", ";");
        set req.http.X-SCP-Vary-Accept = regsuball(req.http.X-SCP-Vary-Accept, "^[[:blank:]]+|[[:blank:]]+$", "");
        if (req.http.X-SCP-Vary-Accept ~ {"(?i)^[a-z0-9!#$%&'*+.^_`|~-]+/[a-z0-9!#$%&'*+.^_`|~-]+(;q=(0([.][0-9]{0,3})?|1([.]0{0,3})?))?(,[a-z0-9!#$%&'*+.^_`|~-]+/[a-z0-9!#$%&'*+.^_`|~-]+(;q=(0([.][0-9]{0,3})?|1([.]0{0,3})?))?)*$"}) {
            set req.http.X-SCP-Normalize-Value = req.http.X-SCP-Vary-Accept;
            call scp_normalize_quality;
            set req.http.X-SCP-Vary-Accept = req.http.X-SCP-Normalize-Value;
            unset req.http.X-SCP-Normalize-Value;
        }
    }
    std.collect(req.http.Accept-Language);
    if (req.http.Accept-Language) {
        set req.http.X-SCP-Vary-Accept-Language = req.http.Accept-Language;
        # Only simple language ranges and weights have case-insensitive values.
        # Other syntax remains an exact variant and still reaches the origin.
        set req.http.X-SCP-Normalize-Value = regsuball(req.http.Accept-Language, "[[:blank:]]*,[[:blank:]]*", ",");
        set req.http.X-SCP-Normalize-Value = regsuball(req.http.X-SCP-Normalize-Value, "[[:blank:]]*;[[:blank:]]*", ";");
        set req.http.X-SCP-Normalize-Value = regsuball(req.http.X-SCP-Normalize-Value, "^[[:blank:]]+|[[:blank:]]+$", "");
        if (req.http.X-SCP-Normalize-Value ~ "(?i)^([a-z]{1,8}(-[a-z0-9]{1,8})*|[*])(;q=(0([.][0-9]{0,3})?|1([.]0{0,3})?))?(,([a-z]{1,8}(-[a-z0-9]{1,8})*|[*])(;q=(0([.][0-9]{0,3})?|1([.]0{0,3})?))?)*$") {
            call scp_normalize_quality;
            set req.http.X-SCP-Vary-Accept-Language = req.http.X-SCP-Normalize-Value;
        }
        unset req.http.X-SCP-Normalize-Value;
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
    # Apache static files and actual page-cache HITs identify stored HTML,
    # including ESI parents. A new dynamic STORE is not this contract.
    if (bereq.http.X-SCP-HTML-Accept && !beresp.uncacheable &&
        beresp.status == 200 && beresp.http.Content-Type ~ "(?i)^text/html(;|$)" &&
        (beresp.http.X-Ultra-Cache-Source == "apache-static" || beresp.http.X-UltraCache-Source == "apache-static" ||
         beresp.http.X-Ultra-Cache == "HIT") &&
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
