# Shared cookie-delivery policy. GPL-3.0-or-later.

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
