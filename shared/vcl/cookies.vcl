# Shared cookies policy. GPL-3.0-or-later.

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
sub scp_admin_cookie_rules {
    @@COOKIE_ADMIN_RULES@@
}

sub scp_cookie_variation {
    # The origin still receives the complete Cookie header. Only an explicit
    # Vary: Cookie is keyed by the functional remainder, without analytics IDs.
    # Unknown/consent/referral/language cookies are retained, never whitelisted.
    unset req.http.X-SCP-Vary-Cookie;
    unset req.http.X-SCP-Vary-ESI-Cookie;
    call scp_admin_cookie_rules;
    if (req.http.Cookie) {
        if (req.http.X-SCP-Admin-Filtered) {
            set req.http.X-SCP-Vary-Cookie = req.http.X-SCP-Admin-Filtered;
        } else if (req.http.X-SCP-Admin-Rule) {
            unset req.http.X-SCP-Vary-Cookie;
        } else {
            set req.http.X-SCP-Vary-Cookie = req.http.Cookie;
        }
        set req.http.X-SCP-Vary-Cookie = regsuball(req.http.X-SCP-Vary-Cookie, {"@@COOKIE_PATTERN_varnishTrackingIgnore@@[^;]*"}, "");
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
sub scp_cookie_diagnostics {
    # A shared cart-carrier selector never makes its personal ESI fragments
    # shared. Retain the core privacy cause after the table's key projection.
    if (req.http.X-UltraCache-ESI-Candidate == "1" && req.http.X-SCP-Admin-Action != "private" &&
        req.http.Cookie ~ {"@@COOKIE_PATTERN_varnishCart@@"}) {
        set req.http.X-SCP-Cookie-Name = regsub(req.http.Cookie, {"^.*?@@COOKIE_PATTERN_varnishCart@@.*$"}, "\2");
        set req.http.X-SCP-Cookie-Role = "private-fragment";
    }
    unset resp.http.X-Cache-Cookie-Rule;
    unset resp.http.X-Cache-Cookie-Scope;
    unset resp.http.X-Cache-Cookie-Action;
    if (req.http.X-SCP-Admin-Rule) {
        set resp.http.X-Cache-Cookie-Rule = req.http.X-SCP-Admin-Rule;
        set resp.http.X-Cache-Cookie-Scope = req.http.X-SCP-Admin-Scope;
        set resp.http.X-Cache-Cookie-Action = req.http.X-SCP-Admin-Action;
    }
    unset resp.http.X-Cache-Cookie-Names;
    unset resp.http.X-Cache-Cookie-Role;
    # Describe the dimension actually used by this stored response. A matching
    # application-owned policy hashes selected variants only; a newer origin
    # policy retains its complete Cookie Vary; ordinary Vary uses our remainder.
    unset req.http.X-SCP-Admin-Matched;
    if (resp.http.Vary ~ "(?i)(^|,)[[:blank:]]*Cookie[[:blank:]]*(,|$)" &&
        !(req.http.X-SCP-Cookie-Contract ~ "^[0-9a-f]{64}$" &&
          resp.http.X-UltraCache-Cookie-Settings == req.http.X-SCP-Cookie-Contract &&
          resp.http.X-UltraCache-Cookie-Vary == "policy-only")) {
        if (req.http.X-SCP-Cookie-Contract ~ "^[0-9a-f]{64}$" && resp.http.X-UltraCache-Cookie-Settings ~ "^[0-9a-f]{64}$" &&
            resp.http.X-UltraCache-Cookie-Settings != req.http.X-SCP-Cookie-Contract) {
            set req.http.X-SCP-Admin-Matched = req.http.Cookie;
        } else { set req.http.X-SCP-Admin-Matched = req.http.X-SCP-Vary-Cookie; }
    } else { set req.http.X-SCP-Admin-Matched = req.http.X-SCP-Admin-Variant; }
    if (req.http.X-SCP-Cookie-Name &&
        (req.http.X-SCP-Cookie-Role == "private" || req.http.X-SCP-Cookie-Role == "private-fragment" ||
         req.http.X-SCP-Cookie-Role == "site-bypass" || req.http.X-SCP-Cookie-Role == "provider-consent")) {
        set resp.http.X-Cache-Cookie-Names = req.http.X-SCP-Cookie-Name;
        set resp.http.X-Cache-Cookie-Role = req.http.X-SCP-Cookie-Role;
    } else if (req.http.X-SCP-Admin-Matched &&
               (req.http.X-SCP-Admin-Matched == req.http.X-SCP-Admin-Variant ||
                req.http.X-SCP-Admin-Matched ~ {"^[[:blank:]]*[!#$%&'*+.^_`|~0-9A-Za-z-]+=[^;]*(;[[:blank:]]*[!#$%&'*+.^_`|~0-9A-Za-z-]+=[^;]*)*$"})) {
        # Validate pair syntax first: malformed Cookie text without '=' must not
        # be reflected as a supposed cookie name. Values are always removed.
        set resp.http.X-Cache-Cookie-Names = regsuball(req.http.X-SCP-Admin-Matched, "=[^;]*", "");
        set resp.http.X-Cache-Cookie-Names = regsuball(resp.http.X-Cache-Cookie-Names, ";[[:blank:]]*", ", ");
        set resp.http.X-Cache-Cookie-Role = "public-variant";
    } else if (req.http.X-SCP-Cookie-Name) {
        set resp.http.X-Cache-Cookie-Names = req.http.X-SCP-Cookie-Name;
        set resp.http.X-Cache-Cookie-Role = req.http.X-SCP-Cookie-Role;
    } else if (req.http.Cookie ~ {"@@COOKIE_PATTERN_varnishTrackingIgnore@@"}) {
        set resp.http.X-Cache-Cookie-Names = regsub(req.http.Cookie, {"^.*?@@COOKIE_PATTERN_varnishTrackingIgnore@@.*$"}, "\2");
        set resp.http.X-Cache-Cookie-Role = "tracking-ignored-for-variation";
    }
    if (resp.http.X-Cache-Cookie-Names) {
        set resp.http.X-Cache-Cookie-Policy = "@@COOKIE_POLICY_VERSION@@";
    }
    unset req.http.X-SCP-Admin-Matched;
}
