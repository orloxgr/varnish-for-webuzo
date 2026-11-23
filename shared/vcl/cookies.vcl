# Shared cookies policy. GPL-3.0-or-later.

sub scp_admin_cookie_rules {
    @@COOKIE_ADMIN_RULES@@
}

# Unclassified UltraCache wire markers are protocol state, not origin HTML
# variation. Explicit rules have already consumed their pairs, so this cannot
# erase a saved Variant or bypass a saved Private choice.
sub scp_protocol_cookie_remainder {
    if (req.http.X-SCP-Profile == "ultracache") {
        set req.http.X-SCP-Admin-Remaining = regsuball(req.http.X-SCP-Admin-Remaining,
            "(^|;[[:blank:]]*)(esi_session|ultracache_esi_optin)=[^;]*", "");
    }
}

sub scp_cookie_variation {
    # The origin still receives the complete Cookie header. Only an explicit
    # Vary: Cookie is keyed by the resolved functional remainder.
    # Only resolved Shared choices omit values; there is no second name list.
    if (req.http.X-SCP-Admin-Reuse == "1") {
        # Selection may replace Admin-Variant with an origin-approved key.
        # Restore the original classification before the current selection.
        cookie_handoff.cookie_classification_restore();
    } else {
        call scp_admin_cookie_rules;
        if (req.http.X-SCP-Profile == "ultracache" && req.esi_level == 0 &&
            req.http.Cookie && req.http.X-SCP-Admin-Applied == "1") {
            cookie_handoff.cookie_classification_snapshot();
        }
    }
    unset req.http.X-SCP-Admin-Reuse;
    if (req.http.Cookie) {
        if (req.http.X-SCP-Admin-Filtered) {
            cookie_handoff.cookie_variation_headers(req.http.X-SCP-Admin-Filtered, false);
        } else if (req.http.X-SCP-Admin-Variant) {
            cookie_handoff.cookie_variation_headers(req.http.X-SCP-Admin-Variant, false);
        } else if (req.http.X-SCP-Admin-Applied == "1") {
            cookie_handoff.cookie_variation_headers("", false);
        } else {
            cookie_handoff.cookie_variation_headers(req.http.Cookie, true);
        }
    } else {
        cookie_handoff.cookie_variation_headers("", false);
    }
}
sub scp_cookie_diagnostics {
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
    # Select the same diagnostic source; materialize names only, not values.
    if (req.http.X-SCP-Cookie-Name &&
        (req.http.X-SCP-Cookie-Role == "private" || req.http.X-SCP-Cookie-Role == "private-fragment" ||
         req.http.X-SCP-Cookie-Role == "site-bypass" || req.http.X-SCP-Cookie-Role == "provider-consent")) {
        set resp.http.X-Cache-Cookie-Names = req.http.X-SCP-Cookie-Name;
        set resp.http.X-Cache-Cookie-Role = req.http.X-SCP-Cookie-Role;
    } else {
        if (resp.http.Vary ~ "(?i)(^|,)[[:blank:]]*Cookie[[:blank:]]*(,|$)" &&
            !(req.http.X-SCP-Cookie-Contract ~ "^[0-9a-f]{64}$" &&
              resp.http.X-UltraCache-Cookie-Settings == req.http.X-SCP-Cookie-Contract &&
              resp.http.X-UltraCache-Cookie-Vary == "policy-only")) {
            if (req.http.X-SCP-Cookie-Contract ~ "^[0-9a-f]{64}$" && resp.http.X-UltraCache-Cookie-Settings ~ "^[0-9a-f]{64}$" &&
                resp.http.X-UltraCache-Cookie-Settings != req.http.X-SCP-Cookie-Contract) {
                set resp.http.X-Cache-Cookie-Names = cookie_handoff.cookie_diagnostic_names(req.http.Cookie, req.http.Cookie == req.http.X-SCP-Admin-Variant || req.http.Cookie ~ {"^[[:blank:]]*[!#$%&'*+.^_`|~0-9A-Za-z-]+=[^;]*(;[[:blank:]]*[!#$%&'*+.^_`|~0-9A-Za-z-]+=[^;]*)*$"});
            } else { set resp.http.X-Cache-Cookie-Names = cookie_handoff.cookie_diagnostic_names(req.http.X-SCP-Vary-Cookie, req.http.X-SCP-Vary-Cookie == req.http.X-SCP-Admin-Variant || req.http.X-SCP-Vary-Cookie ~ {"^[[:blank:]]*[!#$%&'*+.^_`|~0-9A-Za-z-]+=[^;]*(;[[:blank:]]*[!#$%&'*+.^_`|~0-9A-Za-z-]+=[^;]*)*$"}); }
        } else { set resp.http.X-Cache-Cookie-Names = cookie_handoff.cookie_diagnostic_names(req.http.X-SCP-Admin-Variant, req.http.X-SCP-Admin-Variant == req.http.X-SCP-Admin-Variant || req.http.X-SCP-Admin-Variant ~ {"^[[:blank:]]*[!#$%&'*+.^_`|~0-9A-Za-z-]+=[^;]*(;[[:blank:]]*[!#$%&'*+.^_`|~0-9A-Za-z-]+=[^;]*)*$"}); }
        if (resp.http.X-Cache-Cookie-Names) {
            set resp.http.X-Cache-Cookie-Role = "public-variant";
        } else if (req.http.X-SCP-Cookie-Name) {
            set resp.http.X-Cache-Cookie-Names = req.http.X-SCP-Cookie-Name;
            set resp.http.X-Cache-Cookie-Role = req.http.X-SCP-Cookie-Role;
        } else { unset resp.http.X-Cache-Cookie-Names; }
    }
    if (resp.http.X-Cache-Cookie-Names) {
        set resp.http.X-Cache-Cookie-Policy = "@@COOKIE_POLICY_VERSION@@";
    }
    unset req.http.X-SCP-Admin-Matched;
}
