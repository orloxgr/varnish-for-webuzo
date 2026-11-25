# Shared representations policy. GPL-3.0-or-later.

sub scp_cookie_hash {
    if (req.http.X-SCP-Profile == "ultracache") {
        hash_data("native-public-selection-epoch");
        hash_data(cookie_handoff.selection_epoch());
        if (cookie_handoff.guest_key()) {
            hash_data("complete-guest-publication-v1");
            hash_data(cookie_handoff.guest_key());
        }
        if (cookie_handoff.selection_manifest() && !cookie_handoff.selection_cold()) {
            hash_data("authenticated-public-publication");
            hash_data(cookie_handoff.selection_manifest());
        }
    }
    if (req.http.X-SCP-Admin-Variant) {
        hash_data("explicit-cookie-variant");
        if (req.http.X-SCP-Profile == "ultracache" && cookie_handoff.selection_variant()) {
            hash_data(cookie_handoff.selection_variant());
        } else {
            hash_data(req.http.X-SCP-Admin-Variant);
        }
    }
}

sub scp_key {
    set req.http.X-SCP-Key-URL = req.url;
    call scp_normalize_key_copy;
}
# Both cache lookup and the private issuer use this one existing tracking rule.
# Only the supplied native-owned copy changes; req.url is never rewritten.
sub scp_normalize_key_copy {
    if (req.http.X-SCP-Key-URL ~ "[?]") {
        set req.http.X-SCP-Key-Path = regsub(req.http.X-SCP-Key-URL, "[?].*$", "");
        set req.http.X-SCP-Key-Query = regsub(req.http.X-SCP-Key-URL, "^[^?]*[?]", "");
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
sub scp_response_variants {
    std.collect(beresp.http.Vary);
    if (!beresp.uncacheable && beresp.http.Vary ~ "(?i)(^|,)[[:blank:]]*Accept[[:blank:]]*(,|$)") {
        set beresp.http.Vary = regsuball(beresp.http.Vary,
            "(?i)(^|,)[[:blank:]]*Accept[[:blank:]]*(?=,|$)", "\1X-SCP-Vary-Accept");
    }
    if (!beresp.uncacheable && beresp.http.Vary ~ "(?i)(^|,)[[:blank:]]*Cookie[[:blank:]]*(,|$)") {
        if (bereq.http.X-SCP-Cookie-Contract ~ "^[0-9a-f]{64}$" &&
            beresp.http.X-UltraCache-Cookie-Settings ~ "^[0-9a-f]{64}$" &&
            beresp.http.X-UltraCache-Cookie-Settings != bereq.http.X-SCP-Cookie-Contract &&
            !cookie_handoff.selection_local()) {
            # The application has a different effective policy. Preserve its
            # complete Cookie Vary; the old Shared/tracking projection cannot
            # describe the HTML selected by the application's newer policy.
            # Standard native Vary still caches each actual representation.
        } else if (cookie_handoff.selection_local() ||
            (bereq.http.X-SCP-Cookie-Contract ~ "^[0-9a-f]{64}$" &&
            beresp.http.X-UltraCache-Cookie-Settings == bereq.http.X-SCP-Cookie-Contract &&
            beresp.http.X-UltraCache-Cookie-Vary == "policy-only")) {
            # Only our explicitly connected matching policy owns this Vary.
            # Public cookie variants are already in scp_cookie_hash. Do not
            # turn unrelated automatic/tracking cookies into new variants.
            # Retain the origin's downstream Vary even for Shared-only rules,
            # which do not independently add a public cookie hash dimension.
            if (!beresp.http.X-SCP-Client-Vary) {
                set beresp.http.X-SCP-Client-Vary = beresp.http.Vary;
            }
            set beresp.http.Vary = regsuball(beresp.http.Vary,
                "(?i)(^|,)[[:blank:]]*Cookie[[:blank:]]*(?=,|$)", "");
            set beresp.http.Vary = regsuball(beresp.http.Vary, ",[[:blank:]]*,", ",");
            set beresp.http.Vary = regsuball(beresp.http.Vary, "^[[:blank:],]+|[[:blank:],]+$", "");
            if (beresp.http.Vary == "") { unset beresp.http.Vary; }
        } else if (bereq.http.X-SCP-Profile == "ultracache" && beresp.do_esi &&
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
}
