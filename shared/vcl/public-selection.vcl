# Additive original-route selection; old prepare/recovery remains unchanged.
sub scp_selection_context {
    @@PUBLIC_SELECTION_RULES@@
}

# Called only inside the adapters' existing authenticated capabilities branch.
sub scp_selection_negotiate {
    if (req.http.X-UltraCache-Public-Selection-Version ||
        req.http.X-UltraCache-Public-Selection-Enabled ||
        req.http.X-UltraCache-Public-Selection-WordPress-Policy ||
        req.http.X-UltraCache-Public-Selection-Cookies) {
        if (req.http.X-SCP-Profile != "ultracache" ||
            req.http.X-UltraCache-Public-Selection-Version != "1" ||
            req.http.X-UltraCache-Public-Selection-Enabled !~ "^[01]$") {
            return (synth(400, "Invalid public selection declaration"));
        }
        if (!cookie_handoff.selection_register(req.http.X-SCP-Site,req.http.host,
            req.http.X-UltraCache-Public-Selection-WordPress-Policy,
            req.http.X-UltraCache-Public-Selection-Cookies,
            req.http.X-UltraCache-Public-Selection-Enabled == "1")) {
            return (synth(400, "Public selection declaration rejected"));
        }
    }
    set req.http.X-SCP-Selection-Names = cookie_handoff.selection_names(req.http.X-SCP-Site,req.http.host);
    set req.http.X-SCP-Selection-Operation = "actions";
    call scp_selection_context;
    unset req.http.X-SCP-Selection-Operation;
}

sub scp_selection_capabilities {
    if (req.http.X-SCP-Profile == "ultracache" && resp.status == 200 &&
        req.http.X-UltraCache-Operation == "capabilities") {
        set resp.http.X-UltraCache-VCL-Capabilities = resp.http.X-UltraCache-VCL-Capabilities + ",public-selection";
        set resp.http.X-UltraCache-VCL-Public-Selection-Version = "1";
        set resp.http.X-UltraCache-VCL-Public-Selection-Epoch = cookie_handoff.selection_epoch();
        set resp.http.X-UltraCache-VCL-Public-Selection-Native-Policy = req.http.X-SCP-Selection-Native-Policy;
        set resp.http.X-UltraCache-VCL-Public-Selection-WordPress-Policy = cookie_handoff.selection_wordpress_policy(req.http.X-SCP-Site,req.http.host);
        set resp.http.X-UltraCache-VCL-Public-Selection-Actions = req.http.X-SCP-Selection-Actions;
    }
}

# All ordinary auth/route/cookie decisions have already run. A browser's
# Cache-Control/Pragma revalidation headers do not disable this lookup.
sub scp_selection_recv {
    if (req.restarts == 0 &&
        (!req.http.Sec-Fetch-Dest || req.http.Sec-Fetch-Dest ~ "^(document|iframe|frame)$") &&
        (!req.http.Accept || req.http.Accept ~ "(?i)(^|,)[[:blank:]]*(text/html|application/xhtml[+]xml|[*]/[*])([[:blank:];,]|$)")) {
        set req.http.X-SCP-Selection-Operation = "begin";
        call scp_selection_context;
        unset req.http.X-SCP-Selection-Operation;
        if (req.http.X-SCP-Selection-State == "1") { return (pass); }
        if (req.http.X-SCP-Selection-State == "-1") { return (synth(503, "Public selection unavailable")); }
    }
    if (cookie_handoff.selection_manifest()) {
        set req.http.X-SCP-Admin-Variant = cookie_handoff.selection_variant();
    }
    unset req.http.X-SCP-Selection-State;
}

sub scp_selection_origin {
    # Hints cannot authorize an operation. Registration needs a successful
    # authenticated capabilities request, not these request fields.
    set bereq.http.X-UltraCache-VCL-Public-Selection-Version = "1";
    set bereq.http.X-UltraCache-VCL-Public-Selection-Epoch = cookie_handoff.selection_epoch();
    set bereq.http.X-UltraCache-VCL-Public-Selection-Native-Policy = bereq.http.X-SCP-Selection-Native-Policy;
}
