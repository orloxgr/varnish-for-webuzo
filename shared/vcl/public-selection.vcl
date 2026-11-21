# Additive original-route selection; old prepare/recovery remains unchanged.
sub scp_selection_context {
    @@PUBLIC_SELECTION_RULES@@
}

# Called only inside the adapters' existing authenticated capabilities branch.
sub scp_selection_negotiate {
    std.collect(req.http.X-UltraCache-Public-Selection-Version);
    std.collect(req.http.X-UltraCache-Public-Selection-Enabled);
    std.collect(req.http.X-UltraCache-Public-Selection-WordPress-Policy);
    std.collect(req.http.X-UltraCache-Public-Selection-Cookies);
    std.collect(req.http.X-UltraCache-Public-Selection-Scope);
    if (req.http.X-UltraCache-Public-Selection-Version ||
        req.http.X-UltraCache-Public-Selection-Enabled ||
        req.http.X-UltraCache-Public-Selection-WordPress-Policy ||
        req.http.X-UltraCache-Public-Selection-Cookies) {
        if ((req.http.X-SCP-Profile != "ultracache" && req.http.X-UltraCache-Public-Selection-Enabled != "0") ||
            req.http.X-UltraCache-Public-Selection-Version != "1" ||
            req.http.X-UltraCache-Public-Selection-Enabled !~ "^[01]$") {
            return (synth(400, "Invalid public selection declaration"));
        }
        if (!cookie_handoff.selection_register(req.http.X-SCP-Site,req.http.host,
            req.http.X-UltraCache-Public-Selection-Scope,
            req.http.X-UltraCache-Public-Selection-WordPress-Policy,
            req.http.X-UltraCache-Public-Selection-Cookies,
            req.http.X-UltraCache-Public-Selection-Enabled == "1")) {
            return (synth(400, "Public selection declaration rejected"));
        }
    }
    # Scope alone is a read-only query. Only plain probes may default to root;
    # a declaration above always requires its explicit application scope.
    if (req.http.X-UltraCache-Public-Selection-Scope) {
        set req.http.X-SCP-Selection-Scope = req.http.X-UltraCache-Public-Selection-Scope;
    } else {
        # Assigning an absent field first would create a present-empty header.
        set req.http.X-SCP-Selection-Scope = "/";
    }
    set req.http.X-SCP-Selection-Names = cookie_handoff.selection_names(req.http.X-SCP-Site,req.http.host,req.http.X-SCP-Selection-Scope);
    set req.http.X-SCP-Selection-Operation = "actions";
    call scp_selection_context;
    unset req.http.X-SCP-Selection-Operation;
}

sub scp_selection_capabilities {
    if (req.http.X-SCP-Profile == "ultracache" && resp.status == 200 &&
        req.http.X-UltraCache-Operation == "capabilities") {
        set resp.http.X-UltraCache-VCL-Capabilities = resp.http.X-UltraCache-VCL-Capabilities + ",public-selection";
        set resp.http.X-UltraCache-VCL-Public-Selection-Version = "1";
        set resp.http.X-UltraCache-VCL-Delivery-Outcome-Version = "1";
        set resp.http.X-UltraCache-VCL-Public-Selection-Epoch = cookie_handoff.selection_epoch();
        set resp.http.X-UltraCache-VCL-Public-Selection-Native-Policy = req.http.X-SCP-Selection-Native-Policy;
        set resp.http.X-UltraCache-VCL-Public-Selection-WordPress-Policy = cookie_handoff.selection_wordpress_policy(req.http.X-SCP-Site,req.http.host,req.http.X-SCP-Selection-Scope);
        unset resp.http.X-UltraCache-VCL-Public-Selection-Scope;
        if (resp.http.X-UltraCache-VCL-Public-Selection-WordPress-Policy !~ "^[0-9a-f]{64}$") {
            unset resp.http.X-UltraCache-VCL-Public-Selection-WordPress-Policy;
        } else {
            set resp.http.X-UltraCache-VCL-Public-Selection-Scope = req.http.X-SCP-Selection-Scope;
        }
        set resp.http.X-UltraCache-VCL-Public-Selection-Actions = req.http.X-SCP-Selection-Actions;
    }
}

# All ordinary auth/route/cookie decisions have already run. A browser's
# Cache-Control/Pragma revalidation headers do not disable this lookup.
sub scp_selection_recv {
    # These dedicated UltraCache diagnostics publish their own public canary,
    # before the application's normal template/publication lifecycle. Keep the
    # actual native cache and invalidation path: only omit application selection.
    # Existing ESI diagnostic handlers also exit before normal publication;
    # their WordPress token checks and native child transport remain in charge.
    # No request header can force this routing, and normal cookie/origin privacy
    # decisions still apply. Bound every route to its opaque 32-hex identifier.
    if (req.url ~ "(?i)^[^?]*/ultracache-varnishtest/[0-9a-f]{32}/?([?]|$)" ||
        req.http.X-SCP-Query ~ "(^|&)ultracache_varnish_canary=(?i:[0-9a-f]{32})(&|$)" ||
        req.url ~ "(?i)^[^?]*/ultracache/varnishtest/canary-[0-9a-f]{32}[.]html([?]|$)" ||
        req.http.X-SCP-Query ~ "(^|&)ultracache_esi_probe(_fragment|_private|_private_fragment)?=[^&]+(&|$)") {
        return;
    }
    if (req.restarts == 0 &&
        (req.http.Accept ~ "(?i)(^|,)[[:blank:]]*(text/html|application/xhtml[+]xml)([[:blank:];,]|$)" ||
         ((!req.http.Accept || req.http.Accept ~ "(^|,)[[:blank:]]*[*]/[*]([[:blank:];,]|$)") &&
          (!req.http.Sec-Fetch-Dest || req.http.Sec-Fetch-Dest ~ "^(document|iframe|frame)$")))) {
        set req.http.X-SCP-Selection-Operation = "begin";
        set req.http.X-SCP-Selection-Eligible = "1";
        call scp_selection_context;
        unset req.http.X-SCP-Selection-Operation;
        if (req.http.X-SCP-Selection-State == "1") { return (pass); }
        if (req.http.X-SCP-Selection-State == "-1") { return (synth(503, "Public selection unavailable")); }
    }
    if (cookie_handoff.selection_manifest()) {
        set req.http.X-SCP-Admin-Variant = cookie_handoff.selection_variant();
        # Native Vary/hash distinguishes absent from present-but-empty.
        # A Shared-only cold selection must rejoin the original no-Variant key.
        if (req.http.X-SCP-Admin-Variant == "") { unset req.http.X-SCP-Admin-Variant; }
    }
    unset req.http.X-SCP-Selection-State;
}

sub scp_selection_origin {
    # Hints cannot authorize an operation. Registration needs a successful
    # authenticated capabilities request, not these request fields.
    set bereq.http.X-UltraCache-VCL-Public-Selection-Version = "1";
    set bereq.http.X-UltraCache-VCL-Delivery-Outcome-Version = "1";
    set bereq.http.X-UltraCache-VCL-Public-Selection-Epoch = cookie_handoff.selection_epoch();
    set bereq.http.X-UltraCache-VCL-Public-Selection-Native-Policy = bereq.http.X-SCP-Selection-Native-Policy;
}
