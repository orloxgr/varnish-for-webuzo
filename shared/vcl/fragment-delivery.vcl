# Explicit fragment-only operation; never an admission to shared document HTML.
sub scp_fragment_recv {
    if (req.http.X-SCP-Profile != "ultracache") { return; }
    set req.http.X-SCP-Fragment-State = cookie_handoff.fragment_recv(req.http.X-SCP-Site);
    if (req.http.X-SCP-Fragment-State == "1") { return (pass); }
    if (req.http.X-SCP-Fragment-State == "3") { return (hash); }
    if (req.http.X-SCP-Fragment-State == "-1") { return (synth(400,"Invalid fragment operation")); }
    unset req.http.X-SCP-Fragment-State;
    if (req.url ~ "[?]([^&]+&)*ultracache_esi=" &&
        !cookie_handoff.fragment_caching(req.http.X-SCP-Site,req.http.host,req.url)) {
        set req.http.X-SCP-Reason = "fragment-caching-disabled";
        return (pass);
    }
}

sub scp_fragment_negotiate {
    if (req.http.X-UltraCache-Fragment-Delivery-Version ||
        req.http.X-UltraCache-Fragment-Delivery-Route || req.http.X-UltraCache-Fragment-Caching-Enabled) {
        if (req.http.X-SCP-Profile != "ultracache" ||
            req.http.X-UltraCache-Fragment-Delivery-Version != "1" ||
            req.http.X-UltraCache-Fragment-Caching-Enabled !~ "^[01]$" ||
            !cookie_handoff.fragment_register(req.http.X-SCP-Site,req.http.host,
                req.http.X-SCP-Selection-Scope,req.http.X-UltraCache-Fragment-Delivery-Route,
                req.http.X-UltraCache-Fragment-Caching-Enabled == "1")) {
            return (synth(400,"Fragment delivery declaration rejected"));
        }
    }
}

sub scp_fragment_capabilities {
    if (resp.status == 200 && req.http.X-SCP-Profile == "ultracache" && req.http.X-UltraCache-Operation == "capabilities") {
        set resp.http.X-UltraCache-VCL-Fragment-Delivery-Route = cookie_handoff.fragment_route(
            req.http.X-SCP-Site,req.http.host,req.http.X-SCP-Selection-Scope);
        if (resp.http.X-UltraCache-VCL-Fragment-Delivery-Route) {
            set resp.http.X-UltraCache-VCL-Fragment-Delivery-Version = "1";
            set resp.http.X-UltraCache-VCL-Fragment-Caching-Enabled = "0";
            if (cookie_handoff.fragment_caching(req.http.X-SCP-Site,req.http.host,
                resp.http.X-UltraCache-VCL-Fragment-Delivery-Route)) {
                set resp.http.X-UltraCache-VCL-Fragment-Caching-Enabled = "1";
            }
        }
    }
}

sub scp_fragment_deliver {
    if (req.http.X-SCP-Profile != "ultracache") { return; }
    set req.http.X-SCP-Fragment-State = cookie_handoff.fragment_deliver();
    if (req.http.X-SCP-Fragment-State == "1") { return (restart); }
    if (req.http.X-SCP-Fragment-State == "2") { return (synth(200,"Fragment results")); }
    if (req.http.X-SCP-Fragment-State ~ "^(400|404|409)$") {
        return (synth(std.integer(req.http.X-SCP-Fragment-State,503),"Fragment operation rejected"));
    }
    if (req.http.X-SCP-Fragment-State == "-1") { return (synth(503,"Fragment operation unavailable")); }
    unset req.http.X-SCP-Fragment-State;
}
