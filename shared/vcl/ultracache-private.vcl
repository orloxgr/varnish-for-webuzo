# UltraCache scoped native private objects. Isolated candidate; actual application qualification remains required.
# No cookie-based identity or content cache inside the VMOD.
acl uc_private_local { "127.0.0.1"; "::1"; }

# Adapter invokes this ONLY after its native site-secret/control-source gate.
sub scp_private_lookup {
    if (req.url ~ "^/__ultracache-native/held-v1/") { return (synth(403, "Native wait source denied")); }
    if (req.url ~ "^/__ultracache-native/reuse-v1/") { return (synth(403, "Native metadata source denied")); }
    if (req.http.X-SCP-Profile != "ultracache" || req.esi_level > 0 ||
        client.ip !~ uc_private_local ||
        (req.http.X-Real-IP && req.http.X-Real-IP !~ "^(127[.]0[.]0[.]1|::1)$") ||
        (req.http.X-Forwarded-For && req.http.X-Forwarded-For !~ "^(127[.]0[.]0[.]1|::1)$")) {
        return (synth(403, "Private lookup source denied"));
    }
    if (req.http.X-UltraCache-Private-Key !~ "^[0-9a-f]{64}$") {
        return (synth(400, "Invalid private cache key"));
    }
    set req.method = "GET";
    set req.http.X-SCP-Private-Key = req.http.X-UltraCache-Private-Key;
    set req.http.X-SCP-Private-Lookup = "1";
    unset req.http.X-UltraCache-Private-Key;
    unset req.http.X-UltraCache-Token;
    unset req.http.X-Hestia-Varnish-Token;
    unset req.http.X-Webuzo-Varnish-Token;
    unset req.http.Cookie;
    unset req.http.Authorization;
    unset req.http.Accept-Encoding;
    unset req.http.X-SCP-Aggressive;
    unset req.http.X-SCP-Aggressive-TTL;
    return (hash);
}

sub scp_private_hash {
    if (req.http.X-SCP-Profile == "ultracache" && req.http.X-SCP-Private-Key) {
        set req.http.X-SCP-Key-URL = req.url;
        hash_data("ultracache-private-v1");
        hash_data(req.http.X-SCP-Site);
        hash_data(req.http.host);
        hash_data(req.url);
        hash_data(req.http.X-SCP-Private-Key);
        return (lookup);
    }
}

sub scp_private_hit {
    if (req.http.X-SCP-Private-Key) {
        if (obj.http.X-SCP-Private-Object != "1" || obj.ttl <= 0s) {
            if (req.http.X-SCP-Private-Lookup == "1") { return (synth(404, "Private cache miss")); }
            return (pass);
        }
        return (deliver);
    }
}

sub scp_private_miss {
    set req.http.X-SCP-Delivery-Held = cookie_handoff.delivery_held_miss();
    if (req.http.X-SCP-Delivery-Held == "1") { return (restart); }
    if (req.http.X-SCP-Delivery-Held == "-1") { return (synth(503, "Native wait reservation unavailable")); }
    unset req.http.X-SCP-Delivery-Held;
    if (req.http.X-SCP-Private-Lookup == "1") { return (synth(404, "Private cache miss")); }
}

sub scp_private_backend_response {
    if (cookie_handoff.delivery_reuse_response()) {
        if (cookie_handoff.delivery_reuse_retry()) { return (retry); }
        set beresp.do_stream = false;
        set beresp.grace = 0s;
        set beresp.keep = 0s;
        set beresp.filters = "uc_delivery_capture";
        return (deliver);
    }
    if (cookie_handoff.delivery_private_source()) {
        set beresp.do_stream = false;
        set beresp.grace = 0s;
        set beresp.keep = 0s;
        if (beresp.ttl <= 0s) { set beresp.uncacheable = true; }
        set beresp.filters = "uc_request_snapshot";
        return (deliver);
    }
}

sub scp_private_deliver {
    unset resp.http.X-UltraCache-Private-Remaining;
    if (req.http.X-SCP-Private-Key) {
        call scp_private_delivery;
        unset resp.http.X-UltraCache-Tags;
        if (req.http.X-SCP-Private-Lookup == "1") {
            set resp.http.X-UltraCache-Private-Remaining = cookie_handoff.delivery_private_remaining();
        }
    }
    unset resp.http.X-SCP-Private-Object;
    unset resp.http.X-SCP-Reuse-Metadata;
    unset resp.http.X-UltraCache-Private-Key;
}
