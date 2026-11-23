# Experimental metadata operations only, inside the existing authenticated
# adapter control gate. This does not advertise or enable cached delivery reuse.
sub scp_reuse_negotiate {
    if (req.http.X-UltraCache-Public-Selection-Enabled == "0") {
        if (cookie_handoff.delivery_reuse_available()) {
            if (cookie_handoff.reuse_register(req.http.X-SCP-Site,req.http.host,
                req.http.X-SCP-Selection-Scope,"","","",false)) {}
        }
    } else if (req.http.X-UltraCache-Public-Selection-Reuse-Version ||
        req.http.X-UltraCache-Public-Selection-Reuse-Policy) {
        if (req.http.X-SCP-Profile != "ultracache" ||
            req.http.X-UltraCache-Public-Selection-Reuse-Version != "1" ||
            req.http.X-UltraCache-Public-Selection-Reuse-Policy !~ "^[0-9a-f]{64}$" ||
            !cookie_handoff.delivery_reuse_available()) {
            return (synth(400,"Private authority declaration unavailable"));
        }
        if (!cookie_handoff.reuse_register(req.http.X-SCP-Site,req.http.host,
            req.http.X-SCP-Selection-Scope,req.http.X-SCP-Selection-Native-Policy,
            cookie_handoff.selection_wordpress_policy(req.http.X-SCP-Site,req.http.host,req.http.X-SCP-Selection-Scope),
            req.http.X-UltraCache-Public-Selection-Reuse-Policy,true)) {
            return (synth(400,"Private authority declaration rejected"));
        }
    }
}
sub scp_reuse_control {
    if (req.http.X-UltraCache-Operation ~ "^(private-authority-context|private-authority-recover|private-execution-drained|private-mutation-begin|private-mutation-commit|private-mutation-ack|private-generation-publish|private-tag-retire|delivery-reuse-context)$") {
        set req.http.X-SCP-Selection-Operation = "actions";
        call scp_selection_context;
        unset req.http.X-SCP-Selection-Operation;
        set req.http.X-SCP-Reuse-Control-Status = cookie_handoff.reuse_control(
            req.http.X-SCP-Site,req.http.X-SCP-Selection-Native-Policy);
        return (synth(std.integer(req.http.X-SCP-Reuse-Control-Status,503),"Private authority control"));
    }
}
