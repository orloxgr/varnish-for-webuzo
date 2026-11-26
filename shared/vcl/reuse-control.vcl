# Experimental metadata operations only, inside the existing authenticated
# adapter control gate. This does not advertise or enable cached delivery reuse.
sub scp_reuse_negotiate {
    if (req.http.X-UltraCache-Public-Selection-Enabled == "0" &&
        !cookie_handoff.fragment_declaration(req.http.X-SCP-Selection-Scope)) {
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
    if (req.http.X-UltraCache-Operation ~ "^(private-authority-context|private-mutation-begin|private-mutation-commit|private-mutation-ack|private-generation-publish|private-tag-retire|delivery-reuse-context)$") {
        set req.http.X-SCP-Selection-Operation = "actions";
        call scp_selection_context;
        unset req.http.X-SCP-Selection-Operation;
        set req.http.X-SCP-Reuse-Control-Status = cookie_handoff.reuse_control(
            req.http.X-SCP-Site,req.http.X-SCP-Selection-Native-Policy);
        return (synth(std.integer(req.http.X-SCP-Reuse-Control-Status,503),"Private authority control"));
    }
}

# Called from the normal generated backend path, never from a URL allowlist.
# Real public static files are dispatched by the adapter's existing Nginx file
# handler before Varnish. Anything reaching this dynamic application boundary
# can execute a provider; MIME/suffix is not evidence of a read-only operation.
sub scp_mutation_backend_fetch {
    if (bereq.http.X-SCP-Profile == "ultracache") {
        call scp_delivery_authorization;
        if (cookie_handoff.mutation_backend_start(bereq.http.X-SCP-Site,
            bereq.http.X-SCP-Selection-Native-Policy,bereq.http.X-UltraCache-Delivery-Authorization)) {}
        unset bereq.http.X-UltraCache-Delivery-Authorization;
    }
}
