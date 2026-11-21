# Shared cookie-delivery policy. GPL-3.0-or-later.

sub scp_private_delivery {
    set resp.http.Cache-Control = "private, no-store";
    set resp.http.Surrogate-Control = "no-store";
}

# Real provider fields are detached before storage and returned only to the
# client task that caused this fetch. No cookie value is stored in the object.
sub scp_cookie_miss {
    if (req.esi_level == 0) {
        if (req.http.X-SCP-Profile == "ultracache" && req.restarts == 0 &&
            req.http.X-SCP-Selection-Eligible == "1") {
            set req.http.X-SCP-Selection-Operation = "cold-begin";
            call scp_selection_context;
            unset req.http.X-SCP-Selection-Operation;
            if (req.http.X-SCP-Selection-State == "1") { return (pass); }
            if (req.http.X-SCP-Selection-State == "-1") { return (synth(503, "Cold public selection unavailable")); }
            unset req.http.X-SCP-Selection-State;
        }
        if (req.http.X-SCP-Profile == "ultracache" && cookie_handoff.delivery_recover()) {
            # Existing request-owned association and snapshot-only phase.
        } else {
            if (req.http.X-SCP-Profile == "ultracache" && cookie_handoff.delivery_guard()) {
                return (synth(503, "Prepared parent unavailable"));
            }
            set req.http.X-SCP-Cookie-Handoff = cookie_handoff.open();
        }
    }
}

sub scp_shared_response_cookies {
    if (beresp.http.Set-Cookie && !bereq.uncacheable && beresp.ttl > 0s &&
        beresp.status >= 200 && beresp.status != 206 && beresp.status != 304 &&
        beresp.http.Cache-Control !~ "(?i)(^|[[:space:],])(private|no-cache|no-store)([[:space:],=]|$)" &&
        beresp.http.Surrogate-Control !~ "(?i)(^|[[:space:],])(private|no-store)([[:space:],=]|$)" &&
        beresp.http.Pragma !~ "(?i)(^|[[:space:],])no-cache([[:space:],=]|$)" &&
        beresp.http.Vary !~ "(^|,)[[:blank:]]*[*][[:blank:]]*(,|$)") {
        @@COOKIE_RESPONSE_RULES@@
    }
}

# Warm HITs use the provider's existing browser/application delivery path.
# This handoff never invents provider identifiers or grants consent.
