# Explicit anonymous HTML cache override. GPL-3.0-or-later.
sub scp_aggressive_backend_response {
    unset beresp.http.X-SCP-Aggressive-Response;
    unset beresp.http.X-SCP-Browser-Cache-Control;
    unset beresp.http.X-SCP-Browser-Surrogate-Control;
    unset beresp.http.X-SCP-Browser-Pragma;
    unset beresp.http.X-SCP-Browser-Expires;
    if (bereq.http.X-SCP-Aggressive == "1" && !bereq.uncacheable &&
        !(bereq.http.X-SCP-Profile == "ultracache" && beresp.http.X-SCP-Personal-Delivery == "1") &&
        beresp.status == 200 && beresp.http.Content-Type ~ "(?i)^text/html(?:;|$)") {
        # Store the application browser policy separately. Only Varnish's
        # internal storage decision changes; delivery restores every field.
        set beresp.http.X-SCP-Aggressive-Response = "1";
        set beresp.http.X-SCP-Browser-Cache-Control = beresp.http.Cache-Control;
        set beresp.http.X-SCP-Browser-Surrogate-Control = beresp.http.Surrogate-Control;
        set beresp.http.X-SCP-Browser-Pragma = beresp.http.Pragma;
        set beresp.http.X-SCP-Browser-Expires = beresp.http.Expires;
        set beresp.ttl = std.duration(bereq.http.X-SCP-Aggressive-TTL + "s", 0s);
        set beresp.http.Cache-Control = "public, s-maxage=" + bereq.http.X-SCP-Aggressive-TTL;
        set beresp.http.Surrogate-Control = regsuball(beresp.http.Surrogate-Control,
            "(?i)(^|,)[[:blank:]]*(private|no-store)[[:blank:]]*(?=,|$)", "");
        unset beresp.http.Pragma;
        unset beresp.http.Expires;
    }
}

sub scp_aggressive_deliver {
    if (resp.http.X-SCP-Aggressive-Response == "1") {
        unset resp.http.Cache-Control;
        unset resp.http.Surrogate-Control;
        unset resp.http.Pragma;
        unset resp.http.Expires;
        if (resp.http.X-SCP-Browser-Cache-Control) { set resp.http.Cache-Control = resp.http.X-SCP-Browser-Cache-Control; }
        if (resp.http.X-SCP-Browser-Surrogate-Control) { set resp.http.Surrogate-Control = resp.http.X-SCP-Browser-Surrogate-Control; }
        if (resp.http.X-SCP-Browser-Pragma) { set resp.http.Pragma = resp.http.X-SCP-Browser-Pragma; }
        if (resp.http.X-SCP-Browser-Expires) { set resp.http.Expires = resp.http.X-SCP-Browser-Expires; }
    }
    unset resp.http.X-SCP-Aggressive-Response;
    unset resp.http.X-SCP-Browser-Cache-Control;
    unset resp.http.X-SCP-Browser-Surrogate-Control;
    unset resp.http.X-SCP-Browser-Pragma;
    unset resp.http.X-SCP-Browser-Expires;
}
