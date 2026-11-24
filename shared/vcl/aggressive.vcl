# Application HTML storage policy and explicit cache override. GPL-3.0-or-later.
sub scp_aggressive_backend_response {
    unset beresp.http.X-SCP-Aggressive-Response;
    unset beresp.http.X-SCP-Browser-Cache-Control;
    unset beresp.http.X-SCP-Browser-Surrogate-Control;
    unset beresp.http.X-SCP-Browser-Pragma;
    unset beresp.http.X-SCP-Browser-Expires;
    if (!bereq.uncacheable &&
        !(bereq.http.X-SCP-Profile == "ultracache" &&
          (beresp.http.X-SCP-Personal-Delivery == "1" || beresp.http.X-SCP-Public-Fragment == "1")) &&
        beresp.status == 200 && beresp.http.Content-Type ~ "(?i)^text/html(?:;|$)" &&
        (bereq.http.X-SCP-Aggressive == "1" ||
         (bereq.http.X-SCP-Profile == "ultracache" &&
          beresp.http.X-UltraCache-Cacheable == "1" &&
          beresp.http.X-UltraCache-Surrogate-TTL ~ "^[1-9][0-9]*$" &&
          beresp.http.Surrogate-Control !~ "(?i)(^|[[:space:],])(private|no-store)([[:space:],=]|$)"))) {
        # Store the application browser policy separately. Only Varnish's
        # internal storage decision changes; delivery restores every field.
        set beresp.http.X-SCP-Aggressive-Response = "1";
        set beresp.http.X-SCP-Browser-Cache-Control = beresp.http.Cache-Control;
        set beresp.http.X-SCP-Browser-Surrogate-Control = beresp.http.Surrogate-Control;
        set beresp.http.X-SCP-Browser-Pragma = beresp.http.Pragma;
        set beresp.http.X-SCP-Browser-Expires = beresp.http.Expires;
        if (bereq.http.X-SCP-Aggressive == "1") {
            set beresp.ttl = std.duration(bereq.http.X-SCP-Aggressive-TTL + "s", 0s);
            set beresp.http.Cache-Control = "public, s-maxage=" + bereq.http.X-SCP-Aggressive-TTL;
        } else {
            # The existing application decision controls shared storage, while
            # its ordinary HTTP fields continue to control the browser. Keep
            # upstream Age/Date freshness; approval never restarts an old TTL.
            set beresp.ttl = std.duration(beresp.http.X-UltraCache-Surrogate-TTL + "s", 0s) - beresp.age;
            set beresp.grace = std.duration(beresp.http.X-UltraCache-Stale-While-Revalidate + "s", 0s);
            set beresp.http.Cache-Control = "public, s-maxage=" + beresp.http.X-UltraCache-Surrogate-TTL;
        }
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
