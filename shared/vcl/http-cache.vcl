# Shared http-cache policy. GPL-3.0-or-later.

sub scp_mark_uncacheable {
    set beresp.ttl = param.uncacheable_ttl;
    set beresp.uncacheable = true;
}
sub scp_common_recv {
    if (req.http.Authorization) {
        set req.http.X-SCP-Reason = "authorization";
        return (pass);
    }
    if (req.http.Upgrade) {
        set req.http.X-SCP-Reason = "protocol-upgrade";
        return (pass);
    }
    if (req.method != "GET" && req.method != "HEAD") {
        set req.http.X-SCP-Reason = "request-method";
        return (pass);
    }
    if (req.url ~ "^/[.]well-known/(acme-challenge|pki-validation)/") {
        set req.http.X-SCP-Reason = "certificate-validation";
        return (pass);
    }
    if (req.http.X-WP-Nonce || req.http.Cart-Token || req.http.Nonce ||
        req.http.X-WC-Store-API-Nonce ||
        req.http.X-SCP-Query ~ "(?i)(^|&)(_wpnonce|_ajax_nonce|consumer_key|consumer_secret)=") {
        set req.http.X-SCP-Reason = "application-credentials";
        return (pass);
    }
    call scp_cms_recv;
    if (!req.http.X-SCP-CMS || req.http.X-SCP-CMS == "wordpress") {
    if (req.url ~ "(?i)^/([^?]*/)?(wp-admin(?:/|[?]|$)|wp-login[.]php(?:[?]|$)|xmlrpc[.]php(?:[?]|$)|wp-cron[.]php(?:[?]|$)|wp-comments-post[.]php(?:[?]|$))") {
        set req.http.X-SCP-Reason = "wordpress-private-route";
        return (pass);
    }
    if (req.http.X-SCP-Query ~ "(?i)(^|&)(preview|preview_id|preview_nonce|customize_changeset_uuid|elementor-preview|et_fb|vc_editable|nocache)=" ||
        req.http.X-SCP-Query ~ "(?i)(^|&)context=edit(&|$)") {
        set req.http.X-SCP-Reason = "preview-or-private-action";
        return (pass);
    }
    if (req.url ~ "(?i)^/([^?]*/)?(cart|checkout|my-account|wc-api)(/|[?]|$)" ||
        req.http.X-SCP-Query ~ "(?i)(^|&)(add-to-cart|remove_item|undo_item|wc-ajax|wc-api|apply_coupon|remove_coupon|order_again|cancel_order|pay_for_order|download_file)=" ||
        req.http.X-SCP-Query ~ "(?i)(^|&)key=wc_order_") {
        set req.http.X-SCP-Reason = "woocommerce-private-action";
        return (pass);
    }
    # Store API reads can carry cart/notices state even without mutation.
    # Public products and other REST reads retain normal HTTP caching.
    if (req.url ~ "(?i)^/([^?]*/)?wp-json/(wc/store/v[0-9]+/(cart|checkout|order)|wp/v[0-9]+/(users/me|settings))(/|[?]|$)" ||
        req.http.X-SCP-Query ~ "(?i)(^|&)rest_route=(/|%2f)(wc(/|%2f)store(/|%2f)v[0-9]+(/|%2f)(cart|checkout|order)|wp(/|%2f)v[0-9]+(/|%2f)(users(/|%2f)me|settings))(/|%2f|&|$)") {
        set req.http.X-SCP-Reason = "private-rest-context";
        return (pass);
    }
    }
    call scp_private_cookie_recv;
    call scp_cart_cookie_recv;

    call scp_representation_recv;
    call scp_cookie_variation;
}
sub scp_response_privacy {
    # The reason is stored only on uncacheable decisions; no private body is
    # retained. Mandatory origin privacy cannot be overridden by local TTLs.
    if (beresp.http.Surrogate-Control ~ "(?i)(^|[[:space:],])(no-store|private)([[:space:],=]|$)") {
        set beresp.http.X-SCP-Reason = "origin-surrogate-control";
        # ESI can consume Surrogate-Control. Preserve its privacy decision for
        # downstream caches as well as this Varnish instance.
        set beresp.http.Cache-Control = "private, no-store";
    } else if (beresp.http.Set-Cookie) {
        set beresp.http.X-SCP-Reason = "origin-set-cookie";
    } else if (beresp.http.Cache-Control ~ "(?i)(^|[[:space:],])(private|no-cache|no-store)([[:space:],=]|$)" ||
               beresp.http.Pragma ~ "(?i)(^|[[:space:],])no-cache([[:space:],=]|$)") {
        set beresp.http.X-SCP-Reason = "origin-cache-policy";
    } else if (beresp.http.Vary ~ "(^|,)[[:blank:]]*[*][[:blank:]]*(,|$)") {
        set beresp.http.X-SCP-Reason = "origin-vary-star";
    } else if (beresp.status < 200 || beresp.status == 206 || beresp.status == 304) {
        set beresp.http.X-SCP-Reason = "origin-status";
    } else if (beresp.ttl <= 0s) {
        set beresp.http.X-SCP-Reason = "origin-no-freshness";
    }
    if (beresp.http.X-SCP-Reason) { call scp_mark_uncacheable; }
}
