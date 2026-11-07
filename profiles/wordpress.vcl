# WordPress: keep authentication, editors, previews and APIs out of shared cache.
# Private/session cookie and origin-response checks also apply in the envelope.
sub wvw_wordpress_recv {
    if (req.url ~ "(?i)^/(wp-admin(?:/|[?]|$)|wp-login[.]php|wp-json(?:/|[?]|$)|xmlrpc[.]php|wp-cron[.]php|wp-comments-post[.]php)" ||
        req.url ~ "(?i)[?&](preview|preview_id|preview_nonce|customize_changeset_uuid|elementor-preview|et_fb|vc_editable|rest_route|s|nocache)=") {
        set req.http.X-WV-Mode = "PASS"; return (pass);
    }
}
