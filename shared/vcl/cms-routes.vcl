# Shared CMS route policy. GPL-3.0-or-later.
# Installed descriptors are selected by the adapter, never by request headers.
sub scp_cms_recv {
    call scp_cms_normalize;
    @@CMS_ROUTE_RULES@@
    # PrestaShop encrypts authentication, customer identity and cart state in
    # this combined cookie. It is not a generic anonymous PHP session marker.
    if (req.http.X-SCP-CMS == "prestashop" &&
        req.http.Cookie ~ "(^|;[[:blank:]]*)PrestaShop-[0-9a-fA-F]{32}=.+") {
        set req.http.X-SCP-Reason = "prestashop-private-session";
        return (pass);
    }
    # Drupal's authentication cookies carry an identifiable session prefix.
    if (req.http.X-SCP-CMS == "drupal" &&
        req.http.Cookie ~ "(^|;[[:blank:]]*)(SSESS|SESS)[0-9a-f]+=.+") {
        set req.http.X-SCP-Reason = "drupal-authenticated-session";
        return (pass);
    }
    if (req.http.X-SCP-CMS == "joomla" &&
        req.http.Cookie ~ "(^|;[[:blank:]]*)(joomla_user_state=logged_in[[:blank:]]*(;|$)|joomla_remember_me_[^=;[:blank:]]*=)") {
        set req.http.X-SCP-Reason = "joomla-authenticated-session";
        return (pass);
    }
    if (req.http.X-SCP-CMS == "joomla" && req.http.X-SCP-Aggressive == "1" &&
        req.http.Cookie ~ "(^|;[[:blank:]]*)[0-9a-fA-F]{32}=") {
        set req.http.X-SCP-Session-State = cookie_handoff.session_state(
            req.http.X-SCP-Session-Socket, req.http.X-SCP-Session-Site, req.url,
            req.http.Cookie, std.duration(req.http.X-SCP-Session-Timeout, 0s));
        if (req.http.X-SCP-Session-State !~ "^guest[[:blank:]]") {
            set req.http.X-SCP-Reason = regsub(req.http.X-SCP-Session-State, "^[^[:blank:]]+[[:blank:]]", "");
            return (pass);
        }
    }
}
@@CMS_NORMALIZATION@@
