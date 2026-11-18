# Shared CMS route policy. GPL-3.0-or-later.
# Installed descriptors are selected by the adapter, never by request headers.
sub scp_cms_recv {
    call scp_cms_normalize;
    @@CMS_ROUTE_RULES@@
    # Drupal's authentication cookies carry an identifiable session prefix.
    if (req.http.X-SCP-CMS == "drupal" &&
        req.http.Cookie ~ "(^|;[[:blank:]]*)(SSESS|SESS)[0-9a-f]+=.+") {
        set req.http.X-SCP-Reason = "drupal-authenticated-session";
        return (pass);
    }
}
@@CMS_NORMALIZATION@@
