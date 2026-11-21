# Shared CMS route policy. GPL-3.0-or-later.
# Installed descriptors are selected by the adapter, never by request headers.
sub scp_cms_recv {
    call scp_cms_normalize;
    @@CMS_ROUTE_RULES@@
    # CMS authentication/session cookie defaults are ordinary reviewed rules.
    # The selected Shared/Variant/Private action is applied later by the same
    # scoped resolver as every other cookie; routes/actions above remain private.
}
@@CMS_NORMALIZATION@@
