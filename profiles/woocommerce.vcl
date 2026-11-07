# WooCommerce: WordPress plus standard shop routes and cart actions.
# Localized/private shop paths can be added to the site's bypass paths.
sub wvw_woocommerce_recv {
    call wvw_wordpress_recv;
    if (req.url ~ "(?i)^/(cart|checkout|my-account|wc-api)(/|[?]|$)" ||
        req.url ~ "(?i)[?&](add-to-cart|wc-ajax|wc-api)=") {
        set req.http.X-WV-Mode = "PASS"; return (pass);
    }
}
