# Basic: conservative default for new sites; no application plugin required.
sub wvw_basic_recv {
    if (req.http.Cookie || req.url ~ "[?]" ||
        req.url ~ "(?i)^/(wp-admin(?:/|$)|wp-login[.]php|wp-json(?:/|$)|xmlrpc[.]php|wp-cron[.]php|cart(?:/|$)|checkout(?:/|$)|my-account(?:/|$)|wc-api(?:/|$))") {
        set req.http.X-WV-Mode = "PASS"; return (pass);
    }
}
