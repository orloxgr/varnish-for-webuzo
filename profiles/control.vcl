# Authenticated HTTP invalidation. The compiler authenticates the local caller
# and assigns the immutable site identity before entering this subroutine.
sub wvw_http_control {
    if (req.http.X-UltraCache-Soft-Purge || req.http.X-Purge == "soft") {
        if (req.method != "PURGE" ||
            (req.http.X-UltraCache-Contract &&
             (req.http.X-UltraCache-Contract != "2" || req.http.X-UltraCache-Operation != "soft-purge"))) {
            return (synth(400, "Invalid soft-purge operation"));
        }
        if (req.http.X-UltraCache-Contract) { set req.http.X-WV-Control = "2"; }
        set req.http.X-WV-Soft-Purge = "1";
        return (hash);
    }
    if (req.http.X-UltraCache-Contract) {
        if (req.http.X-UltraCache-Contract != "2" || req.method != "PURGE") {
            return (synth(400, "Unsupported cache control contract"));
        }
        set req.http.X-WV-Control = "2";
        if (req.http.X-UltraCache-Operation == "capabilities") {
            if (req.url != "/__ultracache-vcl-contract-v2") {
                return (synth(400, "Invalid capabilities endpoint"));
            }
            return (synth(200, "Cache control capabilities"));
        }
        if (req.http.X-UltraCache-Operation == "exact-purge") {
            call wvw_exact_http_purge;
        }
        if (req.http.X-UltraCache-Operation == "soft-purge") {
            set req.http.X-WV-Soft-Purge = "1";
            return (hash);
        }
        if (req.url != "/__ultracache-vcl-contract-v2") {
            return (synth(400, "Invalid cache control request"));
        }
        # The versioned protocol uses VCL-quoted operands. Extract only the
        # generated host and selector; the expression itself is never executed.
        # Consume plain runs without per-byte captures or backtracking state:
        # long valid operands must not exhaust the regex JIT stack.
        if (req.http.X-UltraCache-Object-Expression ~ {"^obj[.]http[.]X-Cache-Object-Host == "[a-z0-9.-]+(:[0-9]+)?" && obj[.]http[.]X-Cache-Object-URL ~ "(?:[^"\\]++|\\.)++"$"}) {
            set req.http.X-WV-Ban-Host = regsub(req.http.X-UltraCache-Object-Expression,
                {"^obj[.]http[.]X-Cache-Object-Host == "([a-z0-9.-]+(:[0-9]+)?)" &&.*$"}, "\1");
            set req.http.X-WV-Ban-Pattern = regsub(req.http.X-UltraCache-Object-Expression,
                {"^obj[.]http[.]X-Cache-Object-Host == "[a-z0-9.-]+(:[0-9]+)?" && obj[.]http[.]X-Cache-Object-URL ~ "(.*)"$"}, "\2");
            set req.http.X-WV-Ban-Pattern = regsuball(req.http.X-WV-Ban-Pattern, {"\\([\\"])"}, "\1");
            if (req.http.X-WV-Ban-Pattern == ".*") {
                if (req.http.X-UltraCache-Operation != "host-ban") {
                    return (synth(400, "Host invalidation requires host-ban"));
                }
            } else if (req.http.X-UltraCache-Operation != "exact-ban" &&
                req.http.X-UltraCache-Operation != "batch-ban") {
                return (synth(400, "Invalid URL cache operation"));
            }
        } else if (req.http.X-UltraCache-Object-Expression ~ {"^obj[.]http[.]X-Cache-Object-Host == "[a-z0-9.-]+(:[0-9]+)?" && obj[.]http[.]Content-Type ~ "\^text/html"$"} &&
            req.http.X-UltraCache-Operation == "html-ban") {
            set req.http.X-WV-Ban-Host = regsub(req.http.X-UltraCache-Object-Expression,
                {"^obj[.]http[.]X-Cache-Object-Host == "([a-z0-9.-]+(:[0-9]+)?)" &&.*$"}, "\1");
            set req.http.X-WV-Ban-HTML = "1";
        } else {
            return (synth(400, "Unsupported cache control expression"));
        }
    }
    if (!req.http.X-WV-Control && req.method == "PURGE") {
        call wvw_exact_http_purge;
    }

    # Portable UltraCache expressions contain literal, unquoted HTTP operands.
    # Accept only the generated host+URL or host+HTML grammar, never a caller's
    # arbitrary ban expression. In particular an invalid expression cannot turn
    # a targeted operation into a whole-site invalidation.
    if (!req.http.X-WV-Control) {
    if (req.http.X-Ban-Expression ~ {"^req[.]http[.]host == [a-z0-9.-]+(:[0-9]+)? && req[.]url ~ [^[:space:]"']+$"}) {
        set req.http.X-WV-Ban-Host = regsub(req.http.X-Ban-Expression,
            {"^req[.]http[.]host == ([a-z0-9.-]+(:[0-9]+)?) &&.*$"}, "\1");
        set req.http.X-WV-Ban-Pattern = regsub(req.http.X-Ban-Expression,
            {"^req[.]http[.]host == [a-z0-9.-]+(:[0-9]+)? && req[.]url ~ (.*)$"}, "\2");
    } else if (req.http.X-Ban-Expression ~ {"^req[.]http[.]host == [a-z0-9.-]+(:[0-9]+)? && obj[.]http[.]Content-Type ~ \^text/html$"}) {
        set req.http.X-WV-Ban-Host = regsub(req.http.X-Ban-Expression,
            {"^req[.]http[.]host == ([a-z0-9.-]+(:[0-9]+)?) &&.*$"}, "\1");
        set req.http.X-WV-Ban-HTML = "1";
    } else {
        return (synth(400, "Unsupported cache invalidation expression"));
    }
    }

    set req.http.X-WV-Ban-Host = regsub(regsub(req.http.X-WV-Ban-Host, ":[0-9]+$", ""), "[.]$", "");
    if (req.http.X-WV-Ban-Host != req.http.host) {
        return (synth(403, "Cache invalidation host denied"));
    }
    if (req.http.X-WV-Ban-HTML == "1") {
        if (!std.ban("obj.http.X-WV-Site == " + req.http.X-WV-Site +
            " && obj.http.X-Cache-Object-Host == " + req.http.host +
            " && obj.http.Content-Type ~ ^text/html")) {
            return (synth(400, "Invalid HTML cache invalidation"));
        }
    } else {
        if (req.http.X-WV-Ban-Pattern ~ {"[[:space:]"']"}) {
            return (synth(400, "Invalid URL expression operand"));
        }
        if (req.http.X-WV-Ban-Pattern != ".*" &&
            req.http.X-WV-Ban-Pattern !~ {"^\^.*\$$"}) {
            return (synth(400, "URL invalidation must be anchored"));
        }
        if (!std.ban("obj.http.X-WV-Site == " + req.http.X-WV-Site +
            " && obj.http.X-Cache-Object-Host == " + req.http.host +
            " && obj.http.X-Cache-Object-URL ~ " + req.http.X-WV-Ban-Pattern)) {
            return (synth(400, "Invalid URL cache invalidation"));
        }
    }
    return (synth(200, "Ban added"));
}

# Exact URL invalidation covers all HTTP/HTTPS and Vary representations of this
# site's URL, regardless of the selected caching profile. Reject operand
# delimiters and control characters before constructing the scoped ban.
sub wvw_exact_http_purge {
    if (req.url ~ {"[[:space:]"\\]"}) { return (synth(400, "Invalid purge URL")); }
    if (!std.ban("obj.http.X-WV-Site == " + req.http.X-WV-Site +
        " && obj.http.X-Cache-Object-URL == " + req.url)) {
        return (synth(400, "Invalid purge URL"));
    }
    return (synth(200, "URL cache purged"));
}

sub vcl_synth {
    if (req.http.X-WV-Control == "2") {
        set resp.http.X-UltraCache-VCL-Contract = "2";
        set resp.http.X-UltraCache-VCL-Adapter = "ultracache-webuzo-v2";
        set resp.http.X-UltraCache-VCL-Auth = "token";
        set resp.http.X-UltraCache-VCL-Operation = req.http.X-UltraCache-Operation;
        set resp.http.X-UltraCache-VCL-Capabilities = "exact-purge,exact-ban,batch-ban,html-ban,host-ban,soft-purge";
        set resp.http.Cache-Control = "no-store";
        if (resp.status >= 200 && resp.status < 300) {
            set resp.http.X-UltraCache-VCL-Result = "ok";
        } else {
            set resp.http.X-UltraCache-VCL-Result = "error";
        }
    }
}
