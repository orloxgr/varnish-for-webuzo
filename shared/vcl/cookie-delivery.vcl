# Shared cookie-delivery policy. GPL-3.0-or-later.

sub scp_private_delivery {
    set resp.http.Cache-Control = "private, no-store";
    set resp.http.Surrogate-Control = "no-store";
}

# Cookie values are issued by their application/provider. The native proxy
# uses the common cookie cache rules and never generates provider identifiers.
