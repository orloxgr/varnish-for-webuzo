# Shared core policy. GPL-3.0-or-later.

sub scp_init {
    unset req.http.X-UltraCache-VCL-Guest-Inputs-Version;
    unset req.http.X-UltraCache-Delivery-Public-Source-Version;
    unset req.http.X-UltraCache-Delivery-Public-Source-Role;
    unset req.http.X-UltraCache-Delivery-Public-Source-Outcome;
    unset req.http.X-UltraCache-Delivery-Public-Source-Projection-Version;
    unset req.http.X-UltraCache-Delivery-Public-Source-Projection;
    unset req.http.X-UltraCache-Delivery-Public-Source-Fallback;
    unset req.http.X-UltraCache-VCL-Public-Selection-Public-Source-Projection-Version;
    unset req.http.X-UltraCache-VCL-Public-Selection-Public-Source-Version;
    # Only the authenticated native dispatch may create this backend phase.
    if (req.http.X-UltraCache-Delivery-Phase == "execution-drain") {
        return (synth(400,"Invalid execution drain ingress"));
    }
    unset req.http.X-UltraCache-VCL-Execution-Drain-Version;
    unset req.http.X-UltraCache-VCL-Public-Selection-Execution-Drain-Version;
    # Completed classification scratch must release its header slots before
    # adding the continuation reuse marker, including a full browser request.
    unset req.http.X-SCP-Admin-Remaining;
    unset req.http.X-SCP-Admin-Keep;
    unset req.http.X-SCP-Admin-Matched;
    # A continuation restarts this same, already classified top request.
    # Only native phase/site/host/URL ownership plus an unchanged raw Cookie
    # permits reuse. Client headers, ESI children and ordinary restarts cannot.
    unset req.http.X-SCP-Admin-Reuse;
    if (req.http.X-SCP-Admin-Applied == "1" && req.http.Cookie &&
        cookie_handoff.delivery_cookie_unchanged() &&
        cookie_handoff.delivery_resume_authorized(req.http.X-SCP-Site)) {
        set req.http.X-SCP-Admin-Reuse = "1";
    }
    cookie_handoff.reset();
    cookie_handoff.guest_ingress();
    unset req.http.X-SCP-Warm-Projection-Supported;
    unset req.http.X-UltraCache-Warm-Projection;
    unset req.http.X-UltraCache-Warm-Projection-Authorization;
    unset req.http.X-UltraCache-VCL-Warm-Projection-Version;
    unset req.http.X-SCP-Guest-Issuer;
    unset req.http.X-SCP-Guest-Issuer-Canonical;
    unset req.http.X-SCP-Guest-Issuer-Query;
    unset req.http.X-SCP-Cookie-Handoff;
    unset req.http.X-UltraCache-Guest-Issuer-Version;
    unset req.http.X-UltraCache-Guest-Issuer-Canonical-URL;
    unset req.http.X-UltraCache-Guest-Issuer-Authorization;
    unset req.http.X-UltraCache-Delivery-Guest-Publication-Canonical-URL;
    unset req.http.X-UltraCache-Delivery-Guest-Publication-Version;
    unset req.http.X-UltraCache-Delivery-Guest-Publication-Policy;
    unset req.http.X-UltraCache-VCL-Guest-Publication-Version;
    unset req.http.X-UltraCache-VCL-Guest-Publication-Policy;
    unset req.http.X-UltraCache-Guest-Publication;
    unset req.http.X-SCP-Guest-Key;
    unset req.http.X-SCP-Guest-Manifest;
    unset req.http.X-SCP-Guest-Complete;
    unset req.http.X-UltraCache-Delivery-Parent-Source;
    unset req.http.X-SCP-Delivery-Public-Snapshot;
    unset req.http.X-SCP-Personal-Delivery;
    unset req.http.X-SCP-Public-Fragment;
    unset req.http.X-SCP-Fragment-HTTP-Failure;
    unset req.http.X-UltraCache-ESI-Error-Contained;
    unset req.http.X-UltraCache-VCL-Publication-Reselect-Version;
    unset req.http.X-UltraCache-Delivery-Conflict-Version;
    unset req.http.X-UltraCache-Delivery-Conflict;
    unset req.http.X-UltraCache-Delivery-Manifest-SHA256;
    unset req.http.X-UltraCache-Delivery-Outcome;
    unset req.http.X-UltraCache-VCL-Delivery-Outcome-Version;
    unset req.http.X-UltraCache-VCL-Cookie-Delivery-Version;
    unset req.http.X-UltraCache-Cookie-Delivery;
    unset req.http.X-UltraCache-Application-Private;
    unset req.http.X-SCP-Private-Key;
    unset req.http.X-SCP-Private-Lookup;
    unset req.http.X-SCP-Site;
    unset req.http.X-UltraCache-Delivery-Authorization;
    unset req.http.X-UltraCache-Delivery-Reuse-Candidate-Version;
    unset req.http.X-UltraCache-Delivery-Reuse-Context;
    unset req.http.X-UltraCache-Delivery-Reuse-Version;
    if (req.method != "PURGE" || req.url != "/__ultracache-vcl-contract-v2") {
        unset req.http.X-UltraCache-Delivery-Execution-Drain-Context;
        unset req.http.X-UltraCache-Public-Selection-Execution-Drain-Version;
        unset req.http.X-UltraCache-Public-Selection-Public-Source-Version;
        unset req.http.X-UltraCache-Public-Selection-Public-Source-Projection-Version;
        # These selectors also belong to the separately authenticated native
        # control protocol; ordinary/browser application requests cannot set them.
        unset req.http.X-UltraCache-Delivery-Reuse-Recipe;
        unset req.http.X-UltraCache-Private-Request-Id;
        unset req.http.X-UltraCache-Private-Challenge;
        unset req.http.X-UltraCache-Private-Coverage-Proof;
        unset req.http.X-UltraCache-Private-Coverage-Result;
        unset req.http.X-UltraCache-Private-Coverage-Policy;
        unset req.http.X-UltraCache-Private-Coverage-Version;
    }
    unset req.http.X-UltraCache-Mutation-Context;
    unset req.http.X-UltraCache-Mutation-Receipt;
    unset req.http.X-UltraCache-Delivery-Manifest;
    unset req.http.X-UltraCache-Delivery-Recovery-Version;
    unset req.http.X-UltraCache-Delivery-Request-Snapshot-Version;
    unset req.http.X-UltraCache-Delivery-Private-Cache-Version;
    unset req.http.X-UltraCache-Delivery-Private-Document-Version;
    unset req.http.X-UltraCache-Delivery-Recovery;
    unset req.http.X-SCP-Cookie-Contract;
    unset req.http.X-SCP-Selection-Operation;
    unset req.http.X-SCP-Selection-Eligible;
    unset req.http.X-SCP-Selection-State;
    unset req.http.X-SCP-Selection-Names;
    unset req.http.X-SCP-Selection-Scope;
    unset req.http.X-SCP-Selection-Actions;
    unset req.http.X-SCP-Selection-Native-Policy;
    unset req.http.X-UltraCache-Delivery-Public-Selection-Version;
    unset req.http.X-UltraCache-Delivery-Public-Selection-Scope;
    unset req.http.X-UltraCache-Delivery-Policy;
    unset req.http.X-UltraCache-Delivery-WordPress-Policy;
    unset req.http.X-UltraCache-Delivery-Public-Selection-Actions;
    unset req.http.X-UltraCache-VCL-Public-Selection-Version;
    unset req.http.X-UltraCache-VCL-Public-Selection-Canonical-Host;
    unset req.http.X-UltraCache-VCL-Public-Selection-Coverage-Version;
    unset req.http.X-UltraCache-VCL-Public-Selection-Coverage-Policy;
    unset req.http.X-UltraCache-VCL-Public-Selection-Scope;
    unset req.http.X-UltraCache-VCL-Public-Selection-Epoch;
    unset req.http.X-UltraCache-VCL-Public-Selection-Native-Policy;
    unset req.http.X-UltraCache-VCL-Public-Selection-WordPress-Policy;
    unset req.http.X-UltraCache-VCL-Public-Selection-Actions;
    unset req.http.X-UltraCache-Cookie-Settings;
    unset req.http.X-UltraCache-Cookie-Vary;
    if (req.http.X-SCP-Admin-Reuse != "1") {
        unset req.http.X-SCP-Admin-Applied;
        unset req.http.X-SCP-Admin-Filtered;
        unset req.http.X-SCP-Admin-Variant;
        unset req.http.X-SCP-Admin-Has-Variant;
        unset req.http.X-SCP-Admin-Rule;
        unset req.http.X-SCP-Admin-Scope;
        unset req.http.X-SCP-Admin-Action;
        unset req.http.X-SCP-Admin-Input;
        unset req.http.X-SCP-Admin-Request-Variant;
        unset req.http.X-SCP-Cookie-Name;
        unset req.http.X-SCP-Cookie-Role;
    }
    unset req.http.X-SCP-Profile;
    unset req.http.X-SCP-CMS;
    unset req.http.X-SCP-CMS-Path;
    unset req.http.X-SCP-CMS-Query;
    unset req.http.X-SCP-Aggressive;
    unset req.http.X-SCP-Aggressive-TTL;
    unset req.http.X-SCP-Private-Check;
    unset req.http.X-SCP-Reason;
    unset req.http.X-SCP-Pass;
    unset req.http.X-SCP-Key-URL;
    unset req.http.X-SCP-Query;
    unset req.http.X-SCP-Key-Path;
    unset req.http.X-SCP-Key-Query;
    if (req.http.X-SCP-Admin-Reuse != "1") {
        unset req.http.X-SCP-Vary-Cookie;
        unset req.http.X-SCP-Vary-ESI-Cookie;
    }
    unset req.http.X-SCP-Vary-Accept;
    unset req.http.X-SCP-Vary-Accept-Language;
    unset req.http.X-SCP-Normalize-Value;
    unset req.http.X-SCP-HTML-Accept;
    unset req.http.X-SCP-Fbp-Enabled;
    unset req.http.X-SCP-Fbp-Consent;
    unset req.http.X-SCP-Fbp-Domain;
    unset req.http.X-SCP-Fbp-Index;
    unset req.http.X-SCP-Fbp-New;
    unset req.http.X-UltraCache-Cookie-Policy;
    unset req.http.X-UltraCache-Cookie-Delivery;
    unset req.http.X-SCP-Accept-Check;
    unset req.http.X-ESI-Private-Request;
    unset req.http.X-ESI-Request-Level;
    unset req.http.X-ESI-Original-Cookie;
    unset req.http.X-UltraCache-ESI-Transport-Version;
    unset req.http.X-UltraCache-ESI-Adaptive-Nonce-Version;
    unset req.http.X-SCP-Adaptive-Nonce;
    unset req.http.X-UltraCache-ESI-Candidate;
    unset req.http.X-UltraCache-ESI-Cookie-Check;
    unset req.http.X-UltraCache-ESI-Opt-In;
    unset req.http.X-UltraCache-ESI-Shared-Parent;
}

# Normalize a COPY for hashing/invalidation. Never change req.url.
sub scp_recv {
    std.collect(req.http.Cookie, "; ");
    # Existing application raw-Warm transport must reach its source, including
    # when a complete public guest publication is already hot. This shape is
    # routing only: the origin still verifies the runtime credential. PASS
    # cannot replace/fill the guest object, even after origin authentication
    # refuses a correctly shaped but invalid credential.
    if (req.http.X-SCP-Profile == "ultracache" && req.method == "GET" &&
        req.http.X-UltraCache-Warm-Source == "raw-v1" &&
        req.http.X-UltraCache-Internal-Request == "1" && req.http.X-UltraCache-Warm == "1" &&
        req.http.X-UltraCache-Runtime-Token ~ "^v2:[1-9][0-9]*:[0-9a-f]{64}$") {
        set req.http.X-SCP-Reason = "ultracache-raw-warm-source";
        return (pass);
    }
    # This shape routes a private collector request, never authenticates it.
    # The origin owns MAC/one-use validation. Preserve all original cookies,
    # including ESI markers, by passing before profile-specific transport.
    if (req.http.X-UltraCache-Session-Source && req.method == "GET" &&
        req.http.X-UltraCache-Warm-Source == "raw-v1" &&
        req.http.X-UltraCache-Internal-Request == "1" && req.http.X-UltraCache-Warm == "1" &&
        req.http.X-UltraCache-Session-Source-Kind ~ "^(native|observed)$" &&
        req.http.X-UltraCache-Session-Source ~ "^v1:[0-9a-f]{64}:[0-9a-f]{64}:[0-9a-f]{64}:[0-9a-f]{64}$") {
        set req.http.X-SCP-Reason = "ultracache-private-session-source";
        return (pass);
    }
    # Browser revalidation does not decide the server-side cache action.
    # The signed/shaped raw session-source operation above remains separate.
    std.collect(req.http.Cache-Control);
    if (req.url ~ "[?]") { set req.http.X-SCP-Query = regsub(req.url, "^[^?]*[?]", ""); }
    if (req.http.X-SCP-Profile == "ultracache") { call scp_guest_issuer_recv; }
    if (req.http.X-SCP-Profile == "ultracache") { call scp_ultracache_recv; }
    call scp_common_recv;
    if (req.http.X-SCP-Profile == "ultracache" && req.esi_level == 0 && req.method == "GET") {
        call scp_selection_recv;
    }
}
sub scp_pass {
    if (req.esi_level == 0 && req.http.X-SCP-Profile == "ultracache" && cookie_handoff.delivery_guard()) {
        return (synth(503, "Prepared parent unavailable"));
    }
    set req.http.X-SCP-Pass = "1";
}
sub scp_hit {
    if (req.http.X-SCP-Profile == "ultracache") { call scp_private_hit; }
    if (req.http.X-SCP-Profile == "ultracache") { call scp_ultracache_hit; }
}
sub scp_backend_fetch {
    unset bereq.http.X-UltraCache-Private-Coverage-Proof;
    unset bereq.http.X-UltraCache-Private-Coverage-Result;
    unset bereq.http.X-UltraCache-Private-Coverage-Policy;
    unset bereq.http.X-UltraCache-Private-Coverage-Version;
    cookie_handoff.bind(bereq.http.X-SCP-Cookie-Handoff);
    if (cookie_handoff.delivery_public_source_backend()) {}
    call scp_delivery_authorization;
    unset bereq.http.X-UltraCache-Delivery-Authorization;
    call scp_mutation_backend_fetch;
    unset bereq.http.X-SCP-Cookie-Handoff;
    unset bereq.http.X-UltraCache-Guest-Issuer-Version;
    unset bereq.http.X-UltraCache-Guest-Issuer-Canonical-URL;
    unset bereq.http.X-UltraCache-Guest-Issuer-Authorization;
    unset bereq.http.X-UltraCache-Delivery-Guest-Publication-Canonical-URL;
    unset bereq.http.X-UltraCache-Delivery-Guest-Publication-Version;
    unset bereq.http.X-UltraCache-Delivery-Guest-Publication-Policy;
    unset bereq.http.X-UltraCache-VCL-Guest-Publication-Version;
    unset bereq.http.X-UltraCache-VCL-Guest-Inputs-Version;
    unset bereq.http.X-UltraCache-VCL-Guest-Publication-Policy;
    unset bereq.http.X-UltraCache-Guest-Publication;
    unset bereq.http.X-SCP-Guest-Key;
    unset bereq.http.X-SCP-Guest-Manifest;
    unset bereq.http.X-SCP-Guest-Complete;
    unset bereq.http.X-UltraCache-Delivery-Parent-Source;
    unset bereq.http.X-SCP-Delivery-Public-Snapshot;
    unset bereq.http.X-SCP-Personal-Delivery;
    unset bereq.http.X-SCP-Public-Fragment;
    unset bereq.http.X-SCP-Fragment-HTTP-Failure;
    unset bereq.http.X-UltraCache-ESI-Error-Contained;
    unset bereq.http.X-UltraCache-VCL-Publication-Reselect-Version;
    unset bereq.http.X-UltraCache-Delivery-Conflict-Version;
    unset bereq.http.X-UltraCache-Delivery-Conflict;
    unset bereq.http.X-UltraCache-Delivery-Manifest-SHA256;
    unset bereq.http.X-UltraCache-Delivery-Outcome;
    unset bereq.http.X-UltraCache-VCL-Delivery-Outcome-Version;
    unset bereq.http.X-UltraCache-VCL-Cookie-Delivery-Version;
    unset bereq.http.X-UltraCache-Cookie-Delivery;
    unset bereq.http.X-UltraCache-Application-Private;
    unset bereq.http.X-UltraCache-Delivery-Authorization;
    unset bereq.http.X-UltraCache-Delivery-Public-Selection-Version;
    unset bereq.http.X-UltraCache-Delivery-Public-Selection-Scope;
    unset bereq.http.X-UltraCache-Delivery-Policy;
    unset bereq.http.X-UltraCache-Delivery-WordPress-Policy;
    unset bereq.http.X-UltraCache-Delivery-Public-Selection-Actions;
    unset bereq.http.X-UltraCache-VCL-Public-Selection-Version;
    unset bereq.http.X-UltraCache-VCL-Public-Selection-Canonical-Host;
    unset bereq.http.X-UltraCache-VCL-Public-Selection-Coverage-Version;
    unset bereq.http.X-UltraCache-VCL-Public-Selection-Coverage-Policy;
    unset bereq.http.X-UltraCache-VCL-Public-Selection-Scope;
    unset bereq.http.X-UltraCache-VCL-Public-Selection-Epoch;
    unset bereq.http.X-UltraCache-VCL-Public-Selection-Native-Policy;
    unset bereq.http.X-UltraCache-VCL-Public-Selection-WordPress-Policy;
    unset bereq.http.X-UltraCache-VCL-Public-Selection-Actions;
    unset bereq.http.X-UltraCache-Public-Selection-Guest-Version;
    unset bereq.http.X-UltraCache-Public-Selection-Guest-Policy;
    unset bereq.http.X-UltraCache-Public-Selection-Version;
    unset bereq.http.X-UltraCache-Public-Selection-Enabled;
    unset bereq.http.X-UltraCache-Public-Selection-WordPress-Policy;
    unset bereq.http.X-UltraCache-Public-Selection-Cookies;
    unset bereq.http.X-UltraCache-Public-Selection-Scope;
    unset bereq.http.X-UltraCache-Delivery-Manifest;
    unset bereq.http.X-UltraCache-Delivery-Recovery-Version;
    unset bereq.http.X-UltraCache-Delivery-Request-Snapshot-Version;
    unset bereq.http.X-UltraCache-Delivery-Private-Cache-Version;
    unset bereq.http.X-UltraCache-Delivery-Private-Document-Version;
    unset bereq.http.X-UltraCache-Delivery-Recovery;
    unset bereq.http.X-SCP-Private-Check;
    unset bereq.http.X-SCP-Admin-Remaining;
    unset bereq.http.X-SCP-Admin-Applied;
    unset bereq.http.X-SCP-Admin-Reuse;
    unset bereq.http.X-SCP-Admin-Input;
    unset bereq.http.X-SCP-Admin-Request-Variant;
    unset bereq.http.X-SCP-Admin-Keep;
    unset bereq.http.X-SCP-Admin-Matched;
    unset bereq.http.X-SCP-Admin-Filtered;
    unset bereq.http.X-SCP-Admin-Variant;
    unset bereq.http.X-SCP-Admin-Has-Variant;
    unset bereq.http.X-SCP-Admin-Rule;
    unset bereq.http.X-SCP-Admin-Scope;
    unset bereq.http.X-SCP-Admin-Action;
    unset bereq.http.Surrogate-Capability;
    unset bereq.http.X-SCP-Fbp-Enabled;
    unset bereq.http.X-SCP-Fbp-Consent;
    unset bereq.http.X-SCP-Fbp-Domain;
    unset bereq.http.X-SCP-Fbp-Index;
    unset bereq.http.X-SCP-Fbp-New;
    unset bereq.http.X-SCP-Cookie-Name;
    unset bereq.http.X-SCP-Cookie-Role;
    if (bereq.http.X-SCP-Profile == "ultracache") {
        # Routing/selection scratch has completed its request-side work. Free
        # its header slots BEFORE adding the authenticated prepare envelope.
        # Keep representation fields: native Vary still reads them at storage.
        unset bereq.http.X-SCP-CMS;
        unset bereq.http.X-SCP-CMS-Path;
        unset bereq.http.X-SCP-CMS-Query;
        unset bereq.http.X-SCP-Selection-Operation;
        unset bereq.http.X-SCP-Selection-Eligible;
        unset bereq.http.X-SCP-Selection-State;
        unset bereq.http.X-SCP-Selection-Names;
        unset bereq.http.X-SCP-Selection-Scope;
        unset bereq.http.X-SCP-Selection-Actions;
        # These are request-owned delivery/routing carriers, not origin inputs.
        # The top request retains them for ESI and the final cache-status label.
        unset bereq.http.X-ESI-Original-Cookie;
        unset bereq.http.X-UltraCache-ESI-Opt-In;
        unset bereq.http.X-SCP-Pass;
        call scp_selection_origin;
        unset bereq.http.X-SCP-Selection-Native-Policy;
        call scp_ultracache_backend_fetch;
    }
    unset bereq.http.X-SCP-Selection-Native-Policy;
    unset bereq.http.X-SCP-Selection-Operation;
    unset bereq.http.X-SCP-Selection-Eligible;
    unset bereq.http.X-SCP-Selection-State;
    unset bereq.http.X-SCP-Selection-Names;
    unset bereq.http.X-SCP-Selection-Scope;
    unset bereq.http.X-SCP-Selection-Actions;
    unset bereq.http.X-SCP-Adaptive-Nonce;
    unset bereq.http.X-SCP-Warm-Projection-Supported;
}
sub scp_backend_response {
    if (cookie_handoff.mutation_backend_response()) {}
    unset beresp.http.X-UltraCache-Guest-Issuer-Version;
    unset beresp.http.X-UltraCache-Guest-Issuer-Canonical-URL;
    unset beresp.http.X-UltraCache-Guest-Issuer-Authorization;
    unset beresp.http.X-UltraCache-Guest-Publication;
    if (!cookie_handoff.delivery_local_source()) {
        unset beresp.http.X-SCP-Guest-Key;
        unset beresp.http.X-SCP-Guest-Manifest;
        unset beresp.http.X-SCP-Guest-Complete;
    }
    if (bereq.http.X-SCP-Profile == "ultracache") { call scp_private_backend_response; }
    unset beresp.http.X-SCP-Reuse-Metadata;
    unset beresp.http.X-SCP-Delivery-Public-Snapshot;
    unset beresp.http.X-SCP-Personal-Delivery;
    unset beresp.http.X-SCP-Public-Fragment;
    unset beresp.http.X-SCP-Fragment-HTTP-Failure;
    if (bereq.http.X-SCP-Profile == "ultracache") {
        # Only the application's early publication reader may declare this:
        # no WP/provider ran and no issuer fields can be discarded/repeated.
        # Capture before response-cookie detachment or any local rewriting.
        if (beresp.http.X-UltraCache-Delivery-Parent-Source == "public-snapshot-v1" &&
            !beresp.http.Set-Cookie && beresp.status == 200) {
            set beresp.http.X-SCP-Delivery-Public-Snapshot = "1";
        }
        if (cookie_handoff.delivery_conflict_response()) {}
        if (cookie_handoff.delivery_recovery_response()) {}
    }
    unset beresp.http.X-UltraCache-Delivery-Parent-Source;
    # An origin echo must never put the backend-only credential in an object.
    unset beresp.http.X-UltraCache-Delivery-Authorization;
    unset beresp.http.X-UltraCache-Delivery-Manifest;
    unset beresp.http.X-UltraCache-Delivery-Request;
    unset beresp.http.X-UltraCache-Delivery-Original-URL;
    unset beresp.http.X-UltraCache-Delivery-Phase;
    unset beresp.http.X-UltraCache-Delivery-Version;
    unset beresp.http.X-UltraCache-Delivery-Recovery-Version;
    unset beresp.http.X-UltraCache-Delivery-Request-Snapshot-Version;
    unset beresp.http.X-UltraCache-Delivery-Private-Cache-Version;
    unset beresp.http.X-UltraCache-Delivery-Private-Document-Version;
    unset beresp.http.X-SCP-Reason;
    unset beresp.http.X-SCP-Client-Vary;
    unset beresp.http.X-SCP-Result;
    unset beresp.http.X-SCP-Result-Reason;
    std.collect(beresp.http.Cache-Control);
    std.collect(beresp.http.Surrogate-Control);
    std.collect(beresp.http.Vary);
    if (beresp.http.Vary != "*") {
        if (!beresp.http.Vary) { set beresp.http.Vary = "X-Forwarded-Proto"; }
        else if (beresp.http.Vary !~ "(?i)(^|,)[[:blank:]]*X-Forwarded-Proto[[:blank:]]*(,|$)") {
            set beresp.http.Vary = beresp.http.Vary + ", X-Forwarded-Proto";
        }
    }
    if (bereq.http.X-SCP-Profile == "ultracache") {
        call scp_ultracache_personal_response;
        call scp_ultracache_public_fragment_response;
        call scp_ultracache_fragment_http_response;
    }
    call scp_aggressive_backend_response;
    call scp_shared_response_cookies;
    call scp_response_privacy;
    if (bereq.http.X-SCP-Profile == "ultracache") { call scp_ultracache_backend_response; }
    # The prepare capture consumes its own outcome before this cleanup. An
    # ordinary origin response cannot store a delivery verdict in the parent.
    unset beresp.http.X-UltraCache-Delivery-Guest-Publication-Canonical-URL;
    unset beresp.http.X-UltraCache-Delivery-Guest-Publication-Version;
    unset beresp.http.X-UltraCache-Delivery-Guest-Publication-Policy;
    unset beresp.http.X-UltraCache-VCL-Guest-Publication-Version;
    unset beresp.http.X-UltraCache-VCL-Guest-Publication-Policy;
    unset beresp.http.X-UltraCache-VCL-Publication-Reselect-Version;
    unset beresp.http.X-UltraCache-Delivery-Conflict-Version;
    unset beresp.http.X-UltraCache-Delivery-Conflict;
    unset beresp.http.X-UltraCache-Delivery-Manifest-SHA256;
    unset beresp.http.X-UltraCache-Delivery-Outcome;
    unset beresp.http.X-UltraCache-VCL-Delivery-Outcome-Version;
    unset beresp.http.X-UltraCache-VCL-Cookie-Delivery-Version;
    # Static and dynamic responses both retain functional Cookie variation.
    # Only resolved Shared pairs are omitted from the internal Cookie key.
    call scp_representation_response;
    call scp_response_variants;
}
sub scp_deliver {
    if (cookie_handoff.guest_shared_pending() && !cookie_handoff.guest_result()) {
        if (cookie_handoff.guest_fallback()) { return (restart); }
        return (synth(503, "Guest delivery proof unavailable"));
    }
    unset resp.http.X-UltraCache-VCL-Guest-Inputs-Version;
    unset resp.http.X-SCP-Warm-Projection-Supported;
    unset resp.http.X-UltraCache-Warm-Projection;
    unset resp.http.X-UltraCache-Warm-Projection-Authorization;
    if (cookie_handoff.guest_warm_parent_result()) {
        set resp.http.X-UltraCache-Warm-Projection = "parent-v1";
    }
    unset resp.http.X-UltraCache-Guest-Issuer-Version;
    unset resp.http.X-UltraCache-Guest-Issuer-Canonical-URL;
    unset resp.http.X-UltraCache-Guest-Issuer-Authorization;
    unset resp.http.X-UltraCache-Delivery-Guest-Publication-Canonical-URL;
    unset resp.http.X-UltraCache-Delivery-Guest-Publication-Version;
    unset resp.http.X-UltraCache-Delivery-Guest-Publication-Policy;
    unset resp.http.X-UltraCache-VCL-Guest-Publication-Version;
    unset resp.http.X-UltraCache-VCL-Guest-Publication-Policy;
    unset resp.http.X-UltraCache-VCL-Publication-Reselect-Version;
    unset resp.http.X-UltraCache-Delivery-Conflict-Version;
    unset resp.http.X-UltraCache-Delivery-Conflict;
    unset resp.http.X-UltraCache-Delivery-Manifest-SHA256;
    unset resp.http.X-UltraCache-Delivery-Outcome;
    unset resp.http.X-UltraCache-VCL-Delivery-Outcome-Version;
    unset resp.http.X-UltraCache-VCL-Cookie-Delivery-Version;
    call scp_private_deliver;
    unset resp.http.X-SCP-Personal-Delivery;
    unset resp.http.X-SCP-Public-Fragment;
    unset resp.http.X-SCP-Fragment-HTTP-Failure;
    unset resp.http.X-UltraCache-Delivery-Authorization;
    unset resp.http.X-UltraCache-Delivery-Manifest;
    unset resp.http.X-UltraCache-Delivery-Recovery;
    unset resp.http.X-UltraCache-Delivery-Recovery-Version;
    unset resp.http.X-UltraCache-Delivery-Request-Snapshot-Version;
    unset resp.http.X-UltraCache-Delivery-Private-Cache-Version;
    unset resp.http.X-UltraCache-Delivery-Private-Document-Version;
    unset resp.http.X-UltraCache-Delivery-Public-Selection-Version;
    unset resp.http.X-UltraCache-Delivery-Public-Selection-Scope;
    unset resp.http.X-UltraCache-Delivery-Policy;
    unset resp.http.X-UltraCache-Delivery-WordPress-Policy;
    unset resp.http.X-UltraCache-Delivery-Public-Selection-Actions;
    unset resp.http.X-UltraCache-VCL-Public-Selection-Version;
    unset resp.http.X-UltraCache-VCL-Public-Selection-Canonical-Host;
    unset resp.http.X-UltraCache-VCL-Public-Selection-Coverage-Version;
    unset resp.http.X-UltraCache-VCL-Public-Selection-Coverage-Policy;
    unset resp.http.X-UltraCache-VCL-Public-Selection-Scope;
    unset resp.http.X-UltraCache-VCL-Public-Selection-Epoch;
    unset resp.http.X-UltraCache-VCL-Public-Selection-Native-Policy;
    unset resp.http.X-UltraCache-VCL-Public-Selection-WordPress-Policy;
    unset resp.http.X-UltraCache-VCL-Public-Selection-Actions;
    if (req.http.X-SCP-Profile == "ultracache") { call scp_ultracache_deliver; }
    else { unset resp.http.X-UltraCache-Cookie-Delivery; }
    call scp_public_source_diagnostic;
    unset resp.http.X-UltraCache-Private-Cache;
    if (req.http.X-SCP-Profile == "ultracache" && req.esi_level == 0) {
        set resp.http.X-UltraCache-Private-Cache = cookie_handoff.delivery_cache_outcome();
    }
    if (req.http.X-SCP-Profile == "ultracache" && req.esi_level == 0 && !cookie_handoff.guest_result()) {
        set resp.http.X-UltraCache-Delivery-Outcome = cookie_handoff.delivery_outcome();
    }
    unset resp.http.X-UltraCache-Guest-Publication;
    if (req.http.X-SCP-Profile == "ultracache" && cookie_handoff.guest_result()) {
        set resp.http.X-UltraCache-Guest-Publication = "1";
    }
    unset resp.http.X-SCP-Guest-Key;
    unset resp.http.X-SCP-Guest-Manifest;
    unset resp.http.X-SCP-Guest-Complete;
    unset resp.http.X-UltraCache-Delivery-Parent-Source;
    unset resp.http.X-SCP-Delivery-Public-Snapshot;
    cookie_handoff.deliver();
    if (req.http.X-SCP-Aggressive == "1") { set resp.http.X-Cache-Mode = "aggressive"; }
    else { set resp.http.X-Cache-Mode = "standard"; }
    call scp_aggressive_deliver;
    if (req.http.X-SCP-Pass == "1" || obj.uncacheable) {
        set resp.http.X-SCP-Result = "PASS";
        if (req.http.X-SCP-Reason) { set resp.http.X-SCP-Result-Reason = req.http.X-SCP-Reason; }
        else if (resp.http.X-SCP-Reason) { set resp.http.X-SCP-Result-Reason = resp.http.X-SCP-Reason; }
        else { set resp.http.X-SCP-Result-Reason = "origin-uncacheable"; }
    } else if (obj.hits > 0) {
        set resp.http.X-SCP-Result = "HIT";
        set resp.http.X-SCP-Result-Reason = "cached-response";
    } else {
        set resp.http.X-SCP-Result = "MISS";
        set resp.http.X-SCP-Result-Reason = "fetch-required";
    }
    set resp.http.X-Cache = resp.http.X-SCP-Result;
    unset resp.http.X-Cache-Cookie-Delivery;
    # Original provider fields reach only this visitor, regardless of name.
    if (resp.http.Set-Cookie) { call scp_private_delivery; }
    if (req.http.X-SCP-Profile == "ultracache" && cookie_handoff.selection_manifest() && resp.http.X-UltraCache-Guest-Publication != "1") {
        # The native replica remains public. A downstream cache must not skip
        # the real per-request provider selection, even without issuer fields.
        call scp_private_delivery;
    }
    if (req.http.X-SCP-Profile == "ultracache" &&
        (resp.http.X-UltraCache-ESI-Private-Count ~ "^[1-9][0-9]*$" ||
         (!resp.http.X-UltraCache-ESI-Private-Count && resp.http.X-UltraCache-ESI-Shared-Parent == "1"))) {
        # The reusable template declares private-capable occurrences, including
        # adaptive nonces. Protect delivery before ESI selects current identity.
        call scp_private_delivery;
    }
    unset resp.http.X-Cache-Hits;
    if (resp.http.X-Cache == "HIT") { set resp.http.X-Cache-Hits = obj.hits; }
    if (resp.http.X-SCP-Client-Vary) { set resp.http.Vary = resp.http.X-SCP-Client-Vary; }
    set resp.http.Vary = regsuball(resp.http.Vary,
        "(?i)(^|,)[[:blank:]]*X-SCP-Vary-Cookie[[:blank:]]*(?=,|$)", "\1Cookie");
    set resp.http.Vary = regsuball(resp.http.Vary,
        "(?i)(^|,)[[:blank:]]*X-SCP-Vary-ESI-Cookie[[:blank:]]*(?=,|$)", "\1Cookie");
    set resp.http.Vary = regsuball(resp.http.Vary,
        "(?i)(^|,)[[:blank:]]*X-SCP-Vary-Accept[[:blank:]]*(?=,|$)", "\1Accept");
    set resp.http.Vary = regsuball(resp.http.Vary,
        "(?i)(^|,)[[:blank:]]*X-SCP-Vary-Accept-Language[[:blank:]]*(?=,|$)", "\1Accept-Language");
    unset resp.http.X-SCP-Vary-Accept;
    unset resp.http.X-SCP-Vary-Accept-Language;
    unset resp.http.X-SCP-Normalize-Value;
    unset resp.http.X-SCP-Client-Vary;
    unset resp.http.X-SCP-Reason;
    unset resp.http.X-SCP-Key-URL;
    unset resp.http.X-SCP-Profile;
    unset resp.http.X-SCP-Vary-Cookie;
    unset resp.http.X-SCP-Vary-ESI-Cookie;
    unset resp.http.X-SCP-HTML-Accept;
    unset resp.http.X-UltraCache-ESI-Shared-Parent;
    unset resp.http.X-UltraCache-ESI-Candidate;
    unset resp.http.X-UltraCache-ESI-Opt-In;
    call scp_cookie_diagnostics;
    # Explicit public variants are keyed internally even without origin Vary.
    # Private selectors require the same downstream signal for their absent
    # public response, before an outer cache could skip our private guard.
    # Tell downstream caches about Cookie without adding unrelated Cookie
    # dimensions to Varnish's own lookup. Include the no-cookie representation.
    if (req.http.X-SCP-Admin-Has-Variant == "1" && resp.http.Vary != "*" &&
        resp.http.Vary !~ "(?i)(^|,)[[:blank:]]*Cookie[[:blank:]]*(,|$)") {
        if (resp.http.Vary) { set resp.http.Vary = resp.http.Vary + ", Cookie"; }
        else { set resp.http.Vary = "Cookie"; }
    }
    if (req.http.X-SCP-Admin-Action == "private") { call scp_private_delivery; }
}
