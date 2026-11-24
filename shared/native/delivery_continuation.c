/* SPDX-License-Identifier: GPL-3.0-or-later
 * Included by cookie_handoff.c. Candidate UltraCache-only continuation.
 * No worker, cookie issuer, public cookie jar or persistent visitor state. */
#include <stdio.h>
#include <strings.h>
#include "cache/cache_filter.h"
#include "vcl.h"
#include "vrt_obj.h"
#include "delivery_envelope.h"
#include "delivery_reuse_wire.h"
#include "delivery_mutation_wire.h"

/* Separate top-request eligibility storage does not create a continuation. */
static const char guest_top_token;
struct guest_request {
    unsigned captured, eligible, disabled;
    unsigned shared_candidate, shared_proved, fallback_restart;
    char *original_cookie, *site, *host, *url;
    char *classified_cookie, *classified_variant, *projected_variant;
    unsigned classified, projected_variant_restart;
    char shared_manifest[65];
    unsigned warm_requested, warm_single, warm_checked, warm_valid;
    char *warm_projection, *warm_authorization;
    char *key, *policy, *wordpress_policy, *epoch, *scope;
};
static void guest_fini(VRT_CTX, void *value) {
    struct guest_request *g = value;
    (void)ctx;
    free(g->warm_projection); free(g->warm_authorization);
    free(g->original_cookie); free(g->site); free(g->host); free(g->url);
    free(g->classified_cookie); free(g->classified_variant); free(g->projected_variant);
    free(g->key); free(g->policy); free(g->wordpress_policy); free(g->epoch); free(g->scope); free(g);
}
static const struct vmod_priv_methods guest_methods = {
    .magic = VMOD_PRIV_METHODS_MAGIC, .type = "ultracache-guest-top", .fini = guest_fini,
};
static struct guest_request *guest_context(VRT_CTX) {
    struct vmod_priv *p = VRT_priv_top_get(ctx,&guest_top_token);
    return p ? p->priv : NULL;
}
VCL_VOID vmod_guest_ingress(VRT_CTX) {
    struct vmod_priv *p;
    struct guest_request *g;
    if (ctx->req->esi_level || ctx->req->restarts) return;
    p = VRT_priv_top(ctx,&guest_top_token);
    if (!p) { VRT_fail(ctx,"Guest ingress association unavailable"); return; }
    if (p->priv) return;
    g = calloc(1,sizeof(*g));
    if (!g) { VRT_fail(ctx,"Guest ingress state unavailable"); return; }
    g->captured = 1;
    g->eligible = !http_CountHdr(ctx->http_req,H_Cookie) && !http_CountHdr(ctx->http_req,H_Authorization);
    if (!http_CountHdr(ctx->http_req,H_Authorization) && http_CountHdr(ctx->http_req,H_Cookie) == 1) {
        const char *cookie;
        if (http_GetHdr(ctx->http_req,H_Cookie,&cookie)) {
            g->original_cookie = strdup(cookie);
            if (!g->original_cookie) { free(g); VRT_fail(ctx,"Guest original input unavailable"); return; }
        }
    }
    p->priv = g; p->methods = &guest_methods;
    {
        const hdr_t projection = HDR("X-UltraCache-Warm-Projection");
        const hdr_t authorization = HDR("X-UltraCache-Warm-Projection-Authorization");
        const char *value;
        unsigned fields = http_CountHdr(ctx->http_req,projection), proofs = http_CountHdr(ctx->http_req,authorization);
        g->warm_requested = fields || proofs;
        g->warm_single = fields == 1 && proofs == 1;
        if (http_GetHdr(ctx->http_req,projection,&value)) g->warm_projection = strdup(value);
        if (http_GetHdr(ctx->http_req,authorization,&value)) g->warm_authorization = strdup(value);
    }
}
static void guest_disable(VRT_CTX) {
    struct guest_request *g = guest_context(ctx);
    if (g) g->disabled = 1;
}
VCL_STRING vmod_guest_key(VRT_CTX) {
    struct guest_request *g;
    if (ctx->req->esi_level) return NULL;
    g = guest_context(ctx);
    return g && !g->disabled && g->key ? WS_Copy(ctx->ws,g->key,-1) : NULL;
}
VCL_BOOL vmod_guest_shared_pending(VRT_CTX) {
    struct guest_request *g = guest_context(ctx);
    return !ctx->req->esi_level && g && g->shared_candidate && !g->disabled;
}
VCL_BOOL vmod_guest_fallback(VRT_CTX) {
    struct guest_request *g = guest_context(ctx);
    if (!vmod_guest_shared_pending(ctx) || ctx->req->restarts >= ctx->req->max_restarts) return 0;
    g->disabled = 1; g->shared_proved = 0;
    g->fallback_restart = ctx->req->restarts+1;
    return 1;
}
VCL_BOOL vmod_guest_fallback_ready(VRT_CTX) {
    struct guest_request *g = guest_context(ctx);
    const char *host;
    return !ctx->req->esi_level && g && g->disabled && g->shared_candidate &&
        g->fallback_restart && g->fallback_restart == ctx->req->restarts && g->url && g->host &&
        !strcmp(ctx->http_req->hd[HTTP_HDR_METHOD].b,"GET") &&
        !strcmp(ctx->http_req->hd[HTTP_HDR_URL].b,g->url) &&
        http_GetHdr(ctx->http_req,H_Host,&host) && !strcmp(host,g->host);
}

VCL_BOOL vmod_guest_warm_parent_result(VRT_CTX) {
    struct guest_request *g;
    if (ctx->req->esi_level) return 0;
    g = guest_context(ctx);
    return g && g->warm_valid && g->disabled && !g->key;
}

VCL_STRING vmod_guest_issuer_authorization(VRT_CTX, VCL_STRING credential, VCL_STRING canonical) {
    const char *host = NULL, *start, *end, *method, *url, *message;
    char *normalized;
    char digest[65];
    size_t i, length;
    method = ctx->http_bereq->hd[HTTP_HDR_METHOD].b; url = ctx->http_bereq->hd[HTTP_HDR_URL].b;
    if (!credential || !*credential || !delivery_relative(canonical) || !method || strcmp(method,"POST") ||
        !url || http_CountHdr(ctx->http_bereq,H_Host) != 1 || !http_GetHdr(ctx->http_bereq,H_Host,&host)) return NULL;
    start = host; while (*start == ' ' || *start == '\t') ++start;
    end = start+strlen(start); while (end > start && (end[-1] == ' ' || end[-1] == '\t')) --end;
    length = (size_t)(end-start); normalized = WS_Copy(ctx->ws,start,-1);
    if (!normalized || !length) return NULL;
    normalized[length] = 0;
    for (i = 0; i < length; ++i)
        if (normalized[i] >= 'A' && normalized[i] <= 'Z') normalized[i] += 'a'-'A';
    message = WS_Printf(ctx->ws,"ultracache-guest-issuer-v1\nPOST\n%s\n%s\n%s",normalized,url,canonical);
    if (!message || !delivery_hmac_sha256((const unsigned char *)credential,strlen(credential),
        (const unsigned char *)message,strlen(message),digest)) return NULL;
    return WS_Printf(ctx->ws,"v1:%s",digest);
}

enum delivery_phase { D_QUEUED, D_PREPARE, D_RETURN, D_READY,
    D_RECOVERY_QUEUED, D_RECOVERY, D_DELIVERED, D_DOCUMENT, D_DOCUMENT_SENT,
    D_RAW_PASS, D_RAW_DELIVERED, D_CONFLICT, D_RESELECT_QUEUED, D_RESELECT_READY,
    D_FINALIZE_QUEUED, D_FINALIZE, D_FINALIZE_RETURN, D_SOURCE_PERSONAL_QUEUED,
    D_HELD_QUEUED, D_HELD_LOOKUP, D_HELD_RETURN, D_HELD_RESUME, D_FAILED };
enum public_source_stage { SOURCE_NONE, SOURCE_RESOLVER, SOURCE_CAPTURE, SOURCE_PERSONAL, SOURCE_COMPLETE };
enum reuse_lookup_result { REUSE_PLAN_MISS, REUSE_PLAN_HIT, REUSE_PLAN_HELD };
struct delivery_reuse_plan;
struct delivery_held_wait;
struct reuse_scope;
static void delivery_reuse_release(VRT_CTX, struct delivery_reuse_plan *);
static void delivery_held_fini(VRT_CTX, struct continuation *);
struct continuation {
    struct task association; /* only its owner slot is used */
    enum delivery_phase phase;
    unsigned restart, sent, complete, failed;
    unsigned recovery_ready, recovery_sent, recovery_received, recovery_restart;
    unsigned snapshot_ready, snapshot_mode;
    unsigned selection_entry;
    unsigned reselect_attempted, conflict_verified;
    unsigned cold_entry;
    enum public_source_stage source_stage;
    enum public_source_stage source_next;
    unsigned source_declined;
    unsigned source_projected, source_resolved_response, source_reselected, source_unstable;
    char *source_url, *source_cookie, *source_manifest;
    char *resolver_cookie, *projection_header;
    struct delivery_public_projection *projection;
    char source_generation[65];
    double source_deadline;
    unsigned guest_requested, guest_reply, guest_complete, guest_has_variant;
    char *guest_policy, *guest_epoch, *guest_key, *guest_canonical;
    unsigned cookie_delivery;
    unsigned debug_fallback;
    unsigned outcome; /* 0 unverified, 1 verified, 2 degraded; this owner only */
    double public_deadline, prepare_response_time;
    uint64_t occurrences;
    /* Identity check only; exact installed-engine lifetime still needs native
     * qualification. Also revalidate signed manifest/count on final delivery.
     * Never swap engine pointers. Default builds do not call private HSH APIs;
     * the experimental resolver requires a matching engine-source receipt. */
    const struct objcore *parent;
    char *url, *host, *site, *target, *manifest, *cookie, *encoding;
    char *retire_expression;
    char *selection_rules, *selection_policy, *wordpress_policy, *selection_actions, *selection_scope;
    char *candidate, *variant, *lookup_variant;
    char *conditional[6];
    char request_id[32];
    char *body;
    size_t length, capacity;
    struct delivery_fragment *fragments;
    struct delivery_reuse_plan *reuse_plan; /* same top-request owner, not a body store */
    struct delivery_public_parent *public_parent; /* same-request public bytes */
    struct delivery_private_document *document;
    struct delivery_public_selection *selection;
    char reuse_origin_request[65], reuse_origin_challenge[65], reuse_recipe[65];
    char reuse_publication[65], reuse_representation[65];
    char *reuse_scope;
    char reuse_epoch[65], reuse_incarnation[65], reuse_native_policy[65], reuse_wp_policy[65], reuse_policy[65];
    unsigned reuse_negotiated;
    struct delivery_reuse_candidate *reuse_candidate;
    char reuse_binding[65], reuse_metadata_key[65];
    char *reuse_finalize_header, *reuse_metadata_uri;
    unsigned reuse_final_restart, reuse_done, reuse_failed, reuse_fetched, reuse_retry;
    unsigned reuse_fast;
    /* A pinned read cut is request-local ordering, not a scope CLEAN grant. */
    uint64_t reuse_execution_cut;
    unsigned reuse_cut_active, reuse_cut_provisional, held_restart, held_result;
    char held_key[65], held_uri[sizeof("/__ultracache-native/held-v1/")+64];
    struct objcore *held_parent, *held_metadata;
    struct delivery_held_wait *held_wait;
    char reuse_discovery_revision[65];
    struct delivery_reuse_record *reuse_record;
    struct fields *public_headers;
    struct fields *document_headers;
};
static const char *delivery_personal_cookie(const struct continuation *d) {
    return d->resolver_cookie ? d->resolver_cookie : d->cookie ? d->cookie : "";
}
static int delivery_snapshot_headers(VRT_CTX, struct continuation *);
static int public_selection_parse(VRT_CTX, struct continuation *);
static int public_selection_vcl_event(enum vcl_event_e);
static void reuse_registry_free(void);
static int delivery_reuse_capture_parent(VRT_CTX, struct continuation *);
static void delivery_reuse_candidate_capture(VRT_CTX, struct continuation *, const char *, size_t);
static int delivery_reuse_schedule(VRT_CTX, struct vmod_priv *, struct continuation *);
static int delivery_reuse_recv(VRT_CTX, struct continuation *);
static int delivery_reuse_finish(VRT_CTX, struct continuation *);
static int delivery_reuse_try_hit(VRT_CTX, struct vmod_priv *, struct continuation *);
static int delivery_held_recv(VRT_CTX, struct continuation *);
static int delivery_held_finish(VRT_CTX, struct vmod_priv *, struct continuation *);
#ifdef UC_NATIVE_PRIVATE_REUSE
static int delivery_held_schedule(VRT_CTX, struct continuation *, struct reuse_scope *);
static void delivery_held_drop(VRT_CTX, struct continuation *);
#endif
static const char filter_task_token;
static const char private_filter_task_token;
static const hdr_t h_key = HDR("X-SCP-Cookie-Handoff");
static const hdr_t h_version = HDR("X-UltraCache-Delivery-Version");
static const hdr_t h_phase = HDR("X-UltraCache-Delivery-Phase");
static const hdr_t h_request = HDR("X-UltraCache-Delivery-Request");
static const hdr_t h_original = HDR("X-UltraCache-Delivery-Original-URL");
static const hdr_t h_manifest = HDR("X-UltraCache-Delivery-Manifest");
static const hdr_t h_recovery = HDR("X-UltraCache-Delivery-Recovery");
static const hdr_t h_recovery_version = HDR("X-UltraCache-Delivery-Recovery-Version");
static const hdr_t h_request_snapshot_version = HDR("X-UltraCache-Delivery-Request-Snapshot-Version");
static const hdr_t h_private_key = HDR("X-SCP-Private-Key");
static const hdr_t h_private_cache_version = HDR("X-UltraCache-Delivery-Private-Cache-Version");
static const hdr_t h_adapter_site = HDR("X-SCP-Site");
static const hdr_t h_private_document_version = HDR("X-UltraCache-Delivery-Private-Document-Version");
static const hdr_t h_selection_version = HDR("X-UltraCache-Delivery-Public-Selection-Version");
static const hdr_t h_selection_policy = HDR("X-UltraCache-Delivery-Policy");
static const hdr_t h_wordpress_policy = HDR("X-UltraCache-Delivery-WordPress-Policy");
static const hdr_t h_selection_actions = HDR("X-UltraCache-Delivery-Public-Selection-Actions");
static const hdr_t h_selection_scope = HDR("X-UltraCache-Delivery-Public-Selection-Scope");
static const char selection_content_type[] = "application/vnd.ultracache.delivery+json";
static const hdr_t h_reselect_version = HDR("X-UltraCache-VCL-Publication-Reselect-Version");
static const hdr_t h_conflict_version = HDR("X-UltraCache-Delivery-Conflict-Version");
static const hdr_t h_conflict = HDR("X-UltraCache-Delivery-Conflict");
static const hdr_t h_manifest_digest = HDR("X-UltraCache-Delivery-Manifest-SHA256");
static const hdr_t h_set_cookie2 = HDR("Set-Cookie2");
static const hdr_t h_contained_error = HDR("X-UltraCache-ESI-Error-Contained");
static const hdr_t h_delivery_outcome = HDR("X-UltraCache-Delivery-Outcome");
static const hdr_t h_lookup_variant = HDR("X-SCP-Admin-Variant");
static const hdr_t h_cookie_delivery = HDR("X-UltraCache-Cookie-Delivery");
static const hdr_t h_guest_version = HDR("X-UltraCache-Delivery-Guest-Publication-Version");
static const hdr_t h_guest_policy = HDR("X-UltraCache-Delivery-Guest-Publication-Policy");
static const hdr_t h_guest_object_key = HDR("X-SCP-Guest-Key");
static const hdr_t h_guest_object_manifest = HDR("X-SCP-Guest-Manifest");
static const hdr_t h_guest_object_complete = HDR("X-SCP-Guest-Complete");
static const hdr_t h_surrogate_control = HDR("Surrogate-Control");
static const hdr_t conditional_headers[] = {
    HDR("Range"), HDR("If-None-Match"), HDR("If-Modified-Since"), HDR("If-Match"),
    HDR("If-Unmodified-Since"), HDR("If-Range")
};

static struct handoff *delivery_entry(uint64_t key) {
    struct handoff *e = buckets[key % BUCKETS];
    while (e && e->key != key) e = e->next;
    return e;
}
static const struct delivery_fragment *delivery_fragment_named(const struct continuation *d, const char *url) {
    const struct delivery_fragment *f;
    if (!d || !url) return NULL;
    for (f = d->fragments; f; f = f->next) if (!strcmp(f->url,url)) return f;
    return NULL;
}

static void delivery_fini(VRT_CTX, void *value) {
    struct continuation *d = value;
    unsigned i;
    /* The table lock excludes an aborting backend filter before freeing d. */
    delivery_held_fini(ctx,d);
    close_owner(&d->association);
    delivery_reuse_release(ctx,d->reuse_plan);
    delivery_reuse_candidate_free(d->reuse_candidate); free(d->reuse_scope);
    delivery_mutation_header_free(d->reuse_finalize_header); free(d->reuse_metadata_uri);
    delivery_reuse_record_free(d->reuse_record);
    free(d->guest_policy); free(d->guest_epoch); free(d->guest_key); free(d->guest_canonical);
    free(d->source_url); free(d->source_cookie); free(d->source_manifest);
    free(d->resolver_cookie); free(d->projection_header); delivery_public_projection_free(d->projection);
    free(d->retire_expression);
    free(d->url); free(d->host); free(d->site); free(d->target); free(d->cookie); free(d->encoding);
    free(d->selection_rules); free(d->selection_policy); free(d->wordpress_policy);
    free(d->selection_actions); free(d->selection_scope); free(d->candidate); free(d->variant); free(d->lookup_variant);
    delivery_selection_free(d->selection);
    delivery_manifest_free(d->manifest);
    for (i = 0; i < 6; ++i) free(d->conditional[i]);
    free(d->body); delivery_free_fragments(d->fragments);
    clear_fields(d->public_headers);
    clear_fields(d->document_headers);
    delivery_private_document_free(d->document);
    delivery_public_parent_free(d->public_parent); free(d);
}
static const struct vmod_priv_methods delivery_methods = {
    .magic = VMOD_PRIV_METHODS_MAGIC, .type = "ultracache-delivery-top", .fini = delivery_fini,
};

static int delivery_copy_header(const struct http *hp, hdr_t h, char **out) {
    const char *s;
    *out = NULL;
    if (!http_GetHdr(hp, h, &s)) return 1;
    *out = strdup(s);
    return *out != NULL;
}

static int delivery_restore_header(VRT_CTX, hdr_t h, const char *s) {
    /* Repeated owned restarts must not copy an unchanged original Cookie into
     * the finite client workspace again. Preserve absent/empty distinctions;
     * duplicate or changed fields still take the normal restore path. */
    const char *current = NULL;
    unsigned count = http_CountHdr(ctx->http_req,h);
    if ((!s && !count) || (s && count == 1 &&
        http_GetHdr(ctx->http_req,h,&current) && !strcmp(current,s)))
        return !WS_Overflowed(ctx->ws);
    http_Unset(ctx->http_req, h);
    if (s) http_ForceHeader(ctx->http_req, h, s);
    return !WS_Overflowed(ctx->ws);
}

static int delivery_restore(VRT_CTX, const struct continuation *d) {
    unsigned i;
    const char *current = ctx->http_req->hd[HTTP_HDR_URL].b;
    if (!current || strcmp(current,d->url))
        VRT_l_req_url(ctx, NULL, TOSTRAND(d->url));
    if (!delivery_restore_header(ctx, H_Host, d->host) ||
        !delivery_restore_header(ctx, H_Cookie, d->cookie) ||
        !delivery_restore_header(ctx, H_Accept_Encoding, d->encoding)) return 0;
    for (i = 0; i < 6; ++i)
        if (!delivery_restore_header(ctx, conditional_headers[i], d->conditional[i])) return 0;
    return 1;
}

static int delivery_source_resolver_update(struct continuation *d, struct delivery_public_projection *p) {
    char *candidate = NULL, *wire = NULL, *header = NULL;
    if (!delivery_public_projection_candidate(p,d->resolver_cookie ? d->resolver_cookie : d->cookie,
            d->selection_rules,&candidate) ||
        !(wire = delivery_public_projection_cookie(p,d->selection_rules)) ||
        !(header = delivery_public_projection_header(p))) {
        free(candidate); free(wire); free(header); return 0;
    }
    free(d->resolver_cookie); d->resolver_cookie = candidate;
    free(d->source_cookie); d->source_cookie = wire;
    free(d->projection_header); d->projection_header = header;
    delivery_public_projection_free(d->projection); d->projection = p;
    return 1;
}
static int delivery_parse(VRT_CTX, struct continuation *d) {
    char *legacy = NULL, *candidate = NULL;
    size_t legacy_length = 0, candidate_length = 0;
    int ok;
    if (d->source_stage == SOURCE_CAPTURE || d->source_stage == SOURCE_RESOLVER) {
        struct delivery_public_selection *source = NULL;
        struct delivery_public_projection *resolved = NULL;
        struct delivery_private_document *document = NULL;
        d->source_next = SOURCE_PERSONAL;
        if (d->source_declined) ok = d->length == 0;
        else if (d->source_projected) {
            ok = delivery_projected_selection_parse(d->body,d->length,d->request_id,
                d->source_stage == SOURCE_RESOLVER ? d->url : d->source_url,
                d->selection_policy,d->wordpress_policy,
                d->source_stage == SOURCE_RESOLVER ? DELIVERY_PROJECTED_RESOLVER : DELIVERY_PROJECTED_PARENT,
                &source,&document,&resolved);
            if (ok && resolved) {
                char *wire = delivery_public_projection_cookie(resolved,d->selection_rules);
                ok = wire && d->source_resolved_response;
                free(wire);
                if (ok && d->source_stage == SOURCE_RESOLVER) {
                    ok = delivery_source_resolver_update(d,resolved);
                    if (ok) { resolved = NULL; d->source_next = SOURCE_CAPTURE; }
                } else if (ok && !d->source_reselected) {
                    /* Only the actual visitor's resolver may issue its next
                     * public cookies. A pure source tuple is never an issuer. */
                    if (ctx->req->max_restarts > UINT_MAX-2) ok = 0;
                    else {
                        ctx->req->max_restarts += 2; /* two owned reselect phases */
                        d->source_reselected = 1; d->source_next = SOURCE_RESOLVER;
                    }
                } else if (ok) {
                    d->source_unstable = d->source_declined = 1;
                }
            } else if (ok) ok = source && !d->source_resolved_response &&
                delivery_public_projection_equal(source->resolved,d->projection);
        } else ok = delivery_public_source_parse(d->body,d->length,d->request_id,d->source_url,
            d->selection_policy,d->wordpress_policy,&source);
        if (ok && source && !d->source_declined) {
            d->source_manifest = strdup(source->manifest);
            memcpy(d->source_generation,source->parent->generation,65);
            d->source_deadline = d->prepare_response_time+(double)source->parent->fresh_remaining;
            ok = d->source_manifest != NULL;
        }
        delivery_private_document_free(document); delivery_public_projection_free(resolved);
        delivery_selection_free(source);
        free(d->body); d->body = NULL; d->length = d->capacity = 0;
        return ok;
    }
    if (d->reuse_negotiated && delivery_reuse_envelope_split(d->body,d->length,
        &legacy,&legacy_length,&candidate,&candidate_length)) {
        free(d->body); d->body = legacy; d->length = legacy_length; d->capacity = legacy_length+1;
    }
    ok = d->selection_entry ? public_selection_parse(ctx,d) :
        delivery_cookie_envelope_parse(d->body,d->length,d->request_id,d->url,
            d->occurrences,(int)d->cookie_delivery,&d->fragments,&d->public_parent,&d->document);
    if (ok && candidate && !d->document && !d->guest_complete)
        delivery_reuse_candidate_capture(ctx,d,candidate,candidate_length);
    free(candidate);
    free(d->body); d->body = NULL; d->length = d->capacity = 0;
    return ok;
}

static void delivery_log_fallback(VRT_CTX, struct continuation *d) {
    /* The application emits this aggregate only under its existing Debug
     * setting. Log after complete validation, bound to this native request. */
    if (!d->debug_fallback) return;
    d->debug_fallback = 0;
    if (ctx->vsl) VSLb(ctx->vsl,SLT_VCL_Log,
        "UltraCache prepare degraded: contained renderer fallback");
}

static int delivery_header_name(const char *line, const char *name) {
    size_t length = strlen(name);
    return !strncasecmp(line,name,length) && line[length] == ':';
}
static int delivery_connection_field(const struct http *hp, const char *line) {
    unsigned i;
    const char *colon = strchr(line,':');
    size_t length = colon ? (size_t)(colon-line) : 0;
    if (!length) return 0;
    for (i = HTTP_HDR_FIRST; i < hp->nhd; ++i) {
        const char *p = hp->hd[i].b;
        if (!p || !delivery_header_name(p,"Connection")) continue;
        p = strchr(p,':')+1;
        while (*p) {
            const char *start, *end;
            while (*p == ' ' || *p == '\t' || *p == ',') ++p;
            start = p;
            while (*p && *p != ',') ++p;
            end = p;
            while (end > start && (end[-1] == ' ' || end[-1] == '\t')) --end;
            if ((size_t)(end-start) == length && !strncasecmp(start,line,length)) return 1;
        }
    }
    return 0;
}
/* Fresh prepare headers belong to this complete visitor document. Never
 * reuse validators/CSP/length from the selected public parent or JSON wire. */
static int delivery_document_headers(const struct http *hp, struct fields **output, int encoded) {
    struct fields **tail = output;
    unsigned i;
    for (i = HTTP_HDR_FIRST; i < hp->nhd; ++i) {
        const char *line = hp->hd[i].b;
        struct fields *field;
        if (!line) continue;
        if (delivery_connection_field(hp,line) ||
            delivery_header_name(line,"Set-Cookie") || delivery_header_name(line,"Set-Cookie2") ||
            delivery_header_name(line,"Content-Type") || delivery_header_name(line,"Content-Length") ||
            (!encoded && delivery_header_name(line,"Content-Encoding")) || delivery_header_name(line,"Cache-Control") ||
            delivery_header_name(line,"Surrogate-Control") || delivery_header_name(line,"Pragma") ||
            delivery_header_name(line,"Expires") || delivery_header_name(line,"ETag") ||
            delivery_header_name(line,"Last-Modified") || delivery_header_name(line,"Age") ||
            delivery_header_name(line,"Date") || delivery_header_name(line,"Connection") ||
            delivery_header_name(line,"Transfer-Encoding") || delivery_header_name(line,"Trailer") ||
            delivery_header_name(line,"Keep-Alive") || delivery_header_name(line,"Proxy-Connection") ||
            delivery_header_name(line,"TE") || delivery_header_name(line,"Upgrade") ||
            delivery_header_name(line,"Via") || delivery_header_name(line,"Server") || delivery_header_name(line,"X-Varnish") ||
            !strncasecmp(line,"X-SCP-",6) || !strncasecmp(line,"X-HVH-",6) || !strncasecmp(line,"X-WV-",5) ||
            !strncasecmp(line,"X-Cache",7) || !strncasecmp(line,"X-Hestia-Varnish",16) ||
            !strncasecmp(line,"X-Webuzo-Varnish",16) || !strncasecmp(line,"X-UltraCache-Delivery-",22) ||
            !strncasecmp(line,"X-UltraCache-ESI-",17) ||
            !strncasecmp(line,"X-UltraCache-VCL-",sizeof("X-UltraCache-VCL-")-1) ||
            !strncasecmp(line,"X-UltraCache-Public-Selection-",sizeof("X-UltraCache-Public-Selection-")-1)) continue;
        field = calloc(1,sizeof(*field));
        if (!field) return 0;
        field->line = strdup(line);
        if (!field->line) { free(field); return 0; }
        *tail = field; tail = &field->next;
    }
    return 1;
}
static int delivery_original_owner(VRT_CTX, const struct continuation *d) {
    const char *site = NULL, *host = NULL;
    return ctx->req->esi_level == 0 && d->site &&
        http_GetHdr(ctx->http_req,h_adapter_site,&site) && !strcmp(d->site,site) &&
        http_GetHdr(ctx->http_req,H_Host,&host) && !strcmp(d->host,host) &&
        !strcmp(d->url,ctx->http_req->hd[HTTP_HDR_URL].b) &&
        !strcmp("GET",ctx->http_req->hd[HTTP_HDR_METHOD].b) &&
        ctx->req->restarts == d->restart+(d->selection_entry ? 0 : 1);
}
static int delivery_append_cookies(VRT_CTX, struct continuation *d) {
    struct fields *f;
    pthread_mutex_lock(&lock);
    for (f = d->association.owner->fields; f; f = f->next) {
        const char *line = WS_Copy(ctx->ws,f->line,-1);
        if (!line || ctx->http_resp->nhd >= ctx->http_resp->shd) { d->failed = 1; break; }
        http_SetHeader(ctx->http_resp,line);
    }
    clear_fields(d->association.owner->fields); d->association.owner->fields = NULL;
    pthread_mutex_unlock(&lock);
    return !d->failed && !WS_Overflowed(ctx->ws);
}

static enum vfp_status delivery_filter_init(VRT_CTX, struct vfp_ctx *vc, struct vfp_entry *vfe) {
    struct vmod_priv *priv = VRT_priv_task_get(ctx, &filter_task_token);
    (void)vc;
    if (!priv || !priv->priv) return VFP_ERROR;
    /* Keep only an integer key: abort may destroy the owning client early. */
    vfe->priv1 = priv->priv;
    return VFP_OK;
}
static enum vfp_status delivery_filter_pull(struct vfp_ctx *vc, struct vfp_entry *vfe, void *p, ssize_t *lp) {
    enum vfp_status status = VFP_Suck(vc,p,lp);
    uint64_t key = *(const uint64_t *)vfe->priv1;
    struct handoff *entry;
    struct continuation *d;
    int failed = 0;
    size_t needed = 0, capacity = 0;
    pthread_mutex_lock(&lock);
    entry = delivery_entry(key);
    d = entry ? entry->delivery : NULL;
    if (!d) failed = 1;
    else if (status == VFP_ERROR || *lp < 0 ||
        !delivery_buffer_growth(d->length,d->capacity,(size_t)*lp,&needed,&capacity)) failed = 1;
    else {
        if (needed > d->capacity) {
            char *body = realloc(d->body,capacity);
            if (!body) failed = 1;
            else { d->body = body; d->capacity = capacity; }
        }
        if (!failed) {
            if (*lp) memcpy(d->body+d->length,p,(size_t)*lp);
            d->length += (size_t)*lp; d->body[d->length] = '\0';
            if (status == VFP_END) d->complete = 1;
        }
    }
    if (failed && d) {
        if (d->phase == D_FINALIZE) d->reuse_failed = 1;
        else d->failed = 1;
    }
    pthread_mutex_unlock(&lock);
    if (failed) return VFP_Error(vc,"UltraCache delivery capture failed");
    return status;
}
static const struct vfp delivery_filter = {
    .name = "uc_delivery_capture", .init = delivery_filter_init, .pull = delivery_filter_pull,
};

/* Quote exact ban operands for the supported std.ban interface. */
static char *delivery_ban_operand(const char *value) {
    const unsigned char *p;
    size_t n = 0;
    char *out, *at;
    if (!value) return NULL;
    for (p = (const unsigned char *)value; *p; ++p) {
        if (*p < 32 || *p == 127 || n > SIZE_MAX-2) return NULL;
        n += (*p == '"' || *p == '\\') ? 2 : 1;
    }
    if (n > SIZE_MAX-3 || !(out = malloc(n+3))) return NULL;
    at = out; *at++ = '"';
    for (p = (const unsigned char *)value; *p; ++p) {
        if (*p == '"' || *p == '\\') *at++ = '\\';
        *at++ = (char)*p;
    }
    *at++ = '"'; *at = 0; return out;
}
static char *delivery_retirement(VRT_CTX, const struct continuation *d) {
    const char *site = NULL, *host = NULL, *url = NULL, *header = NULL;
    char *qs = NULL, *qh = NULL, *qu = NULL, *qt = NULL, *result = NULL;
    const char *expression;
    if (http_CountHdr(ctx->http_resp,HDR("X-HVH-Site")) == 1 &&
        http_GetHdr(ctx->http_resp,HDR("X-HVH-Site"),&site)) header = "X-HVH-Site";
    else if (http_CountHdr(ctx->http_resp,HDR("X-WV-Site")) == 1 &&
        http_GetHdr(ctx->http_resp,HDR("X-WV-Site"),&site)) header = "X-WV-Site";
    if (!header || !site || !d->site || strcmp(site,d->site) ||
        !http_GetHdr(ctx->http_resp,HDR("X-Cache-Object-Host"),&host) || strcmp(host,d->host) ||
        !http_GetHdr(ctx->http_resp,HDR("X-Cache-Object-URL"),&url)) return NULL;
    qs = delivery_ban_operand(site); qh = delivery_ban_operand(host);
    qu = delivery_ban_operand(url); qt = delivery_ban_operand(d->target);
    if (qs && qh && qu && qt) {
        expression = WS_Printf(ctx->ws,"obj.http.%s == %s && obj.http.X-Cache-Object-Host == %s && obj.http.X-Cache-Object-URL == %s && obj.http.X-UltraCache-Delivery-Prepare == %s",header,qs,qh,qu,qt);
        if (expression) result = strdup(expression);
    }
    free(qs); free(qh); free(qu); free(qt); return result;
}
static int delivery_header_equals(const struct http *hp, hdr_t name, const char *expected) {
    const char *value;
    return expected && http_CountHdr(hp,name) == 1 && http_GetHdr(hp,name,&value) && !strcmp(value,expected);
}
/* Only the negotiated pre-bootstrap conflict can authorize another entry. */
static int guest_object_matches(VRT_CTX, const char *key, const char *manifest) {
    const char *value;
    char digest[65];
    return key && delivery_header_equals(ctx->http_resp,h_guest_object_key,key) &&
        delivery_header_equals(ctx->http_resp,h_guest_object_complete,"1") &&
        http_CountHdr(ctx->http_resp,h_guest_object_manifest) == 1 &&
        http_GetHdr(ctx->http_resp,h_guest_object_manifest,&value) && strlen(value) == 64 &&
        strspn(value,"0123456789abcdef") == 64 &&
        (!manifest || (delivery_selection_digest((const unsigned char *)manifest,strlen(manifest),digest) &&
            !strcmp(value,digest)));
}
VCL_BOOL vmod_guest_result(VRT_CTX) {
    struct guest_request *g;
    if (ctx->req->esi_level) return 0;
    g = guest_context(ctx);
    const char *manifest;
    return g && !g->disabled && g->key && guest_object_matches(ctx,g->key,NULL) &&
        (!g->shared_candidate || (g->shared_proved &&
            http_GetHdr(ctx->http_resp,h_guest_object_manifest,&manifest) && !strcmp(manifest,g->shared_manifest)));
}

static int delivery_conflict(VRT_CTX, const struct continuation *d) {
    const char *reason;
    char digest[65];
    return !d->selection_entry && !d->reselect_attempted && d->sent == 1 && !d->failed &&
        d->retire_expression && d->manifest && !d->complete && !d->length && !d->fragments &&
        !d->public_parent && !d->document && !d->association.owner->fields &&
        http_GetStatus(ctx->http_beresp) == 409 &&
        !http_CountHdr(ctx->http_beresp,H_Set_Cookie) && !http_CountHdr(ctx->http_beresp,h_set_cookie2) &&
        delivery_header_equals(ctx->http_beresp,h_conflict_version,"1") &&
        http_CountHdr(ctx->http_beresp,h_conflict) == 1 && http_GetHdr(ctx->http_beresp,h_conflict,&reason) &&
        (!strcmp(reason,"publication-binding-mismatch") || !strcmp(reason,"public-publication-unavailable")) &&
        delivery_header_equals(ctx->http_beresp,h_request,d->request_id) &&
        delivery_header_equals(ctx->http_beresp,h_original,d->url) &&
        delivery_header_equals(ctx->http_beresp,H_Content_Length,"0") &&
        !http_CountHdr(ctx->http_beresp,H_Content_Encoding) &&
        !http_CountHdr(ctx->http_beresp,H_Transfer_Encoding) &&
        ctx->bo->htc && ctx->bo->htc->body_status == BS_NONE &&
        delivery_selection_digest((const unsigned char *)d->manifest,strlen(d->manifest),digest) &&
        delivery_header_equals(ctx->http_beresp,h_manifest_digest,digest);
}
VCL_BOOL vmod_delivery_conflict_response(VRT_CTX, struct vmod_priv *priv) {
    struct task *task = priv->priv;
    struct handoff *entry;
    struct continuation *d;
    int valid = 0;
    if (!task || !task->key) return 0;
    pthread_mutex_lock(&lock);
    entry = delivery_entry(task->key); d = entry ? entry->delivery : NULL;
    if (d && d->phase == D_PREPARE) {
        valid = d->conflict_verified = delivery_conflict(ctx,d);
    }
    pthread_mutex_unlock(&lock);
    return valid;
}
VCL_STRING vmod_delivery_retire(VRT_CTX, struct vmod_priv *priv) {
    const struct continuation *d = priv->priv;
    return d && d->phase == D_RESELECT_QUEUED && d->reselect_attempted && d->retire_expression
        ? WS_Copy(ctx->ws,d->retire_expression,-1) : NULL;
}
VCL_BOOL vmod_delivery_reselect_pending(VRT_CTX, struct vmod_priv *priv) {
    const struct continuation *d = priv->priv;
    return !ctx->req->esi_level && d && d->phase == D_RESELECT_READY && d->reselect_attempted && !d->failed;
}

VCL_INT vmod_delivery_recv(VRT_CTX, struct vmod_priv *priv) {
    struct continuation *d = priv->priv;
    const char *url;
    unsigned i;
    if (!d) return 0;
    if (!ctx->req->esi_level && (d->phase == D_HELD_QUEUED || d->phase == D_HELD_RETURN))
        return delivery_held_recv(ctx,d);
    if (!ctx->req->esi_level && d->phase == D_SOURCE_PERSONAL_QUEUED &&
        ctx->req->restarts == d->restart+1) {
        if (!delivery_restore(ctx,d)) return -1;
        http_ForceHeader(ctx->http_req,h_key,d->request_id);
        http_Unset(ctx->http_req,H_Accept_Encoding);
        for (i = 0; i < 6; ++i) http_Unset(ctx->http_req,conditional_headers[i]);
        d->restart = ctx->req->restarts; d->phase = D_PREPARE;
        d->source_stage = d->source_next ? d->source_next : SOURCE_PERSONAL;
        d->source_resolved_response = 0; d->sent = d->complete = 0;
        /* This no-resolver gate rejoins the original lookup namespace. A
         * changed actual tuple requires explicit resolver/reselection, not an
         * implicit manifest namespace that repeats source work on every HIT. */
        return WS_Overflowed(ctx->ws) ? -1 : 1;
    }
    if (!ctx->req->esi_level && (d->phase == D_FINALIZE_QUEUED || d->phase == D_FINALIZE_RETURN))
        return delivery_reuse_recv(ctx,d);
    if (ctx->req->esi_level > 0) {
        const struct delivery_fragment *f;
        /* A genuine non-protocol response retains ordinary ESI routing. It
         * has no prepared fragments and must not impersonate that contract. */
        if (d->phase == D_RAW_DELIVERED) return 0;
        if (d->phase != D_DELIVERED) return -1;
        url = ctx->http_req->hd[HTTP_HDR_URL].b;
        for (f = d->fragments; f; f = f->next) if (!strcmp(f->url,url)) {
            if (!f->cache_key || !f->cache_ttl) return 2;
            http_ForceHeader(ctx->http_req,h_private_key,f->cache_key);
            http_ForceHeader(ctx->http_req,h_key,d->request_id);
            http_Unset(ctx->http_req,H_Cookie);
            http_Unset(ctx->http_req,H_Accept_Encoding);
            return WS_Overflowed(ctx->ws) ? -1 : 3;
        }
        return 0; /* ordinary public child remains on its existing path */
    }
    if (d->phase == D_RESELECT_QUEUED && d->reselect_attempted &&
        ctx->req->restarts == d->restart+2) {
        if (!delivery_restore(ctx,d)) return -1;
        http_Unset(ctx->http_req,h_key);
        d->phase = D_RESELECT_READY;
        return 0; /* Re-run ordinary route, authorization and cookie policy. */
    }
    if ((d->phase == D_QUEUED && ctx->req->restarts == d->restart+1) ||
        (d->phase == D_RECOVERY_QUEUED && ctx->req->restarts == d->recovery_restart)) {
        int recovery = d->phase == D_RECOVERY_QUEUED;
        /* The metadata pointer is never an application request. PHP bootstrap
         * and filter_input must see the original route/query from the start. */
        url = WS_Copy(ctx->ws,d->url,-1);
        if (!url) return -1;
        VRT_l_req_url(ctx, NULL, TOSTRAND(url));
        http_ForceHeader(ctx->http_req,h_key,d->request_id);
        http_Unset(ctx->http_req,H_Accept_Encoding);
        for (i = 0; i < 6; ++i) http_Unset(ctx->http_req,conditional_headers[i]);
        d->phase = recovery ? D_RECOVERY : D_PREPARE;
        if (recovery) {
            VRT_l_req_hash_always_miss(ctx,1);
            return 0; /* normal key/variation rules, then one owned snapshot MISS */
        }
        return 1;
    }
    if (d->phase == D_RETURN && ctx->req->restarts == d->restart+(d->selection_entry ? 1 : 2)) {
        d->phase = D_READY;
        return 0;
    }
    d->phase = D_FAILED;
    return -1; /* unrelated restart cannot repeat the provider operation */
}

VCL_BOOL vmod_delivery_guard(VRT_CTX, struct vmod_priv *priv) {
    struct continuation *d = priv->priv;
    return d && ((ctx->req->esi_level == 0 && d->phase == D_READY) ||
        (ctx->req->esi_level > 0 && d->phase == D_DELIVERED));
}

/* Initial ingress authorization precedes continuation creation in managed
 * VCL. Only that SAME owned top request may resume without a client gateway.
 * Read-only: this does not advance the continuation or create another grant. */
VCL_BOOL vmod_delivery_resume_authorized(VRT_CTX, struct vmod_priv *priv, VCL_STRING site) {
    const struct continuation *d = priv->priv;
    const char *host = NULL, *url, *method;
    int phase, valid;
    if (!d) {
        const struct guest_request *g = guest_context(ctx);
        return g && site && g->site && !strcmp(site,g->site) && vmod_guest_fallback_ready(ctx);
    }
    if (!d || ctx->req->esi_level != 0 || !site || !*site || !ctx->req->restarts) return 0;
    if (!http_GetHdr(ctx->http_req,H_Host,&host)) return 0;
    url = ctx->http_req->hd[HTTP_HDR_URL].b;
    method = ctx->http_req->hd[HTTP_HDR_METHOD].b;
    pthread_mutex_lock(&lock);
    phase = ((d->phase == D_HELD_QUEUED || d->phase == D_HELD_RETURN) &&
            ctx->req->restarts == d->held_restart) ||
        (d->phase == D_RESELECT_QUEUED && d->reselect_attempted && ctx->req->restarts == d->restart+2) ||
        (d->phase == D_SOURCE_PERSONAL_QUEUED && ctx->req->restarts == d->restart+1) ||
        (d->phase == D_QUEUED && ctx->req->restarts == d->restart+1) ||
        (d->phase == D_RETURN && ctx->req->restarts == d->restart+(d->selection_entry ? 1 : 2)) ||
        ((d->phase == D_FINALIZE_QUEUED || d->phase == D_FINALIZE_RETURN) &&
            ctx->req->restarts == d->reuse_final_restart) ||
        (d->phase == D_RECOVERY_QUEUED && ctx->req->restarts == d->recovery_restart);
    valid = phase && !d->failed && method && !strcmp(method,"GET") &&
        d->site && !strcmp(d->site,site) && host && !strcmp(d->host,host) &&
        url && (!strcmp(d->url,url) || (d->phase == D_HELD_RETURN && !strcmp(d->held_uri,url)) ||
            (d->phase == D_FINALIZE_RETURN &&
            d->reuse_metadata_uri && !strcmp(d->reuse_metadata_uri,url)));
    pthread_mutex_unlock(&lock);
    return valid;
}

VCL_BOOL vmod_delivery_cookie_unchanged(VRT_CTX, struct vmod_priv *priv) {
    const struct guest_request *g = guest_context(ctx);
    const char *original, *current = NULL;
    (void)priv;
    if (ctx->req->esi_level || !g || !g->classified || http_CountHdr(ctx->http_req,H_Cookie) > 1) return 0;
    original = g->classified_cookie;
    http_GetHdr(ctx->http_req,H_Cookie,&current);
    return (!original && !current) || (original && current && !strcmp(original,current));
}

VCL_VOID vmod_cookie_classification_snapshot(VRT_CTX) {
    struct guest_request *g = guest_context(ctx);
    char *cookie = NULL, *variant = NULL;
    if (ctx->req->esi_level) return;
    if (!g || !delivery_copy_header(ctx->http_req,H_Cookie,&cookie) ||
        !delivery_copy_header(ctx->http_req,h_lookup_variant,&variant)) {
        free(cookie); free(variant);
        VRT_fail(ctx,"Cookie classification snapshot unavailable"); return;
    }
    free(g->classified_cookie); free(g->classified_variant);
    g->classified_cookie = cookie; g->classified_variant = variant; g->classified = 1;
    free(g->projected_variant); g->projected_variant = NULL;
}

VCL_VOID vmod_cookie_classification_restore(VRT_CTX) {
    const struct guest_request *g = guest_context(ctx);
    if (ctx->req->esi_level || !g || !g->classified ||
        !delivery_restore_header(ctx,h_lookup_variant,g->classified_variant))
        VRT_fail(ctx,"Cookie classification restore unavailable");
}

/* These are the same two canonical Vary carriers, not another cookie policy.
 * Keep identical single fields in place across an owned continuation. */
VCL_VOID vmod_cookie_variation_headers(VRT_CTX, VCL_STRING value, VCL_BOOL normalize) {
    const char *canonical = NULL;
    if (!value || !*value) value = NULL;
    if (!delivery_restore_header(ctx,HDR("X-SCP-Vary-Cookie"),value)) {
        VRT_fail(ctx,"Cookie variation header unavailable"); return;
    }
    if (normalize) cookie_working_header_normalize(ctx,HDR("X-SCP-Vary-Cookie"));
    http_GetHdr(ctx->http_req,HDR("X-SCP-Vary-Cookie"),&canonical);
    if (canonical && !*canonical) canonical = NULL;
    if (!delivery_restore_header(ctx,HDR("X-SCP-Vary-ESI-Cookie"),canonical))
        VRT_fail(ctx,"Cookie ESI variation header unavailable");
}

VCL_BOOL vmod_delivery_recover(VRT_CTX, struct vmod_priv *priv) {
    struct continuation *d = priv->priv;
    if (!d || ctx->req->esi_level != 0 || !d->recovery_ready || d->recovery_sent ||
        (d->phase != D_READY && d->phase != D_RECOVERY)) return 0;
    /* Capability is confirmed by the authenticated prepare response, not a
     * browser/version-only declaration. Old applications retain their guard. */
    d->phase = D_RECOVERY;
    http_ForceHeader(ctx->http_req,h_key,d->request_id);
    return !WS_Overflowed(ctx->ws);
}

/* A prepared application execution returns an uncacheable typed envelope, not
 * the representation stored by the following native snapshot fetch. Keep its
 * hash/Vary inputs on the owning request and continuation; do not spend backend
 * header slots copying those four internal storage carriers into PHP. Recovery
 * and ordinary origin fetches still retain their actual Vary input headers.
 * Run before mutation/authorization stamping as well as before the envelope:
 * waiting until after stamping can already exhaust the HTTP header table. */
static void delivery_prepare_backend_scratch(VRT_CTX, const struct continuation *d) {
    if (!d || d->phase != D_PREPARE) return;
    http_Unset(ctx->http_bereq,HDR("X-SCP-Vary-Accept"));
    http_Unset(ctx->http_bereq,HDR("X-SCP-Vary-Accept-Language"));
    http_Unset(ctx->http_bereq,HDR("X-SCP-Vary-Cookie"));
    http_Unset(ctx->http_bereq,HDR("X-SCP-Vary-ESI-Cookie"));
}

VCL_BOOL vmod_delivery_backend(VRT_CTX, struct vmod_priv *priv) {
    struct task *task = priv->priv;
    struct handoff *entry;
    struct continuation *d;
    int owned = 0, repeated = 0, association_failed = 0;
    if (!task || !task->key) return 0;
    pthread_mutex_lock(&lock);
    entry = delivery_entry(task->key); d = entry ? entry->delivery : NULL;
    if (d) {
        delivery_prepare_backend_scratch(ctx,d);
        owned = 1;
        if ((d->phase != D_PREPARE && d->phase != D_RECOVERY) ||
            (d->phase == D_PREPARE ? d->sent++ : d->recovery_sent++)) d->failed = repeated = 1;
        else {
            http_ForceHeader(ctx->http_bereq,h_version,"1");
            http_ForceHeader(ctx->http_bereq,h_phase,
                d->phase == D_PREPARE ? (d->selection_entry ? "public-select" : "prepare") : "parent-snapshot");
            http_ForceHeader(ctx->http_bereq,h_recovery_version,"1");
            http_ForceHeader(ctx->http_bereq,h_request_snapshot_version,"1");
            if (d->phase == D_PREPARE)
                http_ForceHeader(ctx->http_bereq,h_private_cache_version,"1");
            else http_Unset(ctx->http_bereq,h_private_cache_version);
            if (d->phase == D_PREPARE) http_ForceHeader(ctx->http_bereq,h_private_document_version,"1");
            else http_Unset(ctx->http_bereq,h_private_document_version);
            if (d->cookie_delivery && d->phase == D_PREPARE)
                http_ForceHeader(ctx->http_bereq,h_cookie_delivery,"1");
            else http_Unset(ctx->http_bereq,h_cookie_delivery);
            http_ForceHeader(ctx->http_bereq,h_request,d->request_id);
            http_ForceHeader(ctx->http_bereq,h_original,d->source_stage == SOURCE_CAPTURE ? d->source_url : d->url);
            if (d->source_stage == SOURCE_CAPTURE || d->source_stage == SOURCE_RESOLVER) {
                http_ForceHeader(ctx->http_bereq,HDR("X-UltraCache-Delivery-Public-Source-Version"),"1");
                http_ForceHeader(ctx->http_bereq,HDR("X-UltraCache-Delivery-Public-Source-Role"),
                    d->source_stage == SOURCE_RESOLVER ? "resolver-v1" : "parent-v1");
            } else {
                http_Unset(ctx->http_bereq,HDR("X-UltraCache-Delivery-Public-Source-Version"));
                http_Unset(ctx->http_bereq,HDR("X-UltraCache-Delivery-Public-Source-Role"));
            }
            if (d->source_projected && d->phase == D_PREPARE) {
                http_ForceHeader(ctx->http_bereq,HDR("X-UltraCache-Delivery-Public-Source-Projection-Version"),"1");
                if (d->projection_header && !d->source_declined && d->source_stage != SOURCE_RESOLVER)
                    http_ForceHeader(ctx->http_bereq,HDR("X-UltraCache-Delivery-Public-Source-Projection"),d->projection_header);
                else http_Unset(ctx->http_bereq,HDR("X-UltraCache-Delivery-Public-Source-Projection"));
            } else {
                http_Unset(ctx->http_bereq,HDR("X-UltraCache-Delivery-Public-Source-Projection-Version"));
                http_Unset(ctx->http_bereq,HDR("X-UltraCache-Delivery-Public-Source-Projection"));
            }
            if (d->phase == D_PREPARE && d->source_declined)
                http_ForceHeader(ctx->http_bereq,HDR("X-UltraCache-Delivery-Public-Source-Fallback"),
                    d->source_unstable ? "unstable-public-projection" : "public-source-unavailable");
            else http_Unset(ctx->http_bereq,HDR("X-UltraCache-Delivery-Public-Source-Fallback"));
            if (d->phase == D_PREPARE && !d->selection_entry && !d->reselect_attempted)
                http_ForceHeader(ctx->http_bereq,h_reselect_version,"1");
            else http_Unset(ctx->http_bereq,h_reselect_version);
            if (d->manifest && !d->guest_complete) http_ForceHeader(ctx->http_bereq,h_manifest,d->manifest);
            else http_Unset(ctx->http_bereq,h_manifest);
            if (d->selection_entry && d->phase == D_PREPARE) {
                http_ForceHeader(ctx->http_bereq,h_selection_version,"1");
                http_ForceHeader(ctx->http_bereq,h_selection_policy,d->selection_policy);
                http_ForceHeader(ctx->http_bereq,h_wordpress_policy,d->wordpress_policy);
                http_ForceHeader(ctx->http_bereq,h_selection_actions,d->selection_actions);
                http_ForceHeader(ctx->http_bereq,h_selection_scope,d->selection_scope);
                if (d->guest_requested) {
                    http_ForceHeader(ctx->http_bereq,h_guest_version,"1");
                    http_ForceHeader(ctx->http_bereq,h_guest_policy,d->guest_policy);
                    http_ForceHeader(ctx->http_bereq,HDR("X-UltraCache-Delivery-Guest-Publication-Canonical-URL"),d->guest_canonical);
                }
            }
            if (d->source_stage == SOURCE_CAPTURE && d->source_cookie && *d->source_cookie)
                http_ForceHeader(ctx->http_bereq,H_Cookie,d->source_cookie);
            else if (d->source_stage != SOURCE_CAPTURE &&
                ((d->resolver_cookie && *d->resolver_cookie) || (!d->resolver_cookie && d->cookie)))
                http_ForceHeader(ctx->http_bereq,H_Cookie,delivery_personal_cookie(d));
            else http_Unset(ctx->http_bereq,H_Cookie);
        }
    }
    pthread_mutex_unlock(&lock);
    if (owned && !repeated && !WS_Overflowed(ctx->ws)) {
        struct vmod_priv *filter = VRT_priv_task(ctx,&filter_task_token);
        if (!filter) association_failed = 1;
        else filter->priv = &task->key;
    }
    if (repeated) VRT_fail(ctx,"UltraCache prepare cannot be repeated");
    else if (WS_Overflowed(ctx->ws))
        VRT_fail(ctx,"UltraCache backend header slots or workspace exhausted");
    else if (association_failed)
        VRT_fail(ctx,"UltraCache prepare capture association unavailable");
    return owned;
}

/* Run before mutation_backend_start: its context signs the ACTUAL source URI
 * and actual public input wire. Native request ownership is the only selector. */
VCL_BOOL vmod_delivery_public_source_backend(VRT_CTX, struct vmod_priv *priv) {
    struct task *task = priv->priv;
    struct handoff *entry;
    struct continuation *d;
    const char *url = NULL, *cookie = NULL;
    int owned = 0, unavailable = 0;
    pthread_mutex_lock(&lock);
    entry = task && task->key ? delivery_entry(task->key) : NULL;
    d = entry ? entry->delivery : NULL;
    delivery_prepare_backend_scratch(ctx,d);
    if (d && d->phase == D_PREPARE && d->source_stage == SOURCE_CAPTURE) {
        owned = 1;
        url = WS_Copy(ctx->ws,d->source_url,-1);
        if (d->source_cookie && *d->source_cookie) cookie = WS_Copy(ctx->ws,d->source_cookie,-1);
        if (!url || (d->source_cookie && *d->source_cookie && !cookie)) d->failed = unavailable = 1;
    }
    pthread_mutex_unlock(&lock);
    if (!owned) return 0;
    if (unavailable) { VRT_fail(ctx,"Public source input unavailable"); return 0; }
    http_SetH(ctx->http_bereq,HTTP_HDR_URL,url);
    if (cookie) http_ForceHeader(ctx->http_bereq,H_Cookie,cookie);
    else http_Unset(ctx->http_bereq,H_Cookie);
    http_Unset(ctx->http_bereq,H_Authorization);
    http_Unset(ctx->http_bereq,HDR("Proxy-Authorization"));
    return !WS_Overflowed(ctx->ws);
}

VCL_BOOL vmod_delivery_recovery_response(VRT_CTX, struct vmod_priv *priv) {
    struct task *task = priv->priv;
    struct handoff *entry;
    struct continuation *d;
    const char *request, *original, *recovery;
    int owned = 0, valid = 0;
    if (!task || !task->key) return 0;
    pthread_mutex_lock(&lock);
    entry = delivery_entry(task->key); d = entry ? entry->delivery : NULL;
    if (d && d->phase == D_RECOVERY) {
        owned = 1;
        valid = http_GetStatus(ctx->http_beresp) == 200 &&
            !http_CountHdr(ctx->http_beresp,H_Set_Cookie) &&
            http_GetHdr(ctx->http_beresp,h_request,&request) && !strcmp(request,d->request_id) &&
            http_GetHdr(ctx->http_beresp,h_original,&original) && !strcmp(original,d->url) &&
            http_GetHdr(ctx->http_beresp,h_recovery,&recovery) &&
            !strcmp(recovery,d->snapshot_mode ? "request-snapshot-v1" : "public-snapshot-v1");
        if (valid) d->recovery_received = 1;
        else d->failed = 1;
    }
    pthread_mutex_unlock(&lock);
    if (owned && !valid) VRT_fail(ctx,"UltraCache public snapshot recovery rejected");
    return owned;
}

VCL_BOOL vmod_delivery_capture(VRT_CTX, struct vmod_priv *priv) {
    struct task *task = priv->priv;
    struct fields *first = NULL, **tail = &first;
    struct handoff *entry;
    struct vmod_priv *filter;
    struct continuation *d;
    const char *encoding, *recovery, *selection_version = NULL, *content_type = NULL, *contained = NULL, *outcome = NULL;
    unsigned i;
    int owned, valid, source_only, source_operation, declined;
    if (!task || !task->key) return 0;
    pthread_mutex_lock(&lock);
    entry = delivery_entry(task->key);
    d = entry ? entry->delivery : NULL;
    owned = d && d->phase == D_PREPARE;
    if (!owned) { pthread_mutex_unlock(&lock); return 0; }
    source_only = d->source_stage == SOURCE_CAPTURE;
    source_operation = source_only || d->source_stage == SOURCE_RESOLVER;
    declined = source_operation && http_GetStatus(ctx->http_beresp) == 409 &&
        delivery_header_equals(ctx->http_beresp,HDR("X-UltraCache-Delivery-Public-Source-Version"),"1") &&
        delivery_header_equals(ctx->http_beresp,HDR("X-UltraCache-Delivery-Public-Source-Outcome"),"unavailable") &&
        delivery_header_equals(ctx->http_beresp,H_Content_Length,"0") &&
        !http_CountHdr(ctx->http_beresp,H_Transfer_Encoding) && ctx->bo->htc && ctx->bo->htc->body_status == BS_NONE;
    if (declined) d->source_declined = d->complete = 1;
    http_GetHdr(ctx->http_beresp,H_Content_Type,&content_type);
    if (declined) valid = 1;
    else if (d->selection_entry) {
        http_GetHdr(ctx->http_beresp,h_selection_version,&selection_version);
        int declared = http_CountHdr(ctx->http_beresp,h_guest_version) || http_GetHdr(ctx->http_beresp,h_selection_version,&selection_version) ||
            (content_type && !strncasecmp(content_type,selection_content_type,sizeof(selection_content_type)-1));
        valid = declared ? selection_version && !strcmp(selection_version,"1") &&
            http_CountHdr(ctx->http_beresp,h_selection_version) == 1 &&
            content_type && !strncasecmp(content_type,selection_content_type,sizeof(selection_content_type)-1) &&
            (!content_type[sizeof(selection_content_type)-1] || content_type[sizeof(selection_content_type)-1] == ';') :
            http_GetStatus(ctx->http_beresp) >= 200 && http_GetStatus(ctx->http_beresp) <= 599;
        if (valid && !declared && source_operation) valid = 0;
        if (valid && !declared) {
            /* Keep status, MIME, repeated owner cookies and the actual body
             * on this private PASS. No body copy, JSON parse or second fetch. */
            if (d->source_projected) {
                struct fields **owned_tail = &entry->fields;
                while (*owned_tail) owned_tail = &(*owned_tail)->next;
                for (i = HTTP_HDR_FIRST; i < ctx->http_beresp->nhd; ++i) {
                    struct fields *f;
                    const char *line = ctx->http_beresp->hd[i].b;
                    if (!line || (!http_IsHdr(&ctx->http_beresp->hd[i],H_Set_Cookie) &&
                        !delivery_header_name(line,"Set-Cookie2"))) continue;
                    f = calloc(1,sizeof(*f));
                    if (f) f->line = strdup(line);
                    if (!f || !f->line) {
                        free(f); d->failed = 1;
                        pthread_mutex_unlock(&lock);
                        VRT_fail(ctx,"Real visitor cookie handoff unavailable"); return 0;
                    }
                    *owned_tail = f; owned_tail = &f->next;
                }
                /* Keep resolver→actual response cookie chronology without
                 * copying the streaming private body or replaying sources. */
                http_Unset(ctx->http_beresp,H_Set_Cookie); http_Unset(ctx->http_beresp,h_set_cookie2);
            }
            d->phase = D_RAW_PASS;
            pthread_mutex_unlock(&lock); return 0;
        }
    } else valid = 1;
    if (d->conflict_verified) {
        d->phase = D_CONFLICT;
        /* The native HTTP parser has completed the explicit no-body framing;
         * VFP pull is not invoked for Content-Length: 0. */
        d->complete = 1;
        filter = VRT_priv_task(ctx,&filter_task_token);
        if (filter) filter->priv = &task->key;
        else d->failed = 1;
        pthread_mutex_unlock(&lock);
        if (!filter) VRT_fail(ctx,"UltraCache conflict capture association unavailable");
        return 1;
    }
    d->guest_reply = http_CountHdr(ctx->http_beresp,h_guest_version) != 0;
    if (source_operation && d->guest_reply) valid = 0;
    if (d->guest_reply) valid = valid && d->selection_entry && d->guest_requested &&
        delivery_header_equals(ctx->http_beresp,h_guest_version,"1") &&
        !http_CountHdr(ctx->http_beresp,H_Set_Cookie) && !http_CountHdr(ctx->http_beresp,h_set_cookie2);
    valid = valid && (declined || http_GetStatus(ctx->http_beresp) == 200) &&
        (!http_GetHdr(ctx->http_beresp,H_Content_Encoding,&encoding) || !strcmp(encoding,"identity"));
    if (valid && d->source_projected && source_operation && !declined) {
        d->source_resolved_response = delivery_header_equals(ctx->http_beresp,
            HDR("X-UltraCache-Delivery-Public-Source-Outcome"),"resolved");
        valid = delivery_header_equals(ctx->http_beresp,HDR("X-UltraCache-Delivery-Public-Source-Version"),"1") &&
            (d->source_resolved_response || (source_only && delivery_header_equals(ctx->http_beresp,
                HDR("X-UltraCache-Delivery-Public-Source-Outcome"),"captured")));
    }
    pthread_mutex_unlock(&lock);
    for (i = HTTP_HDR_FIRST; valid && i < ctx->http_beresp->nhd; ++i) {
        struct fields *f;
        if (source_only) continue; /* pure source cookies never belong to this visitor */
        if (!ctx->http_beresp->hd[i].b || (!http_IsHdr(&ctx->http_beresp->hd[i],H_Set_Cookie) &&
            !delivery_header_name(ctx->http_beresp->hd[i].b,"Set-Cookie2"))) continue;
        f = calloc(1,sizeof(*f));
        if (!f) { valid = 0; break; }
        f->line = strdup(ctx->http_beresp->hd[i].b);
        if (!f->line) { free(f); valid = 0; break; }
        *tail = f; tail = &f->next;
    }
    filter = VRT_priv_task(ctx,&filter_task_token);
    if (!filter) valid = 0;
    else filter->priv = &task->key; /* backend PRIV_TASK outlives its VFP */
    pthread_mutex_lock(&lock);
    entry = delivery_entry(task->key);
    d = entry ? entry->delivery : NULL;
    if (!entry || !entry->delivery) valid = 0;
    else if (!valid) entry->delivery->failed = 1;
    else {
        if (!source_only && d->source_projected) {
            struct fields **owned_tail = &entry->fields;
            while (*owned_tail) owned_tail = &(*owned_tail)->next;
            *owned_tail = first; first = NULL;
        } else if (!source_only) {
            clear_fields(entry->fields); entry->fields = first; first = NULL;
        }
        entry->delivery->debug_fallback = http_CountHdr(ctx->http_beresp,h_contained_error) == 1 &&
            http_GetHdr(ctx->http_beresp,h_contained_error,&contained) && !strcmp(contained,"1");
        entry->delivery->outcome = 0;
        if (http_CountHdr(ctx->http_beresp,h_delivery_outcome) == 1 &&
            http_GetHdr(ctx->http_beresp,h_delivery_outcome,&outcome)) {
            if (!strcmp(outcome,"degraded")) entry->delivery->outcome = 2;
            else if (!strcmp(outcome,"verified") && !entry->delivery->debug_fallback)
                entry->delivery->outcome = 1;
        }
        entry->delivery->recovery_ready = !d->selection_entry && http_GetHdr(ctx->http_beresp,h_recovery,&recovery) &&
            (!strcmp(recovery,"public-snapshot-v1") || !strcmp(recovery,"request-snapshot-v1"));
        entry->delivery->snapshot_ready = !d->selection_entry && http_GetHdr(ctx->http_beresp,h_recovery,&recovery) &&
            !strcmp(recovery,"request-snapshot-v1");
        entry->delivery->prepare_response_time = ctx->now;
    }
    pthread_mutex_unlock(&lock);
    clear_fields(first);
    http_Unset(ctx->http_beresp,H_Set_Cookie);
    http_Unset(ctx->http_beresp,h_set_cookie2);
    http_Unset(ctx->http_beresp,h_contained_error);
    http_Unset(ctx->http_beresp,h_delivery_outcome);
    if (!valid) VRT_fail(ctx,"UltraCache prepare response rejected");
    return 1;
}

VCL_BOOL vmod_selection_raw(VRT_CTX, struct vmod_priv *priv) {
    struct task *task = priv->priv;
    struct handoff *entry;
    int raw = 0;
    (void)ctx;
    if (!task || !task->key) return 0;
    pthread_mutex_lock(&lock); entry = delivery_entry(task->key);
    if (entry && entry->delivery) raw = entry->delivery->phase == D_RAW_PASS && !entry->delivery->failed;
    pthread_mutex_unlock(&lock); return raw;
}

static int delivery_cookie_marker(const struct http *hp) {
    const char *value;
    if (!http_GetHdr(hp,h_cookie_delivery,&value)) return 0;
    return http_CountHdr(hp,h_cookie_delivery) == 1 && !strcmp(value,"1") ? 1 : -1;
}
VCL_INT vmod_delivery_deliver(VRT_CTX, struct vmod_priv *priv, VCL_STRING target,
    VCL_INT occurrences, VCL_BOOL begin) {
    struct continuation *d = priv->priv;
    unsigned i;
    if (ctx->req->esi_level > 0) return 0;
    if (d && d->phase == D_HELD_RESUME) return delivery_held_finish(ctx,priv,d);
    if (d && d->phase == D_FINALIZE) return delivery_reuse_finish(ctx,d);
    if (!d) {
        struct handoff *entry;
        int cookie_delivery, reuse_result;
        if (!begin || !target || !*target) return 0;
        cookie_delivery = delivery_cookie_marker(ctx->http_resp);
        if (cookie_delivery < 0 || !delivery_relative(target) || occurrences < 0 ||
            (!occurrences && !cookie_delivery) ||
            ctx->req->restarts+2 > ctx->req->max_restarts) return -1;
        d = calloc(1,sizeof(*d));
        if (!d) return -1;
        priv->priv = d; priv->methods = &delivery_methods;
        d->phase = D_FAILED;
        d->url = strdup(ctx->http_req->hd[HTTP_HDR_URL].b);
        d->target = strdup(target);
        d->manifest = delivery_manifest_token(target);
        if (!d->url || !d->target || !d->manifest || !delivery_copy_header(ctx->http_req,H_Host,&d->host) || !d->host ||
            !delivery_copy_header(ctx->http_req,h_adapter_site,&d->site) ||
            !delivery_copy_header(ctx->http_req,H_Cookie,&d->cookie) ||
            !delivery_copy_header(ctx->http_req,H_Accept_Encoding,&d->encoding)) return -1;
        for (i = 0; i < 6; ++i)
            if (!delivery_copy_header(ctx->http_req,conditional_headers[i],&d->conditional[i])) return -1;
        if (!delivery_snapshot_headers(ctx,d)) return -1;
        d->retire_expression = delivery_retirement(ctx,d);
        entry = calloc(1,sizeof(*entry));
        if (!entry) return -1;
        pthread_mutex_lock(&lock);
        if (serial == UINT64_MAX) { pthread_mutex_unlock(&lock); free(entry); return -1; }
        entry->key = ++serial; entry->delivery = d;
        entry->next = buckets[entry->key % BUCKETS]; buckets[entry->key % BUCKETS] = entry; ++live;
        d->association.key = entry->key; d->association.owner = entry;
        pthread_mutex_unlock(&lock);
        snprintf(d->request_id,sizeof(d->request_id),"%" PRIu64,entry->key);
        d->restart = ctx->req->restarts; d->occurrences = (uint64_t)occurrences;
        d->cookie_delivery = (unsigned)cookie_delivery;
        d->parent = ctx->req->objcore;
        (void)delivery_reuse_capture_parent(ctx,d);
        reuse_result = delivery_reuse_try_hit(ctx,priv,d);
        if (reuse_result == REUSE_PLAN_HELD) return 1;
        if (reuse_result == REUSE_PLAN_HIT) {
            d->phase = D_DELIVERED; d->outcome = 1; return 0;
        }
        d->phase = D_QUEUED;
        return 1;
    }
    if (d->phase == D_RAW_PASS) {
        if (d->failed || !delivery_restore(ctx,d) || !delivery_original_owner(ctx,d) ||
            (d->source_projected && !delivery_append_cookies(ctx,d))) {
            d->phase = D_FAILED; return -1;
        }
        d->phase = D_RAW_DELIVERED;
        return 0; /* Native streaming delivery, never a synthetic full-body copy. */
    }
    if (d->phase == D_CONFLICT) {
        if (d->failed || !d->complete || d->length || d->reselect_attempted ||
            http_GetStatus(ctx->http_resp) != 409 || ctx->req->restarts != d->restart+1 ||
            ctx->req->restarts+2 > ctx->req->max_restarts || !delivery_restore(ctx,d) ||
            !delivery_original_owner(ctx,d)) { d->phase = D_FAILED; return -1; }
        d->reselect_attempted = 1;
        d->phase = D_RESELECT_QUEUED;
        return 3; /* Retire exact A, then enter current-policy selection once. */
    }
    if (d->phase == D_PREPARE) {
        int valid;
        pthread_mutex_lock(&lock);
        valid = d->complete && !d->failed;
        pthread_mutex_unlock(&lock);
        if (!valid || http_GetStatus(ctx->http_resp) !=
                ((d->source_stage == SOURCE_CAPTURE || d->source_stage == SOURCE_RESOLVER) && d->source_declined ? 409 : 200) ||
            !delivery_parse(ctx,d) || !delivery_restore(ctx,d)) {
            d->phase = D_FAILED; return -1;
        }
        if (d->source_stage == SOURCE_CAPTURE || d->source_stage == SOURCE_RESOLVER) {
            if (ctx->req->restarts+1 > ctx->req->max_restarts) { d->phase = D_FAILED; return -1; }
            d->phase = D_SOURCE_PERSONAL_QUEUED;
            return 1; /* Only the next real personal prepare can complete delivery. */
        }
        if (d->document) {
            if (d->recovery_ready || !delivery_original_owner(ctx,d) ||
                !delivery_document_headers(ctx->http_resp,&d->document_headers,0)) {
                d->phase = D_FAILED; return -1;
            }
            d->phase = D_DOCUMENT;
            delivery_log_fallback(ctx,d);
            return 2; /* private synth now, never another parent lookup/store */
        }
        if (d->snapshot_ready) {
            double application_deadline;
            if (!d->public_parent) { d->phase = D_FAILED; return -1; }
            application_deadline = d->prepare_response_time+(double)d->public_parent->fresh_remaining;
            if (application_deadline < d->public_deadline) d->public_deadline = application_deadline;
        }
        d->phase = D_RETURN;
        delivery_log_fallback(ctx,d);
        return 1;
    }
    if (d->guest_complete && (d->phase == D_READY || d->phase == D_RECOVERY)) {
        if (http_GetStatus(ctx->http_resp) != 200 || !guest_object_matches(ctx,d->guest_key,d->manifest)) {
            if (d->phase == D_READY && d->recovery_ready && !d->recovery_sent && ctx->req->restarts < ctx->req->max_restarts) {
                d->phase = D_RECOVERY_QUEUED; d->recovery_restart = ctx->req->restarts+1; return 1;
            }
            d->phase = D_FAILED; return -1;
        }
        const char *site = NULL, *host = NULL;
        if (d->failed || (d->phase == D_RECOVERY && !d->recovery_received) || !delivery_restore(ctx,d) ||
            !http_GetHdr(ctx->http_req,h_adapter_site,&site) || !d->site || strcmp(site,d->site) ||
            !http_GetHdr(ctx->http_req,H_Host,&host) || strcmp(host,d->host) ||
            strcmp(d->url,ctx->http_req->hd[HTTP_HDR_URL].b) || strcmp("GET",ctx->http_req->hd[HTTP_HDR_METHOD].b) ||
            ctx->req->restarts != (d->recovery_restart ? d->recovery_restart : d->restart+1)) {
            d->phase = D_FAILED; return -1;
        }
        d->phase = D_DELIVERED;
        return 0; /* Complete guest bytes: no provider cookies or private batch. */
    }
    if (d->phase == D_READY || d->phase == D_RECOVERY) {
        if (http_GetStatus(ctx->http_resp) != 200 ||
            (d->phase == D_READY && ctx->req->objcore != d->parent && !d->recovery_ready) ||
            !target || strcmp(target,d->target) ||
            delivery_cookie_marker(ctx->http_resp) != (int)d->cookie_delivery ||
            occurrences < ((d->selection_entry || d->cookie_delivery) ? 0 : 1) ||
            (uint64_t)occurrences != d->occurrences) {
            if (d->phase == D_READY && d->recovery_ready && !d->recovery_sent &&
                ctx->req->restarts < ctx->req->max_restarts) {
                d->phase = D_RECOVERY_QUEUED;
                d->recovery_restart = ctx->req->restarts+1;
                return 1;
            }
            d->phase = D_FAILED; return -1;
        }
        /* A same-manifest replacement has the same signed publication/context.
         * A recovered fetch additionally requires the bound snapshot response. */
        if (d->failed || (d->phase == D_RECOVERY && !d->recovery_received) ||
            !delivery_restore(ctx,d)) { d->phase = D_FAILED; return -1; }
        /* Before the first ESI child runs, append authentic provider headers. */
        if (d->phase == D_READY && !d->reuse_done && delivery_reuse_schedule(ctx,priv,d)) return 1;
        if (!delivery_append_cookies(ctx,d)) { d->phase = D_FAILED; return -1; }
        d->phase = D_DELIVERED;
        return 0;
    }
    return -1;
}

VCL_STRING vmod_delivery_public_source_outcome(VRT_CTX, struct vmod_priv *priv) {
    const struct continuation *d = priv->priv;
    if (!d || ctx->req->esi_level || d->source_stage == SOURCE_NONE) return NULL;
    if (d->failed || d->phase == D_FAILED) return "protocol-error";
    if (d->source_unstable) return "unstable-public-projection";
    if (d->source_declined) return "unavailable";
    return d->source_stage == SOURCE_COMPLETE ? "parent-v1" : NULL;
}
VCL_STRING vmod_delivery_outcome(VRT_CTX, struct vmod_priv *priv) {
    const struct continuation *d = priv->priv;
    /* Capture is provisional. Only complete, bound, final delivery may report
     * its outcome; ordinary late ESI and failed/raw responses stay unknown. */
    if (ctx->req->esi_level || !d || d->failed || d->guest_complete ||
        (d->phase != D_DELIVERED && d->phase != D_DOCUMENT_SENT)) return "unverified";
    if (d->outcome == 1) return "verified";
    if (d->outcome == 2) return "degraded";
    return "unverified";
}

VCL_BOOL vmod_delivery_synth(VRT_CTX, struct vmod_priv *priv) {
    struct continuation *d = priv->priv;
    const struct delivery_fragment *f;
    struct vrt_blob body;
    const char *url;
    if (d && d->phase == D_DOCUMENT && d->document && delivery_original_owner(ctx,d)) {
        struct fields *field;
        http_PutResponse(ctx->http_resp,"HTTP/1.1",(uint16_t)d->document->status,
            http_Status2Reason(d->document->status,NULL));
        for (field = d->document_headers; field; field = field->next) {
            const char *line = WS_Copy(ctx->ws,field->line,-1);
            if (!line || ctx->http_resp->nhd >= ctx->http_resp->shd) {
                VRT_fail(ctx,"Private document header workspace unavailable"); return 1;
            }
            http_SetHeader(ctx->http_resp,line);
        }
        if (d->cookie_delivery) http_ForceHeader(ctx->http_resp,h_cookie_delivery,"1");
        else http_Unset(ctx->http_resp,h_cookie_delivery);
        http_ForceHeader(ctx->http_resp,H_Cache_Control,"private, no-store");
        http_ForceHeader(ctx->http_resp,h_surrogate_control,"no-store");
        if (*d->document->content_type) http_ForceHeader(ctx->http_resp,H_Content_Type,d->document->content_type);
        else http_Unset(ctx->http_resp,H_Content_Type);
        if (!delivery_append_cookies(ctx,d)) { VRT_fail(ctx,"Private document cookies unavailable"); return 1; }
        INIT_OBJ(&body,VRT_BLOB_MAGIC);
        body.blob = d->document->body; body.len = d->document->length;
        if (d->document->status == 204 || d->document->status == 304) { body.blob = ""; body.len = 0; }
        VRT_l_resp_body(ctx,LBODY_SET_BLOB,NULL,&body);
        d->phase = D_DOCUMENT_SENT;
        return 1;
    }
    if (!d || ctx->req->esi_level == 0 || d->phase != D_DELIVERED) return 0;
    url = ctx->http_req->hd[HTTP_HDR_URL].b;
    for (f = d->fragments; f; f = f->next) if (!strcmp(url,f->url)) break;
    if (!f) return 0;
    http_ForceHeader(ctx->http_resp,H_Cache_Control,"private, no-store");
    http_ForceHeader(ctx->http_resp,H_Content_Type,"text/html; charset=UTF-8");
    INIT_OBJ(&body,VRT_BLOB_MAGIC); body.blob = f->html; body.len = f->length;
    VRT_l_resp_body(ctx,LBODY_SET_BLOB,NULL,&body);
    return 1;
}

#include "delivery_reuse.c"
#include "delivery_snapshot_backend.c"

int vmod_delivery_event(VRT_CTX, struct vmod_priv *priv, enum vcl_event_e event) {
    const char *error;
    if (event == VCL_EVENT_LOAD) {
        error = VRT_AddFilter(ctx,&delivery_filter,NULL);
        if (error) { VRT_fail(ctx,"UltraCache capture filter registration failed"); return -1; }
        if (!delivery_snapshot_load(ctx,priv)) {
            VRT_RemoveFilter(ctx,&delivery_filter,NULL);
            VRT_fail(ctx,"UltraCache request snapshot backend registration failed");
            return -1;
        }
        if (!public_selection_vcl_event(event)) {
            delivery_snapshot_unload(ctx,priv);
            VRT_RemoveFilter(ctx,&delivery_filter,NULL);
            VRT_fail(ctx,"UltraCache registry epoch initialization failed");
            return -1;
        }
    } else if (event == VCL_EVENT_DISCARD) {
        public_selection_vcl_event(event);
        delivery_snapshot_unload(ctx,priv);
        VRT_RemoveFilter(ctx,&delivery_filter,NULL);
    }
    return 0;
}

#include "public_selection_registry.c"
#include "reuse_authority.c"
#include "private_identity_map.c"
#include "mutation_backend.c"
#include "execution_drain.c"
#include "delivery_reuse_runtime.c"
#include "delivery_held.c"
