/* SPDX-License-Identifier: GPL-3.0-or-later
 * Included by cookie_handoff.c. Candidate UltraCache-only continuation.
 * No worker, cookie issuer, public cookie jar or persistent visitor state. */
#include <stdio.h>
#include <strings.h>
#include "cache/cache_filter.h"
#include "vrt_obj.h"
#include "delivery_envelope.h"

enum delivery_phase { D_QUEUED, D_PREPARE, D_RETURN, D_READY,
    D_RECOVERY_QUEUED, D_RECOVERY, D_DELIVERED, D_DOCUMENT, D_DOCUMENT_SENT,
    D_RAW_PASS, D_RAW_DELIVERED, D_FAILED };
struct continuation {
    struct task association; /* only its owner slot is used */
    enum delivery_phase phase;
    unsigned restart, sent, complete, failed;
    unsigned recovery_ready, recovery_sent, recovery_received, recovery_restart;
    unsigned snapshot_ready, snapshot_mode;
    unsigned selection_entry;
    unsigned debug_fallback;
    double public_deadline, prepare_response_time;
    uint64_t occurrences;
    /* Identity check only; exact installed-engine lifetime still needs native
     * qualification. Also revalidate signed manifest/count on final delivery.
     * Never swap engine pointers or call uninstalled private HSH APIs. */
    const struct objcore *parent;
    char *url, *host, *site, *target, *manifest, *cookie, *encoding;
    char *selection_rules, *selection_policy, *wordpress_policy, *selection_actions, *selection_scope;
    char *candidate, *variant;
    char *conditional[6];
    char request_id[32];
    char *body;
    size_t length, capacity;
    struct delivery_fragment *fragments;
    struct delivery_public_parent *public_parent; /* same-request public bytes */
    struct delivery_private_document *document;
    struct delivery_public_selection *selection;
    struct fields *public_headers;
    struct fields *document_headers;
};
static int delivery_snapshot_headers(VRT_CTX, struct continuation *);
static int public_selection_parse(struct continuation *);
static void public_selection_vcl_event(enum vcl_event_e);
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
static const hdr_t h_set_cookie2 = HDR("Set-Cookie2");
static const hdr_t h_contained_error = HDR("X-UltraCache-ESI-Error-Contained");
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
    close_owner(&d->association);
    (void)ctx;
    free(d->url); free(d->host); free(d->site); free(d->target); free(d->cookie); free(d->encoding);
    free(d->selection_rules); free(d->selection_policy); free(d->wordpress_policy);
    free(d->selection_actions); free(d->selection_scope); free(d->candidate); free(d->variant);
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
    http_Unset(ctx->http_req, h);
    if (s) http_ForceHeader(ctx->http_req, h, s);
    return !WS_Overflowed(ctx->ws);
}

static int delivery_restore(VRT_CTX, const struct continuation *d) {
    unsigned i;
    const char *url = WS_Copy(ctx->ws, d->url, -1);
    if (!url) return 0;
    VRT_l_req_url(ctx, NULL, TOSTRAND(url));
    if (!delivery_restore_header(ctx, H_Host, d->host) ||
        !delivery_restore_header(ctx, H_Cookie, d->cookie) ||
        !delivery_restore_header(ctx, H_Accept_Encoding, d->encoding)) return 0;
    for (i = 0; i < 6; ++i)
        if (!delivery_restore_header(ctx, conditional_headers[i], d->conditional[i])) return 0;
    return 1;
}

static int delivery_parse(struct continuation *d) {
    if (d->selection_entry) return public_selection_parse(d);
    int ok = delivery_envelope_parse(d->body,d->length,d->request_id,d->url,
        d->occurrences,&d->fragments,&d->public_parent,&d->document);
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
        !delivery_buffer_growth(d->length,d->capacity,(size_t)*lp,&needed,&capacity)) d->failed = failed = 1;
    else {
        if (needed > d->capacity) {
            char *body = realloc(d->body,capacity);
            if (!body) d->failed = failed = 1;
            else { d->body = body; d->capacity = capacity; }
        }
        if (!failed) {
            if (*lp) memcpy(d->body+d->length,p,(size_t)*lp);
            d->length += (size_t)*lp; d->body[d->length] = '\0';
            if (status == VFP_END) d->complete = 1;
        }
    }
    pthread_mutex_unlock(&lock);
    if (failed) return VFP_Error(vc,"UltraCache delivery capture failed");
    return status;
}
static const struct vfp delivery_filter = {
    .name = "uc_delivery_capture", .init = delivery_filter_init, .pull = delivery_filter_pull,
};

VCL_INT vmod_delivery_recv(VRT_CTX, struct vmod_priv *priv) {
    struct continuation *d = priv->priv;
    const char *url;
    unsigned i;
    if (!d) return 0;
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
    if (!d || ctx->req->esi_level != 0 || !site || !*site || !ctx->req->restarts) return 0;
    if (!http_GetHdr(ctx->http_req,H_Host,&host)) return 0;
    url = ctx->http_req->hd[HTTP_HDR_URL].b;
    method = ctx->http_req->hd[HTTP_HDR_METHOD].b;
    pthread_mutex_lock(&lock);
    phase = (d->phase == D_QUEUED && ctx->req->restarts == d->restart+1) ||
        (d->phase == D_RETURN && ctx->req->restarts == d->restart+(d->selection_entry ? 1 : 2)) ||
        (d->phase == D_RECOVERY_QUEUED && ctx->req->restarts == d->recovery_restart);
    valid = phase && !d->failed && method && !strcmp(method,"GET") &&
        d->site && !strcmp(d->site,site) && host && !strcmp(d->host,host) &&
        url && !strcmp(d->url,url);
    pthread_mutex_unlock(&lock);
    return valid;
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

VCL_BOOL vmod_delivery_backend(VRT_CTX, struct vmod_priv *priv) {
    struct task *task = priv->priv;
    struct handoff *entry;
    struct continuation *d;
    int owned = 0, failed = 0;
    if (!task || !task->key) return 0;
    pthread_mutex_lock(&lock);
    entry = delivery_entry(task->key); d = entry ? entry->delivery : NULL;
    if (d) {
        owned = 1;
        if ((d->phase != D_PREPARE && d->phase != D_RECOVERY) ||
            (d->phase == D_PREPARE ? d->sent++ : d->recovery_sent++)) d->failed = failed = 1;
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
            http_ForceHeader(ctx->http_bereq,h_request,d->request_id);
            http_ForceHeader(ctx->http_bereq,h_original,d->url);
            if (d->manifest) http_ForceHeader(ctx->http_bereq,h_manifest,d->manifest);
            else http_Unset(ctx->http_bereq,h_manifest);
            if (d->selection_entry && d->phase == D_PREPARE) {
                http_ForceHeader(ctx->http_bereq,h_selection_version,"1");
                http_ForceHeader(ctx->http_bereq,h_selection_policy,d->selection_policy);
                http_ForceHeader(ctx->http_bereq,h_wordpress_policy,d->wordpress_policy);
                http_ForceHeader(ctx->http_bereq,h_selection_actions,d->selection_actions);
                http_ForceHeader(ctx->http_bereq,h_selection_scope,d->selection_scope);
            }
            if (d->cookie) http_ForceHeader(ctx->http_bereq,H_Cookie,d->cookie);
            else http_Unset(ctx->http_bereq,H_Cookie);
        }
    }
    pthread_mutex_unlock(&lock);
    if (owned && !failed) {
        struct vmod_priv *filter = VRT_priv_task(ctx,&filter_task_token);
        if (!filter) failed = 1;
        else filter->priv = &task->key;
    }
    if (failed || WS_Overflowed(ctx->ws)) VRT_fail(ctx,"UltraCache prepare cannot be repeated");
    return owned;
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
    const char *encoding, *recovery, *selection_version = NULL, *content_type = NULL, *contained = NULL;
    unsigned i;
    int owned, valid;
    if (!task || !task->key) return 0;
    pthread_mutex_lock(&lock);
    entry = delivery_entry(task->key);
    d = entry ? entry->delivery : NULL;
    owned = d && d->phase == D_PREPARE;
    if (!owned) { pthread_mutex_unlock(&lock); return 0; }
    http_GetHdr(ctx->http_beresp,H_Content_Type,&content_type);
    if (d->selection_entry) {
        int declared = http_GetHdr(ctx->http_beresp,h_selection_version,&selection_version) ||
            (content_type && !strncasecmp(content_type,selection_content_type,sizeof(selection_content_type)-1));
        valid = declared ? selection_version && !strcmp(selection_version,"1") &&
            http_CountHdr(ctx->http_beresp,h_selection_version) == 1 &&
            content_type && !strncasecmp(content_type,selection_content_type,sizeof(selection_content_type)-1) &&
            (!content_type[sizeof(selection_content_type)-1] || content_type[sizeof(selection_content_type)-1] == ';') :
            http_GetStatus(ctx->http_beresp) >= 200 && http_GetStatus(ctx->http_beresp) <= 599;
        if (valid && !declared) {
            /* Keep status, MIME, repeated owner cookies and the actual body
             * on this private PASS. No body copy, JSON parse or second fetch. */
            d->phase = D_RAW_PASS;
            pthread_mutex_unlock(&lock); return 0;
        }
    } else valid = 1;
    valid = valid && http_GetStatus(ctx->http_beresp) == 200 &&
        (!http_GetHdr(ctx->http_beresp,H_Content_Encoding,&encoding) || !strcmp(encoding,"identity"));
    pthread_mutex_unlock(&lock);
    for (i = HTTP_HDR_FIRST; valid && i < ctx->http_beresp->nhd; ++i) {
        struct fields *f;
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
        clear_fields(entry->fields); entry->fields = first; first = NULL;
        entry->delivery->debug_fallback = http_CountHdr(ctx->http_beresp,h_contained_error) == 1 &&
            http_GetHdr(ctx->http_beresp,h_contained_error,&contained) && !strcmp(contained,"1");
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

VCL_INT vmod_delivery_deliver(VRT_CTX, struct vmod_priv *priv, VCL_STRING target,
    VCL_INT occurrences, VCL_BOOL begin) {
    struct continuation *d = priv->priv;
    unsigned i;
    if (ctx->req->esi_level > 0) return 0;
    if (!d) {
        struct handoff *entry;
        if (!begin || !target || !*target) return 0;
        if (!delivery_relative(target) || occurrences < 1 ||
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
        d->parent = ctx->req->objcore;
        d->phase = D_QUEUED;
        return 1;
    }
    if (d->phase == D_RAW_PASS) {
        if (d->failed || !delivery_restore(ctx,d) || !delivery_original_owner(ctx,d)) {
            d->phase = D_FAILED; return -1;
        }
        d->phase = D_RAW_DELIVERED;
        return 0; /* Native streaming delivery, never a synthetic full-body copy. */
    }
    if (d->phase == D_PREPARE) {
        int valid;
        pthread_mutex_lock(&lock);
        valid = d->complete && !d->failed;
        pthread_mutex_unlock(&lock);
        if (!valid || http_GetStatus(ctx->http_resp) != 200 || !delivery_parse(d) || !delivery_restore(ctx,d)) {
            d->phase = D_FAILED; return -1;
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
    if (d->phase == D_READY || d->phase == D_RECOVERY) {
        if (http_GetStatus(ctx->http_resp) != 200 ||
            (d->phase == D_READY && ctx->req->objcore != d->parent && !d->recovery_ready) ||
            !target || strcmp(target,d->target) || occurrences < (d->selection_entry ? 0 : 1) ||
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
        if (!delivery_append_cookies(ctx,d)) { d->phase = D_FAILED; return -1; }
        d->phase = D_DELIVERED;
        return 0;
    }
    return -1;
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
        public_selection_vcl_event(event);
    } else if (event == VCL_EVENT_DISCARD) {
        public_selection_vcl_event(event);
        delivery_snapshot_unload(ctx,priv);
        VRT_RemoveFilter(ctx,&delivery_filter,NULL);
    }
    return 0;
}

#include "public_selection_registry.c"
