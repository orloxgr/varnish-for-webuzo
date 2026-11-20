/* SPDX-License-Identifier: GPL-3.0-or-later
 * Included by cookie_handoff.c. Candidate UltraCache-only continuation.
 * No worker, cookie issuer, public cookie jar or persistent visitor state. */
#include <stdio.h>
#include "cache/cache_filter.h"
#include "vrt_obj.h"
#include "delivery_envelope.h"

enum delivery_phase { D_QUEUED, D_PREPARE, D_RETURN, D_READY,
    D_RECOVERY_QUEUED, D_RECOVERY, D_DELIVERED, D_FAILED };
struct continuation {
    struct task association; /* only its owner slot is used */
    enum delivery_phase phase;
    unsigned restart, sent, complete, failed;
    unsigned recovery_ready, recovery_sent, recovery_received, recovery_restart;
    unsigned snapshot_ready, snapshot_mode;
    double public_deadline, prepare_response_time;
    uint64_t occurrences;
    /* Identity check only; exact installed-engine lifetime still needs native
     * qualification. Also revalidate signed manifest/count on final delivery.
     * Never swap engine pointers or call uninstalled private HSH APIs. */
    const struct objcore *parent;
    char *url, *host, *target, *manifest, *cookie, *encoding;
    char *conditional[6];
    char request_id[32];
    char *body;
    size_t length, capacity;
    struct delivery_fragment *fragments;
    struct delivery_public_parent *public_parent; /* same-request public bytes */
    struct fields *public_headers;
};
static int delivery_snapshot_headers(VRT_CTX, struct continuation *);
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
    free(d->url); free(d->host); free(d->target); free(d->cookie); free(d->encoding);
    delivery_manifest_free(d->manifest);
    for (i = 0; i < 6; ++i) free(d->conditional[i]);
    free(d->body); delivery_free_fragments(d->fragments);
    clear_fields(d->public_headers);
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
    int ok = delivery_envelope_parse(d->body,d->length,d->request_id,d->url,
        d->occurrences,&d->fragments,&d->public_parent);
    free(d->body); d->body = NULL; d->length = d->capacity = 0;
    return ok;
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
    if (d->phase == D_RETURN && ctx->req->restarts == d->restart+2) {
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
                d->phase == D_PREPARE ? "prepare" : "parent-snapshot");
            http_ForceHeader(ctx->http_bereq,h_recovery_version,"1");
            http_ForceHeader(ctx->http_bereq,h_request_snapshot_version,"1");
            http_ForceHeader(ctx->http_bereq,h_request,d->request_id);
            http_ForceHeader(ctx->http_bereq,h_original,d->url);
            http_ForceHeader(ctx->http_bereq,h_manifest,d->manifest);
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
    const char *encoding, *recovery;
    unsigned i;
    int owned, valid;
    if (!task || !task->key) return 0;
    pthread_mutex_lock(&lock);
    entry = delivery_entry(task->key);
    owned = entry && entry->delivery && entry->delivery->phase == D_PREPARE;
    pthread_mutex_unlock(&lock);
    if (!owned) return 0;
    valid = http_GetStatus(ctx->http_beresp) == 200 &&
        (!http_GetHdr(ctx->http_beresp,H_Content_Encoding,&encoding) || !strcmp(encoding,"identity"));
    for (i = HTTP_HDR_FIRST; valid && i < ctx->http_beresp->nhd; ++i) {
        struct fields *f;
        if (!ctx->http_beresp->hd[i].b || !http_IsHdr(&ctx->http_beresp->hd[i],H_Set_Cookie)) continue;
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
    if (!entry || !entry->delivery) valid = 0;
    else if (!valid) entry->delivery->failed = 1;
    else {
        clear_fields(entry->fields); entry->fields = first; first = NULL;
        entry->delivery->recovery_ready = http_GetHdr(ctx->http_beresp,h_recovery,&recovery) &&
            (!strcmp(recovery,"public-snapshot-v1") || !strcmp(recovery,"request-snapshot-v1"));
        entry->delivery->snapshot_ready = http_GetHdr(ctx->http_beresp,h_recovery,&recovery) &&
            !strcmp(recovery,"request-snapshot-v1");
        entry->delivery->prepare_response_time = ctx->now;
    }
    pthread_mutex_unlock(&lock);
    clear_fields(first);
    http_Unset(ctx->http_beresp,H_Set_Cookie);
    if (!valid) VRT_fail(ctx,"UltraCache prepare response rejected");
    return 1;
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
    if (d->phase == D_PREPARE) {
        int valid;
        pthread_mutex_lock(&lock);
        valid = d->complete && !d->failed;
        pthread_mutex_unlock(&lock);
        if (!valid || http_GetStatus(ctx->http_resp) != 200 || !delivery_parse(d) || !delivery_restore(ctx,d)) {
            d->phase = D_FAILED; return -1;
        }
        if (d->snapshot_ready) {
            double application_deadline;
            if (!d->public_parent) { d->phase = D_FAILED; return -1; }
            application_deadline = d->prepare_response_time+(double)d->public_parent->fresh_remaining;
            if (application_deadline < d->public_deadline) d->public_deadline = application_deadline;
        }
        d->phase = D_RETURN;
        return 1;
    }
    if (d->phase == D_READY || d->phase == D_RECOVERY) {
        struct fields *f;
        if (http_GetStatus(ctx->http_resp) != 200 ||
            (d->phase == D_READY && ctx->req->objcore != d->parent && !d->recovery_ready) ||
            !target || strcmp(target,d->target) || occurrences < 1 ||
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
        pthread_mutex_lock(&lock);
        for (f = d->association.owner->fields; f; f = f->next) {
            const char *line = WS_Copy(ctx->ws,f->line,-1);
            if (!line || ctx->http_resp->nhd >= ctx->http_resp->shd) { d->failed = 1; break; }
            http_SetHeader(ctx->http_resp,line);
        }
        clear_fields(d->association.owner->fields); d->association.owner->fields = NULL;
        pthread_mutex_unlock(&lock);
        if (d->failed) { d->phase = D_FAILED; return -1; }
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
    } else if (event == VCL_EVENT_DISCARD) {
        delivery_snapshot_unload(ctx,priv);
        VRT_RemoveFilter(ctx,&delivery_filter,NULL);
    }
    return 0;
}
