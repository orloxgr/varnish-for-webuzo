/* SPDX-License-Identifier: GPL-3.0-or-later
 * Included by delivery_continuation.c. Request-owned public snapshot source.
 * Uses the exact installed cache_int.h http_conn layout under strict ABI.
 * No sockets, service worker, global body cache or engine object-ref mutation.
 */
#include <strings.h>

struct delivery_snapshot_vcl { VCL_BACKEND backend; };
struct delivery_snapshot_stream { uint64_t key; size_t offset; char *fragment_url; };
static const hdr_t snapshot_surrogate_control = HDR("Surrogate-Control");
static const hdr_t snapshot_surrogate_ttl = HDR("X-UltraCache-Surrogate-TTL");
static const hdr_t snapshot_cacheable = HDR("X-UltraCache-Cacheable");
static const hdr_t snapshot_pragma = HDR("Pragma");
static const hdr_t private_object = HDR("X-SCP-Private-Object");
static const hdr_t private_tags = HDR("X-UltraCache-Tags");

static int delivery_snapshot_headers(VRT_CTX, struct continuation *d) {
    struct fields **tail = &d->public_headers;
    unsigned i;
    double ttl = VRT_r_obj_ttl(ctx);
    d->public_deadline = ctx->now+(isfinite(ttl) && ttl > 0 ? ttl : 0);
    for (i = HTTP_HDR_FIRST; i < ctx->http_resp->nhd; ++i) {
        const char *line = ctx->http_resp->hd[i].b;
        struct fields *field;
        if (!line) continue;
        /* A selected public parent must never contain provider cookie fields. */
        if (delivery_header_name(line,"Set-Cookie") || delivery_header_name(line,"Set-Cookie2")) return 0;
        if (delivery_header_name(line,"Content-Length") || delivery_header_name(line,"Content-Encoding") ||
            delivery_header_name(line,"Cache-Control") || delivery_header_name(line,"Surrogate-Control") ||
            delivery_header_name(line,"Date") || delivery_header_name(line,"Age") ||
            delivery_header_name(line,"Connection") || delivery_header_name(line,"Transfer-Encoding") ||
            delivery_header_name(line,"Trailer") || delivery_header_name(line,"Keep-Alive") ||
            delivery_header_name(line,"Proxy-Connection") ||
            !strncasecmp(line,"X-SCP-",6) || !strncasecmp(line,"X-HVH-",6) ||
            !strncasecmp(line,"X-WV-",5) || !strncasecmp(line,"X-Cache",7) ||
            !strncasecmp(line,"X-Hestia-Varnish",15) || !strncasecmp(line,"X-Webuzo-Varnish",15) ||
            (!strncasecmp(line,"X-UltraCache-Delivery-",21) &&
             !delivery_header_name(line,"X-UltraCache-Delivery-Prepare"))) continue;
        field = calloc(1,sizeof(*field));
        if (!field) return 0;
        field->line = strdup(line);
        if (!field->line) { free(field); return 0; }
        *tail = field; tail = &field->next;
    }
    return 1;
}

static enum vfp_status delivery_snapshot_init(VRT_CTX, struct vfp_ctx *vc, struct vfp_entry *vfe) {
    struct vmod_priv *priv = VRT_priv_task_get(ctx,&private_filter_task_token);
    struct delivery_snapshot_stream *stream;
    int fragment = priv && priv->priv;
    (void)vc;
    if (!fragment) priv = VRT_priv_task_get(ctx,&filter_task_token);
    if (!priv || !priv->priv) return VFP_ERROR;
    stream = calloc(1,sizeof(*stream));
    if (!stream) return VFP_ERROR;
    stream->key = *(uint64_t *)priv->priv;
    if (fragment) {
        stream->fragment_url = strdup(ctx->http_bereq->hd[HTTP_HDR_URL].b);
        if (!stream->fragment_url) { free(stream); return VFP_ERROR; }
    }
    vfe->priv1 = stream;
    return VFP_OK;
}
static enum vfp_status delivery_snapshot_pull(struct vfp_ctx *vc, struct vfp_entry *vfe, void *p, ssize_t *length) {
    struct delivery_snapshot_stream *stream = vfe->priv1;
    struct handoff *entry;
    struct continuation *d;
    const struct delivery_fragment *f;
    const void *body = NULL;
    size_t count, size = 0;
    int end = 0, failed = 0;
    pthread_mutex_lock(&lock);
    entry = stream ? delivery_entry(stream->key) : NULL;
    d = entry ? entry->delivery : NULL;
    if (d && stream->fragment_url) {
        f = delivery_fragment_named(d,stream->fragment_url);
        if (f && f->cache_key && f->cache_ttl) { body = f->html; size = f->length; }
    } else if (d && d->snapshot_mode && d->public_parent) {
        body = d->public_parent->body; size = d->public_parent->length;
    }
    if (!body || *length < 0 || stream->offset > size) failed = 1;
    else {
        count = size-stream->offset;
        if (count > (size_t)*length) count = (size_t)*length;
        if (count) memcpy(p,(const unsigned char *)body+stream->offset,count);
        stream->offset += count; *length = (ssize_t)count;
        end = stream->offset == size;
    }
    pthread_mutex_unlock(&lock);
    if (failed) return VFP_Error(vc,"UltraCache request-owned snapshot unavailable");
    return end ? VFP_END : VFP_OK;
}
static void delivery_snapshot_fini(struct vfp_ctx *vc, struct vfp_entry *vfe) {
    struct delivery_snapshot_stream *stream = vfe->priv1;
    (void)vc;
    if (stream) { free(stream->fragment_url); free(stream); }
    vfe->priv1 = NULL;
}
static const struct vfp delivery_snapshot_source = {
    .name = "uc_request_snapshot", .init = delivery_snapshot_init,
    .pull = delivery_snapshot_pull, .fini = delivery_snapshot_fini,
};

static int delivery_snapshot_gethdrs(VRT_CTX, VCL_BACKEND backend) {
    struct vmod_priv *priv = VRT_priv_task_get(ctx,&private_filter_task_token);
    struct handoff *entry;
    struct continuation *d;
    struct fields *field;
    const struct delivery_fragment *fragment;
    struct http_conn *htc;
    double remaining;
    int failed = 0, is_private = priv && priv->priv;
    (void)backend;
    if (!is_private) priv = VRT_priv_task_get(ctx,&filter_task_token);
    if (!priv || !priv->priv) return -1;
    htc = WS_Alloc(ctx->ws,sizeof(*htc));
    if (!htc) return -1;
    INIT_OBJ(htc,HTTP_CONN_MAGIC);
    htc->ws = ctx->ws; htc->doclose = SC_NULL;
    htc->body_status = BS_TAKEN; htc->content_length = -1;
    pthread_mutex_lock(&lock);
    entry = delivery_entry(*(uint64_t *)priv->priv);
    d = entry ? entry->delivery : NULL;
    fragment = is_private ? delivery_fragment_named(d,ctx->http_bereq->hd[HTTP_HDR_URL].b) : NULL;
    if (is_private) {
        if (!d || d->phase != D_DELIVERED || !fragment || !fragment->cache_key || !fragment->cache_ttl) failed = 1;
        else {
            http_PutResponse(ctx->http_beresp,"HTTP/1.1",200,"OK");
            http_ForceHeader(ctx->http_beresp,H_Content_Type,"text/html; charset=UTF-8");
            http_ForceHeader(ctx->http_beresp,private_object,"1");
            http_ForceHeader(ctx->http_beresp,private_tags,fragment->cache_tags);
            remaining = delivery_fragment_deadline(d,fragment)-ctx->now;
            if (!isfinite(remaining) || remaining < 0) remaining = 0;
            http_PrintfHeader(ctx->http_beresp,"Cache-Control: public, max-age=%.0f",floor(remaining));
        }
    } else if (!d || d->phase != D_RECOVERY || !d->snapshot_mode || !d->public_parent) failed = 1;
    else {
        http_PutResponse(ctx->http_beresp,"HTTP/1.1",200,"OK");
        for (field = d->public_headers; field; field = field->next) {
            const char *line = WS_Copy(ctx->ws,field->line,-1);
            if (!line || ctx->http_beresp->nhd >= ctx->http_beresp->shd) { failed = 1; break; }
            http_SetHeader(ctx->http_beresp,line);
        }
        if (d->guest_complete) {
            char digest[65];
            if (!delivery_selection_digest((const unsigned char *)d->manifest,strlen(d->manifest),digest)) failed = 1;
            else {
                /* No opaque publication token is copied into HTTP metadata.
                 * Its digest keeps the final binding at constant header cost. */
                http_ForceHeader(ctx->http_beresp,h_guest_object_key,d->guest_key);
                http_ForceHeader(ctx->http_beresp,h_guest_object_manifest,digest);
                http_ForceHeader(ctx->http_beresp,h_guest_object_complete,"1");
            }
        }
        remaining = d->public_deadline-ctx->now;
        if (!isfinite(remaining) || remaining < 0) remaining = 0;
        if (d->selection_entry) {
            const char *browser_control;
            /* The already-validated selected owner supplies the existing
             * application storage approval, never a new browser policy. */
            http_ForceHeader(ctx->http_beresp,snapshot_cacheable,"1");
            http_Unset(ctx->http_beresp,snapshot_surrogate_ttl);
            http_PrintfHeader(ctx->http_beresp,"X-UltraCache-Surrogate-TTL: %.0f",floor(remaining));
            http_CollectHdr(ctx->http_beresp,H_Cache_Control);
            http_CollectHdr(ctx->http_beresp,snapshot_pragma);
            if (!http_GetHdr(ctx->http_beresp,H_Cache_Control,&browser_control))
                http_PrintfHeader(ctx->http_beresp,"Cache-Control: public, max-age=%.0f",floor(remaining));
        } else {
            http_PrintfHeader(ctx->http_beresp,"Cache-Control: public, max-age=%.0f",floor(remaining));
        }
        if (!d->selection_entry) http_ForceHeader(ctx->http_beresp,snapshot_surrogate_control,"ESI/1.0");
        http_ForceHeader(ctx->http_beresp,h_recovery,"request-snapshot-v1");
        http_ForceHeader(ctx->http_beresp,h_request,d->request_id);
        http_ForceHeader(ctx->http_beresp,h_original,d->url);
    }
    pthread_mutex_unlock(&lock);
    if (failed || WS_Overflowed(ctx->ws)) return -1;
    ctx->bo->htc = htc;
    VSLb(ctx->bo->vsl,SLT_VCL_Log,is_private ? "UltraCache request-owned private fragment source"
        : "UltraCache request-owned public snapshot source");
    return 0;
}
static void delivery_snapshot_finish(VRT_CTX, VCL_BACKEND backend) {
    (void)backend;
    ctx->bo->htc = NULL;
}
static const struct vdi_methods delivery_snapshot_methods = {
    .magic = VDI_METHODS_MAGIC, .type = "uc-request-public-snapshot",
    .gethdrs = delivery_snapshot_gethdrs, .finish = delivery_snapshot_finish,
};
static int delivery_snapshot_load(VRT_CTX, struct vmod_priv *priv) {
    struct delivery_snapshot_vcl *module = calloc(1,sizeof(*module));
    const char *error;
    if (!module) return 0;
    error = VRT_AddFilter(ctx,&delivery_snapshot_source,NULL);
    if (error) { free(module); return 0; }
    module->backend = VRT_AddDirector(ctx,&delivery_snapshot_methods,module,"uc_request_snapshot");
    if (!module->backend) {
        VRT_RemoveFilter(ctx,&delivery_snapshot_source,NULL); free(module); return 0;
    }
    priv->priv = module;
    return 1;
}
static void delivery_snapshot_unload(VRT_CTX, struct vmod_priv *priv) {
    struct delivery_snapshot_vcl *module = priv->priv;
    if (!module) return;
    VRT_DelDirector(&module->backend);
    VRT_RemoveFilter(ctx,&delivery_snapshot_source,NULL);
    free(module); priv->priv = NULL;
}
VCL_BACKEND vmod_delivery_local_backend(VRT_CTX, struct vmod_priv *task_priv, struct vmod_priv *vcl_priv) {
    struct task *task = task_priv->priv;
    struct delivery_snapshot_vcl *module = vcl_priv->priv;
    struct handoff *entry;
    struct continuation *d;
    VCL_BACKEND result = NULL;
    (void)ctx;
    if (!task || !task->key || !module) return NULL;
    pthread_mutex_lock(&lock);
    entry = delivery_entry(task->key); d = entry ? entry->delivery : NULL;
    if (d && d->phase == D_RECOVERY && d->snapshot_ready && d->public_parent) {
        d->snapshot_mode = 1; result = module->backend;
    }
    pthread_mutex_unlock(&lock);
    return result;
}
VCL_BOOL vmod_delivery_local_source(VRT_CTX, struct vmod_priv *priv) {
    struct task *task = priv->priv;
    struct handoff *entry;
    int result = 0;
    (void)ctx;
    if (!task || !task->key) return 0;
    pthread_mutex_lock(&lock);
    entry = delivery_entry(task->key);
    if (entry && entry->delivery) result = entry->delivery->snapshot_mode;
    pthread_mutex_unlock(&lock);
    return result;
}

/* Only a backend task bound to the prepared top request may fill a private
 * native object. Browser lookup fields alone cannot select this body source. */
VCL_BACKEND vmod_delivery_private_backend(VRT_CTX, struct vmod_priv *task_priv, struct vmod_priv *vcl_priv) {
    struct task *task = task_priv->priv;
    struct delivery_snapshot_vcl *module = vcl_priv->priv;
    struct handoff *entry;
    const struct delivery_fragment *f;
    const char *key = NULL;
    int valid = 0;
    struct vmod_priv *filter;
    if (!task || !task->key || !module) return NULL;
    http_GetHdr(ctx->http_bereq,h_private_key,&key);
    pthread_mutex_lock(&lock);
    entry = delivery_entry(task->key);
    f = entry && entry->delivery && entry->delivery->phase == D_DELIVERED
        ? delivery_fragment_named(entry->delivery,ctx->http_bereq->hd[HTTP_HDR_URL].b) : NULL;
    valid = f && f->cache_key && f->cache_ttl && key && !strcmp(f->cache_key,key);
    pthread_mutex_unlock(&lock);
    if (!valid) return NULL;
    filter = VRT_priv_task(ctx,&private_filter_task_token);
    if (!filter) { VRT_fail(ctx,"Private fragment source association unavailable"); return NULL; }
    filter->priv = &task->key;
    return module->backend;
}
VCL_BOOL vmod_delivery_private_source(VRT_CTX) {
    struct vmod_priv *priv = VRT_priv_task_get(ctx,&private_filter_task_token);
    struct handoff *entry;
    const struct delivery_fragment *f;
    double remaining = 0;
    int valid;
    if (!priv || !priv->priv) return 0;
    pthread_mutex_lock(&lock);
    entry = delivery_entry(*(uint64_t *)priv->priv);
    f = entry && entry->delivery && entry->delivery->phase == D_DELIVERED
        ? delivery_fragment_named(entry->delivery,ctx->http_bereq->hd[HTTP_HDR_URL].b) : NULL;
    valid = f && f->cache_key && f->cache_ttl &&
        http_GetStatus(ctx->http_beresp) == 200 && !http_CountHdr(ctx->http_beresp,H_Set_Cookie);
    if (valid) remaining = delivery_fragment_deadline(entry->delivery,f)-ctx->now;
    pthread_mutex_unlock(&lock);
    if (!valid) { VRT_fail(ctx,"Prepared private source rejected"); return 1; }
    if (!isfinite(remaining) || remaining < 0) remaining = 0;
    VRT_l_beresp_ttl(ctx,remaining);
    return 1;
}
VCL_INT vmod_delivery_private_remaining(VRT_CTX) {
    double ttl = VRT_r_obj_ttl(ctx);
    if (!isfinite(ttl) || ttl <= 0) return 0;
    return ttl >= (double)INT64_MAX ? INT64_MAX : (VCL_INT)floor(ttl);
}
