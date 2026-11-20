/* SPDX-License-Identifier: GPL-3.0-or-later
 * Included by cookie_handoff.c. Candidate UltraCache-only continuation.
 * No worker, cookie issuer, public cookie jar or persistent visitor state. */
#include <stdio.h>
#include "cache/cache_filter.h"
#include "vrt_obj.h"
#include "vjsn.h"

#define DELIVERY_MAX_BODY (8U * 1024U * 1024U)
#define DELIVERY_MAX_FRAGMENTS 1024U
enum delivery_phase { D_QUEUED, D_PREPARE, D_RETURN, D_READY, D_DELIVERED, D_FAILED };
struct delivery_fragment {
    struct delivery_fragment *next;
    char *url;
    char *html;
    size_t length;
};
struct continuation {
    struct task association; /* only its owner slot is used */
    enum delivery_phase phase;
    unsigned restart, sent, complete, failed, occurrences;
    /* 9.1 cnt_deliver stashes this object across restart until req cleanup.
     * We retain identity only; never swap engine object pointers or call
     * HSH_Ref/Deref through uninstalled private headers. */
    const struct objcore *parent;
    char *url, *host, *target, *cookie, *encoding;
    char *conditional[6];
    char request_id[32];
    char *body;
    size_t length, capacity;
    struct delivery_fragment *fragments;
};
static const char filter_task_token;
static const hdr_t h_key = HDR("X-SCP-Cookie-Handoff");
static const hdr_t h_version = HDR("X-UltraCache-Delivery-Version");
static const hdr_t h_phase = HDR("X-UltraCache-Delivery-Phase");
static const hdr_t h_request = HDR("X-UltraCache-Delivery-Request");
static const hdr_t h_original = HDR("X-UltraCache-Delivery-Original-URL");
static const hdr_t conditional_headers[] = {
    HDR("Range"), HDR("If-None-Match"), HDR("If-Modified-Since"), HDR("If-Match"),
    HDR("If-Unmodified-Since"), HDR("If-Range")
};

static struct handoff *delivery_entry(uint64_t key) {
    struct handoff *e = buckets[key % BUCKETS];
    while (e && e->key != key) e = e->next;
    return e;
}

static void delivery_free_fragments(struct delivery_fragment *f) {
    while (f) {
        struct delivery_fragment *next = f->next;
        free(f->url); free(f->html); free(f); f = next;
    }
}

static void delivery_fini(VRT_CTX, void *value) {
    struct continuation *d = value;
    unsigned i;
    /* The table lock excludes an aborting backend filter before freeing d. */
    close_owner(&d->association);
    (void)ctx;
    free(d->url); free(d->host); free(d->target); free(d->cookie); free(d->encoding);
    for (i = 0; i < 6; ++i) free(d->conditional[i]);
    free(d->body); delivery_free_fragments(d->fragments); free(d);
}
static const struct vmod_priv_methods delivery_methods = {
    .magic = VMOD_PRIV_METHODS_MAGIC, .type = "ultracache-delivery-top", .fini = delivery_fini,
};

static int delivery_relative(const char *s) {
    const unsigned char *p = (const unsigned char *)s;
    if (!p || p[0] != '/' || p[1] == '/') return 0;
    for (; *p; ++p) if (*p <= 32 || *p == 127 || *p == '\\' || *p == '#') return 0;
    return 1;
}

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
    http_ForceField(ctx->http_req, HTTP_HDR_URL, url);
    if (!delivery_restore_header(ctx, H_Host, d->host) ||
        !delivery_restore_header(ctx, H_Cookie, d->cookie) ||
        !delivery_restore_header(ctx, H_Accept_Encoding, d->encoding)) return 0;
    for (i = 0; i < 6; ++i)
        if (!delivery_restore_header(ctx, conditional_headers[i], d->conditional[i])) return 0;
    return 1;
}

/* JSON strings may contain decoded NUL. Reject it in binding/URL text. */
static int delivery_text(const struct vjsn_val *v) {
    return v && vjsn_is_string(v) &&
        strlen(v->value) == (size_t)(v->value_e - v->value);
}
static int delivery_unsigned(const struct vjsn_val *v, unsigned *result) {
    const char *p;
    unsigned n = 0;
    if (!v || !vjsn_is_number(v) || !v->value || !*v->value) return 0;
    for (p = v->value; *p; ++p) {
        if (*p < '0' || *p > '9' || n > (DELIVERY_MAX_FRAGMENTS - (*p-'0')) / 10U) return 0;
        n = n * 10U + (unsigned)(*p - '0');
    }
    *result = n;
    return 1;
}
static int delivery_unique_keys(const struct vjsn_val *v, unsigned expected) {
    const struct vjsn_val *a, *b;
    unsigned count = 0;
    if (!vjsn_is_object(v)) return 0;
    VTAILQ_FOREACH(a, &v->children, list) {
        if (++count > expected) return 0;
        if (!a->name || strlen(a->name) != (size_t)(a->name_e-a->name)) return 0;
        for (b = VTAILQ_NEXT(a, list); b; b = VTAILQ_NEXT(b, list))
            if (!strcmp(a->name, b->name)) return 0;
    }
    return count == expected;
}

/* Bound parser recursion before calling the native JSON parser. The schema
 * needs only object -> array -> object, and no raw NUL is meaningful JSON. */
static int delivery_json_depth(const char *p, size_t length) {
    unsigned depth = 0;
    int quoted = 0, escaped = 0;
    size_t i;
    for (i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)p[i];
        if (!c) return 0;
        if (quoted) {
            if (escaped) escaped = 0;
            else if (c == '\\') escaped = 1;
            else if (c == '"') quoted = 0;
        } else if (c == '"') quoted = 1;
        else if (c == '{' || c == '[') { if (++depth > 8) return 0; }
        else if (c == '}' || c == ']') { if (!depth--) return 0; }
    }
    return !quoted && !depth;
}

static int delivery_parse(struct continuation *d) {
    const char *error = NULL;
    struct vjsn *json = NULL;
    const struct vjsn_val *root, *v, *array;
    struct delivery_fragment *f;
    unsigned schema, total = 0, count = 0;
    int ok = 0;
    if (!d->body || !delivery_json_depth(d->body,d->length)) goto done;
    json = vjsn_parse_end(d->body, d->body+d->length, &error);
    if (!json || error) goto done;
    root = json->value;
    if (!delivery_unique_keys(root,4) ||
        !delivery_unsigned(vjsn_child(root,"schemaVersion"), &schema) || schema != 1) goto done;
    v = vjsn_child(root,"requestId");
    if (!delivery_text(v) || strcmp(v->value,d->request_id)) goto done;
    v = vjsn_child(root,"originalUrl");
    if (!delivery_text(v) || strcmp(v->value,d->url)) goto done;
    array = vjsn_child(root,"renderedFragments");
    if (!array || !vjsn_is_array(array)) goto done;
    VTAILQ_FOREACH(v, &array->children, list) {
        const struct vjsn_val *url, *html;
        unsigned occurrences;
        if (++count > DELIVERY_MAX_FRAGMENTS || !delivery_unique_keys(v,3)) goto done;
        url = vjsn_child(v,"url"); html = vjsn_child(v,"html");
        if (!delivery_text(url) || !delivery_relative(url->value) || !html || !vjsn_is_string(html) ||
            !delivery_unsigned(vjsn_child(v,"occurrences"), &occurrences) || !occurrences ||
            occurrences > d->occurrences-total) goto done;
        for (f = d->fragments; f; f = f->next) if (!strcmp(f->url,url->value)) goto done;
        f = calloc(1,sizeof(*f));
        if (!f) goto done;
        f->url = strdup(url->value); f->length = (size_t)(html->value_e-html->value);
        f->html = malloc(f->length ? f->length : 1);
        if (!f->url || !f->html) { delivery_free_fragments(f); goto done; }
        if (f->length) memcpy(f->html, html->value, f->length);
        f->next = d->fragments; d->fragments = f; total += occurrences;
    }
    ok = total == d->occurrences && count > 0;
done:
    if (json) vjsn_delete(&json);
    free(d->body); d->body = NULL; d->length = d->capacity = 0;
    if (!ok) { delivery_free_fragments(d->fragments); d->fragments = NULL; }
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
    pthread_mutex_lock(&lock);
    entry = delivery_entry(key);
    d = entry ? entry->delivery : NULL;
    if (!d) failed = 1;
    else if (status == VFP_ERROR || *lp < 0 || (size_t)*lp > DELIVERY_MAX_BODY-d->length) d->failed = failed = 1;
    else {
        size_t needed = d->length+(size_t)*lp+1;
        if (needed > d->capacity) {
            size_t capacity = needed > d->capacity*2 ? needed : d->capacity*2;
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
        for (f = d->fragments; f; f = f->next) if (!strcmp(f->url,url)) return 2;
        return 0; /* ordinary public child remains on its existing path */
    }
    if (d->phase == D_QUEUED && ctx->req->restarts == d->restart+1) {
        url = WS_Copy(ctx->ws,d->target,-1);
        if (!url) return -1;
        http_ForceField(ctx->http_req,HTTP_HDR_URL,url);
        http_ForceHeader(ctx->http_req,h_key,d->request_id);
        http_Unset(ctx->http_req,H_Accept_Encoding);
        for (i = 0; i < 6; ++i) http_Unset(ctx->http_req,conditional_headers[i]);
        d->phase = D_PREPARE;
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
        if (d->phase != D_PREPARE || d->sent++) d->failed = failed = 1;
        else {
            http_ForceHeader(ctx->http_bereq,h_version,"1");
            http_ForceHeader(ctx->http_bereq,h_phase,"prepare");
            http_ForceHeader(ctx->http_bereq,h_request,d->request_id);
            http_ForceHeader(ctx->http_bereq,h_original,d->url);
            if (d->cookie) http_ForceHeader(ctx->http_bereq,H_Cookie,d->cookie);
            else http_Unset(ctx->http_bereq,H_Cookie);
        }
    }
    pthread_mutex_unlock(&lock);
    if (failed || WS_Overflowed(ctx->ws)) VRT_fail(ctx,"UltraCache prepare cannot be repeated");
    return owned;
}

VCL_BOOL vmod_delivery_capture(VRT_CTX, struct vmod_priv *priv) {
    struct task *task = priv->priv;
    struct fields *first = NULL, **tail = &first;
    struct handoff *entry;
    struct vmod_priv *filter;
    const char *encoding;
    unsigned i;
    int owned, valid;
    if (!task || !task->key) return 0;
    pthread_mutex_lock(&lock);
    entry = delivery_entry(task->key); owned = entry && entry->delivery;
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
    else { clear_fields(entry->fields); entry->fields = first; first = NULL; }
    pthread_mutex_unlock(&lock);
    clear_fields(first);
    http_Unset(ctx->http_beresp,H_Set_Cookie);
    if (!valid) VRT_fail(ctx,"UltraCache prepare response rejected");
    return 1;
}

VCL_INT vmod_delivery_deliver(VRT_CTX, struct vmod_priv *priv, VCL_STRING target, VCL_INT occurrences) {
    struct continuation *d = priv->priv;
    unsigned i;
    if (ctx->req->esi_level > 0) return 0;
    if (!d) {
        struct handoff *entry;
        if (!target || !*target) return 0;
        if (!delivery_relative(target) || occurrences < 1 || occurrences > DELIVERY_MAX_FRAGMENTS ||
            ctx->req->restarts+2 > ctx->req->max_restarts) return -1;
        d = calloc(1,sizeof(*d));
        if (!d) return -1;
        priv->priv = d; priv->methods = &delivery_methods;
        d->phase = D_FAILED;
        d->url = strdup(ctx->http_req->hd[HTTP_HDR_URL].b);
        d->target = strdup(target);
        if (!d->url || !d->target || !delivery_copy_header(ctx->http_req,H_Host,&d->host) || !d->host ||
            !delivery_copy_header(ctx->http_req,H_Cookie,&d->cookie) ||
            !delivery_copy_header(ctx->http_req,H_Accept_Encoding,&d->encoding)) return -1;
        for (i = 0; i < 6; ++i)
            if (!delivery_copy_header(ctx->http_req,conditional_headers[i],&d->conditional[i])) return -1;
        entry = calloc(1,sizeof(*entry));
        if (!entry) return -1;
        pthread_mutex_lock(&lock);
        if (serial == UINT64_MAX) { pthread_mutex_unlock(&lock); free(entry); return -1; }
        entry->key = ++serial; entry->delivery = d;
        entry->next = buckets[entry->key % BUCKETS]; buckets[entry->key % BUCKETS] = entry; ++live;
        d->association.key = entry->key; d->association.owner = entry;
        pthread_mutex_unlock(&lock);
        snprintf(d->request_id,sizeof(d->request_id),"%" PRIu64,entry->key);
        d->restart = ctx->req->restarts; d->occurrences = (unsigned)occurrences;
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
        d->phase = D_RETURN;
        return 1;
    }
    if (d->phase == D_READY) {
        struct fields *f;
        if (ctx->req->objcore != d->parent || http_GetStatus(ctx->http_resp) != 200) {
            d->phase = D_FAILED; return -1;
        }
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

int vmod_delivery_event(VRT_CTX, struct vmod_priv *priv, enum vcl_event_e event) {
    const char *error;
    (void)priv;
    if (event == VCL_EVENT_LOAD) {
        error = VRT_AddFilter(ctx,&delivery_filter,NULL);
        if (error) { VRT_fail(ctx,"UltraCache capture filter registration failed"); return -1; }
    } else if (event == VCL_EVENT_DISCARD) VRT_RemoveFilter(ctx,&delivery_filter,NULL);
    return 0;
}
