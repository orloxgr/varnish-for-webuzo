/* SPDX-License-Identifier: GPL-3.0-or-later
 * Included by delivery_continuation.c. Experimental multi-descriptor resolver.
 * No admission/authority, cookie-policy change, producer bypass or VCL caller.
 * Engine internals are enabled only by an explicit source/ABI build receipt.
 */
#ifdef UC_NATIVE_PRIVATE_REUSE
#include "uc_engine_objhead.h"
#include "vsha256.h"
#include "vtim.h"

enum reuse_state { REUSE_UNCACHEABLE, REUSE_MISS, REUSE_HIT };
struct delivery_reuse_pin {
    struct delivery_reuse_pin *next;
    struct delivery_fragment *fragment;
    struct objcore *object; /* independently owned reference; no engine stash cap */
    enum reuse_state state;
    double deadline;
    char *copy;
    size_t length, capacity;
};
struct delivery_reuse_plan {
    struct delivery_reuse_pin *pins;
    unsigned materialized;
};

static void reuse_hash_lp(struct VSHA256Context *hash, const void *bytes, size_t length) {
    const unsigned char prefix[4] = {(unsigned char)(length>>24),(unsigned char)(length>>16),
        (unsigned char)(length>>8),(unsigned char)length};
    VSHA256_Update(hash,prefix,sizeof(prefix));
    if (length) VSHA256_Update(hash,bytes,length);
}
static int delivery_reuse_capture_parent(VRT_CTX, struct continuation *d) {
    static const char domain[] = "ultracache-native-representation-v1";
    struct VSHA256Context hash;
    unsigned char digest[VSHA256_LEN];
    const unsigned char *vary;
    ssize_t length = 0;
    size_t i;
    static const char hex[] = "0123456789abcdef";
    if (!d || !d->manifest || !ctx->req->objcore || !ctx->req->wrk || d->public_deadline <= ctx->now) return 0;
    if (!delivery_selection_digest((const unsigned char *)d->manifest,strlen(d->manifest),d->reuse_publication)) return 0;
    vary = ObjHasAttr(ctx->req->wrk,ctx->req->objcore,OA_VARY) ?
        ObjGetAttr(ctx->req->wrk,ctx->req->objcore,OA_VARY,&length) : NULL;
    if (length < 0 || (uintmax_t)length > UINT32_MAX || (!vary && length)) {
        d->reuse_publication[0] = 0; return 0;
    }
    VSHA256_Init(&hash);
    reuse_hash_lp(&hash,domain,sizeof(domain)-1);
    reuse_hash_lp(&hash,ctx->req->digest,sizeof(ctx->req->digest));
    reuse_hash_lp(&hash,vary,(size_t)length);
    VSHA256_Final(digest,&hash);
    for (i = 0; i < sizeof(digest); ++i) {
        d->reuse_representation[2*i] = hex[digest[i]>>4];
        d->reuse_representation[2*i+1] = hex[digest[i]&15];
    }
    d->reuse_representation[64] = 0;
    return 1;
}

static void delivery_reuse_release(VRT_CTX, struct delivery_reuse_plan *plan) {
    struct delivery_reuse_pin *pin;
    if (!plan) return;
    CHECK_OBJ_NOTNULL(ctx->req,REQ_MAGIC);
    CHECK_OBJ_NOTNULL(ctx->req->wrk,WORKER_MAGIC);
    while ((pin = plan->pins)) {
        plan->pins = pin->next;
        if (pin->object) (void)HSH_DerefObjCore(ctx->req->wrk,&pin->object);
        free(pin->copy); free(pin);
    }
    free(plan);
}

/* Missing/busy dependencies never dispatch a fetch or park the active worker.
 * HSH_Lookup may reserve a busy object even for a read-only miss. Withdraw that
 * exact reservation using the matching engine lifecycle before releasing req.
 */
static struct objcore *delivery_reuse_lookup(VRT_CTX, const struct continuation *d,
    const struct delivery_fragment *fragment) {
    struct req *r, *parent = ctx->req;
    struct worker *worker = parent->wrk;
    struct objcore *object = NULL, *busy = NULL;
    struct boc *fetch;
    struct VSHA256Context hash;
    enum lookup_e result;
    const char *outcome = "workspace-unavailable";
    const char *marker;
    const hdr_t object_marker = HDR("X-SCP-Private-Object");
    int strange = worker->strangelove, valid = 0;
    const char *parts[] = {"ultracache-private-v1", d->site, d->host,
        fragment ? fragment->url : NULL, fragment ? fragment->cache_key : NULL};
    size_t i;
    r = Req_New(parent->sp,parent);
    r->wrk = worker;
    r->vsl->wid = VXID_Get(worker,VSL_CLIENTMARKER);
    VSLb(r->vsl,SLT_Begin,"req %ju reuse",(uintmax_t)VXID(parent->vsl->wid));
    VSLb(parent->vsl,SLT_Link,"req %ju reuse",(uintmax_t)VXID(r->vsl->wid));
    HTTP_Setup(r->http,r->ws,r->vsl,SLT_ReqMethod);
    HTTP_Dup(r->http,parent->http);
    if (fragment) {
        http_SetH(r->http,HTTP_HDR_URL,fragment->url);
        http_ForceField(r->http,HTTP_HDR_METHOD,"GET");
        http_Unset(r->http,H_Cookie); http_Unset(r->http,H_Authorization);
        http_Unset(r->http,H_Accept_Encoding);
        /* Request fields used by BAN/Vary retain the actual private namespace. */
        http_ForceHeader(r->http,H_Host,d->host);
        http_ForceHeader(r->http,h_private_key,fragment->cache_key);
        http_ForceHeader(r->http,HDR("X-SCP-Key-URL"),fragment->url);
    }
    r->t_req = VTIM_real(); r->d_ttl = -1; r->d_grace = -1;
    r->hash_ignore_busy = 1;
    if (WS_Overflowed(r->ws)) goto done;
    if (fragment) {
        VSHA256_Init(&hash);
        for (i = 0; i < sizeof(parts)/sizeof(parts[0]); ++i) {
            HSH_AddString(r,&hash,parts[i]); HSH_AddString(r,&hash,NULL);
        }
        VSHA256_Final(r->digest,&hash);
    } else {
        /* The parent uses its actual already-computed native digest and Vary
         * request. Do not reconstruct its cache key or normalize its inputs. */
        memcpy(r->digest,parent->digest,sizeof(r->digest));
    }
    VRY_Prep(r);
    result = HSH_Lookup(r,&object,&busy);
    VRY_Finish(r,DISCARD);
    if (busy) HSH_Withdraw(worker,&busy);
    if (result != HSH_HIT || !object) {
        VSLb(r->vsl,SLT_Debug,"uc-reuse-lookup native-result=%d",(int)result);
        outcome = "object-unavailable"; goto done;
    }
    /* A streaming HIT is not a complete pre-header dependency. RefBoc safely
     * tests active fetch ownership; never wait in ObjIterate for such a body. */
    fetch = HSH_RefBoc(object);
    if (fetch) { HSH_DerefBoc(worker,object); outcome = "object-fetching"; goto done; }
    marker = fragment ? HTTP_GetHdrPack(worker,object,object_marker) : NULL;
    valid = (fragment ? marker && !strcmp(marker,"1") :
        object == parent->objcore && object->t_origin+object->ttl > VTIM_real()) &&
        !HTTP_GetHdrPack(worker,object,H_Set_Cookie) &&
        !HTTP_GetHdrPack(worker,object,h_set_cookie2);
    outcome = valid ? "hit" : "object-contract-rejected";
done:
    VSLb(r->vsl,SLT_Debug,"uc-reuse-lookup kind=%s outcome=%s",
        !fragment ? "parent" : !strncmp(fragment->url,"/__ultracache-native/reuse-v1/",
            sizeof("/__ultracache-native/reuse-v1/")-1) ? "metadata" : "body",outcome);
    if (!valid && object) (void)HSH_DerefObjCore(worker,&object);
    r->wrk = NULL; Req_Release(r);
    worker->strangelove = strange;
    return object;
}

VCL_BOOL vmod_delivery_reuse_available(VRT_CTX) { (void)ctx; return 1; }

VCL_INT vmod_delivery_reuse_resolve(VRT_CTX, struct vmod_priv *priv) {
    struct continuation *d = priv->priv;
    struct delivery_fragment *fragment;
    struct delivery_reuse_pin *pin, **tail;
    const char *site = NULL, *host = NULL;
    int all = 1;
    if (ctx->req->esi_level || !d || d->failed || d->phase != D_READY ||
        !d->site || !*d->site || !d->host ||
        !http_GetHdr(ctx->http_req,h_adapter_site,&site) || strcmp(site,d->site) ||
        !http_GetHdr(ctx->http_req,H_Host,&host) || strcmp(host,d->host) ||
        strcmp(ctx->http_req->hd[HTTP_HDR_URL].b,d->url) ||
        strcmp(ctx->http_req->hd[HTTP_HDR_METHOD].b,"GET") ||
        ctx->req->restarts != (d->reuse_done ? d->reuse_final_restart :
            d->restart+(d->reuse_fast ? 0 : d->selection_entry ? 1 : 2))) return -1;
    if (!d->reuse_plan) {
        d->reuse_plan = calloc(1,sizeof(*d->reuse_plan));
        if (!d->reuse_plan) return -1;
        tail = &d->reuse_plan->pins;
        for (fragment = d->fragments; fragment; fragment = fragment->next) {
            pin = calloc(1,sizeof(*pin));
            if (!pin) {
                delivery_reuse_release(ctx,d->reuse_plan); d->reuse_plan = NULL; return -1;
            }
            pin->fragment = fragment;
            *tail = pin; tail = &pin->next;
            if (!fragment->cache_key || !fragment->cache_ttl) continue;
            pin->state = REUSE_MISS;
            pin->object = delivery_reuse_lookup(ctx,d,fragment);
            if (!pin->object) continue;
            pin->deadline = fmin(pin->object->t_origin+pin->object->ttl,
                fragment->cache_deadline > 0 ? fragment->cache_deadline :
                    d->prepare_response_time+(double)fragment->cache_ttl);
            if (!isfinite(pin->deadline) || pin->deadline <= VTIM_real()) {
                (void)HSH_DerefObjCore(ctx->req->wrk,&pin->object); continue;
            }
            pin->state = REUSE_HIT;
        }
    }
    for (pin = d->reuse_plan->pins; pin; pin = pin->next)
        if (pin->state != REUSE_HIT || pin->deadline <= VTIM_real()) all = 0;
    return all;
}

VCL_INT vmod_delivery_reuse_count(VRT_CTX, struct vmod_priv *priv, VCL_BOOL hits) {
    const struct continuation *d = priv->priv;
    const struct delivery_reuse_pin *pin;
    VCL_INT count = 0;
    if (ctx->req->esi_level || !d || !d->reuse_plan) return -1;
    for (pin = d->reuse_plan->pins; pin; pin = pin->next) {
        int hit = pin->state == REUSE_HIT && pin->deadline > VTIM_real();
        if (hit == !!hits) { if (count == INT64_MAX) return -1; ++count; }
    }
    return count;
}

static int delivery_reuse_chunk(void *value, unsigned flush, const void *bytes, ssize_t length) {
    struct delivery_reuse_pin *pin = value;
    size_t needed, capacity;
    char *grown;
    (void)flush;
    if (length < 0 || !delivery_buffer_growth(pin->length,pin->capacity,(size_t)length,&needed,&capacity)) return -1;
    if (capacity != pin->capacity) {
        grown = realloc(pin->copy,capacity);
        if (!grown) return -1;
        pin->copy = grown; pin->capacity = capacity;
    }
    if (length) memcpy(pin->copy+pin->length,bytes,(size_t)length);
    pin->length += (size_t)length;
    pin->copy[pin->length] = 0;
    return 0;
}

/* Request-local materialization for selective-fill context and existing ESI
 * replay. This does not authorize reuse; generation/final commit is separate.
 * Reserve/copy ALL selected HITs before altering any existing fragment bytes.
 */
static int delivery_reuse_materialize(VRT_CTX, struct vmod_priv *priv, int locked) {
    struct continuation *d = priv->priv;
    struct delivery_reuse_pin *pin;
    int failed = 0;
    if (ctx->req->esi_level || !d || d->failed || d->phase != D_READY || !d->reuse_plan) return 0;
    if (d->reuse_plan->materialized) return 1;
    for (pin = d->reuse_plan->pins; pin; pin = pin->next) {
        if (pin->state != REUSE_HIT) continue;
        if (pin->deadline <= VTIM_real() || ObjIterate(ctx->req->wrk,pin->object,pin,delivery_reuse_chunk,1) ||
            pin->length != ObjGetLen(ctx->req->wrk,pin->object)) { failed = 1; break; }
        if (!pin->copy && delivery_reuse_chunk(pin,0,"",0)) { failed = 1; break; }
    }
    /* Copying a large dependency set may cross an actual validity deadline. */
    for (pin = d->reuse_plan->pins; !failed && pin; pin = pin->next)
        if (pin->state == REUSE_HIT && pin->deadline <= VTIM_real()) failed = 1;
    if (failed) {
        for (pin = d->reuse_plan->pins; pin; pin = pin->next) {
            free(pin->copy); pin->copy = NULL; pin->length = pin->capacity = 0;
        }
        return 0;
    }
    if (!locked) pthread_mutex_lock(&lock);
    for (pin = d->reuse_plan->pins; pin; pin = pin->next) {
        if (pin->state != REUSE_HIT) continue;
        free(pin->fragment->html); pin->fragment->html = pin->copy;
        pin->fragment->length = pin->length; pin->copy = NULL;
        pin->length = pin->capacity = 0;
    }
    d->reuse_plan->materialized = 1;
    if (!locked) pthread_mutex_unlock(&lock);
    return 1;
}
VCL_BOOL vmod_delivery_reuse_materialize(VRT_CTX, struct vmod_priv *priv) {
    return delivery_reuse_materialize(ctx,priv,0);
}

static double delivery_fragment_deadline(const struct continuation *d, const struct delivery_fragment *f) {
    const struct delivery_reuse_pin *pin;
    if (d->reuse_plan && d->reuse_plan->materialized)
        for (pin = d->reuse_plan->pins; pin; pin = pin->next)
            if (pin->fragment == f && pin->state == REUSE_HIT) return pin->deadline;
    return f->cache_deadline > 0 ? f->cache_deadline : d->prepare_response_time+(double)f->cache_ttl;
}
#else
static int delivery_reuse_capture_parent(VRT_CTX, struct continuation *d) { (void)ctx; (void)d; return 0; }
static void delivery_reuse_release(VRT_CTX, struct delivery_reuse_plan *p) { (void)ctx; (void)p; }
VCL_BOOL vmod_delivery_reuse_available(VRT_CTX) { (void)ctx; return 0; }
VCL_INT vmod_delivery_reuse_resolve(VRT_CTX, struct vmod_priv *p) { (void)ctx; (void)p; return -1; }
VCL_INT vmod_delivery_reuse_count(VRT_CTX, struct vmod_priv *p, VCL_BOOL h) { (void)ctx; (void)p; (void)h; return -1; }
VCL_BOOL vmod_delivery_reuse_materialize(VRT_CTX, struct vmod_priv *p) { (void)ctx; (void)p; return 0; }
static double delivery_fragment_deadline(const struct continuation *d, const struct delivery_fragment *f) {
    return d->prepare_response_time+(double)f->cache_ttl;
}
#endif
