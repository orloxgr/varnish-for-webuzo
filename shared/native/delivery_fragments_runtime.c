/* SPDX-License-Identifier: GPL-3.0-or-later
 * Fragment-only delivery reuses the existing continuation, native object
 * namespace, virtual source and mutation authority. No persistent body store. */

static int fragment_route_valid(const char *scope, const char *route) {
    return delivery_selection_scope_valid(scope) && delivery_relative(route) && !strchr(route,'?') &&
        delivery_selection_scope_matches(scope,route) && strlen(route) >= 10 &&
        !strcmp(route+strlen(route)-10,"/index.php");
}

static int fragment_declaration_active(VRT_CTX, const char *scope) {
    const char *version = reuse_single(ctx->http_req,HDR("X-UltraCache-Fragment-Delivery-Version"));
    const char *route = reuse_single(ctx->http_req,HDR("X-UltraCache-Fragment-Delivery-Route"));
    const char *caching = reuse_single(ctx->http_req,HDR("X-UltraCache-Fragment-Caching-Enabled"));
    return delivery_header_equals(ctx->http_req,HDR("X-SCP-Profile"),"ultracache") &&
        version && !strcmp(version,"1") && caching && (!strcmp(caching,"0") || !strcmp(caching,"1")) &&
        fragment_route_valid(scope,route);
}

VCL_BOOL vmod_fragment_declaration(VRT_CTX, VCL_STRING scope) {
    return fragment_declaration_active(ctx,scope);
}

VCL_BOOL vmod_fragment_register(VRT_CTX, VCL_STRING site, VCL_STRING host,
    VCL_STRING scope, VCL_STRING route, VCL_BOOL caching) {
    struct reuse_scope *owner;
    char *copy_route = NULL;
    int accepted = 0;
    if (!site || !host || !fragment_route_valid(scope,route)) return 0;
    copy_route = strdup(route);
    if (!copy_route) return 0;
    pthread_mutex_lock(&lock);
    owner = reuse_scope_find(site,host,scope);
    if (owner && owner->enabled && vmod_delivery_reuse_available(ctx)) {
        free(owner->fragment_route); owner->fragment_route = copy_route; copy_route = NULL;
        owner->fragment_cache_disabled = !caching;
        accepted = 1;
    }
    pthread_mutex_unlock(&lock); free(copy_route); return accepted;
}

static int fragment_cache_allowed_locked(const char *site, const char *host, const char *url) {
    const struct public_declaration *declaration;
    const struct reuse_scope *scope;
    if (!site || !host || !url) return 1;
    declaration = public_declaration_for_url(site,host,url);
    scope = declaration ? reuse_scope_find(site,host,declaration->scope) : NULL;
    return !scope || !scope->fragment_route || (scope->enabled && !scope->fragment_cache_disabled);
}

VCL_BOOL vmod_fragment_caching(VRT_CTX, VCL_STRING site, VCL_STRING host, VCL_STRING url) {
    int caching;
    (void)ctx;
    pthread_mutex_lock(&lock); caching = fragment_cache_allowed_locked(site,host,url); pthread_mutex_unlock(&lock);
    return caching;
}

VCL_STRING vmod_fragment_route(VRT_CTX, VCL_STRING site, VCL_STRING host, VCL_STRING scope) {
    struct reuse_scope *owner;
    const char *route = NULL;
    if (!site || !host || !scope) return NULL;
    pthread_mutex_lock(&lock);
    owner = reuse_scope_find(site,host,scope);
    if (owner && owner->enabled && owner->fragment_route)
        route = WS_Copy(ctx->ws,owner->fragment_route,-1);
    pthread_mutex_unlock(&lock); return route;
}

static int fragment_dispatch_owner(VRT_CTX, const struct continuation *d) {
    const char *host = NULL;
    return d && d->fragment_batch && !d->failed && !ctx->req->esi_level &&
        d->phase == D_FRAGMENT_OBJECT && d->fragment_resume_uri &&
        ctx->req->restarts == d->fragment_restart &&
        !strcmp(ctx->http_req->hd[HTTP_HDR_METHOD].b,"GET") &&
        !strcmp(ctx->http_req->hd[HTTP_HDR_URL].b,d->fragment_resume_uri) &&
        http_GetHdr(ctx->http_req,H_Host,&host) && !strcmp(host,d->host);
}

/* Caller holds the same lock used by actual native mutation writers. */
static int fragment_authority_current(const struct continuation *d, const struct delivery_fragment *fragment) {
    const struct delivery_fragment_authority *a = d->fragment_results ? d->fragment_results->authority : NULL;
    const struct delivery_fragment_grant *g;
    const struct reuse_scope *scope;
    const struct public_declaration *declaration;
    if (!a || !fragment || !fragment->cache_key || !d->fragment_scope) return 0;
    scope = reuse_scope_find(d->site,d->host,d->fragment_scope);
    declaration = public_declaration(d->site,d->host,d->fragment_scope);
    if (!reuse_scope_ready(scope) || !scope->fragment_route || !declaration ||
        strcmp(a->scope,scope->scope) || strcmp(a->epoch,public_registry_epoch) ||
        strcmp(a->incarnation,scope->incarnation) || strcmp(a->scope_revision,scope->revision) ||
        strcmp(a->native_policy,scope->native_policy) || strcmp(a->wordpress_policy,scope->wordpress_policy) ||
        strcmp(a->reuse_policy,scope->policy) || strcmp(declaration->wordpress_policy,scope->wordpress_policy) ||
        !d->selection_policy || strcmp(d->selection_policy,scope->native_policy) ||
        strcmp(d->fragment_batch->context[0],scope->wordpress_policy) ||
        delivery_fragment_deadline(d,fragment) <= VTIM_real()) return 0;
    for (g = a->fragments; g; g = g->next) if (!strcmp(g->url,fragment->url)) break;
    return g && g->authority && !reuse_authority_current_reason(scope,g->authority);
}

/* Both source selection and its final before-storage check call this under lock. */
static int fragment_source_owned(const struct continuation *d, const char *url, const char *key) {
    return d && d->fragment_batch && d->phase == D_FRAGMENT_OBJECT && !d->failed &&
        d->fragment_cursor && key && url && !strcmp(d->fragment_cursor->url,url) &&
        d->fragment_cursor->cache_key && !strcmp(d->fragment_cursor->cache_key,key) &&
        fragment_authority_current(d,d->fragment_cursor);
}

VCL_BOOL vmod_fragment_object(VRT_CTX, struct vmod_priv *priv) {
    const struct continuation *d = priv->priv;
    const char *site = NULL, *host = NULL;
    return d && d->fragment_batch && !d->failed && d->phase == D_FRAGMENT_OBJECT &&
        d->fragment_cursor && !ctx->req->esi_level && ctx->req->restarts == d->fragment_restart &&
        !strcmp(ctx->http_req->hd[HTTP_HDR_URL].b,d->fragment_cursor->url) &&
        http_GetHdr(ctx->http_req,h_adapter_site,&site) && !strcmp(site,d->site) &&
        http_GetHdr(ctx->http_req,H_Host,&host) && !strcmp(host,d->host);
}

VCL_INT vmod_fragment_recv(VRT_CTX, struct vmod_priv *priv, VCL_STRING site) {
    struct continuation *d = priv->priv;
    const char *url = ctx->http_req->hd[HTTP_HDR_URL].b, *host = NULL, *question;
    struct reuse_scope *scope;
    char *token = NULL, *application_scope = NULL;
    struct delivery_fragment_batch *batch = NULL;
    struct handoff *entry;
    unsigned i;
    if (d && d->fragment_batch) {
        if (!site || strcmp(site,d->site) || !fragment_dispatch_owner(ctx,d) || !d->fragment_cursor) return -1;
        http_Unset(ctx->http_req,H_Cookie); http_Unset(ctx->http_req,H_Authorization);
        http_Unset(ctx->http_req,H_Accept_Encoding);
        VRT_l_req_url(ctx,NULL,TOSTRAND(d->fragment_cursor->url));
        http_ForceHeader(ctx->http_req,h_private_key,d->fragment_cursor->cache_key);
        http_ForceHeader(ctx->http_req,h_key,d->request_id);
        return WS_Overflowed(ctx->ws) ? -1 : 3;
    }
    if (d || !site || !*site || ctx->req->esi_level || ctx->req->restarts ||
        strcmp(ctx->http_req->hd[HTTP_HDR_METHOD].b,"GET") ||
        !(question = strchr(url,'?')) || strncmp(question+1,"ultracache_fragment_delivery=",sizeof("ultracache_fragment_delivery=")-1) ||
        !http_GetHdr(ctx->http_req,H_Host,&host)) return 0;
    /* Only an already authenticated installation registration owns this route. */
    pthread_mutex_lock(&lock);
    for (scope = reuse_scopes; scope; scope = scope->next)
        if (scope->enabled && scope->fragment_route && !strcmp(scope->site,site) && !strcmp(scope->host,host) &&
            strlen(scope->fragment_route) == (size_t)(question-url) &&
            !memcmp(scope->fragment_route,url,(size_t)(question-url))) {
            application_scope = strdup(scope->scope); break;
        }
    pthread_mutex_unlock(&lock);
    if (!scope) return 0;
    token = delivery_fragment_batch_token(url);
    if (!application_scope || !token || !delivery_fragment_batch_parse(token,strlen(token),&batch)) {
        free(application_scope); free(token); return -1;
    }
    d = calloc(1,sizeof(*d));
    if (!d) { delivery_fragment_batch_free(batch); free(application_scope); free(token); return -1; }
    priv->priv = d; priv->methods = &delivery_methods;
    d->phase = D_FAILED;
    d->fragment_batch = batch; d->fragment_scope = application_scope; d->manifest = token;
    d->url = strdup(url); d->host = strdup(host); d->site = strdup(site);
    if (!d->url || !d->host || !d->site ||
        !delivery_copy_header(ctx->http_req,HDR("X-SCP-Selection-Native-Policy"),&d->selection_policy) ||
        !public_policy(d->selection_policy) ||
        !delivery_copy_header(ctx->http_req,H_Cookie,&d->cookie) ||
        !delivery_copy_header(ctx->http_req,H_Accept_Encoding,&d->encoding)) return -1;
    for (i = 0; i < 6; ++i) {
        if (!delivery_copy_header(ctx->http_req,conditional_headers[i],&d->conditional[i])) return -1;
        http_Unset(ctx->http_req,conditional_headers[i]);
    }
    http_Unset(ctx->http_req,H_Accept_Encoding);
    entry = calloc(1,sizeof(*entry));
    if (!entry) return -1;
    pthread_mutex_lock(&lock);
    if (serial == UINT64_MAX) { pthread_mutex_unlock(&lock); free(entry); return -1; }
    entry->key = ++serial; entry->delivery = d;
    entry->next = buckets[entry->key % BUCKETS]; buckets[entry->key % BUCKETS] = entry; ++live;
    d->association.key = entry->key; d->association.owner = entry;
    pthread_mutex_unlock(&lock);
    snprintf(d->request_id,sizeof(d->request_id),"%" PRIu64,entry->key);
    d->occurrences = batch->occurrences; d->restart = ctx->req->restarts;
    d->phase = D_PREPARE;
    http_ForceHeader(ctx->http_req,h_key,d->request_id);
    return WS_Overflowed(ctx->ws) ? -1 : 1;
}

/* Retire this result only; no failed/error object is admitted to native cache. */
static int fragment_retire(struct continuation *d, struct delivery_fragment *f) {
    struct delivery_fragment **link = &d->fragments;
    struct delivery_fragment_grant **grant;
    struct delivery_fragment_failure *failure = calloc(1,sizeof(*failure));
    if (!failure) return 0;
    failure->url = strdup(f->url); failure->code = strdup("state-conflict");
    failure->status = 409; failure->occurrences = f->occurrences;
    if (!failure->url || !failure->code) { free(failure->url); free(failure->code); free(failure); return 0; }
    while (*link && *link != f) link = &(*link)->next;
    if (!*link) { free(failure->url); free(failure->code); free(failure); return 0; }
    *link = f->next; f->next = NULL;
    d->fragment_results->rendered = d->fragments;
    failure->next = d->fragment_results->failed; d->fragment_results->failed = failure;
    grant = &d->fragment_results->authority->fragments;
    while (*grant && strcmp((*grant)->url,f->url)) grant = &(*grant)->next;
    if (*grant) {
        struct delivery_fragment_grant *g = *grant;
        *grant = g->next;
        while (g->authority) { struct delivery_reuse_authority *a = g->authority; g->authority = a->next; free(a); }
        free(g->url); free(g);
    }
    delivery_free_fragments(f);
    return 1;
}

static void fragment_request_local(struct continuation *d, struct delivery_fragment *f) {
    struct delivery_fragment_grant **link;
    if (d->fragment_results->authority) {
        link = &d->fragment_results->authority->fragments;
        while (*link && strcmp((*link)->url,f->url)) link = &(*link)->next;
        if (*link) {
            struct delivery_fragment_grant *g = *link;
            *link = g->next;
            while (g->authority) { struct delivery_reuse_authority *a = g->authority; g->authority = a->next; free(a); }
            free(g->url); free(g);
        }
    }
    free(f->cache_key); f->cache_key = NULL;
    free(f->cache_tags); f->cache_tags = NULL;
    f->cache_ttl = 0; f->cache_deadline = 0;
}

VCL_INT vmod_fragment_deliver(VRT_CTX, struct vmod_priv *priv) {
    struct continuation *d = priv->priv;
    struct delivery_fragment *f;
    unsigned count = 0;
    if (!d || !d->fragment_batch || ctx->req->esi_level) return 0;
    if (d->failed) return -1;
    if (d->phase == D_PREPARE) {
        if (d->fragment_error_status) return (VCL_INT)d->fragment_error_status;
        if (!d->complete || http_GetStatus(ctx->http_resp) != 200 || !delivery_parse(ctx,d)) return -1;
        pthread_mutex_lock(&lock);
        if (!fragment_cache_allowed_locked(d->site,d->host,d->url))
            for (f = d->fragments; f; f = f->next) fragment_request_local(d,f);
        pthread_mutex_unlock(&lock);
        for (f = d->fragments; f; f = f->next) if (f->cache_key) {
            if (count == UINT_MAX) return -1;
            ++count;
        }
        /* Reserve exactly the finite verified dispatch sequence, not a product
         * batch cap or a browser-set global restart allowance. */
        if (ctx->req->restarts == UINT_MAX || count > UINT_MAX-ctx->req->restarts-1) return -1;
        if (ctx->req->max_restarts < ctx->req->restarts+count+1)
            ctx->req->max_restarts = ctx->req->restarts+count+1;
        d->fragment_cursor = d->fragments;
    } else if (d->phase == D_FRAGMENT_OBJECT) {
        if (!d->fragment_cursor || ctx->req->restarts != d->fragment_restart ||
            strcmp(ctx->http_req->hd[HTTP_HDR_URL].b,d->fragment_cursor->url) ||
            http_GetStatus(ctx->http_resp) != 200 ||
            !delivery_header_equals(ctx->http_resp,HDR("X-SCP-Private-Object"),"1") ||
            VRT_r_obj_ttl(ctx) <= 0) return -1;
        d->fragment_cursor = d->fragment_cursor->next;
    } else return -1;
    while ((f = d->fragment_cursor) != NULL) {
        int current;
        if (!f->cache_key) { d->fragment_cursor = f->next; continue; }
        pthread_mutex_lock(&lock); current = fragment_authority_current(d,f); pthread_mutex_unlock(&lock);
        if (!current) {
            d->fragment_cursor = f->next;
            if (!fragment_retire(d,f)) return -1;
            continue;
        }
        free(d->fragment_resume_uri);
        d->fragment_resume_uri = strdup(ctx->http_req->hd[HTTP_HDR_URL].b);
        if (!d->fragment_resume_uri) return -1;
        d->fragment_restart = ctx->req->restarts+1;
        d->phase = D_FRAGMENT_OBJECT;
        return 1;
    }
    /* Build before the final writer-lock check. If a writer retired an item,
     * remove it and rebuild. Each pass retires >=1 item, so this is finite. */
    for (;;) {
        int changed = 0;
        free(d->fragment_json); d->fragment_json = NULL;
        if (!delivery_fragment_results_json(d->fragment_batch,d->fragment_results,
            &d->fragment_json,&d->fragment_json_length)) return -1;
        pthread_mutex_lock(&lock);
        for (f = d->fragments; f; f = f->next)
            if (f->cache_key && !fragment_authority_current(d,f)) break;
        if (!f) d->phase = D_FRAGMENT_RETURN;
        else changed = 1;
        pthread_mutex_unlock(&lock);
        if (!changed) break;
        if (!fragment_retire(d,f)) return -1;
    }
    VRT_l_req_url(ctx,NULL,TOSTRAND(d->url));
    http_Unset(ctx->http_req,h_private_key);
    return WS_Overflowed(ctx->ws) ? -1 : 2;
}

VCL_BOOL vmod_fragment_synth(VRT_CTX, struct vmod_priv *priv) {
    struct continuation *d = priv->priv;
    struct vrt_blob body;
    if (!d || !d->fragment_batch || d->phase != D_FRAGMENT_RETURN || d->failed) return 0;
    http_ForceHeader(ctx->http_resp,H_Cache_Control,"private, no-store");
    http_ForceHeader(ctx->http_resp,h_surrogate_control,"no-store");
    http_ForceHeader(ctx->http_resp,H_Content_Type,"application/json; charset=UTF-8");
    http_ForceHeader(ctx->http_resp,HDR("X-Content-Type-Options"),"nosniff");
    http_ForceHeader(ctx->http_resp,HDR("X-Accel-Expires"),"0");
    if (!delivery_append_cookies(ctx,d)) { VRT_fail(ctx,"Fragment cookies unavailable"); return 1; }
    INIT_OBJ(&body,VRT_BLOB_MAGIC); body.blob = d->fragment_json; body.len = d->fragment_json_length;
    VRT_l_resp_body(ctx,LBODY_SET_BLOB,NULL,&body);
    d->phase = D_FRAGMENT_SENT;
    return 1;
}
