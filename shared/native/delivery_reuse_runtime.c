/* SPDX-License-Identifier: GPL-3.0-or-later
 * Actual request-owned protocol finalization. Metadata uses the existing HSH
 * private namespace. Optional failure never changes the original application
 * response or repeats its provider execution.
 */
#ifdef UC_EXPERIMENTAL_PRIVATE_REUSE
static const hdr_t reuse_metadata_marker = HDR("X-SCP-Reuse-Metadata");
static const hdr_t reuse_context_header = HDR("X-UltraCache-Delivery-Reuse-Context");
static unsigned delivery_reuse_discovery_hash(const char *publication, const char *representation) {
    return reuse_hash(publication)*16777619u ^ reuse_hash(representation);
}
static int delivery_reuse_discovery_grow(struct reuse_scope *scope) {
    size_t capacity = scope->discovery_capacity ? scope->discovery_capacity*2 : 16, i;
    struct reuse_discovery **buckets;
    if (capacity < scope->discovery_capacity || capacity > SIZE_MAX/sizeof(*buckets) ||
        !(buckets = calloc(capacity,sizeof(*buckets)))) return 0;
    for (i = 0; i < scope->discovery_capacity; ++i) {
        struct reuse_discovery *value = scope->discoveries[i];
        while (value) {
            struct reuse_discovery *next = value->next;
            size_t bucket = delivery_reuse_discovery_hash(value->publication,value->representation)%capacity;
            value->next = buckets[bucket]; buckets[bucket] = value; value = next;
        }
    }
    free(scope->discoveries); scope->discoveries = buckets; scope->discovery_capacity = capacity; return 1;
}
static struct reuse_discovery *delivery_reuse_discovery(struct reuse_scope *scope, const struct continuation *d) {
    struct reuse_discovery **at;
    if (!scope->discovery_capacity) return NULL;
    at = &scope->discoveries[delivery_reuse_discovery_hash(d->reuse_publication,d->reuse_representation)%scope->discovery_capacity];
    while (*at) {
        struct reuse_discovery *value = *at;
        if (value->deadline <= VTIM_real()) {
            *at = value->next; --scope->discovery_count; delivery_reuse_recipe_free(value->recipe); free(value); continue;
        }
        if (!strcmp(value->publication,d->reuse_publication) && !strcmp(value->representation,d->reuse_representation)) return value;
        at = &value->next;
    }
    return NULL;
}
static int delivery_reuse_publish_discovery(struct continuation *d, struct reuse_scope *scope,
    const struct delivery_reuse_record *record) {
    struct reuse_discovery *discovery = delivery_reuse_discovery(scope,d);
    struct delivery_reuse_recipe *recipe = NULL;
    char revision[65];
    if (discovery && !strcmp(discovery->recipe->digest,record->recipe->digest)) return 1;
    if (!reuse_random_id(revision) || !delivery_reuse_recipe_parse(record->recipe_json,record->recipe_length,
        d->occurrences,&recipe)) return 0;
    if (!discovery) {
        size_t bucket;
        if ((!scope->discovery_capacity || scope->discovery_count >= scope->discovery_capacity-scope->discovery_capacity/4) &&
            !delivery_reuse_discovery_grow(scope)) { delivery_reuse_recipe_free(recipe); return 0; }
        discovery = calloc(1,sizeof(*discovery));
        if (!discovery) { delivery_reuse_recipe_free(recipe); return 0; }
        memcpy(discovery->publication,d->reuse_publication,65); memcpy(discovery->representation,d->reuse_representation,65);
        bucket = delivery_reuse_discovery_hash(d->reuse_publication,d->reuse_representation)%scope->discovery_capacity;
        discovery->next = scope->discoveries[bucket]; scope->discoveries[bucket] = discovery; ++scope->discovery_count;
    }
    delivery_reuse_recipe_free(discovery->recipe); discovery->recipe = recipe;
    memcpy(discovery->revision,revision,65); discovery->deadline = d->public_deadline;
    return 1;
}
static int delivery_reuse_schedule(VRT_CTX, struct vmod_priv *priv, struct continuation *d) {
    char *header;
    (void)priv;
    static const char prefix[] = "/__ultracache-native/reuse-v1/";
    if (!d->reuse_candidate || d->reuse_done || d->public_deadline <= ctx->now ||
        ctx->req->restarts > UINT_MAX-2 || ctx->req->max_restarts > UINT_MAX-2) return 0;
    header = delivery_reuse_make_finalize(ctx,d);
    d->reuse_finalize_header = header;
    if (!header || !*header || !(d->reuse_metadata_uri = malloc(sizeof(prefix)+64))) {
        delivery_mutation_header_free(d->reuse_finalize_header); d->reuse_finalize_header = NULL;
        return 0;
    }
    memcpy(d->reuse_metadata_uri,prefix,sizeof(prefix)-1);
    memcpy(d->reuse_metadata_uri+sizeof(prefix)-1,d->reuse_metadata_key,65);
    /* Two finite owner transitions: metadata then original parent. Preserve
     * the original request's remaining recovery headroom by adding exactly
     * these transitions once. No global/application timeout or loop changes. */
    ctx->req->max_restarts += 2;
    free(d->body); d->body = NULL; d->length = d->capacity = 0;
    d->complete = 0; d->reuse_done = 1; d->reuse_final_restart = ctx->req->restarts+1;
    d->phase = D_FINALIZE_QUEUED; return 1;
}
static int delivery_reuse_recv(VRT_CTX, struct continuation *d) {
    if (ctx->req->restarts != d->reuse_final_restart || !d->reuse_metadata_uri || d->failed) return -1;
    if (d->phase == D_FINALIZE_QUEUED) {
        VRT_l_req_url(ctx,NULL,TOSTRAND(d->reuse_metadata_uri));
        http_ForceHeader(ctx->http_req,h_private_key,d->reuse_metadata_key);
        http_ForceHeader(ctx->http_req,h_key,d->request_id);
        http_ForceHeader(ctx->http_req,HDR("X-SCP-Key-URL"),d->reuse_metadata_uri);
        http_Unset(ctx->http_req,H_Cookie); http_Unset(ctx->http_req,H_Authorization);
        http_Unset(ctx->http_req,H_Accept_Encoding);
        VRT_l_req_hash_always_miss(ctx,1); /* fresh settlement after this actual fill */
        d->phase = D_FINALIZE;
        return WS_Overflowed(ctx->ws) ? -1 : 3;
    }
    http_Unset(ctx->http_req,h_private_key); http_Unset(ctx->http_req,HDR("X-SCP-Key-URL"));
    VRT_l_req_hash_always_miss(ctx,0);
    if (!delivery_restore(ctx,d)) return -1;
    d->phase = D_READY; return 0;
}
static int delivery_reuse_record_current(const struct continuation *d, const struct delivery_reuse_record *record,
    const struct reuse_scope *scope, int original) {
    const struct delivery_reuse_admitted_fragment *f;
    struct delivery_reuse_context page;
    unsigned char *frame = NULL;
    size_t length = 0;
    char binding[65];
    const char *fields[12];
    size_t i;
    double now = VTIM_real();
    if (!scope || !reuse_scope_ready(scope) || scope->lost_execution_context || !record ||
        record->valid_until <= now || d->public_deadline <= now || record->recipe->occurrences != d->occurrences ||
        strcmp(record->binding,d->reuse_binding) || strcmp(record->recipe->digest,d->reuse_recipe)) return 0;
    fields[0] = d->site; fields[1] = d->host; fields[2] = scope->scope; fields[3] = public_registry_epoch;
    fields[4] = scope->incarnation; fields[5] = scope->revision; fields[6] = scope->native_policy;
    fields[7] = scope->wordpress_policy; fields[8] = scope->policy; fields[9] = d->reuse_publication;
    fields[10] = d->reuse_representation; fields[11] = d->reuse_recipe;
    for (i = 0; i < 12; ++i) if (strcmp(record->context[i],fields[i])) return 0;
    page = (struct delivery_reuse_context){fields[0],fields[1],fields[2],fields[3],fields[6],fields[7],fields[8],fields[9],fields[10],fields[11]};
    if (delivery_reuse_input_projection(record->recipe->inputs,(const unsigned char *)(d->cookie ? d->cookie : ""),
        d->cookie ? strlen(d->cookie) : 0,&frame,&length) != DELIVERY_REUSE_INPUT_OK) return 0;
    i = delivery_reuse_input_mac(scope->reuse_key,&page,frame,length,binding) && !strcmp(binding,record->binding);
    delivery_reuse_frame_free(frame,length);
    if (!i) return 0;
    for (f = record->fragments; f; f = f->next) {
        const struct delivery_reuse_authority *a;
        const struct delivery_fragment *body = delivery_fragment_named(d,f->url);
        if (original && (!body || !body->cache_key || strcmp(body->cache_key,f->cache_key) ||
            !body->cache_tags || strcmp(body->cache_tags,f->cache_tags) ||
            (double)f->body_valid_until > d->prepare_response_time+(double)body->cache_ttl)) return 0;
        frame = NULL; length = 0;
        if (delivery_reuse_input_projection(f->identity_inputs,(const unsigned char *)(d->cookie ? d->cookie : ""),
            d->cookie ? strlen(d->cookie) : 0,&frame,&length) != DELIVERY_REUSE_INPUT_OK) return 0;
        i = delivery_reuse_identity_mac(scope->reuse_key,&page,frame,length,binding) && !strcmp(binding,f->identity_binding);
        delivery_reuse_frame_free(frame,length);
        if (!i) return 0;
        for (a = f->authority; a; a = a->next) {
            const struct reuse_tag *tag = reuse_tag_find((struct reuse_scope *)scope,a->tag,0);
            if (!tag || !reuse_tag_clean(scope,tag) || reuse_active(tag) || strcmp(tag->revision,a->revision) ||
                strcmp(tag->generation,a->generation)) return 0;
        }
    }
    return 1;
}
static int delivery_reuse_finish(VRT_CTX, struct continuation *d) {
    struct delivery_reuse_record *record = NULL;
    struct delivery_reuse_pin wire = {0};
    const char *marker = ctx->req->objcore ? HTTP_GetHdrPack(ctx->req->wrk,ctx->req->objcore,reuse_metadata_marker) : NULL;
    int parsed = 0;
    if (!d->reuse_failed && marker && !strcmp(marker,"1") && http_GetStatus(ctx->http_resp) == 200) {
        if (d->reuse_fetched) {
            parsed = d->complete && delivery_reuse_record_parse(d->body,d->length,&record) &&
                !strcmp(record->request_id,d->request_id) && !strcmp(record->original_url,d->url);
        } else if (!ObjIterate(ctx->req->wrk,ctx->req->objcore,&wire,delivery_reuse_chunk,1))
            parsed = delivery_reuse_record_parse(wire.copy,wire.length,&record);
    }
    if (parsed) {
        pthread_mutex_lock(&lock);
        if (delivery_reuse_record_current(d,record,delivery_reuse_current_scope(d),1)) {
            if (delivery_reuse_publish_discovery(d,delivery_reuse_current_scope(d),record)) {
                (void)reuse_identity_install(delivery_reuse_current_scope(d),record);
                delivery_reuse_record_free(d->reuse_record); d->reuse_record = record; record = NULL;
            }
        }
        pthread_mutex_unlock(&lock);
    }
    delivery_reuse_record_free(record); free(wire.copy);
    free(d->body); d->body = NULL; d->length = d->capacity = 0;
    /* Even 204, malformed metadata, cache pressure and backend failures resume
     * the completed original response, with its genuine provider cookies. */
    d->phase = D_FINALIZE_RETURN; d->reuse_final_restart = ctx->req->restarts+1;
    return 1;
}
static int delivery_reuse_try_hit(VRT_CTX, struct vmod_priv *priv, struct continuation *d) {
    struct reuse_scope *scope;
    struct public_declaration *declaration;
    struct reuse_discovery *discovery;
    struct delivery_reuse_context page;
    struct delivery_fragment metadata = {0}, **tail = &d->fragments;
    struct delivery_reuse_pin wire = {0}, *pin;
    struct delivery_reuse_record *record = NULL;
    const struct delivery_reuse_admitted_fragment *admitted;
    unsigned char *frame = NULL;
    size_t length = 0;
    const char *native_policy = reuse_single(ctx->http_req,HDR("X-SCP-Selection-Native-Policy"));
    char uri[sizeof("/__ultracache-native/reuse-v1/")+64];
    int found = 0, valid = 0;
    if (!*d->reuse_publication || !*d->reuse_representation || !native_policy) return 0;
    pthread_mutex_lock(&lock);
    declaration = public_declaration_for_url(d->site,d->host,d->url);
    scope = declaration ? reuse_scope_find(d->site,d->host,declaration->scope) : NULL;
    if (!scope || !scope->enabled || !reuse_scope_ready(scope) || strcmp(native_policy,scope->native_policy) ||
        strcmp(declaration->wordpress_policy,scope->wordpress_policy) || !(discovery = delivery_reuse_discovery(scope,d)) ||
        discovery->recipe->occurrences != d->occurrences) goto unlock;
    page = (struct delivery_reuse_context){d->site,d->host,scope->scope,public_registry_epoch,
        scope->native_policy,scope->wordpress_policy,scope->policy,d->reuse_publication,d->reuse_representation,discovery->recipe->digest};
    if (delivery_reuse_input_projection(discovery->recipe->inputs,(const unsigned char *)(d->cookie ? d->cookie : ""),
        d->cookie ? strlen(d->cookie) : 0,&frame,&length) != DELIVERY_REUSE_INPUT_OK ||
        !delivery_reuse_input_mac(scope->reuse_key,&page,frame,length,d->reuse_binding) ||
        !delivery_reuse_metadata_key(&page,d->reuse_binding,d->reuse_metadata_key) || !(d->reuse_scope = strdup(scope->scope))) goto unlock;
    memcpy(d->reuse_epoch,public_registry_epoch,65); memcpy(d->reuse_incarnation,scope->incarnation,65);
    memcpy(d->reuse_native_policy,scope->native_policy,65); memcpy(d->reuse_wp_policy,scope->wordpress_policy,65);
    memcpy(d->reuse_policy,scope->policy,65); memcpy(d->reuse_recipe,discovery->recipe->digest,65);
    memcpy(d->reuse_discovery_revision,discovery->revision,65); d->reuse_negotiated = 1; found = 1;
unlock:
    pthread_mutex_unlock(&lock); delivery_reuse_frame_free(frame,length);
    if (!found) goto done;
    snprintf(uri,sizeof(uri),"/__ultracache-native/reuse-v1/%s",d->reuse_metadata_key);
    metadata.url = uri; metadata.cache_key = d->reuse_metadata_key;
    wire.object = delivery_reuse_lookup(ctx,d,&metadata);
    if (!wire.object || !HTTP_GetHdrPack(ctx->req->wrk,wire.object,reuse_metadata_marker) ||
        strcmp(HTTP_GetHdrPack(ctx->req->wrk,wire.object,reuse_metadata_marker),"1") ||
        ObjIterate(ctx->req->wrk,wire.object,&wire,delivery_reuse_chunk,1) ||
        !delivery_reuse_record_parse(wire.copy,wire.length,&record)) goto done;
    pthread_mutex_lock(&lock);
    valid = delivery_reuse_record_current(d,record,delivery_reuse_current_scope(d),0);
    pthread_mutex_unlock(&lock);
    if (!valid) goto done;
    valid = 0;
    for (admitted = record->fragments; admitted; admitted = admitted->next) {
        struct delivery_fragment *fragment = calloc(1,sizeof(*fragment));
        const struct delivery_reuse_descriptor *descriptor;
        if (!fragment) goto done;
        *tail = fragment; tail = &fragment->next;
        fragment->url = strdup(admitted->url); fragment->html = strdup("");
        fragment->cache_key = strdup(admitted->cache_key); fragment->cache_tags = strdup(admitted->cache_tags);
        fragment->cache_ttl = admitted->cache_ttl; fragment->cache_deadline = (double)admitted->body_valid_until;
        for (descriptor = record->recipe->fragments; descriptor; descriptor = descriptor->next)
            if (!strcmp(descriptor->descriptor,admitted->descriptor)) break;
        if (!descriptor || !fragment->url || !fragment->html || !fragment->cache_key || !fragment->cache_tags) goto done;
        fragment->occurrences = descriptor->occurrences;
    }
    d->phase = D_READY; d->reuse_fast = 1;
    if (vmod_delivery_reuse_resolve(ctx,priv) != 1 || !vmod_delivery_reuse_materialize(ctx,priv)) goto done;
    /* No body/header is exposed until every required native object is pinned,
     * complete and copied. The last scope/authority check shares the writer lock. */
    pthread_mutex_lock(&lock);
    scope = delivery_reuse_current_scope(d);
    discovery = scope ? delivery_reuse_discovery(scope,d) : NULL;
    valid = discovery && !strcmp(discovery->revision,d->reuse_discovery_revision) &&
        delivery_reuse_record_current(d,record,scope,0) && wire.object->t_origin+wire.object->ttl > VTIM_real();
    if (valid) {
        struct objcore *current_parent = delivery_reuse_lookup(ctx,d,NULL);
        struct objcore *current_metadata = delivery_reuse_lookup(ctx,d,&metadata);
        valid = current_parent && current_parent == ctx->req->objcore && current_metadata && current_metadata == wire.object;
        if (current_parent) (void)HSH_DerefObjCore(ctx->req->wrk,&current_parent);
        if (current_metadata) (void)HSH_DerefObjCore(ctx->req->wrk,&current_metadata);
    }
    for (pin = d->reuse_plan->pins; valid && pin; pin = pin->next) {
        struct objcore *current = delivery_reuse_lookup(ctx,d,pin->fragment);
        valid = current && current == pin->object && pin->deadline > VTIM_real();
        if (current) (void)HSH_DerefObjCore(ctx->req->wrk,&current);
    }
    pthread_mutex_unlock(&lock);
    if (valid) { d->reuse_record = record; record = NULL; }
done:
    delivery_reuse_record_free(record); free(wire.copy);
    if (wire.object) (void)HSH_DerefObjCore(ctx->req->wrk,&wire.object);
    if (!valid) {
        delivery_reuse_release(ctx,d->reuse_plan); d->reuse_plan = NULL;
        delivery_free_fragments(d->fragments); d->fragments = NULL; d->reuse_fast = d->reuse_negotiated = 0;
        free(d->reuse_scope); d->reuse_scope = NULL; d->reuse_recipe[0] = 0;
    }
    return valid;
}
#else
static int delivery_reuse_schedule(VRT_CTX, struct vmod_priv *p, struct continuation *d) { (void)ctx; (void)p; (void)d; return 0; }
static int delivery_reuse_recv(VRT_CTX, struct continuation *d) { (void)ctx; (void)d; return -1; }
static int delivery_reuse_finish(VRT_CTX, struct continuation *d) { (void)ctx; (void)d; return -1; }
static int delivery_reuse_try_hit(VRT_CTX, struct vmod_priv *p, struct continuation *d) { (void)ctx; (void)p; (void)d; return 0; }
#endif
VCL_BOOL vmod_delivery_reuse_pending(VRT_CTX, struct vmod_priv *priv) {
    const struct continuation *d = priv->priv;
    return !ctx->req->esi_level && d && d->phase == D_FINALIZE;
}
VCL_BOOL vmod_delivery_reuse_backend(VRT_CTX, struct vmod_priv *priv) {
#ifdef UC_EXPERIMENTAL_PRIVATE_REUSE
    struct task *task = priv->priv;
    struct handoff *entry;
    struct continuation *d;
    int owned = 0;
    if (!task || !task->key) return 0;
    pthread_mutex_lock(&lock);
    entry = delivery_entry(task->key); d = entry ? entry->delivery : NULL;
    if (d && d->phase == D_FINALIZE && !d->reuse_fetched && d->reuse_finalize_header &&
        delivery_header_equals(ctx->http_bereq,h_private_key,d->reuse_metadata_key)) {
        owned = d->reuse_fetched = 1;
        http_ForceField(ctx->http_bereq,HTTP_HDR_METHOD,"GET");
        http_SetH(ctx->http_bereq,HTTP_HDR_URL,WS_Copy(ctx->ws,d->url,-1));
        http_ForceHeader(ctx->http_bereq,h_version,"1"); http_ForceHeader(ctx->http_bereq,h_phase,"reuse-finalize");
        http_ForceHeader(ctx->http_bereq,h_request,d->request_id); http_ForceHeader(ctx->http_bereq,h_original,d->url);
        http_ForceHeader(ctx->http_bereq,h_selection_scope,d->reuse_scope);
        http_ForceHeader(ctx->http_bereq,HDR("X-UltraCache-Delivery-Reuse-Version"),"1");
        http_ForceHeader(ctx->http_bereq,HDR("X-UltraCache-Delivery-Reuse-Recipe"),d->reuse_recipe);
        http_ForceHeader(ctx->http_bereq,HDR("X-UltraCache-Private-Request-Id"),d->reuse_origin_request);
        http_ForceHeader(ctx->http_bereq,HDR("X-UltraCache-Private-Challenge"),d->reuse_origin_challenge);
        http_ForceHeader(ctx->http_bereq,reuse_context_header,d->reuse_finalize_header);
        http_Unset(ctx->http_bereq,H_Cookie); http_Unset(ctx->http_bereq,H_Authorization);
        http_Unset(ctx->http_bereq,H_Accept_Encoding);
        http_Unset(ctx->http_bereq,h_mutation_context); http_Unset(ctx->http_bereq,h_mutation_receipt);
        http_Unset(ctx->http_bereq,HDR("X-UltraCache-Delivery-Reuse-Candidate-Version"));
    }
    pthread_mutex_unlock(&lock); return owned;
#else
    (void)ctx; (void)priv; return 0;
#endif
}
VCL_BOOL vmod_delivery_reuse_response(VRT_CTX, struct vmod_priv *priv) {
#ifdef UC_EXPERIMENTAL_PRIVATE_REUSE
    struct task *task = priv->priv;
    struct handoff *entry;
    struct continuation *d;
    struct vmod_priv *filter;
    const char *remaining, *type;
    char *end;
    unsigned long long ttl = 0;
    int owned = 0, valid = 0;
    if (!task || !task->key) return 0;
    pthread_mutex_lock(&lock);
    entry = delivery_entry(task->key); d = entry ? entry->delivery : NULL;
    if (d && d->phase == D_FINALIZE && d->reuse_fetched) {
        owned = 1;
        remaining = reuse_single(ctx->http_beresp,HDR("X-UltraCache-Delivery-Reuse-Fresh-Remaining"));
        type = reuse_single(ctx->http_beresp,H_Content_Type);
        if (remaining && *remaining) {
            for (end = (char *)remaining; *end && *end >= '0' && *end <= '9'; ++end) {}
            if (!*end) { errno = 0; ttl = strtoull(remaining,&end,10); if (errno || *end) ttl = 0; }
        }
        valid = ttl && http_GetStatus(ctx->http_beresp) == 200 &&
            delivery_header_equals(ctx->http_beresp,HDR("X-UltraCache-Delivery-Reuse-Outcome"),"finalized") &&
            type && !strcmp(type,"application/vnd.ultracache.reuse+json") &&
            !http_CountHdr(ctx->http_beresp,H_Set_Cookie) && !http_CountHdr(ctx->http_beresp,h_set_cookie2) &&
            !http_CountHdr(ctx->http_beresp,H_Content_Encoding) && d->public_deadline > ctx->now;
        filter = VRT_priv_task(ctx,&filter_task_token);
        if (filter) filter->priv = &task->key; else valid = 0;
        if (valid) {
            http_ForceHeader(ctx->http_beresp,HDR("X-SCP-Private-Object"),"1");
            http_ForceHeader(ctx->http_beresp,reuse_metadata_marker,"1");
            VRT_l_beresp_ttl(ctx,fmin((double)ttl,d->public_deadline-ctx->now));
        } else {
            d->reuse_failed = 1;
            VRT_l_beresp_ttl(ctx,0); VRT_l_beresp_uncacheable(ctx,1);
        }
        http_Unset(ctx->http_beresp,H_Set_Cookie); http_Unset(ctx->http_beresp,h_set_cookie2);
        http_Unset(ctx->http_beresp,H_Vary);
    }
    pthread_mutex_unlock(&lock); return owned;
#else
    (void)ctx; (void)priv; return 0;
#endif
}
