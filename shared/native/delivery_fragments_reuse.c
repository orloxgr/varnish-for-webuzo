/* SPDX-License-Identifier: GPL-3.0-or-later
 * Fragment-only admission. Bodies and visitor-bound receipts are ordinary
 * native objects. The registry retains declarations and exact authenticated
 * ticket membership only; a missing dependency uses the existing producer.
 */
#ifdef UC_NATIVE_PRIVATE_REUSE
static struct reuse_scope *fragment_admission_scope(const struct continuation *d) {
    struct reuse_scope *scope = reuse_scope_find(d->site,d->host,d->fragment_scope);
    const struct public_declaration *declaration = public_declaration(d->site,d->host,d->fragment_scope);
    return reuse_scope_ready(scope) && !scope->fragment_cache_disabled && scope->fragment_route && declaration &&
        d->selection_policy && !strcmp(d->selection_policy,scope->native_policy) &&
        !strcmp(d->fragment_batch->context[0],scope->wordpress_policy) &&
        !strcmp(declaration->wordpress_policy,scope->wordpress_policy) ? scope : NULL;
}
static struct delivery_reuse_context fragment_admission_context(const struct continuation *d, const struct reuse_scope *scope) {
    return (struct delivery_reuse_context){d->site,d->host,scope->scope,public_registry_epoch,
        scope->native_policy,scope->wordpress_policy,scope->policy,NULL,NULL,NULL};
}
static void fragment_discovery_expire(struct reuse_scope *scope, double now) {
    struct fragment_discovery **discovery = &scope->fragment_discoveries;
    struct fragment_ticket **ticket = &scope->fragment_tickets;
    while (*discovery) {
        struct fragment_discovery *row = *discovery;
        if (row->deadline > now) { discovery = &row->next; continue; }
        *discovery = row->next; free(row->url); free(row->inputs_json); free(row);
    }
    while (*ticket) {
        struct fragment_ticket *row = *ticket;
        if (row->deadline > now) { ticket = &row->next; continue; }
        *ticket = row->next; free(row);
    }
}
static int fragment_ticket_known(struct reuse_scope *scope, const char *digest, double now) {
    const struct fragment_ticket *row;
    fragment_discovery_expire(scope,now);
    for (row = scope->fragment_tickets; row; row = row->next)
        if (!strcmp(row->digest,digest)) return row->deadline > now;
    return 0;
}
static int fragment_row_binding(const struct continuation *d, const struct reuse_scope *scope,
    const struct delivery_reuse_inputs *inputs, char binding[65]) {
    struct delivery_reuse_context context = fragment_admission_context(d,scope);
    unsigned char *frame = NULL;
    size_t length = 0;
    int valid = delivery_reuse_input_projection(inputs,(const unsigned char *)(d->cookie ? d->cookie : ""),
        strlen(d->cookie ? d->cookie : ""),&frame,&length) == DELIVERY_REUSE_INPUT_OK &&
        delivery_reuse_identity_mac(scope->reuse_key,&context,frame,length,binding);
    delivery_reuse_frame_free(frame,length); return valid;
}
static double fragment_row_deadline(const struct delivery_fragment_admission *admission,
    const struct delivery_reuse_admitted_fragment *row) {
    return fmin((double)admission->cookie_valid_until,
        fmin((double)row->body_valid_until,(double)row->identity_valid_until));
}
/* Both input dimensions are checked. Identity alone cannot authorize a body
 * rendered with different recently-viewed, currency or other declared inputs. */
static int fragment_row_current(const struct continuation *d, const struct reuse_scope *scope,
    const struct delivery_fragment_admission *admission, const struct delivery_reuse_admitted_fragment *row,
    int original) {
    char binding[65];
    const struct delivery_fragment *body = original ? delivery_fragment_named(d,row->url) : NULL;
    if (!scope || !admission || !row->inputs || fragment_row_deadline(admission,row) <= VTIM_real() ||
        !delivery_selection_scope_matches(scope->scope,row->url) ||
        !fragment_row_binding(d,scope,row->inputs,binding) || strcmp(binding,row->input_binding) ||
        !fragment_row_binding(d,scope,row->identity_inputs,binding) || strcmp(binding,row->identity_binding) ||
        reuse_authority_current_reason(scope,row->authority)) return 0;
    if (original && (!body || !body->cache_key || !body->cache_tags ||
        strcmp(body->cache_key,row->cache_key) || strcmp(body->cache_tags,row->cache_tags) ||
        body->cache_anonymous != row->anonymous || !fragment_authority_current(d,body))) return 0;
    return 1;
}
static int fragment_row_key(const struct continuation *d, const struct reuse_scope *scope,
    const struct delivery_reuse_admitted_fragment *row, char key[65]) {
    struct delivery_reuse_context context = fragment_admission_context(d,scope);
    return delivery_fragment_metadata_key(&context,scope->incarnation,scope->revision,
        row->descriptor,row->input_binding,key);
}
static int fragment_admission_source_current(const struct continuation *d, const struct delivery_fragment *metadata) {
    const struct delivery_fragment_admission *admission = d->fragment_results ? d->fragment_results->admission : NULL;
    const struct delivery_reuse_admitted_fragment *row;
    struct reuse_scope *scope = fragment_admission_scope(d);
    char key[65];
    if (!scope || !admission || !metadata || metadata->cache_deadline <= VTIM_real()) return 0;
    for (row = admission->fragments; row; row = row->next)
        if (fragment_row_key(d,scope,row,key) && !strcmp(key,metadata->cache_key))
            return fragment_row_current(d,scope,admission,row,1);
    return 0;
}
static int fragment_admission_sources(struct continuation *d) {
    const struct delivery_fragment_admission *admission = d->fragment_results ? d->fragment_results->admission : NULL;
    const struct delivery_reuse_admitted_fragment *row;
    struct delivery_fragment **tail = &d->fragment_metadata;
    struct reuse_scope *scope = fragment_admission_scope(d);
    if (!scope || !admission || !d->fragment_results->authority) return 0;
    for (row = admission->fragments; row; row = row->next) {
        struct delivery_fragment *metadata;
        const struct delivery_fragment *body = delivery_fragment_named(d,row->url);
        struct vsb *wire;
        char key[65], uri[sizeof("/__ultracache-native/reuse-v1/")+64];
        double deadline;
        if (!fragment_row_current(d,scope,admission,row,1) || !fragment_row_key(d,scope,row,key)) continue;
        deadline = fmin(fragment_row_deadline(admission,row),delivery_fragment_deadline(d,body));
        if (!isfinite(deadline) || deadline <= VTIM_real()) continue;
        wire = VSB_new_auto();
        if (!wire) return 0;
        VSB_printf(wire,"{\"version\":1,\"cookieValidUntil\":%" PRIu64 ",\"fragments\":[",admission->cookie_valid_until);
        VSB_bcat(wire,row->wire,row->wire_length); VSB_cat(wire,"]}");
        if (VSB_finish(wire)) { VSB_destroy(&wire); return 0; }
        metadata = calloc(1,sizeof(*metadata));
        if (!metadata) { VSB_destroy(&wire); return 0; }
        snprintf(uri,sizeof(uri),"/__ultracache-native/reuse-v1/%s",key);
        metadata->url = strdup(uri); metadata->html = strdup(VSB_data(wire));
        metadata->length = VSB_len(wire); metadata->cache_key = strdup(key);
        metadata->cache_tags = strdup(row->cache_tags); metadata->cache_ttl = row->cache_ttl;
        metadata->cache_deadline = deadline;
        VSB_destroy(&wire);
        if (!metadata->url || !metadata->html || !metadata->cache_key || !metadata->cache_tags) {
            delivery_free_fragments(metadata); return 0;
        }
        *tail = metadata; tail = &metadata->next;
    }
    return d->fragment_metadata != NULL;
}
/* Learn no binding, Cookie value or body here. Only a successful authenticated
 * full-ticket preparation may publish these declarations/membership facts. */
static void fragment_admission_publish(struct continuation *d) {
    struct reuse_scope *scope = fragment_admission_scope(d);
    const struct delivery_fragment_admission *admission = d->fragment_results->admission;
    const struct delivery_reuse_admitted_fragment *row;
    const struct delivery_fragment *metadata;
    struct fragment_ticket *ticket;
    double deadline = 0;
    if (!scope || !admission) return;
    fragment_discovery_expire(scope,VTIM_real());
    for (row = admission->fragments; row; row = row->next) {
        struct fragment_discovery *discovery;
        char key[65], *url, *inputs;
        if (!fragment_row_current(d,scope,admission,row,1) || !fragment_row_key(d,scope,row,key)) continue;
        for (metadata = d->fragment_metadata; metadata; metadata = metadata->next)
            if (!strcmp(metadata->cache_key,key)) break;
        if (!metadata || !fragment_admission_source_current(d,metadata)) continue;
        url = strdup(row->url); inputs = strdup(row->inputs_json);
        if (!url || !inputs) { free(url); free(inputs); continue; }
        for (discovery = scope->fragment_discoveries; discovery; discovery = discovery->next)
            if (!strcmp(discovery->url,row->url)) break;
        if (!discovery) {
            discovery = calloc(1,sizeof(*discovery));
            if (!discovery) { free(url); free(inputs); continue; }
            discovery->next = scope->fragment_discoveries; scope->fragment_discoveries = discovery;
        }
        if (discovery->inputs_json && !strcmp(discovery->inputs_json,inputs) &&
            !strcmp(discovery->descriptor,row->descriptor))
            discovery->deadline = fmax(discovery->deadline,metadata->cache_deadline);
        else discovery->deadline = metadata->cache_deadline;
        free(discovery->url); free(discovery->inputs_json);
        discovery->url = url; discovery->inputs_json = inputs;
        memcpy(discovery->descriptor,row->descriptor,65);
        deadline = fmax(deadline,metadata->cache_deadline);
    }
    if (!deadline) return;
    for (ticket = scope->fragment_tickets; ticket; ticket = ticket->next)
        if (!strcmp(ticket->digest,d->fragment_ticket)) break;
    if (!ticket) {
        ticket = calloc(1,sizeof(*ticket));
        if (!ticket) return;
        memcpy(ticket->digest,d->fragment_ticket,65);
        ticket->next = scope->fragment_tickets; scope->fragment_tickets = ticket;
    }
    ticket->deadline = fmax(ticket->deadline,deadline);
}
static struct delivery_reuse_authority *fragment_authority_clone(const struct delivery_reuse_authority *source) {
    struct delivery_reuse_authority *head = NULL, **tail = &head;
    for (; source; source = source->next) {
        *tail = malloc(sizeof(**tail));
        if (!*tail) {
            while (head) { struct delivery_reuse_authority *next = head->next; free(head); head = next; }
            return NULL;
        }
        **tail = *source; (*tail)->next = NULL; tail = &(*tail)->next;
    }
    return head;
}
static int fragment_admission_try_hit(VRT_CTX, struct continuation *d) {
    struct reuse_scope *scope;
    const struct delivery_fragment_request *request;
    struct delivery_fragment_results *results = NULL;
    struct delivery_fragment_admission *admission = NULL;
    struct delivery_reuse_pin *pin;
    const char *reason = "scope-unavailable";
    int valid = 0;
    pthread_mutex_lock(&lock);
    scope = fragment_admission_scope(d);
    if (!scope) goto done;
    reason = "ticket-not-authenticated";
    if (!fragment_ticket_known(scope,d->fragment_ticket,VTIM_real())) goto done;
    results = calloc(1,sizeof(*results)); admission = calloc(1,sizeof(*admission));
    d->reuse_plan = calloc(1,sizeof(*d->reuse_plan));
    if (!results || !admission || !d->reuse_plan) goto done;
    results->admission = admission; admission = NULL;
    results->authority = calloc(1,sizeof(*results->authority));
    if (!results->authority) goto done;
    results->authority->scope = strdup(scope->scope);
    if (!results->authority->scope) goto done;
    memcpy(results->authority->epoch,public_registry_epoch,65);
    memcpy(results->authority->incarnation,scope->incarnation,65);
    memcpy(results->authority->scope_revision,scope->revision,65);
    memcpy(results->authority->native_policy,scope->native_policy,65);
    memcpy(results->authority->wordpress_policy,scope->wordpress_policy,65);
    memcpy(results->authority->reuse_policy,scope->policy,65);
    for (request = d->fragment_batch->requested; request; request = request->next) {
        struct fragment_discovery *discovery;
        struct delivery_fragment *metadata = NULL, *body = NULL;
        struct delivery_reuse_inputs *inputs = NULL;
        struct delivery_fragment_admission *row_admission = NULL;
        struct delivery_reuse_admitted_fragment *row;
        struct delivery_fragment_grant *grant;
        struct delivery_reuse_context context = fragment_admission_context(d,scope);
        char binding[65], key[65], uri[sizeof("/__ultracache-native/reuse-v1/")+64];
        reason = "descriptor-unavailable";
        for (discovery = scope->fragment_discoveries; discovery; discovery = discovery->next)
            if (!strcmp(discovery->url,request->url)) break;
        if (!discovery || delivery_reuse_inputs_parse(discovery->inputs_json,strlen(discovery->inputs_json),&inputs) != DELIVERY_REUSE_INPUT_OK) goto done;
        {
            int projected = fragment_row_binding(d,scope,inputs,binding) && delivery_fragment_metadata_key(&context,
                scope->incarnation,scope->revision,discovery->descriptor,binding,key);
            delivery_reuse_inputs_free(inputs);
            if (!projected) { reason = "input-projection-rejected"; goto done; }
        }
        metadata = calloc(1,sizeof(*metadata)); pin = calloc(1,sizeof(*pin));
        if (!metadata || !pin) { free(metadata); free(pin); goto done; }
        snprintf(uri,sizeof(uri),"/__ultracache-native/reuse-v1/%s",key);
        metadata->url = strdup(uri); metadata->cache_key = strdup(key);
        metadata->next = d->fragment_metadata; d->fragment_metadata = metadata;
        pin->fragment = metadata; pin->next = d->reuse_plan->pins; d->reuse_plan->pins = pin;
        reason = "metadata-object-unavailable";
        if (!metadata->url || !metadata->cache_key || !(pin->object = delivery_reuse_lookup(ctx,d,metadata))) goto done;
        pin->deadline = pin->object->t_origin+pin->object->ttl;
        if (pin->deadline <= VTIM_real() || ObjIterate(ctx->req->wrk,pin->object,pin,delivery_reuse_chunk,1) ||
            pin->length != ObjGetLen(ctx->req->wrk,pin->object) ||
            !delivery_fragment_admission_parse(pin->copy,pin->length,&row_admission)) goto done;
        row = row_admission->fragments;
        reason = "metadata-binding-rejected";
        if (!row || row->next || strcmp(row->url,request->url) || strcmp(row->descriptor,discovery->descriptor) ||
            strcmp(row->input_binding,binding) || !fragment_row_current(d,scope,row_admission,row,0)) {
            delivery_fragment_admission_free(row_admission); goto done;
        }
        pin->deadline = fmin(pin->deadline,fragment_row_deadline(row_admission,row));
        if (!results->admission->cookie_valid_until || results->admission->cookie_valid_until > row_admission->cookie_valid_until)
            results->admission->cookie_valid_until = row_admission->cookie_valid_until;
        row_admission->fragments = NULL; delivery_fragment_admission_free(row_admission);
        row->next = results->admission->fragments; results->admission->fragments = row;
        body = calloc(1,sizeof(*body)); grant = calloc(1,sizeof(*grant));
        if (!body || !grant) { free(body); free(grant); goto done; }
        body->next = results->rendered; results->rendered = body;
        grant->next = results->authority->fragments; results->authority->fragments = grant;
        body->url = strdup(row->url); body->cache_key = strdup(row->cache_key); body->cache_tags = strdup(row->cache_tags);
        body->cache_ttl = row->cache_ttl; body->cache_anonymous = row->anonymous; body->occurrences = request->occurrences;
        body->cache_deadline = pin->deadline;
        grant->url = strdup(row->url); grant->authority = fragment_authority_clone(row->authority);
        if (!body->url || !body->cache_key || !body->cache_tags || !grant->url || (row->authority && !grant->authority)) goto done;
        pin = calloc(1,sizeof(*pin));
        if (!pin) goto done;
        pin->fragment = body; pin->next = d->reuse_plan->pins; d->reuse_plan->pins = pin;
        reason = "body-object-unavailable";
        if (!(pin->object = delivery_reuse_lookup(ctx,d,body))) goto done;
        pin->deadline = fmin(body->cache_deadline,pin->object->t_origin+pin->object->ttl);
        if (pin->deadline <= VTIM_real() || ObjIterate(ctx->req->wrk,pin->object,pin,delivery_reuse_chunk,1) ||
            pin->length != ObjGetLen(ctx->req->wrk,pin->object) || (!pin->copy && delivery_reuse_chunk(pin,0,"",0))) goto done;
        body->html = pin->copy; pin->copy = NULL; body->length = pin->length;
        body->cache_deadline = pin->deadline;
    }
    d->fragment_results = results; results = NULL; d->fragments = d->fragment_results->rendered;
    reason = "final-authority-rejected";
    for (request = d->fragment_batch->requested; request; request = request->next)
        if (!fragment_authority_current(d,delivery_fragment_named(d,request->url))) goto done;
    for (pin = d->reuse_plan->pins; pin; pin = pin->next) {
        struct objcore *current = delivery_reuse_lookup(ctx,d,pin->fragment);
        int same = current && current == pin->object && pin->deadline > VTIM_real();
        if (current) (void)HSH_DerefObjCore(ctx->req->wrk,&current);
        if (!same) { reason = "final-object-retired"; goto done; }
    }
    if (!fragment_ticket_known(scope,d->fragment_ticket,VTIM_real()) ||
        !delivery_fragment_results_json(d->fragment_batch,d->fragment_results,&d->fragment_json,&d->fragment_json_length)) goto done;
    d->fragment_fast = 1; d->phase = D_FRAGMENT_RETURN; valid = 1;
done:
    pthread_mutex_unlock(&lock);
    if (!valid) {
        delivery_reuse_release(ctx,d->reuse_plan); d->reuse_plan = NULL;
        delivery_fragment_results_free(results); delivery_fragment_admission_free(admission);
        delivery_fragment_results_free(d->fragment_results); d->fragment_results = NULL; d->fragments = NULL;
        delivery_free_fragments(d->fragment_metadata); d->fragment_metadata = NULL;
        free(d->fragment_json); d->fragment_json = NULL; d->fragment_json_length = 0;
    }
    VSLb(ctx->vsl,SLT_Debug,"uc-fragments admission=%s reason=%s",valid ? "hit" : "miss",valid ? "complete-native-plan" : reason);
    return valid;
}
#else
static int fragment_admission_try_hit(VRT_CTX, struct continuation *d) { (void)ctx; (void)d; return 0; }
static int fragment_admission_sources(struct continuation *d) { (void)d; return 0; }
static int fragment_admission_source_current(const struct continuation *d, const struct delivery_fragment *f) { (void)d; (void)f; return 0; }
static void fragment_admission_publish(struct continuation *d) { (void)d; }
#endif
