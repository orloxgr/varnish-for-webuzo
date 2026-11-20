/* SPDX-License-Identifier: GPL-3.0-or-later
 * Included by delivery_continuation.c. Registry contains declarations only:
 * site/host, exact resolver names and WP policy identity, never cookie values.
 */
struct public_declaration {
    struct public_declaration *next;
    char *site, *host, *wordpress_policy, *names;
};
static struct public_declaration *public_declarations;
static unsigned public_selection_vcls;

static void public_declaration_free(struct public_declaration *p) {
    free(p->site); free(p->host); free(p->wordpress_policy); free(p->names); free(p);
}
static void public_selection_vcl_event(enum vcl_event_e event) {
    pthread_mutex_lock(&lock);
    if (event == VCL_EVENT_LOAD) ++public_selection_vcls;
    else if (event == VCL_EVENT_DISCARD && public_selection_vcls && !--public_selection_vcls) {
        while (public_declarations) {
            struct public_declaration *next = public_declarations->next;
            public_declaration_free(public_declarations); public_declarations = next;
        }
    }
    pthread_mutex_unlock(&lock);
}
static struct public_declaration *public_declaration(const char *site, const char *host) {
    struct public_declaration *p;
    for (p = public_declarations; p; p = p->next)
        if (!strcmp(p->site,site) && !strcmp(p->host,host)) return p;
    return NULL;
}
static int public_policy(const char *s) {
    size_t i;
    if (!s || strlen(s) != 64) return 0;
    for (i = 0; i < 64; ++i)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return 0;
    return 1;
}
static char *public_names(const char *names) {
    const char *p = names;
    char *out;
    size_t used = 0;
    if (!p || !*p) return NULL;
    out = malloc(strlen(p)+1);
    if (!out) return NULL;
    while (*p) {
        const char *end = strchr(p,','), *name = p, *previous;
        size_t n;
        if (!end) end = p+strlen(p);
        while (name < end && (*name == ' ' || *name == '\t')) ++name;
        while (end > name && (end[-1] == ' ' || end[-1] == '\t')) --end;
        n = (size_t)(end-name);
        if (!delivery_cookie_name(name,n)) goto invalid;
        for (previous = out; previous < out+used;) {
            const char *separator = memchr(previous,',',(size_t)(out+used-previous));
            size_t length = separator ? (size_t)(separator-previous) : (size_t)(out+used-previous);
            if (n == length && !memcmp(previous,name,n)) goto invalid;
            previous += length+(separator != NULL);
        }
        if (used) out[used++] = ',';
        memcpy(out+used,name,n); used += n;
        p = strchr(p,',');
        if (!p) break;
        if (!*++p) goto invalid;
    }
    out[used] = 0; return out;
invalid:
    free(out); return NULL;
}
static char *public_actions(const char *rules, const char *names, int *has_variant) {
    const char *p = names;
    size_t length = names ? strlen(names) : 0, used = 0;
    char *out;
    if (has_variant) *has_variant = 0;
    if (length > (SIZE_MAX-3)/16) return NULL;
    out = malloc(length*16+3);
    if (!out) return NULL;
    out[used++] = '{';
    while (p && *p) {
        const char *end = strchr(p,','), *action;
        int selected;
        size_t n;
        if (!end) end = p+strlen(p);
        n = (size_t)(end-p);
        selected = delivery_cookie_action(rules,p,n);
        if (selected < 0) { free(out); return NULL; }
        action = selected == 1 ? "variant" : selected == 2 ? "private" : "shared";
        if (selected == 1 && has_variant) *has_variant = 1;
        if (used > 1) out[used++] = ',';
        out[used++] = '"'; memcpy(out+used,p,n); used += n;
        out[used++] = '"'; out[used++] = ':'; out[used++] = '"';
        memcpy(out+used,action,strlen(action)); used += strlen(action); out[used++] = '"';
        p = *end ? end+1 : end;
    }
    out[used++] = '}'; out[used] = 0; return out;
}
VCL_STRING vmod_selection_epoch(VRT_CTX) { (void)ctx; return PACKAGE_VERSION; }
VCL_BOOL vmod_selection_register(VRT_CTX, VCL_STRING site, VCL_STRING host,
    VCL_STRING wordpress_policy, VCL_STRING names, VCL_BOOL enabled) {
    struct public_declaration *next = NULL, **p;
    (void)ctx;
    if (!site || !*site || !host || !*host || (enabled && !public_policy(wordpress_policy))) return 0;
    if (enabled) {
        next = calloc(1,sizeof(*next));
        if (!next) return 0;
        next->site = strdup(site); next->host = strdup(host);
        next->wordpress_policy = strdup(wordpress_policy); next->names = public_names(names);
        if (!next->site || !next->host || !next->wordpress_policy || !next->names) { public_declaration_free(next); return 0; }
    }
    pthread_mutex_lock(&lock);
    p = &public_declarations;
    while (*p && (strcmp((*p)->site,site) || strcmp((*p)->host,host))) p = &(*p)->next;
    if (*p) {
        struct public_declaration *old = *p;
        *p = old->next; public_declaration_free(old);
    }
    if (next) { next->next = public_declarations; public_declarations = next; }
    pthread_mutex_unlock(&lock); return 1;
}
VCL_STRING vmod_selection_names(VRT_CTX, VCL_STRING site, VCL_STRING host) {
    struct public_declaration *p;
    const char *out = NULL;
    if (!site || !host) return NULL;
    pthread_mutex_lock(&lock); p = public_declaration(site,host);
    if (p) out = WS_Copy(ctx->ws,p->names,-1);
    pthread_mutex_unlock(&lock); return out;
}
VCL_STRING vmod_selection_wordpress_policy(VRT_CTX, VCL_STRING site, VCL_STRING host) {
    struct public_declaration *p;
    const char *out = NULL;
    if (!site || !host) return NULL;
    pthread_mutex_lock(&lock); p = public_declaration(site,host);
    if (p) out = WS_Copy(ctx->ws,p->wordpress_policy,-1);
    pthread_mutex_unlock(&lock); return out;
}
VCL_STRING vmod_selection_actions(VRT_CTX, VCL_STRING rules, VCL_STRING names) {
    char *canonical = names && *names ? public_names(names) : NULL;
    char *actions;
    const char *out;
    if (names && *names && !canonical) { VRT_fail(ctx,"Invalid public resolver names"); return NULL; }
    actions = public_actions(rules,canonical,NULL); free(canonical);
    if (!actions) { VRT_fail(ctx,"Public selection action projection failed"); return NULL; }
    out = WS_Copy(ctx->ws,actions,-1); free(actions);
    return out;
}
VCL_INT vmod_selection_begin(VRT_CTX, struct vmod_priv *priv,
    VCL_STRING site, VCL_STRING policy, VCL_STRING rules) {
    struct continuation *d;
    struct handoff *entry;
    struct public_declaration *declaration;
    const char *host = NULL, *method = ctx->http_req->hd[HTTP_HDR_METHOD].b;
    char *names = NULL, *wordpress_policy = NULL, *actions;
    int has_variant, found;
    unsigned i;
    if (priv->priv || ctx->req->esi_level || ctx->req->restarts || !method || strcmp(method,"GET") ||
        !site || !*site || !public_policy(policy) ||
        !http_GetHdr(ctx->http_req,H_Host,&host)) return 0;
    pthread_mutex_lock(&lock); declaration = public_declaration(site,host);
    found = declaration != NULL;
    if (found) { names = strdup(declaration->names); wordpress_policy = strdup(declaration->wordpress_policy); }
    pthread_mutex_unlock(&lock);
    if (!found) return 0;
    if (!names || !wordpress_policy) { free(names); free(wordpress_policy); return -1; }
    actions = public_actions(rules,names,&has_variant); free(names);
    if (!actions) { free(wordpress_policy); return -1; }
    if (!has_variant) { free(actions); free(wordpress_policy); return 0; }
    if (ctx->req->restarts+1 > ctx->req->max_restarts) { free(actions); free(wordpress_policy); return -1; }
    d = calloc(1,sizeof(*d));
    if (!d) { free(actions); free(wordpress_policy); return -1; }
    priv->priv = d; priv->methods = &delivery_methods;
    d->phase = D_FAILED; d->selection_entry = 1; d->wordpress_policy = wordpress_policy; d->selection_actions = actions;
    d->selection_policy = strdup(policy); d->selection_rules = strdup(rules ? rules : "");
    d->url = strdup(ctx->http_req->hd[HTTP_HDR_URL].b); d->site = strdup(site);
    if (!d->selection_policy || !d->selection_rules || !d->url || !delivery_relative(d->url) || !d->site ||
        !delivery_copy_header(ctx->http_req,H_Host,&d->host) || !d->host ||
        !delivery_copy_header(ctx->http_req,H_Cookie,&d->cookie) ||
        !delivery_copy_header(ctx->http_req,H_Accept_Encoding,&d->encoding)) return -1;
    for (i = 0; i < 6; ++i)
        if (!delivery_copy_header(ctx->http_req,conditional_headers[i],&d->conditional[i])) return -1;
    entry = calloc(1,sizeof(*entry));
    if (!entry) return -1;
    pthread_mutex_lock(&lock);
    if (serial == UINT64_MAX) { pthread_mutex_unlock(&lock); free(entry); return -1; }
    entry->key = ++serial; entry->delivery = d; entry->next = buckets[entry->key % BUCKETS];
    buckets[entry->key % BUCKETS] = entry; ++live; d->association.key = entry->key; d->association.owner = entry;
    pthread_mutex_unlock(&lock);
    snprintf(d->request_id,sizeof(d->request_id),"%" PRIu64,entry->key);
    d->restart = ctx->req->restarts; d->phase = D_PREPARE;
    http_ForceHeader(ctx->http_req,h_key,d->request_id);
    http_Unset(ctx->http_req,H_Accept_Encoding);
    for (i = 0; i < 6; ++i) http_Unset(ctx->http_req,conditional_headers[i]);
    return WS_Overflowed(ctx->ws) ? -1 : 1;
}
static int public_selection_parse(struct continuation *d) {
    struct delivery_public_selection *s;
    struct delivery_header *header;
    struct fields **tail = &d->public_headers;
    if (d->selection_raw) {
        if (!d->document) return 0;
        d->document->body = (unsigned char *)d->body; d->document->length = d->length;
        d->body = NULL; d->length = d->capacity = 0; return 1;
    }
    if (!delivery_selection_parse(d->body,d->length,d->request_id,d->url,d->selection_policy,d->wordpress_policy,
        &d->selection,&d->document)) return 0;
    if (d->document) return 1;
    s = d->selection;
    if (!delivery_selection_candidate(s,d->cookie,d->selection_rules,&d->candidate)) return 0;
    d->variant = delivery_selection_projection(d->candidate,d->selection_rules);
    d->target = strdup(s->target); d->manifest = strdup(s->manifest);
    if (!d->variant || !d->target || !d->manifest) return 0;
    for (header = s->headers; header; header = header->next) {
        struct fields *field = calloc(1,sizeof(*field));
        if (!field) return 0;
        field->line = strdup(header->line);
        if (!field->line) { free(field); return 0; }
        *tail = field; tail = &field->next;
    }
    d->public_parent = s->parent; s->parent = NULL;
    d->fragments = s->fragments; s->fragments = NULL; d->occurrences = s->occurrences;
    d->public_deadline = d->prepare_response_time+(double)d->public_parent->fresh_remaining;
    d->snapshot_ready = d->recovery_ready = 1;
    return 1;
}
VCL_STRING vmod_selection_manifest(VRT_CTX, struct vmod_priv *priv) {
    struct continuation *d = priv->priv;
    if (ctx->req->esi_level || !d || !d->selection_entry || !d->manifest ||
        (d->phase != D_READY && d->phase != D_RECOVERY && d->phase != D_DELIVERED)) return NULL;
    return WS_Copy(ctx->ws,d->manifest,-1);
}
VCL_STRING vmod_selection_variant(VRT_CTX, struct vmod_priv *priv) {
    struct continuation *d = priv->priv;
    if (ctx->req->esi_level || !d || !d->selection_entry || !d->variant ||
        (d->phase != D_READY && d->phase != D_RECOVERY && d->phase != D_DELIVERED)) return NULL;
    return WS_Copy(ctx->ws,d->variant,-1);
}
VCL_BOOL vmod_selection_local(VRT_CTX, struct vmod_priv *priv) {
    struct task *task = priv->priv;
    struct handoff *entry;
    int selected = 0;
    (void)ctx;
    if (!task || !task->key) return 0;
    pthread_mutex_lock(&lock); entry = delivery_entry(task->key);
    if (entry && entry->delivery) selected = entry->delivery->selection_entry && entry->delivery->snapshot_mode;
    pthread_mutex_unlock(&lock); return selected;
}
