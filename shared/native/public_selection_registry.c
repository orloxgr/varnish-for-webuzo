/* SPDX-License-Identifier: GPL-3.0-or-later
 * Included by delivery_continuation.c. Registry contains declarations only:
 * site/host/application scope, resolver names and WP identity, never values.
 * Optional input recipes belong to their exact complete guest publication.
 */
#include "vrnd.h"

struct guest_input_publication {
    struct guest_input_publication *next;
    char key[65], manifest[65];
    double deadline;
    struct delivery_reuse_recipe *recipe;
    unsigned char *empty_projection;
    size_t empty_length;
};
static size_t guest_input_bucket(const char *key, const char *manifest) {
    size_t i, bucket = 0;
    for (i = 0; i < 64; ++i) bucket = (bucket*33+(unsigned char)key[i]+(unsigned char)manifest[i]) % BUCKETS;
    return bucket;
}
static void guest_input_publication_free(struct guest_input_publication *p) {
    delivery_reuse_recipe_free(p->recipe);
    delivery_reuse_frame_free(p->empty_projection,p->empty_length); free(p);
}
static void guest_input_publications_prune(struct guest_input_publication **head, double now) {
    while (*head) {
        struct guest_input_publication *p = *head;
        if (p->deadline <= now) { *head = p->next; guest_input_publication_free(p); }
        else head = &p->next;
    }
}

struct public_declaration {
    struct public_declaration *next;
    char *site, *host, *scope, *wordpress_policy, *names, *guest_policy;
    unsigned public_source;
    unsigned public_projection;
    struct guest_input_publication *guest_inputs[BUCKETS]; /* publication metadata, no visitor state */
};
static struct public_declaration *public_declarations;
static unsigned public_selection_vcls;
static char public_registry_epoch[65];

static void public_declaration_free(struct public_declaration *p) {
    size_t i;
    for (i = 0; i < BUCKETS; ++i) while (p->guest_inputs[i]) {
        struct guest_input_publication *next = p->guest_inputs[i]->next;
        guest_input_publication_free(p->guest_inputs[i]); p->guest_inputs[i] = next;
    }
    free(p->guest_policy); free(p->site); free(p->host); free(p->scope); free(p->wordpress_policy); free(p->names); free(p);
}
static int public_selection_vcl_event(enum vcl_event_e event) {
    unsigned char identity[sizeof(PACKAGE_VERSION)-1+32];
    pthread_mutex_lock(&lock);
    if (event == VCL_EVENT_LOAD) {
        if (!public_selection_vcls) {
            memcpy(identity,PACKAGE_VERSION,sizeof(PACKAGE_VERSION)-1);
            if (VRND_RandomCrypto(identity+sizeof(PACKAGE_VERSION)-1,32) != 0 ||
                !delivery_selection_digest(identity,sizeof(identity),public_registry_epoch)) {
                pthread_mutex_unlock(&lock); return 0;
            }
        }
        ++public_selection_vcls;
    } else if (event == VCL_EVENT_DISCARD && public_selection_vcls && !--public_selection_vcls) {
        reuse_registry_free(); /* same registry lifetime, lock already held */
        while (public_declarations) {
            struct public_declaration *next = public_declarations->next;
            public_declaration_free(public_declarations); public_declarations = next;
        }
        public_registry_epoch[0] = 0;
    }
    pthread_mutex_unlock(&lock);
    return 1;
}
static struct public_declaration *public_declaration(const char *site, const char *host, const char *scope) {
    struct public_declaration *p;
    for (p = public_declarations; p; p = p->next)
        if (!strcmp(p->site,site) && !strcmp(p->host,host) && !strcmp(p->scope,scope)) return p;
    return NULL;
}
static struct public_declaration *public_declaration_for_url(const char *site, const char *host, const char *url) {
    struct public_declaration *p, *selected = NULL;
    size_t longest = 0;
    for (p = public_declarations; p; p = p->next) {
        size_t length = strlen(p->scope);
        if (length > longest && !strcmp(p->site,site) && !strcmp(p->host,host) &&
            delivery_selection_scope_matches(p->scope,url)) { selected = p; longest = length; }
    }
    return selected;
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
    /* No resolvers is a participating application's metadata-only boundary.
     * It shadows an ancestor, without a provider operation or cookie veto. */
    if (!p || !*p) return strdup("");
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
VCL_STRING vmod_selection_epoch(VRT_CTX) {
    const char *epoch;
    pthread_mutex_lock(&lock);
    epoch = *public_registry_epoch ? WS_Copy(ctx->ws,public_registry_epoch,-1) : NULL;
    pthread_mutex_unlock(&lock);
    return epoch;
}
VCL_BOOL vmod_selection_register(VRT_CTX, VCL_STRING site, VCL_STRING host,
    VCL_STRING scope, VCL_STRING wordpress_policy, VCL_STRING names, VCL_BOOL enabled, VCL_STRING guest_policy) {
    struct public_declaration *next = NULL, **p;
    (void)ctx;
    if (!site || !*site || !host || !*host || !delivery_selection_scope_valid(scope) ||
        (enabled && (!public_policy(wordpress_policy) || (guest_policy && *guest_policy && !public_policy(guest_policy))))) return 0;
    if (enabled) {
        next = calloc(1,sizeof(*next));
        if (!next) return 0;
        next->site = strdup(site); next->host = strdup(host); next->scope = strdup(scope);
        next->wordpress_policy = strdup(wordpress_policy); next->names = public_names(names);
        next->guest_policy = strdup(guest_policy ? guest_policy : "");
        next->public_source = delivery_header_equals(ctx->http_req,
            HDR("X-UltraCache-Public-Selection-Public-Source-Version"),"1");
        next->public_projection = delivery_header_equals(ctx->http_req,
            HDR("X-UltraCache-Public-Selection-Public-Source-Projection-Version"),"1");
        if (!next->site || !next->host || !next->scope || !next->wordpress_policy || !next->names || !next->guest_policy) { public_declaration_free(next); return 0; }
    }
    pthread_mutex_lock(&lock);
    p = &public_declarations;
    while (*p && (strcmp((*p)->site,site) || strcmp((*p)->host,host) || strcmp((*p)->scope,scope))) p = &(*p)->next;
    if (*p) {
        struct public_declaration *old = *p;
        /* Authenticated readvertisement of the same policy is idempotent.
         * An actual policy/owner change drops the associated input evidence. */
        if (next && !strcmp(old->wordpress_policy,next->wordpress_policy) &&
            !strcmp(old->names,next->names) && !strcmp(old->guest_policy,next->guest_policy) &&
            old->public_source == next->public_source && old->public_projection == next->public_projection) {
            memcpy(next->guest_inputs,old->guest_inputs,sizeof(old->guest_inputs));
            memset(old->guest_inputs,0,sizeof(old->guest_inputs));
        }
        *p = old->next; public_declaration_free(old);
    }
    if (next) { next->next = public_declarations; public_declarations = next; }
    pthread_mutex_unlock(&lock); return 1;
}
VCL_STRING vmod_selection_names(VRT_CTX, VCL_STRING site, VCL_STRING host, VCL_STRING scope) {
    struct public_declaration *p;
    const char *out = NULL;
    if (!site || !host || !delivery_selection_scope_valid(scope)) return NULL;
    pthread_mutex_lock(&lock); p = public_declaration(site,host,scope);
    if (p) out = WS_Copy(ctx->ws,p->names,-1);
    pthread_mutex_unlock(&lock); return out;
}
VCL_STRING vmod_selection_wordpress_policy(VRT_CTX, VCL_STRING site, VCL_STRING host, VCL_STRING scope) {
    struct public_declaration *p;
    const char *out = NULL;
    if (!site || !host || !delivery_selection_scope_valid(scope)) return NULL;
    pthread_mutex_lock(&lock); p = public_declaration(site,host,scope);
    if (p) out = WS_Copy(ctx->ws,p->wordpress_policy,-1);
    pthread_mutex_unlock(&lock); return out;
}
VCL_STRING vmod_selection_guest_policy(VRT_CTX, VCL_STRING site, VCL_STRING host, VCL_STRING scope) {
    struct public_declaration *p;
    const char *out = NULL;
    if (!site || !host || !delivery_selection_scope_valid(scope)) return NULL;
    pthread_mutex_lock(&lock); p = public_declaration(site,host,scope);
    if (p && *p->guest_policy) out = WS_Copy(ctx->ws,p->guest_policy,-1);
    pthread_mutex_unlock(&lock); return out;
}
VCL_BOOL vmod_selection_public_source(VRT_CTX, VCL_STRING site, VCL_STRING host, VCL_STRING scope) {
    struct public_declaration *p;
    int available;
    (void)ctx;
    pthread_mutex_lock(&lock); p = public_declaration(site,host,scope);
    available = p && p->public_source;
    pthread_mutex_unlock(&lock); return available;
}
VCL_BOOL vmod_selection_public_projection(VRT_CTX, VCL_STRING site, VCL_STRING host, VCL_STRING scope) {
    struct public_declaration *p;
    int available;
    (void)ctx;
    pthread_mutex_lock(&lock); p = public_declaration(site,host,scope);
    available = p && p->public_projection;
    pthread_mutex_unlock(&lock); return available;
}
/* An existing authenticated refill can prime the ordinary parent as well as
 * the complete guest object. The proof only selects this request's namespace;
 * it grants no route/cookie/privacy bypass and never reaches the application. */
VCL_BOOL vmod_guest_warm_parent(VRT_CTX, VCL_STRING site, VCL_STRING policy, VCL_STRING credential, VCL_STRING rules) {
    struct guest_request *g = guest_context(ctx);
    struct public_declaration *p;
    const char *host = NULL, *accept = "", *scheme = NULL, *message = NULL;
    const char *url = ctx->http_req->hd[HTTP_HDR_URL].b;
    char digest[65];
    unsigned i, difference = 0;
    if (!g || !g->warm_requested || ctx->req->esi_level) return 1;
    if (g->warm_checked) return g->warm_valid;
    g->warm_checked = 1;
    /* The authenticated parent Warm also fills measured public Variant tuples.
     * Original Authorization/duplicate Cookie never create original_cookie;
     * effective Private actions still cannot authorize this projection. */
    if ((!g->eligible && (!g->original_cookie || !delivery_selection_all_public(g->original_cookie,rules))) ||
        !g->warm_single || !g->warm_projection || strcmp(g->warm_projection,"parent-v1") ||
        !g->warm_authorization || strlen(g->warm_authorization) != 67 || strncmp(g->warm_authorization,"v1:",3) ||
        !site || !*site || !public_policy(policy) || !credential || !*credential || ctx->req->restarts ||
        strcmp(ctx->http_req->hd[HTTP_HDR_METHOD].b,"GET") || !delivery_relative(url) ||
        http_CountHdr(ctx->http_req,H_Host) != 1 || !http_GetHdr(ctx->http_req,H_Host,&host) ||
        http_CountHdr(ctx->http_req,HDR("Accept")) > 1 ||
        http_CountHdr(ctx->http_req,HDR("X-Forwarded-Proto")) != 1 ||
        !http_GetHdr(ctx->http_req,HDR("X-Forwarded-Proto"),&scheme) ||
        (strcmp(scheme,"http") && strcmp(scheme,"https"))) return 0;
    http_GetHdr(ctx->http_req,HDR("Accept"),&accept);
    pthread_mutex_lock(&lock);
    p = public_declaration_for_url(site,host,url);
    if (p && *p->guest_policy && public_policy(public_registry_epoch))
        message = WS_Printf(ctx->ws,"ultracache-warm-projection-v1\nparent-v1\nGET\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s",
            host,url,scheme,accept ? accept : "",p->scope,policy,p->wordpress_policy,p->guest_policy,public_registry_epoch);
    pthread_mutex_unlock(&lock);
    if (!message || !delivery_hmac_sha256((const unsigned char *)credential,strlen(credential),
        (const unsigned char *)message,strlen(message),digest)) return 0;
    for (i = 0; i < 64; ++i) difference |= (unsigned char)digest[i] ^ (unsigned char)g->warm_authorization[i+3];
    if (difference) return 0;
    g->warm_valid = 1;
    guest_disable(ctx);
    return 1;
}

VCL_VOID vmod_guest_select(VRT_CTX, VCL_STRING site, VCL_STRING policy, VCL_STRING rules) {
    struct guest_request *g = guest_context(ctx);
    struct public_declaration *p;
    const char *host = NULL, *identity;
    char digest[65];
    int shared = g && !g->eligible && g->original_cookie &&
        delivery_selection_all_shared(g->original_cookie,rules);
    int public = g && !g->eligible && !shared && g->original_cookie &&
        delivery_selection_all_public(g->original_cookie,rules);
    if (!g || (!g->eligible && !shared && !public) || g->disabled || g->key || ctx->req->esi_level ||
        !site || !public_policy(policy) || !http_GetHdr(ctx->http_req,H_Host,&host)) return;
    pthread_mutex_lock(&lock);
    p = public_declaration_for_url(site,host,ctx->http_req->hd[HTTP_HDR_URL].b);
    if (p && *p->guest_policy && (!public || (p->public_source && p->public_projection))) {
        g->policy = strdup(p->guest_policy); g->wordpress_policy = strdup(p->wordpress_policy);
        g->scope = strdup(p->scope); g->epoch = strdup(public_registry_epoch);
        g->projected_fill = !shared && p->public_source && p->public_projection;
    }
    pthread_mutex_unlock(&lock);
    if (!g->policy) return;
    g->site = strdup(site); g->host = strdup(host); g->url = strdup(ctx->http_req->hd[HTTP_HDR_URL].b);
    g->shared_candidate = shared || public;
    if (!g->wordpress_policy || !g->scope || !g->epoch || !g->site || !g->host || !g->url) {
        VRT_fail(ctx,"Guest policy snapshot unavailable"); return;
    }
    identity = WS_Printf(ctx->ws,"guest-v1|%s|%s|%s|%s|%s|%s|%s",site,host,policy,g->wordpress_policy,g->policy,g->epoch,g->scope);
    if (!identity || !delivery_selection_digest((const unsigned char *)identity,strlen(identity),digest) ||
        !(g->key = strdup(digest))) VRT_fail(ctx,"Guest namespace unavailable");
    else {
        /* Shared has an empty public projection. Variant keeps its classified
         * Vary carriers AND explicit hash; original input remains separate. */
        if (!public) {
            http_Unset(ctx->http_req,HDR("X-SCP-Vary-Cookie"));
            http_Unset(ctx->http_req,HDR("X-SCP-Vary-ESI-Cookie"));
        }
        if (shared) VSLb(ctx->vsl,SLT_Debug,"uc-guest-inputs candidate=shared");
    }
}

/* The same declared provider-input equality applies to a newly compiled
 * projected guest as to a cached guest. Cookie actions do not prove identity. */
static int guest_fill_inputs_equal(const struct delivery_reuse_recipe *recipe, const char *cookie) {
    unsigned char *empty = NULL, *actual = NULL;
    size_t empty_length = 0, actual_length = 0;
    int valid = recipe &&
        delivery_reuse_input_projection(recipe->inputs,NULL,0,&empty,&empty_length) == DELIVERY_REUSE_INPUT_OK &&
        delivery_reuse_input_projection(recipe->inputs,(const unsigned char *)cookie,cookie ? strlen(cookie) : 0,
            &actual,&actual_length) == DELIVERY_REUSE_INPUT_OK &&
        actual_length == empty_length && !memcmp(actual,empty,empty_length);
    delivery_reuse_frame_free(empty,empty_length); delivery_reuse_frame_free(actual,actual_length);
    return valid;
}

/* Attach evidence to the authenticated complete publication owner. A cache
 * MISS can never create this from a Shared visitor's request or strip cookies. */
static void guest_inputs_remember(VRT_CTX, struct continuation *d, struct delivery_public_selection *s) {
    struct public_declaration *owner;
    struct guest_input_publication *p, **slot;
    size_t bucket;
    char manifest[65];
    if (!d->guest_complete || !s->guest_inputs || d->public_deadline <= ctx->now ||
        !delivery_selection_digest((const unsigned char *)d->manifest,strlen(d->manifest),manifest)) return;
    p = calloc(1,sizeof(*p));
    if (!p) return; /* Optional evidence failure retains legacy no-Cookie service. */
    if (delivery_reuse_input_projection(s->guest_inputs->inputs,NULL,0,
        &p->empty_projection,&p->empty_length) != DELIVERY_REUSE_INPUT_OK) { free(p); return; }
    memcpy(p->key,d->guest_key,65); memcpy(p->manifest,manifest,65); p->deadline = d->public_deadline;
    bucket = guest_input_bucket(p->key,p->manifest);
    pthread_mutex_lock(&lock);
    owner = public_declaration(d->site,d->host,d->selection_scope);
    if (!owner || strcmp(owner->wordpress_policy,d->wordpress_policy) ||
        strcmp(owner->guest_policy,d->guest_policy) || strcmp(public_registry_epoch,d->guest_epoch)) {
        pthread_mutex_unlock(&lock); guest_input_publication_free(p); return;
    }
    guest_input_publications_prune(&owner->guest_inputs[bucket],ctx->now);
    slot = &owner->guest_inputs[bucket];
    while (*slot && (strcmp((*slot)->key,p->key) || strcmp((*slot)->manifest,p->manifest))) slot = &(*slot)->next;
    if (*slot) { struct guest_input_publication *old = *slot; *slot = old->next; guest_input_publication_free(old); }
    p->recipe = s->guest_inputs; s->guest_inputs = NULL;
    p->next = owner->guest_inputs[bucket]; owner->guest_inputs[bucket] = p;
    pthread_mutex_unlock(&lock);
}
VCL_BOOL vmod_guest_shared_hit(VRT_CTX, VCL_STRING key, VCL_STRING manifest, VCL_BOOL complete) {
    struct guest_request *g = guest_context(ctx);
    struct public_declaration *owner;
    struct guest_input_publication *p;
    unsigned char *actual = NULL;
    size_t actual_length = 0;
    size_t bucket;
    int valid = 0;
    const char *reason = "publication-context";
    if (!vmod_guest_shared_pending(ctx) || !complete || !key || !manifest ||
        !public_policy(manifest) || strcmp(key,g->key)) return 0;
    bucket = guest_input_bucket(key,manifest);
    pthread_mutex_lock(&lock);
    owner = public_declaration(g->site,g->host,g->scope);
    if (!owner || strcmp(owner->wordpress_policy,g->wordpress_policy) ||
        strcmp(owner->guest_policy,g->policy) || strcmp(public_registry_epoch,g->epoch)) goto done;
    guest_input_publications_prune(&owner->guest_inputs[bucket],ctx->now);
    for (p = owner->guest_inputs[bucket]; p; p = p->next)
        if (!strcmp(p->key,key) && !strcmp(p->manifest,manifest)) break;
    if (!p) { reason = "input-evidence-unavailable"; goto done; }
    valid = delivery_reuse_input_projection(p->recipe->inputs,(const unsigned char *)g->original_cookie,
        strlen(g->original_cookie),&actual,&actual_length) == DELIVERY_REUSE_INPUT_OK;
    if (!valid) { reason = "input-projection-unavailable"; goto done; }
    valid = actual_length == p->empty_length && !memcmp(actual,p->empty_projection,actual_length);
    reason = valid ? "empty-provider-inputs" : "provider-inputs-differ";
    if (valid) { g->shared_proved = 1; memcpy(g->shared_manifest,manifest,65); }
done:
    pthread_mutex_unlock(&lock);
    delivery_reuse_frame_free(actual,actual_length);
    VSLb(ctx->vsl,SLT_Debug,"uc-guest-inputs admitted=%u reason=%s",(unsigned)valid,reason);
    return valid;
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
/* Hash the same projection as publication without replacing the working
 * classification/Vary headers on every continuation through finite req WS. */
static int public_projection_lookup_variant(VRT_CTX, const char *rules, struct guest_request *g) {
    const char *current = NULL;
    char *canonical;
    if (!g) return 0;
    if (!http_GetHdr(ctx->http_req,h_lookup_variant,&current)) return 1;
    canonical = delivery_selection_projection(current,rules);
    if (!canonical) return 0;
    free(g->projected_variant); g->projected_variant = canonical;
    g->projected_variant_restart = ctx->req->restarts;
    return 1;
}
VCL_INT vmod_selection_begin(VRT_CTX, struct vmod_priv *priv,
    VCL_STRING site, VCL_STRING policy, VCL_STRING rules, VCL_BOOL cold, VCL_BOOL reselect) {
    struct continuation *d = priv->priv;
    struct handoff *entry;
    struct public_declaration *declaration;
    const char *host = NULL, *method = ctx->http_req->hd[HTTP_HDR_METHOD].b;
    char *names = NULL, *wordpress_policy = NULL, *scope = NULL, *actions;
    int has_variant, found, guest, source_available = 0, projection_available = 0, before_lookup;
    struct guest_request *g = guest_context(ctx);
    unsigned i;
    if ((reselect ? (!d || d->phase != D_RESELECT_READY || !d->reselect_attempted || d->failed ||
            d->selection_entry || ctx->req->restarts != d->restart+2) :
            (d || (ctx->req->restarts && !vmod_guest_fallback_ready(ctx)))) ||
        ctx->req->esi_level || !method || strcmp(method,"GET") ||
        !site || !*site || !public_policy(policy) ||
        !http_GetHdr(ctx->http_req,H_Host,&host)) return 0;
    if (reselect && (!d->site || strcmp(d->site,site) || !d->host || strcmp(d->host,host) ||
        !d->url || strcmp(d->url,ctx->http_req->hd[HTTP_HDR_URL].b))) return -1;
    if (!reselect && g && g->shared_candidate && !g->projected_fill && !g->disabled) return 0;
    pthread_mutex_lock(&lock); declaration = public_declaration_for_url(site,host,ctx->http_req->hd[HTTP_HDR_URL].b);
    found = declaration != NULL;
    if (found) {
        names = strdup(declaration->names); wordpress_policy = strdup(declaration->wordpress_policy); scope = strdup(declaration->scope);
        source_available = declaration->public_source;
        projection_available = declaration->public_projection;
    }
    pthread_mutex_unlock(&lock);
    if (!found) return reselect ? -1 : 0;
    if (!names || !wordpress_policy || !scope) { free(names); free(wordpress_policy); free(scope); return -1; }
    actions = public_actions(rules,names,&has_variant); free(names);
    if (!actions) { free(wordpress_policy); free(scope); return -1; }
    if (!reselect && source_available && projection_available &&
        !public_projection_lookup_variant(ctx,rules,g)) {
        free(actions); free(wordpress_policy); free(scope); return -1;
    }
    guest = !reselect && g && (g->eligible || g->projected_fill) && !g->disabled && g->key &&
        !strcmp(g->wordpress_policy,wordpress_policy) && !strcmp(g->scope,scope);
    /* Dynamic resolvers run before lookup. A registered non-resolver boundary
     * prepares on an actual cold MISS, leaving plain warm HITs alone. */
    before_lookup = has_variant && !projection_available;
    if (!reselect && ((guest && !cold) || (!guest && ((!before_lookup && !cold) || (before_lookup && cold))))) {
        free(actions); free(wordpress_policy); free(scope); return 0;
    }
    if (ctx->req->restarts+1 > ctx->req->max_restarts) { free(actions); free(wordpress_policy); free(scope); return -1; }
    if (!reselect) d = calloc(1,sizeof(*d));
    if (!d) { free(actions); free(wordpress_policy); free(scope); return -1; }
    priv->priv = d; priv->methods = &delivery_methods;
    if (reselect) {
        close_owner(&d->association);
        free(d->target); d->target = NULL;
        free(d->manifest); d->manifest = NULL;
        free(d->lookup_variant); d->lookup_variant = NULL;
        free(d->body); d->body = NULL; d->length = d->capacity = 0;
        clear_fields(d->public_headers); d->public_headers = NULL;
        free(d->retire_expression); d->retire_expression = NULL;
        d->sent = d->complete = d->failed = d->conflict_verified = 0;
        d->recovery_ready = d->recovery_sent = d->recovery_received = d->recovery_restart = 0;
        d->snapshot_ready = d->snapshot_mode = d->cookie_delivery = d->debug_fallback = d->outcome = 0;
        d->public_deadline = d->prepare_response_time = 0;
        d->parent = NULL; d->occurrences = 0;
        d->reuse_publication[0] = d->reuse_representation[0] = d->reuse_recipe[0] = 0;
        d->reuse_origin_request[0] = d->reuse_origin_challenge[0] = 0;
        delivery_reuse_candidate_free(d->reuse_candidate); d->reuse_candidate = NULL;
        free(d->reuse_scope); d->reuse_scope = NULL; d->reuse_negotiated = 0;
        cold = !has_variant;
    }
    d->phase = D_FAILED; d->selection_entry = 1; d->cold_entry = cold;
    /* A projected declaration uses the ordinary public tuple lookup. A
     * verified reselection must return to that same namespace, rather than
     * storing its replacement under a manifest-only key ordinary visits never
     * request. Keep this separate from cold input-invariance validation: an
     * authenticated current selection may legitimately update Vary cookies. */
    d->projected_lookup = projection_available;
    if (guest) {
        g->filling = 1;
        d->guest_requested = 1; d->guest_has_variant = has_variant;
        d->guest_policy = strdup(g->policy); d->guest_epoch = strdup(g->epoch); d->guest_key = strdup(g->key);
        delivery_copy_header(ctx->http_req,HDR("X-SCP-Key-URL"),&d->guest_canonical);
    }
    d->wordpress_policy = wordpress_policy; d->selection_actions = actions;
    d->selection_scope = scope;
    d->selection_policy = strdup(policy); d->selection_rules = strdup(rules ? rules : "");
    if (!reselect) { d->url = strdup(ctx->http_req->hd[HTTP_HDR_URL].b); d->site = strdup(site); }
    if ((guest && (!d->guest_policy || !d->guest_epoch || !d->guest_key || !d->guest_canonical)) ||
        !d->selection_policy || !d->selection_rules || !d->url || !delivery_relative(d->url) || !d->site ||
        (!reselect && (!delivery_copy_header(ctx->http_req,H_Host,&d->host) || !d->host ||
        !delivery_copy_header(ctx->http_req,H_Cookie,&d->cookie) ||
        !delivery_copy_header(ctx->http_req,H_Accept_Encoding,&d->encoding)))) return -1;
    /* The issuer-resolved tuple describes the publication, not the key which
     * this visitor looked up. Preserve that input across selection/reselection
     * so the next identical visitor can find the resulting public object. */
    if (projection_available) {
        d->lookup_variant = delivery_selection_projection(d->cookie,d->selection_rules);
        if (!d->lookup_variant) return -1;
    } else if (cold && !delivery_copy_header(ctx->http_req,h_lookup_variant,&d->lookup_variant)) return -1;
    /* Same existing document eligibility; unresolved public resolvers retain
     * their existing actual route resolution. Generic Variant cookies are
     * projected by policy, never by a provider allowlist. */
    if (!reselect && cold && (!guest || (g && g->projected_fill)) &&
        (!has_variant || projection_available) && source_available &&
        delivery_header_equals(ctx->http_req,HDR("X-SCP-Selection-Eligible"),"1")) {
        if (!delivery_copy_header(ctx->http_req,HDR("X-SCP-Key-URL"),&d->source_url) ||
            !delivery_selection_scope_matches(d->selection_scope,d->source_url) ||
            !(d->source_cookie = delivery_selection_projection(d->cookie,d->selection_rules))) return -1;
        d->source_projected = projection_available;
        d->source_stage = projection_available ? SOURCE_RESOLVER : SOURCE_CAPTURE;
    }
    if (!reselect) for (i = 0; i < 6; ++i)
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
    if (g && g->disabled) g->fallback_restart = 0;
    http_ForceHeader(ctx->http_req,h_key,d->request_id);
    http_Unset(ctx->http_req,H_Accept_Encoding);
    /* This is the actual application route, which may be a ranged download.
     * Preserve Range (0) and its If-Range validator (5) upstream. The complete
     * selection envelope is captured before client range processing; a final
     * selected publication still receives the original range at delivery.
     * Old prepare/recovery stripping lives separately and is unchanged. */
    for (i = 1; i < 5; ++i) http_Unset(ctx->http_req,conditional_headers[i]);
    return WS_Overflowed(ctx->ws) ? -1 : 1;
}
static int guest_resume_personal(VRT_CTX, struct continuation *d) {
    /* Existing original-input continuation, not another owner/renderer. Never
     * publish a projected guest whose private inputs differ from this visitor. */
    delivery_selection_free(d->selection); d->selection = NULL;
    guest_disable(ctx); d->guest_requested = d->guest_reply = 0;
    d->guest_declined = 1; d->source_next = SOURCE_PERSONAL;
    return 1;
}
static int public_selection_parse(VRT_CTX, struct continuation *d) {
    struct delivery_public_selection *s;
    struct delivery_header *header;
    struct fields **tail = &d->public_headers;
    if (d->guest_reply) {
        if (!d->guest_requested) { d->diagnostic_reason = "guest-not-requested"; return 0; }
        if (!delivery_guest_selection_parse_diagnostic(d->body,d->length,d->request_id,d->url,
            d->selection_policy,d->wordpress_policy,d->guest_policy,d->guest_epoch,d->selection_scope,&d->selection,&d->diagnostic_reason)) return 0;
        if (d->source_projected) {
            const struct guest_request *g = guest_context(ctx);
            if (g && g->original_cookie && !guest_fill_inputs_equal(d->selection->guest_inputs,g->original_cookie))
                return guest_resume_personal(ctx,d);
        }
    } else {
        if (d->guest_requested && d->source_projected) return guest_resume_personal(ctx,d);
        if (d->source_projected) {
            struct delivery_public_projection *resolved = NULL;
            if (!delivery_projected_selection_parse_diagnostic(d->body,d->length,d->request_id,d->url,
                d->selection_policy,d->wordpress_policy,DELIVERY_PROJECTED_PERSONAL,&d->selection,&d->document,&resolved,&d->diagnostic_reason)) return 0;
            delivery_public_projection_free(resolved);
        } else if (!delivery_selection_parse_diagnostic(d->body,d->length,d->request_id,d->url,d->selection_policy,d->wordpress_policy,
            &d->selection,&d->document,&d->diagnostic_reason)) return 0;
        if (d->guest_requested) { guest_disable(ctx); d->cold_entry = !d->guest_has_variant; }
    }
    if (d->document) return 1;
    /* An unavailable source supplied no public-parent provenance. Complete the
     * same real visitor privately; never publish its newly rendered page as
     * an inferred replacement for the missing pure public source. */
    if (d->source_declined) { d->diagnostic_reason = "source-declined"; return 0; }
    s = d->selection;
    if (d->source_projected && (d->source_unstable ||
        !delivery_public_projection_equal(s->resolved,d->projection))) { d->diagnostic_reason = "selection-public-projection"; return 0; }
    if (d->source_stage == SOURCE_PERSONAL && !d->source_declined &&
        (!d->source_manifest ||
         strcmp(s->guest ? s->guest_source_manifest : s->manifest,d->source_manifest) ||
         strcmp(s->guest ? s->guest_source_generation : s->parent->generation,d->source_generation))) {
        d->diagnostic_reason = "selection-source-binding"; return 0;
    }
    d->guest_complete = s->guest;
    if (!delivery_selection_candidate(s,d->resolver_cookie ? d->resolver_cookie : d->cookie,d->selection_rules,&d->candidate)) {
        d->diagnostic_reason = "selection-cookie-candidate"; return 0;
    }
    d->variant = delivery_selection_projection(d->candidate,d->selection_rules);
    if (d->cold_entry) {
        char *original = d->source_projected ? delivery_public_projection_cookie(d->projection,d->selection_rules) :
            delivery_selection_projection(d->cookie,d->selection_rules);
        int same = original && d->variant && !strcmp(original,d->variant);
        free(original);
        if (!same) { d->diagnostic_reason = "selection-cold-variant"; return 0; }
    }
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
    if (d->source_stage == SOURCE_PERSONAL) {
        if (!d->source_declined && d->source_deadline < d->public_deadline) d->public_deadline = d->source_deadline;
        d->source_stage = SOURCE_COMPLETE;
    }
    d->cookie_delivery = s->cookie_delivery;
    guest_inputs_remember(ctx,d,s);
    if (d->guest_complete && d->source_projected) {
        struct guest_request *g = guest_context(ctx);
        if (g && g->shared_candidate) {
            if (!delivery_selection_digest((const unsigned char *)d->manifest,strlen(d->manifest),g->shared_manifest)) return 0;
            g->shared_proved = 1; /* same input proof, bound to this fill's manifest */
        }
    }
    d->snapshot_ready = d->recovery_ready = 1;
    return 1;
}
VCL_BOOL vmod_selection_cold(VRT_CTX, struct vmod_priv *priv) {
    const struct continuation *d = priv->priv;
    return ctx->req->esi_level == 0 && d && d->selection_entry && (d->cold_entry || d->projected_lookup) &&
        (d->phase == D_READY || d->phase == D_RECOVERY || d->phase == D_DELIVERED);
}

VCL_STRING vmod_selection_manifest(VRT_CTX, struct vmod_priv *priv) {
    struct continuation *d = priv->priv;
    if (ctx->req->esi_level || !d || !d->selection_entry || d->guest_complete || !d->manifest ||
        (d->phase != D_READY && d->phase != D_RECOVERY && d->phase != D_DELIVERED)) return NULL;
    return WS_Copy(ctx->ws,d->manifest,-1);
}
VCL_STRING vmod_selection_variant(VRT_CTX, struct vmod_priv *priv) {
    struct continuation *d = priv->priv;
    const struct guest_request *g = guest_context(ctx);
    const char *value;
    if (ctx->req->esi_level) return NULL;
    if (!d) {
        value = g && g->projected_variant_restart == ctx->req->restarts ? g->projected_variant : NULL;
    } else if (!d->selection_entry) {
        if (d->phase != D_READY && d->phase != D_RECOVERY && d->phase != D_DELIVERED) return NULL;
        value = d->lookup_variant;
    } else {
        if (!d->selection_entry || !d->variant ||
        (d->phase != D_READY && d->phase != D_RECOVERY && d->phase != D_DELIVERED)) return NULL;
        value = d->projected_lookup || (d->cold_entry && !d->source_projected) ? d->lookup_variant : d->variant;
    }
    if (!value) return NULL;
    /* The owning top-request frame cannot change during vcl_hash. Hash its
     * stable bytes directly; recv callers retain their existing WS lifetime. */
    return ctx->method == VCL_MET_HASH ? value : WS_Copy(ctx->ws,value,-1);
}
VCL_VOID vmod_selection_variant_apply(VRT_CTX, struct vmod_priv *priv) {
    const struct continuation *d = priv->priv;
    const char *value;
    if (ctx->req->esi_level || !d || !d->selection_entry || !d->variant ||
        (d->phase != D_READY && d->phase != D_RECOVERY && d->phase != D_DELIVERED)) {
        VRT_fail(ctx,"Public selection variant unavailable"); return;
    }
    value = d->projected_lookup || (d->cold_entry && !d->source_projected) ? d->lookup_variant : d->variant;
    if (value && !*value) value = NULL;
    if (!delivery_restore_header(ctx,h_lookup_variant,value))
        VRT_fail(ctx,"Public selection variant workspace exhausted");
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
