/* SPDX-License-Identifier: GPL-3.0-or-later
 * Included after public_selection_registry.c. Metadata only: existing native
 * registry lock/lifetime, no private bodies, timer or independent datastore.
 * Root/application owns durable intents and actual persistence/drain proof.
 */
#include "vsb.h"
#include "delivery_mutation_wire.h"
#include "delivery_reuse_inputs.h"

struct reuse_scope;
struct reuse_execution_tag { struct reuse_execution_tag *next; char id[65]; };
struct reuse_identity_schema;
struct reuse_discovery {
    struct reuse_discovery *next;
    char publication[65], representation[65], revision[65];
    double deadline;
    struct delivery_reuse_recipe *recipe;
};
struct mutation_execution {
    struct mutation_execution *next;
    struct reuse_scope *scope;
    char request_id[65], challenge[65], proof[65], epoch[65], incarnation[65];
    char native_policy[65], wordpress_policy[65], reuse_policy[65];
    char recipe[65], coverage_policy[65], scope_revision[65];
    unsigned hold, coverage_qualified;
    uint64_t sequence;
    uint64_t delivery_key;
    unsigned char key[32];
    char *header;
    unsigned live, awaiting_receipt, unknown;
    struct reuse_execution_tag *known_tags; /* revoke-only fences until actual drain */
};
static void mutation_execution_free(struct mutation_execution *);
static void mutation_unknown(struct mutation_execution *);
static int mutation_context_current(const struct mutation_execution *);

struct reuse_transaction {
    struct reuse_transaction *next;
    char id[65], lease[65], completed_revision[65];
    char request_id[65], challenge[65]; /* optional exact V2 receipt owner */
    unsigned active;
};
struct reuse_tag {
    struct reuse_tag *next;
    char id[65], revision[65], generation[65], bound_scope_revision[65];
    unsigned clean;
    struct reuse_transaction *transactions;
};
struct reuse_scope {
    struct reuse_scope *next;
    char *site, *host, *scope;
    char incarnation[65], revision[65];
    char native_policy[65], wordpress_policy[65], policy[65], coverage_policy[65];
    unsigned char reuse_key[32]; /* authenticated purpose-separated key, never raw site credential */
    unsigned enabled, ready, revision_pending, execution_drain;
    unsigned lost_execution_context;
    uint64_t execution_sequence;
    struct reuse_transaction *scope_mutations; /* real unknown-owner writers, never fake tags */
    struct mutation_execution *executions;
    struct reuse_discovery **discoveries; /* declarations only; cached record is authority */
    size_t discovery_capacity, discovery_count;
    struct reuse_identity_schema *identity_schemas;
    struct reuse_tag **tags;
    size_t tag_capacity, tag_count;
};
static struct reuse_scope *reuse_scopes;
static const char *reuse_single(const struct http *, hdr_t);
static void delivery_held_notify(struct reuse_scope *);
static void reuse_identity_free(struct reuse_scope *);
#ifdef UC_NATIVE_PRIVATE_REUSE
static int reuse_identity_install(struct reuse_scope *, const struct delivery_reuse_record *);
#endif
static void reuse_identity_prearm(struct reuse_scope *, struct mutation_execution *, const char *);

static int reuse_random_id(char output[65]) {
    unsigned char bytes[32];
    return VRND_RandomCrypto(bytes,sizeof(bytes)) == 0 &&
        delivery_selection_digest(bytes,sizeof(bytes),output);
}
static void reuse_tag_free(struct reuse_tag *tag) {
    while (tag->transactions) {
        struct reuse_transaction *next = tag->transactions->next;
        free(tag->transactions); tag->transactions = next;
    }
    free(tag);
}
static void reuse_registry_free(void) {
    while (reuse_scopes) {
        struct reuse_scope *scope = reuse_scopes;
        size_t i;
        reuse_scopes = scope->next;
        while (scope->scope_mutations) {
            struct reuse_transaction *next = scope->scope_mutations->next;
            free(scope->scope_mutations); scope->scope_mutations = next;
        }
        while (scope->executions) {
            struct mutation_execution *next = scope->executions->next;
            mutation_execution_free(scope->executions); scope->executions = next;
        }
        for (i = 0; i < scope->discovery_capacity; ++i) while (scope->discoveries[i]) {
            struct reuse_discovery *value = scope->discoveries[i];
            scope->discoveries[i] = value->next; delivery_reuse_recipe_free(value->recipe); free(value);
        }
        free(scope->discoveries);
        reuse_identity_free(scope);
        for (i = 0; i < scope->tag_capacity; ++i) {
            struct reuse_tag *tag = scope->tags[i];
            while (tag) { struct reuse_tag *next = tag->next; reuse_tag_free(tag); tag = next; }
        }
        {
            volatile unsigned char *wipe = scope->reuse_key;
            for (i = 0; i < sizeof(scope->reuse_key); ++i) wipe[i] = 0;
        }
        free(scope->tags); free(scope->site); free(scope->host); free(scope->scope); free(scope);
    }
}
static struct reuse_scope *reuse_scope_find(const char *site, const char *host, const char *scope) {
    struct reuse_scope *value;
    if (!site || !host || !scope) return NULL;
    for (value = reuse_scopes; value; value = value->next)
        if (!strcmp(value->site,site) && !strcmp(value->host,host) && !strcmp(value->scope,scope)) return value;
    return NULL;
}
static unsigned reuse_hash(const char *value) {
    unsigned hash = 2166136261U;
    while (*value) { hash ^= (unsigned char)*value++; hash *= 16777619U; }
    return hash;
}
static int reuse_tag_grow(struct reuse_scope *scope) {
    size_t capacity = scope->tag_capacity ? scope->tag_capacity*2 : 16, i;
    struct reuse_tag **buckets;
    if (capacity < scope->tag_capacity || capacity > SIZE_MAX/sizeof(*buckets)) return 0;
    buckets = calloc(capacity,sizeof(*buckets));
    if (!buckets) return 0;
    for (i = 0; i < scope->tag_capacity; ++i) {
        struct reuse_tag *tag = scope->tags[i];
        while (tag) {
            struct reuse_tag *next = tag->next;
            size_t bucket = reuse_hash(tag->id)%capacity;
            tag->next = buckets[bucket]; buckets[bucket] = tag; tag = next;
        }
    }
    free(scope->tags); scope->tags = buckets; scope->tag_capacity = capacity; return 1;
}
static struct reuse_tag *reuse_tag_find(struct reuse_scope *scope, const char *id, int create) {
    struct reuse_tag *tag;
    size_t bucket;
    if (!scope || !public_policy(id)) return NULL;
    if (scope->tag_capacity) {
        bucket = reuse_hash(id)%scope->tag_capacity;
        for (tag = scope->tags[bucket]; tag; tag = tag->next)
            if (!strcmp(tag->id,id)) return tag;
    }
    if (!create) return NULL;
    if ((!scope->tag_capacity || scope->tag_count >= scope->tag_capacity-scope->tag_capacity/4) && !reuse_tag_grow(scope)) return NULL;
    tag = calloc(1,sizeof(*tag));
    if (!tag || !reuse_random_id(tag->revision)) { free(tag); return NULL; }
    memcpy(tag->id,id,65); /* newly observed authority is UNBOUND, never CLEAN */
    bucket = reuse_hash(id)%scope->tag_capacity;
    tag->next = scope->tags[bucket]; scope->tags[bucket] = tag; ++scope->tag_count;
    return tag;
}
static size_t reuse_active(const struct reuse_tag *tag) {
    const struct reuse_transaction *transaction;
    size_t count = 0;
    for (transaction = tag ? tag->transactions : NULL; transaction; transaction = transaction->next)
        if (transaction->active) ++count;
    return count;
}
static int reuse_tag_execution(const struct reuse_scope *scope, const char *id) {
    const struct mutation_execution *execution;
    for (execution = scope->executions; execution; execution = execution->next) {
        const struct reuse_execution_tag *tag;
        for (tag = execution->known_tags; tag; tag = tag->next) if (!strcmp(tag->id,id)) return 1;
    }
    return 0;
}
static size_t reuse_scope_holds(const struct reuse_scope *scope) {
    const struct mutation_execution *execution;
    size_t count = 0;
    for (execution = scope ? scope->executions : NULL; execution; execution = execution->next)
        if (execution->hold) ++count;
    return count;
}
static int reuse_scope_ready(const struct reuse_scope *scope) {
    return scope && scope->ready && !scope->revision_pending && !reuse_scope_holds(scope);
}
/* The complete pinned plan may linearize before executions that start after
 * its admission cut. Earlier executions must still prove independent drain.
 * Real revisions/dirty tags/unknown state remain separate final barriers. */
#ifdef UC_NATIVE_PRIVATE_REUSE
static int delivery_reuse_scope_ready(const struct continuation *d, const struct reuse_scope *scope) {
    const struct mutation_execution *execution;
    if (!scope || !scope->ready || scope->revision_pending) return 0;
    if (d->reuse_cut_provisional) return 1;
    if (!d->reuse_cut_active) return !reuse_scope_holds(scope);
    for (execution = scope->executions; execution; execution = execution->next)
        if (execution->hold && execution->sequence <= d->reuse_execution_cut) return 0;
    return 1;
}
#endif
static int reuse_tag_clean(const struct reuse_scope *scope, const struct reuse_tag *tag) {
    return reuse_scope_ready(scope) && tag->clean && !strcmp(tag->bound_scope_revision,scope->revision);
}
static size_t reuse_scope_active(const struct reuse_scope *scope) {
    size_t count = 0, i;
    for (i = 0; i < scope->tag_capacity; ++i) {
        const struct reuse_tag *tag;
        for (tag = scope->tags[i]; tag; tag = tag->next) count += reuse_active(tag);
    }
    return count;
}
static struct reuse_transaction *reuse_transaction_lookup(struct reuse_transaction *list, const char *id) {
    struct reuse_transaction *transaction;
    for (transaction = list; transaction; transaction = transaction->next)
        if (!strcmp(transaction->id,id)) return transaction;
    return NULL;
}
static struct reuse_transaction *reuse_transaction_find(struct reuse_tag *tag, const char *id) {
    return reuse_transaction_lookup(tag->transactions,id);
}
static int reuse_transaction_owned_by(const struct reuse_transaction *transaction,
    const struct mutation_execution *execution) {
    return *transaction->request_id && !strcmp(transaction->request_id,execution->request_id) &&
        !strcmp(transaction->challenge,execution->challenge);
}
static int reuse_transaction_receipt_pending(const struct reuse_scope *scope,
    const struct reuse_transaction *transaction) {
    const struct mutation_execution *execution;
    for (execution = scope->executions; execution; execution = execution->next)
        if (execution->live && execution->awaiting_receipt &&
            (!*transaction->request_id || !execution->hold || reuse_transaction_owned_by(transaction,execution))) return 1;
    return 0;
}
static struct reuse_transaction *reuse_transaction_new(const char *id) {
    struct reuse_transaction *transaction = calloc(1,sizeof(*transaction));
    if (!transaction || !reuse_random_id(transaction->lease)) { free(transaction); return NULL; }
    memcpy(transaction->id,id,65); transaction->active = 1;
    return transaction;
}
static struct reuse_transaction *reuse_transaction_begin(struct reuse_tag *tag, const char *id) {
    struct reuse_transaction *transaction = reuse_transaction_find(tag,id);
    char revision[65];
    if (transaction) return transaction; /* active or completed retry: never reopen */
    transaction = reuse_transaction_new(id);
    if (!transaction || !reuse_random_id(revision)) { free(transaction); return NULL; }
    transaction->next = tag->transactions; tag->transactions = transaction;
    memcpy(tag->revision,revision,65); tag->clean = 0; tag->generation[0] = 0;
    return transaction;
}
static int reuse_scope_revision_repair(struct reuse_scope *scope) {
    char revision[65];
    if (!scope->revision_pending) return 1;
    if (!reuse_random_id(revision)) return 0;
    memcpy(scope->revision,revision,65); scope->revision_pending = 0;
    return 1;
}
static void reuse_scope_unbind(struct reuse_scope *scope) {
    scope->ready = 0; scope->revision_pending = 1;
    /* Failure keeps authority suspended and the old namespace unavailable.
     * A later authenticated observation may mint its actual replacement, but
     * neither observation nor recovery may expose the old revision as fresh. */
    (void)reuse_scope_revision_repair(scope);
    delivery_held_notify(scope);
}

VCL_BOOL vmod_reuse_register(VRT_CTX, VCL_STRING site, VCL_STRING host, VCL_STRING scope,
    VCL_STRING native_policy, VCL_STRING wordpress_policy, VCL_STRING policy, VCL_BOOL enabled, VCL_STRING coverage_policy) {
    struct reuse_scope *value;
    struct public_declaration *declaration;
    unsigned char key[32] = {0};
    const char *credential;
    size_t i;
    int valid = 0;
    (void)ctx;
    if (!coverage_policy) coverage_policy = "";
#ifndef UC_NATIVE_PRIVATE_REUSE
    (void)site; (void)host; (void)scope; (void)native_policy; (void)wordpress_policy; (void)policy; (void)enabled;
    return 0;
#endif
    if (!site || !*site || !host || !*host || !delivery_selection_scope_valid(scope) ||
        (*coverage_policy && !public_policy(coverage_policy)) ||
        (enabled && (!public_policy(native_policy) || !public_policy(wordpress_policy) || !public_policy(policy)))) return 0;
    credential = reuse_single(ctx->http_req,HDR("X-UltraCache-Token"));
    if (enabled && (!credential || !delivery_reuse_key_derive((const unsigned char *)credential,strlen(credential),key))) return 0;
    pthread_mutex_lock(&lock);
    value = reuse_scope_find(site,host,scope);
    if (!enabled) {
        if (value) {
            volatile unsigned char *wipe = value->reuse_key;
            value->enabled = 0; value->coverage_policy[0] = 0; value->execution_drain = 0; reuse_scope_unbind(value);
            for (i = 0; i < sizeof(value->reuse_key); ++i) wipe[i] = 0;
        }
        valid = 1; goto done;
    }
    declaration = public_declaration(site,host,scope);
    if (!declaration || strcmp(declaration->wordpress_policy,wordpress_policy)) goto done;
    if (!value) {
        value = calloc(1,sizeof(*value));
        if (!value) goto done;
        value->site = strdup(site); value->host = strdup(host); value->scope = strdup(scope);
        if (!value->site || !value->host || !value->scope ||
            !reuse_random_id(value->incarnation) || !reuse_random_id(value->revision)) {
            free(value->site); free(value->host); free(value->scope); free(value); goto done;
        }
        value->next = reuse_scopes; reuse_scopes = value;
    }
    if (!value->enabled || strcmp(value->native_policy,native_policy) ||
        strcmp(value->wordpress_policy,wordpress_policy) || strcmp(value->policy,policy) ||
        memcmp(value->reuse_key,key,sizeof(key)) || strcmp(value->coverage_policy,coverage_policy)) reuse_scope_unbind(value);
    memcpy(value->native_policy,native_policy,65); memcpy(value->wordpress_policy,wordpress_policy,65);
    memcpy(value->policy,policy,65);
    snprintf(value->coverage_policy,sizeof(value->coverage_policy),"%s",coverage_policy); value->enabled = 1; valid = 1;
    memcpy(value->reuse_key,key,sizeof(key));
    value->execution_drain = *coverage_policy && delivery_header_equals(ctx->http_req,
        HDR("X-UltraCache-Public-Selection-Execution-Drain-Version"),"1");
done:
    pthread_mutex_unlock(&lock);
    {
        volatile unsigned char *wipe = key;
        for (i = 0; i < sizeof(key); ++i) wipe[i] = 0;
    }
    return valid;
}

VCL_STRING vmod_reuse_coverage_policy(VRT_CTX, VCL_STRING site, VCL_STRING host, VCL_STRING application_scope) {
    struct reuse_scope *scope;
    const char *out = NULL;
    pthread_mutex_lock(&lock);
    scope = reuse_scope_find(site,host,application_scope);
    if (scope && scope->enabled && *scope->coverage_policy) out = WS_Copy(ctx->ws,scope->coverage_policy,-1);
    pthread_mutex_unlock(&lock); return out;
}
VCL_BOOL vmod_execution_drain_available(VRT_CTX, VCL_STRING site, VCL_STRING host, VCL_STRING application_scope) {
    struct reuse_scope *scope;
    int available;
    (void)ctx;
    pthread_mutex_lock(&lock);
    scope = reuse_scope_find(site,host,application_scope);
    available = scope && scope->enabled && *scope->coverage_policy && scope->execution_drain;
    pthread_mutex_unlock(&lock); return available;
}
static const char *reuse_single(const struct http *http, hdr_t header) {
    const char *value;
    return http_CountHdr(http,header) == 1 && http_GetHdr(http,header,&value) ? value : NULL;
}
#ifdef UC_NATIVE_PRIVATE_REUSE
static struct reuse_scope *delivery_reuse_current_scope(const struct continuation *d) {
    struct reuse_scope *scope;
    const struct public_declaration *declaration;
    if (!d || !d->reuse_negotiated || !d->reuse_scope) return NULL;
    scope = reuse_scope_find(d->site,d->host,d->reuse_scope);
    declaration = public_declaration_for_url(d->site,d->host,d->url);
    if (!scope || !scope->enabled || !declaration || strcmp(declaration->scope,scope->scope) ||
        strcmp(declaration->wordpress_policy,scope->wordpress_policy) ||
        strcmp(public_registry_epoch,d->reuse_epoch) || strcmp(scope->incarnation,d->reuse_incarnation) ||
        strcmp(scope->native_policy,d->reuse_native_policy) || strcmp(scope->wordpress_policy,d->reuse_wp_policy) ||
        strcmp(scope->policy,d->reuse_policy)) return NULL;
    return scope;
}
#endif
static void delivery_reuse_candidate_capture(VRT_CTX, struct continuation *d, const char *wire, size_t length) {
#ifdef UC_NATIVE_PRIVATE_REUSE
    struct delivery_reuse_candidate *candidate = NULL;
    const struct delivery_reuse_descriptor *descriptor;
    const struct delivery_fragment *fragment;
    struct delivery_reuse_context context;
    struct reuse_scope *scope;
    unsigned char *frame = NULL;
    size_t frame_length = 0, expected = 0, actual = 0;
    char evidence[65];
    int valid = 0;
    (void)ctx;
    if (!delivery_reuse_candidate_parse(wire,length,d->occurrences,&candidate) ||
        strcmp(candidate->request_id,d->reuse_origin_request) || strcmp(candidate->challenge,d->reuse_origin_challenge) ||
        (*d->reuse_recipe && strcmp(candidate->recipe->digest,d->reuse_recipe))) goto done;
    for (descriptor = candidate->recipe->fragments; descriptor; descriptor = descriptor->next) {
        fragment = delivery_fragment_named(d,descriptor->url);
        if (!fragment || fragment->occurrences != descriptor->occurrences || !fragment->cache_key ||
            !fragment->cache_ttl || !fragment->cache_tags) goto done;
        ++expected;
    }
    for (fragment = d->fragments; fragment; fragment = fragment->next) ++actual;
    if (expected != actual || delivery_reuse_input_projection(candidate->recipe->inputs,
        (const unsigned char *)delivery_personal_cookie(d),strlen(delivery_personal_cookie(d)),
        &frame,&frame_length) != DELIVERY_REUSE_INPUT_OK) goto done;
    pthread_mutex_lock(&lock);
    scope = delivery_reuse_current_scope(d);
    if (scope) {
        context = (struct delivery_reuse_context){d->site,d->host,scope->scope,public_registry_epoch,
            scope->native_policy,scope->wordpress_policy,scope->policy,NULL,NULL,NULL};
        valid = delivery_reuse_identity_mac(scope->reuse_key,&context,frame,frame_length,evidence) &&
            !strcmp(evidence,candidate->input_evidence);
        if (valid) {
            delivery_reuse_candidate_free(d->reuse_candidate); d->reuse_candidate = candidate; candidate = NULL;
            memcpy(d->reuse_recipe,d->reuse_candidate->recipe->digest,65);
        }
    }
    pthread_mutex_unlock(&lock);
done:
    delivery_reuse_frame_free(frame,frame_length); delivery_reuse_candidate_free(candidate);
#else
    (void)ctx; (void)d; (void)wire; (void)length;
#endif
}
#ifdef UC_NATIVE_PRIVATE_REUSE
static char *delivery_reuse_make_finalize(VRT_CTX, struct continuation *d) {
    struct delivery_reuse_finalize_context context;
    struct reuse_scope *scope;
    unsigned char *frame = NULL, *effective = NULL;
    size_t length = 0, effective_length = 0;
    char binding[65], evidence[65], *header = NULL;
    char *out = NULL;
    if (ctx->req->esi_level || !d || d->phase != D_READY || d->failed || !d->reuse_candidate ||
        !delivery_reuse_capture_parent(ctx,d) ||
        delivery_reuse_input_projection(d->reuse_candidate->recipe->inputs,
            (const unsigned char *)delivery_personal_cookie(d),strlen(delivery_personal_cookie(d)),
            &frame,&length) != DELIVERY_REUSE_INPUT_OK) goto done;
    /* Original evidence does not authorize another projection after issuance.
     * Unrelated Shared updates can differ while consumed inputs stay identical. */
    if (d->selection_entry && (delivery_reuse_input_projection(d->reuse_candidate->recipe->inputs,
        (const unsigned char *)(d->candidate ? d->candidate : ""),d->candidate ? strlen(d->candidate) : 0,
        &effective,&effective_length) != DELIVERY_REUSE_INPUT_OK || effective_length != length ||
        memcmp(effective,frame,length))) goto done;
    pthread_mutex_lock(&lock);
    scope = delivery_reuse_current_scope(d);
    if (scope) {
        context.page = (struct delivery_reuse_context){d->site,d->host,scope->scope,public_registry_epoch,
            scope->native_policy,scope->wordpress_policy,scope->policy,d->reuse_publication,d->reuse_representation,d->reuse_recipe};
        context.incarnation = scope->incarnation; context.scope_revision = scope->revision;
        context.request_id = d->reuse_origin_request; context.challenge = d->reuse_origin_challenge;
        context.delivery_request_id = d->request_id; context.binding = binding;
        context.input_evidence = d->reuse_candidate->input_evidence;
        if (delivery_reuse_identity_mac(scope->reuse_key,&context.page,frame,length,evidence) &&
            !strcmp(evidence,context.input_evidence) &&
            delivery_reuse_input_mac(scope->reuse_key,&context.page,frame,length,binding) &&
            delivery_reuse_finalize_header(scope->reuse_key,"GET",d->url,&context,&header) &&
            delivery_reuse_metadata_key(&context.page,binding,d->reuse_metadata_key)) {
            memcpy(d->reuse_binding,binding,65);
            out = header; header = NULL;
        }
    }
    pthread_mutex_unlock(&lock);
done:
    delivery_mutation_header_free(header); delivery_reuse_frame_free(frame,length);
    delivery_reuse_frame_free(effective,effective_length); return out;
 }
#endif
VCL_STRING vmod_delivery_reuse_finalize_context(VRT_CTX, struct vmod_priv *priv) {
#ifdef UC_NATIVE_PRIVATE_REUSE
    char *header = delivery_reuse_make_finalize(ctx,priv->priv);
    const char *out = header ? WS_Copy(ctx->ws,header,-1) : NULL;
    delivery_mutation_header_free(header); return out;
#else
    (void)ctx; (void)priv; return NULL;
#endif
}
static void reuse_json(struct vsb *json, const char *value) {
    const unsigned char *p = (const unsigned char *)value;
    VSB_putc(json,'"');
    for (; p && *p; ++p) {
        if (*p == '"' || *p == '\\') { VSB_putc(json,'\\'); VSB_putc(json,*p); }
        else if (*p < 32 || *p == 127) VSB_printf(json,"\\u%04x",*p);
        else VSB_putc(json,*p);
    }
    VSB_putc(json,'"');
}
static void reuse_json_field(struct vsb *json, const char *name, const char *value) {
    VSB_putc(json,','); reuse_json(json,name); VSB_putc(json,':'); reuse_json(json,value);
}
static int reuse_control_reply(struct task *task, int status, const char *reason,
    const struct reuse_scope *scope, const struct reuse_tag *tag, const struct reuse_transaction *transaction,
    const struct mutation_execution *drained, const struct mutation_execution *context_owner,
    const struct continuation *delivery, const char *observation, const char *observation_target) {
    struct vsb *json = VSB_new_auto();
    char *body = NULL;
    if (!json) return 503;
    VSB_printf(json,"{\"schemaVersion\":1,\"accepted\":%s",status == 200 ? "true" : "false");
    reuse_json_field(json,"reason",reason);
    reuse_json_field(json,"epoch",public_registry_epoch);
    if (observation) reuse_json_field(json,"observation",observation);
    if (observation_target) reuse_json_field(json,"observationTarget",observation_target);
    if (drained) {
        reuse_json_field(json,"requestId",drained->request_id);
        reuse_json_field(json,"challenge",drained->challenge);
    }
    if (context_owner) {
        int parent_bound = delivery && *delivery->reuse_publication && *delivery->reuse_representation;
        reuse_json_field(json,"requestId",context_owner->request_id);
        reuse_json_field(json,"challenge",context_owner->challenge);
        reuse_json_field(json,"recipeDigest",context_owner->recipe);
        if (delivery) reuse_json_field(json,"deliveryRequestId",delivery->request_id);
        reuse_json_field(json,"contextState",parent_bound ? "parent-bound" : "unqualified");
        reuse_json_field(json,"parentIdentitySource",parent_bound ? "native-selected-parent" : "none");
        if (parent_bound) {
            reuse_json_field(json,"publicationDigest",delivery->reuse_publication);
            reuse_json_field(json,"representation",delivery->reuse_representation);
        }
        VSB_cat(json,",\"provisional\":true,\"cachedFragments\":[]");
    }
    if (scope) {
        reuse_json_field(json,"siteId",scope->site); reuse_json_field(json,"canonicalHost",scope->host);
        reuse_json_field(json,"scope",scope->scope); reuse_json_field(json,"incarnation",scope->incarnation);
        reuse_json_field(json,"scopeRevision",scope->revision_pending ? "" : scope->revision);
        reuse_json_field(json,"scopeState",reuse_scope_ready(scope) ? "ready" : "unbound");
        if (reuse_scope_holds(scope)) VSB_printf(json,",\"temporaryHolds\":%ju",(uintmax_t)reuse_scope_holds(scope));
        reuse_json_field(json,"nativePolicy",scope->native_policy);
        reuse_json_field(json,"wordpressPolicy",scope->wordpress_policy);
        reuse_json_field(json,"reusePolicy",scope->policy);
        if (*scope->coverage_policy) {
            VSB_cat(json,",\"coverageVersion\":1"); reuse_json_field(json,"coveragePolicy",scope->coverage_policy);
        }
        /* Projections describe their exact observed set. Omission is never an
         * empty census; old callers retain the complete original response. */
        if (observation && !strcmp(observation,"quiescence")) {
            const struct mutation_execution *execution;
            const struct reuse_transaction *writer;
            size_t executions = 0, writers = 0, active = 0;
            for (execution = scope->executions; execution; execution = execution->next) ++executions;
            for (writer = scope->scope_mutations; writer; writer = writer->next) {
                ++writers; if (writer->active) ++active;
            }
            VSB_printf(json,",\"unsettledExecutionCount\":%ju,\"scopeMutationCount\":%ju,\"activeScopeMutationCount\":%ju",
                (uintmax_t)executions,(uintmax_t)writers,(uintmax_t)active);
        }
        if (!observation || !strcmp(observation,"all") || !strcmp(observation,"execution")) {
            const struct mutation_execution *execution;
            size_t emitted = 0;
            VSB_cat(json,",\"unsettledExecutions\":[");
            for (execution = scope->executions; execution; execution = execution->next) {
                if (observation && !strcmp(observation,"execution") &&
                    (!observation_target || strcmp(execution->request_id,observation_target))) continue;
                if (emitted++) VSB_putc(json,',');
                VSB_cat(json,"{\"requestId\":"); reuse_json(json,execution->request_id);
                reuse_json_field(json,"challenge",execution->challenge);
                VSB_printf(json,",\"live\":%s,\"awaitingReceipt\":%s,\"unknown\":%s",
                    execution->live ? "true" : "false",execution->awaiting_receipt ? "true" : "false",
                    execution->unknown ? "true" : "false");
                if (execution->hold) {
                    VSB_printf(json,",\"coverageVersion\":1,\"receiptQualified\":%s",execution->coverage_qualified ? "true" : "false");
                    reuse_json_field(json,"coveragePolicy",execution->coverage_policy);
                }
                VSB_putc(json,'}');
            }
            VSB_putc(json,']');
        }
        if (!observation || !strcmp(observation,"all") || !strcmp(observation,"scope-transaction")) {
            const struct reuse_transaction *writer;
            size_t emitted = 0;
            VSB_cat(json,",\"scopeMutations\":[");
            for (writer = scope->scope_mutations; writer; writer = writer->next) {
                if (observation && !strcmp(observation,"scope-transaction") &&
                    (!observation_target || strcmp(writer->id,observation_target))) continue;
                if (emitted++) VSB_putc(json,',');
                VSB_cat(json,"{\"transaction\":"); reuse_json(json,writer->id);
                reuse_json_field(json,"lease",writer->lease);
                VSB_printf(json,",\"active\":%s",writer->active ? "true" : "false");
                if (!writer->active) reuse_json_field(json,"committedRevision",writer->completed_revision);
                VSB_putc(json,'}');
            }
            VSB_putc(json,']');
        }
        if (scope->lost_execution_context) VSB_cat(json,",\"lostExecutionContext\":true");
    }
    if (tag) {
        size_t active = reuse_active(tag);
        reuse_json_field(json,"tag",tag->id); reuse_json_field(json,"revision",tag->revision);
        reuse_json_field(json,"state",active ? "dirty" : reuse_tag_clean(scope,tag) ? "clean" : "unbound");
        VSB_printf(json,",\"remainingMutations\":%ju",(uintmax_t)active);
        if (reuse_tag_clean(scope,tag)) reuse_json_field(json,"generation",tag->generation);
    }
    if (transaction) {
        if (!tag) reuse_json_field(json,"transactionKind","scope");
        reuse_json_field(json,"transaction",transaction->id); reuse_json_field(json,"lease",transaction->lease);
        if (*transaction->request_id) {
            reuse_json_field(json,"requestId",transaction->request_id);
            reuse_json_field(json,"challenge",transaction->challenge);
        }
        VSB_printf(json,",\"active\":%s",transaction->active ? "true" : "false");
        if (!transaction->active) reuse_json_field(json,"committedRevision",transaction->completed_revision);
    }
    VSB_putc(json,'}');
    if (!VSB_finish(json)) {
        body = malloc((size_t)VSB_len(json)+1);
        if (body) {
            memcpy(body,VSB_data(json),(size_t)VSB_len(json)+1);
            free(task->control_body); task->control_body = body; task->control_length = (size_t)VSB_len(json);
        }
    }
    VSB_destroy(&json); return body ? status : 503;
}

/* Only the adapters' existing authenticated per-site control branch calls this.
 * Method/path/profile/site/scope are checked again; ordinary headers grant no
 * admission and context creation only creates UNBOUND metadata.
 */
VCL_INT vmod_reuse_control(VRT_CTX, struct vmod_priv *priv, VCL_STRING site, VCL_STRING native_policy) {
    struct task *task = get_task(priv);
    struct reuse_scope *scope = NULL;
    struct reuse_tag *tag = NULL;
    struct reuse_transaction *transaction = NULL;
    struct mutation_execution *drained = NULL;
    struct mutation_execution *context_owner = NULL;
    struct continuation *delivery = NULL;
    const char *operation, *application_scope, *id, *epoch, *incarnation, *expected_scope, *expected;
    const char *observation, *observation_target = NULL;
    const char *reason = "invalid-control";
    int status = 400;
    if (!task) return 503;
    free(task->control_body); task->control_body = NULL; task->control_length = 0;
    operation = reuse_single(ctx->http_req,HDR("X-UltraCache-Operation"));
    application_scope = reuse_single(ctx->http_req,HDR("X-UltraCache-Public-Selection-Scope"));
    id = reuse_single(ctx->http_req,HDR("X-UltraCache-Private-Tag"));
    epoch = reuse_single(ctx->http_req,HDR("X-UltraCache-Private-Epoch"));
    incarnation = reuse_single(ctx->http_req,HDR("X-UltraCache-Private-Incarnation"));
    expected_scope = reuse_single(ctx->http_req,HDR("X-UltraCache-Private-Scope-Revision"));
    expected = reuse_single(ctx->http_req,HDR("X-UltraCache-Private-Expected-Revision"));
    observation = reuse_single(ctx->http_req,HDR("X-UltraCache-Private-Observation"));
    pthread_mutex_lock(&lock);
#ifndef UC_NATIVE_PRIVATE_REUSE
    status = 501; reason = "reuse-not-enabled"; goto reply;
#endif
    if (!operation || !site || !*site || ctx->req->esi_level ||
        strcmp(ctx->http_req->hd[HTTP_HDR_METHOD].b,"PURGE") ||
        strcmp(ctx->http_req->hd[HTTP_HDR_URL].b,"/__ultracache-vcl-contract-v2") ||
        !delivery_header_equals(ctx->http_req,HDR("X-UltraCache-Contract"),"2") ||
        !delivery_header_equals(ctx->http_req,HDR("X-SCP-Profile"),"ultracache") ||
        !delivery_header_equals(ctx->http_req,h_adapter_site,site) ||
        !delivery_selection_scope_valid(application_scope)) goto reply;
    scope = reuse_scope_find(site,reuse_single(ctx->http_req,H_Host),application_scope);
    if (!scope || !scope->enabled || !native_policy || strcmp(native_policy,scope->native_policy)) {
        status = 409; reason = "authority-unavailable"; goto reply;
    }
    {
        const struct public_declaration *current = public_declaration(site,scope->host,scope->scope);
        if (!current || strcmp(current->wordpress_policy,scope->wordpress_policy)) {
            reuse_scope_unbind(scope); status = 409; reason = "wordpress-policy-changed"; goto reply;
        }
    }
    if (!reuse_scope_revision_repair(scope)) {
        status = 503; reason = "scope-revision-unavailable"; goto reply;
    }
    if (observation) {
        int context = !strcmp(operation,"private-authority-context");
        int scope_operation = !strcmp(operation,"private-scope-mutation-begin") ||
            !strcmp(operation,"private-scope-mutation-commit") || !strcmp(operation,"private-scope-mutation-ack");
        if (!strcmp(observation,"execution")) {
            observation_target = reuse_single(ctx->http_req,HDR("X-UltraCache-Private-Request-Id"));
            if (!context || !public_policy(observation_target)) {
                status = 400; reason = "invalid-observation-target"; goto reply;
            }
        } else if (!strcmp(observation,"scope-transaction")) {
            observation_target = reuse_single(ctx->http_req,HDR("X-UltraCache-Private-Transaction"));
            if ((!context && !scope_operation) || !public_policy(observation_target)) {
                status = 400; reason = "invalid-observation-target"; goto reply;
            }
        } else if (!strcmp(observation,"quiescence")) {
            if (!context) { status = 400; reason = "invalid-observation-operation"; goto reply; }
        } else if (strcmp(observation,"all") && strcmp(observation,"identity")) {
            status = 400; reason = "invalid-observation"; goto reply;
        }
    }
    if (!strcmp(operation,"delivery-reuse-context")) {
        const char *request_id = reuse_single(ctx->http_req,HDR("X-UltraCache-Private-Request-Id"));
        const char *challenge = reuse_single(ctx->http_req,HDR("X-UltraCache-Private-Challenge"));
        const char *recipe = reuse_single(ctx->http_req,HDR("X-UltraCache-Delivery-Reuse-Recipe"));
        const char *delivery_id = reuse_single(ctx->http_req,h_request);
        const char *original_url = reuse_single(ctx->http_req,h_original);
        const struct public_declaration *boundary;
        struct handoff *entry;
        if (!public_policy(request_id) || !public_policy(challenge) || !public_policy(recipe)) goto reply;
        for (context_owner = scope->executions; context_owner; context_owner = context_owner->next)
            if (!strcmp(context_owner->request_id,request_id)) break;
        if (!context_owner || strcmp(context_owner->challenge,challenge) || !context_owner->live ||
            !epoch || strcmp(epoch,context_owner->epoch) || !incarnation || strcmp(incarnation,context_owner->incarnation) ||
            !mutation_context_current(context_owner)) {
            context_owner = NULL; status = 409; reason = "execution-context-unavailable"; goto reply;
        }
        if (*context_owner->recipe && strcmp(context_owner->recipe,recipe)) {
            context_owner = NULL; status = 409; reason = "delivery-recipe-changed"; goto reply;
        }
        entry = context_owner->delivery_key ? delivery_entry(context_owner->delivery_key) : NULL;
        delivery = entry ? entry->delivery : NULL;
        boundary = delivery ? public_declaration_for_url(site,scope->host,delivery->url) : NULL;
        if (delivery && (!boundary || strcmp(boundary->scope,scope->scope) ||
            delivery->failed || delivery->phase != D_PREPARE || delivery->sent != 1 || delivery->complete ||
            (delivery_id && strcmp(delivery->request_id,delivery_id)) || strcmp(delivery->site,site) ||
            strcmp(delivery->host,scope->host) || (original_url && strcmp(delivery->url,original_url)) ||
            strcmp(delivery->reuse_origin_request,request_id) || strcmp(delivery->reuse_origin_challenge,challenge) ||
            (*delivery->reuse_recipe && strcmp(delivery->reuse_recipe,recipe)) ||
            (delivery->selection_scope && strcmp(delivery->selection_scope,scope->scope)) ||
            (delivery->selection_policy && strcmp(delivery->selection_policy,scope->native_policy)) ||
            (delivery->wordpress_policy && strcmp(delivery->wordpress_policy,scope->wordpress_policy)))) {
            delivery = NULL; context_owner = NULL; status = 409; reason = "delivery-owner-unavailable"; goto reply;
        }
        if (!delivery && (delivery_id || original_url)) {
            context_owner = NULL; status = 409; reason = "delivery-owner-unavailable"; goto reply;
        }
        memcpy(context_owner->recipe,recipe,65);
        if (delivery) memcpy(delivery->reuse_recipe,recipe,65);
        status = 200; reason = "delivery-context-provisional"; goto reply;
    }
    if (!strcmp(operation,"private-authority-context")) {
        if (id) {
            if (!public_policy(id)) goto reply;
            tag = reuse_tag_find(scope,id,1);
            if (!tag) { reuse_scope_unbind(scope); status = 503; reason = "authority-memory"; goto reply; }
        }
        status = 200; reason = "observed"; goto reply;
    }
    if (!epoch || strcmp(epoch,public_registry_epoch)) { status = 409; reason = "epoch-changed"; goto reply; }
    if (!incarnation || strcmp(incarnation,scope->incarnation)) { status = 409; reason = "incarnation-changed"; goto reply; }
    if (!strcmp(operation,"private-execution-drained")) {
        const char *request_id = reuse_single(ctx->http_req,HDR("X-UltraCache-Private-Request-Id"));
        const char *challenge = reuse_single(ctx->http_req,HDR("X-UltraCache-Private-Challenge"));
        struct mutation_execution **position = &scope->executions;
        struct mutation_execution *execution;
        if (!public_policy(request_id) || !public_policy(challenge) ||
            !delivery_header_equals(ctx->http_req,HDR("X-UltraCache-Private-Drained"),"1")) goto reply;
        if (!expected_scope || strcmp(expected_scope,scope->revision)) { status = 409; reason = "scope-revision-changed"; goto reply; }
        while (*position && strcmp((*position)->request_id,request_id)) position = &(*position)->next;
        execution = *position;
        if (!execution) { status = 409; reason = "execution-unavailable"; goto reply; }
        if (strcmp(execution->challenge,challenge)) { status = 409; reason = "execution-challenge-changed"; goto reply; }
        if (execution->live || execution->awaiting_receipt) { status = 409; reason = "execution-active"; goto reply; }
        if (execution->hold) {
            const char *version = reuse_single(ctx->http_req,HDR("X-UltraCache-Private-Coverage-Version"));
            const char *policy = reuse_single(ctx->http_req,HDR("X-UltraCache-Private-Coverage-Policy"));
            const char *result = reuse_single(ctx->http_req,HDR("X-UltraCache-Private-Coverage-Result"));
            const char *proof = reuse_single(ctx->http_req,HDR("X-UltraCache-Private-Coverage-Proof"));
            char expected_proof[65];
            unsigned qualified, difference = 0;
            size_t i;
            if (!version || strcmp(version,"1") || !policy || strcmp(policy,execution->coverage_policy) ||
                !result || (strcmp(result,"qualified") && strcmp(result,"unknown")) || !public_policy(proof)) {
                mutation_unknown(execution); status = 400; reason = "coverage-completion-invalid"; goto reply;
            }
            qualified = !strcmp(result,"qualified");
            if (!delivery_mutation_completion_proof(execution->key,execution->proof,execution->request_id,
                execution->challenge,execution->coverage_policy,qualified,expected_proof)) {
                mutation_unknown(execution); status = 503; reason = "coverage-proof-unavailable"; goto reply;
            }
            for (i = 0; i < 64; ++i) difference |= (unsigned char)proof[i] ^ (unsigned char)expected_proof[i];
            if (difference) { mutation_unknown(execution); status = 409; reason = "coverage-proof-mismatch"; goto reply; }
            if (qualified && (execution->unknown || !execution->coverage_qualified || !mutation_context_current(execution))) {
                mutation_unknown(execution); status = 409; reason = "coverage-unqualified"; goto reply;
            }
            if (qualified && strcmp(execution->scope_revision,scope->revision)) {
                mutation_unknown(execution); status = 409; reason = "coverage-scope-changed"; goto reply;
            }
            if (!qualified) mutation_unknown(execution);
        }
        /* Authenticated producer attests actual independent runtime/provider
         * drain for precisely this execution. Native does not infer that from
         * headers, socket/task end, timeout or the absence of a DIRTY receipt. */
        *position = execution->next; drained = execution;
        status = 200; reason = "execution-drained"; goto reply;
    }
    if (!strcmp(operation,"private-scope-mutation-begin") ||
        !strcmp(operation,"private-scope-mutation-commit") ||
        !strcmp(operation,"private-scope-mutation-ack")) {
        const char *transaction_id = reuse_single(ctx->http_req,HDR("X-UltraCache-Private-Transaction"));
        const char *lease = reuse_single(ctx->http_req,HDR("X-UltraCache-Private-Lease"));
        char revision[65];
        /* A real scope writer has no inferred cookie identity or placeholder
         * tag. Count, not reuse_single, also rejects empty/duplicate tags. */
        if (http_CountHdr(ctx->http_req,HDR("X-UltraCache-Private-Tag")) || !public_policy(transaction_id)) goto reply;
        transaction = reuse_transaction_lookup(scope->scope_mutations,transaction_id);
        if (!strcmp(operation,"private-scope-mutation-begin")) {
            if (!public_policy(expected_scope)) goto reply;
            if (transaction) { status = 200; reason = "scope-mutation-recorded"; goto reply; }
            if (!expected_scope || strcmp(expected_scope,scope->revision)) {
                status = 409; reason = "scope-revision-changed"; goto reply;
            }
            transaction = reuse_transaction_new(transaction_id);
            if (!transaction || !reuse_random_id(revision)) {
                free(transaction); transaction = NULL; reuse_scope_unbind(scope);
                status = 503; reason = "authority-memory-or-identity"; goto reply;
            }
            transaction->next = scope->scope_mutations; scope->scope_mutations = transaction;
            scope->ready = 0; scope->revision_pending = 0; memcpy(scope->revision,revision,65);
            status = 200; reason = "scope-mutation-recorded"; goto reply;
        }
        if (!transaction || !lease || strcmp(lease,transaction->lease)) {
            transaction = NULL; status = 409; reason = "unknown-lease"; goto reply;
        }
        if (!strcmp(operation,"private-scope-mutation-commit")) {
            if (!delivery_header_equals(ctx->http_req,HDR("X-UltraCache-Private-Drained"),"1")) goto reply;
            if (transaction->active) {
                if (!reuse_random_id(revision)) { status = 503; reason = "identity-unavailable"; goto reply; }
                transaction->active = 0; scope->ready = 0; scope->revision_pending = 0; memcpy(scope->revision,revision,65);
                memcpy(transaction->completed_revision,revision,65);
            }
            status = 200; reason = "scope-mutation-committed"; goto reply;
        }
        if (transaction->active) { status = 409; reason = "mutation-active"; goto reply; }
        {
            struct reuse_transaction **position = &scope->scope_mutations;
            /* The producer durably records the actual native commit ACK before
             * this request. Fence delayed begin frames before forgetting ID. */
            if (!reuse_random_id(revision)) { status = 503; reason = "identity-unavailable"; goto reply; }
            scope->ready = 0; scope->revision_pending = 0; memcpy(scope->revision,revision,65);
            while (*position && *position != transaction) position = &(*position)->next;
            *position = transaction->next; free(transaction); transaction = NULL;
            status = 200; reason = "scope-mutation-acknowledged"; goto reply;
        }
    }
    if (!strcmp(operation,"private-authority-recover")) {
        if (!expected_scope || strcmp(expected_scope,scope->revision)) { status = 409; reason = "scope-revision-changed"; goto reply; }
        if (scope->scope_mutations) { status = 409; reason = "scope-mutation-unsettled"; goto reply; }
        if (reuse_scope_active(scope)) { status = 409; reason = "mutation-active"; goto reply; }
        if (scope->executions || scope->lost_execution_context) { status = 409; reason = "execution-unsettled"; goto reply; }
        /* Explicit authenticated producer recovery, after durable intent/drain
         * proof. Neither ordinary context nor a rendered fill calls this. */
        if (!delivery_header_equals(ctx->http_req,HDR("X-UltraCache-Private-Drained"),"1")) goto reply;
        /* Real invalidation already installed the current namespace revision.
         * Preserve it for fresh source bodies observed before this recovery.
         * Pending/failed fencing was repaired or refused before dispatch above.
         * Old tag generations remain bound to the preceding invalidated ID. */
        scope->ready = 1;
        status = 200; reason = "scope-recovered"; goto reply;
    }
    if (!public_policy(id)) goto reply;
    tag = reuse_tag_find(scope,id,!strcmp(operation,"private-mutation-begin"));
    if (!tag) { status = 409; reason = "authority-unavailable"; goto reply; }
    if (!strcmp(operation,"private-generation-publish")) {
        const char *generation = reuse_single(ctx->http_req,HDR("X-UltraCache-Private-Generation"));
        if (!reuse_scope_ready(scope)) { status = 409; reason = scope->ready ? "execution-held" : "scope-unbound"; goto reply; }
        if (!expected_scope || strcmp(expected_scope,scope->revision)) { status = 409; reason = "scope-revision-changed"; goto reply; }
        if (reuse_active(tag)) { status = 409; reason = "mutation-active"; goto reply; }
        if (reuse_tag_execution(scope,id)) { status = 409; reason = "execution-unsettled"; goto reply; }
        if (!expected || strcmp(expected,tag->revision)) { status = 409; reason = "revision-changed"; goto reply; }
        if (!public_policy(generation)) goto reply;
        if (reuse_tag_clean(scope,tag) && !strcmp(tag->generation,generation)) {
            status = 200; reason = "generation-published"; goto reply;
        }
        if (!reuse_random_id(tag->revision)) { status = 503; reason = "identity-unavailable"; goto reply; }
        memcpy(tag->generation,generation,65); memcpy(tag->bound_scope_revision,scope->revision,65); tag->clean = 1;
        status = 200; reason = "generation-published"; goto reply;
    }
    if (!strcmp(operation,"private-tag-retire")) {
        struct reuse_tag **position;
        if (!expected || strcmp(expected,tag->revision)) { status = 409; reason = "revision-changed"; goto reply; }
        if (tag->transactions) { status = 409; reason = "transaction-unacknowledged"; goto reply; }
        if (reuse_tag_execution(scope,id)) { status = 409; reason = "execution-unsettled"; goto reply; }
        position = &scope->tags[reuse_hash(id)%scope->tag_capacity];
        while (*position && *position != tag) position = &(*position)->next;
        *position = tag->next; --scope->tag_count; reuse_tag_free(tag); tag = NULL;
        status = 200; reason = "tag-retired"; goto reply;
    }
    {
        const char *transaction_id = reuse_single(ctx->http_req,HDR("X-UltraCache-Private-Transaction"));
        const char *lease = reuse_single(ctx->http_req,HDR("X-UltraCache-Private-Lease"));
        if (!public_policy(transaction_id)) goto reply;
        if (!strcmp(operation,"private-mutation-begin")) {
            const char *request_id = reuse_single(ctx->http_req,HDR("X-UltraCache-Private-Request-Id"));
            const char *challenge = reuse_single(ctx->http_req,HDR("X-UltraCache-Private-Challenge"));
            struct mutation_execution *origin = NULL;
            if (http_CountHdr(ctx->http_req,HDR("X-UltraCache-Private-Request-Id")) ||
                http_CountHdr(ctx->http_req,HDR("X-UltraCache-Private-Challenge"))) {
                if (!public_policy(request_id) || !public_policy(challenge)) goto reply;
                for (origin = scope->executions; origin; origin = origin->next)
                    if (!strcmp(origin->request_id,request_id) && !strcmp(origin->challenge,challenge)) break;
                if (!origin || !origin->hold || !origin->live || !origin->awaiting_receipt || !mutation_context_current(origin)) {
                    status = 409; reason = "mutation-execution-unavailable"; goto reply;
                }
            }
            transaction = reuse_transaction_find(tag,transaction_id);
            if (transaction && origin && *transaction->request_id && !reuse_transaction_owned_by(transaction,origin)) {
                status = 409; reason = "mutation-execution-changed"; goto reply;
            }
            if (!transaction && (!expected || strcmp(expected,tag->revision))) {
                status = 409; reason = "revision-changed"; goto reply;
            }
            if (!transaction) {
                transaction = reuse_transaction_begin(tag,transaction_id);
                if (!transaction) { reuse_scope_unbind(scope); status = 503; reason = "authority-memory"; goto reply; }
                if (origin) {
                    memcpy(transaction->request_id,origin->request_id,65);
                    memcpy(transaction->challenge,origin->challenge,65);
                }
            }
            status = 200; reason = "mutation-recorded"; goto reply;
        }
        transaction = reuse_transaction_find(tag,transaction_id);
        if (!transaction || !lease || strcmp(lease,transaction->lease)) { transaction = NULL; status = 409; reason = "unknown-lease"; goto reply; }
        if (!strcmp(operation,"private-mutation-commit")) {
            if (transaction->active) {
                if (!reuse_random_id(tag->revision)) { status = 503; reason = "identity-unavailable"; goto reply; }
                transaction->active = 0; tag->clean = 0; tag->generation[0] = 0;
                memcpy(transaction->completed_revision,tag->revision,65);
            }
            status = 200; reason = "mutation-committed"; goto reply;
        }
        if (!strcmp(operation,"private-mutation-ack")) {
            struct reuse_transaction **position = &tag->transactions;
            if (transaction->active) { status = 409; reason = "mutation-active"; goto reply; }
            if (reuse_transaction_receipt_pending(scope,transaction)) { status = 409; reason = "receipt-outstanding"; goto reply; }
            /* Invalidate even a completed-begin retry frame observed after a
             * later publication, before forgetting its idempotency record.
             * Content generation/clean state stay intact: this is CAS fencing. */
            if (!reuse_random_id(tag->revision)) { status = 503; reason = "identity-unavailable"; goto reply; }
            while (*position && *position != transaction) position = &(*position)->next;
            *position = transaction->next; free(transaction); transaction = NULL;
            status = 200; reason = "mutation-acknowledged"; goto reply;
        }
    }
reply:
    if (scope && operation && strcmp(operation,"private-authority-context") &&
        strcmp(operation,"delivery-reuse-context")) delivery_held_notify(scope);
    status = reuse_control_reply(task,status,reason,scope,tag,transaction,drained,context_owner,delivery,observation,observation_target);
    mutation_execution_free(drained);
    pthread_mutex_unlock(&lock); return status;
}
VCL_BOOL vmod_reuse_control_synth(VRT_CTX, struct vmod_priv *priv) {
    struct task *task = priv->priv;
    struct vrt_blob body;
    if (!task || !task->control_body) return 0;
    http_ForceHeader(ctx->http_resp,H_Content_Type,"application/json");
    http_ForceHeader(ctx->http_resp,H_Cache_Control,"private, no-store");
    http_ForceHeader(ctx->http_resp,HDR("Surrogate-Control"),"no-store");
    INIT_OBJ(&body,VRT_BLOB_MAGIC); body.blob = task->control_body; body.len = task->control_length;
    VRT_l_resp_body(ctx,LBODY_SET_BLOB,NULL,&body); return 1;
}
