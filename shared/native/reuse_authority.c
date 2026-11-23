/* SPDX-License-Identifier: GPL-3.0-or-later
 * Included after public_selection_registry.c. Metadata only: existing native
 * registry lock/lifetime, no private bodies, timer or independent datastore.
 * Root/application owns durable intents and actual persistence/drain proof.
 */
#include "vsb.h"

struct reuse_transaction {
    struct reuse_transaction *next;
    char id[65], lease[65], completed_revision[65];
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
    char native_policy[65], wordpress_policy[65], policy[65];
    unsigned enabled, ready;
    struct reuse_tag **tags;
    size_t tag_capacity, tag_count;
};
static struct reuse_scope *reuse_scopes;

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
        for (i = 0; i < scope->tag_capacity; ++i) {
            struct reuse_tag *tag = scope->tags[i];
            while (tag) { struct reuse_tag *next = tag->next; reuse_tag_free(tag); tag = next; }
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
static int reuse_tag_clean(const struct reuse_scope *scope, const struct reuse_tag *tag) {
    return scope && scope->ready && tag->clean && !strcmp(tag->bound_scope_revision,scope->revision);
}
static size_t reuse_scope_active(const struct reuse_scope *scope) {
    size_t count = 0, i;
    for (i = 0; i < scope->tag_capacity; ++i) {
        const struct reuse_tag *tag;
        for (tag = scope->tags[i]; tag; tag = tag->next) count += reuse_active(tag);
    }
    return count;
}
static struct reuse_transaction *reuse_transaction_find(struct reuse_tag *tag, const char *id) {
    struct reuse_transaction *transaction;
    for (transaction = tag->transactions; transaction; transaction = transaction->next)
        if (!strcmp(transaction->id,id)) return transaction;
    return NULL;
}
static struct reuse_transaction *reuse_transaction_begin(struct reuse_tag *tag, const char *id) {
    struct reuse_transaction *transaction = reuse_transaction_find(tag,id);
    char revision[65];
    if (transaction) return transaction; /* active or completed retry: never reopen */
    transaction = calloc(1,sizeof(*transaction));
    if (!transaction || !reuse_random_id(transaction->lease) || !reuse_random_id(revision)) {
        free(transaction); return NULL;
    }
    memcpy(transaction->id,id,65); transaction->active = 1;
    transaction->next = tag->transactions; tag->transactions = transaction;
    memcpy(tag->revision,revision,65); tag->clean = 0; tag->generation[0] = 0;
    return transaction;
}
static void reuse_scope_unbind(struct reuse_scope *scope) {
    scope->ready = 0;
    (void)reuse_random_id(scope->revision); /* failure remains UNBOUND */
}

VCL_BOOL vmod_reuse_register(VRT_CTX, VCL_STRING site, VCL_STRING host, VCL_STRING scope,
    VCL_STRING native_policy, VCL_STRING wordpress_policy, VCL_STRING policy, VCL_BOOL enabled) {
    struct reuse_scope *value;
    struct public_declaration *declaration;
    int valid = 0;
    (void)ctx;
#ifndef UC_EXPERIMENTAL_PRIVATE_REUSE
    (void)site; (void)host; (void)scope; (void)native_policy; (void)wordpress_policy; (void)policy; (void)enabled;
    return 0;
#endif
    if (!site || !*site || !host || !*host || !delivery_selection_scope_valid(scope) ||
        (enabled && (!public_policy(native_policy) || !public_policy(wordpress_policy) || !public_policy(policy)))) return 0;
    pthread_mutex_lock(&lock);
    value = reuse_scope_find(site,host,scope);
    if (!enabled) {
        if (value) { value->enabled = 0; reuse_scope_unbind(value); }
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
        strcmp(value->wordpress_policy,wordpress_policy) || strcmp(value->policy,policy)) reuse_scope_unbind(value);
    memcpy(value->native_policy,native_policy,65); memcpy(value->wordpress_policy,wordpress_policy,65);
    memcpy(value->policy,policy,65); value->enabled = 1; valid = 1;
done:
    pthread_mutex_unlock(&lock); return valid;
}

static const char *reuse_single(const struct http *http, hdr_t header) {
    const char *value;
    return http_CountHdr(http,header) == 1 && http_GetHdr(http,header,&value) ? value : NULL;
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
    const struct reuse_scope *scope, const struct reuse_tag *tag, const struct reuse_transaction *transaction) {
    struct vsb *json = VSB_new_auto();
    char *body = NULL;
    if (!json) return 503;
    VSB_printf(json,"{\"schemaVersion\":1,\"accepted\":%s",status == 200 ? "true" : "false");
    reuse_json_field(json,"reason",reason);
    reuse_json_field(json,"epoch",public_registry_epoch);
    if (scope) {
        reuse_json_field(json,"siteId",scope->site); reuse_json_field(json,"canonicalHost",scope->host);
        reuse_json_field(json,"scope",scope->scope); reuse_json_field(json,"incarnation",scope->incarnation);
        reuse_json_field(json,"scopeRevision",scope->revision);
        reuse_json_field(json,"scopeState",scope->ready ? "ready" : "unbound");
        reuse_json_field(json,"nativePolicy",scope->native_policy);
        reuse_json_field(json,"wordpressPolicy",scope->wordpress_policy);
        reuse_json_field(json,"reusePolicy",scope->policy);
    }
    if (tag) {
        size_t active = reuse_active(tag);
        reuse_json_field(json,"tag",tag->id); reuse_json_field(json,"revision",tag->revision);
        reuse_json_field(json,"state",active ? "dirty" : reuse_tag_clean(scope,tag) ? "clean" : "unbound");
        VSB_printf(json,",\"remainingMutations\":%ju",(uintmax_t)active);
        if (reuse_tag_clean(scope,tag)) reuse_json_field(json,"generation",tag->generation);
    }
    if (transaction) {
        reuse_json_field(json,"transaction",transaction->id); reuse_json_field(json,"lease",transaction->lease);
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
    const char *operation, *application_scope, *id, *epoch, *incarnation, *expected_scope, *expected;
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
    pthread_mutex_lock(&lock);
#ifndef UC_EXPERIMENTAL_PRIVATE_REUSE
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
    if (!strcmp(operation,"private-authority-recover")) {
        if (!expected_scope || strcmp(expected_scope,scope->revision)) { status = 409; reason = "scope-revision-changed"; goto reply; }
        if (reuse_scope_active(scope)) { status = 409; reason = "mutation-active"; goto reply; }
        /* Explicit authenticated producer recovery, after durable intent/drain
         * proof. Neither ordinary context nor a rendered fill calls this. */
        if (!delivery_header_equals(ctx->http_req,HDR("X-UltraCache-Private-Drained"),"1")) goto reply;
        if (!scope->ready) {
            if (!reuse_random_id(scope->revision)) { status = 503; reason = "identity-unavailable"; goto reply; }
            scope->ready = 1;
        }
        status = 200; reason = "scope-recovered"; goto reply;
    }
    if (!public_policy(id)) goto reply;
    tag = reuse_tag_find(scope,id,!strcmp(operation,"private-mutation-begin"));
    if (!tag) { status = 409; reason = "authority-unavailable"; goto reply; }
    if (!strcmp(operation,"private-generation-publish")) {
        const char *generation = reuse_single(ctx->http_req,HDR("X-UltraCache-Private-Generation"));
        if (!scope->ready) { status = 409; reason = "scope-unbound"; goto reply; }
        if (!expected_scope || strcmp(expected_scope,scope->revision)) { status = 409; reason = "scope-revision-changed"; goto reply; }
        if (reuse_active(tag)) { status = 409; reason = "mutation-active"; goto reply; }
        if (!expected || strcmp(expected,tag->revision)) { status = 409; reason = "revision-changed"; goto reply; }
        if (!public_policy(generation)) goto reply;
        if (!reuse_random_id(tag->revision)) { status = 503; reason = "identity-unavailable"; goto reply; }
        memcpy(tag->generation,generation,65); memcpy(tag->bound_scope_revision,scope->revision,65); tag->clean = 1;
        status = 200; reason = "generation-published"; goto reply;
    }
    if (!strcmp(operation,"private-tag-retire")) {
        struct reuse_tag **position;
        if (!expected || strcmp(expected,tag->revision)) { status = 409; reason = "revision-changed"; goto reply; }
        if (tag->transactions) { status = 409; reason = "transaction-unacknowledged"; goto reply; }
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
            transaction = reuse_transaction_find(tag,transaction_id);
            if (!transaction && (!expected || strcmp(expected,tag->revision))) {
                status = 409; reason = "revision-changed"; goto reply;
            }
            transaction = reuse_transaction_begin(tag,transaction_id);
            if (!transaction) { reuse_scope_unbind(scope); status = 503; reason = "authority-memory"; goto reply; }
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
    status = reuse_control_reply(task,status,reason,scope,tag,transaction);
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
