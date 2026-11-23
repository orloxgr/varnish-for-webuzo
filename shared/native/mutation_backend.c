/* SPDX-License-Identifier: GPL-3.0-or-later
 * Existing backend PRIV_TASK/registry ownership. No helper, public credential,
 * body store or clean grant. Recovery of retained unknown
 * execution markers and trusted identity mapping are separate integration gates.
 */
static const hdr_t h_mutation_context = HDR("X-UltraCache-Mutation-Context");
static const hdr_t h_mutation_receipt = HDR("X-UltraCache-Mutation-Receipt");

static void mutation_execution_free(struct mutation_execution *execution) {
    volatile unsigned char *wipe;
    size_t i;
    if (!execution) return;
    while (execution->known_tags) {
        struct reuse_execution_tag *next = execution->known_tags->next;
        free(execution->known_tags); execution->known_tags = next;
    }
    delivery_mutation_header_free(execution->header);
    wipe = execution->key;
    for (i = 0; i < sizeof(execution->key); ++i) wipe[i] = 0;
    free(execution);
}
static void mutation_unknown(struct mutation_execution *execution) {
    execution->unknown = 1;
    reuse_scope_unbind(execution->scope);
}
static void mutation_task_fini(VRT_CTX, struct task *task) {
    struct mutation_execution *execution = task ? task->mutation : NULL;
    if (!execution) return;
    if (ctx && ctx->http_bereq) http_Unset(ctx->http_bereq,h_mutation_context);
    pthread_mutex_lock(&lock);
    if (execution->awaiting_receipt) mutation_unknown(execution);
    /* This backend owner can no longer return a receipt. Unknown application
     * execution remains retained until independent actual-drain attestation. */
    execution->awaiting_receipt = 0;
    execution->live = 0;
    if (!execution->unknown && !execution->hold) {
        struct mutation_execution **position = &execution->scope->executions;
        while (*position && *position != execution) position = &(*position)->next;
        if (*position) *position = execution->next;
        mutation_execution_free(execution);
    } else {
        volatile unsigned char *wipe = execution->key;
        size_t i;
        /* No engine pointer/header survives fini. V2 retains its original
         * purpose key until exact post-drain completion can be verified. */
        delivery_mutation_header_free(execution->header); execution->header = NULL;
        if (!execution->hold) for (i = 0; i < sizeof(execution->key); ++i) wipe[i] = 0;
    }
    task->mutation = NULL;
    pthread_mutex_unlock(&lock);
}
static int mutation_context_current(const struct mutation_execution *execution) {
    const struct reuse_scope *scope = execution->scope;
    const struct public_declaration *current = public_declaration(scope->site,scope->host,scope->scope);
    return scope->enabled && current && !strcmp(current->wordpress_policy,execution->wordpress_policy) &&
        !strcmp(execution->epoch,public_registry_epoch) && !strcmp(execution->incarnation,scope->incarnation) &&
        !strcmp(execution->native_policy,scope->native_policy) &&
        !strcmp(execution->wordpress_policy,scope->wordpress_policy) && !strcmp(execution->reuse_policy,scope->policy) &&
        (!execution->hold || !strcmp(execution->coverage_policy,scope->coverage_policy));
}
VCL_BOOL vmod_mutation_backend_start(VRT_CTX, struct vmod_priv *priv, VCL_STRING site,
    VCL_STRING native_policy, VCL_STRING credential) {
    struct task *task;
    struct public_declaration *declaration;
    struct reuse_scope *scope = NULL;
    struct mutation_execution *execution = NULL;
    struct delivery_mutation_context context;
    const char *host, *method, *url;
    char scope_digest[65], *header = NULL;
    size_t length;
    static const char prefix[] = "X-UltraCache-Mutation-Context: ";
    int valid = 0;
    http_Unset(ctx->http_bereq,h_mutation_context);
    http_Unset(ctx->http_bereq,h_mutation_receipt);
    http_Unset(ctx->http_bereq,HDR("X-UltraCache-Delivery-Reuse-Candidate-Version"));
    http_Unset(ctx->http_bereq,HDR("X-UltraCache-VCL-Execution-Drain-Version"));
#ifndef UC_NATIVE_PRIVATE_REUSE
    (void)priv; (void)site; (void)native_policy; (void)credential;
    return 0;
#endif
    task = get_task(priv);
    if (task) mutation_task_fini(ctx,task);
    host = reuse_single(ctx->http_bereq,H_Host);
    method = ctx->http_bereq->hd[HTTP_HDR_METHOD].b;
    url = ctx->http_bereq->hd[HTTP_HDR_URL].b;
    if (!site || !host || !url || !method ||
        !delivery_header_equals(ctx->http_bereq,h_adapter_site,site) ||
        !delivery_header_equals(ctx->http_bereq,HDR("X-SCP-Profile"),"ultracache")) return 0;
    pthread_mutex_lock(&lock);
    declaration = public_declaration_for_url(site,host,url);
    scope = declaration ? reuse_scope_find(site,host,declaration->scope) : NULL;
    if (!scope || !scope->enabled || !native_policy || strcmp(native_policy,scope->native_policy) ||
        strcmp(declaration->wordpress_policy,scope->wordpress_policy)) goto done;
    if (task && task->key) {
        struct handoff *entry = delivery_entry(task->key);
        struct continuation *delivery = entry ? entry->delivery : NULL;
        const struct delivery_fragment *fragment = delivery ? delivery_fragment_named(delivery,url) : NULL;
        /* Native-owned publication-only recovery and prepared private virtual
         * sources do not execute an application/provider. Client headers alone
         * cannot enter either phase or create a skip grant. */
        if (delivery && (delivery->phase == D_RECOVERY || delivery->phase == D_FINALIZE ||
            (delivery->phase == D_DELIVERED && fragment && fragment->cache_key && fragment->cache_ttl))) goto done;
    }
    /* Positive personal maps prearm known tags below. They do not prove full
     * cross-route actor coverage for this backend lifecycle: retain the explicit
     * own-scope unknown fence instead of inferring known-empty from a match. */
    if (!*scope->coverage_policy) reuse_scope_unbind(scope);
    execution = calloc(1,sizeof(*execution));
    if (!task || !execution || !credential || !*credential ||
        !reuse_random_id(execution->request_id) || !reuse_random_id(execution->challenge) ||
        !delivery_selection_digest((const unsigned char *)scope->scope,strlen(scope->scope),scope_digest) ||
        !delivery_mutation_key((const unsigned char *)credential,strlen(credential),execution->key)) {
        reuse_scope_unbind(scope); scope->lost_execution_context = 1; goto done;
    }
    execution->scope = scope; execution->live = execution->awaiting_receipt = 1;
    if (scope->execution_sequence == UINT64_MAX) {
        reuse_scope_unbind(scope); scope->lost_execution_context = 1; goto done;
    }
    execution->sequence = ++scope->execution_sequence;
    execution->hold = *scope->coverage_policy != 0; execution->unknown = !execution->hold;
    memcpy(execution->scope_revision,scope->revision,65);
    if (execution->hold) memcpy(execution->coverage_policy,scope->coverage_policy,65);
    else reuse_identity_prearm(scope,execution,reuse_single(ctx->http_bereq,H_Cookie));
    if (task->key) {
        struct handoff *entry = delivery_entry(task->key);
        struct continuation *delivery = entry ? entry->delivery : NULL;
        if (delivery && delivery->phase == D_PREPARE && delivery->source_stage != SOURCE_CAPTURE &&
            delivery->source_stage != SOURCE_RESOLVER && !delivery->source_unstable &&
            delivery->site && !strcmp(delivery->site,site) &&
            delivery->host && !strcmp(delivery->host,host)) {
            execution->delivery_key = task->key;
            memcpy(delivery->reuse_origin_request,execution->request_id,65);
            memcpy(delivery->reuse_origin_challenge,execution->challenge,65);
            free(delivery->reuse_scope); delivery->reuse_scope = strdup(scope->scope);
            memcpy(delivery->reuse_epoch,public_registry_epoch,65);
            memcpy(delivery->reuse_incarnation,scope->incarnation,65);
            memcpy(delivery->reuse_native_policy,scope->native_policy,65);
            memcpy(delivery->reuse_wp_policy,scope->wordpress_policy,65);
            memcpy(delivery->reuse_policy,scope->policy,65);
        }
    }
    memcpy(execution->epoch,public_registry_epoch,65); memcpy(execution->incarnation,scope->incarnation,65);
    memcpy(execution->native_policy,scope->native_policy,65); memcpy(execution->wordpress_policy,scope->wordpress_policy,65);
    memcpy(execution->reuse_policy,scope->policy,65);
    context = (struct delivery_mutation_context){site,host,scope_digest,execution->epoch,execution->incarnation,
        execution->native_policy,execution->wordpress_policy,execution->reuse_policy,
        execution->request_id,execution->challenge,method,url};
    if (!(execution->hold ? delivery_mutation_context_header_v2(execution->key,&context,execution->coverage_policy,&header,execution->proof) :
        delivery_mutation_context_header(execution->key,&context,&header,execution->proof))) {
        reuse_scope_unbind(scope); scope->lost_execution_context = 1; goto done;
    }
    length = strlen(header);
    if (length > SIZE_MAX-sizeof(prefix) || !(execution->header = malloc(sizeof(prefix)+length)) ||
        ctx->http_bereq->nhd >= ctx->http_bereq->shd) {
        reuse_scope_unbind(scope); scope->lost_execution_context = 1; goto done;
    }
    memcpy(execution->header,prefix,sizeof(prefix)-1);
    memcpy(execution->header+sizeof(prefix)-1,header,length+1);
    execution->next = scope->executions; scope->executions = execution; task->mutation = execution;
    http_SetHeader(ctx->http_bereq,execution->header);
    if (scope->execution_drain && execution->hold)
        http_ForceHeader(ctx->http_bereq,HDR("X-UltraCache-VCL-Execution-Drain-Version"),"1");
    if (execution->delivery_key) {
        struct handoff *entry = delivery_entry(execution->delivery_key);
        struct continuation *delivery = entry ? entry->delivery : NULL;
        if (delivery && delivery->reuse_scope && ctx->http_bereq->nhd < ctx->http_bereq->shd) {
            http_ForceHeader(ctx->http_bereq,HDR("X-UltraCache-Delivery-Reuse-Candidate-Version"),"1");
            delivery->reuse_negotiated = 1;
        }
    }
    execution = NULL; valid = 1;
done:
    pthread_mutex_unlock(&lock);
    delivery_mutation_header_free(header); mutation_execution_free(execution);
    return valid;
}
VCL_BOOL vmod_mutation_backend_response(VRT_CTX, struct vmod_priv *priv) {
    struct task *task = priv->priv;
    struct mutation_execution *execution = task ? task->mutation : NULL;
    struct delivery_mutation_receipt *receipt = NULL;
    struct delivery_mutation_pair *pair;
    const char *header = reuse_single(ctx->http_beresp,h_mutation_receipt);
    int valid = execution && header && (execution->hold ?
        delivery_mutation_receipt_verify_v2(execution->key,execution->proof,execution->coverage_policy,header,strlen(header),&receipt) :
        delivery_mutation_receipt_verify(execution->key,execution->proof,header,strlen(header),&receipt));
    http_Unset(ctx->http_beresp,h_mutation_receipt);
    http_Unset(ctx->http_beresp,h_mutation_context);
    if (!execution) { delivery_mutation_receipt_free(receipt); return 0; }
    pthread_mutex_lock(&lock);
    execution->awaiting_receipt = 0;
    if (!valid || !mutation_context_current(execution)) { mutation_unknown(execution); valid = 0; goto done; }
    if (receipt->state == MUTATION_SCOPE || (execution->hold && !receipt->coverage_qualified)) mutation_unknown(execution);
    else if (execution->hold) execution->coverage_qualified = 1;
    if (receipt->state == MUTATION_DIRTY) {
        for (pair = receipt->pairs; pair; pair = pair->next) {
            struct reuse_tag *tag = reuse_tag_find(execution->scope,pair->tag,1);
            if (!tag || !reuse_transaction_begin(tag,pair->transaction)) {
                mutation_unknown(execution); valid = 0; break;
            }
        }
        delivery_held_notify(execution->scope);
    }
done:
    pthread_mutex_unlock(&lock);
    delivery_mutation_receipt_free(receipt);
    return valid;
}
