/* SPDX-License-Identifier: GPL-3.0-or-later
 * Existing client-task/handoff lifetime. Authenticated producer housekeeping
 * only: no worker, queue, body store, hold retirement or admission authority.
 */
#include <limits.h>
static const hdr_t h_execution_drain = HDR("X-UltraCache-Delivery-Execution-Drain-Context");

VCL_INT vmod_execution_drain_authorize(VRT_CTX, struct vmod_priv *priv,
    VCL_STRING site, VCL_STRING native_policy, VCL_STRING credential) {
    struct task *task = get_task(priv);
    struct delivery_execution_drain *d = NULL;
    struct reuse_scope *scope;
    struct mutation_execution *execution;
    const struct public_declaration *boundary;
    const char *header, *key, *content_length;
    unsigned char purpose[32] = {0};
    size_t i;
    int status = 400;
    if (!task) return 503;
#ifndef UC_NATIVE_PRIVATE_REUSE
    (void)site; (void)native_policy; (void)credential;
    return 501;
#endif
    header = reuse_single(ctx->http_req,h_execution_drain);
    content_length = reuse_single(ctx->http_req,H_Content_Length);
    if (!site || !credential || !*credential || ctx->req->esi_level || ctx->req->restarts ||
        strcmp(ctx->http_req->hd[HTTP_HDR_METHOD].b,"PURGE") ||
        strcmp(ctx->http_req->hd[HTTP_HDR_URL].b,"/__ultracache-vcl-contract-v2") ||
        !delivery_header_equals(ctx->http_req,HDR("X-UltraCache-Contract"),"2") ||
        !delivery_header_equals(ctx->http_req,HDR("X-UltraCache-Operation"),"private-execution-drain-dispatch") ||
        !delivery_header_equals(ctx->http_req,HDR("X-SCP-Profile"),"ultracache") ||
        !delivery_header_equals(ctx->http_req,h_adapter_site,site) ||
        http_CountHdr(ctx->http_req,H_Transfer_Encoding) ||
        (http_CountHdr(ctx->http_req,H_Content_Length) && (!content_length || strcmp(content_length,"0"))) ||
        !header || !delivery_mutation_key((const unsigned char *)credential,strlen(credential),purpose) ||
        !delivery_execution_drain_verify(purpose,header,strlen(header),&d)) goto done;
    /* Existing owner allocation is outside the registry lock. Its normal task
     * finalizer also closes an abandoned producer dispatch. */
    key = vmod_open(ctx,priv);
    if (!key) { status = 503; goto done; }
    pthread_mutex_lock(&lock);
    scope = reuse_scope_find(site,reuse_single(ctx->http_req,H_Host),d->scope);
    boundary = public_declaration_for_url(site,d->host,d->target);
    if (!scope || !scope->enabled || !scope->execution_drain || !*scope->coverage_policy ||
        !native_policy || strcmp(native_policy,scope->native_policy) || !boundary ||
        strcmp(boundary->scope,scope->scope) || strcmp(d->site_id,site) || strcmp(d->host,scope->host) ||
        !delivery_header_equals(ctx->http_req,HDR("X-UltraCache-Public-Selection-Scope"),scope->scope) ||
        strcmp(d->epoch,public_registry_epoch) || strcmp(d->incarnation,scope->incarnation)) {
        status = 409; goto unlock;
    }
    for (execution = scope->executions; execution; execution = execution->next)
        if (!strcmp(execution->request_id,d->request_id)) break;
    if (execution && (strcmp(execution->challenge,d->challenge) || !execution->hold ||
        strcmp(execution->epoch,d->epoch) || strcmp(execution->incarnation,d->incarnation) ||
        strcmp(execution->native_policy,d->native_policy) || strcmp(execution->wordpress_policy,d->wordpress_policy) ||
        strcmp(execution->reuse_policy,d->reuse_policy) || strcmp(execution->coverage_policy,d->coverage_policy))) {
        status = 409; goto unlock;
    }
    /* A retired marker may be retried after ACK loss. Only the producer's exact
     * durable journal validates that case; this dispatch grants no CLEAN fact. */
    if (!task->owner || task->owner->execution_drain) { status = 409; goto unlock; }
    task->owner->execution_drain = d; d = NULL;
    http_ForceHeader(ctx->http_req,h_key,key);
    status = WS_Overflowed(ctx->ws) ? 503 : 200;
unlock:
    pthread_mutex_unlock(&lock);
done:
    delivery_execution_drain_free(d);
    {
        volatile unsigned char *wipe = purpose;
        for (i = 0; i < sizeof(purpose); ++i) wipe[i] = 0;
    }
    return status;
}

/* Retain only the adapter's already-owned routing inputs. Dynamic arbitrary
 * browser/control headers do not become inputs of the early metadata owner. */
static int execution_drain_routing_header(const struct http *http, unsigned i) {
    return http_IsHdr(&http->hd[i],H_Host) ||
        http_IsHdr(&http->hd[i],HDR("X-Forwarded-Proto")) ||
        http_IsHdr(&http->hd[i],HDR("X-Forwarded-Host")) ||
        http_IsHdr(&http->hd[i],HDR("X-Forwarded-Port")) ||
        http_IsHdr(&http->hd[i],HDR("X-Real-IP")) ||
        http_IsHdr(&http->hd[i],HDR("X-Forwarded-For")) ||
        http_IsHdr(&http->hd[i],HDR("X-WV-Origin"));
}
static int execution_drain_clear_headers(struct http *http) {
    unsigned i = HTTP_HDR_FIRST;
    while (i < http->nhd) {
        const char *line = http->hd[i].b, *colon;
        char *name;
        hdr_t dynamic;
        size_t length;
        if (!line || execution_drain_routing_header(http,i)) { ++i; continue; }
        colon = strchr(line,':');
        if (!colon || (length = (size_t)(colon-line)+1) > UCHAR_MAX) return 0;
        name = malloc(length+2);
        if (!name) return 0;
        name[0] = (char)length; memcpy(name+1,line,length); name[length+1] = 0;
        CAST_HDR(dynamic,name);
        http_Unset(http,dynamic); free(name);
    }
    return 1;
}
VCL_INT vmod_execution_drain_backend(VRT_CTX, struct vmod_priv *priv, VCL_STRING credential) {
    struct task *task = priv->priv;
    struct handoff *entry;
    struct delivery_execution_drain *d;
    const char *target = NULL, *header = NULL, *application_scope = NULL;
    int owned = 0;
    pthread_mutex_lock(&lock);
    entry = task && task->key ? delivery_entry(task->key) : NULL;
    d = entry ? entry->execution_drain : NULL;
    if (d) {
        owned = 1;
        target = WS_Copy(ctx->ws,d->target,-1);
        header = WS_Copy(ctx->ws,d->header,-1);
        application_scope = WS_Copy(ctx->ws,d->scope,-1);
    }
    pthread_mutex_unlock(&lock);
    if (!owned) return http_CountHdr(ctx->http_bereq,h_execution_drain) ? -1 : 0;
    if (task->execution_drain_sent || !credential || !*credential || !target || !header || !application_scope ||
        !execution_drain_clear_headers(ctx->http_bereq)) return -1;
    task->execution_drain_sent = 1;
    http_SetH(ctx->http_bereq,HTTP_HDR_METHOD,"GET");
    http_SetH(ctx->http_bereq,HTTP_HDR_URL,target);
    http_ForceHeader(ctx->http_bereq,h_version,"1");
    http_ForceHeader(ctx->http_bereq,h_phase,"execution-drain");
    http_ForceHeader(ctx->http_bereq,HDR("X-UltraCache-Delivery-Execution-Drain-Version"),"1");
    http_ForceHeader(ctx->http_bereq,h_original,target);
    http_ForceHeader(ctx->http_bereq,h_selection_scope,application_scope);
    http_ForceHeader(ctx->http_bereq,HDR("X-UltraCache-Delivery-Authorization"),credential);
    http_ForceHeader(ctx->http_bereq,h_execution_drain,header);
    return WS_Overflowed(ctx->ws) ? -1 : 1;
}
VCL_INT vmod_execution_drain_response(VRT_CTX, struct vmod_priv *priv) {
    struct task *task = priv->priv;
    const char *outcome;
    if (!task || !task->execution_drain_sent) return 0;
    outcome = reuse_single(ctx->http_beresp,HDR("X-UltraCache-Execution-Drain-Outcome"));
    if (http_GetStatus(ctx->http_beresp) != 204 ||
        !delivery_header_equals(ctx->http_beresp,HDR("X-UltraCache-Execution-Drain-Version"),"1") ||
        !outcome || (strcmp(outcome,"settled") && strcmp(outcome,"pending") && strcmp(outcome,"unavailable"))) return -1;
    http_Unset(ctx->http_beresp,H_Set_Cookie); http_Unset(ctx->http_beresp,h_set_cookie2);
    http_Unset(ctx->http_beresp,h_execution_drain); http_Unset(ctx->http_beresp,h_mutation_context);
    http_Unset(ctx->http_beresp,h_mutation_receipt);
    http_Unset(ctx->http_beresp,HDR("X-UltraCache-Delivery-Authorization"));
    return 1;
}
