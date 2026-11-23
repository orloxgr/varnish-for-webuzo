/* SPDX-License-Identifier: GPL-3.0-or-later
 * Same continuation, native HSH waiting list and existing pool waiter only.
 * A wake is permission to revalidate a pinned read, NEVER a CLEAN grant.
 */
#ifdef UC_NATIVE_PRIVATE_REUSE
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <poll.h>
#include "waiter/waiter.h"
#include "uc_engine_counters.h"
#include "uc_engine_pool.h"
#include "uc_engine_transport.h"

/* Same optional execution-observation budget as the existing PHP finalizer.
 * This bounds cache-only scheduling, never application work or a CLEAN grant. */
#define UC_EXECUTION_OBSERVATION_BUDGET 0.5

struct delivery_held_wait {
    struct waited waited;
    struct pool_task task;
    struct objcore *reservation;
    struct vcl *vcl;
    struct req *request; /* borrowed only while its registered owner is alive */
    const struct waiter *engine_waiter;
    uint64_t owner;
    double deadline;
    int fd[2], cancelled;
};

/* Called with the existing registry lock, including from real prewrite RPCs. */
static void delivery_held_notify(struct reuse_scope *scope) {
    struct handoff *entry;
    unsigned i;
    for (i = 0; i < BUCKETS; ++i) for (entry = buckets[i]; entry; entry = entry->next) {
        struct continuation *d = entry->delivery;
        if (d && d->held_wait && d->reuse_scope && !strcmp(d->site,scope->site) &&
            !strcmp(d->host,scope->host) && !strcmp(d->reuse_scope,scope->scope)) {
            ssize_t ignored = write(d->held_wait->fd[1],"x",1);
            (void)ignored; /* EAGAIN already means a pending native wake. */
        }
    }
}

VCL_INT vmod_delivery_held_waiters(VRT_CTX) {
    struct handoff *entry;
    struct req *request;
    struct objhead *head;
    VCL_INT count = 0;
    unsigned i;
    (void)ctx;
    pthread_mutex_lock(&lock);
    for (i = 0; i < BUCKETS; ++i) for (entry = buckets[i]; entry; entry = entry->next) {
        struct continuation *d = entry->delivery;
        if (!d || !d->held_wait || !d->held_wait->reservation) continue;
        head = d->held_wait->reservation->objhead;
        Lck_Lock(&head->mtx);
        VTAILQ_FOREACH(request,&head->waitinglist,w_list)
            if (request == d->held_wait->request) ++count;
        Lck_Unlock(&head->mtx);
    }
    pthread_mutex_unlock(&lock);
    return count;
}

static void delivery_held_run(struct worker *, void *);
static int delivery_held_cancelled(const struct req *req) {
    struct pollfd descriptor;
    char byte;
    ssize_t count;
    if (req->req_reset) return 1;
    if (req->transport->poll) return req->transport->poll((struct req *)req) < 0;
    descriptor.fd = req->sp->fd; descriptor.events = POLLIN; descriptor.revents = 0;
    if (poll(&descriptor,1,0) <= 0) return 0;
    if (descriptor.revents & (POLLHUP|POLLERR|POLLNVAL)) return 1;
    /* Peek only: never consume pipelined HTTP or TLS bytes. Socket EOF is a
     * disconnect; readable application bytes alone are not cancellation. */
    count = recv(req->sp->fd,&byte,1,MSG_PEEK|MSG_DONTWAIT);
    return count == 0;
}
static void delivery_held_event(struct waited *waited, enum wait_event event, vtim_real now) {
    struct delivery_held_wait *wait = waited->priv1;
    (void)event; (void)now;
    wait->task.func = delivery_held_run; wait->task.priv = wait;
    /* Native RUSH priority, like HSH wakeups: an existing request must finish
     * cleanup even when new-request queue admission is exhausted. */
    AZ(Pool_Task_Any(&wait->task,TASK_QUEUE_RUSH));
}

static void delivery_held_run(struct worker *worker, void *value) {
    struct delivery_held_wait *wait = value;
    struct handoff *entry;
    struct continuation *d = NULL;
    struct reuse_scope *scope;
    struct objcore *reservation;
    struct vcl *vcl;
    char buffer[128];
    int valid = 0, blocked = 0;
    double now;
    while (read(wait->fd[0],buffer,sizeof(buffer)) > 0) {}
    pthread_mutex_lock(&lock);
    entry = delivery_entry(wait->owner);
    if (entry && entry->delivery && entry->delivery->held_wait == wait && !wait->cancelled) {
        d = entry->delivery;
        scope = delivery_reuse_current_scope(d);
        d->reuse_cut_provisional = 1;
        valid = delivery_reuse_record_current(d,d->reuse_record,scope,0);
        d->reuse_cut_provisional = 0;
        wait->cancelled = delivery_held_cancelled(wait->request);
        now = VTIM_real(); /* Registry contention cannot extend this deadline. */
        blocked = valid && !delivery_reuse_scope_ready(d,scope);
        if (!wait->cancelled && valid && blocked && now < wait->deadline) {
            wait->waited.idle = now; wait->waited.tmo = wait->deadline-now;
            if (!Wait_Enter(wait->engine_waiter,&wait->waited)) {
                pthread_mutex_unlock(&lock); return;
            }
            valid = 0;
        }
        d->held_result = wait->cancelled ? 3 : valid && !blocked && now < wait->deadline ? 1 : 2;
        d->held_wait = NULL;
    }
    reservation = wait->reservation; wait->reservation = NULL;
    vcl = wait->vcl; wait->vcl = NULL;
    close(wait->fd[0]); close(wait->fd[1]);
    pthread_mutex_unlock(&lock);
    /* No continuation pointer is touched after the native engine can wake it. */
    HSH_Withdraw(worker,&reservation);
    free(wait);
    VCL_Rel(&vcl);
}

static struct objcore *delivery_held_reserve(VRT_CTX, const struct continuation *d) {
    struct req *r = Req_New(ctx->req->sp,ctx->req);
    struct worker *worker = ctx->req->wrk;
    struct objcore *object = NULL, *busy = NULL;
    struct VSHA256Context hash;
    enum lookup_e result;
    const char *parts[] = {"ultracache-private-v1",d->site,d->host,d->held_uri,d->held_key};
    size_t i;
    r->wrk = worker;
    r->vsl->wid = VXID_Get(worker,VSL_CLIENTMARKER);
    VSLb(r->vsl,SLT_Begin,"req %ju held-reservation",(uintmax_t)VXID(ctx->req->vsl->wid));
    VSLb(ctx->req->vsl,SLT_Link,"req %ju held-reservation",(uintmax_t)VXID(r->vsl->wid));
    HTTP_Setup(r->http,r->ws,r->vsl,SLT_ReqMethod);
    HTTP_Dup(r->http,ctx->http_req);
    r->t_req = VTIM_real(); r->d_ttl = -1; r->d_grace = -1; r->hash_ignore_busy = 1;
    VSHA256_Init(&hash);
    for (i = 0; i < sizeof(parts)/sizeof(parts[0]); ++i) {
        HSH_AddString(r,&hash,parts[i]); HSH_AddString(r,&hash,NULL);
    }
    VSHA256_Final(r->digest,&hash);
    VRY_Prep(r); result = HSH_Lookup(r,&object,&busy); VRY_Finish(r,DISCARD);
    if (object) (void)HSH_DerefObjCore(worker,&object);
    if (result != HSH_MISS && busy) HSH_Withdraw(worker,&busy);
    r->wrk = NULL; Req_Release(r);
    return result == HSH_MISS ? busy : NULL;
}

/* The entire plan/cut and arm operation share the native registry lock. */
static int delivery_held_schedule(VRT_CTX, struct continuation *d, struct reuse_scope *scope) {
    struct delivery_held_wait *wait;
    const struct delivery_reuse_pin *pin;
    double now = VTIM_real(), deadline = fmin(d->public_deadline,(double)d->reuse_record->valid_until);
    const char *deadline_source;
    int i;
    (void)scope;
    if (ctx->req->max_restarts > UINT_MAX-2 || ctx->req->restarts > UINT_MAX-2 ||
        !reuse_random_id(d->held_key)) return 0;
    snprintf(d->held_uri,sizeof(d->held_uri),"/__ultracache-native/held-v1/%s",d->held_key);
    deadline = fmin(deadline,d->held_metadata->t_origin+d->held_metadata->ttl);
    for (pin = d->reuse_plan->pins; pin; pin = pin->next) deadline = fmin(deadline,pin->deadline);
    deadline = fmin(deadline,ctx->req->t_prev+SESS_TMO(ctx->req->sp,send_timeout));
    deadline_source = deadline < now+UC_EXECUTION_OBSERVATION_BUDGET ? "natural" : "observation";
    deadline = fmin(deadline,now+UC_EXECUTION_OBSERVATION_BUDGET);
    if (!isfinite(deadline) || deadline <= now) return 0;
    wait = calloc(1,sizeof(*wait));
    if (!wait) return 0;
    if (socketpair(AF_UNIX,SOCK_STREAM,0,wait->fd)) { free(wait); return 0; }
    for (i = 0; i < 2; ++i) if (fcntl(wait->fd[i],F_SETFL,O_NONBLOCK) ||
        fcntl(wait->fd[i],F_SETFD,FD_CLOEXEC)) goto failed;
    wait->reservation = delivery_held_reserve(ctx,d);
    if (!wait->reservation) goto failed;
    wait->owner = d->association.key; wait->deadline = deadline; wait->request = ctx->req;
    wait->vcl = ctx->req->vcl; VCL_Ref(wait->vcl);
    wait->engine_waiter = ctx->req->sp->pool->waiter;
    INIT_OBJ(&wait->waited,WAITED_MAGIC);
    wait->waited.fd = wait->fd[0]; wait->waited.priv1 = wait;
    wait->waited.func = delivery_held_event; wait->waited.idle = now;
    wait->waited.tmo = deadline-now;
    d->held_wait = wait;
    if (Wait_Enter(wait->engine_waiter,&wait->waited)) {
        d->held_wait = NULL; VCL_Rel(&wait->vcl); goto failed;
    }
    /* Exactly two owner transitions; they preserve all previous headroom. */
    ctx->req->max_restarts += 2;
    d->held_restart = ctx->req->restarts+1; d->phase = D_HELD_QUEUED;
    VSLb(ctx->req->vsl,SLT_Debug,"uc-held cut=%ju parked deadline=%s",(uintmax_t)d->reuse_execution_cut,deadline_source);
    return 1;
failed:
    if (wait->reservation) HSH_Withdraw(ctx->req->wrk,&wait->reservation);
    close(wait->fd[0]); close(wait->fd[1]); free(wait); return 0;
}

static void delivery_held_pins_release(VRT_CTX, struct continuation *d) {
    if (d->held_parent) (void)HSH_DerefObjCore(ctx->req->wrk,&d->held_parent);
    if (d->held_metadata) (void)HSH_DerefObjCore(ctx->req->wrk,&d->held_metadata);
}
static void delivery_held_drop(VRT_CTX, struct continuation *d) {
    delivery_held_pins_release(ctx,d);
    delivery_reuse_release(ctx,d->reuse_plan); d->reuse_plan = NULL;
    delivery_reuse_record_free(d->reuse_record); d->reuse_record = NULL;
    delivery_free_fragments(d->fragments); d->fragments = NULL;
    d->reuse_fast = d->reuse_negotiated = d->reuse_cut_active = d->reuse_cut_provisional = 0;
    free(d->reuse_scope); d->reuse_scope = NULL; d->reuse_recipe[0] = 0;
}
static void delivery_held_fini(VRT_CTX, struct continuation *d) {
    pthread_mutex_lock(&lock);
    if (d->held_wait) {
        ssize_t ignored;
        d->held_wait->cancelled = 1;
        ignored = write(d->held_wait->fd[1],"x",1); (void)ignored;
        d->held_wait = NULL;
    }
    pthread_mutex_unlock(&lock);
    delivery_held_pins_release(ctx,d);
}
static int delivery_held_recv(VRT_CTX, struct continuation *d) {
    if (ctx->req->restarts != d->held_restart || d->failed) return -1;
    if (d->phase == D_HELD_QUEUED) {
        VRT_l_req_url(ctx,NULL,TOSTRAND(d->held_uri));
        http_ForceHeader(ctx->http_req,h_private_key,d->held_key);
        http_ForceHeader(ctx->http_req,h_key,d->request_id);
        VRT_l_req_hash_always_miss(ctx,0);
        d->phase = D_HELD_LOOKUP;
        return WS_Overflowed(ctx->ws) ? -1 : 3;
    }
    http_Unset(ctx->http_req,h_private_key);
    http_Unset(ctx->http_req,HDR("X-SCP-Key-URL"));
    if (!delivery_restore(ctx,d)) return -1;
    if (d->held_result == 3) {
        delivery_held_drop(ctx,d); d->failed = 1; return -1;
    }
    if (d->held_result != 1) {
        /* Actual expiry/failure is ordinary original prepare, never CLEAN. */
        delivery_held_drop(ctx,d);
        unsigned i;
        d->restart = ctx->req->restarts-1; d->phase = D_PREPARE;
        http_ForceHeader(ctx->http_req,h_key,d->request_id);
        http_Unset(ctx->http_req,H_Accept_Encoding);
        for (i = 0; i < 6; ++i) http_Unset(ctx->http_req,conditional_headers[i]);
        return WS_Overflowed(ctx->ws) ? -1 : 1;
    }
    d->restart = ctx->req->restarts; d->phase = D_HELD_RESUME;
    return 0;
}
VCL_INT vmod_delivery_held_miss(VRT_CTX, struct vmod_priv *priv) {
    struct continuation *d = priv->priv;
    if (!d || ctx->req->esi_level) return 0;
    if (d->phase == D_HELD_LOOKUP) {
        if (ctx->req->restarts != d->held_restart || !d->held_result ||
            strcmp(ctx->http_req->hd[HTTP_HDR_URL].b,d->held_uri)) return -1;
        d->held_restart++; d->phase = D_HELD_RETURN; return 1;
    }
    if (d->phase == D_HELD_RESUME) {
        delivery_held_drop(ctx,d); d->restart = ctx->req->restarts;
        d->phase = D_QUEUED; return 1;
    }
    return 0;
}
static int delivery_held_finish(VRT_CTX, struct vmod_priv *priv, struct continuation *d) {
    struct reuse_scope *scope;
    struct reuse_discovery *discovery;
    struct delivery_reuse_pin *pin;
    struct objcore *current;
    struct delivery_fragment metadata = {0};
    char uri[sizeof("/__ultracache-native/reuse-v1/")+64];
    int valid;
    (void)priv;
    snprintf(uri,sizeof(uri),"/__ultracache-native/reuse-v1/%s",d->reuse_metadata_key);
    metadata.url = uri; metadata.cache_key = d->reuse_metadata_key;
    pthread_mutex_lock(&lock);
    scope = delivery_reuse_current_scope(d);
    discovery = scope ? delivery_reuse_discovery(scope,d) : NULL;
    valid = ctx->req->objcore == d->held_parent && discovery &&
        !strcmp(discovery->revision,d->reuse_discovery_revision) &&
        delivery_reuse_record_current(d,d->reuse_record,scope,0) &&
        d->held_metadata->t_origin+d->held_metadata->ttl > VTIM_real();
    if (valid) {
        current = delivery_reuse_lookup(ctx,d,&metadata);
        valid = current && current == d->held_metadata;
        if (current) (void)HSH_DerefObjCore(ctx->req->wrk,&current);
    }
    for (pin = d->reuse_plan->pins; valid && pin; pin = pin->next) {
        current = delivery_reuse_lookup(ctx,d,pin->fragment);
        valid = current && current == pin->object && pin->deadline > VTIM_real();
        if (current) (void)HSH_DerefObjCore(ctx->req->wrk,&current);
    }
    pthread_mutex_unlock(&lock);
    if (valid) {
        delivery_held_pins_release(ctx,d); d->phase = D_DELIVERED; d->outcome = 1;
        VSLb(ctx->req->vsl,SLT_Debug,"uc-held cut=%ju cached",(uintmax_t)d->reuse_execution_cut);
        return 0;
    }
    delivery_held_drop(ctx,d); d->restart = ctx->req->restarts; d->phase = D_QUEUED;
    return 1;
}
#else
static void delivery_held_notify(struct reuse_scope *s) { (void)s; }
static void delivery_held_fini(VRT_CTX, struct continuation *d) { (void)ctx; (void)d; }
static int delivery_held_recv(VRT_CTX, struct continuation *d) { (void)ctx; (void)d; return -1; }
static int delivery_held_finish(VRT_CTX, struct vmod_priv *p, struct continuation *d) { (void)ctx; (void)p; (void)d; return -1; }
VCL_INT vmod_delivery_held_miss(VRT_CTX, struct vmod_priv *p) { (void)ctx; (void)p; return 0; }
VCL_INT vmod_delivery_held_waiters(VRT_CTX) { (void)ctx; return 0; }
#endif
