/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "config.h"
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
/* The request-owned virtual fetch needs the exact installed http_conn layout.
 * This is an explicit strict-ABI internal-header dependency, not bundled ABI. */
#include "cache/cache_int.h"
#include "vcc_if.h"

/* No global cookie cache: each entry is owned and freed by one client task.
 * Backend access is synchronized with delivery and abort finalization. */
struct fields { struct fields *next; char *line; };
struct continuation;
struct handoff {
    struct handoff *next;
    uint64_t key;
    struct fields *fields;
    struct continuation *delivery; /* PRIV_TOP-owned; only accessed under lock. */
};
struct task { struct handoff *owner; uint64_t key; };
#define BUCKETS 1024
static struct handoff *buckets[BUCKETS];
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t serial;
static unsigned live;

static void clear_fields(struct fields *p) {
    while (p) { struct fields *next = p->next; free(p->line); free(p); p = next; }
}

static void close_owner(struct task *task) {
    if (task->owner) {
        struct handoff **p;
        pthread_mutex_lock(&lock);
        p = &buckets[task->key % BUCKETS];
        while (*p && *p != task->owner) p = &(*p)->next;
        if (*p) { *p = task->owner->next; --live; }
        clear_fields(task->owner->fields);
        free(task->owner);
        task->owner = NULL; task->key = 0;
        pthread_mutex_unlock(&lock);
    }
}

static void task_fini(VRT_CTX, void *value) {
    struct task *task = value;
    (void)ctx;
    close_owner(task); free(task);
}

static const struct vmod_priv_methods methods = {
    .magic = VMOD_PRIV_METHODS_MAGIC,
    .type = "cookie-handoff-task",
    .fini = task_fini,
};

static struct task *get_task(struct vmod_priv *priv) {
    if (!priv->priv) {
        priv->priv = calloc(1, sizeof(struct task));
        if (priv->priv) priv->methods = &methods;
    }
    return priv->priv;
}

VCL_VOID vmod_reset(VRT_CTX, struct vmod_priv *priv) {
    (void)ctx;
    if (priv->priv) { close_owner(priv->priv); free(priv->priv); priv->priv = NULL; }
}

static void discard_key(uint64_t key) {
    struct handoff *entry;
    if (!key) return;
    pthread_mutex_lock(&lock);
    entry = buckets[key % BUCKETS];
    while (entry && entry->key != key) entry = entry->next;
    if (entry) { clear_fields(entry->fields); entry->fields = NULL; }
    pthread_mutex_unlock(&lock);
}

VCL_VOID vmod_discard(VRT_CTX, struct vmod_priv *priv) {
    struct task *task = priv->priv;
    (void)ctx;
    if (task) discard_key(task->key);
}

VCL_STRING vmod_open(VRT_CTX, struct vmod_priv *priv) {
    struct task *task = get_task(priv);
    const char *key;
    if (!task) { VRT_fail(ctx, "Cookie handoff allocation failed"); return NULL; }
    if (!task->owner) {
        struct handoff *entry = calloc(1, sizeof(*entry));
        if (!entry) { VRT_fail(ctx, "Cookie handoff allocation failed"); return NULL; }
        pthread_mutex_lock(&lock);
        if (serial == UINT64_MAX) {
            pthread_mutex_unlock(&lock); free(entry);
            VRT_fail(ctx, "Cookie handoff identity exhausted"); return NULL;
        }
        entry->key = ++serial;
        entry->next = buckets[entry->key % BUCKETS];
        buckets[entry->key % BUCKETS] = entry;
        ++live;
        task->key = entry->key; task->owner = entry;
        pthread_mutex_unlock(&lock);
    } else {
        pthread_mutex_lock(&lock);
        clear_fields(task->owner->fields); task->owner->fields = NULL;
        pthread_mutex_unlock(&lock);
    }
    key = WS_Printf(ctx->ws, "%" PRIu64, task->key);
    if (!key) VRT_fail(ctx, "Cookie handoff workspace exhausted");
    return key;
}

VCL_VOID vmod_bind(VRT_CTX, struct vmod_priv *priv, VCL_STRING key) {
    struct task *task = get_task(priv);
    char *end;
    (void)ctx;
    if (!task) { VRT_fail(ctx, "Cookie handoff allocation failed"); return; }
    // A retry retains its backend task after the internal header was stripped.
    // Clear any response from its previous attempt before starting another.
    discard_key(task->key);
    if (!key || !*key) return;
    task->key = 0;
    errno = 0;
    uint64_t parsed = strtoull(key, &end, 10);
    if (!errno && !*end) task->key = parsed;
}

/* First matching rule wins, exactly as in cookie_admin.active(). Never parse
 * cookies by splitting on comma: Expires and extension attributes may use it. */
static int shared_name(const char *rules, const char *name, size_t len) {
    const char *p = rules;
    if (!p) return 0;
    while (*p) {
        const char *end = strchr(p, '\n');
        const char *action = strchr(p, '\t');
        const char *kind = action ? strchr(action + 1, '\t') : NULL;
        if (!end) end = p + strlen(p);
        if (!action || !kind || action >= end || kind >= end) return 0;
        size_t n = (size_t)(end - kind - 1);
        int prefix = kind - action == 7 && !memcmp(action + 1, "prefix", 6);
        int exact = kind - action == 6 && !memcmp(action + 1, "exact", 5);
        if (((exact && n == len) || (prefix && n <= len)) && !memcmp(kind + 1, name, n))
            return action - p == 6 && !memcmp(p, "shared", 6);
        p = *end ? end + 1 : end;
    }
    return 0;
}

VCL_BOOL vmod_detach(VRT_CTX, struct vmod_priv *priv, VCL_STRING rules, VCL_BOOL background) {
    struct task *task = priv->priv;
    struct fields *first = NULL, **tail = &first;
    unsigned i;
    int seen = 0;
    for (i = HTTP_HDR_FIRST; i < ctx->http_beresp->nhd; ++i) {
        const char *line = ctx->http_beresp->hd[i].b;
        if (!ctx->http_beresp->hd[i].b || !http_IsHdr(&ctx->http_beresp->hd[i], H_Set_Cookie)) continue;
        seen = 1;
        const char *name = strchr(line, ':') + 1;
        while (*name == ' ' || *name == '\t') ++name;
        const char *eq = strchr(name, '=');
        if (!eq || !shared_name(rules, name, (size_t)(eq - name))) goto retained;
        if (!background) {
            struct fields *field = calloc(1, sizeof(*field));
            if (!field) goto retained;
            field->line = strdup(line);
            if (!field->line) { free(field); goto retained; }
            *tail = field; tail = &field->next;
        }
    }
    if (!seen) return 0;
    if (!background) {
        struct handoff *entry;
        if (!task || !task->key) goto retained;
        pthread_mutex_lock(&lock);
        entry = buckets[task->key % BUCKETS];
        while (entry && entry->key != task->key) entry = entry->next;
        if (!entry) { pthread_mutex_unlock(&lock); goto retained; }
        clear_fields(entry->fields); entry->fields = first; first = NULL;
        pthread_mutex_unlock(&lock);
    }
    http_Unset(ctx->http_beresp, H_Set_Cookie);
    return 1;
retained:
    clear_fields(first);
    return 0;
}

VCL_VOID vmod_deliver(VRT_CTX, struct vmod_priv *priv) {
    struct task *task = priv->priv;
    struct fields *fields, *field;
    if (!task || !task->owner) return;
    pthread_mutex_lock(&lock);
    fields = task->owner->fields; task->owner->fields = NULL;
    pthread_mutex_unlock(&lock);
    for (field = fields; field; field = field->next) {
        const char *line = WS_Copy(ctx->ws, field->line, -1);
        if (!line || ctx->http_resp->nhd >= ctx->http_resp->shd) {
            VRT_fail(ctx, "Cookie handoff response workspace exhausted"); break;
        }
        http_SetHeader(ctx->http_resp, line);
    }
    clear_fields(fields);
}

VCL_INT vmod_pending(VRT_CTX) {
    unsigned count;
    (void)ctx;
    pthread_mutex_lock(&lock); count = live; pthread_mutex_unlock(&lock);
    return count;
}

/* Shares the association table/field ownership, without changing MISS reset. */
#include "delivery_continuation.c"
