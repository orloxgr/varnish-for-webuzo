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
#include "delivery_mutation_wire.h"

/* No global cookie cache: each entry is owned and freed by one client task.
 * Backend access is synchronized with delivery and abort finalization. */
struct fields { struct fields *next; char *line; };
struct continuation;
struct mutation_execution;
struct handoff {
    struct handoff *next;
    uint64_t key;
    struct fields *fields;
    struct continuation *delivery; /* PRIV_TOP-owned; only accessed under lock. */
};
struct task {
    struct handoff *owner; uint64_t key;
    char *control_body; size_t control_length;
    char *cookie_variant, *cookie_variant_names; size_t cookie_variant_length;
    struct mutation_execution *mutation;
};
static void mutation_task_fini(VRT_CTX, struct task *);
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
    mutation_task_fini(ctx,task);
    close_owner(task); free(task->control_body); free(task->cookie_variant); free(task->cookie_variant_names); free(task);
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
    if (priv->priv) {
        struct task *task = priv->priv;
        mutation_task_fini(ctx,task);
        close_owner(task); free(task->control_body); free(task->cookie_variant); free(task->cookie_variant_names); free(task); priv->priv = NULL;
    }
}

static char *cookie_normalized_copy(const char *value) {
    const char *first = value, *last = value+strlen(value), *p;
    size_t length = (size_t)(last-value), used = 0;
    char *normalized;
    if (length > (SIZE_MAX-1)/2) return NULL;
    while (first < last && (*first == ';' || *first == ' ' || *first == '\t')) ++first;
    while (last > first && (last[-1] == ';' || last[-1] == ' ' || last[-1] == '\t')) --last;
    normalized = malloc(length*2+1);
    if (!normalized) return NULL;
    for (p = first; p < last;) {
        char ch = *p++;
        normalized[used++] = ch;
        if (ch == ';') {
            normalized[used++] = ' ';
            while (p < last && (*p == ' ' || *p == '\t')) ++p;
        }
    }
    normalized[used] = '\0';
    return normalized;
}

static char *cookie_names_copy(const char *value) {
    size_t length = strlen(value);
    const char *p;
    char *names, *out;
    if (length > (SIZE_MAX-1)/2) return NULL;
    names = malloc(length*2+1);
    if (!names) return NULL;
    out = names;
    for (p = value; *p;) {
        if (*p == '=') { while (*p && *p != ';') ++p; }
        else if (*p == ';') {
            *out++ = ','; *out++ = ' '; ++p;
            while (*p == ' ' || *p == '\t') ++p;
        } else { *out++ = *p++; }
    }
    *out = '\0';
    return names;
}

VCL_STRING vmod_cookie_diagnostic_names(VRT_CTX, VCL_STRING value, VCL_BOOL allowed) {
    char *names;
    const char *result;
    if (!allowed || !value || !*value) return NULL;
    names = cookie_names_copy(value);
    if (!names) { VRT_fail(ctx,"Cookie diagnostic name allocation failed"); return NULL; }
    result = WS_Copy(ctx->ws,names,-1);
    free(names);
    if (!result) VRT_fail(ctx,"Cookie diagnostic name workspace exhausted");
    return result;
}

/* Keep the exact ordered Variant bytes on the owning task until classification
 * finishes. Repeated VCL header concatenation permanently spends request
 * workspace on each intermediate copy, even after that header is replaced.
 * This common path needs no private cache-engine interfaces. */
VCL_VOID vmod_cookie_variant_begin(VRT_CTX, struct vmod_priv *priv) {
    struct task *task = priv->priv;
    (void)ctx;
    if (!task) return;
    free(task->cookie_variant); task->cookie_variant = NULL;
    free(task->cookie_variant_names); task->cookie_variant_names = NULL;
    task->cookie_variant_length = 0;
}

VCL_VOID vmod_cookie_variant_append(VRT_CTX, struct vmod_priv *priv, VCL_STRING value) {
    struct task *task;
    size_t length, separator, total;
    char *grown, *normalized, *names;
    if (!value || !*value) return;
    task = get_task(priv);
    if (!task) { VRT_fail(ctx,"Cookie variant allocation failed"); return; }
    normalized = cookie_normalized_copy(value);
    if (!normalized) { VRT_fail(ctx,"Cookie variant normalization failed"); return; }
    length = strlen(normalized); separator = task->cookie_variant_length ? 2 : 0;
    if (!length) { free(normalized); return; }
    if (task->cookie_variant_length > SIZE_MAX-separator-1 ||
        length > SIZE_MAX-task->cookie_variant_length-separator-1) {
        free(normalized); VRT_fail(ctx,"Cookie variant size overflow"); return;
    }
    names = cookie_names_copy(normalized);
    if (!names) { free(normalized); VRT_fail(ctx,"Cookie name allocation failed"); return; }
    total = task->cookie_variant_length+separator+length;
    grown = realloc(task->cookie_variant,total+1);
    if (!grown) { free(names); free(normalized); VRT_fail(ctx,"Cookie variant allocation failed"); return; }
    task->cookie_variant = grown;
    if (separator) memcpy(grown+task->cookie_variant_length,"; ",2);
    memcpy(grown+task->cookie_variant_length+separator,normalized,length+1);
    free(normalized);
    free(task->cookie_variant_names); task->cookie_variant_names = names;
    task->cookie_variant_length = total;
}

VCL_STRING vmod_cookie_variant_names(VRT_CTX, struct vmod_priv *priv) {
    const struct task *task = priv->priv;
    const char *names;
    if (!task || !task->cookie_variant_names) return NULL;
    names = WS_Copy(ctx->ws,task->cookie_variant_names,-1);
    if (!names) VRT_fail(ctx,"Cookie name workspace exhausted");
    return names;
}

VCL_VOID vmod_cookie_variant_finish(VRT_CTX, struct vmod_priv *priv) {
    struct task *task = priv->priv;
    const hdr_t name = HDR("X-SCP-Admin-Variant");
    http_Unset(ctx->http_req,name);
    if (!task || !task->cookie_variant_length) return;
    if (ctx->http_req->nhd >= ctx->http_req->shd) {
        VRT_fail(ctx,"Cookie variant header slots exhausted"); return;
    }
    http_ForceHeader(ctx->http_req,name,task->cookie_variant);
    if (WS_Overflowed(ctx->ws)) VRT_fail(ctx,"Cookie variant workspace exhausted");
    free(task->cookie_variant); task->cookie_variant = NULL;
    task->cookie_variant_length = 0;
}

/* Byte-equivalent to the compiler's delimiter normalization, at the same rule
 * boundary. Keep temporary whole-cookie copies off the finite request WS. */
static void cookie_working_header_normalize(VRT_CTX, hdr_t name) {
    const char *value = NULL;
    char *normalized;
    size_t used;
    if (!http_GetHdr(ctx->http_req,name,&value)) return;
    normalized = cookie_normalized_copy(value);
    if (!normalized) { VRT_fail(ctx,"Cookie working-header normalization failed"); return; }
    used = strlen(normalized);
    if (!strcmp(value,normalized) && used) { free(normalized); return; }
    http_Unset(ctx->http_req,name);
    if (used) http_ForceHeader(ctx->http_req,name,normalized);
    free(normalized);
    if (WS_Overflowed(ctx->ws)) VRT_fail(ctx,"Cookie remainder workspace exhausted");
}

VCL_VOID vmod_cookie_remainder_normalize(VRT_CTX) {
    cookie_working_header_normalize(ctx,HDR("X-SCP-Admin-Remaining"));
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
    if (task) { mutation_task_fini(ctx,task); discard_key(task->key); }
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
    mutation_task_fini(ctx,task);
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
