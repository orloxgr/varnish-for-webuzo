/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include "cache/cache.h"
#include "vcc_if.h"

/* No global cookie cache: each entry is owned and freed by one client task.
 * Backend access is synchronized with delivery and abort finalization. */
struct fields { struct fields *next; char *line; };
struct handoff {
    struct handoff *next;
    uint64_t key;
    struct fields *fields;
    char csrf[33];
};
struct task { struct handoff *owner; uint64_t key; char token_reason[80]; };
struct csrf_top { char token[33]; };
#define BUCKETS 1024
static struct handoff *buckets[BUCKETS];
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t serial;
static unsigned live;
#include "joomla_forms.h"

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

VCL_VOID vmod_reset(VRT_CTX, struct vmod_priv *priv, struct vmod_priv *top_priv) {
    if (ctx->req && ctx->req->esi_level == 0 && top_priv->priv)
        memset(top_priv->priv, 0, sizeof(struct csrf_top));
    if (priv->priv) { close_owner(priv->priv); free(priv->priv); priv->priv = NULL; }
}

static void discard_key(uint64_t key) {
    struct handoff *entry;
    if (!key) return;
    pthread_mutex_lock(&lock);
    entry = buckets[key % BUCKETS];
    while (entry && entry->key != key) entry = entry->next;
    if (entry) { clear_fields(entry->fields); entry->fields = NULL; entry->csrf[0] = '\0'; }
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
        task->owner->csrf[0] = '\0';
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

static double resolver_now(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value)) return 0;
    return value.tv_sec + value.tv_nsec / 1e9;
}

static int resolver_ready(int fd, short events, double deadline) {
    struct pollfd descriptor = { .fd = fd, .events = events };
    for (;;) {
        double left = deadline - resolver_now();
        if (left <= 0) return 0;
        int milliseconds = left * 1000 >= INT_MAX ? INT_MAX : (int)(left * 1000) + 1;
        int result = poll(&descriptor, 1, milliseconds);
        if (result < 0 && errno == EINTR) continue;
        return result > 0 && (descriptor.revents & events);
    }
}

static char *resolver_json_string(char *out, const char *input) {
    static const char hex[] = "0123456789abcdef";
    const unsigned char *p = (const unsigned char *)(input ? input : "");
    *out++ = '"';
    while (*p) {
        unsigned char c = *p++;
        if (c == '"' || c == '\\') { *out++ = '\\'; *out++ = c; }
        else if (c < 32 || c >= 127) {
            memcpy(out, "\\u00", 4); out += 4;
            *out++ = hex[c >> 4]; *out++ = hex[c & 15];
        } else *out++ = c;
    }
    *out++ = '"';
    return out;
}

VCL_STRING vmod_session_state(VRT_CTX, VCL_STRING socket_path, VCL_STRING site,
                             VCL_STRING path, VCL_STRING cookie, VCL_DURATION timeout) {
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    struct ucred peer;
    socklen_t peer_length = sizeof(peer);
    char response[256], *message = NULL;
    const char *result = "unresolved\tcms-session-unavailable";
    int fd = -1, complete = 0;
    size_t used = 0;
    if (!socket_path || socket_path[0] != '/' || strlen(socket_path) >= sizeof(address.sun_path) ||
        !site || strlen(site) != 32 || strspn(site, "0123456789abcdef") != 32 ||
        !isfinite(timeout) || timeout <= 0) goto done;
    size_t lengths = strlen(site);
    if (path && strlen(path) > SIZE_MAX - lengths) goto done;
    lengths += path ? strlen(path) : 0;
    if (cookie && strlen(cookie) > SIZE_MAX - lengths) goto done;
    lengths += cookie ? strlen(cookie) : 0;
    if (lengths > (SIZE_MAX - 128) / 6) goto done;
    message = malloc(lengths * 6 + 128);
    if (!message) goto done;
    char *out = message;
    memcpy(out, "{\"schema\":1,\"site\":", 19); out += 19;
    out = resolver_json_string(out, site);
    memcpy(out, ",\"path\":", 8); out += 8;
    out = resolver_json_string(out, path);
    memcpy(out, ",\"cookie\":", 10); out += 10;
    out = resolver_json_string(out, cookie);
    *out++ = '}'; *out++ = '\n';
    size_t length = (size_t)(out - message);
    double deadline = resolver_now() + timeout;
    memcpy(address.sun_path, socket_path, strlen(socket_path) + 1);
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) goto done;
    if (connect(fd, (struct sockaddr *)&address, sizeof(address))) {
        if (errno != EINPROGRESS || !resolver_ready(fd, POLLOUT, deadline)) goto done;
        int error = 0; socklen_t error_length = sizeof(error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_length) || error) goto done;
    }
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &peer_length) || peer.uid != 0) {
        result = "unresolved\tcms-session-peer"; goto done;
    }
    while (used < length) {
        if (!resolver_ready(fd, POLLOUT, deadline)) goto done;
        ssize_t count = send(fd, message + used, length - used, MSG_NOSIGNAL);
        if (count < 0 && (errno == EAGAIN || errno == EINTR)) continue;
        if (count <= 0) goto done;
        used += (size_t)count;
    }
    used = 0;
    while (used + 1 < sizeof(response)) {
        if (!resolver_ready(fd, POLLIN, deadline)) goto done;
        ssize_t count = recv(fd, response + used, 1, 0);
        if (count < 0 && (errno == EAGAIN || errno == EINTR)) continue;
        if (count != 1) goto done;
        if (response[used] == '\n') { complete = 1; break; }
        ++used;
    }
    response[used] = '\0';
    const char *reason = strchr(response, '\t');
    if (!complete || !reason || !reason[1] ||
        (strncmp(response, "guest\t", 6) && strncmp(response, "private\t", 8) && strncmp(response, "unresolved\t", 11))) {
        result = "unresolved\tcms-session-protocol"; goto done;
    }
    for (const char *p = reason + 1; *p; ++p) {
        if (!(*p >= 'a' && *p <= 'z') && !(*p >= '0' && *p <= '9') && *p != '-') {
            result = "unresolved\tcms-session-protocol"; goto done;
        }
    }
    result = response;
done:
    if (fd >= 0) close(fd);
    free(message);
    return WS_Copy(ctx->ws, result, -1);
}

static void csrf_top_fini(VRT_CTX, void *value) { (void)ctx; free(value); }
static const struct vmod_priv_methods csrf_top_methods = {
    .magic = VMOD_PRIV_METHODS_MAGIC, .type = "request-csrf-token", .fini = csrf_top_fini
};
static struct csrf_top *csrf_top_get(struct vmod_priv *priv) {
    if (!priv->priv) {
        priv->priv = calloc(1, sizeof(struct csrf_top));
        if (priv->priv) priv->methods = &csrf_top_methods;
    }
    return priv->priv;
}
VCL_BOOL vmod_prepare_token(VRT_CTX, struct vmod_priv *priv, struct vmod_priv *top_priv) {
    struct csrf_top *top = csrf_top_get(top_priv);
    struct task *task = priv->priv;
    (void)ctx;
    if (!top) return 0;
    if (top->token[0]) return 1;
    if (!task || !task->owner) return 0;
    pthread_mutex_lock(&lock);
    memcpy(top->token, task->owner->csrf, sizeof(top->token));
    pthread_mutex_unlock(&lock);
    return top->token[0] != '\0';
}
VCL_STRING vmod_csrf_token(VRT_CTX, struct vmod_priv *top_priv) {
    struct csrf_top *top = top_priv->priv;
    return top && top->token[0] ? WS_Copy(ctx->ws, top->token, -1) : NULL;
}
VCL_STRING vmod_token_reason(VRT_CTX, struct vmod_priv *priv) {
    struct task *task = priv->priv;
    return WS_Copy(ctx->ws, task && task->token_reason[0] ? task->token_reason : "joomla-token-unavailable", -1);
}

/* A single private response frame. The real root peer is trusted, and reply
 * storage grows to its actual fields rather than truncating cookies. */
static char *token_exchange(const char *socket_path, const char *site, const char *path,
                            const char *cookie, const char *host, const char *scheme,
                            const char *agent, const char *client_ip, const char *language, double timeout) {
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    struct ucred peer; socklen_t peer_length = sizeof(peer);
    const char *names[] = {"site", "path", "cookie", "host", "scheme", "user_agent", "client_ip", "accept_language"};
    const char *values[] = {site, path, cookie, host, scheme, agent, client_ip, language};
    char *message = NULL, *reply = NULL;
    int fd = -1, success = 0;
    if (!socket_path || socket_path[0] != '/' || strlen(socket_path) >= sizeof(address.sun_path) ||
        !site || strlen(site) != 32 || strspn(site, "0123456789abcdef") != 32 || !isfinite(timeout) || timeout <= 0) return NULL;
    size_t size = 512;
    for (unsigned i = 0; i < sizeof(values)/sizeof(*values); ++i) {
        size_t length = values[i] ? strlen(values[i]) : 0;
        if (length > (SIZE_MAX - size) / 6) goto done;
        size += length * 6;
    }
    message = malloc(size);
    if (!message) goto done;
    char *out = message;
    const char *prefix = "{\"schema\":1,\"op\":\"token\"";
    memcpy(out, prefix, strlen(prefix)); out += strlen(prefix);
    for (unsigned i = 0; i < sizeof(values)/sizeof(*values); ++i) {
        *out++ = ','; out = resolver_json_string(out, names[i]); *out++ = ':';
        out = resolver_json_string(out, values[i]);
    }
    *out++ = '}'; *out++ = '\n';
    size_t length = (size_t)(out - message), used = 0;
    double deadline = resolver_now() + timeout;
    memcpy(address.sun_path, socket_path, strlen(socket_path) + 1);
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) goto done;
    if (connect(fd, (struct sockaddr *)&address, sizeof(address))) {
        if (errno != EINPROGRESS || !resolver_ready(fd, POLLOUT, deadline)) goto done;
        int error = 0; socklen_t n = sizeof(error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &n) || error) goto done;
    }
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &peer_length) || peer.uid != 0) goto done;
    while (used < length) {
        if (!resolver_ready(fd, POLLOUT, deadline)) goto done;
        ssize_t n = send(fd, message + used, length - used, MSG_NOSIGNAL);
        if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (n <= 0) goto done;
        used += (size_t)n;
    }
    size = 1024; used = 0; reply = malloc(size);
    if (!reply) goto done;
    for (;;) {
        if (used + 1 == size) {
            if (size > SIZE_MAX / 2) goto done;
            char *next = realloc(reply, size * 2);
            if (!next) goto done;
            reply = next; size *= 2;
        }
        if (!resolver_ready(fd, POLLIN, deadline)) goto done;
        ssize_t n = recv(fd, reply + used, size - used - 1, 0);
        if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (n <= 0) goto done;
        char *end = memchr(reply + used, '\n', (size_t)n);
        if (end) { *end = '\0'; success = 1; break; }
        used += (size_t)n;
    }
done:
    if (fd >= 0) close(fd);
    free(message);
    if (!success) { free(reply); return NULL; }
    return reply;
}
static int csrf_b64(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}
static struct fields *csrf_cookie_fields(const char *encoded, int *valid) {
    size_t length = strlen(encoded), count = 0;
    struct fields *first = NULL, **tail = &first;
    *valid = 0;
    if (length % 4) return NULL;
    char *data = malloc(length / 4 * 3 + 1);
    if (!data) return NULL;
    for (size_t i = 0; i < length; i += 4) {
        int a = csrf_b64(encoded[i]), b = csrf_b64(encoded[i+1]);
        int c = encoded[i+2] == '=' ? 0 : csrf_b64(encoded[i+2]);
        int d = encoded[i+3] == '=' ? 0 : csrf_b64(encoded[i+3]);
        if (a < 0 || b < 0 || c < 0 || d < 0 ||
            ((encoded[i+2] == '=' || encoded[i+3] == '=') && i + 4 != length) ||
            (encoded[i+2] == '=' && encoded[i+3] != '=')) goto done;
        data[count++] = (char)((a << 2) | (b >> 4));
        if (encoded[i+2] != '=') data[count++] = (char)((b << 4) | (c >> 2));
        if (encoded[i+3] != '=') data[count++] = (char)((c << 6) | d);
    }
    if (memchr(data, '\0', count) || memchr(data, '\r', count)) goto done;
    data[count] = '\0';
    char *p = data;
    while (*p) {
        char *end = strchr(p, '\n');
        if (end) *end = '\0';
        if (strncasecmp(p, "Set-Cookie:", 11) || !strchr(p + 11, '=')) goto done;
        struct fields *field = calloc(1, sizeof(*field));
        if (!field) goto done;
        field->line = strdup(p);
        if (!field->line) { free(field); goto done; }
        *tail = field; tail = &field->next;
        if (!end) break;
        p = end + 1;
    }
    *valid = 1;
done:
    free(data);
    if (!*valid) { clear_fields(first); return NULL; }
    return first;
}
VCL_BOOL vmod_ensure_token(VRT_CTX, struct vmod_priv *priv, struct vmod_priv *top_priv,
                           VCL_STRING socket_path, VCL_STRING site, VCL_STRING path,
                           VCL_STRING cookie, VCL_STRING host, VCL_STRING scheme,
                           VCL_STRING agent, VCL_STRING client_ip, VCL_STRING language, VCL_DURATION timeout) {
    if (vmod_prepare_token(ctx, priv, top_priv)) return 1;
    struct task *task = get_task(priv);
    if (!task) return 0;
    strcpy(task->token_reason, "joomla-token-unavailable");
    char *reply = token_exchange(socket_path, site, path, cookie, host, scheme, agent, client_ip, language, timeout);
    if (!reply) return 0;
    if (strncmp(reply, "token\t", 6) || strlen(reply) < 39 || reply[38] != '\t' ||
        !jf_hex((struct joomla_span){(const unsigned char *)reply + 6, 32})) {
        const char *reason = strchr(reply, '\t');
        if (reason && (!strncmp(reply,"private\t",8) || !strncmp(reply,"unresolved\t",11)) &&
            reason[1] && strlen(reason+1)<sizeof(task->token_reason) &&
            strspn(reason+1,"abcdefghijklmnopqrstuvwxyz0123456789-")==strlen(reason+1)) strcpy(task->token_reason,reason+1);
        free(reply); return 0;
    }
    int valid;
    struct fields *fields = csrf_cookie_fields(reply + 39, &valid);
    if (!valid) { free(reply); return 0; }
    if (!task->owner && !vmod_open(ctx, priv)) { clear_fields(fields); free(reply); return 0; }
    struct csrf_top *top = csrf_top_get(top_priv);
    if (!top) { clear_fields(fields); free(reply); return 0; }
    memcpy(top->token, reply + 6, 32); top->token[32] = '\0';
    pthread_mutex_lock(&lock);
    memcpy(task->owner->csrf, top->token, sizeof(top->token));
    struct fields **tail = &task->owner->fields;
    while (*tail) tail = &(*tail)->next;
    *tail = fields;
    pthread_mutex_unlock(&lock);
    free(reply);
    return 1;
}
