/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Inspect Joomla tokens before object allocation. Public JSON token values
 * become private ESI fields; actual session forms remain origin responses. */
#include "cache/cache_filter.h"
#include "vrt_obj.h"

struct joomla_span { const unsigned char *p; size_t n; };
struct joomla_body { unsigned char *data; size_t length, capacity, offset; uint64_t owner; };
static hdr_t const jf_reason_header = HDR("X-SCP-Reason");
static hdr_t const jf_owner_header = HDR("X-SCP-Form-Owner");
static const char jf_include[] = "<esi:include src=\"/.__varnish_cms_token/v1\"/>";

static int jf_space(unsigned char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f';
}
static unsigned char jf_lower(unsigned char c) {
    return c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c;
}
static int jf_equal(struct joomla_span value, const char *text) {
    size_t n = strlen(text);
    if (value.n != n) return 0;
    for (size_t i = 0; i < n; ++i) if (jf_lower(value.p[i]) != (unsigned char)text[i]) return 0;
    return 1;
}
static int jf_hex(struct joomla_span value) {
    if (value.n != 32) return 0;
    for (size_t i = 0; i < value.n; ++i) {
        unsigned char c = jf_lower(value.p[i]);
        if (!(c >= 'a' && c <= 'f') && !(c >= '0' && c <= '9')) return 0;
    }
    return 1;
}
static const unsigned char *jf_find(const unsigned char *p, const unsigned char *end, const char *text) {
    size_t n = strlen(text);
    while ((size_t)(end - p) >= n) {
        if (jf_equal((struct joomla_span){p, n}, text)) return p;
        ++p;
    }
    return NULL;
}
static struct joomla_span jf_attribute(const unsigned char *p, const unsigned char *end, const char *name) {
    while (p < end) {
        while (p < end && (jf_space(*p) || *p == '/')) ++p;
        const unsigned char *start = p;
        while (p < end && !jf_space(*p) && *p != '=' && *p != '/') ++p;
        struct joomla_span key = {start, (size_t)(p - start)};
        while (p < end && jf_space(*p)) ++p;
        struct joomla_span value = {NULL, 0};
        if (p < end && *p == '=') {
            ++p; while (p < end && jf_space(*p)) ++p;
            unsigned char quote = p < end && (*p == '"' || *p == '\'') ? *p++ : 0;
            start = p;
            while (p < end && (quote ? *p != quote : !jf_space(*p))) ++p;
            value = (struct joomla_span){start, (size_t)(p - start)};
            if (quote && p < end) ++p;
        }
        if (jf_equal(key, name)) return value;
        if (p == start && p < end) ++p;
    }
    return (struct joomla_span){NULL, 0};
}
static const unsigned char *jf_json_token(const unsigned char *p, const unsigned char *end) {
    while ((p = jf_find(p, end, "\"csrf.token\"")) != NULL) {
        p += strlen("\"csrf.token\"");
        while (p < end && jf_space(*p)) ++p;
        if (p == end || *p++ != ':') continue;
        while (p < end && jf_space(*p)) ++p;
        if (p < end && *p++ == '"' && end - p >= 33 && p[32] == '"' && jf_hex((struct joomla_span){p, 32})) return p;
    }
    return NULL;
}
static int jf_private_html(const unsigned char *p, size_t length) {
    const unsigned char *end = p + length;
    int form = 0;
    while (p < end) {
        if (*p++ != '<') continue;
        if (end - p >= 3 && !memcmp(p, "!--", 3)) {
            const unsigned char *finish = jf_find(p + 3, end, "-->");
            p = finish ? finish + 3 : end; continue;
        }
        int closing = p < end && *p == '/';
        if (closing) ++p;
        const unsigned char *start = p;
        while (p < end && ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9'))) ++p;
        struct joomla_span tag = {start, (size_t)(p - start)};
        const unsigned char *attributes = p;
        unsigned char quote = 0;
        while (p < end) {
            unsigned char c = *p;
            if (quote) { if (c == quote) quote = 0; }
            else if (c == '"' || c == '\'') quote = c;
            else if (c == '>') break;
            ++p;
        }
        const unsigned char *finish = p;
        if (p < end) ++p;
        if (jf_equal(tag, "form")) { form = !closing; continue; }
        if (!closing && jf_equal(tag, "input") && (form || jf_attribute(attributes, finish, "form").n) &&
            jf_equal(jf_attribute(attributes, finish, "type"), "hidden") &&
            jf_equal(jf_attribute(attributes, finish, "value"), "1") && jf_hex(jf_attribute(attributes, finish, "name"))) return 1;
        if (!closing && (jf_equal(tag, "script") || jf_equal(tag, "style") || jf_equal(tag, "textarea") || jf_equal(tag, "title"))) {
            const char *ending = jf_equal(tag,"script") ? "</script" : jf_equal(tag,"style") ? "</style" : jf_equal(tag,"textarea") ? "</textarea" : "</title";
            const unsigned char *stop = jf_find(p, end, ending);
            if (!stop) stop = end;
            p = stop;
        }
    }
    return 0;
}

static int jf_public_token(struct joomla_body *body) {
    const unsigned char *p = body->data, *end = p + body->length;
    size_t *slots = NULL, count = 0;
    char token[33] = {0};
    while (p < end) {
        if (*p++ != '<') continue;
        if (end - p >= 3 && !memcmp(p, "!--", 3)) {
            const unsigned char *finish = jf_find(p + 3, end, "-->");
            p = finish ? finish + 3 : end; continue;
        }
        int closing = p < end && *p == '/';
        if (closing) ++p;
        const unsigned char *start = p;
        while (p < end && ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9'))) ++p;
        struct joomla_span tag = {start, (size_t)(p - start)};
        const unsigned char *attributes = p;
        unsigned char quote = 0;
        while (p < end) {
            if (quote) { if (*p == quote) quote = 0; }
            else if (*p == '"' || *p == '\'') quote = *p;
            else if (*p == '>') break;
            ++p;
        }
        const unsigned char *finish = p;
        if (p < end) ++p;
        if (closing) continue;
        if (jf_equal(tag,"textarea") || jf_equal(tag,"style") || jf_equal(tag,"title")) {
            const char *ending = jf_equal(tag,"textarea") ? "</textarea" : jf_equal(tag,"style") ? "</style" : "</title";
            const unsigned char *stop = jf_find(p, end, ending);
            p = stop ? stop : end; continue;
        }
        if (!jf_equal(tag,"script")) continue;
        const unsigned char *stop = jf_find(p, end, "</script");
        if (!stop) stop = end;
        if (jf_equal(jf_attribute(attributes, finish, "type"), "application/json")) {
            const unsigned char *value;
            while ((value = jf_json_token(p, stop)) != NULL) {
                if (count && memcmp(token, value, 32)) { free(slots); return -2; }
                if (!count) memcpy(token, value, 32);
                if (count == SIZE_MAX / sizeof(*slots)) { free(slots); return -1; }
                size_t *next = realloc(slots, (count + 1) * sizeof(*slots));
                if (!next) { free(slots); return -1; }
                slots = next; slots[count++] = (size_t)(value - body->data);
                p = value + 32;
            }
        }
        p = stop;
    }
    if (!count) { free(slots); return 0; }
    size_t extra = sizeof(jf_include) - 1 - 32;
    if (count > (SIZE_MAX - body->length) / extra) { free(slots); return -1; }
    size_t length = body->length + count * extra;
    unsigned char *data = malloc(length);
    if (!data) { free(slots); return -1; }
    size_t from = 0, to = 0;
    for (size_t i = 0; i < count; ++i) {
        memcpy(data + to, body->data + from, slots[i] - from); to += slots[i] - from;
        memcpy(data + to, jf_include, sizeof(jf_include) - 1); to += sizeof(jf_include) - 1;
        from = slots[i] + 32;
    }
    memcpy(data + to, body->data + from, body->length - from);
    free(slots); free(body->data); body->data = data; body->length = length; body->capacity = length;
    pthread_mutex_lock(&lock);
    struct handoff *entry = buckets[body->owner % BUCKETS];
    while (entry && entry->key != body->owner) entry = entry->next;
    if (entry) memcpy(entry->csrf, token, 33);
    pthread_mutex_unlock(&lock);
    return 1;
}

static void jf_private(VRT_CTX, const char *reason) {
    VRT_l_beresp_uncacheable(ctx, 1);
    VRT_l_beresp_ttl(ctx, VRT_r_param_uncacheable_ttl(ctx));
    http_Unset(ctx->bo->beresp, jf_reason_header);
    http_PrintfHeader(ctx->bo->beresp, "X-SCP-Reason: %s", reason);
}
static enum vfp_status jf_init(VRT_CTX, struct vfp_ctx *vc, struct vfp_entry *entry) {
    struct joomla_body *body = calloc(1, sizeof(*body));
    if (!body) return VFP_Error(vc, "Joomla form inspection allocation failed");
    entry->priv1 = body;
    const char *owner = NULL;
    if (http_GetHdr(ctx->bo->bereq, jf_owner_header, &owner)) body->owner = strtoull(owner, NULL, 10);
    http_Unset(ctx->bo->bereq, jf_owner_header);
    struct vfp_entry *saved = vc->vfp_nxt;
    enum vfp_status status;
    do {
        unsigned char block[16384];
        ssize_t length = sizeof(block);
        vc->vfp_nxt = VTAILQ_NEXT(entry, list);
        status = VFP_Suck(vc, block, &length);
        if (status == VFP_ERROR) { vc->vfp_nxt = saved; return status; }
        if (length < 0 || (size_t)length > SIZE_MAX - body->length) {
            vc->vfp_nxt = saved; return VFP_Error(vc, "Joomla form inspection allocation overflow");
        }
        size_t needed = body->length + (size_t)length;
        if (needed > body->capacity) {
            size_t capacity = body->capacity ? body->capacity : sizeof(block);
            while (capacity < needed) { if (capacity > SIZE_MAX / 2) { capacity = needed; break; } capacity *= 2; }
            unsigned char *data = realloc(body->data, capacity);
            if (!data) { vc->vfp_nxt = saved; return VFP_Error(vc, "Joomla form inspection allocation failed"); }
            body->data = data; body->capacity = capacity;
        }
        if (length) memcpy(body->data + body->length, block, (size_t)length);
        body->length = needed;
    } while (status == VFP_OK);
    vc->vfp_nxt = saved;
    if (body->length && jf_private_html(body->data, body->length)) jf_private(ctx, "joomla-session-form");
    else if (body->length) {
        int token = jf_public_token(body);
        if (token == -1) return VFP_Error(vc, "Joomla token template allocation failed");
        if (token == -2) jf_private(ctx, "joomla-session-form");
        if (token == 1) {
            http_PrintfHeader(ctx->bo->beresp, "X-SCP-Joomla-Token: 1");
            http_Unset(ctx->bo->beresp, H_Content_Length);
            http_Unset(ctx->bo->beresp, H_ETag);
            http_Unset(ctx->bo->beresp, H_Last_Modified);
        }
    }
    return VFP_OK;
}
static enum vfp_status jf_pull(struct vfp_ctx *vc, struct vfp_entry *entry, void *data, ssize_t *length) {
    struct joomla_body *body = entry->priv1;
    (void)vc;
    size_t available = body->length - body->offset;
    if ((size_t)*length > available) *length = (ssize_t)available;
    if (*length) memcpy(data, body->data + body->offset, (size_t)*length);
    body->offset += (size_t)*length;
    return body->offset == body->length ? VFP_END : VFP_OK;
}
static void jf_fini(struct vfp_ctx *vc, struct vfp_entry *entry) {
    struct joomla_body *body = entry->priv1;
    (void)vc;
    if (body) { free(body->data); free(body); entry->priv1 = NULL; }
}
static const struct vfp joomla_filter = {
    .name = "scp_joomla_form", .init = jf_init, .pull = jf_pull, .fini = jf_fini
};

int vmod_cookie_event(VRT_CTX, struct vmod_priv *priv, enum vcl_event_e event) {
    (void)priv;
    if (event == VCL_EVENT_LOAD) return VRT_AddFilter(ctx, &joomla_filter, NULL) ? -1 : 0;
    if (event == VCL_EVENT_DISCARD) VRT_RemoveFilter(ctx, &joomla_filter, NULL);
    return 0;
}

VCL_VOID vmod_guard_joomla_forms(VRT_CTX, struct vmod_priv *priv) {
    struct task *task = priv->priv;
    http_Unset(ctx->bo->bereq, jf_owner_header);
    if (task && task->key) http_PrintfHeader(ctx->bo->bereq, "X-SCP-Form-Owner: %" PRIu64, task->key);
    VRT_l_beresp_do_esi(ctx, 1);
    const char *filters = VRT_r_beresp_filters(ctx);
    const char *encoding = NULL;
    if (!filters) return;
    while (jf_space((unsigned char)*filters)) ++filters;
    http_GetHdr(ctx->bo->beresp, H_Content_Encoding, &encoding);
    if (encoding && strcasecmp(encoding, "gzip") && strcasecmp(encoding, "identity")) {
        jf_private(ctx, "joomla-session-form-encoding"); return;
    }
    const char *prefix = "scp_joomla_form ";
    const char *suffix = filters;
    if (!strncmp(filters, "gunzip ", 7)) { prefix = "gunzip scp_joomla_form "; suffix = filters + 7; }
    else if (!strcmp(filters, "gunzip")) { prefix = "gunzip scp_joomla_form"; suffix = ""; }
    else if (!strcmp(filters, "testgunzip")) { prefix = "gunzip scp_joomla_form gzip"; suffix = ""; }
    else if (encoding && !strcasecmp(encoding, "gzip") && !*filters) { prefix = "gunzip scp_joomla_form gzip"; suffix = ""; }
    size_t length = strlen(prefix) + strlen(suffix) + 1;
    char *value = WS_Alloc(ctx->ws, length);
    if (!value) { VRT_fail(ctx, "Joomla form filter workspace exhausted"); return; }
    strcpy(value, prefix); strcat(value, suffix);
    VRT_l_beresp_do_stream(ctx, 0);
    VRT_l_beresp_filters(ctx, NULL, TOSTRAND(value));
}
