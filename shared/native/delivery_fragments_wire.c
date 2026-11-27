/* SPDX-License-Identifier: GPL-3.0-or-later
 * Included by delivery_envelope.c to share its strict UTF-8/JSON primitives.
 * A parsed public request never creates native cache authority. */
#include "delivery_fragments_wire.h"
#include <stdio.h>
#include <limits.h>
#include <zlib.h>

static const char *fragment_context_names[] = {
    "policy", "bucket", "cookies", "locale", "language"
};

void delivery_fragment_batch_free(struct delivery_fragment_batch *b) {
    unsigned i;
    if (!b) return;
    while (b->requested) {
        struct delivery_fragment_request *r = b->requested;
        b->requested = r->next; free(r->url); free(r);
    }
    for (i = 0; i < 5; ++i) free(b->context[i]);
    free(b->source_url); free(b);
}
void delivery_fragment_results_free(struct delivery_fragment_results *r) {
    if (!r) return;
    delivery_free_fragments(r->rendered);
    while (r->failed) {
        struct delivery_fragment_failure *f = r->failed;
        r->failed = f->next; free(f->url); free(f->code); free(f);
    }
    if (r->authority) {
        while (r->authority->fragments) {
            struct delivery_fragment_grant *g = r->authority->fragments;
            r->authority->fragments = g->next;
            while (g->authority) {
                struct delivery_reuse_authority *a = g->authority;
                g->authority = a->next; free(a);
            }
            free(g->url); free(g);
        }
        free(r->authority->scope); free(r->authority);
    }
    delivery_fragment_admission_free(r->admission); free(r);
}

void delivery_fragment_admission_free(struct delivery_fragment_admission *value) {
    if (!value) return;
    delivery_reuse_admitted_free(value->fragments); free(value);
}
int delivery_fragment_metadata_key(const struct delivery_reuse_context *context,
    const char *incarnation, const char *revision, const char *descriptor,
    const char *binding, char key[65]) {
    struct reuse_frame frame = {NULL,0,0};
    const char *fields[] = {"ultracache-fragment-admission-v1", context ? context->site_id : NULL,
        context ? context->canonical_host : NULL, context ? context->scope : NULL,
        context ? context->epoch : NULL, incarnation, revision,
        context ? context->native_policy : NULL, context ? context->wordpress_policy : NULL,
        context ? context->reuse_policy : NULL, descriptor, binding};
    size_t i;
    int valid = 0;
    if (!context || !key) return 0;
    for (i = 0; i < sizeof(fields)/sizeof(fields[0]); ++i)
        if (!fields[i] || !reuse_lp(&frame,fields[i],strlen(fields[i]))) goto done;
    valid = delivery_selection_digest(frame.bytes,frame.length,key);
done:
    delivery_reuse_frame_free(frame.bytes,frame.length); return valid;
}
int delivery_fragment_admission_parse(const char *body, size_t length,
    struct delivery_fragment_admission **out) {
    struct reader r;
    struct delivery_reuse_record rows = {0};
    struct delivery_fragment_admission *value = NULL;
    struct delivery_reuse_admitted_fragment *f, *other;
    unsigned seen = 0;
    int valid = 0;
    if (!out) return 0;
    *out = NULL;
    if (!body || !length || length == SIZE_MAX || !(r.buffer = malloc(length+1))) return 0;
    memcpy(r.buffer,body,length); r.buffer[length] = 0; r.length = length; r.offset = 0;
    value = calloc(1,sizeof(*value));
    if (!value || !take(&r,'{')) goto done;
    for (;;) {
        struct text key;
        unsigned bit;
        uint64_t version;
        if (!string(&r,&key) || !take(&r,':')) goto done;
        if (equal(key,"version")) bit = 1;
        else if (equal(key,"cookieValidUntil")) bit = 2;
        else if (equal(key,"fragments")) bit = 4;
        else goto done;
        if (seen & bit) goto done;
        seen |= bit;
        if (bit == 1) { if (!number(&r,&version) || version != 1) goto done; }
        else if (bit == 2) { if (!number(&r,&value->cookie_valid_until) || !value->cookie_valid_until) goto done; }
        else if (!reuse_metadata_fragments(&r,body,&rows)) goto done;
        if (take(&r,'}')) break;
        if (!take(&r,',')) goto done;
    }
    whitespace(&r);
    if (seen != 7 || r.offset != length || !rows.fragments) goto done;
    for (f = rows.fragments; f; f = f->next) {
        const struct delivery_reuse_authority *a;
        size_t count = 0, i;
        if (!f->inputs || !*f->input_binding) goto done;
        for (other = f->next; other; other = other->next)
            if (!strcmp(other->url,f->url) || !strcmp(other->descriptor,f->descriptor)) goto done;
        for (a = f->authority; a; a = a->next) {
            ++count;
            for (i = 0; i < f->identity_tag_count; ++i) if (!strcmp(f->identity_tags[i],a->tag)) break;
            if (i == f->identity_tag_count) goto done;
        }
        if (count != f->identity_tag_count) goto done;
    }
    value->fragments = rows.fragments; rows.fragments = NULL;
    *out = value; value = NULL; valid = 1;
done:
    delivery_reuse_admitted_free(rows.fragments); delivery_fragment_admission_free(value); free(r.buffer); return valid;
}

static char *fragment_query_value(const char *p, size_t length) {
    const char *end = p+length;
    char *out, *cursor;
    if (!length || length == SIZE_MAX) return NULL;
    cursor = out = malloc(length+1);
    if (!out) return NULL;
    while (p < end) {
        unsigned char c = (unsigned char)*p++;
        if (c == '%') {
            int high, low;
            if (end-p < 2 || (high = hex_digit((unsigned char)p[0])) < 0 ||
                (low = hex_digit((unsigned char)p[1])) < 0) goto invalid;
            c = (unsigned char)((high<<4)|low); p += 2;
        }
        if (c <= 32 || c >= 127) goto invalid;
        *cursor++ = (char)c;
    }
    *cursor = 0;
    return out;
invalid:
    free(out); return NULL;
}

int delivery_fragment_batch_operation(const char *uri) {
    const char *p = uri ? strchr(uri,'?') : NULL;
    if (!p) return 0;
    for (++p; *p;) {
        const char *end = strchr(p,'&'), *equal_at;
        size_t name;
        if (!end) end = p+strlen(p);
        equal_at = memchr(p,'=',(size_t)(end-p));
        name = (size_t)((equal_at ? equal_at : end)-p);
        if ((name == sizeof("ultracache_fragment_delivery")-1 &&
            !memcmp(p,"ultracache_fragment_delivery",name)) ||
            (name == sizeof("ultracache_fragment_subset")-1 &&
            !memcmp(p,"ultracache_fragment_subset",name))) return 1;
        if (!*end) break;
        p = end+1;
    }
    return 0;
}

int delivery_fragment_batch_request(const char *uri, char **token, char **subset) {
    const char *p;
    unsigned seen = 0;
    if (!token || !subset) return 0;
    *token = *subset = NULL;
    if (!uri || !delivery_relative(uri) || !(p = strchr(uri,'?')) || !*++p) return 0;
    for (;;) {
        const char *end = strchr(p,'&'), *equal_at;
        size_t name;
        unsigned bit;
        char *value;
        if (!end) end = p+strlen(p);
        equal_at = memchr(p,'=',(size_t)(end-p));
        if (!equal_at) goto invalid;
        name = (size_t)(equal_at-p);
        if (name == sizeof("ultracache_fragment_delivery")-1 &&
            !memcmp(p,"ultracache_fragment_delivery",name)) bit = 1;
        else if (name == sizeof("ultracache_fragment_subset")-1 &&
            !memcmp(p,"ultracache_fragment_subset",name)) bit = 2;
        else goto invalid;
        if (seen & bit) goto invalid;
        value = fragment_query_value(equal_at+1,(size_t)(end-equal_at-1));
        if (!value) goto invalid;
        if (bit == 1) *token = value; else *subset = value;
        seen |= bit;
        if (!*end) break;
        p = end+1;
        if (!*p) goto invalid;
    }
    if (seen & 1) return 1;
invalid:
    free(*token); free(*subset); *token = *subset = NULL;
    return 0;
}

char *delivery_fragment_batch_token(const char *uri) {
    char *token = NULL, *subset = NULL;
    if (!delivery_fragment_batch_request(uri,&token,&subset)) return NULL;
    /* Legacy callers must not accidentally execute an explicit full batch. */
    if (subset) { free(token); token = NULL; }
    free(subset); return token;
}

int delivery_fragment_batch_select(struct delivery_fragment_batch *b,
    const char *token, const char *subset) {
    static const char purpose[] = "ultracache-fragment-delivery-subset-v1\n";
    struct delivery_fragment_request *item, **link;
    unsigned char *selected = NULL;
    const char *p = subset;
    size_t count = 0, previous = 0, chosen = 0, index, i, token_length, subset_length, length;
    char *frame = NULL, digest[65];
    int valid = 0;
    if (!b || !token) return 0;
    if (!subset) return 1;
    if (!*subset) return 0;
    for (item = b->requested; item; item = item->next) {
        if (count == SIZE_MAX) return 0;
        ++count;
    }
    if (!count || !(selected = calloc(count,1))) return 0;
    for (;;) {
        index = 0;
        if (*p < '0' || *p > '9' || (*p == '0' && p[1] >= '0' && p[1] <= '9')) goto done;
        while (*p >= '0' && *p <= '9') {
            unsigned digit = (unsigned)(*p++-'0');
            if (index > (SIZE_MAX-digit)/10) goto done;
            index = index*10+digit;
        }
        if (index >= count || (chosen && index <= previous)) goto done;
        selected[index] = 1; previous = index; ++chosen;
        if (!*p) break;
        if (*p++ != ',' || !*p) goto done;
    }
    token_length = strlen(token); subset_length = strlen(subset);
    if (token_length > SIZE_MAX-sizeof(purpose) ||
        subset_length > SIZE_MAX-sizeof(purpose)-token_length) goto done;
    length = sizeof(purpose)-1+token_length+1+subset_length;
    frame = malloc(length);
    if (!frame) goto done;
    memcpy(frame,purpose,sizeof(purpose)-1);
    memcpy(frame+sizeof(purpose)-1,token,token_length);
    frame[sizeof(purpose)-1+token_length] = '\n';
    memcpy(frame+sizeof(purpose)+token_length,subset,subset_length);
    if (!delivery_selection_digest((const unsigned char *)frame,length,digest)) goto done;
    link = &b->requested; b->occurrences = 0; i = 0;
    while ((item = *link) != NULL) {
        if (!selected[i++]) { *link = item->next; free(item->url); free(item); }
        else { b->occurrences += item->occurrences; link = &item->next; }
    }
    memcpy(b->digest,digest,sizeof(digest)); valid = 1;
done:
    free(frame); free(selected); return valid;
}

static int fragment_batch_context(struct reader *r, struct delivery_fragment_batch *b) {
    unsigned seen = 0;
    if (!take(r,'{')) return 0;
    for (;;) {
        struct text key, value;
        unsigned i;
        if (!string(r,&key) || !take(r,':') || !string(r,&value) ||
            strlen(value.data) != value.length) return 0;
        for (i = 0; i < 5; ++i) if (equal(key,fragment_context_names[i])) break;
        if (i == 5 || (seen & (1U<<i))) return 0;
        if ((i == 0 || i == 2) && !selection_hex(value)) return 0;
        if (i == 1 && !value.length) return 0;
        b->context[i] = copy(value);
        if (!b->context[i]) return 0;
        seen |= 1U<<i;
        if (take(r,'}')) return seen == 31;
        if (!take(r,',')) return 0;
    }
}

static int fragment_batch_requests(struct reader *r, struct delivery_fragment_batch *b) {
    struct delivery_fragment_request **tail = &b->requested;
    if (!take(r,'[') || take(r,']')) return 0;
    for (;;) {
        struct delivery_fragment_request *entry, *other;
        struct text url = {NULL,0};
        uint64_t count = 0;
        unsigned seen = 0;
        if (!take(r,'{')) return 0;
        for (;;) {
            struct text key;
            unsigned bit;
            if (!string(r,&key) || !take(r,':')) return 0;
            if (equal(key,"url")) bit = 1;
            else if (equal(key,"occurrences")) bit = 2;
            else return 0;
            if (seen & bit) return 0;
            seen |= bit;
            if (bit == 1) { if (!string(r,&url)) return 0; }
            else if (!number(r,&count) || !count) return 0;
            if (take(r,'}')) break;
            if (!take(r,',')) return 0;
        }
        if (seen != 3 || strlen(url.data) != url.length || !delivery_relative(url.data) ||
            count > UINT64_MAX-b->occurrences) return 0;
        /* Registry URIs are compared byte-for-byte, never decoded twice or
         * rewritten from home_url to the batch's site_url/index.php route. */
        for (other = b->requested; other; other = other->next)
            if (!strcmp(other->url,url.data)) return 0;
        entry = calloc(1,sizeof(*entry));
        if (!entry) return 0;
        entry->url = copy(url); entry->occurrences = count;
        *tail = entry; tail = &entry->next;
        if (!entry->url) return 0;
        b->occurrences += count;
        if (take(r,']')) return 1;
        if (!take(r,',')) return 0;
    }
}

/* The per-site memory-admission MAC is distinct from the application's
 * outer ticket signature. No unauthenticated declared size reaches malloc or
 * inflate. Existing scope/descriptor/identity checks still authorize delivery. */
static unsigned char *fragment_batch_inflate(const unsigned char *frame, size_t length,
    const unsigned char key[32], const char *scope, size_t *output_length) {
    static const char domain[] = "ultracache-fragment-batch-deflate-v1";
    struct reuse_frame message = {NULL,0,0};
    unsigned char *output = NULL;
    uint64_t declared = 0;
    size_t i, raw_length, input_assigned = 0, output_assigned = 0, capacity;
    size_t input_length;
    const unsigned char *input;
    char expected[65];
    unsigned mismatch = 0;
    z_stream stream;
    int initialized = 0, status = Z_OK, valid = 0;
    if (!frame || length <= 41 || frame[0] != 1 || !key || !scope || !*scope || !output_length) return NULL;
    input = frame+41; input_length = length-41;
    if (!reuse_lp_string(&message,domain) || !reuse_lp_string(&message,scope) ||
        !reuse_append(&message,frame+1,8) || !reuse_append(&message,input,input_length) ||
        !delivery_hmac_sha256(key,32,message.bytes,message.length,expected)) goto done;
    for (i = 0; i < 32; ++i)
        mismatch |= frame[9+i] ^ (unsigned)(hex_digit((unsigned char)expected[2*i])*16+
            hex_digit((unsigned char)expected[2*i+1]));
    if (mismatch) goto done;
    for (i = 0; i < 8; ++i) declared = (declared<<8)|frame[1+i];
    if (!declared || declared > SIZE_MAX-1) goto done;
    raw_length = (size_t)declared; capacity = raw_length+1;
    output = malloc(capacity);
    if (!output) goto done;
    memset(&stream,0,sizeof(stream));
    if (inflateInit2(&stream,-MAX_WBITS) != Z_OK) goto done;
    initialized = 1;
    for (;;) {
        size_t before_in, before_out;
        if (!stream.avail_in && input_assigned < input_length) {
            size_t n = input_length-input_assigned;
            if (n > UINT_MAX) n = UINT_MAX;
            stream.next_in = (Bytef *)(input+input_assigned); stream.avail_in = (uInt)n; input_assigned += n;
        }
        if (!stream.avail_out && output_assigned < capacity) {
            size_t n = capacity-output_assigned;
            if (n > UINT_MAX) n = UINT_MAX;
            stream.next_out = output+output_assigned; stream.avail_out = (uInt)n; output_assigned += n;
        }
        before_in = input_assigned-stream.avail_in; before_out = output_assigned-stream.avail_out;
        status = inflate(&stream,Z_NO_FLUSH);
        if (status == Z_STREAM_END) {
            valid = input_assigned-stream.avail_in == input_length &&
                output_assigned-stream.avail_out == raw_length;
            break;
        }
        if (status != Z_OK || (before_in == input_assigned-stream.avail_in &&
            before_out == output_assigned-stream.avail_out) ||
            output_assigned-stream.avail_out == capacity) break;
    }
    if (valid) { output[raw_length] = 0; *output_length = raw_length; }
done:
    if (initialized) inflateEnd(&stream);
    delivery_reuse_frame_free(message.bytes,message.length);
    if (!valid) { free(output); output = NULL; }
    return output;
}

int delivery_fragment_batch_parse_scoped(const char *token, size_t length,
    const unsigned char key[32], const char *scope, struct delivery_fragment_batch **out) {
    static const char purpose[] = "ultracache-fragment-delivery-v1\n";
    const char *dot;
    char *padded = NULL, *frame = NULL;
    unsigned char *decoded = NULL;
    size_t i, start, payload, padded_length, decoded_length = 0;
    int compressed;
    struct delivery_fragment_batch *b = NULL;
    struct reader r;
    unsigned seen = 0;
    int ok = 0;
    if (!out) return 0;
    *out = NULL;
    if (!token || !length || length == SIZE_MAX || strlen(token) != length ||
        !(dot = strchr(token,'.')) || dot == token || strlen(dot+1) != 64 ||
        !selection_hex((struct text){dot+1,64})) return 0;
    compressed = !strncmp(token,"z1_",3);
    if (compressed && (!key || !scope)) return 0;
    start = compressed ? 3 : 0;
    payload = (size_t)(dot-token)-start;
    if (payload%4 == 1 || payload > SIZE_MAX-4 || length > SIZE_MAX-sizeof(purpose)) return 0;
    padded_length = (payload+3)/4*4;
    padded = malloc(padded_length+1);
    if (!padded) goto done;
    for (i = 0; i < payload; ++i) {
        unsigned char c = (unsigned char)token[start+i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) padded[i] = (char)c;
        else if (c == '-') padded[i] = '+';
        else if (c == '_') padded[i] = '/';
        else goto done;
    }
    while (i < padded_length) padded[i++] = '=';
    padded[i] = 0;
    if (!base64_body((struct text){padded,padded_length},&decoded,&decoded_length) ||
        !decoded_length) goto done;
    if (compressed) {
        unsigned char *expanded = fragment_batch_inflate(decoded,decoded_length,key,scope,&decoded_length);
        free(decoded); decoded = expanded;
        if (!decoded) goto done;
    }
    b = calloc(1,sizeof(*b));
    if (!b) goto done;
    r = (struct reader){(char *)decoded,decoded_length,0};
    if (!take(&r,'{')) goto done;
    for (;;) {
        struct text key, text;
        unsigned bit;
        uint64_t version;
        if (!string(&r,&key) || !take(&r,':')) goto done;
        if (equal(key,"schemaVersion")) bit = 1;
        else if (equal(key,"sourceUrl")) bit = 2;
        else if (equal(key,"context")) bit = 4;
        else if (equal(key,"fragments")) bit = 8;
        else goto done;
        if (seen & bit) goto done;
        seen |= bit;
        if (bit == 1) { if (!number(&r,&version) || version != 1) goto done; }
        else if (bit == 2) {
            if (!string(&r,&text) || strlen(text.data) != text.length || !delivery_relative(text.data)) goto done;
            b->source_url = copy(text); if (!b->source_url) goto done;
        } else if (bit == 4) { if (!fragment_batch_context(&r,b)) goto done; }
        else if (!fragment_batch_requests(&r,b)) goto done;
        if (take(&r,'}')) break;
        if (!take(&r,',')) goto done;
    }
    whitespace(&r);
    if (seen != 15 || r.offset != r.length) goto done;
    frame = malloc(sizeof(purpose)-1+length);
    if (!frame) goto done;
    memcpy(frame,purpose,sizeof(purpose)-1);
    memcpy(frame+sizeof(purpose)-1,token,length);
    if (!delivery_selection_digest((const unsigned char *)frame,sizeof(purpose)-1+length,b->digest)) goto done;
    *out = b; b = NULL; ok = 1;
done:
    free(frame); free(padded); free(decoded); delivery_fragment_batch_free(b);
    return ok;
}

int delivery_fragment_batch_parse(const char *token, size_t length,
    struct delivery_fragment_batch **out) {
    return delivery_fragment_batch_parse_scoped(token,length,NULL,NULL,out);
}

static int fragment_failure_code(struct text code) {
    static const char *codes[] = {"fragment-disabled", "context-unavailable",
        "renderer-unavailable", "renderer-failed", "fragment-redirect", "state-conflict"};
    size_t i;
    for (i = 0; i < sizeof(codes)/sizeof(codes[0]); ++i) if (equal(code,codes[i])) return 1;
    return 0;
}
static int fragment_batch_failures(struct reader *r, struct delivery_fragment_results *out) {
    if (!take(r,'[')) return 0;
    if (take(r,']')) return 1;
    for (;;) {
        struct text url = {NULL,0}, code = {NULL,0};
        struct delivery_fragment_failure *f, *other;
        uint64_t occurrences = 0, status = 0;
        unsigned seen = 0;
        if (!take(r,'{')) return 0;
        for (;;) {
            struct text key;
            unsigned bit;
            if (!string(r,&key) || !take(r,':')) return 0;
            if (equal(key,"url")) bit = 1;
            else if (equal(key,"occurrences")) bit = 2;
            else if (equal(key,"status")) bit = 4;
            else if (equal(key,"code")) bit = 8;
            else return 0;
            if (seen & bit) return 0;
            seen |= bit;
            if (bit == 1) { if (!string(r,&url)) return 0; }
            else if (bit == 8) { if (!string(r,&code) || !fragment_failure_code(code)) return 0; }
            else if (bit == 2) { if (!number(r,&occurrences) || !occurrences) return 0; }
            else if (!number(r,&status) || status < 400 || status > 599) return 0;
            if (take(r,'}')) break;
            if (!take(r,',')) return 0;
        }
        if (seen != 15 || strlen(url.data) != url.length || !delivery_relative(url.data)) return 0;
        for (other = out->failed; other; other = other->next) if (!strcmp(other->url,url.data)) return 0;
        f = calloc(1,sizeof(*f));
        if (!f) return 0;
        f->url = copy(url); f->code = copy(code); f->occurrences = occurrences; f->status = (unsigned)status;
        f->next = out->failed; out->failed = f;
        if (!f->url || !f->code) return 0;
        if (take(r,']')) return 1;
        if (!take(r,',')) return 0;
    }
}
static int fragment_batch_grants(struct reader *r, struct delivery_fragment_authority *authority) {
    if (!take(r,'[') || take(r,']')) return 0;
    for (;;) {
        struct delivery_fragment_grant *g = calloc(1,sizeof(*g)), *other;
        unsigned seen = 0;
        if (!g) return 0;
        g->next = authority->fragments; authority->fragments = g;
        if (!take(r,'{')) return 0;
        for (;;) {
            struct text key, text;
            unsigned bit;
            if (!string(r,&key) || !take(r,':')) return 0;
            if (equal(key,"url")) bit = 1;
            else if (equal(key,"authority")) bit = 2;
            else return 0;
            if (seen & bit) return 0;
            seen |= bit;
            if (bit == 1) {
                if (!string(r,&text) || strlen(text.data) != text.length || !delivery_relative(text.data)) return 0;
                g->url = copy(text); if (!g->url) return 0;
            } else {
                struct delivery_reuse_admitted_fragment temp = {0};
                int ok = reuse_metadata_authority(r,&temp);
                g->authority = temp.authority;
                if (!ok) return 0;
            }
            if (take(r,'}')) break;
            if (!take(r,',')) return 0;
        }
        if (seen != 3) return 0;
        for (other = g->next; other; other = other->next) if (!strcmp(other->url,g->url)) return 0;
        if (take(r,']')) return 1;
        if (!take(r,',')) return 0;
    }
}
static int fragment_batch_authority(struct reader *r, struct delivery_fragment_results *out) {
    static const char *names[] = {"scope", "epoch", "incarnation", "scopeRevision", "nativePolicy", "wordpressPolicy", "reusePolicy", "fragments"};
    struct delivery_fragment_authority *a = calloc(1,sizeof(*a));
    unsigned seen = 0;
    if (!a) return 0;
    out->authority = a;
    if (!take(r,'{')) return 0;
    for (;;) {
        struct text key, text;
        unsigned i;
        if (!string(r,&key) || !take(r,':')) return 0;
        for (i = 0; i < 8; ++i) if (equal(key,names[i])) break;
        if (i == 8 || (seen & (1U<<i))) return 0;
        seen |= 1U<<i;
        if (i == 7) { if (!fragment_batch_grants(r,a)) return 0; }
        else {
            if (!string(r,&text)) return 0;
            if (i == 0) {
                if (strlen(text.data) != text.length || !delivery_selection_scope_valid(text.data)) return 0;
                a->scope = copy(text); if (!a->scope) return 0;
            } else {
                char *fields[] = {a->epoch,a->incarnation,a->scope_revision,a->native_policy,a->wordpress_policy,a->reuse_policy};
                if (!selection_hex(text)) return 0;
                memcpy(fields[i-1],text.data,64);
            }
        }
        if (take(r,'}')) return seen == 255;
        if (!take(r,',')) return 0;
    }
}

static int fragment_results_complete(const struct delivery_fragment_batch *batch,
    const struct delivery_fragment_results *out) {
    const struct delivery_fragment_request *request;
    const struct delivery_fragment *f;
    const struct delivery_fragment_failure *failure;
    const struct delivery_fragment_grant *g;
    for (request = batch->requested; request; request = request->next) {
        unsigned matches = 0;
        for (f = out->rendered; f; f = f->next) if (!strcmp(f->url,request->url)) {
            if (f->occurrences != request->occurrences) return 0;
            ++matches;
        }
        for (failure = out->failed; failure; failure = failure->next) if (!strcmp(failure->url,request->url)) {
            if (failure->occurrences != request->occurrences) return 0;
            ++matches;
        }
        if (matches != 1) return 0;
    }
    for (f = out->rendered; f; f = f->next) {
        for (request = batch->requested; request; request = request->next) if (!strcmp(request->url,f->url)) break;
        if (!request) return 0;
        for (g = out->authority ? out->authority->fragments : NULL; g; g = g->next) if (!strcmp(g->url,f->url)) break;
        if ((f->cache_key && !g) || (!f->cache_key && g)) return 0;
        /* Only explicitly anonymous output with no content dependencies may
         * use an empty closure. Anonymous content tags still need authority. */
        if (g && (f->cache_anonymous && f->cache_tags && !*f->cache_tags
            ? g->authority != NULL : g->authority == NULL)) return 0;
    }
    for (failure = out->failed; failure; failure = failure->next) {
        for (request = batch->requested; request; request = request->next) if (!strcmp(request->url,failure->url)) break;
        if (!request) return 0;
    }
    for (g = out->authority ? out->authority->fragments : NULL; g; g = g->next) {
        for (f = out->rendered; f; f = f->next) if (!strcmp(f->url,g->url)) break;
        if (!f || !f->cache_key) return 0;
    }
    return 1;
}

int delivery_fragment_envelope_parse_v1(const char *body, size_t length,
    const char *request_id, const char *original_url,
    const struct delivery_fragment_batch *batch, struct delivery_fragment_results **out) {
    struct delivery_fragment_results *result = NULL;
    struct reader r;
    unsigned seen = 0;
    int ok = 0;
    if (!out) return 0;
    *out = NULL;
    if (!body || !length || length == SIZE_MAX || !request_id || !original_url || !batch || !batch->requested) return 0;
    r.buffer = malloc(length+1); r.length = length; r.offset = 0;
    if (!r.buffer) return 0;
    memcpy(r.buffer,body,length); r.buffer[length] = 0;
    result = calloc(1,sizeof(*result));
    if (!result || !take(&r,'{')) goto done;
    for (;;) {
        struct text key, text;
        unsigned bit;
        uint64_t version;
        if (!string(&r,&key) || !take(&r,':')) goto done;
        if (equal(key,"schemaVersion")) bit = 1;
        else if (equal(key,"requestId")) bit = 2;
        else if (equal(key,"originalUrl")) bit = 4;
        else if (equal(key,"requestDigest")) bit = 8;
        else if (equal(key,"renderedFragments")) bit = 16;
        else if (equal(key,"failedFragments")) bit = 32;
        else if (equal(key,"authority")) bit = 64;
        else if (equal(key,"reuseAdmission")) bit = 128;
        else goto done;
        if (seen & bit) goto done;
        seen |= bit;
        if (bit == 1) { if (!number(&r,&version) || version != 2) goto done; }
        else if (bit == 2 || bit == 4 || bit == 8) {
            const char *expected = bit == 2 ? request_id : bit == 4 ? original_url : batch->digest;
            if (!string(&r,&text) || !equal(text,expected)) goto done;
        } else if (bit == 16) {
            uint64_t total;
            if (!selection_fragments_mode(&r,&result->rendered,&total,1)) goto done;
        } else if (bit == 32) { if (!fragment_batch_failures(&r,result)) goto done; }
        else if (bit == 64) { if (!fragment_batch_authority(&r,result)) goto done; }
        else {
            size_t start;
            whitespace(&r); start = r.offset;
            if (!reuse_skip_value(&r)) goto done;
            /* Optional admission can decline without losing completed results. */
            (void)delivery_fragment_admission_parse(body+start,r.offset-start,&result->admission);
        }
        if (take(&r,'}')) break;
        if (!take(&r,',')) goto done;
    }
    whitespace(&r);
    if ((seen & ~192U) != 63 || r.offset != r.length || !fragment_results_complete(batch,result)) goto done;
    *out = result; result = NULL; ok = 1;
done:
    delivery_fragment_results_free(result); free(r.buffer); return ok;
}

struct fragment_json { char *data; size_t length, capacity; };
static int fragment_json_add(struct fragment_json *b, const char *text, size_t length) {
    size_t needed, capacity;
    char *p;
    if (!delivery_buffer_growth(b->length,b->capacity,length,&needed,&capacity)) return 0;
    if (capacity > b->capacity) {
        p = realloc(b->data,capacity);
        if (!p) return 0;
        b->data = p; b->capacity = capacity;
    }
    if (length) memcpy(b->data+b->length,text,length);
    b->length += length; b->data[b->length] = 0;
    return 1;
}
static int fragment_json_literal(struct fragment_json *b, const char *text) {
    return fragment_json_add(b,text,strlen(text));
}
static int fragment_json_quote(struct fragment_json *b, const char *text, size_t length) {
    static const char hex[] = "0123456789abcdef";
    size_t i;
    if (!fragment_json_literal(b,"\"")) return 0;
    for (i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)text[i];
        char escaped[6] = {'\\','u','0','0',0,0};
        if (c < 32) {
            escaped[4] = hex[c>>4]; escaped[5] = hex[c&15];
            if (!fragment_json_add(b,escaped,6)) return 0;
        } else if (c == '"' || c == '\\') {
            char pair[2] = {'\\',(char)c};
            if (!fragment_json_add(b,pair,2)) return 0;
        } else if (!fragment_json_add(b,text+i,1)) return 0;
    }
    return fragment_json_literal(b,"\"");
}

int delivery_fragment_results_json(const struct delivery_fragment_batch *batch,
    const struct delivery_fragment_results *results, char **body, size_t *length) {
    struct fragment_json json = {NULL,0,0};
    const struct delivery_fragment_request *request;
    unsigned first = 1;
    if (!body || !length) return 0;
    *body = NULL; *length = 0;
    if (!batch || !batch->requested || !results || !fragment_results_complete(batch,results) ||
        !fragment_json_literal(&json,"{\"schemaVersion\":1,\"results\":[")) goto invalid;
    for (request = batch->requested; request; request = request->next) {
        const struct delivery_fragment *f;
        const struct delivery_fragment_failure *failure;
        for (f = results->rendered; f; f = f->next) if (!strcmp(f->url,request->url)) break;
        for (failure = results->failed; failure; failure = failure->next) if (!strcmp(failure->url,request->url)) break;
        if ((!f && !failure) || (f && failure)) goto invalid;
        if (!first && !fragment_json_literal(&json,",")) goto invalid;
        first = 0;
        if (!fragment_json_literal(&json,"{\"url\":") ||
            !fragment_json_quote(&json,request->url,strlen(request->url))) goto invalid;
        if (f) {
            /* Runtime projects only after every claimed object completed normal
             * storage and the final authority check. This is an output fact,
             * never an input claim or a cache/identity grant. */
            const char *scope = !f->cache_key ? "none" :
                f->cache_anonymous ? "anonymous" : "private";
            if (!fragment_json_literal(&json,",\"status\":200,\"html\":") ||
                !fragment_json_quote(&json,f->html,f->length) ||
                !fragment_json_literal(&json,",\"cacheScope\":") ||
                !fragment_json_quote(&json,scope,strlen(scope))) goto invalid;
        } else {
            char status[32];
            int n = snprintf(status,sizeof(status),",\"status\":%u,\"error\":{\"code\":",failure->status);
            if (n < 0 || (size_t)n >= sizeof(status) ||
                !fragment_json_add(&json,status,(size_t)n) ||
                !fragment_json_quote(&json,failure->code,strlen(failure->code)) ||
                !fragment_json_literal(&json,"}")) goto invalid;
        }
        if (!fragment_json_literal(&json,"}")) goto invalid;
    }
    if (!fragment_json_literal(&json,"]}")) goto invalid;
    *body = json.data; *length = json.length; return 1;
invalid:
    free(json.data); return 0;
}
