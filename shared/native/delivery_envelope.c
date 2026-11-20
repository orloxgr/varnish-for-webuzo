/* SPDX-License-Identifier: GPL-3.0-or-later
 * Only the fixed UltraCache delivery-v1 envelope grammar is accepted. There is
 * no recursive generic JSON tree, engine-private header or external JSON DSO.
 */
#include "delivery_envelope.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct reader { char *buffer; size_t length, offset; };
struct text { const char *data; size_t length; };

void delivery_free_fragments(struct delivery_fragment *f) {
    while (f) {
        struct delivery_fragment *next = f->next;
        free(f->url); free(f->html); free(f); f = next;
    }
}

int delivery_relative(const char *s) {
    const unsigned char *p = (const unsigned char *)s;
    if (!p || p[0] != '/' || p[1] == '/') return 0;
    for (; *p; ++p) if (*p <= 32 || *p == 127 || *p == '\\' || *p == '#') return 0;
    return 1;
}

static void whitespace(struct reader *r) {
    while (r->offset < r->length) {
        char c = r->buffer[r->offset];
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n') break;
        ++r->offset;
    }
}
static int take(struct reader *r, char c) {
    whitespace(r);
    if (r->offset == r->length || r->buffer[r->offset] != c) return 0;
    ++r->offset;
    return 1;
}
static int equal(struct text s, const char *literal) {
    size_t length = strlen(literal);
    return s.length == length && !memcmp(s.data,literal,length);
}
static char *copy(struct text s) {
    char *p = malloc(s.length+1);
    if (p) { memcpy(p,s.data,s.length); p[s.length] = '\0'; }
    return p;
}
int delivery_buffer_growth(size_t used, size_t capacity, size_t chunk,
    size_t *needed, size_t *target_capacity) {
    size_t target;
    if (used == SIZE_MAX || chunk > SIZE_MAX-used-1) return 0;
    *needed = used+chunk+1;
    target = capacity <= SIZE_MAX/2 ? capacity*2 : *needed;
    if (target < *needed) target = *needed;
    *target_capacity = capacity >= *needed ? capacity : target;
    return 1;
}
static int hex4(struct reader *r, uint32_t *value) {
    unsigned i;
    uint32_t n = 0;
    if (r->length-r->offset < 4) return 0;
    for (i = 0; i < 4; ++i) {
        unsigned char c = (unsigned char)r->buffer[r->offset++];
        unsigned digit;
        if (c >= '0' && c <= '9') digit = c-'0';
        else if (c >= 'a' && c <= 'f') digit = c-'a'+10;
        else if (c >= 'A' && c <= 'F') digit = c-'A'+10;
        else return 0;
        n = n*16U+digit;
    }
    *value = n;
    return 1;
}
static char *utf8_write(char *p, uint32_t u) {
    if (u < 0x80) *p++ = (char)u;
    else if (u < 0x800) {
        *p++ = (char)(0xc0U | (u>>6)); *p++ = (char)(0x80U | (u&63U));
    } else if (u < 0x10000) {
        *p++ = (char)(0xe0U | (u>>12)); *p++ = (char)(0x80U | ((u>>6)&63U));
        *p++ = (char)(0x80U | (u&63U));
    } else {
        *p++ = (char)(0xf0U | (u>>18)); *p++ = (char)(0x80U | ((u>>12)&63U));
        *p++ = (char)(0x80U | ((u>>6)&63U)); *p++ = (char)(0x80U | (u&63U));
    }
    return p;
}
static int string(struct reader *r, struct text *out) {
    char *start, *p;
    if (!take(r,'"')) return 0;
    start = p = r->buffer+r->offset;
    while (r->offset < r->length) {
        unsigned char c = (unsigned char)r->buffer[r->offset++];
        if (c == '"') {
            out->data = start; out->length = (size_t)(p-start); *p = '\0';
            return 1;
        }
        if (c < 32) return 0;
        if (c == '\\') {
            uint32_t u, low;
            if (r->offset == r->length) return 0;
            c = (unsigned char)r->buffer[r->offset++];
            switch (c) {
            case '"': case '\\': case '/': *p++ = (char)c; break;
            case 'b': *p++ = '\b'; break;
            case 'f': *p++ = '\f'; break;
            case 'n': *p++ = '\n'; break;
            case 'r': *p++ = '\r'; break;
            case 't': *p++ = '\t'; break;
            case 'u':
                if (!hex4(r,&u)) return 0;
                if (u >= 0xd800 && u <= 0xdbff) {
                    if (r->length-r->offset < 6 || r->buffer[r->offset] != '\\' ||
                        r->buffer[r->offset+1] != 'u') return 0;
                    r->offset += 2;
                    if (!hex4(r,&low) || low < 0xdc00 || low > 0xdfff) return 0;
                    u = 0x10000+((u-0xd800)<<10)+(low-0xdc00);
                } else if (u >= 0xdc00 && u <= 0xdfff) return 0;
                p = utf8_write(p,u);
                break;
            default: return 0;
            }
        } else if (c < 0x80) *p++ = (char)c;
        else {
            unsigned more, i;
            uint32_t u, minimum;
            if (c >= 0xc2 && c <= 0xdf) { more = 1; u = c&31U; minimum = 0x80; }
            else if (c >= 0xe0 && c <= 0xef) { more = 2; u = c&15U; minimum = 0x800; }
            else if (c >= 0xf0 && c <= 0xf4) { more = 3; u = c&7U; minimum = 0x10000; }
            else return 0;
            if (r->length-r->offset < more) return 0;
            for (i = 0; i < more; ++i) {
                unsigned char next = (unsigned char)r->buffer[r->offset++];
                if ((next&0xc0U) != 0x80U) return 0;
                u = (u<<6) | (next&63U);
            }
            if (u < minimum || u > 0x10ffff || (u >= 0xd800 && u <= 0xdfff)) return 0;
            p = utf8_write(p,u);
        }
    }
    return 0;
}
static int number(struct reader *r, uint64_t *out) {
    uint64_t n = 0;
    size_t start;
    whitespace(r); start = r->offset;
    while (r->offset < r->length) {
        unsigned char c = (unsigned char)r->buffer[r->offset];
        if (c < '0' || c > '9') break;
        if (r->offset > start && r->buffer[start] == '0') return 0;
        if (n > (UINT64_MAX-(c-'0'))/10U) return 0;
        n = n*10U+(c-'0'); ++r->offset;
    }
    if (r->offset == start) return 0;
    *out = n;
    return 1;
}
static int fragment(struct reader *r, uint64_t remaining,
    struct delivery_fragment **output, uint64_t *occurrences) {
    struct text key, url = {NULL,0}, html = {NULL,0};
    struct delivery_fragment *f;
    unsigned seen = 0;
    uint64_t n = 0;
    if (!take(r,'{')) return 0;
    for (;;) {
        unsigned bit;
        if (!string(r,&key) || !take(r,':')) return 0;
        if (equal(key,"url")) bit = 1;
        else if (equal(key,"html")) bit = 2;
        else if (equal(key,"occurrences")) bit = 4;
        else return 0;
        if (seen&bit) return 0;
        seen |= bit;
        if (bit == 1) { if (!string(r,&url)) return 0; }
        else if (bit == 2) { if (!string(r,&html)) return 0; }
        else if (!number(r,&n) || !n || n > remaining) return 0;
        if (take(r,'}')) break;
        if (!take(r,',')) return 0;
    }
    if (seen != 7 || strlen(url.data) != url.length || !delivery_relative(url.data)) return 0;
    for (f = *output; f; f = f->next) if (!strcmp(f->url,url.data)) return 0;
    f = calloc(1,sizeof(*f));
    if (!f) return 0;
    f->url = copy(url); f->html = copy(html); f->length = html.length;
    if (!f->url || !f->html) { delivery_free_fragments(f); return 0; }
    f->next = *output; *output = f; *occurrences = n;
    return 1;
}
static int fragments(struct reader *r, uint64_t expected, struct delivery_fragment **out) {
    uint64_t total = 0, n;
    if (!take(r,'[') || take(r,']')) return 0;
    for (;;) {
        if (!fragment(r,expected-total,out,&n)) return 0;
        total += n;
        if (take(r,']')) return total == expected;
        if (!take(r,',')) return 0;
    }
}

int delivery_envelope_parse(const char *body, size_t length,
    const char *request_id, const char *original_url, uint64_t occurrences,
    struct delivery_fragment **output) {
    struct reader r;
    struct text key, text;
    unsigned seen = 0;
    uint64_t schema;
    int ok = 0;
    if (!output) return 0;
    *output = NULL;
    if (!body || !request_id || !original_url || !length || length == SIZE_MAX || !occurrences) return 0;
    r.buffer = malloc(length+1); r.length = length; r.offset = 0;
    if (!r.buffer) return 0;
    memcpy(r.buffer,body,length); r.buffer[length] = '\0';
    if (!take(&r,'{')) goto done;
    for (;;) {
        unsigned bit;
        if (!string(&r,&key) || !take(&r,':')) goto done;
        if (equal(key,"schemaVersion")) bit = 1;
        else if (equal(key,"requestId")) bit = 2;
        else if (equal(key,"originalUrl")) bit = 4;
        else if (equal(key,"renderedFragments")) bit = 8;
        else goto done;
        if (seen&bit) goto done;
        seen |= bit;
        if (bit == 1) { if (!number(&r,&schema) || schema != 1) goto done; }
        else if (bit == 2 || bit == 4) {
            if (!string(&r,&text) || !equal(text,bit == 2 ? request_id : original_url)) goto done;
        } else if (!fragments(&r,occurrences,output)) goto done;
        if (take(&r,'}')) break;
        if (!take(&r,',')) goto done;
    }
    whitespace(&r);
    ok = seen == 15 && r.offset == length;
done:
    free(r.buffer);
    if (!ok) { delivery_free_fragments(*output); *output = NULL; }
    return ok;
}
