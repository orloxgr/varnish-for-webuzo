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
void delivery_public_parent_free(struct delivery_public_parent *parent) {
    if (parent) { free(parent->body); free(parent); }
}

int delivery_relative(const char *s) {
    const unsigned char *p = (const unsigned char *)s;
    if (!p || p[0] != '/' || p[1] == '/') return 0;
    for (; *p; ++p) if (*p <= 32 || *p == 127 || *p == '\\' || *p == '#') return 0;
    return 1;
}

static int hex_digit(unsigned char c) {
    if (c >= '0' && c <= '9') return c-'0';
    if (c >= 'a' && c <= 'f') return c-'a'+10;
    if (c >= 'A' && c <= 'F') return c-'A'+10;
    return -1;
}

char *delivery_manifest_token(const char *pointer) {
    static const char name[] = "ultracache_delivery=";
    const char *p, *end;
    char *token = NULL;
    if (!delivery_relative(pointer) || !(p = strchr(pointer,'?'))) return NULL;
    ++p;
    while (*p) {
        end = strchr(p,'&');
        if (!end) end = p+strlen(p);
        if ((size_t)(end-p) >= sizeof(name)-1 && !memcmp(p,name,sizeof(name)-1)) {
            const char *value = p+sizeof(name)-1;
            char *out;
            if (token || value == end) goto invalid;
            token = malloc((size_t)(end-value)+1);
            if (!token) return NULL;
            out = token;
            while (value < end) {
                unsigned char c = (unsigned char)*value++;
                if (c == '%') {
                    int high, low;
                    if (end-value < 2 || (high = hex_digit((unsigned char)value[0])) < 0 ||
                        (low = hex_digit((unsigned char)value[1])) < 0) goto invalid;
                    c = (unsigned char)((high<<4)|low); value += 2;
                }
                /* Raw URL decoding: '+' is a token character, not a space. */
                if (c <= 32 || c >= 127) goto invalid;
                *out++ = (char)c;
            }
            *out = '\0';
        }
        p = *end ? end+1 : end;
    }
    return token;
invalid:
    free(token);
    return NULL;
}
void delivery_manifest_free(char *token) { free(token); }

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

static int base64_value(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c-'A';
    if (c >= 'a' && c <= 'z') return c-'a'+26;
    if (c >= '0' && c <= '9') return c-'0'+52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}
static int base64_body(struct text text, unsigned char **out, size_t *length) {
    size_t i, n = 0, groups = text.length/4;
    unsigned char *body;
    if (text.length%4 || groups > (SIZE_MAX-1)/3) return 0;
    body = malloc(groups*3+1);
    if (!body) return 0;
    for (i = 0; i < text.length; i += 4) {
        int a = base64_value((unsigned char)text.data[i]);
        int b = base64_value((unsigned char)text.data[i+1]);
        int c = base64_value((unsigned char)text.data[i+2]);
        int d = base64_value((unsigned char)text.data[i+3]);
        if (a < 0 || b < 0) goto invalid;
        body[n++] = (unsigned char)((a<<2)|(b>>4));
        if (text.data[i+2] == '=') {
            if (text.data[i+3] != '=' || i+4 != text.length || (b&15)) goto invalid;
        } else {
            if (c < 0) goto invalid;
            body[n++] = (unsigned char)((b<<4)|(c>>2));
            if (text.data[i+3] == '=') {
                if (i+4 != text.length || (c&3)) goto invalid;
            } else {
                if (d < 0) goto invalid;
                body[n++] = (unsigned char)((c<<6)|d);
            }
        }
    }
    body[n] = 0; *out = body; *length = n;
    return 1;
invalid:
    free(body);
    return 0;
}
static int public_parent(struct reader *r, struct delivery_public_parent **output) {
    struct delivery_public_parent *parent = calloc(1,sizeof(*parent));
    unsigned seen = 0;
    if (!parent || !take(r,'{')) goto invalid;
    for (;;) {
        struct text key, text;
        unsigned bit;
        size_t i;
        if (!string(r,&key) || !take(r,':')) goto invalid;
        if (equal(key,"generation")) bit = 1;
        else if (equal(key,"bodyBase64")) bit = 2;
        else if (equal(key,"freshRemaining")) bit = 4;
        else goto invalid;
        if (seen&bit) goto invalid;
        seen |= bit;
        if (bit == 4) {
            if (!number(r,&parent->fresh_remaining)) goto invalid;
        } else {
            if (!string(r,&text)) goto invalid;
            if (bit == 1) {
                if (text.length != 64) goto invalid;
                for (i = 0; i < text.length; ++i)
                    if ((text.data[i] < '0' || text.data[i] > '9') &&
                        (text.data[i] < 'a' || text.data[i] > 'f')) goto invalid;
                memcpy(parent->generation,text.data,64);
            } else if (!base64_body(text,&parent->body,&parent->length)) goto invalid;
        }
        if (take(r,'}')) break;
        if (!take(r,',')) goto invalid;
    }
    if (seen != 7) goto invalid;
    *output = parent;
    return 1;
invalid:
    delivery_public_parent_free(parent);
    return 0;
}

int delivery_envelope_parse(const char *body, size_t length,
    const char *request_id, const char *original_url, uint64_t occurrences,
    struct delivery_fragment **output, struct delivery_public_parent **snapshot) {
    struct reader r;
    struct text key, text;
    unsigned seen = 0;
    uint64_t schema;
    int ok = 0;
    if (!output || !snapshot) return 0;
    *output = NULL;
    *snapshot = NULL;
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
        else if (equal(key,"publicParent")) bit = 16;
        else goto done;
        if (seen&bit) goto done;
        seen |= bit;
        if (bit == 1) { if (!number(&r,&schema) || schema != 1) goto done; }
        else if (bit == 2 || bit == 4) {
            if (!string(&r,&text) || !equal(text,bit == 2 ? request_id : original_url)) goto done;
        } else if (bit == 8) {
            if (!fragments(&r,occurrences,output)) goto done;
        } else if (!public_parent(&r,snapshot)) goto done;
        if (take(&r,'}')) break;
        if (!take(&r,',')) goto done;
    }
    whitespace(&r);
    ok = (seen == 15 || seen == 31) && r.offset == length;
done:
    free(r.buffer);
    if (!ok) {
        delivery_free_fragments(*output); *output = NULL;
        delivery_public_parent_free(*snapshot); *snapshot = NULL;
    }
    return ok;
}
