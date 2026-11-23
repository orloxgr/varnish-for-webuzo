/* SPDX-License-Identifier: GPL-3.0-or-later
 * Included by delivery_envelope.c: strict public-selection grammar only.
 * This entry selects a NEW publication; old prepare/recovery stays unchanged.
 */
#include <errno.h>
#include <ctype.h>
#include "selection_digest.c"
#include "delivery_reuse_inputs.h"

static int reuse_skip_value(struct reader *);
static struct delivery_reuse_recipe *guest_inputs_read(const char *, size_t, uint64_t);

/* Application routing metadata, not a cookie decision. Compare the literal
 * frontend path; never decode a query or confuse /shop/ with /shopper/. */
int delivery_selection_scope_valid(const char *scope) {
    const char *segment, *end;
    size_t length;
    if (!delivery_relative(scope) || strchr(scope,'?') || strstr(scope,"//")) return 0;
    length = strlen(scope);
    if (scope[length-1] != '/') return 0;
    for (segment = scope+1; *segment; segment = end+1) {
        end = strchr(segment,'/');
        if (!end || (end-segment == 1 && segment[0] == '.') ||
            (end-segment == 2 && segment[0] == '.' && segment[1] == '.')) return 0;
    }
    return 1;
}
int delivery_selection_scope_matches(const char *scope, const char *url) {
    size_t length, path_length;
    if (!delivery_selection_scope_valid(scope) || !delivery_relative(url)) return 0;
    length = strlen(scope); path_length = strcspn(url,"?");
    return (path_length >= length && !memcmp(scope,url,length)) ||
        (path_length == length-1 && !memcmp(scope,url,path_length));
}

void delivery_selection_free(struct delivery_public_selection *s) {
    if (s) {
        struct delivery_cookie_update *u = s->updates;
        struct delivery_header *h = s->headers;
        while (u) { struct delivery_cookie_update *n = u->next; free(u->name); free(u->value); free(u); u = n; }
        while (h) { struct delivery_header *n = h->next; free(h->line); free(h); h = n; }
        free(s->manifest); free(s->target); delivery_public_parent_free(s->parent);
        delivery_free_fragments(s->fragments); delivery_public_projection_free(s->resolved);
        delivery_reuse_recipe_free(s->guest_inputs); free(s);
    }
}

static int selection_token(const char *s, size_t length) {
    size_t i;
    if (!length) return 0;
    for (i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || (c && strchr("!#$%&'*+-.^_`|~", c)))) return 0;
    }
    return 1;
}
int delivery_cookie_name(const char *name, size_t length) { return selection_token(name,length); }
/* Same literal-name contract as cookie_defaults.valid_name. This PUBLIC
 * projection is not a private consumed-input/PHP identifier declaration. */
static int selection_cookie_literal(const char *name, size_t length) {
    static const char *unicode_space[] = {"\xc2\x85","\xc2\xa0","\xe1\x9a\x80",
        "\xe2\x80\x80","\xe2\x80\x81","\xe2\x80\x82","\xe2\x80\x83","\xe2\x80\x84",
        "\xe2\x80\x85","\xe2\x80\x86","\xe2\x80\x87","\xe2\x80\x88","\xe2\x80\x89",
        "\xe2\x80\x8a","\xe2\x80\xa8","\xe2\x80\xa9","\xe2\x80\xaf","\xe2\x81\x9f","\xe3\x80\x80"};
    size_t i;
    if (!length || name[0] == ' ' || name[length-1] == ' ') return 0;
    for (i = 0; i < sizeof(unicode_space)/sizeof(*unicode_space); ++i) {
        size_t n = strlen(unicode_space[i]);
        if (length >= n && (!memcmp(name,unicode_space[i],n) || !memcmp(name+length-n,unicode_space[i],n))) return 0;
    }
    for (i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)name[i];
        if (c < 32 || c == 127 || strchr(";=\"{}",c)) return 0;
    }
    return 1;
}
static int selection_hex(struct text text) {
    size_t i;
    if (text.length != 64) return 0;
    for (i = 0; i < 64; ++i)
        if (!((text.data[i] >= '0' && text.data[i] <= '9') ||
            (text.data[i] >= 'a' && text.data[i] <= 'f'))) return 0;
    return 1;
}
static int selection_updates(struct reader *r, struct delivery_cookie_update **out) {
    struct delivery_cookie_update **tail = out;
    if (!take(r,'[')) return 0;
    if (take(r,']')) return 1;
    for (;;) {
        struct text name = {NULL,0}, encoded = {NULL,0}, key;
        struct delivery_cookie_update *u, *previous;
        unsigned seen = 0;
        int absent = 0;
        if (!take(r,'{')) return 0;
        for (;;) {
            unsigned bit;
            if (!string(r,&key) || !take(r,':')) return 0;
            if (equal(key,"name")) bit = 1;
            else if (equal(key,"valueBase64")) bit = 2;
            else return 0;
            if (seen&bit) return 0;
            seen |= bit;
            if (bit == 1) { if (!string(r,&name)) return 0; }
            else {
                whitespace(r);
                if (r->length-r->offset >= 4 && !memcmp(r->buffer+r->offset,"null",4)) { r->offset += 4; absent = 1; }
                else if (!string(r,&encoded)) return 0;
            }
            if (take(r,'}')) break;
            if (!take(r,',')) return 0;
        }
        if (seen != 3 || !selection_cookie_literal(name.data,name.length)) return 0;
        for (previous = *out; previous; previous = previous->next)
            if (strlen(previous->name) == name.length && !memcmp(previous->name,name.data,name.length)) return 0;
        u = calloc(1,sizeof(*u));
        if (!u) return 0;
        *tail = u; tail = &u->next; u->name = copy(name);
        if (!u->name) return 0;
        if (!absent) {
            unsigned char *value = NULL;
            size_t length, i;
            if (!base64_body(encoded,&value,&length)) return 0;
            u->value = (char *)value;
            for (i = 0; i < length; ++i)
                if (value[i] < 32 || value[i] == 127 || value[i] == ';') return 0;
        }
        if (take(r,']')) return 1;
        if (!take(r,',')) return 0;
    }
}
void delivery_public_projection_free(struct delivery_public_projection *p) {
    if (p) {
        struct delivery_cookie_update *u = p->cookies;
        while (u) { struct delivery_cookie_update *next = u->next; free(u->name); free(u->value); free(u); u = next; }
        free(p->bucket); free(p->locale); free(p->language); free(p);
    }
}
static int selection_public_projection(struct reader *r, struct delivery_public_projection **out) {
    struct delivery_public_projection *p = calloc(1,sizeof(*p));
    struct delivery_cookie_update *previous = NULL, *u;
    unsigned seen = 0;
    if (!p || !take(r,'{')) goto invalid;
    for (;;) {
        struct text key,value;
        unsigned bit;
        uint64_t version;
        if (!string(r,&key) || !take(r,':')) goto invalid;
        if (equal(key,"version")) bit = 1;
        else if (equal(key,"bucket")) bit = 2;
        else if (equal(key,"locale")) bit = 4;
        else if (equal(key,"language")) bit = 8;
        else if (equal(key,"cookieValues")) bit = 16;
        else goto invalid;
        if (seen & bit) goto invalid;
        seen |= bit;
        if (bit == 1) { if (!number(r,&version) || version != 1) goto invalid; }
        else if (bit == 16) { if (!selection_updates(r,&p->cookies)) goto invalid; }
        else {
            char **field = bit == 2 ? &p->bucket : bit == 4 ? &p->locale : &p->language;
            if (!string(r,&value) || !(*field = copy(value))) goto invalid;
        }
        if (take(r,'}')) break;
        if (!take(r,',')) goto invalid;
    }
    if (seen != 31) goto invalid;
    for (u = p->cookies; u; previous = u, u = u->next)
        if (previous && strcmp(previous->name,u->name) >= 0) goto invalid;
    *out = p; return 1;
invalid:
    delivery_public_projection_free(p); return 0;
}
int delivery_public_projection_parse(const char *body, size_t length,
    struct delivery_public_projection **out) {
    struct reader r;
    int ok;
    if (!out) return 0;
    *out = NULL;
    if (!body || !length || length == SIZE_MAX) return 0;
    r.buffer = malloc(length+1); r.offset = 0; r.length = length;
    if (!r.buffer) return 0;
    memcpy(r.buffer,body,length); r.buffer[length] = 0;
    ok = selection_public_projection(&r,out);
    whitespace(&r);
    ok = ok && r.offset == length;
    free(r.buffer);
    if (!ok) { delivery_public_projection_free(*out); *out = NULL; }
    return ok;
}
int delivery_public_projection_equal(const struct delivery_public_projection *a,
    const struct delivery_public_projection *b) {
    const struct delivery_cookie_update *x, *y;
    if (!a || !b || strcmp(a->bucket,b->bucket) || strcmp(a->locale,b->locale) || strcmp(a->language,b->language)) return 0;
    for (x = a->cookies, y = b->cookies; x && y; x = x->next, y = y->next)
        if (strcmp(x->name,y->name) || !!x->value != !!y->value ||
            (x->value && strcmp(x->value,y->value))) return 0;
    return !x && !y;
}
static int selection_case(const char *s, size_t n, const char *literal) {
    size_t i;
    if (strlen(literal) != n) return 0;
    for (i = 0; i < n; ++i)
        if (tolower((unsigned char)s[i]) != (unsigned char)literal[i]) return 0;
    return 1;
}
static int selection_prefix(const char *s, size_t n, const char *literal) {
    size_t length = strlen(literal);
    return n >= length && selection_case(s,length,literal);
}
static int selection_private_directive(const char *s) {
    while (*s) {
        const char *end, *token;
        while (*s == ' ' || *s == '\t' || *s == ',') ++s;
        token = s;
        while (*s && *s != ',' && *s != '=' && *s != ' ' && *s != '\t') ++s;
        if (selection_case(token,(size_t)(s-token),"private") ||
            selection_case(token,(size_t)(s-token),"no-store") ||
            selection_case(token,(size_t)(s-token),"no-cache")) return 1;
        end = strchr(s,',');
        if (!end) break;
        s = end+1;
    }
    return 0;
}
static int selection_headers(struct reader *r, struct delivery_public_selection *s) {
    struct delivery_header **tail = &s->headers;
    if (!take(r,'[')) return 0;
    if (take(r,']')) return 1;
    for (;;) {
        struct text text;
        struct delivery_header *h;
        const char *colon, *value;
        size_t n, i;
        if (!string(r,&text) || !(colon = memchr(text.data,':',text.length))) return 0;
        n = (size_t)(colon-text.data);
        if (!selection_token(text.data,n)) return 0;
        for (i = 0; i < text.length; ++i)
            if (((unsigned char)text.data[i] < 32 && text.data[i] != '\t') || (unsigned char)text.data[i] == 127) return 0;
        while (text.length && (text.data[text.length-1] == ' ' || text.data[text.length-1] == '\t')) --text.length;
        value = colon+1;
        while (*value == ' ' || *value == '\t') ++value;
        if (selection_case(text.data,n,"set-cookie") || selection_case(text.data,n,"set-cookie2") ||
            selection_case(text.data,n,"authorization") || selection_case(text.data,n,"proxy-authorization") ||
            selection_case(text.data,n,"www-authenticate") || selection_case(text.data,n,"proxy-authenticate") ||
            selection_case(text.data,n,"connection") || selection_case(text.data,n,"transfer-encoding") ||
            selection_case(text.data,n,"trailer") || selection_case(text.data,n,"keep-alive") ||
            selection_case(text.data,n,"te") || selection_case(text.data,n,"upgrade") ||
            selection_case(text.data,n,"proxy-connection") || selection_case(text.data,n,"content-length") ||
            selection_case(text.data,n,"content-encoding") || selection_case(text.data,n,"age") ||
            selection_case(text.data,n,"date") || selection_case(text.data,n,"cookie") ||
            selection_prefix(text.data,n,"x-scp-") || selection_prefix(text.data,n,"x-hvh-") ||
            selection_prefix(text.data,n,"x-wv-") || selection_prefix(text.data,n,"x-cache") ||
            selection_prefix(text.data,n,"x-ultracache-vcl-") ||
            selection_prefix(text.data,n,"x-ultracache-public-selection-") ||
            (selection_prefix(text.data,n,"x-ultracache-delivery-") &&
             !selection_case(text.data,n,"x-ultracache-delivery-prepare"))) return 0;
        if ((selection_case(text.data,n,"cache-control") || selection_case(text.data,n,"surrogate-control") ||
             selection_case(text.data,n,"pragma")) && selection_private_directive(value)) return 0;
        if (selection_case(text.data,n,"vary")) {
            const char *p = value;
            while (*p) {
                while (*p == ' ' || *p == '\t' || *p == ',') ++p;
                if (*p == '*' && (!p[1] || p[1] == ',' || p[1] == ' ' || p[1] == '\t')) return 0;
                p = strchr(p,','); if (!p) break;
            }
        }
        h = calloc(1,sizeof(*h));
        if (!h) return 0;
        *tail = h; tail = &h->next; h->line = copy(text);
        if (!h->line) return 0;
        if (take(r,']')) return 1;
        if (!take(r,',')) return 0;
    }
}
static int selection_header_binding(struct delivery_public_selection *s) {
    struct delivery_header *h;
    unsigned seen = 0;
    for (h = s->headers; h; h = h->next) {
        const char *colon = strchr(h->line,':'), *value = colon+1;
        size_t n = (size_t)(colon-h->line);
        unsigned bit = 0;
        while (*value == ' ' || *value == '\t') ++value;
        if (selection_case(h->line,n,"content-type")) {
            const char *parameters;
            bit = 1;
            if (strlen(value) < 9 || !selection_case(value,9,"text/html")) return 0;
            parameters = value+9;
            while (*parameters == ' ' || *parameters == '\t') ++parameters;
            if (*parameters && *parameters != ';') return 0;
        } else if (selection_case(h->line,n,"x-ultracache-delivery-prepare")) {
            char *manifest = delivery_manifest_token(value);
            bit = 2;
            if (!manifest || strcmp(manifest,s->manifest)) { free(manifest); return 0; }
            free(manifest); if (s->target) return 0;
            s->target = copy((struct text){value,strlen(value)});
            if (!s->target) return 0;
        } else if (selection_case(h->line,n,"x-ultracache-esi-private-count")) {
            char *end;
            unsigned long long count;
            bit = 4;
            if (!*value) return 0;
            for (end = (char *)value; *end; ++end) if (*end < '0' || *end > '9') return 0;
            errno = 0; count = strtoull(value,&end,10);
            if (errno || *end || count != s->occurrences) return 0;
        } else if (selection_case(h->line,n,"x-ultracache-cookie-delivery")) {
            bit = 8;
            if (strcmp(value,"1") || !s->cookie_delivery) return 0;
        } else if (selection_case(h->line,n,"x-ultracache-cookie-settings") && strcmp(value,s->wordpress_policy)) return 0;
        if (bit && (seen&bit)) return 0;
        seen |= bit;
    }
    return seen == (s->cookie_delivery ? 15u : 7u);
}
static int selection_fragments(struct reader *r, struct delivery_fragment **out, uint64_t *total) {
    if (!take(r,'[')) return 0;
    *total = 0;
    if (take(r,']')) return 1;
    for (;;) {
        uint64_t n;
        if (!fragment(r,UINT64_MAX-*total,out,&n)) return 0;
        *total += n;
        if (take(r,']')) return 1;
        if (!take(r,',')) return 0;
    }
}
static int selection_source_role(struct reader *r) {
    unsigned seen = 0;
    if (!take(r,'{')) return 0;
    for (;;) {
        struct text name,value;
        unsigned bit;
        uint64_t n;
        if (!string(r,&name) || !take(r,':')) return 0;
        if (equal(name,"version")) bit = 1;
        else if (equal(name,"role")) bit = 2;
        else return 0;
        if (seen & bit) return 0;
        seen |= bit;
        if (bit == 1) { if (!number(r,&n) || n != 1) return 0; }
        else if (!string(r,&value) || !equal(value,"parent-v1")) return 0;
        if (take(r,'}')) return seen == 3;
        if (!take(r,',')) return 0;
    }
}
static int selected_public(struct reader *r, const char *policy, const char *wordpress_policy,
    struct delivery_public_selection **output, int source_only, int projected) {
    struct delivery_public_selection *s = calloc(1,sizeof(*s));
    unsigned seen = 0;
    uint64_t total = 0;
    char digest[65];
    if (!s || !take(r,'{')) goto invalid;
    for (;;) {
        struct text key, text;
        unsigned bit;
        if (!string(r,&key) || !take(r,':')) goto invalid;
        if (equal(key,"policyDigest")) bit = 1;
        else if (!source_only && equal(key,"cookieUpdates")) bit = 2;
        else if (equal(key,"manifest")) bit = 4;
        else if (equal(key,"occurrences")) bit = 8;
        else if (equal(key,"publicParent")) bit = 16;
        else if (equal(key,"headers")) bit = 32;
        else if (!source_only && equal(key,"renderedFragments")) bit = 64;
        else if (equal(key,"wordpressPolicyDigest")) bit = 128;
        else if (equal(key,"cookieDelivery")) bit = 256;
        else if (source_only && equal(key,"publicSource")) bit = 512;
        else if (projected && equal(key,"resolvedPublic")) bit = 1024;
        else goto invalid;
        if (seen&bit) goto invalid;
        seen |= bit;
        if (bit == 1024) {
            if (!selection_public_projection(r,&s->resolved)) goto invalid;
        } else if (bit == 512) {
            if (!selection_source_role(r)) goto invalid;
            s->source_only = 1;
        } else if (bit == 1) {
            if (!string(r,&text) || !selection_hex(text) || !equal(text,policy)) goto invalid;
            memcpy(s->policy,text.data,64);
        } else if (bit == 128) {
            if (!string(r,&text) || !selection_hex(text) || !equal(text,wordpress_policy)) goto invalid;
            memcpy(s->wordpress_policy,text.data,64);
        } else if (bit == 256) {
            if (!literal_true(r)) goto invalid;
            s->cookie_delivery = 1;
        } else if (bit == 2) { if (!selection_updates(r,&s->updates)) goto invalid; }
        else if (bit == 4) {
            size_t i;
            if (!string(r,&text) || !text.length) goto invalid;
            for (i = 0; i < text.length; ++i) if ((unsigned char)text.data[i] <= 32 || (unsigned char)text.data[i] >= 127) goto invalid;
            s->manifest = copy(text); if (!s->manifest) goto invalid;
        } else if (bit == 8) { if (!number(r,&s->occurrences)) goto invalid; }
        else if (bit == 16) { if (!public_parent(r,&s->parent)) goto invalid; }
        else if (bit == 32) { if (!selection_headers(r,s)) goto invalid; }
        else if (!selection_fragments(r,&s->fragments,&total)) goto invalid;
        if (take(r,'}')) break;
        if (!take(r,',')) goto invalid;
    }
    if (seen != ((source_only ? 701u : 255u)+(s->cookie_delivery ? 256u : 0u)+(projected ? 1024u : 0u)) ||
        (!source_only && total != s->occurrences) || !selection_header_binding(s) ||
        !delivery_selection_digest(s->parent->body,s->parent->length,digest) || strcmp(digest,s->parent->generation)) goto invalid;
    *output = s; return 1;
invalid:
    delivery_selection_free(s); return 0;
}
static int selection_parse(const char *body, size_t length,
    const char *request_id, const char *original_url, const char *policy, const char *wordpress_policy,
    struct delivery_public_selection **selection, struct delivery_private_document **document,
    int source_only, int projection_mode, struct delivery_public_projection **resolved_only) {
    struct reader r;
    unsigned seen = 0;
    int ok = 0;
    if (!selection || !document) return 0;
    *selection = NULL; *document = NULL;
    if (resolved_only) *resolved_only = NULL;
    if (!body || !length || length == SIZE_MAX || !request_id || !original_url || !policy || strlen(policy) != 64 ||
        !wordpress_policy || strlen(wordpress_policy) != 64) return 0;
    r.buffer = malloc(length+1); r.length = length; r.offset = 0;
    if (!r.buffer) return 0;
    memcpy(r.buffer,body,length); r.buffer[length] = 0;
    if (!take(&r,'{')) goto done;
    for (;;) {
        struct text key, text;
        uint64_t schema;
        unsigned bit;
        if (!string(&r,&key) || !take(&r,':')) goto done;
        if (equal(key,"schemaVersion")) bit = 1;
        else if (equal(key,"requestId")) bit = 2;
        else if (equal(key,"originalUrl")) bit = 4;
        else if (projection_mode != DELIVERY_PROJECTED_RESOLVER && equal(key,"selectedPublic")) bit = 8;
        else if (!source_only && equal(key,"privateDocument")) bit = 16;
        else if (resolved_only && projection_mode >= DELIVERY_PROJECTED_PARENT && equal(key,"resolvedPublic")) bit = 32;
        else goto done;
        if (seen&bit) goto done;
        seen |= bit;
        if (bit == 1) { if (!number(&r,&schema) || schema != 1) goto done; }
        else if (bit == 2 || bit == 4) {
            if (!string(&r,&text) || !equal(text,bit == 2 ? request_id : original_url)) goto done;
        } else if (bit == 8) { if (!selected_public(&r,policy,wordpress_policy,selection,source_only,projection_mode >= 0)) goto done; }
        else if (bit == 32) { if (!selection_public_projection(&r,resolved_only)) goto done; }
        else if (!private_document_type(&r,document,0)) goto done;
        if (take(&r,'}')) break;
        if (!take(&r,',')) goto done;
    }
    whitespace(&r);
    ok = (seen == 15 || seen == 23 || (resolved_only && seen == 39)) && r.offset == length;
done:
    free(r.buffer);
    if (!ok) {
        delivery_selection_free(*selection); *selection = NULL; delivery_private_document_free(*document); *document = NULL;
        if (resolved_only) { delivery_public_projection_free(*resolved_only); *resolved_only = NULL; }
    }
    return ok;
}
int delivery_selection_parse(const char *body, size_t length,
    const char *request_id, const char *original_url, const char *policy, const char *wordpress_policy,
    struct delivery_public_selection **selection, struct delivery_private_document **document) {
    return selection_parse(body,length,request_id,original_url,policy,wordpress_policy,selection,document,0,-1,NULL);
}
int delivery_public_source_parse(const char *body, size_t length,
    const char *request_id, const char *source_url, const char *policy, const char *wordpress_policy,
    struct delivery_public_selection **selection) {
    struct delivery_private_document *document = NULL;
    return selection_parse(body,length,request_id,source_url,policy,wordpress_policy,selection,&document,1,-1,NULL);
}
int delivery_projected_selection_parse(const char *body, size_t length,
    const char *request_id, const char *original_url, const char *policy, const char *wordpress_policy,
    enum delivery_projected_role role, struct delivery_public_selection **selection,
    struct delivery_private_document **document, struct delivery_public_projection **resolved_only) {
    if (role < DELIVERY_PROJECTED_PERSONAL || role > DELIVERY_PROJECTED_RESOLVER) return 0;
    return selection_parse(body,length,request_id,original_url,policy,wordpress_policy,selection,document,
        role != DELIVERY_PROJECTED_PERSONAL,(int)role,resolved_only);
}
/* Complete guest outcome is negotiated separately. Existing batch grammar is
 * intentionally unchanged: no private occurrence or issuer marker is erased. */
static int guest_token(struct reader *r, char **output) {
    struct text text;
    size_t i;
    if (!string(r,&text) || !text.length) return 0;
    for (i = 0; i < text.length; ++i)
        if ((unsigned char)text.data[i] < 33 || (unsigned char)text.data[i] > 126) return 0;
    *output = copy(text); return *output != NULL;
}
static int guest_headers(struct delivery_public_selection *s) {
    struct delivery_header *h;
    unsigned types = 0;
    for (h = s->headers; h; h = h->next) {
        const char *colon = strchr(h->line,':'), *value = colon+1;
        size_t n = (size_t)(colon-h->line);
        while (*value == ' ' || *value == '\t') ++value;
        if (selection_case(h->line,n,"content-type")) {
            if (++types != 1 || strlen(value) < 9 || !selection_case(value,9,"text/html") ||
                (value[9] && value[9] != ';' && value[9] != ' ' && value[9] != '\t')) return 0;
        }
        if (selection_prefix(h->line,n,"x-ultracache-esi-") ||
            selection_prefix(h->line,n,"x-ultracache-guest-") ||
            selection_case(h->line,n,"x-ultracache-delivery-prepare") ||
            selection_case(h->line,n,"x-ultracache-cookie-delivery") ||
            selection_case(h->line,n,"surrogate-control") ||
            (selection_case(h->line,n,"x-ultracache-cookie-settings") && strcmp(value,s->wordpress_policy))) return 0;
    }
    return types == 1;
}
static int guest_public(struct reader *r, const char *policy, const char *wordpress_policy,
    const char *guest_policy, const char *epoch, const char *scope, struct delivery_public_selection **output) {
    struct delivery_public_selection *s = calloc(1,sizeof(*s));
    struct text text;
    unsigned seen = 0;
    uint64_t count = 0;
    char digest[65], *source_manifest = NULL;
    size_t i, inputs_start = 0, inputs_length = 0;
    unsigned inputs_duplicate = 0;
    if (!s || !take(r,'{')) goto invalid;
    for (;;) {
        struct text key;
        unsigned bit;
        if (!string(r,&key) || !take(r,':')) goto invalid;
        if (equal(key,"policyDigest")) bit = 1;
        else if (equal(key,"wordpressPolicyDigest")) bit = 2;
        else if (equal(key,"guestPolicyDigest")) bit = 4;
        else if (equal(key,"registryEpoch")) bit = 8;
        else if (equal(key,"scope")) bit = 16;
        else if (equal(key,"manifest")) bit = 32;
        else if (equal(key,"sourceManifest")) bit = 64;
        else if (equal(key,"sourceGeneration")) bit = 128;
        else if (equal(key,"resolvedOccurrences")) bit = 256;
        else if (equal(key,"publicParent")) bit = 512;
        else if (equal(key,"headers")) bit = 1024;
        else if (equal(key,"cookieDelivery")) bit = 2048;
        else if (equal(key,"guestInputs")) bit = 4096;
        else goto invalid;
        if ((seen&bit) && bit != 4096) goto invalid;
        if ((seen&bit) && bit == 4096) inputs_duplicate = 1;
        seen |= bit;
        if (bit <= 16 || bit == 128 || bit == 2048) {
            if (!string(r,&text)) goto invalid;
            if (bit <= 8) {
                const char *expected = bit == 1 ? policy : bit == 2 ? wordpress_policy : bit == 4 ? guest_policy : epoch;
                if (!selection_hex(text) || !equal(text,expected)) goto invalid;
                if (bit == 1) memcpy(s->policy,text.data,64);
                if (bit == 2) memcpy(s->wordpress_policy,text.data,64);
            } else if (bit == 16) { if (!equal(text,scope)) goto invalid; }
            else if (bit == 128) { if (!selection_hex(text)) goto invalid; }
            else if (!equal(text,"none") && !equal(text,"deferred")) goto invalid;
        } else if (bit == 32) { if (!guest_token(r,&s->manifest)) goto invalid; }
        else if (bit == 64) { if (!guest_token(r,&source_manifest)) goto invalid; }
        else if (bit == 256) { if (!number(r,&count)) goto invalid; }
        else if (bit == 512) { if (!public_parent(r,&s->parent)) goto invalid; }
        else if (bit == 4096) {
            /* Boundary scanning must not mutate escaped recipe strings before
             * the existing canonical recipe parser receives their raw JSON. */
            struct reader scan = *r;
            scan.buffer = malloc(r->length+1);
            if (!scan.buffer) goto invalid;
            memcpy(scan.buffer,r->buffer,r->length+1);
            inputs_start = r->offset;
            int valid = reuse_skip_value(&scan);
            inputs_length = scan.offset-inputs_start;
            r->offset = scan.offset; free(scan.buffer);
            if (!valid) goto invalid;
        }
        else if (!selection_headers(r,s)) goto invalid;
        if (take(r,'}')) break;
        if (!take(r,',')) goto invalid;
    }
    if ((seen & ~4096U) != 4095 || !guest_headers(s) || !delivery_selection_digest(s->parent->body,s->parent->length,digest) ||
        strcmp(digest,s->parent->generation)) goto invalid;
    for (i = 0; i+5 <= s->parent->length; ++i)
        if (selection_case((const char *)s->parent->body+i,5,"<esi:")) goto invalid;
    if (inputs_length && !inputs_duplicate)
        s->guest_inputs = guest_inputs_read(r->buffer+inputs_start,inputs_length,count);
    s->target = copy((struct text){s->manifest,strlen(s->manifest)}); if (!s->target) goto invalid;
    s->guest = 1; *output = s; free(source_manifest); return 1;
invalid:
    free(source_manifest); delivery_selection_free(s); return 0;
}
int delivery_guest_selection_parse(const char *body, size_t length,
    const char *request_id, const char *original_url, const char *policy, const char *wordpress_policy,
    const char *guest_policy, const char *epoch, const char *scope, struct delivery_public_selection **selection) {
    struct reader r;
    unsigned seen = 0;
    int ok = 0;
    if (!selection) return 0;
    *selection = NULL;
    if (!body || !length || length == SIZE_MAX || !request_id || !original_url || !policy ||
        !wordpress_policy || !guest_policy || !epoch || !delivery_selection_scope_valid(scope)) return 0;
    r.buffer = malloc(length+1); r.length = length; r.offset = 0;
    if (!r.buffer) return 0;
    memcpy(r.buffer,body,length); r.buffer[length] = 0;
    if (!take(&r,'{')) goto done;
    for (;;) {
        struct text key, text;
        uint64_t schema;
        unsigned bit;
        if (!string(&r,&key) || !take(&r,':')) goto done;
        if (equal(key,"schemaVersion")) bit = 1;
        else if (equal(key,"requestId")) bit = 2;
        else if (equal(key,"originalUrl")) bit = 4;
        else if (equal(key,"guestPublic")) bit = 8;
        else goto done;
        if (seen&bit) goto done;
        seen |= bit;
        if (bit == 1) { if (!number(&r,&schema) || schema != 1) goto done; }
        else if (bit == 2 || bit == 4) {
            if (!string(&r,&text) || !equal(text,bit == 2 ? request_id : original_url)) goto done;
        } else if (!guest_public(&r,policy,wordpress_policy,guest_policy,epoch,scope,selection)) goto done;
        if (take(&r,'}')) break;
        if (!take(&r,',')) goto done;
    }
    whitespace(&r); ok = seen == 15 && r.offset == length;
done:
    free(r.buffer);
    if (!ok) { delivery_selection_free(*selection); *selection = NULL; }
    return ok;
}

static int selection_cookie_action(const char *rules, const char *name, size_t length, int fallback) {
    const char *p = rules;
    if (!p) return fallback;
    while (*p) {
        const char *end = strchr(p,'\n'), *action = strchr(p,'\t'), *kind = action ? strchr(action+1,'\t') : NULL;
        size_t n;
        int prefix, exact;
        if (!end) end = p+strlen(p);
        if (!action || !kind || action >= end || kind >= end) return -1;
        n = (size_t)(end-kind-1);
        prefix = kind-action == 7 && !memcmp(action+1,"prefix",6);
        exact = kind-action == 6 && !memcmp(action+1,"exact",5);
        if (!n || (!exact && !prefix)) return -1;
        if (((exact && n == length) || (prefix && n <= length)) && !memcmp(kind+1,name,n)) {
            if (action-p == 7 && !memcmp(p,"variant",7)) return 1;
            if (action-p == 7 && !memcmp(p,"private",7)) return 2;
            if (action-p == 6 && !memcmp(p,"shared",6)) return 0;
            return -1;
        }
        p = *end ? end+1 : end;
    }
    return fallback;
}
int delivery_cookie_action(const char *rules, const char *name, size_t length) {
    return selection_cookie_action(rules,name,length,0);
}
int delivery_selection_all_shared(const char *original, const char *rules) {
    const char *p = original;
    unsigned pairs = 0;
    if (!p || !*p) return 0;
    while (*p) {
        const char *end = strchr(p,';'), *equals;
        if (!end) end = p+strlen(p);
        while (p < end && (*p == ' ' || *p == '\t')) ++p;
        equals = memchr(p,'=',(size_t)(end-p));
        if (!equals || !delivery_cookie_name(p,(size_t)(equals-p)) ||
            selection_cookie_action(rules,p,(size_t)(equals-p),-1) != 0) return 0;
        ++pairs; p = *end ? end+1 : end;
    }
    return pairs != 0;
}
int delivery_selection_candidate(const struct delivery_public_selection *s,
    const char *original, const char *rules, char **candidate) {
    const struct delivery_cookie_update *u;
    const char *p = original ? original : "";
    size_t length = strlen(p), capacity, used = 0;
    char *out;
    if (!candidate) return 0;
    *candidate = NULL;
    if (!s || length > (SIZE_MAX-1)/2) return 0;
    capacity = length*2+1; /* canonical separators may add a space per pair */
    for (u = s->updates; u; u = u->next) {
        size_t extra;
        if (delivery_cookie_action(rules,u->name,strlen(u->name)) != 1) return 0;
        if (!u->value) continue;
        extra = strlen(u->name)+strlen(u->value)+3;
        if (extra > SIZE_MAX-capacity) return 0;
        capacity += extra;
    }
    out = malloc(capacity);
    if (!out) return 0;
    while (*p) {
        const char *end = strchr(p,';'), *name = p, *equals;
        int replaced = 0;
        if (!end) end = p+strlen(p);
        while (name < end && (*name == ' ' || *name == '\t')) ++name;
        equals = end > name ? memchr(name,'=',(size_t)(end-name)) : NULL;
        if (equals) for (u = s->updates; u; u = u->next)
            if (strlen(u->name) == (size_t)(equals-name) && !memcmp(u->name,name,(size_t)(equals-name))) { replaced = 1; break; }
        if (!replaced && end > name) {
            if (used) { out[used++] = ';'; out[used++] = ' '; }
            memcpy(out+used,name,(size_t)(end-name)); used += (size_t)(end-name);
        }
        p = *end ? end+1 : end;
    }
    for (u = s->updates; u; u = u->next) if (u->value) {
        size_t n;
        if (used) { out[used++] = ';'; out[used++] = ' '; }
        n = strlen(u->name); memcpy(out+used,u->name,n); used += n;
        out[used++] = '='; n = strlen(u->value); memcpy(out+used,u->value,n); used += n;
    }
    out[used] = 0; *candidate = out; return 1;
}

struct selection_pair { const char *name, *value; size_t name_length, value_length; };
static int selection_pair_compare(const void *a, const void *b) {
    const struct selection_pair *x = a, *y = b;
    size_t n = x->name_length < y->name_length ? x->name_length : y->name_length;
    int result = memcmp(x->name,y->name,n);
    return result ? result : x->name_length > y->name_length ? 1 : x->name_length < y->name_length ? -1 : 0;
}
char *delivery_selection_projection(const char *candidate, const char *rules) {
    const char *p = candidate ? candidate : "";
    size_t count = 0, capacity = 0, used = 0, length = strlen(p), i;
    struct selection_pair *pairs = NULL;
    char *out;
    if (length > (SIZE_MAX-1)/2) return NULL;
    while (*p) {
        const char *end = strchr(p,';'), *name = p, *eq;
        if (!end) end = p+strlen(p);
        while (name < end && (*name == ' ' || *name == '\t')) ++name;
        eq = memchr(name,'=',(size_t)(end-name));
        if (eq && delivery_cookie_action(rules,name,(size_t)(eq-name)) == 1) {
            for (i = 0; i < count; ++i)
                if (pairs[i].name_length == (size_t)(eq-name) && !memcmp(pairs[i].name,name,(size_t)(eq-name))) break;
            if (i == count) {
                if (count == capacity) {
                    struct selection_pair *grown;
                    size_t next = capacity ? capacity*2 : 8;
                    if (next <= capacity || next > SIZE_MAX/sizeof(*pairs)) { free(pairs); return NULL; }
                    grown = realloc(pairs,next*sizeof(*pairs));
                    if (!grown) { free(pairs); return NULL; }
                    pairs = grown; capacity = next;
                }
                pairs[count++] = (struct selection_pair){name,eq+1,(size_t)(eq-name),(size_t)(end-eq-1)};
            }
        }
        p = *end ? end+1 : end;
    }
    if (count > 1) qsort(pairs,count,sizeof(*pairs),selection_pair_compare);
    out = malloc(length*2+1);
    if (out) {
        for (i = 0; i < count; ++i) {
            if (used) { out[used++] = ';'; out[used++] = ' '; }
            memcpy(out+used,pairs[i].name,pairs[i].name_length); used += pairs[i].name_length;
            out[used++] = '='; memcpy(out+used,pairs[i].value,pairs[i].value_length); used += pairs[i].value_length;
        }
        out[used] = 0;
    }
    free(pairs); return out;
}
char *delivery_public_projection_cookie(const struct delivery_public_projection *p, const char *rules) {
    struct delivery_public_selection input = {0};
    char *wire = NULL;
    if (!p) return NULL;
    input.updates = p->cookies;
    return delivery_selection_candidate(&input,NULL,rules,&wire) ? wire : NULL;
}
int delivery_public_projection_candidate(const struct delivery_public_projection *p,
    const char *original, const char *rules, char **candidate) {
    struct delivery_public_selection input = {0};
    char *wire = NULL, *expected = NULL;
    int valid = 0;
    if (!candidate) return 0;
    *candidate = NULL;
    if (!p || !(expected = delivery_public_projection_cookie(p,rules))) goto done;
    input.updates = p->cookies;
    if (!delivery_selection_candidate(&input,original,rules,candidate) ||
        !(wire = delivery_selection_projection(*candidate,rules)) || strcmp(wire,expected)) goto done;
    valid = 1;
done:
    free(wire); free(expected);
    if (!valid) { free(*candidate); *candidate = NULL; }
    return valid;
}
