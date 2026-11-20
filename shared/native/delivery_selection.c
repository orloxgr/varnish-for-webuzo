/* SPDX-License-Identifier: GPL-3.0-or-later
 * Included by delivery_envelope.c: strict public-selection grammar only.
 * This entry selects a NEW publication; old prepare/recovery stays unchanged.
 */
#include <errno.h>
#include <ctype.h>
#include "selection_digest.c"

void delivery_selection_free(struct delivery_public_selection *s) {
    if (s) {
        struct delivery_cookie_update *u = s->updates;
        struct delivery_header *h = s->headers;
        while (u) { struct delivery_cookie_update *n = u->next; free(u->name); free(u->value); free(u); u = n; }
        while (h) { struct delivery_header *n = h->next; free(h->line); free(h); h = n; }
        free(s->manifest); free(s->target); delivery_public_parent_free(s->parent);
        delivery_free_fragments(s->fragments); free(s);
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
        if (seen != 3 || !selection_token(name.data,name.length)) return 0;
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
        } else if (selection_case(h->line,n,"x-ultracache-cookie-settings") && strcmp(value,s->wordpress_policy)) return 0;
        if (bit && (seen&bit)) return 0;
        seen |= bit;
    }
    return seen == 7;
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
static int selected_public(struct reader *r, const char *policy, const char *wordpress_policy, struct delivery_public_selection **output) {
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
        else if (equal(key,"cookieUpdates")) bit = 2;
        else if (equal(key,"manifest")) bit = 4;
        else if (equal(key,"occurrences")) bit = 8;
        else if (equal(key,"publicParent")) bit = 16;
        else if (equal(key,"headers")) bit = 32;
        else if (equal(key,"renderedFragments")) bit = 64;
        else if (equal(key,"wordpressPolicyDigest")) bit = 128;
        else goto invalid;
        if (seen&bit) goto invalid;
        seen |= bit;
        if (bit == 1) {
            if (!string(r,&text) || !selection_hex(text) || !equal(text,policy)) goto invalid;
            memcpy(s->policy,text.data,64);
        } else if (bit == 128) {
            if (!string(r,&text) || !selection_hex(text) || !equal(text,wordpress_policy)) goto invalid;
            memcpy(s->wordpress_policy,text.data,64);
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
    if (seen != 255 || total != s->occurrences || !selection_header_binding(s) ||
        !delivery_selection_digest(s->parent->body,s->parent->length,digest) || strcmp(digest,s->parent->generation)) goto invalid;
    *output = s; return 1;
invalid:
    delivery_selection_free(s); return 0;
}
int delivery_selection_parse(const char *body, size_t length,
    const char *request_id, const char *original_url, const char *policy, const char *wordpress_policy,
    struct delivery_public_selection **selection, struct delivery_private_document **document) {
    struct reader r;
    unsigned seen = 0;
    int ok = 0;
    if (!selection || !document) return 0;
    *selection = NULL; *document = NULL;
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
        else if (equal(key,"selectedPublic")) bit = 8;
        else if (equal(key,"privateDocument")) bit = 16;
        else goto done;
        if (seen&bit) goto done;
        seen |= bit;
        if (bit == 1) { if (!number(&r,&schema) || schema != 1) goto done; }
        else if (bit == 2 || bit == 4) {
            if (!string(&r,&text) || !equal(text,bit == 2 ? request_id : original_url)) goto done;
        } else if (bit == 8) { if (!selected_public(&r,policy,wordpress_policy,selection)) goto done; }
        else if (!private_document_type(&r,document,0)) goto done;
        if (take(&r,'}')) break;
        if (!take(&r,',')) goto done;
    }
    whitespace(&r);
    ok = (seen == 15 || seen == 23) && r.offset == length;
done:
    free(r.buffer);
    if (!ok) { delivery_selection_free(*selection); *selection = NULL; delivery_private_document_free(*document); *document = NULL; }
    return ok;
}
int delivery_cookie_action(const char *rules, const char *name, size_t length) {
    const char *p = rules;
    if (!p) return 0;
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
    return 0;
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
        equals = memchr(name,'=',(size_t)(end-name));
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
