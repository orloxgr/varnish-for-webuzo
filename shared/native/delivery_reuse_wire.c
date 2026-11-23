/* SPDX-License-Identifier: GPL-3.0-or-later
 * Included after the portable input/mutation codecs. No authority installation.
 */
#include "delivery_reuse_wire.h"

/* Optional evidence for the already compiled complete guest publication.
 * Reuses the existing canonical recipe, including PHP parser context. Invalid
 * evidence affects Shared-cookie reuse only, never the legacy no-Cookie body. */
static struct delivery_reuse_recipe *guest_inputs_read(const char *json, size_t length, uint64_t resolved) {
    struct reader r;
    struct delivery_reuse_recipe *recipe = NULL;
    uint64_t version = 0, occurrences = 0;
    size_t start = 0, size = 0;
    unsigned seen = 0;
    if (!reuse_reader(json,length,&r)) return NULL;
    if (!take(&r,'{')) goto done;
    for (;;) {
        struct text key;
        unsigned bit;
        if (!string(&r,&key) || !take(&r,':')) goto done;
        if (equal(key,"version")) bit = 1;
        else if (equal(key,"privateOccurrences")) bit = 2;
        else if (equal(key,"recipe")) bit = 4;
        else goto done;
        if (seen & bit) goto done;
        seen |= bit;
        if (bit == 1) { if (!number(&r,&version) || version != 1) goto done; }
        else if (bit == 2) { if (!number(&r,&occurrences) || occurrences > resolved) goto done; }
        else {
            start = r.offset;
            if (!reuse_skip_value(&r)) goto done;
            size = r.offset-start;
        }
        if (take(&r,'}')) break;
        if (!take(&r,',')) goto done;
    }
    whitespace(&r);
    if (seen == 7 && r.offset == length)
        (void)delivery_reuse_recipe_parse(json+start,size,occurrences,&recipe);
done:
    free(r.buffer); return recipe;
}

/* Generic value boundaries only, used to remove the optional extension before
 * the unchanged strict legacy parser. An explicit stack avoids recursive JSON
 * parsing and introduces no product nesting/byte limit. */
static int reuse_skip_value(struct reader *r) {
    unsigned char *stack = NULL;
    size_t depth = 0, capacity = 0;
    int want = 1, valid = 0;
    for (;;) {
        whitespace(r);
        if (want) {
            struct text ignored;
            char c;
            if (r->offset == r->length) goto done;
            c = r->buffer[r->offset];
            if (c == '{' || c == '[') {
                unsigned char *grown;
                if (depth == capacity) {
                    size_t next = capacity ? capacity*2 : 16;
                    if (next < capacity || !(grown = realloc(stack,next))) goto done;
                    stack = grown; capacity = next;
                }
                ++r->offset; stack[depth++] = c == '{' ? 0 : 3;
                want = 0; continue;
            }
            if (c == '"') { if (!string(r,&ignored)) goto done; }
            else if (c == 't' || c == 'f' || c == 'n') {
                const char *word = c == 't' ? "true" : c == 'f' ? "false" : "null";
                size_t n = strlen(word);
                if (r->length-r->offset < n || memcmp(r->buffer+r->offset,word,n)) goto done;
                r->offset += n;
            } else {
                size_t start = r->offset;
                if (c == '-') ++r->offset;
                if (r->offset == r->length) goto done;
                c = r->buffer[r->offset++];
                if (c != '0') {
                    if (c < '1' || c > '9') goto done;
                    while (r->offset < r->length && r->buffer[r->offset] >= '0' && r->buffer[r->offset] <= '9') ++r->offset;
                }
                if (r->offset < r->length && r->buffer[r->offset] == '.') {
                    ++r->offset;
                    if (r->offset == r->length || r->buffer[r->offset] < '0' || r->buffer[r->offset] > '9') goto done;
                    while (r->offset < r->length && r->buffer[r->offset] >= '0' && r->buffer[r->offset] <= '9') ++r->offset;
                }
                if (r->offset < r->length && (r->buffer[r->offset] == 'e' || r->buffer[r->offset] == 'E')) {
                    ++r->offset;
                    if (r->offset < r->length && (r->buffer[r->offset] == '+' || r->buffer[r->offset] == '-')) ++r->offset;
                    if (r->offset == r->length || r->buffer[r->offset] < '0' || r->buffer[r->offset] > '9') goto done;
                    while (r->offset < r->length && r->buffer[r->offset] >= '0' && r->buffer[r->offset] <= '9') ++r->offset;
                }
                if (r->offset == start) goto done;
            }
            want = 0;
        }
        if (!depth) { valid = 1; goto done; }
        switch (stack[depth-1]) {
        case 0: /* first object key or empty object */
            if (take(r,'}')) { --depth; break; }
            stack[depth-1] = 1;
            /* fall through */
        case 1: {
            struct text ignored;
            if (!string(r,&ignored) || !take(r,':')) goto done;
            stack[depth-1] = 2; want = 1; break;
        }
        case 2:
            if (take(r,'}')) { --depth; break; }
            if (!take(r,',')) goto done;
            stack[depth-1] = 1; break;
        case 3:
            if (take(r,']')) { --depth; break; }
            stack[depth-1] = 4; want = 1; break;
        case 4:
            if (take(r,']')) { --depth; break; }
            if (!take(r,',')) goto done;
            stack[depth-1] = 5; want = 1; break;
        case 5: stack[depth-1] = 4; break;
        }
    }
done:
    free(stack); return valid;
}
int delivery_reuse_envelope_split(const char *body, size_t length, char **legacy,
    size_t *legacy_length, char **candidate, size_t *candidate_length) {
    struct reader r;
    struct reuse_frame wire = {NULL,0,0};
    size_t fields = 0, candidates = 0;
    int valid = 0;
    if (!legacy || !legacy_length || !candidate || !candidate_length) return 0;
    *legacy = *candidate = NULL; *legacy_length = *candidate_length = 0;
    if (!body || !length || length == SIZE_MAX || !(r.buffer = malloc(length+1))) return 0;
    memcpy(r.buffer,body,length); r.buffer[length] = 0; r.length = length; r.offset = 0;
    if (!take(&r,'{') || !reuse_append(&wire,"{",1)) goto done;
    if (!take(&r,'}')) for (;;) {
        struct text key;
        size_t start, value, end;
        whitespace(&r); start = r.offset;
        if (!string(&r,&key) || !take(&r,':')) goto done;
        whitespace(&r); value = r.offset;
        if (!reuse_skip_value(&r)) goto done;
        end = r.offset;
        if (equal(key,"reuseCandidate")) {
            ++candidates;
            free(*candidate); *candidate = NULL; *candidate_length = 0;
            if (candidates == 1) {
                *candidate = malloc(end-value+1);
                if (!*candidate) goto done;
                memcpy(*candidate,body+value,end-value); (*candidate)[end-value] = 0;
                *candidate_length = end-value;
            }
        } else {
            if ((fields++ && !reuse_append(&wire,",",1)) || !reuse_append(&wire,body+start,end-start)) goto done;
        }
        if (take(&r,'}')) break;
        if (!take(&r,',')) goto done;
    }
    whitespace(&r);
    if (r.offset != length || !reuse_append(&wire,"}",2)) goto done;
    *legacy = (char *)wire.bytes; *legacy_length = wire.length-1; wire.bytes = NULL; valid = 1;
done:
    free(r.buffer); delivery_reuse_frame_free(wire.bytes,wire.length);
    if (!valid) { free(*candidate); *candidate = NULL; *candidate_length = 0; }
    return valid;
}
void delivery_reuse_candidate_free(struct delivery_reuse_candidate *candidate) {
    if (!candidate) return;
    delivery_reuse_recipe_free(candidate->recipe); free(candidate);
}
int delivery_reuse_candidate_parse(const char *body, size_t length, uint64_t occurrences,
    struct delivery_reuse_candidate **out) {
    struct reader r;
    struct delivery_reuse_candidate *candidate;
    unsigned seen = 0;
    int valid = 0;
    if (!out) return 0;
    *out = NULL;
    if (!body || !length || length == SIZE_MAX || !(r.buffer = malloc(length+1))) return 0;
    candidate = calloc(1,sizeof(*candidate));
    if (!candidate) { free(r.buffer); return 0; }
    memcpy(r.buffer,body,length); r.buffer[length] = 0; r.length = length; r.offset = 0;
    if (!take(&r,'{')) goto done;
    for (;;) {
        struct text key, value;
        unsigned bit;
        if (!string(&r,&key) || !take(&r,':')) goto done;
        if (equal(key,"version")) bit = 1;
        else if (equal(key,"requestId")) bit = 2;
        else if (equal(key,"challenge")) bit = 4;
        else if (equal(key,"recipe")) bit = 8;
        else if (equal(key,"inputEvidence")) bit = 16;
        else goto done;
        if (seen & bit) goto done;
        seen |= bit;
        if (bit == 1) {
            uint64_t version;
            if (!number(&r,&version) || version != 1) goto done;
        } else if (bit == 8) {
            size_t start;
            whitespace(&r); start = r.offset;
            if (!reuse_skip_value(&r) || !delivery_reuse_recipe_parse(body+start,r.offset-start,occurrences,&candidate->recipe)) goto done;
        } else {
            if (!string(&r,&value) || !reuse_hex64(value)) goto done;
            memcpy(bit == 2 ? candidate->request_id : bit == 4 ? candidate->challenge : candidate->input_evidence,value.data,64);
        }
        if (take(&r,'}')) break;
        if (!take(&r,',')) goto done;
    }
    whitespace(&r);
    if (seen != 31 || r.offset != length) goto done;
    *out = candidate; candidate = NULL; valid = 1;
done:
    free(r.buffer); delivery_reuse_candidate_free(candidate); return valid;
}
static void reuse_finalize_fields(const struct delivery_reuse_finalize_context *c, const char *fields[12]) {
    fields[0] = c->page.site_id; fields[1] = c->page.canonical_host; fields[2] = c->page.scope;
    fields[3] = c->page.epoch; fields[4] = c->incarnation; fields[5] = c->scope_revision;
    fields[6] = c->page.native_policy; fields[7] = c->page.wordpress_policy; fields[8] = c->page.reuse_policy;
    fields[9] = c->page.publication_digest; fields[10] = c->page.representation; fields[11] = c->page.recipe_digest;
}
int delivery_reuse_finalize_proof(const unsigned char key[32], const char *method,
    const char *url, const struct delivery_reuse_finalize_context *context, char proof[65]) {
    struct reuse_frame message = {NULL,0,0};
    const char *fields[12], *ids[3];
    size_t i;
    int valid = 0;
    if (proof) proof[0] = 0;
    if (!key || !context || !proof || !method || strcmp(method,"GET") || !delivery_relative(url)) return 0;
    reuse_finalize_fields(context,fields);
    ids[0] = context->request_id; ids[1] = context->challenge; ids[2] = context->delivery_request_id;
    if (!mutation_hex(ids[0],64) || !mutation_hex(ids[1],64) || !mutation_visible(ids[2]) ||
        !mutation_hex(context->binding,64) || !mutation_hex(context->input_evidence,64)) return 0;
    for (i = 0; i < 12; ++i)
        if (i == 0 ? !mutation_hex(fields[i],32) : i == 1 ? !mutation_visible(fields[i]) :
            i == 2 ? !delivery_selection_scope_valid(fields[i]) : !mutation_hex(fields[i],64)) return 0;
    if (!reuse_lp_string(&message,"ultracache-private-finalize-context-v1") ||
        !reuse_lp_string(&message,method) || !reuse_lp_string(&message,url)) goto done;
    for (i = 0; i < 3; ++i) if (!reuse_lp_string(&message,ids[i])) goto done;
    for (i = 0; i < 12; ++i) if (!reuse_lp_string(&message,fields[i])) goto done;
    if (!reuse_lp_string(&message,context->binding) || !reuse_lp_string(&message,context->input_evidence)) goto done;
    valid = delivery_hmac_sha256(key,32,message.bytes,message.length,proof);
done:
    delivery_reuse_frame_free(message.bytes,message.length); return valid;
}
int delivery_reuse_finalize_header(const unsigned char key[32], const char *method,
    const char *url, const struct delivery_reuse_finalize_context *context, char **header) {
    static const char *names[] = {"siteId","canonicalHost","scope","epoch","incarnation","scopeRevision",
        "nativePolicy","wordpressPolicy","reusePolicy","publicationDigest","representation","recipeDigest"};
    struct reuse_frame json = {NULL,0,0};
    const char *fields[12];
    char proof[65];
    size_t i;
    if (!header) return 0;
    *header = NULL;
    if (!delivery_reuse_finalize_proof(key,method,url,context,proof)) return 0;
    reuse_finalize_fields(context,fields);
#define REUSE_JSON_LITERAL(s) reuse_append(&json,s,sizeof(s)-1)
    if (!REUSE_JSON_LITERAL("{\"version\":1,\"requestId\":") || !mutation_json_string(&json,context->request_id) ||
        !REUSE_JSON_LITERAL(",\"challenge\":") || !mutation_json_string(&json,context->challenge) ||
        !REUSE_JSON_LITERAL(",\"deliveryRequestId\":") || !mutation_json_string(&json,context->delivery_request_id) ||
        !REUSE_JSON_LITERAL(",\"context\":{")) goto done;
    for (i = 0; i < 12; ++i)
        if ((i && !REUSE_JSON_LITERAL(",")) || !mutation_json_string(&json,names[i]) ||
            !REUSE_JSON_LITERAL(":") || !mutation_json_string(&json,fields[i])) goto done;
    if (!REUSE_JSON_LITERAL("},\"binding\":") || !mutation_json_string(&json,context->binding) ||
        !REUSE_JSON_LITERAL(",\"inputEvidence\":") || !mutation_json_string(&json,context->input_evidence) ||
        !REUSE_JSON_LITERAL(",\"proof\":") || !mutation_json_string(&json,proof) || !REUSE_JSON_LITERAL("}")) goto done;
    *header = mutation_base64(json.bytes,json.length);
#undef REUSE_JSON_LITERAL
done:
    delivery_reuse_frame_free(json.bytes,json.length); return *header != NULL;
}
