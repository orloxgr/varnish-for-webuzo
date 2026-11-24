/* SPDX-License-Identifier: GPL-3.0-or-later
 * Strict metadata-only grammar; native scope, authority and HSH checks remain
 * mandatory. Successful parsing is never a cache-admission grant.
 */
static const char *reuse_context_names[] = {"siteId","canonicalHost","scope","epoch","incarnation","scopeRevision",
    "nativePolicy","wordpressPolicy","reusePolicy","publicationDigest","representation","recipeDigest"};
void delivery_reuse_record_free(struct delivery_reuse_record *record) {
    size_t i;
    if (!record) return;
    for (i = 0; i < 12; ++i) free(record->context[i]);
    while (record->fragments) {
        struct delivery_reuse_admitted_fragment *f = record->fragments;
        record->fragments = f->next;
        while (f->authority) { struct delivery_reuse_authority *next = f->authority->next; free(f->authority); f->authority = next; }
        for (i = 0; i < f->identity_tag_count; ++i) free(f->identity_tags[i]);
        free(f->identity_tags); delivery_reuse_inputs_free(f->identity_inputs);
        free(f->url); free(f->cache_key); free(f->cache_tags); free(f);
    }
    free(record->request_id); free(record->original_url); free(record->recipe_json);
    delivery_reuse_recipe_free(record->recipe); free(record);
}
static int reuse_metadata_context(struct reader *r, struct delivery_reuse_record *record) {
    unsigned seen = 0;
    if (!take(r,'{')) return 0;
    for (;;) {
        struct text key, value;
        size_t i;
        if (!string(r,&key) || !take(r,':') || !string(r,&value) || strlen(value.data) != value.length) return 0;
        for (i = 0; i < 12; ++i) if (equal(key,reuse_context_names[i])) break;
        if (i == 12 || (seen & (1u<<i))) return 0;
        seen |= 1u<<i;
        if (i == 0 ? !mutation_hex(value.data,32) : i == 1 ? !mutation_visible(value.data) :
            i == 2 ? !delivery_selection_scope_valid(value.data) : !reuse_hex64(value)) return 0;
        record->context[i] = copy(value);
        if (!record->context[i]) return 0;
        if (take(r,'}')) break;
        if (!take(r,',')) return 0;
    }
    return seen == 4095;
}
static int reuse_metadata_identity(struct reader *r, const char *body, struct delivery_reuse_admitted_fragment *f) {
    unsigned seen = 0, owner_null = 0;
    if (!take(r,'{')) return 0;
    for (;;) {
        struct text key, value;
        unsigned bit;
        if (!string(r,&key) || !take(r,':')) return 0;
        if (equal(key,"identityState")) bit = 1;
        else if (equal(key,"identityInputs")) bit = 2;
        else if (equal(key,"identityBinding")) bit = 4;
        else if (equal(key,"owner")) bit = 8;
        else if (equal(key,"tags")) bit = 16;
        else if (equal(key,"validUntil")) bit = 32;
        else return 0;
        if (seen & bit) return 0;
        seen |= bit;
        if (bit == 1) {
            if (!string(r,&value)) return 0;
            if (equal(value,"anonymous")) f->anonymous = 1;
            else if (!equal(value,"personal")) return 0;
        }
        else if (bit == 2) {
            size_t start;
            whitespace(r); start = r->offset;
            if (!reuse_skip_value(r) || delivery_reuse_inputs_parse(body+start,r->offset-start,&f->identity_inputs) != DELIVERY_REUSE_INPUT_OK) return 0;
        } else if (bit == 32) { if (!number(r,&f->identity_valid_until) || !f->identity_valid_until) return 0; }
        else if (bit == 16) {
            if (!take(r,'[')) return 0;
            if (!take(r,']')) for (;;) {
                char **grown;
                size_t i;
                if (!string(r,&value) || !reuse_hex64(value) || f->identity_tag_count == SIZE_MAX/sizeof(*grown)) return 0;
                for (i = 0; i < f->identity_tag_count; ++i) if (!strcmp(f->identity_tags[i],value.data)) return 0;
                grown = realloc(f->identity_tags,(f->identity_tag_count+1)*sizeof(*grown));
                if (!grown) return 0;
                f->identity_tags = grown; grown[f->identity_tag_count] = copy(value);
                if (!grown[f->identity_tag_count]) return 0;
                ++f->identity_tag_count;
                if (take(r,']')) break;
                if (!take(r,',')) return 0;
            }
        } else {
            whitespace(r);
            if (bit == 8 && r->length-r->offset >= 4 && !memcmp(r->buffer+r->offset,"null",4)) {
                r->offset += 4; owner_null = 1;
            } else {
                if (!string(r,&value) || !reuse_hex64(value)) return 0;
                memcpy(bit == 4 ? f->identity_binding : f->owner,value.data,64);
            }
        }
        if (take(r,'}')) break;
        if (!take(r,',')) return 0;
    }
    if (seen == 63) {
        size_t i;
        /* Anonymous fixes visitor identity, not content immutability. Its tags
         * may name mutable content, but never manufacture a visitor owner.
         * Exact authority coverage and runtime revisions are checked below. */
        if (f->anonymous) return owner_null;
        if (owner_null) return 0;
        for (i = 0; i < f->identity_tag_count; ++i) if (!strcmp(f->identity_tags[i],f->owner)) return 1;
    }
    return 0;
}
static int reuse_metadata_authority(struct reader *r, struct delivery_reuse_admitted_fragment *f) {
    if (!take(r,'[')) return 0;
    if (take(r,']')) return 1;
    for (;;) {
        struct delivery_reuse_authority *a = calloc(1,sizeof(*a)), *other;
        unsigned seen = 0;
        if (!a) return 0;
        a->next = f->authority; f->authority = a;
        if (!take(r,'{')) return 0;
        for (;;) {
            struct text key, value;
            unsigned bit;
            if (!string(r,&key) || !take(r,':') || !string(r,&value) || !reuse_hex64(value)) return 0;
            if (equal(key,"tag")) bit = 1;
            else if (equal(key,"revision")) bit = 2;
            else if (equal(key,"generation")) bit = 4;
            else return 0;
            if (seen & bit) return 0;
            seen |= bit;
            memcpy(bit == 1 ? a->tag : bit == 2 ? a->revision : a->generation,value.data,64);
            if (take(r,'}')) break;
            if (!take(r,',')) return 0;
        }
        if (seen != 7) return 0;
        for (other = a->next; other; other = other->next) if (!strcmp(other->tag,a->tag)) return 0;
        if (take(r,']')) return 1;
        if (!take(r,',')) return 0;
    }
}
static int reuse_metadata_fragments(struct reader *r, const char *body, struct delivery_reuse_record *record) {
    if (!take(r,'[')) return 0;
    if (take(r,']')) return 1;
    for (;;) {
        struct delivery_reuse_admitted_fragment *f = calloc(1,sizeof(*f));
        unsigned seen = 0;
        if (!f) return 0;
        f->next = record->fragments; record->fragments = f;
        if (!take(r,'{')) return 0;
        for (;;) {
            struct text key, value;
            unsigned bit;
            if (!string(r,&key) || !take(r,':')) return 0;
            if (equal(key,"descriptor")) bit = 1;
            else if (equal(key,"url")) bit = 2;
            else if (equal(key,"cache")) bit = 4;
            else if (equal(key,"bodyValidUntil")) bit = 8;
            else if (equal(key,"identity")) bit = 16;
            else if (equal(key,"authority")) bit = 32;
            else return 0;
            if (seen & bit) return 0;
            seen |= bit;
            if (bit == 1 || bit == 2) {
                if (!string(r,&value) || strlen(value.data) != value.length ||
                    (bit == 1 ? !reuse_hex64(value) : !delivery_relative(value.data))) return 0;
                if (bit == 1) memcpy(f->descriptor,value.data,64);
                else if (!(f->url = copy(value))) return 0;
            } else if (bit == 4) {
                struct text cache_key, tags;
                if (!private_cache(r,&cache_key,&tags,&f->cache_ttl) || !f->cache_ttl ||
                    !(f->cache_key = copy(cache_key)) || !(f->cache_tags = copy(tags))) return 0;
            } else if (bit == 8) { if (!number(r,&f->body_valid_until) || !f->body_valid_until) return 0; }
            else if (bit == 16) { if (!reuse_metadata_identity(r,body,f)) return 0; }
            else if (!reuse_metadata_authority(r,f)) return 0;
            if (take(r,'}')) break;
            if (!take(r,',')) return 0;
        }
        if (seen != 63) return 0;
        if (take(r,']')) return 1;
        if (!take(r,',')) return 0;
    }
}
static int reuse_metadata_admission(struct reader *r, const char *body, struct delivery_reuse_record *record) {
    unsigned seen = 0;
    if (!take(r,'{')) return 0;
    for (;;) {
        struct text key, value;
        unsigned bit;
        if (!string(r,&key) || !take(r,':')) return 0;
        if (equal(key,"binding")) bit = 1;
        else if (equal(key,"validUntil")) bit = 2;
        else if (equal(key,"cookieWork")) bit = 4;
        else if (equal(key,"fragments")) bit = 8;
        else return 0;
        if (seen & bit) return 0;
        seen |= bit;
        if (bit == 1) {
            if (!string(r,&value) || !reuse_hex64(value)) return 0;
            memcpy(record->binding,value.data,64);
        } else if (bit == 2) { if (!number(r,&record->valid_until) || !record->valid_until) return 0; }
        else if (bit == 4) {
            unsigned work = 0;
            if (!take(r,'{')) return 0;
            for (;;) {
                unsigned field;
                if (!string(r,&key) || !take(r,':')) return 0;
                if (equal(key,"state")) field = 1;
                else if (equal(key,"validUntil")) field = 2;
                else return 0;
                if (work & field) return 0;
                work |= field;
                if (field == 1) { if (!string(r,&value) || !equal(value,"none")) return 0; }
                else if (!number(r,&record->cookie_valid_until) || !record->cookie_valid_until) return 0;
                if (take(r,'}')) break;
                if (!take(r,',')) return 0;
            }
            if (work != 3) return 0;
        } else if (!reuse_metadata_fragments(r,body,record)) return 0;
        if (take(r,'}')) break;
        if (!take(r,',')) return 0;
    }
    return seen == 15;
}
static int reuse_metadata_reuse(struct reader *r, const char *body, struct delivery_reuse_record *record) {
    unsigned seen = 0;
    if (!take(r,'{')) return 0;
    for (;;) {
        struct text key;
        unsigned bit;
        if (!string(r,&key) || !take(r,':')) return 0;
        if (equal(key,"version")) bit = 1;
        else if (equal(key,"context")) bit = 2;
        else if (equal(key,"recipe")) bit = 4;
        else if (equal(key,"admission")) bit = 8;
        else return 0;
        if (seen & bit) return 0;
        seen |= bit;
        if (bit == 1) { uint64_t version; if (!number(r,&version) || version != 1) return 0; }
        else if (bit == 2) { if (!reuse_metadata_context(r,record)) return 0; }
        else if (bit == 4) {
            size_t start;
            whitespace(r); start = r->offset;
            if (!reuse_skip_value(r)) return 0;
            record->recipe_length = r->offset-start;
            record->recipe_json = malloc(record->recipe_length+1);
            if (!record->recipe_json) return 0;
            memcpy(record->recipe_json,body+start,record->recipe_length); record->recipe_json[record->recipe_length] = 0;
        } else if (!reuse_metadata_admission(r,body,record)) return 0;
        if (take(r,'}')) break;
        if (!take(r,',')) return 0;
    }
    return seen == 15;
}
int delivery_reuse_record_parse(const char *body, size_t length, struct delivery_reuse_record **out) {
    struct reader r;
    struct delivery_reuse_record *record;
    struct delivery_reuse_admitted_fragment *f, *other;
    const struct delivery_reuse_descriptor *descriptor;
    uint64_t total = 0;
    unsigned seen = 0;
    size_t count = 0, expected = 0;
    int valid = 0;
    if (!out) return 0;
    *out = NULL;
    if (!body || !length || length == SIZE_MAX || !(r.buffer = malloc(length+1))) return 0;
    record = calloc(1,sizeof(*record));
    if (!record) { free(r.buffer); return 0; }
    memcpy(r.buffer,body,length); r.buffer[length] = 0; r.length = length; r.offset = 0;
    if (!take(&r,'{')) goto done;
    for (;;) {
        struct text key, value;
        unsigned bit;
        if (!string(&r,&key) || !take(&r,':')) goto done;
        if (equal(key,"schemaVersion")) bit = 1;
        else if (equal(key,"requestId")) bit = 2;
        else if (equal(key,"originalUrl")) bit = 4;
        else if (equal(key,"reuse")) bit = 8;
        else goto done;
        if (seen & bit) goto done;
        seen |= bit;
        if (bit == 1) { uint64_t version; if (!number(&r,&version) || version != 1) goto done; }
        else if (bit == 8) { if (!reuse_metadata_reuse(&r,body,record)) goto done; }
        else {
            if (!string(&r,&value) || strlen(value.data) != value.length ||
                (bit == 2 ? !mutation_visible(value.data) : !delivery_relative(value.data))) goto done;
            if (bit == 2) record->request_id = copy(value); else record->original_url = copy(value);
            if (bit == 2 ? !record->request_id : !record->original_url) goto done;
        }
        if (take(&r,'}')) break;
        if (!take(&r,',')) goto done;
    }
    whitespace(&r);
    if (seen != 15 || r.offset != length || record->valid_until > record->cookie_valid_until) goto done;
    /* Expected count comes from the complete canonical recipe, not the metadata
     * rows (which intentionally have no HTML or repeated occurrence counts). */
    if (!reuse_recipe_read(record->recipe_json,record->recipe_length,NULL,&record->recipe)) goto done;
    if (strcmp(record->recipe->digest,record->context[11])) goto done;
    for (descriptor = record->recipe->fragments; descriptor; descriptor = descriptor->next) {
        ++expected;
        for (f = record->fragments; f; f = f->next) if (!strcmp(f->descriptor,descriptor->descriptor) && !strcmp(f->url,descriptor->url)) break;
        if (!f) goto done;
        if (UINT64_MAX-total < descriptor->occurrences) goto done;
        total += descriptor->occurrences;
    }
    for (f = record->fragments; f; f = f->next) {
        const struct delivery_reuse_authority *a;
        size_t authorities = 0, i;
        ++count;
        if (record->valid_until > f->body_valid_until || record->valid_until > f->identity_valid_until) goto done;
        for (other = f->next; other; other = other->next)
            if (!strcmp(other->descriptor,f->descriptor) || !strcmp(other->url,f->url)) goto done;
        for (a = f->authority; a; a = a->next) {
            ++authorities;
            for (i = 0; i < f->identity_tag_count; ++i) if (!strcmp(f->identity_tags[i],a->tag)) break;
            if (i == f->identity_tag_count) goto done;
        }
        if (authorities != f->identity_tag_count) goto done;
    }
    if (count != expected || total != record->recipe->occurrences) goto done;
    *out = record; record = NULL; valid = 1;
done:
    free(r.buffer); delivery_reuse_record_free(record); return valid;
}
int delivery_reuse_metadata_key(const struct delivery_reuse_context *context, const char *binding, char key[65]) {
    struct reuse_frame frame = {NULL,0,0};
    const char *fields[10];
    size_t i;
    int valid = 0;
    if (!context || !key || !mutation_hex(binding,64)) return 0;
    fields[0] = context->site_id; fields[1] = context->canonical_host; fields[2] = context->scope;
    fields[3] = context->epoch; fields[4] = context->native_policy; fields[5] = context->wordpress_policy;
    fields[6] = context->reuse_policy; fields[7] = context->representation;
    fields[8] = context->recipe_digest; fields[9] = binding;
    /* Private admissions follow the exact recipe/representation and provider
     * inputs, independently of an unrelated public HTML generation. */
    if (!reuse_lp_string(&frame,"ultracache-private-admission-object-v3")) goto done;
    for (i = 0; i < 10; ++i) if (!fields[i] || !*fields[i] || !reuse_lp_string(&frame,fields[i])) goto done;
    valid = delivery_selection_digest(frame.bytes,frame.length,key);
done:
    delivery_reuse_frame_free(frame.bytes,frame.length); return valid;
}
