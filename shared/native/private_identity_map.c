/* SPDX-License-Identifier: GPL-3.0-or-later
 * Generic revoke-only provenance from fully accepted actual finalizations.
 * No Cookie/frame/body persistence, known-empty inference or admission grant.
 */
struct reuse_identity_entry {
    struct reuse_identity_entry *next;
    char binding[65], owner[65];
    char **tags;
    size_t count;
    uint64_t valid_until;
};
struct reuse_identity_schema {
    struct reuse_identity_schema *next;
    char declaration[65];
    struct delivery_reuse_inputs *inputs;
    struct reuse_identity_entry **entries;
    size_t capacity, count;
};
static void reuse_identity_entry_free(struct reuse_identity_entry *entry) {
    size_t i;
    for (i = 0; i < entry->count; ++i) free(entry->tags[i]);
    free(entry->tags); free(entry);
}
static void reuse_identity_schema_free(struct reuse_identity_schema *schema) {
    size_t i;
    for (i = 0; i < schema->capacity; ++i) while (schema->entries[i]) {
        struct reuse_identity_entry *entry = schema->entries[i];
        schema->entries[i] = entry->next; reuse_identity_entry_free(entry);
    }
    free(schema->entries); delivery_reuse_inputs_free(schema->inputs); free(schema);
}
static void reuse_identity_free(struct reuse_scope *scope) {
    while (scope->identity_schemas) {
        struct reuse_identity_schema *schema = scope->identity_schemas;
        scope->identity_schemas = schema->next; reuse_identity_schema_free(schema);
    }
}
#ifdef UC_NATIVE_PRIVATE_REUSE
static struct delivery_reuse_inputs *reuse_identity_inputs_copy(const struct delivery_reuse_inputs *source) {
    struct delivery_reuse_inputs *copy = calloc(1,sizeof(*copy));
    size_t i;
    if (!copy) return NULL;
    copy->php_max_input_vars = source->php_max_input_vars;
    if (source->name_count && !(copy->names = calloc(source->name_count,sizeof(*copy->names)))) goto failed;
    if (source->prefix_count && !(copy->prefixes = calloc(source->prefix_count,sizeof(*copy->prefixes)))) goto failed;
    for (i = 0; i < source->name_count; ++i) {
        copy->names[i] = strdup(source->names[i]);
        if (!copy->names[i]) goto failed;
        ++copy->name_count;
    }
    for (i = 0; i < source->prefix_count; ++i) {
        copy->prefixes[i] = strdup(source->prefixes[i]);
        if (!copy->prefixes[i]) goto failed;
        ++copy->prefix_count;
    }
    return copy;
failed:
    delivery_reuse_inputs_free(copy); return NULL;
}
static int reuse_identity_grow(struct reuse_identity_schema *schema) {
    size_t capacity = schema->capacity ? schema->capacity*2 : 16, i;
    struct reuse_identity_entry **buckets;
    if (capacity < schema->capacity || capacity > SIZE_MAX/sizeof(*buckets) ||
        !(buckets = calloc(capacity,sizeof(*buckets)))) return 0;
    for (i = 0; i < schema->capacity; ++i) {
        struct reuse_identity_entry *entry = schema->entries[i];
        while (entry) {
            struct reuse_identity_entry *next = entry->next;
            size_t bucket = reuse_hash(entry->binding)%capacity;
            entry->next = buckets[bucket]; buckets[bucket] = entry; entry = next;
        }
    }
    free(schema->entries); schema->entries = buckets; schema->capacity = capacity; return 1;
}
static int reuse_identity_same_tags(const struct reuse_identity_entry *entry, const struct delivery_reuse_admitted_fragment *fragment) {
    size_t i, j;
    if (entry->count != fragment->identity_tag_count) return 0;
    for (i = 0; i < entry->count; ++i) {
        for (j = 0; j < fragment->identity_tag_count; ++j) if (!strcmp(entry->tags[i],fragment->identity_tags[j])) break;
        if (j == fragment->identity_tag_count) return 0;
    }
    return 1;
}
#endif
#ifdef UC_NATIVE_PRIVATE_REUSE
static int reuse_identity_install(struct reuse_scope *scope, const struct delivery_reuse_record *record) {
    const struct delivery_reuse_admitted_fragment *fragment;
    for (fragment = record->fragments; fragment; fragment = fragment->next) {
        struct reuse_identity_schema *schema;
        struct reuse_identity_entry *entry;
        unsigned char *frame = NULL;
        size_t length = 0, i, bucket;
        char declaration[65];
        /* Anonymous is an authenticated per-document body/input fact only.
         * Even when it depends on mutable content tags, it must not install
         * a visitor owner/revoke map, known-empty map or route coverage. */
        if (fragment->anonymous) continue;
        if (delivery_reuse_input_projection(fragment->identity_inputs,NULL,0,&frame,&length) != DELIVERY_REUSE_INPUT_OK) return 0;
        i = delivery_selection_digest(frame,length,declaration);
        delivery_reuse_frame_free(frame,length);
        if (!i) return 0;
        for (schema = scope->identity_schemas; schema; schema = schema->next)
            if (!strcmp(schema->declaration,declaration)) break;
        if (!schema) {
            schema = calloc(1,sizeof(*schema));
            if (!schema || !(schema->inputs = reuse_identity_inputs_copy(fragment->identity_inputs))) { free(schema); return 0; }
            memcpy(schema->declaration,declaration,65); schema->next = scope->identity_schemas; scope->identity_schemas = schema;
        }
        if ((!schema->capacity || schema->count >= schema->capacity-schema->capacity/4) && !reuse_identity_grow(schema)) return 0;
        bucket = reuse_hash(fragment->identity_binding)%schema->capacity;
        for (entry = schema->entries[bucket]; entry; entry = entry->next)
            if (!strcmp(entry->binding,fragment->identity_binding) && !strcmp(entry->owner,fragment->owner) &&
                reuse_identity_same_tags(entry,fragment)) break;
        if (entry) {
            /* Each proof independently attests this identity boundary. This is
             * revoke provenance, never a body/admission lifetime extension. */
            if (fragment->identity_valid_until > entry->valid_until) entry->valid_until = fragment->identity_valid_until;
            continue;
        }
        entry = calloc(1,sizeof(*entry));
        if (!entry) return 0;
        entry->tags = calloc(fragment->identity_tag_count,sizeof(*entry->tags));
        if (!entry->tags) { free(entry); return 0; }
        for (i = 0; i < fragment->identity_tag_count; ++i) {
            entry->tags[i] = strdup(fragment->identity_tags[i]);
            if (!entry->tags[i]) { reuse_identity_entry_free(entry); return 0; }
            ++entry->count;
        }
        memcpy(entry->binding,fragment->identity_binding,65); memcpy(entry->owner,fragment->owner,65);
        entry->valid_until = fragment->identity_valid_until;
        entry->next = schema->entries[bucket]; schema->entries[bucket] = entry; ++schema->count;
    }
    return 1;
}
#endif
static void reuse_identity_prearm(struct reuse_scope *scope, struct mutation_execution *execution, const char *cookie) {
#ifdef UC_NATIVE_PRIVATE_REUSE
    struct reuse_identity_schema *schema;
    struct delivery_reuse_context context = {scope->site,scope->host,scope->scope,public_registry_epoch,
        scope->native_policy,scope->wordpress_policy,scope->policy,NULL,NULL,NULL};
    for (schema = scope->identity_schemas; schema; schema = schema->next) {
        unsigned char *frame = NULL;
        size_t length = 0;
        struct reuse_identity_entry **position;
        char binding[65];
        int valid;
        if (!schema->capacity || delivery_reuse_input_projection(schema->inputs,(const unsigned char *)(cookie ? cookie : ""),
            cookie ? strlen(cookie) : 0,&frame,&length) != DELIVERY_REUSE_INPUT_OK) continue;
        valid = delivery_reuse_identity_mac(scope->reuse_key,&context,frame,length,binding);
        delivery_reuse_frame_free(frame,length);
        if (!valid) continue;
        position = &schema->entries[reuse_hash(binding)%schema->capacity];
        while (*position) {
            struct reuse_identity_entry *entry = *position;
            size_t i;
            if ((double)entry->valid_until <= VTIM_real()) {
                *position = entry->next; --schema->count; reuse_identity_entry_free(entry); continue;
            }
            position = &entry->next;
            if (strcmp(entry->binding,binding)) continue;
            for (i = 0; i < entry->count; ++i) {
                struct reuse_execution_tag *fence;
                struct reuse_tag *tag;
                char revision[65];
                for (fence = execution->known_tags; fence; fence = fence->next) if (!strcmp(fence->id,entry->tags[i])) break;
                if (fence) continue;
                fence = calloc(1,sizeof(*fence)); tag = reuse_tag_find(scope,entry->tags[i],1);
                if (!fence || !tag || !reuse_random_id(revision)) { free(fence); continue; }
                memcpy(fence->id,entry->tags[i],65); fence->next = execution->known_tags; execution->known_tags = fence;
                memcpy(tag->revision,revision,65); tag->clean = 0;
            }
        }
    }
    /* A positive match revokes known tags only. It does not clear unknown,
     * recover the scope, close other actors or assert complete route coverage. */
#else
    (void)scope; (void)execution; (void)cookie;
#endif
}
