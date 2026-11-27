/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef UC_DELIVERY_REUSE_WIRE_H
#define UC_DELIVERY_REUSE_WIRE_H
#include "delivery_reuse_inputs.h"
struct delivery_reuse_candidate {
    char request_id[65], challenge[65], input_evidence[65];
    struct delivery_reuse_recipe *recipe;
};
struct delivery_reuse_finalize_context {
    struct delivery_reuse_context page;
    const char *incarnation, *scope_revision;
    const char *request_id, *challenge, *delivery_request_id;
    const char *binding, *input_evidence;
};
struct delivery_reuse_authority {
    struct delivery_reuse_authority *next;
    char tag[65], revision[65], generation[65];
};
struct delivery_reuse_admitted_fragment {
    struct delivery_reuse_admitted_fragment *next;
    char descriptor[65], identity_binding[65], owner[65], input_binding[65];
    char *url, *cache_key, *cache_tags;
    uint64_t cache_ttl, body_valid_until, identity_valid_until;
    struct delivery_reuse_inputs *identity_inputs;
    struct delivery_reuse_inputs *inputs; /* optional complete render-input declaration */
    char *inputs_json, *wire; /* declarations / authenticated row, never Cookie values */
    size_t wire_length;
    char **identity_tags;
    size_t identity_tag_count;
    unsigned anonymous; /* UID0 identity; tags may fence content, never a visitor map */
    struct delivery_reuse_authority *authority;
};
struct delivery_reuse_record {
    char *request_id, *original_url;
    char *context[12]; /* exact frozen field order; owned strings */
    char binding[65];
    uint64_t valid_until, cookie_valid_until;
    struct delivery_reuse_recipe *recipe;
    char *recipe_json; size_t recipe_length; /* declarations only, never Cookie/body */
    struct delivery_reuse_admitted_fragment *fragments;
};
/* The split preserves every legacy member byte-for-byte. The optional member
 * may fail independently; malformed JSON remains a malformed transport. A
 * duplicate optional member is discarded in its entirety, never last-wins. */
int delivery_reuse_envelope_split(const char *, size_t, char **, size_t *, char **, size_t *);
int delivery_reuse_candidate_parse(const char *, size_t, uint64_t, struct delivery_reuse_candidate **);
void delivery_reuse_candidate_free(struct delivery_reuse_candidate *);
int delivery_reuse_finalize_proof(const unsigned char key[32], const char *method,
    const char *url, const struct delivery_reuse_finalize_context *, char proof[65]);
int delivery_reuse_finalize_header(const unsigned char key[32], const char *method,
    const char *url, const struct delivery_reuse_finalize_context *, char **header);
int delivery_reuse_record_parse(const char *, size_t, struct delivery_reuse_record **);
void delivery_reuse_record_free(struct delivery_reuse_record *);
void delivery_reuse_admitted_free(struct delivery_reuse_admitted_fragment *);
int delivery_reuse_metadata_key(const struct delivery_reuse_context *, const char *binding, char key[65]);
#endif
