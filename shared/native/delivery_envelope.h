/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef UC_DELIVERY_ENVELOPE_H
#define UC_DELIVERY_ENVELOPE_H
#include <stddef.h>
#include <stdint.h>

struct delivery_fragment {
    struct delivery_fragment *next;
    char *url;
    char *html;
    size_t length;
    char *cache_key; /* optional authenticated application claim, never public */
    char *cache_tags;
    uint64_t cache_ttl;
    uint64_t occurrences; /* exact authenticated renderer coverage */
    double cache_deadline; /* optional actual absolute body deadline, never slid */
    unsigned cache_anonymous; /* explicit schema2 anonymous identity; dependencies are separate */
};
struct delivery_public_parent {
    char generation[65];
    unsigned char *body;
    size_t length;
    uint64_t fresh_remaining;
};
struct delivery_private_document {
    unsigned char *body;
    size_t length;
    char *content_type;
    unsigned status;
};
struct delivery_cookie_update {
    struct delivery_cookie_update *next;
    char *name, *value; /* NULL value is absence, never a new cookie action. */
};
struct delivery_header {
    struct delivery_header *next;
    char *line;
};
struct delivery_public_projection {
    char *bucket, *locale, *language;
    struct delivery_cookie_update *cookies; /* actual sorted Variant wire values */
};
void delivery_public_projection_free(struct delivery_public_projection *projection);
int delivery_public_projection_parse(const char *body, size_t length,
    struct delivery_public_projection **projection);
int delivery_public_projection_header_parse(const char *header, size_t length,
    struct delivery_public_projection **projection);
char *delivery_public_projection_header(const struct delivery_public_projection *projection);
int delivery_public_projection_equal(const struct delivery_public_projection *a,
    const struct delivery_public_projection *b);
char *delivery_public_projection_cookie(const struct delivery_public_projection *projection,
    const char *rules);
int delivery_public_projection_candidate(const struct delivery_public_projection *projection,
    const char *original, const char *rules, char **candidate);
struct delivery_public_selection {
    char policy[65], wordpress_policy[65];
    char *manifest, *target;
    uint64_t occurrences;
    unsigned cookie_delivery;
    unsigned guest;
    struct delivery_cookie_update *updates;
    struct delivery_header *headers;
    struct delivery_public_parent *parent;
    struct delivery_fragment *fragments;
    unsigned source_only; /* explicit public parent role, never private completion */
    struct delivery_public_projection *resolved;
    struct delivery_reuse_recipe *guest_inputs; /* optional negotiated complete guest closure */
    char *guest_source_manifest;
    char guest_source_generation[65];
};
enum delivery_projected_role {
    DELIVERY_PROJECTED_PERSONAL, DELIVERY_PROJECTED_PARENT, DELIVERY_PROJECTED_RESOLVER
};
int delivery_projected_selection_parse(const char *body, size_t length,
    const char *request_id, const char *original_url, const char *policy, const char *wordpress_policy,
    enum delivery_projected_role role, struct delivery_public_selection **selection,
    struct delivery_private_document **document, struct delivery_public_projection **resolved_only);
/* Separate entry/outcome: never weakens delivery_envelope_parse's v1 binding. */
int delivery_selection_parse(const char *body, size_t length,
    const char *request_id, const char *original_url, const char *policy, const char *wordpress_policy,
    struct delivery_public_selection **selection,
    struct delivery_private_document **document);
int delivery_public_source_parse(const char *body, size_t length,
    const char *request_id, const char *source_url, const char *policy, const char *wordpress_policy,
    struct delivery_public_selection **selection);
int delivery_guest_selection_parse(const char *body, size_t length,
    const char *request_id, const char *original_url, const char *policy, const char *wordpress_policy,
    const char *guest_policy, const char *epoch, const char *scope,
    struct delivery_public_selection **selection);
/* Optional caller-owned first failure. Only fixed diagnostic literals are
 * returned; the existing Boolean parser entry points remain unchanged. */
int delivery_selection_parse_diagnostic(const char *body, size_t length,
    const char *request_id, const char *original_url, const char *policy, const char *wordpress_policy,
    struct delivery_public_selection **selection, struct delivery_private_document **document,
    const char **reason);
int delivery_public_source_parse_diagnostic(const char *body, size_t length,
    const char *request_id, const char *source_url, const char *policy, const char *wordpress_policy,
    struct delivery_public_selection **selection, const char **reason);
int delivery_projected_selection_parse_diagnostic(const char *body, size_t length,
    const char *request_id, const char *original_url, const char *policy, const char *wordpress_policy,
    enum delivery_projected_role role, struct delivery_public_selection **selection,
    struct delivery_private_document **document, struct delivery_public_projection **resolved_only,
    const char **reason);
int delivery_guest_selection_parse_diagnostic(const char *body, size_t length,
    const char *request_id, const char *original_url, const char *policy, const char *wordpress_policy,
    const char *guest_policy, const char *epoch, const char *scope,
    struct delivery_public_selection **selection, const char **reason);
void delivery_selection_free(struct delivery_public_selection *selection);
/* Ordered action TAB kind TAB literal-name LF, from the effective resolver. */
int delivery_selection_candidate(const struct delivery_public_selection *selection,
    const char *original, const char *rules, char **candidate);
int delivery_cookie_name(const char *name, size_t length);
int delivery_selection_scope_valid(const char *scope);
int delivery_selection_scope_matches(const char *scope, const char *url);
/* 0 Shared (including existing fallback), 1 Variant, 2 Private; -1 bad rules. */
int delivery_cookie_action(const char *rules, const char *name, size_t length);
int delivery_selection_all_shared(const char *original, const char *rules);
int delivery_selection_all_public(const char *original, const char *rules);
char *delivery_selection_projection(const char *candidate, const char *rules);
int delivery_selection_digest(const unsigned char *body, size_t length, char digest[65]);
int delivery_hmac_sha256(const unsigned char *key, size_t key_length,
    const unsigned char *body, size_t length, char digest[65]);

/* A fixed-schema parser for delivery v1 only. No engine JSON internals.
 * Strings are strict UTF-8/JSON with UTF-16 surrogate-pair decoding. Embedded
 * NUL is retained in HTML bytes but forbidden in binding text and URLs.
 * Output is all-or-nothing and owned by the caller on success. */
int delivery_envelope_parse(const char *body, size_t length,
    const char *request_id, const char *original_url, uint64_t occurrences,
    struct delivery_fragment **output, struct delivery_public_parent **public_parent,
    struct delivery_private_document **document);
int delivery_cookie_envelope_parse(const char *body, size_t length,
    const char *request_id, const char *original_url, uint64_t occurrences, int cookie_delivery,
    struct delivery_fragment **output, struct delivery_public_parent **public_parent,
    struct delivery_private_document **document);
void delivery_public_parent_free(struct delivery_public_parent *parent);
void delivery_private_document_free(struct delivery_private_document *document);
/* Overflow-checked native buffer growth, with no product byte-size cap. */
int delivery_buffer_growth(size_t used, size_t capacity, size_t chunk,
    size_t *needed, size_t *target_capacity);
int delivery_relative(const char *url);
/* The pointer is metadata only. Decode its one literal ultracache_delivery
 * value once using raw URL semantics; return owned printable-ASCII token. */
char *delivery_manifest_token(const char *pointer);
void delivery_manifest_free(char *token);
void delivery_free_fragments(struct delivery_fragment *fragment);
#endif
