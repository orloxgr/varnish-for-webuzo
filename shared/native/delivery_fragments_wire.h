/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef UC_DELIVERY_FRAGMENTS_WIRE_H
#define UC_DELIVERY_FRAGMENTS_WIRE_H
#include "delivery_envelope.h"

/* Public request metadata. Parsing is not signature or owner authorization. */
struct delivery_fragment_request {
    struct delivery_fragment_request *next;
    char *url;
    uint64_t occurrences;
};
struct delivery_fragment_batch {
    char *source_url;
    char *context[5]; /* existing policy/bucket/cookies/locale/language codec */
    char digest[65];
    uint64_t occurrences;
    struct delivery_fragment_request *requested;
};
struct delivery_fragment_failure {
    struct delivery_fragment_failure *next;
    char *url, *code;
    uint64_t occurrences;
    unsigned status;
};
struct delivery_reuse_authority;
struct delivery_fragment_grant {
    struct delivery_fragment_grant *next;
    char *url;
    struct delivery_reuse_authority *authority;
};
struct delivery_fragment_authority {
    char *scope;
    char epoch[65], incarnation[65], scope_revision[65];
    char native_policy[65], wordpress_policy[65], reuse_policy[65];
    struct delivery_fragment_grant *fragments;
};
struct delivery_fragment_results {
    struct delivery_fragment *rendered;
    struct delivery_fragment_failure *failed;
    struct delivery_fragment_authority *authority;
};

/* Extract only the one literal batch query argument, raw-decoded exactly once.
 * The exact index path is checked against authenticated registration by caller. */
char *delivery_fragment_batch_token(const char *uri);
int delivery_fragment_batch_parse(const char *token, size_t length,
    struct delivery_fragment_batch **out);
/* Compressed tickets additionally require the matched registered scope's
 * existing purpose-separated key before any output allocation/inflation. */
int delivery_fragment_batch_parse_scoped(const char *token, size_t length,
    const unsigned char key[32], const char *scope, struct delivery_fragment_batch **out);
void delivery_fragment_batch_free(struct delivery_fragment_batch *batch);
void delivery_fragment_results_free(struct delivery_fragment_results *results);
int delivery_fragment_envelope_parse_v1(const char *body, size_t length,
    const char *request_id, const char *original_url,
    const struct delivery_fragment_batch *batch, struct delivery_fragment_results **out);

/* Browser projection only: never emits cache claims or control credentials.
 * Call only after task binding, complete-set and authority checks. */
int delivery_fragment_results_json(const struct delivery_fragment_batch *batch,
    const struct delivery_fragment_results *results, char **body, size_t *length);
#endif
