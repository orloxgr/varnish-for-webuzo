/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef UC_DELIVERY_MUTATION_WIRE_H
#define UC_DELIVERY_MUTATION_WIRE_H
#include <stddef.h>
struct delivery_mutation_context {
    const char *site_id, *host, *scope_digest, *epoch, *incarnation;
    const char *native_policy, *wordpress_policy, *reuse_policy;
    const char *request_id, *challenge, *method, *url;
};
struct delivery_mutation_pair {
    struct delivery_mutation_pair *next;
    char tag[65], transaction[65];
};
enum delivery_mutation_state { MUTATION_NONE, MUTATION_DIRTY, MUTATION_SCOPE };
struct delivery_mutation_receipt {
    enum delivery_mutation_state state;
    struct delivery_mutation_pair *pairs;
    size_t count;
};
int delivery_mutation_key(const unsigned char *secret, size_t length, unsigned char key[32]);
int delivery_mutation_request_proof(const unsigned char key[32],
    const struct delivery_mutation_context *context, char proof[65]);
int delivery_mutation_context_header(const unsigned char key[32],
    const struct delivery_mutation_context *context, char **header, char proof[65]);
int delivery_mutation_receipt_verify(const unsigned char key[32], const char *request_proof,
    const char *header, size_t length, struct delivery_mutation_receipt **output);
void delivery_mutation_receipt_free(struct delivery_mutation_receipt *receipt);
void delivery_mutation_header_free(char *header);
#endif
