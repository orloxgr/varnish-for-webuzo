/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef UC_DELIVERY_REUSE_INPUTS_H
#define UC_DELIVERY_REUSE_INPUTS_H
#include <stddef.h>
#include <stdint.h>

enum delivery_reuse_input_result {
    DELIVERY_REUSE_INPUT_OK = 1,
    DELIVERY_REUSE_INPUT_MEMORY = -1,
    DELIVERY_REUSE_INPUT_DECLARATION = -2,
    DELIVERY_REUSE_INPUT_SYNTAX = -3,
    DELIVERY_REUSE_INPUT_AMBIGUOUS = -4,
    DELIVERY_REUSE_INPUT_RUNTIME = -5
};
struct delivery_reuse_inputs {
    char **names, **prefixes; /* complete declarations, sorted/deduplicated */
    size_t name_count, prefix_count;
    uint32_t php_max_input_vars; /* actual negotiated PHP runtime, not addon limit */
};
struct delivery_reuse_descriptor {
    struct delivery_reuse_descriptor *next;
    char descriptor[65];
    char *url, *provider;
    uint64_t occurrences;
};
struct delivery_reuse_recipe {
    char digest[65]; /* checked canonical digest, not native authority */
    struct delivery_reuse_inputs *inputs;
    struct delivery_reuse_descriptor *fragments;
    uint64_t occurrences;
};
struct delivery_reuse_context {
    const char *site_id, *canonical_host, *scope, *epoch;
    const char *native_policy, *wordpress_policy, *reuse_policy;
    const char *publication_digest, *representation, *recipe_digest;
};
/* Portable framing only. No browser identity/admission/policy is inferred. */
int delivery_reuse_inputs_parse(const char *json, size_t length,
    struct delivery_reuse_inputs **output);
void delivery_reuse_inputs_free(struct delivery_reuse_inputs *inputs);
int delivery_reuse_recipe_parse(const char *json, size_t length,
    uint64_t expected_occurrences, struct delivery_reuse_recipe **output);
void delivery_reuse_recipe_free(struct delivery_reuse_recipe *recipe);
/* Independent ownership of an already parsed immutable declaration. */
struct delivery_reuse_recipe *delivery_reuse_recipe_clone(const struct delivery_reuse_recipe *recipe);
int delivery_reuse_descriptor_digest(const char *url, const char *provider, char digest[65]);
int delivery_reuse_recipe_digest(const struct delivery_reuse_recipe *recipe, char digest[65]);
int delivery_reuse_input_projection(const struct delivery_reuse_inputs *inputs,
    const unsigned char *cookie, size_t cookie_length,
    unsigned char **frame, size_t *frame_length);
void delivery_reuse_frame_free(unsigned char *frame, size_t length);
/* All context values come from accepted native state, never client headers.
 * This function frames/signs that exact state; it does not authenticate it. */
int delivery_reuse_input_binding(const unsigned char *site_secret, size_t secret_length,
    const struct delivery_reuse_context *context,
    const unsigned char *projection, size_t projection_length, char mac[65]);
/* Revoke-only identity provenance. Uses the first seven context dimensions;
 * publication/representation/recipe never split a validated owner mapping. */
int delivery_reuse_identity_binding(const unsigned char *site_secret, size_t secret_length,
    const struct delivery_reuse_context *context,
    const unsigned char *identity_projection, size_t projection_length, char mac[65]);
/* Native cache lookup retains only this purpose-separated key, not the site
 * credential. These produce the identical frozen MACs without deriving twice. */
int delivery_reuse_key_derive(const unsigned char *site_secret, size_t secret_length, unsigned char key[32]);
int delivery_reuse_input_mac(const unsigned char key[32], const struct delivery_reuse_context *context,
    const unsigned char *projection, size_t projection_length, char mac[65]);
int delivery_reuse_identity_mac(const unsigned char key[32], const struct delivery_reuse_context *context,
    const unsigned char *projection, size_t projection_length, char mac[65]);
#endif
