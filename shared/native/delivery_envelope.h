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
};

/* A fixed-schema parser for delivery v1 only. No engine JSON internals.
 * Strings are strict UTF-8/JSON with UTF-16 surrogate-pair decoding. Embedded
 * NUL is retained in HTML bytes but forbidden in binding text and URLs.
 * Output is all-or-nothing and owned by the caller on success. */
int delivery_envelope_parse(const char *body, size_t length,
    const char *request_id, const char *original_url, uint64_t occurrences,
    struct delivery_fragment **output);
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
