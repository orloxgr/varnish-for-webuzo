/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef UC_DELIVERY_ENVELOPE_H
#define UC_DELIVERY_ENVELOPE_H
#include <stddef.h>

#define DELIVERY_MAX_BODY (8U * 1024U * 1024U)
#define DELIVERY_MAX_FRAGMENTS 1024U

struct delivery_fragment {
    struct delivery_fragment *next;
    char *url;
    char *html;
    size_t length;
};

/* A bounded parser for the delivery-v1 schema only. No engine JSON internals.
 * Strings are strict UTF-8/JSON with UTF-16 surrogate-pair decoding. Embedded
 * NUL is retained in HTML bytes but forbidden in binding text and URLs.
 * Output is all-or-nothing and owned by the caller on success. */
int delivery_envelope_parse(const char *body, size_t length,
    const char *request_id, const char *original_url, unsigned occurrences,
    struct delivery_fragment **output);
int delivery_relative(const char *url);
void delivery_free_fragments(struct delivery_fragment *fragment);
#endif
