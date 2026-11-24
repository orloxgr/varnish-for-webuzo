/* SPDX-License-Identifier: GPL-3.0-or-later
 * Included after delivery_reuse_inputs.c. Portable request challenge and
 * revoke-only receipt codec. No engine APIs, authority grant or cookie issuer.
 */
#include "delivery_mutation_wire.h"

static int mutation_hex(const char *value, size_t length) {
    size_t i;
    if (!value || strlen(value) != length) return 0;
    for (i = 0; i < length; ++i)
        if (!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f'))) return 0;
    return 1;
}
static int mutation_visible(const char *value) {
    const unsigned char *p = (const unsigned char *)value;
    if (!p || !*p) return 0;
    for (; *p; ++p) if (*p <= 32 || *p == 127) return 0;
    return 1;
}
int delivery_mutation_key(const unsigned char *secret, size_t length, unsigned char key[32]) {
    static const unsigned char purpose[] = "ultracache-mutation-key-v1";
    char digest[65];
    size_t i;
    if (!secret || !length || !key || !delivery_hmac_sha256(secret,length,purpose,sizeof(purpose)-1,digest)) return 0;
    for (i = 0; i < 32; ++i)
        key[i] = (unsigned char)(hex_digit((unsigned char)digest[2*i])*16+hex_digit((unsigned char)digest[2*i+1]));
    {
        volatile unsigned char *wipe = (unsigned char *)digest;
        for (i = 0; i < sizeof(digest); ++i) wipe[i] = 0;
    }
    return 1;
}
static int mutation_request_proof(const unsigned char key[32],
    const struct delivery_mutation_context *context, char proof[65]) {
    struct reuse_frame message = {NULL,0,0};
    const char *fields[12];
    size_t i;
    int valid = 0;
    if (proof) proof[0] = 0;
    if (!key || !context || !proof) return 0;
    fields[0] = context->site_id; fields[1] = context->host; fields[2] = context->scope_digest;
    fields[3] = context->epoch; fields[4] = context->incarnation;
    fields[5] = context->native_policy; fields[6] = context->wordpress_policy; fields[7] = context->reuse_policy;
    fields[8] = context->request_id; fields[9] = context->challenge;
    fields[10] = context->method; fields[11] = context->url;
    for (i = 0; i < 12; ++i) if (!fields[i] || !*fields[i]) return 0;
    if (!mutation_hex(fields[0],32) || !mutation_visible(fields[1])) return 0;
    for (i = 2; i < 10; ++i) if (!mutation_hex(fields[i],64)) return 0;
    if (!reuse_token(fields[10],strlen(fields[10])) || fields[11][0] != '/' ||
        !mutation_visible(fields[11]) || strchr(fields[11],'#')) return 0;
    if (!reuse_lp_string(&message,"ultracache-mutation-request-v1")) goto done;
    for (i = 0; i < 10; ++i) if (!reuse_lp_string(&message,fields[i])) goto done;
    for (i = 10; i < 12; ++i) if (!reuse_lp_string(&message,fields[i])) goto done;
    valid = delivery_hmac_sha256(key,32,message.bytes,message.length,proof);
done:
    delivery_reuse_frame_free(message.bytes,message.length); return valid;
}
int delivery_mutation_request_proof(const unsigned char key[32],
    const struct delivery_mutation_context *context, char proof[65]) {
    return mutation_request_proof(key,context,proof);
}
static int mutation_json_string(struct reuse_frame *json, const char *value) {
    const unsigned char *p = (const unsigned char *)value;
    static const char hex[] = "0123456789abcdef";
    if (!reuse_append(json,"\"",1)) return 0;
    for (; *p; ++p) {
        if (*p == '"' || *p == '\\') {
            if (!reuse_append(json,"\\",1) || !reuse_append(json,p,1)) return 0;
        } else if (*p < 32 || *p == 127) {
            char escape[6] = {'\\','u','0','0',hex[*p>>4],hex[*p&15]};
            if (!reuse_append(json,escape,sizeof(escape))) return 0;
        } else if (!reuse_append(json,p,1)) return 0;
    }
    return reuse_append(json,"\"",1);
}
static char *mutation_base64(const unsigned char *bytes, size_t length) {
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i, used = 0, groups;
    char *out;
    if (length > SIZE_MAX-2 || (groups = (length+2)/3) > (SIZE_MAX-1)/4) return NULL;
    out = malloc(groups*4+1);
    if (!out) return NULL;
    for (i = 0; i < length; i += 3) {
        unsigned value = (unsigned)bytes[i]<<16;
        if (length-i > 1) value |= (unsigned)bytes[i+1]<<8;
        if (length-i > 2) value |= bytes[i+2];
        out[used++] = alphabet[(value>>18)&63]; out[used++] = alphabet[(value>>12)&63];
        out[used++] = length-i > 1 ? alphabet[(value>>6)&63] : '=';
        out[used++] = length-i > 2 ? alphabet[value&63] : '=';
    }
    out[used] = 0; return out;
}
static int mutation_context_header(const unsigned char key[32],
    const struct delivery_mutation_context *context, char **header, char proof[65]) {
    static const char *names[] = {"siteId","canonicalHost","scopeDigest","epoch","incarnation",
        "nativePolicy","wordpressPolicy","reusePolicy","requestId","challenge","proof"};
    const char *values[11];
    struct reuse_frame json = {NULL,0,0};
    size_t i;
    if (!header) return 0;
    *header = NULL;
    if (!mutation_request_proof(key,context,proof)) return 0;
    values[0] = context->site_id; values[1] = context->host; values[2] = context->scope_digest;
    values[3] = context->epoch; values[4] = context->incarnation;
    values[5] = context->native_policy; values[6] = context->wordpress_policy; values[7] = context->reuse_policy;
    values[8] = context->request_id; values[9] = context->challenge; values[10] = proof;
    if (!reuse_append(&json,"{\"schemaVersion\":1",18)) goto done;
    for (i = 0; i < 11; ++i)
        if (!reuse_append(&json,",",1) || !mutation_json_string(&json,names[i]) || !reuse_append(&json,":",1) ||
            !mutation_json_string(&json,values[i])) goto done;
    if (!reuse_append(&json,"}",1)) goto done;
    *header = mutation_base64(json.bytes,json.length);
done:
    delivery_reuse_frame_free(json.bytes,json.length); return *header != NULL;
}
int delivery_mutation_context_header(const unsigned char key[32],
    const struct delivery_mutation_context *context, char **header, char proof[65]) {
    return mutation_context_header(key,context,header,proof);
}
void delivery_mutation_header_free(char *header) {
    if (header) delivery_reuse_frame_free((unsigned char *)header,strlen(header));
}
void delivery_mutation_receipt_free(struct delivery_mutation_receipt *receipt) {
    if (!receipt) return;
    while (receipt->pairs) {
        struct delivery_mutation_pair *next = receipt->pairs->next;
        free(receipt->pairs); receipt->pairs = next;
    }
    free(receipt);
}
static int mutation_read_pairs(struct reader *reader, struct delivery_mutation_receipt *receipt) {
    struct delivery_mutation_pair **tail = &receipt->pairs;
    if (!take(reader,'[')) return 0;
    if (take(reader,']')) return 1;
    for (;;) {
        struct delivery_mutation_pair *pair;
        unsigned seen = 0;
        if (!take(reader,'{') || receipt->count == UINT32_MAX) return 0;
        pair = calloc(1,sizeof(*pair));
        if (!pair) return 0;
        for (;;) {
            struct text key, value;
            unsigned bit;
            if (!string(reader,&key) || !take(reader,':') || !string(reader,&value) || !reuse_hex64(value)) goto failed;
            if (equal(key,"tag")) bit = 1;
            else if (equal(key,"transaction")) bit = 2;
            else goto failed;
            if (seen & bit) goto failed;
            seen |= bit;
            memcpy(bit == 1 ? pair->tag : pair->transaction,value.data,64);
            if (take(reader,'}')) break;
            if (!take(reader,',')) goto failed;
        }
        if (seen != 3) goto failed;
        *tail = pair; tail = &pair->next; ++receipt->count;
        if (take(reader,']')) return 1;
        if (!take(reader,',')) return 0;
        continue;
failed:
        free(pair); return 0;
    }
}
static int mutation_pair_compare(const void *left, const void *right) {
    const struct delivery_mutation_pair *a = *(const struct delivery_mutation_pair * const *)left;
    const struct delivery_mutation_pair *b = *(const struct delivery_mutation_pair * const *)right;
    int tag = strcmp(a->tag,b->tag);
    return tag ? tag : strcmp(a->transaction,b->transaction);
}
static int mutation_receipt_mac(const unsigned char key[32], const char *request_proof,
    const struct delivery_mutation_receipt *receipt, char output[65]) {
    const struct delivery_mutation_pair *pair, **ordered = NULL;
    struct reuse_frame frame = {NULL,0,0};
    const char *state = receipt->state == MUTATION_NONE ? "none" : receipt->state == MUTATION_DIRTY ? "dirty" : "scope";
    size_t i = 0;
    int valid = 0;
    if (receipt->count > SIZE_MAX/sizeof(*ordered)) return 0;
    if (receipt->count) {
        ordered = malloc(receipt->count*sizeof(*ordered));
        if (!ordered) return 0;
        for (pair = receipt->pairs; pair; pair = pair->next) ordered[i++] = pair;
        if (i != receipt->count) goto done;
        if (i > 1) qsort(ordered,i,sizeof(*ordered),mutation_pair_compare);
        for (i = 1; i < receipt->count; ++i)
            if (!strcmp(ordered[i-1]->tag,ordered[i]->tag) &&
                !strcmp(ordered[i-1]->transaction,ordered[i]->transaction)) goto done;
    }
    if (!reuse_lp_string(&frame,"ultracache-mutation-response-v1") ||
        !reuse_lp_string(&frame,request_proof)) goto done;
    if (!reuse_lp_string(&frame,state) || !reuse_u32(&frame,receipt->count)) goto done;
    for (i = 0; i < receipt->count; ++i)
        if (!reuse_lp_string(&frame,ordered[i]->tag) || !reuse_lp_string(&frame,ordered[i]->transaction)) goto done;
    valid = delivery_hmac_sha256(key,32,frame.bytes,frame.length,output);
done:
    free(ordered); delivery_reuse_frame_free(frame.bytes,frame.length); return valid;
}
static int mutation_receipt_verify(const unsigned char key[32], const char *request_proof,
    const char *header, size_t length, struct delivery_mutation_receipt **output) {
    struct delivery_mutation_receipt *receipt = NULL;
    struct reader reader = {NULL,0,0};
    char expected[65] = {0}, actual[65] = {0};
    unsigned seen = 0, difference = 0;
    int valid = 0;
    size_t i;
    if (!output) return 0;
    *output = NULL;
    if (!key || !request_proof || !reuse_hex64((struct text){request_proof,strlen(request_proof)}) ||
        (!header && length) || !base64_body((struct text){header,length},(unsigned char **)&reader.buffer,&reader.length)) return 0;
    receipt = calloc(1,sizeof(*receipt));
    if (!receipt || !take(&reader,'{')) goto done;
    for (;;) {
        struct text name, value;
        unsigned bit;
        if (!string(&reader,&name) || !take(&reader,':')) goto done;
        if (equal(name,"schemaVersion")) bit = 1;
        else if (equal(name,"state")) bit = 2;
        else if (equal(name,"transactions")) bit = 4;
        else if (equal(name,"mac")) bit = 8;
        else goto done;
        if (seen & bit) goto done;
        seen |= bit;
        if (bit == 1) {
            uint64_t version;
            if (!number(&reader,&version) || version != 1) goto done;
        }
        else if (bit == 4) { if (!mutation_read_pairs(&reader,receipt)) goto done; }
        else {
            if (!string(&reader,&value)) goto done;
            if (bit == 2) {
                if (equal(value,"none")) receipt->state = MUTATION_NONE;
                else if (equal(value,"dirty")) receipt->state = MUTATION_DIRTY;
                else if (equal(value,"scope")) receipt->state = MUTATION_SCOPE;
                else goto done;
            } else {
                if (!reuse_hex64(value)) goto done;
                memcpy(actual,value.data,64);
            }
        }
        if (take(&reader,'}')) break;
        if (!take(&reader,',')) goto done;
    }
    whitespace(&reader);
    if (seen != 15 || reader.offset != reader.length ||
        (receipt->state == MUTATION_DIRTY ? !receipt->count : receipt->count != 0) ||
        !mutation_receipt_mac(key,request_proof,receipt,expected)) goto done;
    for (i = 0; i < 64; ++i) difference |= (unsigned char)actual[i] ^ (unsigned char)expected[i];
    valid = difference == 0;
done:
    free(reader.buffer);
    if (valid) *output = receipt;
    else delivery_mutation_receipt_free(receipt);
    return valid;
}

int delivery_mutation_receipt_verify(const unsigned char key[32], const char *request_proof,
    const char *header, size_t length, struct delivery_mutation_receipt **output) {
    return mutation_receipt_verify(key,request_proof,header,length,output);
}
