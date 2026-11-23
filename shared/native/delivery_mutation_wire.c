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
    const struct delivery_mutation_context *context, const char *coverage_policy, char proof[65]) {
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
    if (coverage_policy && !mutation_hex(coverage_policy,64)) return 0;
    if (!reuse_lp_string(&message,coverage_policy ? "ultracache-mutation-request-v2" : "ultracache-mutation-request-v1")) goto done;
    for (i = 0; i < 10; ++i) if (!reuse_lp_string(&message,fields[i])) goto done;
    if (coverage_policy && (!reuse_u32(&message,1) || !reuse_lp_string(&message,coverage_policy))) goto done;
    for (i = 10; i < 12; ++i) if (!reuse_lp_string(&message,fields[i])) goto done;
    valid = delivery_hmac_sha256(key,32,message.bytes,message.length,proof);
done:
    delivery_reuse_frame_free(message.bytes,message.length); return valid;
}
int delivery_mutation_request_proof(const unsigned char key[32],
    const struct delivery_mutation_context *context, char proof[65]) {
    return mutation_request_proof(key,context,NULL,proof);
}
int delivery_mutation_request_proof_v2(const unsigned char key[32],
    const struct delivery_mutation_context *context, const char *coverage_policy, char proof[65]) {
    return coverage_policy && mutation_request_proof(key,context,coverage_policy,proof);
}
int delivery_mutation_completion_proof(const unsigned char key[32], const char *request_proof,
    const char *request_id, const char *challenge, const char *coverage_policy, unsigned qualified, char proof[65]) {
    struct reuse_frame message = {NULL,0,0};
    int valid = 0;
    if (proof) proof[0] = 0;
    if (!key || !proof || qualified > 1 || !mutation_hex(request_proof,64) ||
        !mutation_hex(request_id,64) || !mutation_hex(challenge,64) || !mutation_hex(coverage_policy,64)) return 0;
    if (reuse_lp_string(&message,"ultracache-mutation-completion-v2") && reuse_lp_string(&message,request_proof) &&
        reuse_lp_string(&message,request_id) && reuse_lp_string(&message,challenge) && reuse_u32(&message,1) &&
        reuse_lp_string(&message,coverage_policy) && reuse_lp_string(&message,qualified ? "qualified" : "unknown"))
        valid = delivery_hmac_sha256(key,32,message.bytes,message.length,proof);
    delivery_reuse_frame_free(message.bytes,message.length); return valid;
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
    const struct delivery_mutation_context *context, const char *coverage_policy, char **header, char proof[65]) {
    static const char *names[] = {"siteId","canonicalHost","scopeDigest","epoch","incarnation",
        "nativePolicy","wordpressPolicy","reusePolicy","requestId","challenge","proof"};
    const char *values[11];
    struct reuse_frame json = {NULL,0,0};
    size_t i;
    if (!header) return 0;
    *header = NULL;
    if (!mutation_request_proof(key,context,coverage_policy,proof)) return 0;
    values[0] = context->site_id; values[1] = context->host; values[2] = context->scope_digest;
    values[3] = context->epoch; values[4] = context->incarnation;
    values[5] = context->native_policy; values[6] = context->wordpress_policy; values[7] = context->reuse_policy;
    values[8] = context->request_id; values[9] = context->challenge; values[10] = proof;
    if (!reuse_append(&json,coverage_policy ? "{\"schemaVersion\":2" : "{\"schemaVersion\":1",18)) goto done;
    for (i = 0; i < 11; ++i)
        if (!reuse_append(&json,",",1) || !mutation_json_string(&json,names[i]) || !reuse_append(&json,":",1) ||
            !mutation_json_string(&json,values[i])) goto done;
    if (coverage_policy && (!reuse_append(&json,",\"coverageVersion\":1,\"coveragePolicy\":",38) ||
        !mutation_json_string(&json,coverage_policy))) goto done;
    if (!reuse_append(&json,"}",1)) goto done;
    *header = mutation_base64(json.bytes,json.length);
done:
    delivery_reuse_frame_free(json.bytes,json.length); return *header != NULL;
}
int delivery_mutation_context_header(const unsigned char key[32],
    const struct delivery_mutation_context *context, char **header, char proof[65]) {
    return mutation_context_header(key,context,NULL,header,proof);
}
int delivery_mutation_context_header_v2(const unsigned char key[32],
    const struct delivery_mutation_context *context, const char *coverage_policy, char **header, char proof[65]) {
    return coverage_policy && mutation_context_header(key,context,coverage_policy,header,proof);
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
    if (!reuse_lp_string(&frame,receipt->coverage_version ? "ultracache-mutation-response-v2" : "ultracache-mutation-response-v1") ||
        !reuse_lp_string(&frame,request_proof)) goto done;
    if (receipt->coverage_version && (!reuse_u32(&frame,1) || !reuse_lp_string(&frame,receipt->coverage_policy) ||
        !reuse_lp_string(&frame,receipt->coverage_qualified ? "qualified" : "unknown"))) goto done;
    if (!reuse_lp_string(&frame,state) || !reuse_u32(&frame,receipt->count)) goto done;
    for (i = 0; i < receipt->count; ++i)
        if (!reuse_lp_string(&frame,ordered[i]->tag) || !reuse_lp_string(&frame,ordered[i]->transaction)) goto done;
    valid = delivery_hmac_sha256(key,32,frame.bytes,frame.length,output);
done:
    free(ordered); delivery_reuse_frame_free(frame.bytes,frame.length); return valid;
}
static int mutation_receipt_verify(const unsigned char key[32], const char *request_proof, const char *coverage_policy,
    const char *header, size_t length, struct delivery_mutation_receipt **output) {
    struct delivery_mutation_receipt *receipt = NULL;
    struct reader reader = {NULL,0,0};
    char expected[65] = {0}, actual[65] = {0};
    unsigned seen = 0, difference = 0;
    int valid = 0;
    size_t i;
    if (!output) return 0;
    *output = NULL;
    if ((coverage_policy && !mutation_hex(coverage_policy,64)) || !key || !request_proof || !reuse_hex64((struct text){request_proof,strlen(request_proof)}) ||
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
        else if (coverage_policy && equal(name,"coverageVersion")) bit = 16;
        else if (coverage_policy && equal(name,"coveragePolicy")) bit = 32;
        else if (coverage_policy && equal(name,"coverage")) bit = 64;
        else goto done;
        if (seen & bit) goto done;
        seen |= bit;
        if (bit == 1 || bit == 16) {
            uint64_t version;
            if (!number(&reader,&version) || version != (bit == 16 ? 1 : coverage_policy ? 2 : 1)) goto done;
            if (bit == 16) receipt->coverage_version = 1;
        }
        else if (bit == 4) { if (!mutation_read_pairs(&reader,receipt)) goto done; }
        else {
            if (!string(&reader,&value)) goto done;
            if (bit == 2) {
                if (equal(value,"none")) receipt->state = MUTATION_NONE;
                else if (equal(value,"dirty")) receipt->state = MUTATION_DIRTY;
                else if (equal(value,"scope")) receipt->state = MUTATION_SCOPE;
                else goto done;
            } else if (bit == 64) {
                if (equal(value,"qualified")) receipt->coverage_qualified = 1;
                else if (!equal(value,"unknown")) goto done;
            } else {
                if (!reuse_hex64(value)) goto done;
                memcpy(bit == 32 ? receipt->coverage_policy : actual,value.data,64);
            }
        }
        if (take(&reader,'}')) break;
        if (!take(&reader,',')) goto done;
    }
    whitespace(&reader);
    if (seen != (coverage_policy ? 127 : 15) || reader.offset != reader.length ||
        (coverage_policy && (strcmp(coverage_policy,receipt->coverage_policy) ||
            (receipt->state == MUTATION_SCOPE && receipt->coverage_qualified))) ||
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
    return mutation_receipt_verify(key,request_proof,NULL,header,length,output);
}
int delivery_mutation_receipt_verify_v2(const unsigned char key[32], const char *request_proof,
    const char *coverage_policy, const char *header, size_t length, struct delivery_mutation_receipt **output) {
    return coverage_policy && mutation_receipt_verify(key,request_proof,coverage_policy,header,length,output);
}

/* Same portable mutation codec, separate dispatch purpose; never a completion
 * proof, admission or an inference that the original application ended. */
int delivery_execution_drain_proof(const unsigned char key[32],
    const struct delivery_execution_drain *d, char proof[65]) {
    struct reuse_frame frame = {NULL,0,0};
    const char *fields[11];
    size_t i;
    int valid = 0;
    if (proof) proof[0] = 0;
    if (!key || !d || !proof || !mutation_hex(d->dispatch_id,64) ||
        !mutation_hex(d->site_id,32) || !mutation_visible(d->host) ||
        !mutation_visible(d->target) || d->target[0] != '/' || d->target[1] == '/' ||
        strchr(d->target,'#') || strchr(d->target,'\\') ||
        !mutation_visible(d->scope) || d->scope[0] != '/' ||
        d->scope[strlen(d->scope)-1] != '/' || strchr(d->scope,'?') || strchr(d->scope,'#') ||
        !mutation_hex(d->coverage_policy,64) || !mutation_hex(d->request_id,64) || !mutation_hex(d->challenge,64)) return 0;
    fields[0] = "GET"; fields[1] = d->target; fields[2] = d->dispatch_id;
    fields[3] = d->site_id; fields[4] = d->host; fields[5] = d->scope;
    fields[6] = d->epoch; fields[7] = d->incarnation; fields[8] = d->native_policy;
    fields[9] = d->wordpress_policy; fields[10] = d->reuse_policy;
    for (i = 6; i < 11; ++i) if (!mutation_hex(fields[i],64)) return 0;
    if (!reuse_lp_string(&frame,"ultracache-execution-drain-dispatch-v1")) goto done;
    for (i = 0; i < 11; ++i) if (!reuse_lp_string(&frame,fields[i])) goto done;
    if (!reuse_u32(&frame,1) || !reuse_lp_string(&frame,d->coverage_policy) ||
        !reuse_lp_string(&frame,d->request_id) || !reuse_lp_string(&frame,d->challenge)) goto done;
    valid = delivery_hmac_sha256(key,32,frame.bytes,frame.length,proof);
done:
    delivery_reuse_frame_free(frame.bytes,frame.length); return valid;
}
void delivery_execution_drain_free(struct delivery_execution_drain *d) {
    if (!d) return;
    free(d->dispatch_id); free(d->target); free(d->site_id); free(d->host); free(d->scope);
    free(d->epoch); free(d->incarnation); free(d->native_policy); free(d->wordpress_policy);
    free(d->reuse_policy); free(d->coverage_policy); free(d->request_id); free(d->challenge);
    delivery_mutation_header_free(d->header); free(d);
}
static int execution_drain_fields(struct reader *r, const char * const *names,
    char ***destinations, size_t count, int coverage) {
    uint32_t seen = 0, expected = ((uint32_t)1 << (count+coverage))-1;
    if (!take(r,'{')) return 0;
    for (;;) {
        struct text name,value;
        size_t i;
        if (!string(r,&name) || !take(r,':')) return 0;
        if (coverage && equal(name,"coverageVersion")) {
            uint64_t n;
            if ((seen & ((uint32_t)1<<count)) || !number(r,&n) || n != 1) return 0;
            seen |= (uint32_t)1<<count;
        } else {
            for (i = 0; i < count; ++i) if (equal(name,names[i])) break;
            if (i == count || (seen & ((uint32_t)1<<i)) || !string(r,&value) ||
                memchr(value.data,0,value.length) || !(*destinations[i] = copy(value))) return 0;
            seen |= (uint32_t)1<<i;
        }
        if (take(r,'}')) return seen == expected;
        if (!take(r,',')) return 0;
    }
}
int delivery_execution_drain_verify(const unsigned char key[32], const char *header,
    size_t length, struct delivery_execution_drain **output) {
    static const char * const names[] = {"siteId","canonicalHost","scope","epoch","incarnation",
        "nativePolicy","wordpressPolicy","reusePolicy","coveragePolicy"};
    static const char * const executions[] = {"requestId","challenge"};
    struct reader r = {NULL,0,0};
    struct delivery_execution_drain *d = NULL;
    char expected[65], *actual = NULL;
    unsigned seen = 0, difference = 0;
    size_t i;
    int valid = 0;
    if (!output) return 0;
    *output = NULL;
    if (!key || !header || !length ||
        !base64_body((struct text){header,length},(unsigned char **)&r.buffer,&r.length)) return 0;
    d = calloc(1,sizeof(*d));
    if (!d || !take(&r,'{')) goto done;
    for (;;) {
        struct text name,value;
        unsigned bit;
        if (!string(&r,&name) || !take(&r,':')) goto done;
        if (equal(name,"schemaVersion")) bit = 1;
        else if (equal(name,"dispatchId")) bit = 2;
        else if (equal(name,"target")) bit = 4;
        else if (equal(name,"context")) bit = 8;
        else if (equal(name,"execution")) bit = 16;
        else if (equal(name,"proof")) bit = 32;
        else goto done;
        if (seen & bit) goto done;
        seen |= bit;
        if (bit == 1) {
            uint64_t n;
            if (!number(&r,&n) || n != 1) goto done;
        } else if (bit == 8) {
            char **destinations[] = {&d->site_id,&d->host,&d->scope,&d->epoch,&d->incarnation,
                &d->native_policy,&d->wordpress_policy,&d->reuse_policy,&d->coverage_policy};
            if (!execution_drain_fields(&r,names,destinations,9,1)) goto done;
        } else if (bit == 16) {
            char **destinations[] = {&d->request_id,&d->challenge};
            if (!execution_drain_fields(&r,executions,destinations,2,0)) goto done;
        } else {
            char **destination = bit == 2 ? &d->dispatch_id : bit == 4 ? &d->target : &actual;
            if (!string(&r,&value) || memchr(value.data,0,value.length) || !(*destination = copy(value))) goto done;
        }
        if (take(&r,'}')) break;
        if (!take(&r,',')) goto done;
    }
    whitespace(&r);
    if (seen != 63 || r.offset != r.length || !mutation_hex(actual,64) ||
        !delivery_execution_drain_proof(key,d,expected)) goto done;
    for (i = 0; i < 64; ++i) difference |= (unsigned char)actual[i] ^ (unsigned char)expected[i];
    if (difference || !(d->header = malloc(length+1))) goto done;
    memcpy(d->header,header,length); d->header[length] = 0; valid = 1;
done:
    free(actual); free(r.buffer);
    if (valid) *output = d;
    else delivery_execution_drain_free(d);
    return valid;
}
