/* SPDX-License-Identifier: GPL-3.0-or-later
 * Included by delivery_envelope.c. Portable recipe/input framing, qualified
 * against actual PHP parser vectors. No engine API or cookie policy decision.
 */
#include "delivery_reuse_inputs.h"

struct reuse_frame { unsigned char *bytes; size_t length, capacity; };
struct reuse_pair {
    char *php_name;
    const unsigned char *name, *value;
    size_t name_length, value_length, order;
};
static int reuse_token(const char *value, size_t length) {
    size_t i;
    if (!value || !length) return 0;
    for (i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)value[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || (c && strchr("!#$%&'*+.^_`|~-",c)))) return 0;
    }
    return 1;
}
static int reuse_hex64(struct text value) {
    size_t i;
    if (value.length != 64) return 0;
    for (i = 0; i < value.length; ++i)
        if (!((value.data[i] >= '0' && value.data[i] <= '9') ||
            (value.data[i] >= 'a' && value.data[i] <= 'f'))) return 0;
    return 1;
}
static int reuse_string_compare(const void *left, const void *right) {
    return strcmp(*(char * const *)left,*(char * const *)right);
}
static int reuse_selectors(struct reader *reader, char ***output, size_t *count) {
    char **values = NULL;
    size_t n = 0, i, unique = 0;
    if (!take(reader,'[')) return 0;
    if (!take(reader,']')) for (;;) {
        struct text value;
        char **grown;
        if (!string(reader,&value) || !reuse_token(value.data,value.length) ||
            n == UINT32_MAX || n >= SIZE_MAX/sizeof(*values)) goto failed;
        grown = realloc(values,(n+1)*sizeof(*values));
        if (!grown) goto failed;
        values = grown; values[n] = copy(value);
        if (!values[n]) goto failed;
        ++n;
        if (take(reader,']')) break;
        if (!take(reader,',')) goto failed;
    }
    if (n > 1) qsort(values,n,sizeof(*values),reuse_string_compare);
    for (i = 0; i < n; ++i) {
        if (unique && !strcmp(values[unique-1],values[i])) free(values[i]);
        else values[unique++] = values[i];
    }
    *output = values; *count = unique; return 1;
failed:
    for (i = 0; i < n; ++i) free(values[i]);
    free(values); return 0;
}
void delivery_reuse_inputs_free(struct delivery_reuse_inputs *inputs) {
    size_t i;
    if (!inputs) return;
    for (i = 0; i < inputs->name_count; ++i) free(inputs->names[i]);
    for (i = 0; i < inputs->prefix_count; ++i) free(inputs->prefixes[i]);
    free(inputs->names); free(inputs->prefixes); free(inputs);
}
static int reuse_read_inputs(struct reader *reader, struct delivery_reuse_inputs **output) {
    struct delivery_reuse_inputs *inputs;
    unsigned seen = 0;
    if (!take(reader,'{')) return 0;
    inputs = calloc(1,sizeof(*inputs));
    if (!inputs) return 0;
    for (;;) {
        struct text key;
        unsigned bit;
        if (!string(reader,&key) || !take(reader,':')) goto failed;
        if (equal(key,"cookieNames")) bit = 1;
        else if (equal(key,"cookiePrefixes")) bit = 2;
        else if (equal(key,"phpMaxInputVars")) bit = 4;
        else goto failed;
        if (seen & bit) goto failed;
        seen |= bit;
        if (bit == 1) {
            if (!reuse_selectors(reader,&inputs->names,&inputs->name_count)) goto failed;
        } else if (bit == 2) {
            if (!reuse_selectors(reader,&inputs->prefixes,&inputs->prefix_count)) goto failed;
        } else {
            uint64_t actual;
            if (!number(reader,&actual) || actual > UINT32_MAX) goto failed;
            inputs->php_max_input_vars = (uint32_t)actual;
        }
        if (take(reader,'}')) break;
        if (!take(reader,',')) goto failed;
    }
    if (seen != 7) goto failed;
    *output = inputs; return 1;
failed:
    delivery_reuse_inputs_free(inputs); return 0;
}
static int reuse_reader(const char *json, size_t length, struct reader *reader) {
    if ((!json && length) || length == SIZE_MAX) return 0;
    reader->buffer = malloc(length+1);
    if (!reader->buffer) return 0;
    if (length) memcpy(reader->buffer,json,length);
    reader->buffer[length] = 0; reader->length = length; reader->offset = 0;
    return 1;
}
int delivery_reuse_inputs_parse(const char *json, size_t length, struct delivery_reuse_inputs **output) {
    struct reader reader;
    int valid;
    if (!output) return DELIVERY_REUSE_INPUT_DECLARATION;
    *output = NULL;
    if (!reuse_reader(json,length,&reader)) return DELIVERY_REUSE_INPUT_MEMORY;
    valid = reuse_read_inputs(&reader,output);
    whitespace(&reader);
    if (reader.offset != reader.length) valid = 0;
    free(reader.buffer);
    if (!valid) { delivery_reuse_inputs_free(*output); *output = NULL; }
    return valid ? DELIVERY_REUSE_INPUT_OK : DELIVERY_REUSE_INPUT_DECLARATION;
}

static void reuse_descriptors_free(struct delivery_reuse_descriptor *row) {
    while (row) {
        struct delivery_reuse_descriptor *next = row->next;
        free(row->url); free(row->provider); free(row); row = next;
    }
}
void delivery_reuse_recipe_free(struct delivery_reuse_recipe *recipe) {
    if (!recipe) return;
    delivery_reuse_inputs_free(recipe->inputs);
    reuse_descriptors_free(recipe->fragments); free(recipe);
}
static int reuse_descriptors(struct reader *reader, struct delivery_reuse_recipe *recipe) {
    struct delivery_reuse_descriptor **tail = &recipe->fragments;
    if (!take(reader,'[')) return 0;
    if (take(reader,']')) return 1;
    for (;;) {
        struct delivery_reuse_descriptor *row, *other;
        unsigned seen = 0;
        if (!take(reader,'{')) return 0;
        row = calloc(1,sizeof(*row));
        if (!row) return 0;
        for (;;) {
            struct text key, value;
            unsigned bit;
            if (!string(reader,&key) || !take(reader,':')) goto failed;
            if (equal(key,"descriptor")) bit = 1;
            else if (equal(key,"url")) bit = 2;
            else if (equal(key,"provider")) bit = 4;
            else if (equal(key,"occurrences")) bit = 8;
            else goto failed;
            if (seen & bit) goto failed;
            seen |= bit;
            if (bit == 8) {
                if (!number(reader,&row->occurrences) || !row->occurrences ||
                    row->occurrences > UINT64_MAX-recipe->occurrences) goto failed;
            } else {
                if (!string(reader,&value) || strlen(value.data) != value.length) goto failed;
                if (bit == 1) {
                    if (!reuse_hex64(value)) goto failed;
                    memcpy(row->descriptor,value.data,64);
                } else if (bit == 2) {
                    if (!delivery_relative(value.data) || !(row->url = copy(value))) goto failed;
                } else {
                    size_t i;
                    if (!value.length) goto failed;
                    for (i = 0; i < value.length; ++i)
                        if ((unsigned char)value.data[i] < 32 || value.data[i] == 127) goto failed;
                    if (!(row->provider = copy(value))) goto failed;
                }
            }
            if (take(reader,'}')) break;
            if (!take(reader,',')) goto failed;
        }
        if (seen != 15) goto failed;
        {
            char expected[65];
            if (!delivery_reuse_descriptor_digest(row->url,row->provider,expected) || strcmp(row->descriptor,expected)) goto failed;
        }
        for (other = recipe->fragments; other; other = other->next)
            if (!strcmp(row->descriptor,other->descriptor) || !strcmp(row->url,other->url)) goto failed;
        recipe->occurrences += row->occurrences;
        *tail = row; tail = &row->next;
        if (take(reader,']')) return 1;
        if (!take(reader,',')) return 0;
        continue;
failed:
        reuse_descriptors_free(row); return 0;
    }
}
static int reuse_recipe_read(const char *json, size_t length,
    const uint64_t *expected_occurrences, struct delivery_reuse_recipe **output) {
    struct reader reader;
    struct delivery_reuse_recipe *recipe;
    unsigned seen = 0;
    int valid = 0;
    if (!output) return 0;
    *output = NULL;
    if (!reuse_reader(json,length,&reader)) return 0;
    recipe = calloc(1,sizeof(*recipe));
    if (!recipe || !take(&reader,'{')) goto finished;
    for (;;) {
        struct text key, value;
        unsigned bit;
        if (!string(&reader,&key) || !take(&reader,':')) goto finished;
        if (equal(key,"digest")) bit = 1;
        else if (equal(key,"inputs")) bit = 2;
        else if (equal(key,"fragments")) bit = 4;
        else goto finished;
        if (seen & bit) goto finished;
        seen |= bit;
        if (bit == 1) {
            if (!string(&reader,&value) || !reuse_hex64(value)) goto finished;
            memcpy(recipe->digest,value.data,64);
        } else if (bit == 2) {
            if (!reuse_read_inputs(&reader,&recipe->inputs)) goto finished;
        } else if (!reuse_descriptors(&reader,recipe)) goto finished;
        if (take(&reader,'}')) break;
        if (!take(&reader,',')) goto finished;
    }
    whitespace(&reader);
    valid = seen == 7 && reader.offset == reader.length &&
        (!expected_occurrences || recipe->occurrences == *expected_occurrences);
    if (valid) {
        char expected[65];
        valid = delivery_reuse_recipe_digest(recipe,expected) && !strcmp(recipe->digest,expected);
    }
finished:
    free(reader.buffer);
    if (valid) *output = recipe;
    else delivery_reuse_recipe_free(recipe);
    return valid;
}
int delivery_reuse_recipe_parse(const char *json, size_t length,
    uint64_t expected_occurrences, struct delivery_reuse_recipe **output) {
    return reuse_recipe_read(json,length,&expected_occurrences,output);
}

static int reuse_append(struct reuse_frame *frame, const void *bytes, size_t length) {
    size_t needed, capacity;
    unsigned char *grown;
    if (!delivery_buffer_growth(frame->length,frame->capacity,length,&needed,&capacity)) return 0;
    if (capacity != frame->capacity) {
        grown = realloc(frame->bytes,capacity);
        if (!grown) return 0;
        frame->bytes = grown; frame->capacity = capacity;
    }
    if (length) memcpy(frame->bytes+frame->length,bytes,length);
    frame->length += length; frame->bytes[frame->length] = 0; return 1;
}
static int reuse_u32(struct reuse_frame *frame, size_t value) {
    unsigned char bytes[4];
    if (value > UINT32_MAX) return 0;
    bytes[0] = (unsigned char)(value>>24); bytes[1] = (unsigned char)(value>>16);
    bytes[2] = (unsigned char)(value>>8); bytes[3] = (unsigned char)value;
    return reuse_append(frame,bytes,sizeof(bytes));
}
static int reuse_lp(struct reuse_frame *frame, const void *bytes, size_t length) {
    return reuse_u32(frame,length) && reuse_append(frame,bytes,length);
}
static int reuse_lp_string(struct reuse_frame *frame, const char *value) {
    return reuse_lp(frame,value,strlen(value));
}
static int reuse_u64(struct reuse_frame *frame, uint64_t value) {
    unsigned char bytes[8];
    size_t i;
    for (i = 0; i < sizeof(bytes); ++i) bytes[i] = (unsigned char)(value>>(56-8*i));
    return reuse_append(frame,bytes,sizeof(bytes));
}
int delivery_reuse_descriptor_digest(const char *url, const char *provider, char digest[65]) {
    struct reuse_frame frame = {NULL,0,0};
    size_t i;
    int valid = 0;
    if (digest) digest[0] = 0;
    if (!digest || !delivery_relative(url) || !provider || !*provider) return 0;
    for (i = 0; provider[i]; ++i) if ((unsigned char)provider[i] < 32 || provider[i] == 127) return 0;
    if (reuse_lp_string(&frame,"ultracache-private-descriptor-v1") &&
        reuse_lp_string(&frame,url) && reuse_lp_string(&frame,provider))
        valid = delivery_selection_digest(frame.bytes,frame.length,digest);
    delivery_reuse_frame_free(frame.bytes,frame.length); return valid;
}
static int reuse_descriptor_compare(const void *left, const void *right) {
    const struct delivery_reuse_descriptor *a = *(const struct delivery_reuse_descriptor * const *)left;
    const struct delivery_reuse_descriptor *b = *(const struct delivery_reuse_descriptor * const *)right;
    return strcmp(a->descriptor,b->descriptor);
}
int delivery_reuse_recipe_digest(const struct delivery_reuse_recipe *recipe, char digest[65]) {
    const struct delivery_reuse_descriptor *row, **ordered = NULL;
    struct reuse_frame frame = {NULL,0,0};
    unsigned char *declaration = NULL;
    size_t length = 0, count = 0, i;
    int valid = 0;
    if (digest) digest[0] = 0;
    if (!digest || !recipe || !recipe->inputs) return 0;
    for (row = recipe->fragments; row; row = row->next) {
        if (count == UINT32_MAX || count == SIZE_MAX/sizeof(*ordered)) goto done;
        ++count;
    }
    if (count && !(ordered = malloc(count*sizeof(*ordered)))) goto done;
    for (row = recipe->fragments,i = 0; row; row = row->next) ordered[i++] = row;
    if (count > 1) qsort(ordered,count,sizeof(*ordered),reuse_descriptor_compare);
    if (delivery_reuse_input_projection(recipe->inputs,NULL,0,&declaration,&length) != DELIVERY_REUSE_INPUT_OK ||
        !reuse_lp_string(&frame,"ultracache-private-recipe-v1") || !reuse_lp(&frame,declaration,length) ||
        !reuse_u32(&frame,count)) goto done;
    for (i = 0; i < count; ++i) {
        char expected[65];
        row = ordered[i];
        if (!row->occurrences || !delivery_reuse_descriptor_digest(row->url,row->provider,expected) ||
            strcmp(row->descriptor,expected) || (i && !strcmp(ordered[i-1]->descriptor,row->descriptor)) ||
            !reuse_lp_string(&frame,row->descriptor) || !reuse_lp_string(&frame,row->url) ||
            !reuse_lp_string(&frame,row->provider) || !reuse_u64(&frame,row->occurrences)) goto done;
    }
    valid = delivery_selection_digest(frame.bytes,frame.length,digest);
done:
    free(ordered); delivery_reuse_frame_free(declaration,length);
    delivery_reuse_frame_free(frame.bytes,frame.length); return valid;
}
static int reuse_selector_matches(const char *selector, const char *php_name, int prefix) {
    size_t i;
    for (i = 0; selector[i]; ++i)
        if (!php_name[i] || (selector[i] == '.' ? '_' : selector[i]) != php_name[i]) return 0;
    return prefix || !php_name[i];
}
static int reuse_input_matches(const struct delivery_reuse_inputs *inputs, const char *php_name) {
    size_t i;
    for (i = 0; i < inputs->name_count; ++i)
        if (reuse_selector_matches(inputs->names[i],php_name,0)) return 1;
    for (i = 0; i < inputs->prefix_count; ++i)
        if (reuse_selector_matches(inputs->prefixes[i],php_name,1)) return 1;
    return 0;
}
static int reuse_pair_compare(const void *left, const void *right) {
    const struct reuse_pair *a = left, *b = right;
    int name = strcmp(a->php_name,b->php_name);
    return name ? name : (a->order > b->order)-(a->order < b->order);
}
void delivery_reuse_frame_free(unsigned char *frame, size_t length) {
    volatile unsigned char *bytes = frame;
    if (!frame) return;
    while (length--) *bytes++ = 0;
    free(frame);
}
int delivery_reuse_input_projection(const struct delivery_reuse_inputs *inputs,
    const unsigned char *cookie, size_t cookie_length,
    unsigned char **output, size_t *output_length) {
    struct reuse_pair *pairs = NULL;
    struct reuse_frame frame = {NULL,0,0};
    size_t i, cursor = 0, count = 0, groups = 0, php_tokens = 0;
    int result = DELIVERY_REUSE_INPUT_MEMORY;
    if (!output || !output_length) return DELIVERY_REUSE_INPUT_DECLARATION;
    *output = NULL; *output_length = 0;
    if (!inputs || (!cookie && cookie_length)) return DELIVERY_REUSE_INPUT_DECLARATION;
    for (i = 0; i < cookie_length; ++i)
        if (cookie[i] < 9 || (cookie[i] >= 10 && cookie[i] < 32) || cookie[i] == 127)
            return DELIVERY_REUSE_INPUT_SYNTAX;
    while (cursor < cookie_length) {
        size_t start = cursor, end, equal_at, base_length, j;
        char *php_name;
        struct reuse_pair *grown;
        while (cursor < cookie_length && cookie[cursor] != ';') ++cursor;
        end = cursor;
        if (cursor < cookie_length) ++cursor;
        while (start < end && (cookie[start] == ' ' || cookie[start] == '\t')) ++start;
        equal_at = start;
        while (equal_at < end && cookie[equal_at] != '=') ++equal_at;
        /* Match the actual PHP Cookie parser's count before registration:
         * empty/whitespace-only/empty-name pairs do not consume input slots;
         * unrelated and bare tokens do. Never impose a guessed PHP default. */
        if (start == end || equal_at == start) continue;
        ++php_tokens;
        base_length = 0;
        while (start+base_length < equal_at && cookie[start+base_length] != '[') ++base_length;
        if (base_length == SIZE_MAX) goto finished;
        php_name = malloc(base_length+1);
        if (!php_name) goto finished;
        for (j = 0; j < base_length; ++j) {
            unsigned char c = cookie[start+j];
            php_name[j] = (c == '.' || c == ' ') ? '_' : (char)c;
        }
        php_name[base_length] = 0;
        if (!reuse_input_matches(inputs,php_name)) {
            /* PHP falls back to a flat key when the FIRST array opener has
             * no closing bracket: auth[session -> auth_session. Check this
             * normalized target before discarding it as unrelated. A leading
             * opener with an empty base is discarded by PHP, not flattened. */
            size_t name_length = equal_at-start;
            if (base_length && base_length < name_length &&
                !memchr(cookie+start+base_length+1,']',name_length-base_length-1)) {
                char *fallback;
                if (name_length == SIZE_MAX) { free(php_name); goto finished; }
                fallback = realloc(php_name,name_length+1);
                if (!fallback) { free(php_name); goto finished; }
                php_name = fallback;
                for (j = 0; j < name_length; ++j) {
                    unsigned char c = cookie[start+j];
                    php_name[j] = (c == '.' || c == ' ' || c == '[') ? '_' : (char)c;
                }
                php_name[name_length] = 0;
                if (reuse_input_matches(inputs,php_name)) {
                    free(php_name);
                    result = php_tokens > inputs->php_max_input_vars ? DELIVERY_REUSE_INPUT_RUNTIME : DELIVERY_REUSE_INPUT_AMBIGUOUS;
                    goto finished;
                }
            }
            free(php_name); continue;
        }
        if (php_tokens > inputs->php_max_input_vars) {
            free(php_name); result = DELIVERY_REUSE_INPUT_RUNTIME; goto finished;
        }
        if (equal_at == end || !reuse_token((const char *)cookie+start,equal_at-start)) {
            free(php_name); result = DELIVERY_REUSE_INPUT_AMBIGUOUS; goto finished;
        }
        if (count == UINT32_MAX || count >= SIZE_MAX/sizeof(*pairs)) { free(php_name); goto finished; }
        grown = realloc(pairs,(count+1)*sizeof(*pairs));
        if (!grown) { free(php_name); goto finished; }
        pairs = grown;
        pairs[count].php_name = php_name; pairs[count].name = cookie+start;
        pairs[count].name_length = equal_at-start; pairs[count].value = cookie+equal_at+1;
        pairs[count].value_length = end-equal_at-1; pairs[count].order = count; ++count;
    }
    if (count > 1) qsort(pairs,count,sizeof(*pairs),reuse_pair_compare);
    for (i = 0; i < count; ++i) if (!i || strcmp(pairs[i-1].php_name,pairs[i].php_name)) ++groups;
    if (!reuse_lp_string(&frame,"ultracache-cookie-inputs-v1") ||
        !reuse_u32(&frame,inputs->php_max_input_vars) || !reuse_u32(&frame,inputs->name_count)) goto finished;
    for (i = 0; i < inputs->name_count; ++i) if (!reuse_lp_string(&frame,inputs->names[i])) goto finished;
    if (!reuse_u32(&frame,inputs->prefix_count)) goto finished;
    for (i = 0; i < inputs->prefix_count; ++i) if (!reuse_lp_string(&frame,inputs->prefixes[i])) goto finished;
    if (!reuse_u32(&frame,groups)) goto finished;
    i = 0;
    while (i < count) {
        size_t end = i+1;
        while (end < count && !strcmp(pairs[i].php_name,pairs[end].php_name)) ++end;
        if (!reuse_lp_string(&frame,pairs[i].php_name) || !reuse_u32(&frame,end-i)) goto finished;
        while (i < end) {
            if (!reuse_lp(&frame,pairs[i].name,pairs[i].name_length) ||
                !reuse_lp(&frame,pairs[i].value,pairs[i].value_length)) goto finished;
            ++i;
        }
    }
    *output = frame.bytes; *output_length = frame.length; frame.bytes = NULL;
    result = DELIVERY_REUSE_INPUT_OK;
finished:
    for (i = 0; i < count; ++i) free(pairs[i].php_name);
    free(pairs); delivery_reuse_frame_free(frame.bytes,frame.length); return result;
}

int delivery_reuse_key_derive(const unsigned char *secret, size_t secret_length, unsigned char key[32]) {
    static const unsigned char purpose[] = "ultracache-delivery-reuse-key-v1";
    char key_hex[65];
    size_t i;
    volatile unsigned char *wipe = (unsigned char *)key_hex;
    if (!secret || !secret_length || !key || !delivery_hmac_sha256(secret,secret_length,purpose,sizeof(purpose)-1,key_hex)) return 0;
    for (i = 0; i < 32; ++i)
        key[i] = (unsigned char)(hex_digit((unsigned char)key_hex[2*i])*16+hex_digit((unsigned char)key_hex[2*i+1]));
    for (i = 0; i < sizeof(key_hex); ++i) wipe[i] = 0;
    return 1;
}
static int reuse_context_mac(const unsigned char key[32],
    const struct delivery_reuse_context *context, const char *domain, size_t field_count, const unsigned char *projection,
    size_t projection_length, char mac[65]) {
    struct reuse_frame message = {NULL,0,0};
    const char *fields[10];
    size_t i;
    int valid = 0;
    if (mac) mac[0] = 0;
    if (!key || !context || !mac || (!projection && projection_length)) return 0;
    fields[0] = context->site_id; fields[1] = context->canonical_host; fields[2] = context->scope;
    fields[3] = context->epoch; fields[4] = context->native_policy; fields[5] = context->wordpress_policy;
    fields[6] = context->reuse_policy; fields[7] = context->publication_digest;
    fields[8] = context->representation; fields[9] = context->recipe_digest;
    for (i = 0; i < field_count; ++i) if (!fields[i] || !*fields[i]) return 0;
    if (!reuse_lp_string(&message,domain)) goto finished;
    for (i = 0; i < field_count; ++i) if (!reuse_lp_string(&message,fields[i])) goto finished;
    if (!reuse_lp(&message,projection,projection_length)) goto finished;
    valid = delivery_hmac_sha256(key,32,message.bytes,message.length,mac);
finished:
    delivery_reuse_frame_free(message.bytes,message.length); return valid;
}
static int reuse_context_binding(const unsigned char *secret, size_t secret_length,
    const struct delivery_reuse_context *context, const char *domain, size_t field_count, const unsigned char *projection,
    size_t projection_length, char mac[65]) {
    unsigned char key[32];
    volatile unsigned char *wipe = key;
    size_t i;
    int valid;
    if (mac) mac[0] = 0;
    if (!delivery_reuse_key_derive(secret,secret_length,key)) return 0;
    valid = reuse_context_mac(key,context,domain,field_count,projection,projection_length,mac);
    for (i = 0; i < sizeof(key); ++i) wipe[i] = 0;
    return valid;
}
int delivery_reuse_input_binding(const unsigned char *secret, size_t secret_length,
    const struct delivery_reuse_context *context, const unsigned char *projection,
    size_t projection_length, char mac[65]) {
    return reuse_context_binding(secret,secret_length,context,"ultracache-delivery-reuse-binding-v1",10,
        projection,projection_length,mac);
}
int delivery_reuse_identity_binding(const unsigned char *secret, size_t secret_length,
    const struct delivery_reuse_context *context, const unsigned char *projection,
    size_t projection_length, char mac[65]) {
    return reuse_context_binding(secret,secret_length,context,"ultracache-private-identity-binding-v1",7,
        projection,projection_length,mac);
}
int delivery_reuse_input_mac(const unsigned char key[32], const struct delivery_reuse_context *context,
    const unsigned char *projection, size_t length, char mac[65]) {
    return reuse_context_mac(key,context,"ultracache-delivery-reuse-binding-v1",10,projection,length,mac);
}
int delivery_reuse_identity_mac(const unsigned char key[32], const struct delivery_reuse_context *context,
    const unsigned char *projection, size_t length, char mac[65]) {
    return reuse_context_mac(key,context,"ultracache-private-identity-binding-v1",7,projection,length,mac);
}
