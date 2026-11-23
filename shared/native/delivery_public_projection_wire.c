/* SPDX-License-Identifier: GPL-3.0-or-later
 * Included after the existing portable mutation codec. Reuse its strict JSON
 * string/base64 encoders; projection remains data, not a new authority/MAC.
 */
char *delivery_public_projection_header(const struct delivery_public_projection *p) {
    struct reuse_frame json = {NULL,0,0};
    const struct delivery_cookie_update *u;
    char *header = NULL, *value = NULL;
    const char *names[] = {"bucket","locale","language"};
    const char *values[3];
    size_t i;
    static const char opening[] = "{\"version\":1";
    static const char cookies[] = ",\"cookieValues\":[";
    if (!p || !p->bucket || !p->locale || !p->language) return NULL;
    values[0] = p->bucket; values[1] = p->locale; values[2] = p->language;
    if (!reuse_append(&json,opening,sizeof(opening)-1)) goto done;
    for (i = 0; i < 3; ++i)
        if (!reuse_append(&json,",",1) || !mutation_json_string(&json,names[i]) ||
            !reuse_append(&json,":",1) || !mutation_json_string(&json,values[i])) goto done;
    if (!reuse_append(&json,cookies,sizeof(cookies)-1)) goto done;
    for (u = p->cookies; u; u = u->next) {
        static const char row[] = "{\"name\":";
        static const char encoded[] = ",\"valueBase64\":";
        if ((u != p->cookies && !reuse_append(&json,",",1)) ||
            !reuse_append(&json,row,sizeof(row)-1) || !mutation_json_string(&json,u->name) ||
            !reuse_append(&json,encoded,sizeof(encoded)-1)) goto done;
        if (!u->value) { if (!reuse_append(&json,"null",4)) goto done; }
        else {
            value = mutation_base64((const unsigned char *)u->value,strlen(u->value));
            if (!value || !mutation_json_string(&json,value)) goto done;
            free(value); value = NULL;
        }
        if (!reuse_append(&json,"}",1)) goto done;
    }
    if (reuse_append(&json,"]}",2)) header = mutation_base64(json.bytes,json.length);
done:
    free(value); free(json.bytes); return header;
}
int delivery_public_projection_header_parse(const char *header, size_t length,
    struct delivery_public_projection **out) {
    unsigned char *body = NULL;
    size_t decoded = 0;
    int valid = 0;
    if (!out) return 0;
    *out = NULL;
    if (header && base64_body((struct text){header,length},&body,&decoded))
        valid = delivery_public_projection_parse((const char *)body,decoded,out);
    free(body); return valid;
}
