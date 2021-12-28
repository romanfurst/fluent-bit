#include "kb_audit.h"
#include "base64.h"
#include <string.h>

void kb_audit_sign(struct flb_kafka *ctx, char **jsonMessage) {
    cJSON *input = cJSON_Parse(*jsonMessage);

    cJSON *elem = input->child;
    while (elem != NULL && elem->string != NULL && strcmp("@meta", elem->string))
    {
        elem = elem->next;
    }
    if ((elem == NULL) || (elem->string == NULL) || strcmp("@meta", elem->string)) {
        flb_plg_info(ctx->ins, "@meta field not found in audit log. Hmac signing skipped");
        return;
    }
    unsigned char *result = NULL;
    unsigned int result_len = -1;

    //todo tohle se musi odnekud vzit dynamicky
    unsigned char *key = "sekret";

    result = HMAC(EVP_sha256(), key, strlen(key), *jsonMessage, strlen(*jsonMessage), result, &result_len);
    if (result) {
        unsigned char hex_str[65];
        to_hex_string(result, hex_str);
        flb_plg_info(ctx->ins, "hmac %s", hex_str);

        unsigned int encode_len = Base64encode_len(64);
        unsigned char encoded_result[encode_len];
        Base64encode(encoded_result, hex_str, 64);

        cJSON_AddStringToObject(elem, "id", encoded_result);
    } else {
        flb_plg_warn(ctx->ins, "Hmac cannot be computed. ID @meta filed not set");
    }

    *jsonMessage = cJSON_PrintUnformatted(input);
    cJSON_Delete(input);
}

void to_hex_string(unsigned char* input, unsigned  char output[65])
{
    for (unsigned int i = 0; i < 32; ++i) {
        sprintf(output + (i * 2), "%02x", (unsigned char)input[i]);
    }
    output[64] = 0;
}