#include "kb_audit.h"
#include <string.h>

void kb_audit_sign(struct flb_kafka *ctx, char *jsonMessage) {
    flb_plg_info(ctx->ins, "---------before");
    flb_plg_info(ctx->ins, "%s", jsonMessage);
    cJSON *input = cJSON_Parse(jsonMessage);

    /*cJSON *meta_object = get_object_item(input, "@meta", 1);
    if (meta_object) {
        flb_plg_info(ctx->ins, "@meta found");
        //cJSON_AddStringToObject
    }else {
        flb_plg_info(ctx->ins, "@meta field not found in audit log. Hmac signing skipped");
    }*/

    /*cJSON *elem;
    for (elem = input->child; elem != NULL; elem = elem->next) {
        flb_plg_info(ctx->ins, "%s", elem->string);
        //todo use get_object_item
        if (cJSON_IsObject(elem) && elem->string && !strcmp(elem->string, "@meta")) {
            flb_plg_info(ctx->ins, "@meta found");


        }
    }*/
    cJSON *elem = input->child;
    while (elem != NULL && elem->string != NULL && strcmp("@meta", elem->string))
    {
        elem = elem->next;
    }
    if ((elem == NULL) || (elem->string == NULL) || strcmp("@meta", elem->string)) {
        flb_plg_info(ctx->ins, "@meta field not found in audit log. Hmac signing skipped");
        return;
    }
    flb_plg_info(ctx->ins, "@meta found");
    //cJSON_AddStringToObject(cJSON * const object, const char * const name, const char * const string);
    cJSON_AddStringToObject(elem, "id", "blabla");


    jsonMessage = cJSON_PrintUnformatted(input);


    //flb_plg_info(ctx->ins, "---------after");
    //flb_plg_info(ctx->ins, "%s", jsonMessage);

    cJSON_Delete(input);

}

/*
static void simplifyAndPrint(const char *json) {
    cJSON *input = cJSON_Parse(json);
    cJSON *output = cJSON_CreateObject();
    simplify(input->child, output);
    printf("%s\n", cJSON_PrintUnformatted(output));
    cJSON_Delete(input);
    cJSON_Delete(output);
}*/
