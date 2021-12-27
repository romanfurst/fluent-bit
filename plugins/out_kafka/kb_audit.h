#ifndef KB_AUDII_H   /* Include guard */
#define KB_AUDIT_H

#include "cJSON.h"
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <float.h>

#include "kafka_config.h"
#include <fluent-bit/flb_output_plugin.h>

void kb_audit_sign(struct flb_kafka *ctx, char **jsonMessage);

#endif