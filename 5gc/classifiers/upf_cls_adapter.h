#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "../../onvm/updk/updk/rule_pdr.h"
#include "classifier_wrapper.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Convert a control-plane UPDK_PDR into a classifier-ready rule.
 * - is_uplink selects the sourceInterface (ACCESS vs CORE) and may affect SDF mapping.
 * - The returned pdr_t is a POD struct the builder can pass to cls_insert_rule().
 * - 'descriptor' is not set here. */
pdr_t updk_pdr_to_cls_rule(const UPDK_PDR *in, bool is_uplink);

#ifdef __cplusplus
}
#endif
