#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <rte_memory.h>                  /* rte_wmb */
#include "../../onvm/updk/updk/rule_pdr.h"
#include "../../onvm/upf/upf_context.h"  /* g_upf_cls_ctrl */
#include "classifier_wrapper.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Convert a control-plane UPDK_PDR into a classifier-ready rule.
 * - is_uplink selects the sourceInterface (ACCESS vs CORE) and may affect SDF mapping.
 * - The returned pdr_t is a POD struct the builder can pass to cls_insert_rule().
 * - 'descriptor' is not set here (builder may set it to a PDR cookie or DP-view). */
pdr_t updk_pdr_to_cls_rule(const UPDK_PDR *in, bool is_uplink);

/* Publish a freshly built immutable snapshot into the shared control slot.
 * Returns the new monotonically increasing version.
 * If retired_out != NULL, *retired_out receives the previously active pointer. */
static inline uint32_t upf_cls_publish(void *new_snap, void **retired_out) {
    /* Publish order: snapshot contents (already built) → pointer → version */
    rte_wmb();
    void *old = g_upf_cls_ctrl->active;
    g_upf_cls_ctrl->active = new_snap;
    rte_wmb();
    uint32_t v = g_upf_cls_ctrl->version + 1u;
    g_upf_cls_ctrl->version = v;
    if (retired_out) *retired_out = old;
    return v;
}

#ifdef __cplusplus
}
#endif
