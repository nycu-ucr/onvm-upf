#pragma once
#include <stdint.h>
#include <stdbool.h>

/* UPDK_PDR definition */
#include "../../onvm/updk/updk/rule_pdr.h"
#include "classifier_wrapper.h"


#ifdef __cplusplus
extern "C" {
#endif

/* Insert the PDR into the classifier.
 * Returns 0 on success, −1 on failure (e.g. capacity, duplicate).         */
uintptr_t upf_cls_add_pdr(const UPDK_PDR *pdr);

/* Remove that exact PDR (keyed by its pointer).
 * Returns 0 on success, −1 if not found.                                  */
int upf_cls_del_pdr(const UPDK_PDR *pdr);

/* Fast-path lookup.  Returns matching UPDK_PDR* or NULL if no hit.        */
const UPDK_PDR *upf_cls_lookup(const ps_packet_t *pkt);

#ifdef __cplusplus
}
#endif
