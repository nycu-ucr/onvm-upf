#pragma once
#include <stdint.h>
#include <stdbool.h>

#include "onvm/updk/updk/rule_pdr.h"     /* UPDK_PDR definition              */

#ifdef __cplusplus
extern "C" {
#endif

/* Insert the PDR into the selected classifier back-end.
 * Returns 0 on success, -1 on error (e.g., capacity or duplicate).        */
int upf_cls_add_pdr(const UPDK_PDR *pdr);

/* Remove the rule keyed by that exact PDR pointer (descriptor pattern).
 * Returns 0 on success, -1 if not found.                                   */
int upf_cls_del_pdr(const UPDK_PDR *pdr);

#ifdef __cplusplus
}
#endif
