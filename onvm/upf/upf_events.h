#pragma once
#include <stdint.h>
#include <rte_malloc.h>
#include "onvm_nflib.h"

/* -------- Event types (control-plane and cross-NF) -------- */
#define UPF_EVT_REG_SESSION      0x1001u  /* payload: arg0 = SEID (uint64_t)   */
#define UPF_EVT_DEL_SESSION      0x1002u  /* payload: arg0 = SEID (uint64_t)   */
#define UPF_EVT_CLEAR_BUFFERING  0x1003u  /* payload: arg0 = SEID (uint64_t)   */

/* -------- Default wiring (override at build if you like) -------- */
#ifndef UPF_EGRESS_SID
#define UPF_EGRESS_SID  42   /* Egress NF SID; set to our actual SID in go.sh/args */
#endif

#ifndef UPF_DL_RING_SIZE
#define UPF_DL_RING_SIZE  4096
#endif

/* -------- Minimal 1-arg event sender (ownership transferred on success) -------- */
static inline int UpfSendEvt1(uint16_t dest_sid, uint32_t type, uintptr_t a0) {
    Event *e = (Event *)rte_calloc("upf_evt", 1, sizeof(*e), 0);
    if (unlikely(!e)) return -1;
    e->type = (uintptr_t)type;
    e->argc = 1;
    e->arg0 = a0;
    const int rc = onvm_nflib_send_msg_to_nf(dest_sid, e);
    if (rc < 0) rte_free(e);
    return rc;
}
