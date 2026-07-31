#pragma once

#include <stdint.h>

#include <rte_malloc.h>

#include "onvm_nflib.h"
#include "utlt_event.h"

// UPF-U service id = 1
#ifndef UPF_U_SERVICE_ID
#define UPF_U_SERVICE_ID  1 
#endif

#ifndef UPF_C_SERVICE_ID
#define UPF_C_SERVICE_ID  2
#endif


enum {
        UPF_EVENT_SET_BUFFER       = 0xA0,
        UPF_EVENT_CLEAR_AND_DRAIN  = 0xA1,
        EVT_CLS_GC_REQ = 0x4201,
        EVT_CLS_GC_ACK = 0x4202,
};

static inline int
UpfSendEvt1(uint16_t dest_sid, uint32_t type, uintptr_t a0) {
        Event *e = (Event *)rte_calloc("upf_evt", 1, sizeof(*e), 0);
        if (!e) return -1;
        e->type = (uintptr_t)type;
        e->argc = 1;
        e->arg0 = a0;
        int rc = onvm_nflib_send_msg_to_nf(dest_sid, e);
        if (rc < 0) rte_free(e);
        return rc;
}

