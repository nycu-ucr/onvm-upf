#pragma once

// Service IDs (override at build/run time if needed)
#ifndef UPF_INGRESS_SERVICE_ID
#define UPF_INGRESS_SERVICE_ID 1
#endif

#ifndef UPF_EGRESS_SERVICE_ID
#define UPF_EGRESS_SERVICE_ID 14
#endif

#ifndef UPF_U_SERVICE_ID
#define UPF_U_SERVICE_ID UPF_INGRESS_SERVICE_ID
#endif

#ifndef UPF_C_SERVICE_ID
#define UPF_C_SERVICE_ID 2
#endif

// Classifier consumer IDs (for GC ACK masking)
enum {
        UPF_CLS_CONS_INGRESS = 0,
        UPF_CLS_CONS_EGRESS  = 1,
        UPF_CLS_CONS_MAX     = 2,
};

enum {
        UPF_EVENT_SET_BUFFER       = 0xA0,
        UPF_EVENT_CLEAR_AND_DRAIN  = 0xA1,
        UPF_EVENT_REGISTER_SESSION = 0xA2,
        UPF_EVENT_DELETE_SESSION   = 0xA3,

        EVT_CLS_GC_REQ = 0x4201,
        EVT_CLS_GC_ACK = 0x4202,
};
