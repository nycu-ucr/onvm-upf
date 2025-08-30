#pragma once

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


