#pragma once

// UPF-U service id = 1
#ifndef UPF_U_SERVICE_ID
#define UPF_U_SERVICE_ID  1 
#endif


/* Tunables (power-of-two ring size recommended) */
// Max number of downlink mbufs we’ll buffer per UE in that UE’s rte_ring
#ifndef UPF_SESSION_RING_SIZE
#define UPF_SESSION_RING_SIZE 2048
#endif


// Max number of packets we’ll pop from a UE’s ring in one drain call
// Budget per CLEAR_AND_DRAIN; 64–256 are typical
#ifndef UPF_SESSION_DRAIN_BUDGET
#define UPF_SESSION_DRAIN_BUDGET 128
#endif

enum {
  UPF_EVENT_SET_BUFFER       = 0xA0,
  UPF_EVENT_CLEAR_AND_DRAIN  = 0xA1,
};