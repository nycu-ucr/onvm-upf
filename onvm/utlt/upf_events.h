#pragma once

// UPF-U service id = 1
#ifndef UPF_U_SERVICE_ID
#define UPF_U_SERVICE_ID  1 
#endif


/* Tunables (power-of-two ring size recommended) */
// Max number of downlink mbufs we’ll buffer per UE in that UE’s rte_ring
#ifndef UPF_SESSION_RING_SIZE
#define UPF_SESSION_RING_SIZE 256
#endif


// Max number of packets we’ll pop from a UE’s ring in one drain call
// Budget per CLEAR_AND_DRAIN; 64–256 are typical
// Not being used now
#ifndef UPF_SESSION_DRAIN_BUDGET
#define UPF_SESSION_DRAIN_BUDGET 256
#endif


// UPF_EGRESS_TICK_INTERVAL — how often to run the tick (in enqueues).

// UPF_TICK_DRAIN_BUDGET — how much to drain per touched UE.

// UPF_INLINE_DRAIN_BUDGET — how much to drain immediately for the current UE.

// Inline drain budget when BUFF is OFF (live path kick)
#ifndef UPF_INLINE_DRAIN_BUDGET
#define UPF_INLINE_DRAIN_BUDGET 8
#endif

// Drain budget when CLEAR_AND_DRAIN fires (release kick)
#ifndef UPF_EVENT_KICK_BUDGET
#define UPF_EVENT_KICK_BUDGET 512
#endif

// Per-burst egress tick budget per touched UE
#ifndef UPF_TICK_DRAIN_BUDGET
#define UPF_TICK_DRAIN_BUDGET 32
#endif

// How often (in number of successful enqueues) to run egress tick
#ifndef UPF_EGRESS_TICK_INTERVAL
#define UPF_EGRESS_TICK_INTERVAL 32
#endif

enum {
        UPF_EVENT_SET_BUFFER       = 0xA0,
        UPF_EVENT_CLEAR_AND_DRAIN  = 0xA1,
};


