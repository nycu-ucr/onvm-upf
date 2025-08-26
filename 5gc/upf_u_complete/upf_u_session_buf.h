#pragma once

#include <stdint.h>
#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_atomic.h>
#include <rte_byteorder.h>

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"

#include "upf_context.h"
#include "upf_events.h"


typedef enum {
    UPF_DRAIN_SRC_INLINE = 1,
    UPF_DRAIN_SRC_TICK   = 2,
    UPF_DRAIN_SRC_EVENT  = 3
} upf_drain_src_t;


// Flip UE-wide buffering gate (atomic). 1=paused (BUFF ON), 0=live (BUFF OFF)
static inline int upfu_set_buffering(UpfSession *s, int new_state) {
    int prev = rte_atomic32_read(&s->buffering);
    if (new_state != prev) {
        rte_atomic32_set(&s->buffering, new_state);
    }
    return prev;
}

/* Initialize/destroy per-UE ring and counters */
int  upfu_session_buf_init(UpfSession *s, unsigned ring_size);
void upfu_session_buf_destroy(UpfSession *s);

/* Enqueue one DL mbuf. Takes a new ref on success. Returns 0, or -ENOSPC/-ENOENT. */
int  upfu_enqueue_dl(UpfSession *s, struct rte_mbuf *m);

/* Drain up to UPF_SESSION_DRAIN_BUDGET packets via the live pipeline */
void upfu_drain_now(UpfSession *s, struct onvm_nf_local_ctx *ctx);

/* Drain up to 'budget' packets via the live pipeline */
void upfu_drain_some(UpfSession *s, struct onvm_nf_local_ctx *ctx, unsigned budget, upf_drain_src_t src);

/* Implemented in upf_u.c: hands a drained packet into the exact live pipeline */
void __upf_process_dl_packet(struct rte_mbuf *m, UpfSession *s, struct onvm_nf_local_ctx *ctx, upf_drain_src_t src);
