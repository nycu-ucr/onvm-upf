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

// Flip UE-wide buffering gate (atomic)
static inline void upfu_set_buffering(UpfSession *s, int on) {
    rte_atomic32_set(&s->buffering, on ? 1 : 0);
}

// UPF-C owns init/free in this model; init here is a stub for linkage
int  upfu_session_buf_init(UpfSession *s, unsigned ring_size);

void upfu_session_buf_destroy(UpfSession *s);

/* Enqueue one DL mbuf. Takes a new ref on success. Returns 0, or -ENOSPC/-ENOENT. */
int  upfu_enqueue_dl(UpfSession *s, struct rte_mbuf *m);

/* Drain up to budget packets and process via the live pipeline */
void upfu_drain_now(UpfSession *s, struct onvm_nf_local_ctx *ctx);

/* Implemented in upf_u.c: hands a drained packet into the exact live pipeline */
void __upf_process_dl_packet(struct rte_mbuf *m,
                             UpfSession *s,
                             struct onvm_nf_local_ctx *ctx);
