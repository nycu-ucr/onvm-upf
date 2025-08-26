#include <stdio.h>
#include <errno.h>
#include <inttypes.h>

#include <rte_errno.h>

#include "upf_events.h"
#include "upf_u_session_buf.h"

// remove after test
#define DUPLOG(fmt, ...) \
  do { if (g_upf_dup_trace) UTLT_Info("[DUPTRACE] " fmt, ##__VA_ARGS__); } while (0)




// Guard defined in upf_u.c; we toggle it so drained packets never re-enqueue
extern int __upf_in_drain;

// remove after test
extern int g_upf_dup_trace;

extern int upf_icmp_seq(struct rte_mbuf *m, uint16_t *seq_out);


int upfu_session_buf_init(UpfSession *s, unsigned ring_size) {
    if (!s) return -EINVAL;
    s->dl_ring = NULL;
    rte_atomic32_set(&s->buffering, 0);
    s->dl_enq = s->dl_deq = s->dl_drp = 0;
    return 0;
}

void upfu_session_buf_destroy(UpfSession *s) {
    if (!s || !s->dl_ring) return;

    struct rte_mbuf *m = NULL;
    while (rte_ring_sc_dequeue(s->dl_ring, (void**)&m) == 0) {
        rte_pktmbuf_free(m);
    }
        // Ring lifetime is owned by context/session destroy (now we free in upf_context.c)
}

int upfu_enqueue_dl(UpfSession *s, struct rte_mbuf *m) {
    if (unlikely(!s || !s->dl_ring)) {
        if (s) s->dl_drp++;      // no ring provisioned
        return -ENOENT;
    }

    // Buffer takes its own reference; the ingress path will DROP/free its ref
    // rte_pktmbuf_refcnt_update(m, 1);


    uint16_t seq=0; int has = upf_icmp_seq(m, &seq);
    DUPLOG("ENQ try  s=%p m=%p%s%u",
       s, m, has ? " icmp_seq=" : "", has ? seq : 0);
    

    // Single-core: SP enqueue
    if (rte_ring_sp_enqueue(s->dl_ring, m) != 0) {
        // Tail-drop: undo the extra ref and count drop
        rte_pktmbuf_free(m);
        s->dl_drp++;
        return -ENOSPC;
    }

    DUPLOG("ENQ ok   s=%p m=%p ring_count=%u",
       s, m, rte_ring_count(s->dl_ring));


    s->dl_enq++;
    return 0;
}

static inline void upfu_drain_budget(UpfSession *s, struct onvm_nf_local_ctx *ctx, unsigned budget) {
    if (!s || !s->dl_ring || budget == 0) return;

    unsigned drained = 0;
    struct rte_mbuf *m = NULL;

    // Mark that we are processing drained packets (no re-enqueue in packet_handler)
    int prev = __upf_in_drain;
    __upf_in_drain = 1;

    while (drained < budget && rte_ring_sc_dequeue(s->dl_ring, (void**)&m) == 0) {

        uint16_t dseq=0; int dhas = upf_icmp_seq(m, &dseq);
        DUPLOG("DEQ      s=%p m=%p left=%u%s%u",
        s, m, rte_ring_count(s->dl_ring),
        dhas ? " icmp_seq=" : "", dhas ? dseq : 0);

        __upf_process_dl_packet(m, s, ctx);
        drained++;
    }

    __upf_in_drain = prev;

    s->dl_deq += drained;

}

void upfu_drain_some(UpfSession *s, struct onvm_nf_local_ctx *ctx, unsigned budget) {
    // Only drain when not paused (BUFF OFF)
    if (!s) return;
    if (rte_atomic32_read(&s->buffering) != 0) return;
    upfu_drain_budget(s, ctx, budget);
}

void upfu_drain_now(UpfSession *s, struct onvm_nf_local_ctx *ctx) {
    upfu_drain_some(s, ctx, UPF_SESSION_DRAIN_BUDGET);
}
