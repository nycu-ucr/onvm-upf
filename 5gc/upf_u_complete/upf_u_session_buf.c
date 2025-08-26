#include <stdio.h>
#include <errno.h>
#include <inttypes.h>

#include <rte_errno.h>

#include "upf_events.h"
#include "upf_u_session_buf.h"

extern int g_upf_dup_trace;
#define BUFLOG(tag, fmt, ...) \
  do { if (g_upf_dup_trace) UTLT_Info("[BUF:%s] " fmt, tag, ##__VA_ARGS__); } while (0)



static inline const char* src2s(upf_drain_src_t src) {
    switch (src) {
    case UPF_DRAIN_SRC_INLINE: return "INLINE";
    case UPF_DRAIN_SRC_TICK:   return "TICK";
    case UPF_DRAIN_SRC_EVENT:  return "EVENT";
    default: return "UNKNOWN";
    }
}


// Guard defined in upf_u.c; we toggle it so drained packets never re-enqueue
extern int __upf_in_drain;


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
    

    // Single-core: SP enqueue
    if (rte_ring_sp_enqueue(s->dl_ring, m) != 0) {
        // Tail-drop: undo the extra ref and count drop
        rte_pktmbuf_free(m);
        s->dl_drp++;
        return -ENOSPC;
    }

    BUFLOG("ENQ", "ok s=%p m=%p ring=%u", s, m,
      s && s->dl_ring ? rte_ring_count(s->dl_ring) : 0);


    s->dl_enq++;
    return 0;
}

static inline void upfu_drain_budget(UpfSession *s, struct onvm_nf_local_ctx *ctx, unsigned budget, upf_drain_src_t src) {
    if (!s || !s->dl_ring || budget == 0) return;

    unsigned drained = 0;

    BUFLOG("DRAIN", "start src=%s s=%p budget=%u avail=%u",
          src2s(src), s, budget, rte_ring_count(s->dl_ring));

    // Mark that we are processing drained packets (no re-enqueue in packet_handler)
    __upf_in_drain++;

    while (drained < budget) {
        struct rte_mbuf *m = NULL;
        if (rte_ring_dequeue(s->dl_ring, (void**)&m) != 0) break;

        /* hand off to the live pipeline; packet_handler() must fully consume m */
        __upf_process_dl_packet(m, s, ctx, src);
        drained++;
    }

    __upf_in_drain--;

    s->dl_deq += drained;

    BUFLOG("DRAIN", "done  src=%s s=%p drained=%u left=%u",
          src2s(src), s, drained, rte_ring_count(s->dl_ring));

}

void upfu_drain_some(UpfSession *s, struct onvm_nf_local_ctx *ctx, unsigned budget, upf_drain_src_t src) {
    // Only drain when not paused (BUFF OFF)
    if (!s) return;
    if (rte_atomic32_read(&s->buffering) != 0) return;
    upfu_drain_budget(s, ctx, budget, src);
}

void upfu_drain_now(UpfSession *s, struct onvm_nf_local_ctx *ctx) {
    upfu_drain_some(s, ctx, UPF_SESSION_DRAIN_BUDGET, UPF_DRAIN_SRC_EVENT);
}
