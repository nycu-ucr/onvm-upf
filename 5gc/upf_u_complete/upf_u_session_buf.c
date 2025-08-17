#include <stdio.h>
#include <errno.h>
#include <inttypes.h>

#include <rte_errno.h>

#include "upf_events.h"
#include "upf_u_session_buf.h"


/* static inline const char * ring_name_for(UpfSession *s, char *buf, size_t n) {
    snprintf(buf, n, "upf_dl_%p", (void*)s);
    return buf;
} */


static inline void upfu_set_buffering(UpfSession *s, int on) {
    rte_atomic32_set(&s->buffering, on ? 1 : 0);
}


// NOTE: init is owned by UPF-C now. Keeping a stub for linkage if anything ever calls it.

int upfu_session_buf_init(UpfSession *s, unsigned ring_size) {
    (void)ring_size;
    return (s && s->dl_ring) ? 0 : -ENOENT;
}

// NOTE: ring free is owned by UPF-C now. If ever called, only drain mbufs it sees
// no call to rte_ring_free() here; UPF-C owns/frees the ring

void upfu_session_buf_destroy(UpfSession *s) {
    if (!s || !s->dl_ring) return;

    struct rte_mbuf *m = NULL;
    while (rte_ring_sc_dequeue(s->dl_ring, (void**)&m) == 0) {
        rte_pktmbuf_free(m);
    }
}

int upfu_enqueue_dl(UpfSession *s, struct rte_mbuf *m) {
    
    if (unlikely(!s || !s->dl_ring)) {
        if (s) s->dl_drp++;      // no ring provisioned
        return -ENOENT;
    }

    // Buffer takes its own reference; live path will DROP/free its ref
    rte_pktmbuf_refcnt_update(m, 1);

    if (rte_ring_mp_enqueue(s->dl_ring, m) != 0) {
        // Tail-drop: undo the extra ref and count drop
        rte_pktmbuf_free(m);
        s->dl_drp++;
        return -ENOSPC;
    }

    s->dl_enq++;
    return 0;
}


void upfu_drain_now(UpfSession *s, struct onvm_nf_local_ctx *ctx) {
    if (!s || !s->dl_ring) return;

    unsigned drained = 0;
    struct rte_mbuf *m = NULL;

    while (drained < UPF_SESSION_DRAIN_BUDGET && rte_ring_sc_dequeue(s->dl_ring, (void**)&m) == 0) {
        __upf_process_dl_packet(m, s, ctx);
        drained++;
    }

    s->dl_deq += drained;
}
