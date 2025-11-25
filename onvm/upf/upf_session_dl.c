#include "upf_session_dl.h"

#include <stdio.h>

#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_memory.h>
#include <rte_ring.h>
#include <rte_string_fns.h>

#include "utlt_debug.h"

struct rte_ring *
UpfSessionEnsureDlRing(UpfSession *session) {
    if (!session) return NULL;

    struct rte_ring *ring = __atomic_load_n(&session->dl_ring, __ATOMIC_ACQUIRE);
    if (ring) return ring;

    char name[RTE_RING_NAMESIZE];
    int len = snprintf(name, sizeof(name), "upf_dl_%u", session->sess_id);
    if (len < 0 || len >= (int)sizeof(name)) {
        UTLT_Error("Failed to format DL ring name for sess_id=%u", session->sess_id);
        return NULL;
    }

    /* Reuse if another producer created it first */
    ring = rte_ring_lookup(name);
    if (!ring) {
        ring = rte_ring_create(name, UPF_DL_RING_SIZE, rte_socket_id(), RING_F_SC_DEQ);
    }
    if (!ring) {
        UTLT_Error("DL ring create/lookup failed for sess_id=%u name=%s (errno=%d)", session->sess_id, name, rte_errno);
        return NULL;
    }

    /* Publish pointer with release semantics before any enqueue */
    __atomic_store_n(&session->dl_ring, ring, __ATOMIC_RELEASE);
    rte_wmb();
    return ring;
}
