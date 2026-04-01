/*
 * Per-Session DL Buffer State — implementation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>
#include <rte_memzone.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_malloc.h>

#include "upf_sess_buf.h"
#include "utlt_debug.h"

UpfSessBuf *g_sess_buf = NULL;

int UpfSessBufInit(void) {
    const struct rte_memzone *mz = rte_memzone_lookup(MZ_UPF_SESS_BUF);
    if (!mz) {
        /* Primary process — create and zero-init */
        mz = rte_memzone_reserve_aligned(
            MZ_UPF_SESS_BUF,
            sizeof(UpfSessBuf) * SESS_BUF_MAX_USERS,
            SOCKET_ID_ANY,
            RTE_MEMZONE_2MB,
            RTE_CACHE_LINE_SIZE);
        if (!mz) {
            UTLT_Error("Failed to reserve memzone for sess_buf");
            return -1;
        }
        memset(mz->addr, 0, sizeof(UpfSessBuf) * SESS_BUF_MAX_USERS);
    }

    g_sess_buf = (UpfSessBuf *)mz->addr;
    return 0;
}

int UpfSessBufRingCreate(int sess_index) {
    if (sess_index < 0 || sess_index >= SESS_BUF_MAX_USERS)
        return -1;

    UpfSessBuf *sb = &g_sess_buf[sess_index];
    if (sb->ring_created)
        return 0;  /* already exists */

    char name[32];
    snprintf(name, sizeof(name), "sb_%04d", sess_index);

    sb->ring = rte_ring_create(name, SESS_RING_SIZE,
                               SOCKET_ID_ANY,
                               RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (!sb->ring) {
        UTLT_Error("Failed to create ring %s", name);
        return -1;
    }
    sb->ring_created = 1;
    sb->touched = 0;
    sb->is_buffering = 0;
    return 0;
}

void UpfSessBufRingDestroy(int sess_index) {
    if (sess_index < 0 || sess_index >= SESS_BUF_MAX_USERS)
        return;

    UpfSessBuf *sb = &g_sess_buf[sess_index];
    if (sb->ring) {
        /* Drain and free any remaining mbufs */
        struct rte_mbuf *m;
        while (rte_ring_sc_dequeue(sb->ring, (void **)&m) == 0)
            rte_pktmbuf_free(m);
        rte_ring_free(sb->ring);
    }
    sb->ring = NULL;
    sb->ring_created = 0;
    sb->touched = 0;
    sb->is_buffering = 0;
}