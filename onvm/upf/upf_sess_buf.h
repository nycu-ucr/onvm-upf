/*
 * Per-Session DL Buffer State — shared between UPF-C and UPF-U
 *
 * Each session gets an rte_ring for DL packet buffering.  The state
 * array lives in a DPDK memzone so both processes see the same data.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdint.h>
#include <rte_ring.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MZ_UPF_SESS_BUF     "UPF_SESS_BUF"
#define SESS_BUF_MAX_USERS   1024        /* must match MAX_NUM_OF_USERS */
#define SESS_RING_SIZE       1024        /* per-session ring capacity   */

typedef struct {
    struct rte_ring *ring;       /* SP/SC ring for DL packets      */
    uint8_t  ring_created;       /* 1 = ring has been allocated     */
    uint8_t  touched;            /* 1 = has pending pkts since tick */
    uint8_t  is_buffering;       /* 1 = FAR is BUFF, skip drains   */
} UpfSessBuf;

/* Global pointer to the shared UpfSessBuf array (set by UpfSessBufInit) */
extern UpfSessBuf *g_sess_buf;

/* Map or create the shared memzone.  Called once per process. */
int  UpfSessBufInit(void);

/* Create a session ring (called from UPF-C on UpfSessionAdd).
 * Returns 0 on success, -1 on failure. */
int  UpfSessBufRingCreate(int sess_index);

/* Destroy a session ring (called from UPF-C on UpfSessionRemove). */
void UpfSessBufRingDestroy(int sess_index);

#ifdef __cplusplus
}
#endif