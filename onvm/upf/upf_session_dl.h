#pragma once

#include <stdint.h>

#include <rte_atomic.h>

#include "upf_context.h"

#ifndef UPF_DL_RING_SIZE
#define UPF_DL_RING_SIZE 4096
#endif

/* Accessors for the shared buffering flag (0 = live, 1 = paused) */
static inline uint32_t UpfSessionIsBuffered(const UpfSession *s) {
    return rte_atomic32_read(&s->buffering);
}

static inline void UpfSessionSetBuffering(UpfSession *s, uint32_t val) {
    rte_atomic32_set(&s->buffering, val ? 1 : 0);
}

/* Ensure a per-session DL ring exists and is published. Returns NULL on failure. */
struct rte_ring *UpfSessionEnsureDlRing(UpfSession *session);

