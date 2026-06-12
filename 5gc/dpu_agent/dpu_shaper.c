/*
 * dpu_shaper.c — DPU ARM-side buffered token-bucket shaper for GBR YELLOW
 *
 * GBR traffic is metered by a trTCM color gate in hardware: GREEN stays on
 * the HW fast path, RED is dropped, and YELLOW (between GBR and MBR) is
 * RSS-redirected to ARM Rx queues.  This module shapes that YELLOW at the
 * Excess Information Rate (EIR = MBR - GBR) using a per-flow token bucket,
 * and — when buffering is enabled (m-shape-bytes > 0) — QUEUES over-token
 * YELLOW per-flow up to a delay/memory-bounded cap and drains it at EIR,
 * instead of dropping on the first token miss.  With m-shape-bytes == 0 the
 * module degrades to the legacy immediate pass/drop token-bucket policer.
 *
 * Thread model:
 *   - shaper_loop runs on a dedicated lcore: it drains backlogged flows
 *     (ready_ring) and then polls the Rx queues.  Both the per-flow queue
 *     producer (Rx enqueue) and consumer (drain dequeue) are this ONE lcore,
 *     so each flow->queue is single-threaded (SP/SC).
 *   - register/unregister/update_rate/request_flush run on the Comch thread.
 *     The rte_hash uses RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY so concurrent
 *     lookup (lcore) + add_key (Comch) is safe.  Flow-slot visibility is
 *     guarded by __atomic ACQUIRE/RELEASE on flow->state.
 *   - The Comch thread NEVER frees queued mbufs.  Unregister marks the flow
 *     CLOSING and pushes it to ready_ring; the shaper lcore frees the backlog
 *     and sets the slot INACTIVE.  The slot AND its hash key persist for
 *     in-place reuse (the next register of the same hw_rule_id lands on the
 *     same slot via add_key and reuses it once INACTIVE) — mirroring the
 *     dpu_buffer slot-lifecycle invariant.  The lcore does NOT del_key
 *     (that would race add_key on the Comch thread); the table therefore
 *     fills after max_hw_rules distinct GBR flows — the same bounded
 *     behaviour the buffer module accepts.
 *
 * Slow-path Tx in VNF mode: software-Tx'd packets traverse the EGRESS
 * pipeline of the Tx port and never re-enter the ingress ROOT, so the
 * shaper finalises the wire-form packet in software and Tx's it on the
 * peer port:
 *   UL YELLOW (Rx N3): SW GTP-U decap (dpu_gtp_decap_ul) -> Tx N6 wire.
 *   DL YELLOW (Rx N6): SW GTP-U + PSC encap (dpu_gtp_encap_dl) -> Tx N3 wire.
 * The codec also clears the Rx-inherited dyn-metadata flag/field on each
 * packet so DL_ENCAP doesn't re-match a SW-encapped DL frame on N3 EGRESS
 * and double-encap.  See dpu_gtp_codec.{h,c}.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>
#include <rte_ring.h>

#include <doca_log.h>

#include "dpu_gtp_codec.h"
#include "dpu_shaper.h"

DOCA_LOG_REGISTER(DPU_SHAPER);

/* ── Helpers ────────────────────────────────────────────────────────── */

/** Convert kbps to bytes/sec: kbps * 1000 / 8 */
static inline uint64_t
kbps_to_bytes_per_sec(uint64_t kbps)
{
    return kbps * 125;  /* kbps * 1000 / 8 */
}

/**
 * Derive the per-flow queued-byte cap from EIR and the delay target:
 *   q_max = clamp(EIR * shape_max_delay_ms / 1000, MIN, MAX)
 * EIR == 0 yields 0 (YELLOW has no excess entitlement -> drop all).
 */
static inline uint64_t
compute_q_max_bytes(const shaper_ctx_t *ctx, uint64_t eir_Bps)
{
    if (eir_Bps == 0)
        return 0;
    uint64_t q = eir_Bps * (uint64_t)ctx->shape_max_delay_ms / 1000ULL;
    if (q < SHAPER_MIN_FLOW_BYTES)
        q = SHAPER_MIN_FLOW_BYTES;
    if (q > SHAPER_MAX_FLOW_BYTES)
        q = SHAPER_MAX_FLOW_BYTES;
    return q;
}

/**
 * Refill tokens based on elapsed TSC since last refill.
 * Uses integer arithmetic to avoid floating point on the data path.
 */
static inline void
token_refill(shaper_flow_t *flow, uint64_t now_tsc)
{
    uint64_t rate = __atomic_load_n(&flow->rate_bytes_per_sec,
                                    __ATOMIC_RELAXED);
    if (rate == 0)
        return;

    uint64_t elapsed = now_tsc - flow->last_refill_tsc;
    uint64_t hz = rte_get_tsc_hz();

    /* tokens_to_add = rate * elapsed / hz
     * Use 64-bit multiply; if elapsed < hz/rate this rounds to 0 which
     * is acceptable (sub-refill granularity, tokens accumulate next time). */
    uint64_t add = rate * (elapsed / hz)
                 + (rate * (elapsed % hz)) / hz;

    if (add == 0)
        return;

    flow->tokens += add;
    if (flow->tokens > flow->max_tokens)
        flow->tokens = flow->max_tokens;
    flow->last_refill_tsc = now_tsc;
}

/**
 * Try to consume pkt_len bytes of tokens.
 * Returns true if pkt is conforming (tokens consumed), false if not.
 */
static inline bool
token_consume(shaper_flow_t *flow, uint32_t pkt_len)
{
    if (flow->tokens >= pkt_len) {
        flow->tokens -= pkt_len;
        return true;
    }
    return false;
}

/**
 * Look up an ACTIVE flow slot from hw_rule_id via rte_hash.
 * Returns NULL if the key is absent or the slot is not ACTIVE (CLOSING /
 * INACTIVE are not admittable — this is what stops new packets from entering
 * a queue the lcore is tearing down, even while the key still resolves).
 */
static inline shaper_flow_t *
lookup_flow(shaper_ctx_t *ctx, uint32_t hw_rule_id)
{
    int idx = rte_hash_lookup(ctx->rule_id_map, &hw_rule_id);
    if (idx < 0)
        return NULL;
    shaper_flow_t *flow = &ctx->flows[idx];
    if (__atomic_load_n(&flow->state, __ATOMIC_ACQUIRE) != SHAPER_FLOW_ACTIVE)
        return NULL;
    return flow;
}

/** Slot index of a flow pointer within the ctx->flows array. */
static inline uint32_t
flow_slot_idx(const shaper_ctx_t *ctx, const shaper_flow_t *flow)
{
    return (uint32_t)(flow - ctx->flows);
}

/**
 * Push a slot index onto ready_ring exactly once (CAS 0->1 on in_ready).
 * ready_ring is sized >= max_flows and dedup'd here, so enqueue cannot fail
 * in normal operation; if it ever does we clear in_ready and log rather than
 * silently stranding a backlogged/closing flow.
 */
static inline void
mark_ready(shaper_ctx_t *ctx, uint32_t idx, shaper_flow_t *flow)
{
    if (__atomic_exchange_n(&flow->in_ready, 1, __ATOMIC_ACQ_REL) != 0)
        return;  /* already queued */
    if (rte_ring_enqueue(ctx->ready_ring,
                         (void *)(uintptr_t)idx) != 0) {
        __atomic_store_n(&flow->in_ready, 0, __ATOMIC_RELEASE);
        DOCA_LOG_ERR("shaper ready_ring full — idx=%u not scheduled", idx);
    }
}

/** Account a successful queue enqueue across per-flow + global byte totals. */
static inline void
shape_account_enqueued(shaper_ctx_t *ctx, shaper_flow_t *flow, uint32_t pkt_len)
{
    uint64_t q = __atomic_add_fetch(&flow->queued_bytes, pkt_len,
                                    __ATOMIC_RELAXED);
    __atomic_add_fetch(&ctx->shape_global_bytes, pkt_len, __ATOMIC_RELAXED);
    if (q > flow->max_queued_bytes_seen)
        flow->max_queued_bytes_seen = q;
}

/** Subtract bytes that left the queue/held state from both totals. */
static inline void
shape_account_dequeued(shaper_ctx_t *ctx, shaper_flow_t *flow, uint64_t bytes)
{
    if (bytes == 0)
        return;
    __atomic_sub_fetch(&flow->queued_bytes, bytes, __ATOMIC_RELAXED);
    __atomic_sub_fetch(&ctx->shape_global_bytes, bytes, __ATOMIC_RELAXED);
}

/**
 * Admission test for one queue enqueue.  Returns true to admit.  Bumps the
 * matching queue_drop_* counter and returns false on rejection.  EIR == 0
 * (q_max_bytes == 0) rejects every YELLOW packet.
 */
static inline bool
shape_admit(shaper_ctx_t *ctx, shaper_flow_t *flow, uint32_t pkt_len)
{
    uint64_t cap = __atomic_load_n(&flow->q_max_bytes, __ATOMIC_RELAXED);
    if (cap == 0) {                       /* EIR == 0 */
        flow->queue_drop_flow++;
        return false;
    }
    uint64_t q = __atomic_load_n(&flow->queued_bytes, __ATOMIC_RELAXED);
    if (q + pkt_len > cap) {
        flow->queue_drop_flow++;
        return false;
    }
    if (__atomic_load_n(&ctx->shape_global_bytes, __ATOMIC_RELAXED) + pkt_len
            > ctx->m_shape_bytes) {
        flow->queue_drop_global++;
        return false;
    }
    return true;
}

/**
 * Software-finalise one packet for Tx: UL -> GTP-U decap, DL -> GTP-U+PSC
 * encap (per-rule encap params).  On failure the mbuf is freed and the
 * matching counter is bumped; returns 0 on success (mbuf ready for Tx),
 * -1 on failure.  Direction is taken from the registered flow.
 */
static inline int
shape_finalize(shaper_ctx_t *ctx, shaper_flow_t *flow, struct rte_mbuf *m)
{
    const dpu_port_cfg_t *port_cfg = &ctx->pipeline->port_cfg;

    if (flow->direction == HW_DIR_UPLINK) {
        if (dpu_gtp_decap_ul(m, port_cfg) != 0) {
            flow->mal_pkt++;
            rte_pktmbuf_free(m);
            return -1;
        }
    } else {
        uint32_t ohc_ipv4 = 0, ohc_teid = 0;
        uint8_t  encap_qfi = 0;
        if (!dpu_pipeline_get_dl_encap_params(ctx->pipeline, flow->hw_rule_id,
                                              &ohc_ipv4, &ohc_teid,
                                              &encap_qfi)) {
            flow->no_encap++;
            rte_pktmbuf_free(m);
            return -1;
        }
        if (dpu_gtp_encap_dl(m, port_cfg, ohc_ipv4, ohc_teid, encap_qfi) != 0) {
            flow->mal_pkt++;
            rte_pktmbuf_free(m);
            return -1;
        }
    }
    return 0;
}

/**
 * Tx a finalised burst and attribute passed / tx_dropped per-flow only after
 * rte_eth_tx_burst returns the actual number accepted (so passed never
 * over-counts under Tx backpressure).
 */
static inline void
shape_tx_attrib(uint16_t tx_port_id, uint16_t tx_queue_id,
                struct rte_mbuf **bufs, shaper_flow_t **flows, uint16_t n)
{
    if (n == 0)
        return;
    uint16_t sent = rte_eth_tx_burst(tx_port_id, tx_queue_id, bufs, n);
    for (uint16_t k = 0; k < sent; k++)
        flows[k]->passed++;
    for (uint16_t k = sent; k < n; k++) {
        flows[k]->tx_dropped++;
        rte_pktmbuf_free(bufs[k]);
    }
}

/**
 * Free a flow's entire backlog (held_pkt + ring) and subtract the bytes from
 * both totals.  Used by the FAR-BUFF / EIR->0 flush and by CLOSING cleanup.
 * Guards a NULL ring (legacy disabled mode never allocates one).
 */
static uint32_t
shape_flush_backlog(shaper_ctx_t *ctx, shaper_flow_t *flow)
{
    uint64_t bytes = 0;
    uint32_t cnt = 0;

    if (flow->held_pkt) {
        bytes += flow->held_pkt_len;
        rte_pktmbuf_free(flow->held_pkt);
        flow->held_pkt = NULL;
        flow->held_pkt_len = 0;
        cnt++;
    }
    if (flow->queue) {
        struct rte_mbuf *m;
        while (rte_ring_sc_dequeue(flow->queue, (void **)&m) == 0) {
            bytes += rte_pktmbuf_pkt_len(m);
            rte_pktmbuf_free(m);
            cnt++;
        }
    }
    if (bytes)
        shape_account_dequeued(ctx, flow, bytes);
    flow->flushed += cnt;
    return cnt;
}

/**
 * CLOSING cleanup on the shaper lcore: free the backlog, then mark INACTIVE.
 *
 * The slot AND its hash key are kept (NOT rte_hash_del_key'd here) — mirroring
 * the dpu_buffer slot-lifecycle invariant.  A future register of the same
 * hw_rule_id lands on the same slot (add_key returns the existing binding) and
 * reuses it in place once state is INACTIVE.  Deleting the key on this lcore
 * would race rte_hash_add_key on the Comch thread (every del-vs-reuse ordering
 * has a window where a freshly reactivated slot loses its key, or a clean slot
 * is refused).  Cost: the table fills after max_hw_rules distinct GBR flows —
 * the same bounded behaviour the buffer module documents and accepts.
 */
static void
shape_cleanup_closing(shaper_ctx_t *ctx, shaper_flow_t *flow)
{
    uint32_t freed = shape_flush_backlog(ctx, flow);
    uint32_t id = flow->hw_rule_id;

    __atomic_store_n(&flow->state, SHAPER_FLOW_INACTIVE, __ATOMIC_RELEASE);

    if (freed)
        DOCA_LOG_DBG("shaper close: hw_rule_id=%u freed %u backlog pkt(s)",
                     id, freed);
}

/* ── Public API ─────────────────────────────────────────────────────── */

int
shaper_init(shaper_ctx_t *ctx,
            uint16_t n3_port_id,
            uint16_t n3_rx_queue_base,
            uint16_t n3_nr_rx_queues,
            uint16_t n6_port_id,
            uint16_t n6_rx_queue_base,
            uint16_t n6_nr_rx_queues,
            uint16_t ul_tx_port_id,
            uint16_t ul_tx_queue_id,
            uint16_t dl_tx_port_id,
            uint16_t dl_tx_queue_id,
            dpu_pipeline_ctx_t *pipeline,
            uint32_t max_flows,
            uint64_t m_shape_bytes,
            uint32_t shape_max_delay_ms)
{
    memset(ctx, 0, sizeof(*ctx));

    ctx->max_flows          = max_flows;
    ctx->n3_port_id         = n3_port_id;
    ctx->n3_rx_queue_base   = n3_rx_queue_base;
    ctx->n3_nr_rx_queues    = n3_nr_rx_queues;
    ctx->n6_port_id         = n6_port_id;
    ctx->n6_rx_queue_base   = n6_rx_queue_base;
    ctx->n6_nr_rx_queues    = n6_nr_rx_queues;
    ctx->ul_tx_port_id      = ul_tx_port_id;
    ctx->ul_tx_queue_id     = ul_tx_queue_id;
    ctx->dl_tx_port_id      = dl_tx_port_id;
    ctx->dl_tx_queue_id     = dl_tx_queue_id;
    ctx->pipeline           = pipeline;
    ctx->m_shape_bytes      = m_shape_bytes;
    ctx->shape_max_delay_ms = shape_max_delay_ms ? shape_max_delay_ms : 50;
    ctx->shape_global_bytes = 0;
    ctx->running            = true;   /* set before lcore launch so shaper_stop() is never a no-op */

    ctx->flows = calloc(max_flows, sizeof(shaper_flow_t));
    if (!ctx->flows) {
        DOCA_LOG_ERR("Failed to allocate %u shaper flow slots", max_flows);
        return -1;
    }

    /* Create rte_hash for hw_rule_id → slot index mapping */
    struct rte_hash_parameters hash_params = {
        .name       = "shaper_rule_map",
        .entries    = max_flows,
        .key_len    = sizeof(uint32_t),
        .hash_func  = rte_jhash,
        .socket_id  = (int)rte_socket_id(),
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY,
    };
    ctx->rule_id_map = rte_hash_create(&hash_params);
    if (!ctx->rule_id_map) {
        DOCA_LOG_ERR("Failed to create shaper rte_hash (entries=%u)",
                     max_flows);
        free(ctx->flows);
        ctx->flows = NULL;
        return -1;
    }

    /* Ready ring of backlogged/closing slot indexes.  Sized >= max_flows
     * (usable = size-1) so the in_ready-deduped enqueue can never fail.
     * Single consumer (shaper lcore); multiple producers (Comch + lcore). */
    uint32_t ring_sz = rte_align32pow2(max_flows + 1);
    ctx->ready_ring = rte_ring_create("shaper_ready", ring_sz,
                                      (int)rte_socket_id(), RING_F_SC_DEQ);
    if (!ctx->ready_ring) {
        DOCA_LOG_ERR("Failed to create shaper ready_ring (size=%u)", ring_sz);
        rte_hash_free(ctx->rule_id_map);
        ctx->rule_id_map = NULL;
        free(ctx->flows);
        ctx->flows = NULL;
        return -1;
    }

    DOCA_LOG_INFO("Shaper init: UL Rx N3 port=%u q=[%u..%u] → SW-decap → "
                  "Tx port=%u q=%u | DL Rx N6 port=%u q=[%u..%u] → "
                  "SW-encap → Tx port=%u q=%u | max_flows=%u | "
                  "buffering=%s m_shape_bytes=%lu shape_max_delay_ms=%u",
                  n3_port_id, n3_rx_queue_base,
                  n3_rx_queue_base + n3_nr_rx_queues - 1,
                  ul_tx_port_id, ul_tx_queue_id,
                  n6_port_id, n6_rx_queue_base,
                  n6_rx_queue_base + n6_nr_rx_queues - 1,
                  dl_tx_port_id, dl_tx_queue_id,
                  max_flows,
                  m_shape_bytes ? "ON" : "OFF (legacy policer)",
                  (unsigned long)m_shape_bytes, ctx->shape_max_delay_ms);
    return 0;
}

int
shaper_register_flow(shaper_ctx_t *ctx,
                     uint32_t hw_rule_id,
                     uint8_t direction,
                     uint64_t gbr_kbps,
                     uint64_t mbr_kbps)
{
    if (!ctx->rule_id_map)
        return -1;

    /* EIR = MBR − GBR.  If MBR <= GBR, shaping rate is 0 (drop all YELLOW) */
    uint64_t eir_kbps = (mbr_kbps > gbr_kbps) ? (mbr_kbps - gbr_kbps) : 0;
    uint64_t eir_Bps  = kbps_to_bytes_per_sec(eir_kbps);

    /* Add to hash — rte_hash_add_key returns the slot index */
    int idx = rte_hash_add_key(ctx->rule_id_map, &hw_rule_id);
    if (idx < 0) {
        DOCA_LOG_ERR("shaper register: hash add failed hw_rule_id=%u "
                     "(rc=%d, table full?)", hw_rule_id, idx);
        return -1;
    }

    shaper_flow_t *flow = &ctx->flows[idx];

    /* add_key may return an EXISTING binding (same hw_rule_id) whose slot is
     * still owned by the shaper lcore (CLOSING cleanup pending) or already
     * ACTIVE.  Resetting/freeing it here would race the lcore's mbuf frees and
     * leak shape_global_bytes (the reuse path below assumes cleanup already
     * reconciled the bytes — only true for an INACTIVE slot).  Refuse; the
     * caller downgrades to policed, and once the lcore finishes cleanup
     * (state → INACTIVE) a later register reuses the slot cleanly.
     * A brand-new slot is calloc'd INACTIVE, so this never blocks first use. */
    uint32_t st = __atomic_load_n(&flow->state, __ATOMIC_ACQUIRE);
    if (st != SHAPER_FLOW_INACTIVE) {
        DOCA_LOG_WARN("shaper register: hw_rule_id=%u slot=%d busy "
                      "(state=%u) — refusing reuse until cleaned",
                      hw_rule_id, idx, st);
        return -1;
    }

    /* Per-slot ring (named by slot index, persistent for reuse).  Created
     * lazily on first use of the slot, and only when buffering is enabled. */
    if (ctx->m_shape_bytes != 0 && !flow->queue) {
        char name[32];
        snprintf(name, sizeof(name), "shp_slot_%d", idx);
        flow->queue = rte_ring_create(name, SHAPER_RING_DEPTH,
                                      (int)rte_socket_id(),
                                      RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (!flow->queue) {
            DOCA_LOG_ERR("shaper register: rte_ring_create failed slot=%d "
                         "hw_rule_id=%u", idx, hw_rule_id);
            rte_hash_del_key(ctx->rule_id_map, &hw_rule_id);
            return -1;
        }
    } else if (flow->queue) {
        /* Reuse: free any residual mbufs from a prior life of this slot.
         * Global bytes were already reconciled at CLOSING cleanup, so do
         * NOT touch shape_global_bytes here — just reset the local ring. */
        struct rte_mbuf *m;
        while (rte_ring_sc_dequeue(flow->queue, (void **)&m) == 0)
            rte_pktmbuf_free(m);
    }
    if (flow->held_pkt) {
        rte_pktmbuf_free(flow->held_pkt);
        flow->held_pkt = NULL;
    }

    flow->hw_rule_id   = hw_rule_id;
    flow->direction    = direction;
    __atomic_store_n(&flow->rate_bytes_per_sec, eir_Bps, __ATOMIC_RELAXED);
    flow->tokens       = SHAPER_BURST_BYTES;
    flow->max_tokens   = SHAPER_BURST_BYTES;
    flow->last_refill_tsc = rte_rdtsc();
    flow->held_pkt_len = 0;
    __atomic_store_n(&flow->q_max_bytes, compute_q_max_bytes(ctx, eir_Bps),
                     __ATOMIC_RELAXED);
    __atomic_store_n(&flow->queued_bytes, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&flow->in_ready, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&flow->flush_pending, 0, __ATOMIC_RELAXED);

    flow->passed = flow->dropped = flow->mal_pkt = 0;
    flow->no_encap = flow->tx_dropped = 0;
    flow->queued_pkts = flow->queue_drop_flow = flow->queue_drop_global = 0;
    flow->queue_drop_ring = flow->flushed = flow->max_queued_bytes_seen = 0;

    /* Release fence: all fields above are visible to the shaper lcore
     * before it observes state==ACTIVE via ACQUIRE load in lookup_flow. */
    __atomic_store_n(&flow->state, SHAPER_FLOW_ACTIVE, __ATOMIC_RELEASE);

    DOCA_LOG_INFO("shaper register: hw_rule_id=%u dir=%s "
                  "gbr=%lu mbr=%lu eir=%lu kbps q_max=%lu B slot=%d",
                  hw_rule_id,
                  (direction == HW_DIR_UPLINK) ? "UL" : "DL",
                  (unsigned long)gbr_kbps, (unsigned long)mbr_kbps,
                  (unsigned long)eir_kbps,
                  (unsigned long)compute_q_max_bytes(ctx, eir_Bps), idx);
    return 0;
}

void
shaper_unregister_flow(shaper_ctx_t *ctx, uint32_t hw_rule_id)
{
    if (!ctx->rule_id_map)
        return;

    int idx = rte_hash_lookup(ctx->rule_id_map, &hw_rule_id);
    if (idx < 0)
        return;

    shaper_flow_t *flow = &ctx->flows[idx];

    /* Transition ACTIVE → CLOSING atomically.  Idempotent: a duplicate
     * unregister on an already-CLOSING or already-cleaned (INACTIVE) slot is
     * a no-op.  Without this, with persistent keys a redundant unregister
     * would re-mark a clean slot CLOSING — a false busy window that makes a
     * racing 0→gbr re-register get refused and downgraded unnecessarily.
     * On success the Rx path stops admitting immediately (lookup_flow admits
     * only ACTIVE); the shaper lcore then frees the backlog and returns the
     * slot to INACTIVE (the Comch thread must NOT free queued mbufs itself). */
    uint32_t expected = SHAPER_FLOW_ACTIVE;
    if (!__atomic_compare_exchange_n(&flow->state, &expected,
                                     SHAPER_FLOW_CLOSING, false,
                                     __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return;   /* not ACTIVE — already closing/closed */

    DOCA_LOG_INFO("shaper unregister: hw_rule_id=%u "
                  "passed=%lu dropped=%lu mal_pkt=%lu no_encap=%lu "
                  "tx_dropped=%lu queued_pkts=%lu flushed=%lu "
                  "drop(flow=%lu global=%lu ring=%lu)",
                  hw_rule_id,
                  (unsigned long)flow->passed,
                  (unsigned long)flow->dropped,
                  (unsigned long)flow->mal_pkt,
                  (unsigned long)flow->no_encap,
                  (unsigned long)flow->tx_dropped,
                  (unsigned long)flow->queued_pkts,
                  (unsigned long)flow->flushed,
                  (unsigned long)flow->queue_drop_flow,
                  (unsigned long)flow->queue_drop_global,
                  (unsigned long)flow->queue_drop_ring);

    mark_ready(ctx, (uint32_t)idx, flow);
}

int
shaper_update_rate(shaper_ctx_t *ctx,
                   uint32_t hw_rule_id,
                   uint64_t gbr_kbps,
                   uint64_t mbr_kbps)
{
    shaper_flow_t *flow = lookup_flow(ctx, hw_rule_id);
    if (!flow) {
        DOCA_LOG_WARN("shaper update_rate: hw_rule_id=%u not found",
                      hw_rule_id);
        return -1;
    }

    uint64_t eir_kbps = (mbr_kbps > gbr_kbps) ? (mbr_kbps - gbr_kbps) : 0;
    uint64_t eir_Bps  = kbps_to_bytes_per_sec(eir_kbps);
    __atomic_store_n(&flow->rate_bytes_per_sec, eir_Bps, __ATOMIC_RELAXED);
    __atomic_store_n(&flow->q_max_bytes, compute_q_max_bytes(ctx, eir_Bps),
                     __ATOMIC_RELAXED);

    /* Don't reset tokens — let the bucket drain/fill naturally.
     * If EIR dropped to 0 the bucket will never refill, so any existing
     * backlog would pin M_shape forever — nudge the lcore to visit and
     * flush it (the drain pass flushes on rate==0). */
    if (eir_Bps == 0)
        mark_ready(ctx, flow_slot_idx(ctx, flow), flow);

    DOCA_LOG_INFO("shaper update_rate: hw_rule_id=%u "
                  "gbr=%lu mbr=%lu eir=%lu kbps q_max=%lu B",
                  hw_rule_id,
                  (unsigned long)gbr_kbps, (unsigned long)mbr_kbps,
                  (unsigned long)eir_kbps,
                  (unsigned long)compute_q_max_bytes(ctx, eir_Bps));
    return 0;
}

void
shaper_request_flush(shaper_ctx_t *ctx, uint32_t hw_rule_id)
{
    shaper_flow_t *flow = lookup_flow(ctx, hw_rule_id);
    if (!flow)
        return;   /* not registered / not GBR — no-op */

    __atomic_store_n(&flow->flush_pending, 1, __ATOMIC_RELEASE);
    mark_ready(ctx, flow_slot_idx(ctx, flow), flow);

    DOCA_LOG_DBG("shaper request_flush: hw_rule_id=%u (FAR BUFF override)",
                 hw_rule_id);
}

/**
 * Poll shaper Rx queues on one port, apply per-flow token-bucket shaping,
 * and either finalise+Tx immediately (fast path) or admit into the per-flow
 * queue (buffered mode).  Token consumption is based on the *received* packet
 * length (matches the ingress-side meter accounting and keeps GBR/MBR
 * semantics intact regardless of the codec's length delta).
 *
 * Called twice per shaper_loop iteration: UL (Rx N3 → Tx N6) and DL
 * (Rx N6 → Tx N3).  expected_dir is what flow->direction must match; a
 * mismatch is counted as mal_pkt and dropped (defends against RSS misroute).
 */
static void
shaper_poll_port(shaper_ctx_t *ctx,
                 uint16_t rx_port_id,
                 uint16_t rx_queue_base,
                 uint16_t nr_rx_queues,
                 uint16_t tx_port_id,
                 uint16_t tx_queue_id,
                 uint8_t expected_dir)
{
    struct rte_mbuf *rx_bufs[SHAPER_RX_BURST];
    struct rte_mbuf *tx_bufs[SHAPER_RX_BURST];
    shaper_flow_t   *tx_flow[SHAPER_RX_BURST];
    const bool buffering = (ctx->m_shape_bytes != 0);

    for (uint16_t q = 0; q < nr_rx_queues; q++) {
        uint16_t qid = rx_queue_base + q;
        uint16_t nb_rx = rte_eth_rx_burst(rx_port_id, qid,
                                          rx_bufs, SHAPER_RX_BURST);
        if (nb_rx == 0)
            continue;

        uint64_t now_tsc = rte_rdtsc();
        uint16_t nb_tx = 0;

        for (uint16_t i = 0; i < nb_rx; i++) {
            /* mbuf dynamic metadata is host-order on Rx (DPDK convention).
             * HW action stamps htonl(hw_rule_id); mlx5 PMD applies BE→host
             * conversion on the way to the mbuf, so the value here is the
             * host-order hw_rule_id used as the lookup_flow key. */
            uint32_t rule_id = rte_flow_dynf_metadata_get(rx_bufs[i]);

            shaper_flow_t *flow = lookup_flow(ctx, rule_id);
            if (!flow) {
                rte_pktmbuf_free(rx_bufs[i]);
                continue;
            }

            /* Defensive direction check (RSS should make this impossible). */
            if (flow->direction != expected_dir) {
                flow->mal_pkt++;
                rte_pktmbuf_free(rx_bufs[i]);
                continue;
            }

            token_refill(flow, now_tsc);
            uint32_t pkt_len = rte_pktmbuf_pkt_len(rx_bufs[i]);

            if (!buffering) {
                /* Legacy policer: immediate pass/drop. */
                if (!token_consume(flow, pkt_len)) {
                    flow->dropped++;
                    rte_pktmbuf_free(rx_bufs[i]);
                    continue;
                }
                if (shape_finalize(ctx, flow, rx_bufs[i]) != 0)
                    continue;            /* freed inside */
                tx_bufs[nb_tx] = rx_bufs[i];
                tx_flow[nb_tx] = flow;
                nb_tx++;
                continue;
            }

            /* Buffered mode.  EIR == 0 has no excess entitlement. */
            if (__atomic_load_n(&flow->q_max_bytes, __ATOMIC_RELAXED) == 0) {
                flow->queue_drop_flow++;
                rte_pktmbuf_free(rx_bufs[i]);
                continue;
            }

            bool has_backlog = (flow->held_pkt != NULL) ||
                               (rte_ring_count(flow->queue) > 0);

            if (!has_backlog && token_consume(flow, pkt_len)) {
                /* Fast path: nothing queued and tokens available. */
                if (shape_finalize(ctx, flow, rx_bufs[i]) != 0)
                    continue;            /* freed inside */
                tx_bufs[nb_tx] = rx_bufs[i];
                tx_flow[nb_tx] = flow;
                nb_tx++;
                continue;
            }

            /* Queue path (preserves FIFO: even token-passing packets queue
             * behind existing backlog). */
            if (!shape_admit(ctx, flow, pkt_len)) {
                rte_pktmbuf_free(rx_bufs[i]);   /* counter bumped in admit */
                continue;
            }
            if (rte_ring_sp_enqueue(flow->queue, rx_bufs[i]) != 0) {
                flow->queue_drop_ring++;
                rte_pktmbuf_free(rx_bufs[i]);
                continue;
            }
            shape_account_enqueued(ctx, flow, pkt_len);
            flow->queued_pkts++;
            mark_ready(ctx, flow_slot_idx(ctx, flow), flow);
        }

        shape_tx_attrib(tx_port_id, tx_queue_id, tx_bufs, tx_flow, nb_tx);
    }
}

/**
 * Drain backlogged flows at EIR.  Pops a bounded number of slot indexes from
 * ready_ring; for each: handles CLOSING cleanup and FAR-BUFF/EIR->0 flush,
 * otherwise paces queued packets out at EIR using a per-flow held_pkt to
 * preserve FIFO when tokens are insufficient.  Re-pushes flows that still
 * have backlog.
 */
static void
drain_ready_flows(shaper_ctx_t *ctx)
{
    struct rte_mbuf *tx_bufs[SHAPER_DRAIN_PKTS_PER_FLOW];
    shaper_flow_t   *tx_flow[SHAPER_DRAIN_PKTS_PER_FLOW];

    for (uint32_t n = 0; n < SHAPER_DRAIN_FLOWS_PER_ITER; n++) {
        void *p;
        if (rte_ring_sc_dequeue(ctx->ready_ring, &p) != 0)
            break;
        uint32_t idx = (uint32_t)(uintptr_t)p;
        shaper_flow_t *flow = &ctx->flows[idx];

        /* Clear membership now; if backlog remains we re-mark at the end.
         * A concurrent producer that sets in_ready again will simply push a
         * fresh entry — the state checks below tolerate duplicates. */
        __atomic_store_n(&flow->in_ready, 0, __ATOMIC_RELEASE);

        uint32_t state = __atomic_load_n(&flow->state, __ATOMIC_ACQUIRE);
        if (state == SHAPER_FLOW_CLOSING) {
            shape_cleanup_closing(ctx, flow);
            continue;
        }
        if (state != SHAPER_FLOW_ACTIVE)
            continue;                    /* stale/duplicate entry */

        uint64_t now_tsc = rte_rdtsc();
        uint64_t rate = __atomic_load_n(&flow->rate_bytes_per_sec,
                                        __ATOMIC_RELAXED);

        /* FAR-BUFF override, or EIR dropped to 0: drop the backlog (it would
         * otherwise never drain / would deliver while the FAR says hold). */
        if (__atomic_load_n(&flow->flush_pending, __ATOMIC_ACQUIRE) ||
            rate == 0) {
            shape_flush_backlog(ctx, flow);
            __atomic_store_n(&flow->flush_pending, 0, __ATOMIC_RELEASE);
            continue;                    /* nothing left to re-schedule */
        }

        /* No queue (legacy disabled mode never allocates one) — nothing to
         * pace.  The flush/CLOSING paths above already handled this slot. */
        if (!flow->queue)
            continue;

        token_refill(flow, now_tsc);

        uint16_t nb_tx = 0;
        for (uint32_t k = 0; k < SHAPER_DRAIN_PKTS_PER_FLOW; k++) {
            struct rte_mbuf *m;
            uint32_t mlen;
            if (flow->held_pkt) {
                m = flow->held_pkt;
                mlen = flow->held_pkt_len;
            } else {
                if (rte_ring_sc_dequeue(flow->queue, (void **)&m) != 0)
                    break;               /* ring empty */
                mlen = rte_pktmbuf_pkt_len(m);
                /* Becomes the FIFO head; stays counted in queued_bytes. */
                flow->held_pkt = m;
                flow->held_pkt_len = mlen;
            }

            if (!token_consume(flow, mlen))
                break;                   /* keep held; retry next visit */

            /* Packet leaves the queue/held state now. */
            flow->held_pkt = NULL;
            flow->held_pkt_len = 0;
            shape_account_dequeued(ctx, flow, mlen);

            if (shape_finalize(ctx, flow, m) != 0)
                continue;                /* freed inside, counter bumped */
            tx_bufs[nb_tx] = m;
            tx_flow[nb_tx] = flow;
            nb_tx++;
        }

        if (nb_tx > 0) {
            uint16_t tx_port = (flow->direction == HW_DIR_UPLINK)
                             ? ctx->ul_tx_port_id : ctx->dl_tx_port_id;
            uint16_t tx_q    = (flow->direction == HW_DIR_UPLINK)
                             ? ctx->ul_tx_queue_id : ctx->dl_tx_queue_id;
            shape_tx_attrib(tx_port, tx_q, tx_bufs, tx_flow, nb_tx);
        }

        if (flow->held_pkt != NULL || rte_ring_count(flow->queue) > 0)
            mark_ready(ctx, idx, flow);
    }
}

int
shaper_loop(void *arg)
{
    shaper_ctx_t *ctx = (shaper_ctx_t *)arg;

    DOCA_LOG_INFO("Shaper loop started on lcore %u: "
                  "UL Rx N3 port=%u q=[%u..%u] → Tx port=%u q=%u | "
                  "DL Rx N6 port=%u q=[%u..%u] → Tx port=%u q=%u | "
                  "buffering=%s",
                  rte_lcore_id(),
                  ctx->n3_port_id,
                  ctx->n3_rx_queue_base,
                  ctx->n3_rx_queue_base + ctx->n3_nr_rx_queues - 1,
                  ctx->ul_tx_port_id, ctx->ul_tx_queue_id,
                  ctx->n6_port_id,
                  ctx->n6_rx_queue_base,
                  ctx->n6_rx_queue_base + ctx->n6_nr_rx_queues - 1,
                  ctx->dl_tx_port_id, ctx->dl_tx_queue_id,
                  ctx->m_shape_bytes ? "ON" : "OFF");

    while (ctx->running) {
        /* Drain backlogged flows (and service CLOSING/flush) even when no
         * new packets arrive. */
        drain_ready_flows(ctx);

        /* UL YELLOW: Rx on N3, SW-decap, Tx on N6. */
        shaper_poll_port(ctx,
                         ctx->n3_port_id, ctx->n3_rx_queue_base,
                         ctx->n3_nr_rx_queues,
                         ctx->ul_tx_port_id, ctx->ul_tx_queue_id,
                         HW_DIR_UPLINK);
        /* DL YELLOW: Rx on N6, SW-encap, Tx on N3. */
        shaper_poll_port(ctx,
                         ctx->n6_port_id, ctx->n6_rx_queue_base,
                         ctx->n6_nr_rx_queues,
                         ctx->dl_tx_port_id, ctx->dl_tx_queue_id,
                         HW_DIR_DOWNLINK);
    }

    DOCA_LOG_INFO("Shaper loop exiting on lcore %u", rte_lcore_id());
    return 0;
}

void
shaper_stop(shaper_ctx_t *ctx)
{
    ctx->running = false;
}

void
shaper_destroy(shaper_ctx_t *ctx)
{
    /* Final per-flow stats — share format with the SIGUSR1 dispatcher
     * so shutdown logs and live dumps don't drift. */
    shaper_dump_stats(ctx);

    if (ctx->flows) {
        /* Free per-slot rings and any residual packets. */
        for (uint32_t i = 0; i < ctx->max_flows; i++) {
            shaper_flow_t *fl = &ctx->flows[i];
            if (fl->held_pkt) {
                rte_pktmbuf_free(fl->held_pkt);
                fl->held_pkt = NULL;
            }
            if (fl->queue) {
                struct rte_mbuf *m;
                while (rte_ring_sc_dequeue(fl->queue, (void **)&m) == 0)
                    rte_pktmbuf_free(m);
                rte_ring_free(fl->queue);
                fl->queue = NULL;
            }
        }
        free(ctx->flows);
        ctx->flows = NULL;
    }

    if (ctx->ready_ring) {
        rte_ring_free(ctx->ready_ring);
        ctx->ready_ring = NULL;
    }

    if (ctx->rule_id_map) {
        rte_hash_free(ctx->rule_id_map);
        ctx->rule_id_map = NULL;
    }

    DOCA_LOG_INFO("Shaper destroyed");
}

void
shaper_dump_stats(const shaper_ctx_t *ctx)
{
    if (!ctx || !ctx->flows)
        return;

    DOCA_LOG_INFO("Shaper stats (global): max_flows=%u buffering=%s "
                  "shape_global_bytes=%lu / m_shape_bytes=%lu "
                  "shape_max_delay_ms=%u | "
                  "UL Rx port=%u q=[%u..%u] → Tx port=%u q=%u | "
                  "DL Rx port=%u q=[%u..%u] → Tx port=%u q=%u",
                  ctx->max_flows,
                  ctx->m_shape_bytes ? "ON" : "OFF",
                  (unsigned long)__atomic_load_n(&ctx->shape_global_bytes,
                                                 __ATOMIC_RELAXED),
                  (unsigned long)ctx->m_shape_bytes,
                  ctx->shape_max_delay_ms,
                  ctx->n3_port_id,
                  ctx->n3_rx_queue_base,
                  ctx->n3_rx_queue_base + ctx->n3_nr_rx_queues - 1,
                  ctx->ul_tx_port_id, ctx->ul_tx_queue_id,
                  ctx->n6_port_id,
                  ctx->n6_rx_queue_base,
                  ctx->n6_rx_queue_base + ctx->n6_nr_rx_queues - 1,
                  ctx->dl_tx_port_id, ctx->dl_tx_queue_id);

    uint32_t nr_active = 0;
    uint64_t tot_passed = 0, tot_dropped = 0, tot_mal = 0;
    uint64_t tot_no_encap = 0, tot_tx_dropped = 0;
    uint64_t tot_qpkts = 0, tot_qd_flow = 0, tot_qd_global = 0;
    uint64_t tot_qd_ring = 0, tot_flushed = 0;

    const uint64_t hz = rte_get_tsc_hz();
    const uint64_t now_tsc = rte_rdtsc();

    for (uint32_t i = 0; i < ctx->max_flows; i++) {
        const shaper_flow_t *fl = &ctx->flows[i];
        if (__atomic_load_n(&fl->state, __ATOMIC_ACQUIRE) != SHAPER_FLOW_ACTIVE)
            continue;
        nr_active++;

        uint64_t rate_bps = __atomic_load_n(&fl->rate_bytes_per_sec,
                                            __ATOMIC_RELAXED);
        uint64_t rate_kbps = (rate_bps * 8) / 1000;

        uint64_t age_tsc = now_tsc - fl->last_refill_tsc;
        uint64_t age_us = (hz > 0) ? (age_tsc * 1000000ULL / hz) : 0;

        uint64_t qb = __atomic_load_n(&fl->queued_bytes, __ATOMIC_RELAXED);

        DOCA_LOG_INFO("  flow hw_rule_id=%u dir=%s rate=%lu kbps "
                      "tokens=%lu/%lu refill_age_us=%lu | "
                      "passed=%lu dropped=%lu mal_pkt=%lu no_encap=%lu "
                      "tx_dropped=%lu",
                      fl->hw_rule_id,
                      fl->direction == HW_DIR_UPLINK ? "UL" : "DL",
                      (unsigned long)rate_kbps,
                      (unsigned long)fl->tokens,
                      (unsigned long)fl->max_tokens,
                      (unsigned long)age_us,
                      (unsigned long)fl->passed,
                      (unsigned long)fl->dropped,
                      (unsigned long)fl->mal_pkt,
                      (unsigned long)fl->no_encap,
                      (unsigned long)fl->tx_dropped);
        DOCA_LOG_INFO("       queue: queued_bytes=%lu/%lu max_seen=%lu "
                      "queued_pkts=%lu flushed=%lu "
                      "drop(flow=%lu global=%lu ring=%lu)",
                      (unsigned long)qb,
                      (unsigned long)__atomic_load_n(&fl->q_max_bytes,
                                                     __ATOMIC_RELAXED),
                      (unsigned long)fl->max_queued_bytes_seen,
                      (unsigned long)fl->queued_pkts,
                      (unsigned long)fl->flushed,
                      (unsigned long)fl->queue_drop_flow,
                      (unsigned long)fl->queue_drop_global,
                      (unsigned long)fl->queue_drop_ring);

        tot_passed     += fl->passed;
        tot_dropped    += fl->dropped;
        tot_mal        += fl->mal_pkt;
        tot_no_encap   += fl->no_encap;
        tot_tx_dropped += fl->tx_dropped;
        tot_qpkts      += fl->queued_pkts;
        tot_qd_flow    += fl->queue_drop_flow;
        tot_qd_global  += fl->queue_drop_global;
        tot_qd_ring    += fl->queue_drop_ring;
        tot_flushed    += fl->flushed;
    }

    DOCA_LOG_INFO("Shaper stats (totals): active_flows=%u "
                  "passed=%lu dropped=%lu mal_pkt=%lu no_encap=%lu "
                  "tx_dropped=%lu | queued_pkts=%lu flushed=%lu "
                  "drop(flow=%lu global=%lu ring=%lu)",
                  nr_active,
                  (unsigned long)tot_passed,
                  (unsigned long)tot_dropped,
                  (unsigned long)tot_mal,
                  (unsigned long)tot_no_encap,
                  (unsigned long)tot_tx_dropped,
                  (unsigned long)tot_qpkts,
                  (unsigned long)tot_flushed,
                  (unsigned long)tot_qd_flow,
                  (unsigned long)tot_qd_global,
                  (unsigned long)tot_qd_ring);
}
