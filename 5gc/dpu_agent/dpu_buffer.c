/*
 * dpu_buffer.c — DPU ARM-side per-flow packet buffering (rte_ring based)
 *
 * Rx side: polls N6 RSS queues fed by TO_DPU_ARM_DL.  DL packets that
 * matched a BUFFER-mode rule are enqueued into per-flow rte_rings.
 *
 * Drain side: software-encaps each buffered DL packet into a wire-form
 * GTP-U + PSC frame (using the per-rule encap params cached in the
 * pipeline rule record) and Tx's it on N3.  In VNF mode, software-Tx'd
 * packets traverse the EGRESS pipeline of the Tx port — on N3 that
 * hits DL_ENCAP (egress_root); the SW-encapped frame's pkt_meta is 0,
 * so it fwd_misses to N3_EGRESS_PASSTHROUGH and exits the wire as-is.
 *
 * Uses DPDK rte_ring in SPSC (single-producer, single-consumer) mode
 * for lockless thread safety between the Rx lcore (enqueue) and the
 * Comch callback thread (drain/unregister).
 *
 * Rings are created on first register_flow and persist until
 * dpu_buffer_destroy() (shutdown).  Close paths only flush and mark the
 * slot CLOSED — they never free the ring or drop the hash binding
 * (avoids a free-while-enqueue race with the Rx lcore and keeps the
 * "buf_<id>" ring name reusable).  The slot+ring are reused when the
 * same hw_rule_id re-enters BUFF (CLOSED branch in register_flow).
 *
 * State machine:
 *   FORW path: ACTIVE → DRAINING → CLOSED
 *     Rx lcore owns drain + pass-through in DRAINING state (Option A).
 *     Main thread waits for drain_done before switching HW.
 *   DROP/DELETE path: ACTIVE → CLOSING → CLOSED (Rx-owned discard close)
 *     HW source cut first; begin_close sets the discard flag and returns;
 *     the Rx lcore frees the backlog and closes at end-of-poll.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_mbuf.h>
#include <rte_ring.h>

#include <doca_log.h>

#include "dpu_buffer.h"
#include "dpu_gtp_codec.h"
#include "hw_offload_msg.h"

DOCA_LOG_REGISTER(DPU_BUFFER);

/* ── Internal helpers ───────────────────────────────────────────────── */

/**
 * Find a flow by hw_rule_id.  Returns any non-INACTIVE flow (ACTIVE,
 * DRAINING, CLOSING, or CLOSED) so that state-transition APIs can
 * locate them regardless of current lifecycle stage.
 */
static dpu_buffer_flow_t *
find_flow(dpu_buffer_ctx_t *ctx, uint32_t hw_rule_id)
{
    int idx = rte_hash_lookup(ctx->flow_id_map, &hw_rule_id);
    if (idx < 0)
        return NULL;
    dpu_buffer_flow_t *f = &ctx->flows[idx];
    uint32_t st = __atomic_load_n(&f->state, __ATOMIC_ACQUIRE);
    if (st == DPU_BUF_INACTIVE)
        return NULL;
    return f;
}

/**
 * Allocate a free flow slot via rte_hash.
 */
static dpu_buffer_flow_t *
alloc_flow(dpu_buffer_ctx_t *ctx, uint32_t hw_rule_id)
{
    int idx = rte_hash_add_key(ctx->flow_id_map, &hw_rule_id);
    if (idx < 0)
        return NULL;
    return &ctx->flows[idx];
}

/* ── BDP byte-budget accounting helpers ─────────────────────────────── */

/** Sum payload bytes across a burst.  Call BEFORE freeing/reinjecting. */
static inline uint64_t
sum_pkt_len(struct rte_mbuf **bufs, uint16_t n)
{
    uint64_t s = 0;
    for (uint16_t i = 0; i < n; i++)
        s += rte_pktmbuf_pkt_len(bufs[i]);
    return s;
}

/** Subtract drained/freed bytes from the per-flow and global byte totals. */
static inline void
buf_account_dequeued(dpu_buffer_ctx_t *ctx, dpu_buffer_flow_t *flow, uint64_t bytes)
{
    if (bytes == 0)
        return;
    __atomic_fetch_sub(&flow->queued_bytes, bytes, __ATOMIC_RELAXED);
    __atomic_fetch_sub(&ctx->global_bytes,  bytes, __ATOMIC_RELAXED);
}

/**
 * Admission test for one enqueue.  Returns true to admit.  On a per-flow
 * byte-grant or global-budget rejection, charges byte_dropped (the
 * offered-load signal) and returns false.  When the allocator is OFF
 * (m_op_bytes == UINT64_MAX) the per-flow check is inert (A_i_bytes is
 * UINT64_MAX) and the global check falls back to the legacy packet-count
 * cap with the byte path left silent — byte-for-byte legacy admission.
 */
static inline bool
buf_admit(dpu_buffer_ctx_t *ctx, dpu_buffer_flow_t *flow, uint32_t pkt_len)
{
    if (flow->A_i_bytes != UINT64_MAX) {
        uint64_t q = __atomic_load_n(&flow->queued_bytes, __ATOMIC_RELAXED);
        /* One-packet admission floor: an EMPTY flow always takes its first
         * packet (still bounded by the global M_op check below).  Without
         * this, a flow whose grant decayed to ~0 while idle in BUFF would
         * black-hole the first DL packet that arrives after idle — exactly
         * the packet that must be buffered for a paging UE.  The flow's
         * max-min grant claim still decays to 0 while idle (so it doesn't
         * over-reserve the budget); the floor only governs admission, not
         * the grant. */
        if (q > 0 && q + pkt_len > flow->A_i_bytes) {
            flow->byte_dropped += pkt_len;
            return false;
        }
    }
    if (ctx->m_op_bytes != UINT64_MAX) {
        if (__atomic_load_n(&ctx->global_bytes, __ATOMIC_RELAXED) + pkt_len
                > ctx->m_op_bytes) {
            flow->byte_dropped += pkt_len;
            return false;
        }
    } else {
        /* Legacy global cap (packet count); byte path silent. */
        if (__atomic_load_n(&ctx->global_count, __ATOMIC_RELAXED)
                >= DPU_BUFFER_GLOBAL_CAP)
            return false;
    }
    return true;
}

/** Account a successful enqueue across byte + packet totals. */
static inline void
buf_account_enqueued(dpu_buffer_ctx_t *ctx, dpu_buffer_flow_t *flow, uint32_t pkt_len)
{
    __atomic_fetch_add(&flow->queued_bytes, pkt_len, __ATOMIC_RELAXED);
    __atomic_fetch_add(&ctx->global_bytes,  pkt_len, __ATOMIC_RELAXED);
    flow->enq_bytes += pkt_len;
    __atomic_fetch_add(&ctx->global_count, 1, __ATOMIC_RELAXED);
}

/** Stamp discard-teardown evidence for a freed late arrival: pushes the
 *  observed-idle close fence forward (same evidence fields the retire
 *  fence reads, so one fence formula serves both close families). */
static inline void
stamp_discard_arrival(dpu_buffer_flow_t *flow, uint64_t epoch_now)
{
    uint64_t now = rte_get_tsc_cycles();
    __atomic_store_n(&flow->last_old_path_rx_tsc,   now,       __ATOMIC_RELAXED);
    __atomic_store_n(&flow->last_old_path_done_tsc, now,       __ATOMIC_RELAXED);
    __atomic_store_n(&flow->last_old_path_rx_epoch, epoch_now, __ATOMIC_RELAXED);
}

/** Flush all remaining packets from a flow's ring. */
static uint32_t
ring_flush(dpu_buffer_ctx_t *ctx, dpu_buffer_flow_t *flow)
{
    if (!flow->ring)
        return 0;

    struct rte_mbuf *mbuf;
    uint32_t flushed = 0;
    uint64_t bytes = 0;
    while (rte_ring_sc_dequeue(flow->ring, (void **)&mbuf) == 0) {
        bytes += rte_pktmbuf_pkt_len(mbuf);
        rte_pktmbuf_free(mbuf);
        flushed++;
    }
    if (flushed > 0) {
        __atomic_fetch_sub(&ctx->global_count, flushed, __ATOMIC_RELAXED);
        buf_account_dequeued(ctx, flow, bytes);
    }
    return flushed;
}


/**
 * Software-encap a batch of buffered DL packets and Tx them on N3.
 *
 * For every packet, looks up the per-rule encap params cached in the
 * pipeline rule record (gNB IP/TEID/QFI), prepends the wire-form
 * GTP-U + PSC headers, and submits the burst to the configured Tx
 * queue on the N3 PF.  Frees any packet that fails encap or Tx.
 *
 * All packets in the batch belong to the same flow, so encap params
 * are looked up once per call.
 *
 * @return  Number of packets successfully transmitted.
 */
static uint16_t
reinject_burst(dpu_buffer_ctx_t *ctx, dpu_buffer_flow_t *flow,
               struct rte_mbuf **pkts, uint16_t nb_pkts)
{
    if (nb_pkts == 0)
        return 0;

    /* UL buffering is not supported by the SW-encap path.  Free and
     * skip rather than mis-encap.  This path should not be reached:
     * the BUFF guard in dpu_pipeline_update_far refuses UL BUFF, so
     * no UL flow ever transitions to BUFFER mode here. */
    if (flow->direction != HW_DIR_DOWNLINK) {
        for (uint16_t i = 0; i < nb_pkts; i++)
            rte_pktmbuf_free(pkts[i]);
        return 0;
    }

    uint32_t ohc_ipv4 = 0;
    uint32_t ohc_teid = 0;
    uint8_t encap_qfi = 0;
    if (!dpu_pipeline_get_dl_encap_params(ctx->pipeline, flow->hw_rule_id,
                                          &ohc_ipv4, &ohc_teid, &encap_qfi)) {
        DOCA_LOG_WARN("buffer SW-encap: no DL encap params for hw_rule_id=%u "
                      "(dropping %u pkt(s))",
                      flow->hw_rule_id, nb_pkts);
        for (uint16_t i = 0; i < nb_pkts; i++)
            rte_pktmbuf_free(pkts[i]);
        return 0;
    }

    /* Build the wire-form headers in place.  Drop and remove from the
     * burst any packet that fails (e.g. headroom shortfall).  We
     * compact the burst so rte_eth_tx_burst sees only valid packets. */
    uint16_t built = 0;
    for (uint16_t i = 0; i < nb_pkts; i++) {
        if (dpu_gtp_encap_dl(pkts[i], &ctx->pipeline->port_cfg,
                             ohc_ipv4, ohc_teid, encap_qfi) == 0) {
            pkts[built++] = pkts[i];
        } else {
            rte_pktmbuf_free(pkts[i]);
        }
    }
    if (built == 0)
        return 0;

    uint16_t sent = rte_eth_tx_burst(ctx->tx_port_id, ctx->tx_queue_id, pkts, built);
    if (sent < built) {
        /* Tx-queue backpressure: these packets are lost, not deferred.
         * Counted per flow so a saturated N3 Tx queue is visible in the
         * SIGUSR1 dump instead of silently shrinking "drained". */
        flow->tx_dropped += (uint64_t)(built - sent);
        for (uint16_t i = sent; i < built; i++)
            rte_pktmbuf_free(pkts[i]);
    }

    return sent;
}


/* ═══════════════════════════════════════════════════════════════════════
 *  Public API
 * ═══════════════════════════════════════════════════════════════════════ */

int
dpu_buffer_init(dpu_buffer_ctx_t *ctx,
                uint16_t rx_port_id,
                uint16_t rx_nr_queues,
                uint16_t tx_port_id,
                uint16_t tx_queue_id,
                dpu_pipeline_ctx_t *pipeline,
                uint32_t max_flows,
                const dpu_buf_alloc_cfg_t *alloc_cfg)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->max_flows    = max_flows;
    ctx->rx_port_id   = rx_port_id;
    ctx->rx_nr_queues = rx_nr_queues;
    ctx->tx_port_id   = tx_port_id;
    ctx->tx_queue_id  = tx_queue_id;
    ctx->pipeline     = pipeline;
    ctx->running      = true;

    /* BDP byte-budget allocator config.  No cfg (or m_op_bytes==UINT64_MAX)
     * ⇒ allocator OFF: legacy packet-count caps apply, byte path inert. */
    if (alloc_cfg) {
        ctx->m_op_bytes            = alloc_cfg->m_op_bytes;
        ctx->default_seed_rate_Bps = alloc_cfg->default_seed_rate_Bps;
        ctx->t_hold_ms             = alloc_cfg->t_hold_ms;
        ctx->tick_ms               = alloc_cfg->tick_ms;
        ctx->ewma_alpha_pct        = alloc_cfg->ewma_alpha_pct;
        ctx->measure_demand        = alloc_cfg->measure_demand;
    } else {
        ctx->m_op_bytes            = UINT64_MAX;
    }

    ctx->flows = calloc(max_flows, sizeof(dpu_buffer_flow_t));
    if (!ctx->flows) {
        DOCA_LOG_ERR("Failed to allocate %u buffer flow slots", max_flows);
        return -1;
    }

    struct rte_hash_parameters hp = {
        .name = "buffer_flow_id_map",
        .entries = max_flows,
        .key_len = sizeof(uint32_t),
        .hash_func = rte_jhash,
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY,
    };
    ctx->flow_id_map = rte_hash_create(&hp);
    if (!ctx->flow_id_map) {
        DOCA_LOG_ERR("Failed to create buffer flow_id_map rte_hash");
        free(ctx->flows);
        ctx->flows = NULL;
        return -1;
    }

    /* Index scratch for the max-min recompute (buffer-lcore-only). */
    ctx->mm_scratch = calloc(max_flows, sizeof(uint32_t));
    if (!ctx->mm_scratch) {
        DOCA_LOG_ERR("Failed to allocate buffer max-min scratch (%u)", max_flows);
        rte_hash_free(ctx->flow_id_map);
        ctx->flow_id_map = NULL;
        free(ctx->flows);
        ctx->flows = NULL;
        return -1;
    }

    DOCA_LOG_INFO("Buffer init: rx_port=%u rx_queues=%u tx_port=%u tx_queue=%u "
                  "max_flows=%u (DL SW-encap → N3)",
                  rx_port_id, rx_nr_queues, tx_port_id, tx_queue_id, max_flows);
    if (ctx->m_op_bytes == UINT64_MAX) {
        DOCA_LOG_INFO("Buffer allocator: OFF (legacy caps per-flow=%u global=%u pkts)",
                      DPU_BUFFER_PER_FLOW, DPU_BUFFER_GLOBAL_CAP);
    } else {
        DOCA_LOG_INFO("Buffer allocator: ON m_op_bytes=%lu t_hold_ms=%u tick_ms=%u "
                      "ewma_alpha=%u%% measure_demand=%u default_seed_Bps=%lu",
                      (unsigned long)ctx->m_op_bytes, ctx->t_hold_ms, ctx->tick_ms,
                      ctx->ewma_alpha_pct, ctx->measure_demand,
                      (unsigned long)ctx->default_seed_rate_Bps);
    }
    return 0;
}

int
dpu_buffer_register_flow(dpu_buffer_ctx_t *ctx,
                         uint32_t hw_rule_id,
                         uint8_t direction,
                         uint64_t mbr_dl_Bps,
                         uint64_t gbr_dl_Bps)
{
    /* Check if already registered.  A CLOSED flow for the same
     * hw_rule_id is NOT "already registered" — it completed a previous
     * BUFF cycle and must be re-activated for the new BUFF request. */
    dpu_buffer_flow_t *flow = find_flow(ctx, hw_rule_id);
    if (flow) {
        uint32_t st = __atomic_load_n(&flow->state, __ATOMIC_ACQUIRE);
        if (st == DPU_BUF_ACTIVE) {
            /* Idempotent re-BUFF.  Distinguished from a fresh registration
             * (return 0) so the caller's override-failure rollback never
             * tears down a flow that was already live before this call. */
            DOCA_LOG_DBG("buffer: flow hw_rule_id=%u already ACTIVE",
                         hw_rule_id);
            return 1;
        }
        if (st == DPU_BUF_DRAINING) {
            DOCA_LOG_WARN("buffer: flow hw_rule_id=%u still DRAINING "
                          "from previous FORW cycle \u2014 refusing registration",
                          hw_rule_id);
            return -1;
        }
        if (st == DPU_BUF_RETIRING || st == DPU_BUF_CLOSING) {
            /* A previous cycle is still being closed by the Rx lcore
             * (RETIRING: observed retire, typically ~1 ms; CLOSING:
             * discard close, ~one poll).  The Rx lcore may still be
             * touching this slot's ring, so only CLOSED is a safe reuse
             * source — give the asynchronous close a bounded grace
             * before refusing. */
            uint64_t deadline = rte_get_timer_cycles() +
                (uint64_t)DPU_BUFFER_REGISTER_WAIT_US *
                    rte_get_timer_hz() / 1000000;
            while ((st = __atomic_load_n(&flow->state, __ATOMIC_ACQUIRE))
                       == DPU_BUF_RETIRING || st == DPU_BUF_CLOSING) {
                if (rte_get_timer_cycles() > deadline)
                    break;
                rte_pause();
            }
            if (st != DPU_BUF_CLOSED) {
                DOCA_LOG_WARN("buffer: flow hw_rule_id=%u still in state=%u "
                              "after %u us grace — refusing registration",
                              hw_rule_id, st, DPU_BUFFER_REGISTER_WAIT_US);
                return -1;
            }
        }
        /* CLOSED: reuse this slot — fall through to re-initialise */
    } else {
        flow = alloc_flow(ctx, hw_rule_id);
        if (!flow) {
            DOCA_LOG_ERR("buffer: no free flow slots for hw_rule_id=%u",
                         hw_rule_id);
            return -1;
        }
    }

    /* Create rte_ring if this slot hasn't been used before (or was
     * destroyed at shutdown).  If the ring already exists from a
     * previous BUFF cycle (CLOSED slot reuse), flush any stale mbufs
     * (possible from the Rx-lcore enqueue-after-close race) before
     * resetting for reuse. */
    if (flow->ring) {
        ring_flush(ctx, flow);
        rte_ring_reset(flow->ring);
    } else {
        char name[RTE_RING_NAMESIZE];
        snprintf(name, sizeof(name), "buf_%u", hw_rule_id);
        flow->ring = rte_ring_create(name, DPU_BUFFER_PER_FLOW,
                                      rte_socket_id(),
                                      RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (!flow->ring) {
            DOCA_LOG_ERR("buffer: rte_ring_create failed for hw_rule_id=%u",
                         hw_rule_id);
            return -1;
        }
    }

    flow->hw_rule_id  = hw_rule_id;
    flow->direction   = direction;
    flow->enqueued    = 0;
    flow->dropped     = 0;
    flow->drained     = 0;
    flow->passthrough = 0;
    flow->requeued    = 0;
    flow->tx_dropped  = 0;
    __atomic_store_n(&flow->discard, 0, __ATOMIC_RELAXED);

    /* ── BDP allocator state (reset for fresh + reused CLOSED slots) ──── */
    __atomic_store_n(&flow->queued_bytes, 0, __ATOMIC_RELAXED);
    flow->byte_dropped       = 0;
    flow->enq_bytes          = 0;
    flow->ewma_rate_Bps      = 0;
    flow->ewma_samples       = 0;
    flow->warmup_ticks_left  = SEED_WARMUP_TICKS;
    flow->last_offered_bytes = 0;

    /* Cold-start grant.  Ladder: MBR → GBR → operator default (all B/s).
     * U_i = seed_rate × T_hold; A_i = min(U_i, M_op).  When the allocator
     * is OFF the per-flow cap is disabled (A_i = UINT64_MAX).  These are
     * set BEFORE the state=ACTIVE release store below, so the control tick
     * and the Rx enqueue path observe a valid grant once they see ACTIVE. */
    if (ctx->m_op_bytes == UINT64_MAX) {
        flow->U_i_bytes = 0;
        flow->A_i_bytes = UINT64_MAX;
    } else {
        uint64_t seed_Bps = mbr_dl_Bps ? mbr_dl_Bps
                          : (gbr_dl_Bps ? gbr_dl_Bps : ctx->default_seed_rate_Bps);
        uint64_t u_i = seed_Bps * (uint64_t)ctx->t_hold_ms / 1000;
        flow->U_i_bytes = u_i;
        flow->A_i_bytes = (u_i < ctx->m_op_bytes) ? u_i : ctx->m_op_bytes;
    }

    /* Reset drain signalling */
    __atomic_store_n(&flow->drain_done, 0, __ATOMIC_RELAXED);

    /* Reset observed-retire evidence (RETIRING state).  begin_retire
     * re-stamps these immediately before the DRAINING->RETIRING transition,
     * but reset here too so a freshly reused CLOSED slot is clean for any
     * SIGUSR1 dump taken between register and begin_retire. */
    __atomic_store_n(&flow->retire_entry_tsc,       0, __ATOMIC_RELAXED);
    __atomic_store_n(&flow->retire_entry_epoch,     0, __ATOMIC_RELAXED);
    __atomic_store_n(&flow->last_old_path_rx_tsc,   0, __ATOMIC_RELAXED);
    __atomic_store_n(&flow->last_old_path_done_tsc, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&flow->last_old_path_rx_epoch, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&flow->old_path_inflight,      0, __ATOMIC_RELAXED);

    /* Publish state=ACTIVE last (release semantics) so the Rx lcore
     * sees a fully initialised flow when it observes state==ACTIVE. */
    __atomic_store_n(&flow->state, DPU_BUF_ACTIVE, __ATOMIC_RELEASE);
    /* Count this slot for the control-tick scan bound (CLOSED reuse and
     * fresh alloc both land here; the already-ACTIVE path returned early). */
    __atomic_fetch_add(&ctx->nr_buffering, 1, __ATOMIC_RELEASE);

    DOCA_LOG_INFO("buffer: registered flow hw_rule_id=%u dir=%s",
                  hw_rule_id,
                  direction == HW_DIR_UPLINK ? "UL" : "DL");
    return 0;
}

int
dpu_buffer_rollback_register(dpu_buffer_ctx_t *ctx, uint32_t hw_rule_id)
{
    dpu_buffer_flow_t *flow = find_flow(ctx, hw_rule_id);
    if (!flow) {
        DOCA_LOG_WARN("rollback_register: hw_rule_id=%u not found",
                      hw_rule_id);
        return -1;
    }

    uint32_t st = __atomic_load_n(&flow->state, __ATOMIC_ACQUIRE);
    if (st != DPU_BUF_ACTIVE) {
        /* Only a registration made this control-thread turn (override
         * never installed) is rollback-eligible — anything else means
         * the caller violated the contract; leave the slot alone. */
        DOCA_LOG_WARN("rollback_register: hw_rule_id=%u unexpected state=%u "
                      "— not rolling back", hw_rule_id, st);
        return -1;
    }

    /* ACTIVE → CLOSED.  No override was ever installed, so no packet for
     * this flow is in flight; the flush is a defensive no-op except for a
     * stale enqueue-after-close race remnant from a previous cycle.  The
     * hash binding and ring persist (slot-lifecycle invariant).  CLOSED is
     * published LAST — not racy here (register and rollback both run on
     * the control thread), but every close path keeps the same invariant
     * so reuse-safety never depends on which thread closed the slot. */
    ring_flush(ctx, flow);
    __atomic_fetch_sub(&ctx->nr_buffering, 1, __ATOMIC_RELEASE);
    __atomic_store_n(&flow->state, DPU_BUF_CLOSED, __ATOMIC_RELEASE);

    DOCA_LOG_INFO("rollback_register: hw_rule_id=%u ACTIVE → CLOSED "
                  "(override install failed)", hw_rule_id);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Rx-owned drain API (FORW path: begin_drain / wait_drain_done / retire)
 * ═══════════════════════════════════════════════════════════════════════ */

int
dpu_buffer_begin_drain(dpu_buffer_ctx_t *ctx,
                       uint32_t hw_rule_id)
{
    dpu_buffer_flow_t *flow = find_flow(ctx, hw_rule_id);
    if (!flow) {
        DOCA_LOG_DBG("begin_drain: hw_rule_id=%u not registered", hw_rule_id);
        return -1;
    }

    uint32_t st = __atomic_load_n(&flow->state, __ATOMIC_ACQUIRE);
    if (st == DPU_BUF_DRAINING)
        return 0;  /* idempotent */

    if (st != DPU_BUF_ACTIVE) {
        DOCA_LOG_WARN("begin_drain: hw_rule_id=%u unexpected state=%u "
                      "(expected ACTIVE)", hw_rule_id, st);
        return -1;
    }

    __atomic_store_n(&flow->drain_done, 0, __ATOMIC_RELAXED);

    /* ACTIVE → DRAINING: Rx lcore will drain ring + pass-through.
     * HW must still point to TO_DPU_ARM at this point. */
    __atomic_store_n(&flow->state, DPU_BUF_DRAINING, __ATOMIC_RELEASE);
    __atomic_fetch_add(&ctx->nr_draining, 1, __ATOMIC_RELEASE);

    DOCA_LOG_INFO("begin_drain: hw_rule_id=%u ACTIVE \u2192 DRAINING "
                  "(ring_count=%u)", hw_rule_id,
                  flow->ring ? rte_ring_count(flow->ring) : 0);
    return 0;
}

int
dpu_buffer_wait_drain_done(dpu_buffer_ctx_t *ctx,
                           uint32_t hw_rule_id)
{
    dpu_buffer_flow_t *flow = find_flow(ctx, hw_rule_id);
    if (!flow)
        return -1;

    uint32_t st = __atomic_load_n(&flow->state, __ATOMIC_ACQUIRE);
    if (st != DPU_BUF_DRAINING) {
        DOCA_LOG_WARN("wait_drain_done: hw_rule_id=%u not DRAINING (state=%u)",
                      hw_rule_id, st);
        return -1;
    }

    uint64_t deadline = rte_get_timer_cycles() +
        (uint64_t)DPU_BUFFER_QUIESCE_US * rte_get_timer_hz() / 1000000;

    while (!__atomic_load_n(&flow->drain_done, __ATOMIC_ACQUIRE)) {
        if (rte_get_timer_cycles() > deadline) {
            DOCA_LOG_ERR("wait_drain_done: timeout hw_rule_id=%u "
                         "(ring_count=%u) \u2014 flow stays DRAINING",
                         hw_rule_id,
                         flow->ring ? rte_ring_count(flow->ring) : 0);
            return -1;
        }
        rte_pause();
    }

    DOCA_LOG_INFO("wait_drain_done: hw_rule_id=%u drain complete "
                  "(drained=%lu passthrough=%lu)",
                  hw_rule_id,
                  (unsigned long)flow->drained,
                  (unsigned long)flow->passthrough);
    return 0;
}

int
dpu_buffer_begin_retire(dpu_buffer_ctx_t *ctx, uint32_t hw_rule_id)
{
    dpu_buffer_flow_t *flow = find_flow(ctx, hw_rule_id);
    if (!flow) {
        DOCA_LOG_WARN("begin_retire: hw_rule_id=%u not found", hw_rule_id);
        return -1;
    }

    uint32_t st = __atomic_load_n(&flow->state, __ATOMIC_ACQUIRE);
    if (st != DPU_BUF_DRAINING) {
        DOCA_LOG_WARN("begin_retire: hw_rule_id=%u not DRAINING (state=%u)",
                      hw_rule_id, st);
        return -1;
    }

    /* Preconditions: begin_retire is only valid once the Rx lcore has
     * signalled drain_done and the ring is empty.  After RETIRING, Phase 1
     * stops touching the flow, so protect the API here rather than relying
     * on caller ordering. */
    if (!__atomic_load_n(&flow->drain_done, __ATOMIC_ACQUIRE)) {
        DOCA_LOG_WARN("begin_retire: hw_rule_id=%u drain not done — refusing",
                      hw_rule_id);
        return -1;
    }
    uint32_t ring_count = flow->ring ? rte_ring_count(flow->ring) : 0;
    if (ring_count != 0) {
        DOCA_LOG_WARN("begin_retire: hw_rule_id=%u ring not empty (count=%u) "
                      "— refusing", hw_rule_id, ring_count);
        return -1;
    }

    /* Stamp the retire-entry floor and reset all evidence fields BEFORE the
     * state store-RELEASE, so an Rx lcore that later observes state==RETIRING
     * (ACQUIRE) sees a fully-initialised, floored frame.  The floor makes
     * "K epochs + tail_idle" measure from THIS instant, not from epoch/tsc 0. */
    uint64_t epoch = __atomic_load_n(&ctx->current_rx_poll_epoch,
                                     __ATOMIC_RELAXED);
    __atomic_store_n(&flow->retire_entry_tsc,   rte_get_tsc_cycles(),
                     __ATOMIC_RELAXED);
    __atomic_store_n(&flow->retire_entry_epoch, epoch, __ATOMIC_RELAXED);
    __atomic_store_n(&flow->last_old_path_rx_tsc,   0, __ATOMIC_RELAXED);
    __atomic_store_n(&flow->last_old_path_done_tsc, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&flow->last_old_path_rx_epoch, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&flow->old_path_inflight,      0, __ATOMIC_RELAXED);

    __atomic_store_n(&flow->state, DPU_BUF_RETIRING, __ATOMIC_RELEASE);

    /* Move accounting DRAINING -> RETIRING and ALSO drop the flow from
     * nr_buffering (RETIRING-leaves-the-buffering-set): the ring is empty and
     * the flow holds no byte grant, so the BDP control tick must ignore it.
     * Decrement AFTER the state store above so a concurrent control-tick scan
     * never observes state==DRAINING with nr_buffering already decremented.
     * The Rx lcore's RETIRING→CLOSED close decrements only nr_retiring. */
    __atomic_fetch_sub(&ctx->nr_draining,  1, __ATOMIC_RELEASE);
    __atomic_fetch_sub(&ctx->nr_buffering, 1, __ATOMIC_RELEASE);
    __atomic_fetch_add(&ctx->nr_retiring,  1, __ATOMIC_RELEASE);

    DOCA_LOG_INFO("begin_retire: hw_rule_id=%u DRAINING → RETIRING "
                  "(entry_epoch=%lu)", hw_rule_id, (unsigned long)epoch);
    return 0;
}


/* ═══════════════════════════════════════════════════════════════════════
 *  DROP/DELETE path API (begin_close — Rx-owned discard close)
 * ═══════════════════════════════════════════════════════════════════════ */

int
dpu_buffer_begin_close(dpu_buffer_ctx_t *ctx,
                       uint32_t hw_rule_id)
{
    dpu_buffer_flow_t *flow = find_flow(ctx, hw_rule_id);
    if (!flow)
        return 0;  /* not registered — nothing to close */

    uint32_t st = __atomic_load_n(&flow->state, __ATOMIC_ACQUIRE);
    if (st == DPU_BUF_CLOSED || st == DPU_BUF_CLOSING)
        return 0;  /* idempotent — CLOSING already carries the discard flag */

    /* Stamp the idle-fence floor BEFORE publishing the discard flag (the
     * RELEASE below orders it): every teardown close waits for the same
     * observed-idle fence as the FORW retire (K empty epochs + tail idle,
     * measured from max(this floor, last freed late arrival)).  The fence
     * is the REUSE GUARD: it keeps the slot out of CLOSED until the NIC
     * residual DMA tail has demonstrably gone quiet, so a fast re-BUFF of
     * the same hw_rule_id cannot capture an old session's packet into the
     * new cycle.  For RETIRING this re-stamps (extends) the begin_retire
     * floor — harmless and uniform. */
    __atomic_store_n(&flow->retire_entry_tsc, rte_get_tsc_cycles(),
                     __ATOMIC_RELAXED);
    __atomic_store_n(&flow->retire_entry_epoch,
                     __atomic_load_n(&ctx->current_rx_poll_epoch,
                                     __ATOMIC_RELAXED),
                     __ATOMIC_RELAXED);

    if (st == DPU_BUF_DRAINING || st == DPU_BUF_RETIRING) {
        /* DROP/DELETE while the flow is leaving via the FORW path (a
         * drain-timeout remnant, or a retire still in flight).  The Rx
         * lcore is the ring's consumer in both states: the discard flag
         * makes it free the backlog (instead of reinjecting packets for
         * a rule whose HW entry is gone) and close the slot itself. */
        __atomic_store_n(&flow->discard, 1, __ATOMIC_RELEASE);
        DOCA_LOG_INFO("begin_close: hw_rule_id=%u %s — discard requested "
                      "(Rx lcore will free backlog and close)",
                      hw_rule_id,
                      st == DPU_BUF_DRAINING ? "DRAINING" : "RETIRING");
        return 0;
    }

    if (st != DPU_BUF_ACTIVE) {
        DOCA_LOG_WARN("begin_close: hw_rule_id=%u unexpected state=%u",
                      hw_rule_id, st);
        return 0;
    }

    /* ACTIVE → CLOSING with the discard flag up.  The HW source is
     * already cut by the caller; the Rx lcore frees any late in-flight
     * arrival (Phase 2) and flushes the backlog, then closes the slot
     * once the idle fence holds.  Publish discard BEFORE the state
     * store-RELEASE so a thread that observes CLOSING is guaranteed to
     * observe the flag (and the floor stamped above) too. */
    __atomic_store_n(&flow->discard, 1, __ATOMIC_RELEASE);
    __atomic_store_n(&flow->state, DPU_BUF_CLOSING, __ATOMIC_RELEASE);
    __atomic_fetch_add(&ctx->nr_closing, 1, __ATOMIC_RELEASE);

    DOCA_LOG_INFO("begin_close: hw_rule_id=%u ACTIVE → CLOSING "
                  "(Rx lcore will free backlog and close)", hw_rule_id);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  BDP byte-budget allocator: control tick (buffer-lcore-only)
 * ═══════════════════════════════════════════════════════════════════════ */

/**
 * Recompute per-flow byte grants (A_i) by max-min fair division of M_op.
 * Runs ONLY on the buffer lcore from the control tick; no-op when OFF.
 *
 * Leaving flows (DRAINING/CLOSING) are FIXED reservations: their A_i is
 * subtracted off the top and never modified here, so neither a falling EWMA
 * nor a concurrent BUFF (lower λ) can cut a draining flow's headroom.  Only
 * ACTIVE flows max-min the remaining budget.  A leaving flow's reservation
 * is released automatically once it reaches CLOSED (next tick drops it).
 */
static void
recompute_maxmin(dpu_buffer_ctx_t *ctx)
{
    if (ctx->m_op_bytes == UINT64_MAX)
        return;  /* allocator OFF */

    dpu_buffer_flow_t *flows = ctx->flows;
    uint32_t *idx = ctx->mm_scratch;

    /* Reserve leaving flows off the top; gather ACTIVE flow indices.
     * Bounded by nr_buffering so a sparse slot table (max_flows ≫ live
     * flows) is not fully walked every tick. */
    uint64_t reserved = 0;
    uint32_t n = 0;
    uint32_t want = __atomic_load_n(&ctx->nr_buffering, __ATOMIC_ACQUIRE);
    uint32_t seen = 0;
    for (uint32_t i = 0; i < ctx->max_flows && seen < want; i++) {
        uint32_t st = __atomic_load_n(&flows[i].state, __ATOMIC_ACQUIRE);
        if (st == DPU_BUF_ACTIVE) {
            seen++;
            idx[n++] = i;
        } else if (st == DPU_BUF_DRAINING || st == DPU_BUF_CLOSING) {
            seen++;
            uint64_t a = flows[i].A_i_bytes;
            if (a != UINT64_MAX)
                reserved += a;
        }
    }
    if (n == 0)
        return;

    uint64_t budget = (reserved < ctx->m_op_bytes)
                    ? (ctx->m_op_bytes - reserved) : 0;

    /* Insertion-sort ACTIVE indices by demand U_i ascending (N small). */
    for (uint32_t a = 1; a < n; a++) {
        uint32_t key = idx[a];
        uint64_t ku  = flows[key].U_i_bytes;
        uint32_t b   = a;
        while (b > 0 && flows[idx[b - 1]].U_i_bytes > ku) {
            idx[b] = idx[b - 1];
            b--;
        }
        idx[b] = key;
    }

    /* Single-pass progressive fill: once a demand exceeds the equal share of
     * the remaining budget, that flow and all larger-demand flows are capped
     * at that share (max-min). */
    uint64_t remaining = budget;
    for (uint32_t k = 0; k < n; k++) {
        uint32_t cnt  = n - k;             /* flows idx[k..n-1] unfinalised   */
        uint64_t fair = remaining / cnt;   /* equal share of the remainder    */
        dpu_buffer_flow_t *f = &flows[idx[k]];
        if (f->U_i_bytes <= fair) {
            f->A_i_bytes = f->U_i_bytes;   /* satisfied fully                 */
            remaining   -= f->U_i_bytes;
        } else {
            for (uint32_t j = k; j < n; j++)
                flows[idx[j]].A_i_bytes = fair;   /* capped at the fair share */
            break;
        }
    }
}

/**
 * Measure each ACTIVE flow's offered load this tick and refresh its demand
 * U_i (EWMA).  DRAINING/CLOSING flows are never measured (held fixed).
 *
 * offered = enqueued + ALL dropped bytes (invariant to A_i — keeps the loop
 * unbiased).  While on the cold-start seed (ewma_samples == 0) an idle tick
 * is tolerated for SEED_WARMUP_TICKS, then the flow hands off to measurement
 * (a forever-silent flow measures ~0 and releases its reservation).  Once
 * measuring, R̂ = EWMA forever — never reverts to the QoS seed.
 */
static void
buffer_measure_tick(dpu_buffer_ctx_t *ctx, uint64_t tsc_hz, uint64_t delta_cycles)
{
    if (delta_cycles == 0)
        return;
    uint32_t alpha = ctx->ewma_alpha_pct;  /* 0..100 */
    uint32_t want  = __atomic_load_n(&ctx->nr_buffering, __ATOMIC_ACQUIRE);
    uint32_t seen  = 0;

    for (uint32_t i = 0; i < ctx->max_flows && seen < want; i++) {
        dpu_buffer_flow_t *f = &ctx->flows[i];
        uint32_t st = __atomic_load_n(&f->state, __ATOMIC_ACQUIRE);
        if (st == DPU_BUF_DRAINING || st == DPU_BUF_CLOSING) {
            seen++;            /* counts toward the scan bound, not measured */
            continue;
        }
        if (st != DPU_BUF_ACTIVE)
            continue;
        seen++;

        uint64_t offered = f->enq_bytes + f->byte_dropped;  /* A_i-invariant  */
        uint64_t delta   = offered - f->last_offered_bytes;
        f->last_offered_bytes = offered;

        if (f->ewma_samples == 0) {
            /* Cold-start grace: keep the seed through idle ticks, but bound
             * it so a forever-silent flow eventually measures ~0. */
            if (delta == 0 && f->warmup_ticks_left > 0) {
                f->warmup_ticks_left--;
                continue;  /* U_i unchanged (still the QoS/default seed) */
            }
            /* first real traffic OR grace expired → begin measuring */
        }

        /* Integer-safe bytes/s. */
        uint64_t rate_Bps = delta * tsc_hz / delta_cycles;

        if (f->ewma_samples == 0)
            f->ewma_rate_Bps = rate_Bps;                    /* seed the EWMA  */
        else
            f->ewma_rate_Bps = (alpha * rate_Bps
                              + (100 - alpha) * f->ewma_rate_Bps) / 100;
        f->ewma_samples++;

        f->U_i_bytes = f->ewma_rate_Bps * (uint64_t)ctx->t_hold_ms / 1000;
    }
}

/**
 * Observed-idle close fence: ring empty ∧ no reinject in flight ∧ K empty
 * Rx epochs ∧ tail_idle_us of silence, the windows measured from the later
 * of {fence floor, last late-packet evidence}.  Shared by the RETIRING
 * retire close and every discard teardown close (CLOSING / DRAINING).
 * The fence is the REUSE GUARD: it keeps a slot out of CLOSED — and thus
 * out of register_flow reuse — until the NIC residual DMA tail for the
 * old cycle has demonstrably gone quiet, so a fast same-hw_rule_id
 * re-BUFF cannot capture an old session's packet into the new cycle.
 * Bounded idle confidence, not deterministic (no HW retire barrier). */
static inline bool
close_fence_holds(dpu_buffer_flow_t *fl, uint64_t epoch_now,
                  uint64_t now, uint64_t tail_idle_cycles)
{
    uint32_t ring_count = fl->ring ? rte_ring_count(fl->ring) : 0;
    uint32_t inflight =
        __atomic_load_n(&fl->old_path_inflight, __ATOMIC_ACQUIRE);

    /* Reference = later of {floor, last sighting}.  The last_* fields are
     * zeroed at register/begin_retire, so with no late packet the max()
     * collapses to the floor and the fence waits exactly K epochs +
     * tail_idle from the floor stamp. */
    uint64_t ref_epoch =
        __atomic_load_n(&fl->retire_entry_epoch, __ATOMIC_RELAXED);
    uint64_t last_epoch =
        __atomic_load_n(&fl->last_old_path_rx_epoch, __ATOMIC_RELAXED);
    if (last_epoch > ref_epoch) ref_epoch = last_epoch;

    uint64_t ref_tsc =
        __atomic_load_n(&fl->retire_entry_tsc, __ATOMIC_RELAXED);
    uint64_t last_done =
        __atomic_load_n(&fl->last_old_path_done_tsc, __ATOMIC_RELAXED);
    if (last_done > ref_tsc) ref_tsc = last_done;

    bool epochs_ok = (epoch_now - ref_epoch) >= DPU_BUFFER_RETIRE_K_EPOCHS;
    bool idle_ok   = (now - ref_tsc) >= tail_idle_cycles;

    return ring_count == 0 && inflight == 0 && epochs_ok && idle_ok;
}

int
dpu_buffer_rx_loop(void *arg)
{
    dpu_buffer_ctx_t *ctx = (dpu_buffer_ctx_t *)arg;
    struct rte_mbuf *rx_bufs[32];

    DOCA_LOG_INFO("Buffer Rx loop started on lcore %u: "
                  "rx_port=%u rx_queues=%u tx_port=%u tx_queue=%u",
                  rte_lcore_id(), ctx->rx_port_id, ctx->rx_nr_queues,
                  ctx->tx_port_id, ctx->tx_queue_id);

    /* ── BDP control-tick cadence (allocator ON only) ─────────────────── */
    const uint64_t tsc_hz = rte_get_tsc_hz();
    const uint64_t tick_cycles =
        (ctx->m_op_bytes != UINT64_MAX && ctx->tick_ms)
            ? (uint64_t)ctx->tick_ms * tsc_hz / 1000 : 0;
    uint64_t last_tick = rte_rdtsc();

    while (ctx->running) {
        /* Bump the Rx poll epoch FIRST — the "K empty epochs" retire fence
         * references it, and it must advance every iteration regardless of
         * the control tick / Phase 1 / Phase 2 below. */
        uint64_t epoch_now = __atomic_add_fetch(&ctx->current_rx_poll_epoch,
                                                1, __ATOMIC_RELAXED);

        /*
         * ── BDP control tick ──────────────────────────────────────────
         * Periodically (tick_ms) measure each ACTIVE flow's offered load
         * (v2; skipped in the static v1 ablation) and recompute the max-min
         * grants.  Membership is read directly from each flow's state — no
         * event signal.  Runs on this (the buffer) lcore, so A_i writes here
         * and A_i reads on the enqueue path below never race.
         */
        if (tick_cycles) {
            uint64_t now = rte_rdtsc();
            uint64_t delta_cycles = now - last_tick;
            if (delta_cycles >= tick_cycles) {
                last_tick = now;
                if (ctx->measure_demand)
                    buffer_measure_tick(ctx, tsc_hz, delta_cycles);
                recompute_maxmin(ctx);
            }
        }

        /*
         * ── Phase 1: service DRAINING flows (Rx-owned ring drain) ──
         *
         * drain_done is ONLY set here (never in Phase 2).  This ensures
         * that when the main thread observes drain_done=1, Phase 2 of
         * the previous iteration has fully completed — meaning all
         * Rx queue packets have been processed (pass-through reinjected
         * or enqueued for other states).  This is the strongest fence
         * we can provide: at least one full Rx burst cycle has passed
         * since the ring was emptied.
         *
         * Also handles the "no new traffic" edge case: drains the ring
         * progressively in bounded chunks (32 pkts) to avoid starving
         * Rx queue processing.  Early-exit once all DRAINING flows
         * are visited.
         */
        uint32_t nr_drain = __atomic_load_n(&ctx->nr_draining,
                                            __ATOMIC_ACQUIRE);
        if (nr_drain > 0) {
            for (uint32_t f = 0;
                 f < ctx->max_flows && nr_drain > 0; f++) {
                dpu_buffer_flow_t *fl = &ctx->flows[f];
                if (__atomic_load_n(&fl->state, __ATOMIC_ACQUIRE)
                    != DPU_BUF_DRAINING)
                    continue;
                nr_drain--;

                /* DROP/DELETE arrived while DRAINING (discard flag): the
                 * HW rule is gone, so free the backlog instead of
                 * reinjecting it — the Rx lcore owns the ring in DRAINING.
                 * The close itself waits for the observed-idle fence (the
                 * reuse guard); the flush is idempotent across revisits.
                 * Checked BEFORE drain_done: a flow whose drain completed
                 * but whose FORW aborted (begin_retire never ran) sits
                 * here with drain_done=1 and would otherwise never be
                 * visited again. */
                if (__atomic_load_n(&fl->discard, __ATOMIC_ACQUIRE)) {
                    uint32_t freed = ring_flush(ctx, fl);
                    uint64_t hz = rte_get_tsc_hz();
                    if (!close_fence_holds(fl, epoch_now,
                            rte_get_tsc_cycles(),
                            (uint64_t)DPU_BUFFER_TAIL_IDLE_US * hz / 1000000))
                        continue;  /* backlog freed; close next poll(s) */
                    /* DRAINING is still in the buffering set: release both
                     * counts (begin_drain's nr_draining increment + the
                     * registration's nr_buffering).  The CLOSED store-
                     * RELEASE is the LAST write — a re-BUFF reuses the
                     * slot the instant it observes CLOSED. */
                    __atomic_fetch_sub(&ctx->nr_draining,  1, __ATOMIC_RELEASE);
                    __atomic_fetch_sub(&ctx->nr_buffering, 1, __ATOMIC_RELEASE);
                    __atomic_store_n(&fl->state, DPU_BUF_CLOSED,
                                     __ATOMIC_RELEASE);
                    DOCA_LOG_INFO("buffer rx: hw_rule_id=%u DRAINING → CLOSED "
                                  "(discard, freed=%u)", fl->hw_rule_id, freed);
                    continue;
                }

                if (__atomic_load_n(&fl->drain_done, __ATOMIC_RELAXED))
                    continue;

                struct rte_mbuf *drain_bufs[32];
                unsigned int nb = rte_ring_sc_dequeue_burst(
                    fl->ring, (void **)drain_bufs, 32, NULL);
                if (nb > 0) {
                    __atomic_fetch_sub(&ctx->global_count,
                                       nb, __ATOMIC_RELAXED);
                    buf_account_dequeued(ctx, fl,
                                         sum_pkt_len(drain_bufs, (uint16_t)nb));
                    fl->drained += reinject_burst(ctx, fl,
                                                  drain_bufs, (uint16_t)nb);
                } else {
                    __atomic_store_n(&fl->drain_done, 1, __ATOMIC_RELEASE);
                }
            }
        }

        /*
         * ── Phase 2: Rx burst processing ───────────────────────────
         */
        for (uint16_t q = 0; q < ctx->rx_nr_queues; q++) {
            uint16_t nb_rx = rte_eth_rx_burst(ctx->rx_port_id,
                                               q, rx_bufs, 32);
            if (nb_rx == 0)
                continue;

            for (uint16_t i = 0; i < nb_rx; i++) {
                /* mbuf dynamic metadata is host-order on Rx (DPDK convention).
                 * The HW action stamps htonl(hw_rule_id) but mlx5 PMD applies
                 * BE→host conversion on the way to the mbuf, so the value here
                 * matches the host-order hw_rule_id used as the find_flow key. */
                uint32_t rule_id = rte_flow_dynf_metadata_get(rx_bufs[i]);

                dpu_buffer_flow_t *flow = find_flow(ctx, rule_id);
                if (!flow) {
                    DOCA_LOG_DBG("buffer rx: no flow for rule_id=%u, "
                                "dropping", rule_id);
                    rte_pktmbuf_free(rx_bufs[i]);
                    continue;
                }

                uint32_t st = __atomic_load_n(&flow->state,
                                              __ATOMIC_ACQUIRE);

                /*
                 * DRAINING: bounded drain + conditional re-enqueue.
                 *
                 * Pull at most 32 old packets from the ring (bounded
                 * to avoid starving rte_eth_rx_burst for other flows).
                 * If old packets remain after the bounded drain, the
                 * new packet is enqueued at the ring TAIL — it sits
                 * behind old packets, preserving FIFO order, and will
                 * be drained by Phase 1 in a subsequent iteration.
                 * If the ring is empty, the new packet is pass-through
                 * reinjected directly (fast path).
                 *
                 * drain_done is NOT set here — Phase 1 handles it
                 * exclusively at the top of the next iteration.  This
                 * guarantees that when the main thread observes
                 * drain_done=1, at least one full Rx burst cycle has
                 * completed since the ring was emptied (i.e. Phase 2
                 * of the previous iteration has fully processed any
                 * Rx queue packets).
                 */
                if (st == DPU_BUF_DRAINING) {
                    /* DROP/DELETE pending (discard): the HW rule is gone,
                     * this is a late in-flight DMA — free it and push the
                     * idle fence forward.  Phase 1 frees the backlog and
                     * closes the slot once the fence holds. */
                    if (__atomic_load_n(&flow->discard, __ATOMIC_ACQUIRE)) {
                        stamp_discard_arrival(flow, epoch_now);
                        flow->dropped++;
                        rte_pktmbuf_free(rx_bufs[i]);
                        continue;
                    }
                    if (!__atomic_load_n(&flow->drain_done,
                                         __ATOMIC_RELAXED)) {
                        /* Bounded drain: pull at most 32 old packets. */
                        struct rte_mbuf *drain_bufs[32];
                        unsigned int nb = rte_ring_sc_dequeue_burst(
                            flow->ring, (void **)drain_bufs, 32, NULL);
                        if (nb > 0) {
                            __atomic_fetch_sub(&ctx->global_count,
                                               nb, __ATOMIC_RELAXED);
                            buf_account_dequeued(ctx, flow,
                                sum_pkt_len(drain_bufs, (uint16_t)nb));
                            flow->drained += reinject_burst(
                                ctx, flow, drain_bufs, (uint16_t)nb);
                        }

                        /* If old packets remain, enqueue new pkt at
                         * ring tail.  FIFO: it sits behind old pkts.
                         * Phase 1 will drain it in a future iteration. */
                        if (rte_ring_count(flow->ring) > 0) {
                            uint32_t pkt_len = rte_pktmbuf_pkt_len(rx_bufs[i]);
                            /* Byte-grant enforcement only when the allocator
                             * is ON; legacy keeps the historical uncapped
                             * requeue during drain (no behaviour change). */
                            if (ctx->m_op_bytes != UINT64_MAX &&
                                !buf_admit(ctx, flow, pkt_len)) {
                                flow->dropped++;
                                rte_pktmbuf_free(rx_bufs[i]);
                                continue;
                            }
                            if (rte_ring_sp_enqueue(flow->ring,
                                                     rx_bufs[i]) == 0) {
                                buf_account_enqueued(ctx, flow, pkt_len);
                                flow->requeued++;
                            } else {
                                flow->dropped++;
                                if (ctx->m_op_bytes != UINT64_MAX)
                                    flow->byte_dropped += pkt_len;
                                rte_pktmbuf_free(rx_bufs[i]);
                            }
                            continue;
                        }
                    }
                    /* Ring is empty (or drain_done already set) —
                     * pass-through reinject directly. */
                    flow->passthrough += reinject_burst(
                        ctx, flow, &rx_bufs[i], 1);
                    continue;
                }

                /*
                 * RETIRING: override is gone, ring is empty (precondition).
                 * Any packet here is a late in-flight DMA from before the
                 * override removal.  Pass-through SW-encap + Tx on N3, and
                 * stamp retire-evidence so the end-of-poll close sees
                 * "in-flight right now" and "just completed" precisely —
                 * a late packet pushes the quiescence reference forward,
                 * deferring the close past it.  With a pending discard
                 * (DROP/DELETE), free instead of reinjecting: the rule's
                 * HW entry is gone, the packet must not reach the wire.
                 */
                if (st == DPU_BUF_RETIRING) {
                    if (__atomic_load_n(&flow->discard, __ATOMIC_ACQUIRE)) {
                        stamp_discard_arrival(flow, epoch_now);
                        flow->dropped++;
                        rte_pktmbuf_free(rx_bufs[i]);
                        continue;
                    }

                    __atomic_store_n(&flow->last_old_path_rx_tsc,
                                     rte_get_tsc_cycles(), __ATOMIC_RELAXED);
                    __atomic_store_n(&flow->last_old_path_rx_epoch,
                                     epoch_now, __ATOMIC_RELAXED);
                    __atomic_fetch_add(&flow->old_path_inflight, 1,
                                       __ATOMIC_ACQ_REL);

                    flow->passthrough += reinject_burst(
                        ctx, flow, &rx_bufs[i], 1);

                    __atomic_store_n(&flow->last_old_path_done_tsc,
                                     rte_get_tsc_cycles(), __ATOMIC_RELAXED);
                    __atomic_fetch_sub(&flow->old_path_inflight, 1,
                                       __ATOMIC_ACQ_REL);
                    continue;
                }

                /* CLOSING: teardown pending (discard is up) — the rule's
                 * HW entry is gone and this is a late in-flight DMA; free
                 * it and push the idle fence forward.  The end-of-poll
                 * discard-close scan flushes the backlog and closes the
                 * slot once the fence holds. */
                if (st == DPU_BUF_CLOSING) {
                    stamp_discard_arrival(flow, epoch_now);
                    flow->dropped++;
                    rte_pktmbuf_free(rx_bufs[i]);
                    continue;
                }

                /* ACTIVE: enqueue into the per-flow ring.
                 * INACTIVE / CLOSED: reject (free). */
                if (st != DPU_BUF_ACTIVE) {
                    rte_pktmbuf_free(rx_bufs[i]);
                    continue;
                }

                uint32_t pkt_len = rte_pktmbuf_pkt_len(rx_bufs[i]);

                /* Byte-grant + global-budget admission.  In legacy mode this
                 * falls back to the global packet-count cap inside buf_admit. */
                if (!buf_admit(ctx, flow, pkt_len)) {
                    flow->dropped++;
                    rte_pktmbuf_free(rx_bufs[i]);
                    continue;
                }

                if (rte_ring_sp_enqueue(flow->ring, rx_bufs[i]) != 0) {
                    flow->dropped++;
                    if (ctx->m_op_bytes != UINT64_MAX)
                        flow->byte_dropped += pkt_len;
                    rte_pktmbuf_free(rx_bufs[i]);
                    continue;
                }

                buf_account_enqueued(ctx, flow, pkt_len);
                flow->enqueued++;
            }
        }

        /*
         * ── End-of-poll retire close (Rx-owned) ────────────────────────
         * For each RETIRING flow, evaluate the observed-idle fence and
         * close the slot (RETIRING → CLOSED) the moment it holds.  A
         * pending DROP/DELETE (discard flag) changes what Phase 2 does
         * with late packets (free instead of reinject) but NOT the fence:
         * the close never lands before the residual NIC tail has gone
         * quiet, which is what makes same-hw_rule_id reuse safe.  The
         * close runs on this lcore, the only producer AND (in RETIRING)
         * only consumer of the ring, so there is no close-boundary race:
         * a late packet processed earlier this poll already pushed the
         * fence reference forward.  This replaces the old control-thread
         * wait_retire_done/close_flow loop, which blocked the Comch
         * thread ≥1 ms per FORW and leaked the slot on timeout.  Gated on
         * nr_retiring so the scan is skipped entirely when no retire is
         * pending.
         */
        if (__atomic_load_n(&ctx->nr_retiring, __ATOMIC_RELAXED) > 0) {
            uint64_t hz = rte_get_tsc_hz();
            uint64_t tail_idle_cycles =
                (uint64_t)DPU_BUFFER_TAIL_IDLE_US * hz / 1000000;
            uint64_t now = rte_get_tsc_cycles();
            uint32_t remaining = __atomic_load_n(&ctx->nr_retiring,
                                                 __ATOMIC_RELAXED);

            for (uint32_t f = 0; f < ctx->max_flows && remaining > 0; f++) {
                dpu_buffer_flow_t *fl = &ctx->flows[f];
                uint32_t fst = __atomic_load_n(&fl->state, __ATOMIC_ACQUIRE);
                if (fst != DPU_BUF_RETIRING)
                    continue;
                remaining--;

                bool discard =
                    __atomic_load_n(&fl->discard, __ATOMIC_ACQUIRE) != 0;

                /* One fence for both close reasons.  With discard, Phase 2
                 * freed (rather than reinjected) any late arrival and
                 * stamped the same evidence fields, so the fence still
                 * measures real old-path silence — the close may not land
                 * before the residual NIC tail has gone quiet (reuse
                 * guard). */
                if (!close_fence_holds(fl, epoch_now, now, tail_idle_cycles))
                    continue;  /* not quiescent yet — re-check next poll */

                /* RETIRING → CLOSED.  Keep the hash binding + ring (slot-
                 * lifecycle invariant); only nr_retiring is decremented —
                 * begin_retire already released nr_draining/nr_buffering.
                 *
                 * The CLOSED store-RELEASE is the LAST write: register_flow's
                 * RETIRING grace spins on state and reuses the slot (ring
                 * flush + reset) the instant it observes CLOSED, so every
                 * cleanup write here must be ordered before that store or
                 * the control thread races our residual flush. */
                uint32_t residual = ring_flush(ctx, fl);
                __atomic_fetch_sub(&ctx->nr_retiring, 1, __ATOMIC_RELEASE);
                __atomic_store_n(&fl->state, DPU_BUF_CLOSED, __ATOMIC_RELEASE);

                DOCA_LOG_INFO("buffer rx: hw_rule_id=%u RETIRING → CLOSED "
                              "(%s, enq=%lu requeued=%lu drop=%lu drain=%lu "
                              "passthrough=%lu residual=%u)",
                              fl->hw_rule_id,
                              discard ? "discard" : "observed quiescence",
                              (unsigned long)fl->enqueued,
                              (unsigned long)fl->requeued,
                              (unsigned long)fl->dropped,
                              (unsigned long)fl->drained,
                              (unsigned long)fl->passthrough,
                              residual);
            }
        }

        /*
         * ── End-of-poll discard close (CLOSING slots, Rx-owned) ────────
         * begin_close (DROP/DELETE on an ACTIVE flow) moves the slot to
         * CLOSING with the discard flag up and returns immediately; this
         * scan frees the backlog at once and closes the slot when the
         * observed-idle fence holds (the reuse guard — see
         * close_fence_holds).  It runs on the only thread that touches
         * the ring, so by end-of-poll there is no in-flight packet by
         * construction — no quiesce is needed.  Every CLOSING slot
         * carries the discard flag (the only path in sets it).  Gated on
         * nr_closing so the scan is skipped when no teardown is pending.
         */
        if (__atomic_load_n(&ctx->nr_closing, __ATOMIC_RELAXED) > 0) {
            uint64_t hz = rte_get_tsc_hz();
            uint64_t tail_idle_cycles =
                (uint64_t)DPU_BUFFER_TAIL_IDLE_US * hz / 1000000;
            uint64_t now = rte_get_tsc_cycles();
            uint32_t remaining = __atomic_load_n(&ctx->nr_closing,
                                                 __ATOMIC_RELAXED);
            for (uint32_t f = 0; f < ctx->max_flows && remaining > 0; f++) {
                dpu_buffer_flow_t *fl = &ctx->flows[f];
                if (__atomic_load_n(&fl->state, __ATOMIC_ACQUIRE)
                        != DPU_BUF_CLOSING)
                    continue;
                remaining--;

                uint32_t freed = ring_flush(ctx, fl);
                if (!close_fence_holds(fl, epoch_now, now, tail_idle_cycles))
                    continue;  /* backlog freed; close once the tail is quiet */

                /* CLOSING is still in the buffering set: release both
                 * counts.  The CLOSED store-RELEASE is the LAST write
                 * (uniform close invariant: cleanup → counter releases →
                 * state) — a re-BUFF reuses the slot the instant it
                 * observes CLOSED. */
                __atomic_fetch_sub(&ctx->nr_closing,   1, __ATOMIC_RELEASE);
                __atomic_fetch_sub(&ctx->nr_buffering, 1, __ATOMIC_RELEASE);
                __atomic_store_n(&fl->state, DPU_BUF_CLOSED, __ATOMIC_RELEASE);

                DOCA_LOG_INFO("buffer rx: hw_rule_id=%u CLOSING → CLOSED "
                              "(discard, freed=%u, enq=%lu drop=%lu)",
                              fl->hw_rule_id, freed,
                              (unsigned long)fl->enqueued,
                              (unsigned long)fl->dropped);
            }
        }
    }

    DOCA_LOG_INFO("Buffer Rx loop exiting on lcore %u", rte_lcore_id());
    return 0;
}

void
dpu_buffer_stop(dpu_buffer_ctx_t *ctx)
{
    ctx->running = false;
}

void
dpu_buffer_destroy(dpu_buffer_ctx_t *ctx)
{
    if (ctx->flows) {
        for (uint32_t i = 0; i < ctx->max_flows; i++) {
            dpu_buffer_flow_t *flow = &ctx->flows[i];
            if (flow->ring) {
                ring_flush(ctx, flow);
                rte_ring_free(flow->ring);
                flow->ring = NULL;
            }
        }
        free(ctx->flows);
        ctx->flows = NULL;
    }
    if (ctx->flow_id_map) {
        rte_hash_free(ctx->flow_id_map);
        ctx->flow_id_map = NULL;
    }
    if (ctx->mm_scratch) {
        free(ctx->mm_scratch);
        ctx->mm_scratch = NULL;
    }
    DOCA_LOG_INFO("Buffer destroyed");
}

void
dpu_buffer_dump_stats(const dpu_buffer_ctx_t *ctx)
{
    if (!ctx || !ctx->flows)
        return;

    uint32_t global   = __atomic_load_n(&ctx->global_count, __ATOMIC_RELAXED);
    uint32_t draining = __atomic_load_n(&ctx->nr_draining,  __ATOMIC_RELAXED);

    DOCA_LOG_INFO("Buffer stats (global): in_flight=%u draining=%u "
                  "max_flows=%u rx_port=%u tx_port=%u tx_q=%u",
                  global, draining, ctx->max_flows,
                  ctx->rx_port_id, ctx->tx_port_id, ctx->tx_queue_id);
    if (ctx->m_op_bytes != UINT64_MAX) {
        uint64_t gb = __atomic_load_n(&ctx->global_bytes, __ATOMIC_RELAXED);
        DOCA_LOG_INFO("Buffer stats (bdp): global_bytes=%lu / m_op_bytes=%lu "
                      "t_hold_ms=%u tick_ms=%u ewma_alpha=%u%% measure_demand=%u",
                      (unsigned long)gb, (unsigned long)ctx->m_op_bytes,
                      ctx->t_hold_ms, ctx->tick_ms, ctx->ewma_alpha_pct,
                      ctx->measure_demand);
    }

    uint32_t nr_active = 0, nr_drain = 0, nr_closing = 0, nr_closed = 0;
    uint32_t nr_retire = 0;
    uint64_t tot_enq = 0, tot_drop = 0, tot_drained = 0;
    uint64_t tot_passthrough = 0, tot_requeued = 0, tot_tx_dropped = 0;

    for (uint32_t i = 0; i < ctx->max_flows; i++) {
        const dpu_buffer_flow_t *fl = &ctx->flows[i];
        uint32_t st = __atomic_load_n(&fl->state, __ATOMIC_ACQUIRE);
        if (st == DPU_BUF_INACTIVE)
            continue;

        const char *state_str =
            st == DPU_BUF_ACTIVE   ? "ACTIVE"   :
            st == DPU_BUF_DRAINING ? "DRAINING" :
            st == DPU_BUF_RETIRING ? "RETIRING" :
            st == DPU_BUF_CLOSING  ? "CLOSING"  :
            st == DPU_BUF_CLOSED   ? "CLOSED"   : "?";

        switch (st) {
        case DPU_BUF_ACTIVE:   nr_active++;  break;
        case DPU_BUF_DRAINING: nr_drain++;   break;
        case DPU_BUF_RETIRING: nr_retire++;  break;
        case DPU_BUF_CLOSING:  nr_closing++; break;
        case DPU_BUF_CLOSED:   nr_closed++;  break;
        default: break;
        }

        uint32_t ring_count = fl->ring ? rte_ring_count(fl->ring) : 0;
        uint32_t drain_done = __atomic_load_n(&fl->drain_done, __ATOMIC_RELAXED);
        uint32_t discard = __atomic_load_n(&fl->discard, __ATOMIC_RELAXED);

        DOCA_LOG_INFO("  flow hw_rule_id=%u dir=%s state=%s ring=%u "
                      "drain_done=%u discard=%u | "
                      "enq=%lu drop=%lu drained=%lu passthrough=%lu "
                      "requeued=%lu tx_drop=%lu",
                      fl->hw_rule_id,
                      fl->direction == HW_DIR_UPLINK ? "UL" : "DL",
                      state_str, ring_count, drain_done, discard,
                      (unsigned long)fl->enqueued,
                      (unsigned long)fl->dropped,
                      (unsigned long)fl->drained,
                      (unsigned long)fl->passthrough,
                      (unsigned long)fl->requeued,
                      (unsigned long)fl->tx_dropped);

        if (ctx->m_op_bytes != UINT64_MAX) {
            uint64_t qb = __atomic_load_n(&fl->queued_bytes, __ATOMIC_RELAXED);
            char ai[24];
            if (fl->A_i_bytes == UINT64_MAX)
                snprintf(ai, sizeof(ai), "off");
            else
                snprintf(ai, sizeof(ai), "%lu", (unsigned long)fl->A_i_bytes);
            DOCA_LOG_INFO("       bdp: queued_bytes=%lu A_i=%s U_i=%lu "
                          "rate_Bps=%lu samples=%u byte_drop=%lu",
                          (unsigned long)qb, ai,
                          (unsigned long)fl->U_i_bytes,
                          (unsigned long)fl->ewma_rate_Bps,
                          fl->ewma_samples,
                          (unsigned long)fl->byte_dropped);
        }

        if (st == DPU_BUF_RETIRING) {
            uint64_t now        = rte_get_tsc_cycles();
            uint64_t hz         = rte_get_tsc_hz();
            uint64_t last_rx    = __atomic_load_n(&fl->last_old_path_rx_tsc,   __ATOMIC_RELAXED);
            uint64_t last_done  = __atomic_load_n(&fl->last_old_path_done_tsc, __ATOMIC_RELAXED);
            uint32_t inflight   = __atomic_load_n(&fl->old_path_inflight,      __ATOMIC_RELAXED);
            uint64_t entry_ep   = __atomic_load_n(&fl->retire_entry_epoch,     __ATOMIC_RELAXED);
            uint64_t last_ep    = __atomic_load_n(&fl->last_old_path_rx_epoch, __ATOMIC_RELAXED);
            uint64_t cur_ep     = __atomic_load_n(&ctx->current_rx_poll_epoch, __ATOMIC_RELAXED);
            uint64_t ref_ep     = last_ep > entry_ep ? last_ep : entry_ep;
            DOCA_LOG_INFO("       RETIRING: inflight=%u "
                          "epoch_gap=%lu last_rx=%lu ms_ago last_done=%lu ms_ago",
                          inflight,
                          (unsigned long)(cur_ep - ref_ep),
                          last_rx   == 0 ? 0UL : (unsigned long)((now - last_rx)   * 1000 / hz),
                          last_done == 0 ? 0UL : (unsigned long)((now - last_done) * 1000 / hz));
        }

        tot_enq         += fl->enqueued;
        tot_drop        += fl->dropped;
        tot_drained     += fl->drained;
        tot_passthrough += fl->passthrough;
        tot_requeued    += fl->requeued;
        tot_tx_dropped  += fl->tx_dropped;
    }

    DOCA_LOG_INFO("Buffer stats (slots): active=%u draining=%u retiring=%u "
                  "closing=%u closed=%u",
                  nr_active, nr_drain, nr_retire, nr_closing, nr_closed);
    DOCA_LOG_INFO("Buffer stats (totals): enq=%lu drop=%lu drained=%lu "
                  "passthrough=%lu requeued=%lu tx_dropped=%lu",
                  (unsigned long)tot_enq,
                  (unsigned long)tot_drop,
                  (unsigned long)tot_drained,
                  (unsigned long)tot_passthrough,
                  (unsigned long)tot_requeued,
                  (unsigned long)tot_tx_dropped);
}
