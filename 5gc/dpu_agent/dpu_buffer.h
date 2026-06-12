/*
 * dpu_buffer.h — DPU ARM-side per-flow packet buffering (DL only)
 *
 * When the SMF sends UpdateFAR(BUFF) for a DL rule, the DPU Agent swaps
 * the per-entry fwd from COLOR_GATE → TO_DPU_ARM_DL.  Packets for that
 * flow arrive via RSS on the N6 Rx queues this module owns, where they
 * are stored in per-flow rte_ring queues (SPSC lockless) in BF3 DDR.
 *
 * On UpdateFAR(FORW), the buffer is drained with near-ordered delivery:
 *   1. Main thread sets state=DRAINING (HW still points to TO_DPU_ARM_DL)
 *   2. Rx lcore performs bounded drain (≤32 pkts/iter) of old ring packets;
 *      if old packets remain, new arrivals are re-enqueued at ring tail
 *      (FIFO-preserving).  Once the ring is empty, new arrivals are
 *      pass-through reinjected directly (no enqueue).
 *   3. Main thread waits for drain_done, removes the HW override, sets
 *      pipeline mode FAST, transitions the slot DRAINING → RETIRING, and
 *      RETURNS (the close is Rx-lcore-owned from here)
 *   4. Rx lcore keeps pass-through reinjecting late in-flight DMA packets
 *      and, at end-of-poll, closes RETIRING → CLOSED itself once it
 *      observes old-path quiescence (replaces both the fixed 50 µs
 *      cutover delay and the old control-thread wait_retire_done loop)
 *
 * Drain Tx: software GTP-U + PSC encap on the buffer lcore.
 *   In VNF mode, software-Tx'd packets traverse the EGRESS pipeline of
 *   the Tx port — they do NOT re-enter the ingress ROOT.  Stamping
 *   pkt_meta and Tx'ing on N6 (the historical reinject pattern) would
 *   exit the N6 wire un-encapped.  Instead, the lcore prepends a full
 *   Ethernet + IPv4 + UDP + GTP-U + GTP-PSC header per packet using the
 *   per-rule encap params cached in the pipeline rule record, and Tx's
 *   the finalised wire-form packet on N3 (the DL egress port), where
 *   DL_ENCAP's fwd_miss → N3_EGRESS_PASSTHROUGH lets the packet escape
 *   to the wire.
 *
 * UL buffering is not supported.  TO_DPU_ARM_DL is N6/DL-only and the
 * UPF-C side suppresses BUFF for UL PDRs; defense-in-depth on the DPU
 * side rejects UL BUFF in dpu_pipeline_update_far().
 *
 * Thread safety:
 *   rte_ring provides lockless SPSC semantics (Rx lcore = producer,
 *   Comch thread = consumer).  global_count uses __atomic builtins.
 *   flow->state uses atomic store/load for cross-lcore visibility.
 *
 * State machine (per-flow):
 *   INACTIVE → ACTIVE (register)
 *   ACTIVE   → CLOSED   (rollback_register) [override install failed]
 *   ACTIVE   → DRAINING (begin_drain)  [FORW path: Rx-owned drain]
 *   ACTIVE   → CLOSING  (begin_close)  [DROP/DELETE path: HW source cut]
 *   DRAINING → RETIRING (begin_retire) [FORW: after override removed]
 *   DRAINING → CLOSED   (Rx lcore)     [DROP/DELETE: discard flag set]
 *   RETIRING → CLOSED   (Rx lcore)     [observed quiescence OR discard]
 *   CLOSING  → CLOSED   (quiesce_and_drain)
 *
 *   ACTIVE:   Rx lcore enqueues into per-flow ring.
 *   DRAINING: Rx lcore bounded-drains ring; re-enqueues new pkts while
 *             ring non-empty, then pass-through reinjects once empty.
 *             If the discard flag is set (DROP/DELETE arrived while
 *             DRAINING), the Rx lcore frees the backlog and closes the
 *             slot instead (fixes the old stuck-DRAINING wedge).
 *   RETIRING: override gone (HW fast path live); ring empty; Rx pass-through
 *             reinjects late in-flight DMA packets, stamps retire-evidence,
 *             and closes the slot itself at end-of-poll once old-path
 *             quiescence holds (K empty epochs + tail idle), or immediately
 *             when the discard flag is set.
 *   CLOSING:  HW source cut; Rx still enqueues in-flight packets.
 *   CLOSED:   Rx rejects; safe to reuse slot.
 *   INACTIVE: Slot available.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include <rte_hash.h>

#include "dpu_pipeline.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Per-flow buffer queue limits ───────────────────────────────────── */
#define DPU_BUFFER_PER_FLOW    8192     /* rte_ring capacity per flow       */
#define DPU_BUFFER_GLOBAL_CAP  32768  /* max pkts queued across all flows */
#define DPU_BUFFER_QUIESCE_US  100000 /* spin-loop safety timeout in µs (100ms)
                                       * Used by wait_drain_done (FORW path)
                                       * and quiesce_and_drain (DROP/DELETE).
                                       * Not an intentional delay — both loops
                                       * converge in microseconds normally.   */
#define SEED_WARMUP_TICKS      3      /* cold-start seed grace, in control ticks:
                                       * a flow with no arrivals keeps its QoS
                                       * seed for this many idle ticks, then
                                       * hands off to measurement (~0).        */

/* ── Observed-retire (BUFF→FORW close timing; replaces a fixed 50 µs delay) ─ *
 * After the override is removed the flow enters RETIRING; the Rx lcore
 * declares quiescence only after K empty Rx poll epochs AND tail_idle_us of
 * silence, both measured from the later of {RETIRING entry, last late packet}. */
#define DPU_BUFFER_RETIRE_K_EPOCHS  5         /* K consecutive empty Rx epochs   */
#define DPU_BUFFER_TAIL_IDLE_US     1000      /* tail-idle floor (1 ms)          */
#define DPU_BUFFER_REGISTER_WAIT_US 5000      /* register_flow grace for a slot
                                               * still RETIRING from the previous
                                               * FORW (the Rx lcore closes it
                                               * asynchronously, typically ~1 ms) */

/* ── Per-flow buffer state machine ─────────────────────────────────── */
enum dpu_buffer_state {
    DPU_BUF_INACTIVE = 0,  /* Slot never used (initial state only)             */
    DPU_BUF_ACTIVE   = 1,  /* Actively buffering; Rx lcore enqueues            */
    DPU_BUF_DRAINING = 2,  /* FORW transition: Rx drains ring + pass-through   */
    DPU_BUF_CLOSING  = 3,  /* DROP/DELETE: HW source cut; Rx accepts in-flight */
    DPU_BUF_CLOSED   = 4,  /* Quiesced + drained; Rx rejects; safe to reuse    */
    DPU_BUF_RETIRING = 5,  /* FORW: override removed, HW fast path live, SW
                            * path still accepts late in-flight DMA packets;
                            * the Rx lcore closes the slot itself once it
                            * observes old-path quiescence (or immediately on
                            * discard).  Replaces the old 50 µs delay.        */
};

/* ── BDP byte-budget allocator config (passed to dpu_buffer_init) ─────── *
 * All rates are bytes/s.  The wire QoS is kbps; the agent converts once
 * (Bps = kbps * 125) before handing values to the buffer module.          */
typedef struct {
    uint64_t m_op_bytes;            /* hard global byte budget;
                                     * UINT64_MAX = allocator OFF (legacy
                                     * packet-count caps apply).              */
    uint64_t default_seed_rate_Bps; /* cold-start seed for no-QoS flows.      */
    uint32_t t_hold_ms;             /* demand horizon: U_i = rate * T_hold.   */
    uint32_t tick_ms;               /* control-tick interval (recompute).     */
    uint32_t ewma_alpha_pct;        /* EWMA weight, 0..100 (e.g. 30 = 0.3).   */
    uint8_t  measure_demand;        /* 1 = EWMA-measured demand (product);
                                     * 0 = static QoS-seed demand (v1 ablation,
                                     * tick still max-mins, no measurement).   */
} dpu_buf_alloc_cfg_t;

/* ── Per-flow buffer slot ───────────────────────────────────────────── */
typedef struct {
    uint32_t state;                    /* enum dpu_buffer_state (atomic)   */
    uint32_t hw_rule_id;
    uint8_t  direction;                /* HW_DIR_UPLINK / HW_DIR_DOWNLINK */

    struct rte_ring *ring;             /* SPSC lockless ring (or NULL)     */

    /* Quiesce sequence counters (atomic, written by Rx lcore).
     * enq_seq: incremented BEFORE Rx processes a packet for this flow.
     * deq_seq: incremented AFTER Rx finishes (enqueue/drop/free).
     * Quiesce waits for enq_seq == deq_seq to prove no in-flight pkts.
     * Used by CLOSING (DROP/DELETE) path only. */
    uint64_t enq_seq;
    uint64_t deq_seq;

    /* Rx-owned drain signalling (DRAINING state, FORW path).
     * Set to 1 by Rx lcore when ring drain completes (release).
     * Polled by main thread via wait_drain_done (acquire). */
    uint32_t drain_done;               /* atomic: 0=pending, 1=complete   */

    /* DROP/DELETE-while-leaving signal (atomic).  Set by the control
     * thread (begin_close) when the flow is DRAINING or RETIRING: the HW
     * source is already cut, so the Rx lcore — the ring's consumer in
     * those states — frees the backlog instead of reinjecting it and
     * closes the slot itself.  Reset by register_flow on reuse. */
    uint32_t discard;

    /* Statistics (written by Rx lcore, read by main thread for logging) */
    uint64_t enqueued;
    uint64_t dropped;                  /* tail-drop when at per-flow cap  */
    uint64_t drained;
    uint64_t passthrough;              /* pass-through reinjected (DRAINING) */
    uint64_t requeued;                 /* new pkts re-enqueued at ring tail
                                        * during DRAINING (bounded drain)   */
    uint64_t tx_dropped;               /* reinject_burst pkts lost to Tx-burst
                                        * backpressure (freed, not sent)     */

    /* ── BDP byte-budget allocator state ─────────────────────────────── *
     * queued_bytes is touched by both the Rx lcore (enqueue/drain) and the
     * main thread (flush/drain/quiesce) — atomic, like global_count.
     * The remaining fields are written only by the buffer lcore (enqueue
     * site + control tick) and read for stats — plain, like enqueued/dropped. */
    uint64_t queued_bytes;             /* atomic: payload bytes now in ring  */
    uint64_t byte_dropped;             /* bytes dropped (per-flow+global+ring
                                        * -full) — the unmet-demand signal   */
    uint64_t enq_bytes;                /* cumulative enqueued bytes          */
    uint64_t A_i_bytes;                /* enforced byte grant; UINT64_MAX =
                                        * no per-flow cap (legacy / unset)   */
    uint64_t ewma_rate_Bps;            /* smoothed offered-load rate (B/s)   */
    uint32_t ewma_samples;             /* 0 = on cold-start seed;
                                        * >0 = measuring (never reverts)     */
    uint32_t warmup_ticks_left;        /* seed-grace budget (SEED_WARMUP_TICKS) */
    uint64_t U_i_bytes;                /* demand = rate_est * T_hold (or seed) */
    uint64_t last_offered_bytes;       /* snapshot for per-tick offered delta */

    /* ── Observed-retire evidence (RETIRING state, FORW path) ─────────────── *
     * Written by the Rx lcore in Phase 2's RETIRING branch and read by the
     * Rx lcore at end-of-poll (which now also performs the RETIRING→CLOSED
     * transition itself); the *_entry_* floor is written by the control
     * thread in begin_retire (published via the state store-RELEASE).  The
     * floor makes "K epochs + tail_idle" measure from RETIRING entry, not
     * from epoch/tsc 0.  All atomic-relaxed unless noted. */
    uint64_t retire_entry_tsc;         /* TSC at begin_retire (idle floor)     */
    uint64_t retire_entry_epoch;       /* epoch at begin_retire (epoch floor)  */
    uint64_t last_old_path_rx_tsc;     /* stamped at packet observation start  */
    uint64_t last_old_path_done_tsc;   /* stamped after reinject_burst returns */
    uint64_t last_old_path_rx_epoch;   /* ctx->current_rx_poll_epoch snapshot  */
    uint32_t old_path_inflight;        /* +1 at start, -1 at end of per-pkt    */
} dpu_buffer_flow_t;

/* ── Buffer context (single instance on ARM) ────────────────────────── */
typedef struct {
    dpu_buffer_flow_t *flows;          /* heap-allocated [max_flows]      */
    uint32_t          max_flows;
    struct rte_hash  *flow_id_map;     /* hw_rule_id → flows[] index      */
    uint32_t          global_count;    /* atomic: total pkts across flows */

    /* Drain coordination: incremented by begin_drain, decremented by
     * begin_retire or the Rx lcore's DRAINING discard close.  The Rx loop
     * uses this as a fast check to skip the DRAINING flow scan when no
     * drains are active. */
    uint32_t          nr_draining;     /* atomic: count of DRAINING flows */
    uint32_t          nr_buffering;    /* atomic: count of ACTIVE+DRAINING+
                                        * CLOSING slots; bounds the control-
                                        * tick scan when max_flows is large  */

    /* ── Observed-retire bookkeeping (RETIRING flows are kept SEPARATE from
     * nr_buffering: a RETIRING flow has an empty ring and holds no byte grant,
     * so the BDP control tick must ignore it — begin_retire moves the slot out
     * of nr_buffering and into nr_retiring). */
    uint32_t          nr_retiring;     /* atomic: count of RETIRING flows; gates
                                        * the end-of-poll retire scan          */
    uint64_t          current_rx_poll_epoch; /* atomic-relaxed; ++ at the top of
                                        * the Rx outer loop; "K empty epochs"
                                        * fence reference                       */

    /* ── BDP byte-budget allocator (control tick recomputes A_i) ──────── */
    uint64_t          global_bytes;    /* atomic: total payload bytes buffered */
    uint64_t          m_op_bytes;      /* hard byte budget; UINT64_MAX = legacy */
    uint64_t          default_seed_rate_Bps; /* cold-start seed, no-QoS flows  */
    uint32_t          t_hold_ms;       /* demand horizon                       */
    uint32_t          tick_ms;         /* control-tick interval                */
    uint32_t          ewma_alpha_pct;  /* EWMA weight 0..100                   */
    uint8_t           measure_demand;  /* 1 = EWMA (product); 0 = static seed  */
    uint32_t         *mm_scratch;      /* [max_flows] index scratch for max-min
                                        * (buffer-lcore-only; alloc'd at init)  */

    /* DPDK Rx/Tx identifiers.
     *
     * Rx (N6): TO_DPU_ARM_DL RSSes buffered DL packets to N6 Rx queues
     *          0..(rx_nr_queues-1).  The lcore polls those queues.
     *
     * Tx (N3): software GTP-U + PSC encap finalises a wire-form packet,
     *          which is Tx'd on N3.  The N3 EGRESS pipeline (DL_ENCAP →
     *          N3_EGRESS_PASSTHROUGH on fwd_miss) lets the packet escape
     *          to the wire unchanged.  pkt_meta is left at 0 so neither
     *          DL_ENCAP nor any reinject ROOT entry matches. */
    uint16_t          rx_port_id;        /* N6 PF — RSS source for DL BUFF      */
    uint16_t          rx_nr_queues;      /* number of N6 Rx queues to poll      */
    uint16_t          tx_port_id;        /* N3 PF — finalised wire-form egress  */
    uint16_t          tx_queue_id;       /* dedicated Tx queue on N3            */

    /* Back-reference to pipeline for drain reinject */
    dpu_pipeline_ctx_t *pipeline;

    volatile bool     running;
} dpu_buffer_ctx_t;


/* ═══════════════════════════════════════════════════════════════════════
 *  API
 * ═══════════════════════════════════════════════════════════════════════ */

/**
 * Initialise the buffer context.
 *
 * @param ctx           Buffer context (caller-allocated, zero-initialised)
 * @param rx_port_id    DPDK port ID for the N6 PF (Rx side — DL BUFF RSS)
 * @param rx_nr_queues  Number of N6 Rx queues configured for RSS
 * @param tx_port_id    DPDK port ID for the N3 PF (Tx side — SW-encap egress)
 * @param tx_queue_id   Tx queue ID on N3 for finalised wire-form Tx
 * @param pipeline      Back-reference to the pipeline context (for the
 *                      DL-encap-params accessor used during SW encap)
 * @param max_flows     Maximum number of concurrent buffered flows
 * @param alloc_cfg     BDP byte-budget allocator config (see struct).
 * @return  0 on success, -1 on allocation failure
 */
int dpu_buffer_init(dpu_buffer_ctx_t *ctx,
                    uint16_t rx_port_id,
                    uint16_t rx_nr_queues,
                    uint16_t tx_port_id,
                    uint16_t tx_queue_id,
                    dpu_pipeline_ctx_t *pipeline,
                    uint32_t max_flows,
                    const dpu_buf_alloc_cfg_t *alloc_cfg);

/**
 * Register a flow for buffering.  Called BEFORE the HW override is
 * installed (register-first ordering), so the first redirected packet
 * always finds a flow — no onset drop window.
 *
 * A slot still RETIRING from the previous FORW cycle is given a bounded
 * grace (DPU_BUFFER_REGISTER_WAIT_US) for the Rx lcore's asynchronous
 * close to land before the registration is refused.
 *
 * @param ctx          Buffer context
 * @param hw_rule_id   Globally unique rule ID
 * @param direction    HW_DIR_UPLINK or HW_DIR_DOWNLINK
 * @param mbr_dl_Bps   DL MBR in bytes/s (0 if none) — cold-start seed only
 * @param gbr_dl_Bps   DL GBR in bytes/s (0 if none) — cold-start seed only
 * @return             0 = newly registered (rollback_register is valid),
 *                     1 = already ACTIVE (idempotent re-BUFF; never roll back),
 *                    -1 = refused (no slot / slot still draining or closing)
 */
int dpu_buffer_register_flow(dpu_buffer_ctx_t *ctx,
                             uint32_t hw_rule_id,
                             uint8_t direction,
                             uint64_t mbr_dl_Bps,
                             uint64_t gbr_dl_Bps);

/**
 * Roll back a registration made this control-thread turn (ACTIVE → CLOSED).
 *
 * Only valid when register_flow returned 0 (newly registered) AND the HW
 * override was never installed (its add failed) — so no packet for this
 * flow can be in flight.  Flushes the ring defensively and releases the
 * slot's nr_buffering count.  Calling it on a slot that register_flow
 * reported as already ACTIVE (return 1) would tear down a live flow —
 * the caller must gate on register_flow's return value.
 *
 * @return             0 on rollback, -1 if the slot is not ACTIVE
 */
int dpu_buffer_rollback_register(dpu_buffer_ctx_t *ctx,
                                 uint32_t hw_rule_id);

/**
 * Begin Rx-owned drain for a BUFF→FORW transition (ACTIVE → DRAINING).
 *
 * HW must still point to TO_DPU_ARM when this is called.  The Rx lcore
 * will drain old ring packets first, then pass-through reinject new
 * arrivals.  When the ring is empty, the Rx lcore sets drain_done=1.
 *
 * The caller must update DL_ENCAP with new target gNB params (via
 * dpu_pipeline_update_dlencap_only) BEFORE calling this, so drained
 * DL packets get the correct outer header during handover.
 *
 * Call wait_drain_done() after this, THEN switch HW to COLOR_GATE.
 *
 * @param ctx          Buffer context
 * @param hw_rule_id   Globally unique rule ID
 * @return             0 on success, -1 if flow not found or wrong state
 */
int dpu_buffer_begin_drain(dpu_buffer_ctx_t *ctx,
                           uint32_t hw_rule_id);

/**
 * Wait for the Rx lcore to complete the ring drain (spins on drain_done).
 *
 * Returns once drain_done==1 (set by Rx lcore) or on timeout.
 * On success, the ring is guaranteed empty and the caller can safely
 * switch HW to COLOR_GATE.
 *
 * @param ctx          Buffer context
 * @param hw_rule_id   Globally unique rule ID
 * @return             0 on success, -1 on timeout (flow stays DRAINING)
 */
int dpu_buffer_wait_drain_done(dpu_buffer_ctx_t *ctx,
                               uint32_t hw_rule_id);

/**
 * Transition a drained flow DRAINING → RETIRING (FORW path).
 *
 * Called by the control thread AFTER dpu_pipeline_update_far(FORW) has
 * removed the override entry and AFTER dpu_pipeline_set_mode(FAST).
 * Requires drain_done==1 and an empty ring (both asserted).  Stamps the
 * retire-entry floor, resets all retire-evidence fields, then publishes
 * state=RETIRING and moves the slot out of nr_buffering/nr_draining into
 * nr_retiring.  This is the control thread's LAST involvement in the FORW
 * close: the Rx lcore pass-through reinjects any late in-flight DMA
 * packet and, at end-of-poll, closes the slot itself (RETIRING → CLOSED)
 * once old-path quiescence holds (ring empty, no in-flight, K empty Rx
 * epochs AND tail_idle_us since the later of {RETIRING entry, last
 * old-path packet}).
 *
 * @param ctx          Buffer context
 * @param hw_rule_id   Globally unique rule ID
 * @return             0 on success, -1 if not found / wrong state / not drained
 */
int dpu_buffer_begin_retire(dpu_buffer_ctx_t *ctx,
                            uint32_t hw_rule_id);

/**
 * Begin closing a buffered flow (DROP/DELETE paths; HW source cut FIRST).
 *
 * ACTIVE flows transition to CLOSING and the caller must follow with
 * quiesce_and_drain (synchronous close, return 0).  DRAINING/RETIRING
 * flows get the discard flag instead (return 1): the Rx lcore — the
 * ring's consumer in those states — frees the backlog and closes the
 * slot asynchronously, so the caller must NOT call quiesce_and_drain.
 * This replaces the old behaviour where a DRAINING flow was silently
 * skipped (begin_close returned 0 having done nothing) and then
 * quiesce_and_drain refused it — wedging the slot forever.
 *
 * For BUFF→FORW transitions, use begin_drain + wait_drain_done +
 * begin_retire instead.
 *
 * @param ctx          Buffer context
 * @param hw_rule_id   Globally unique rule ID
 * @return             0 = CLOSING (caller runs quiesce_and_drain) or no-op,
 *                     1 = async discard close requested (Rx lcore owns it)
 */
int dpu_buffer_begin_close(dpu_buffer_ctx_t *ctx,
                           uint32_t hw_rule_id);

/**
 * Quiesce, drain (or discard), and mark a flow CLOSED.
 * Used for DROP/DELETE paths (begin_close → quiesce_and_drain).
 *
 * Spins until the Rx lcore's in-flight sequence counters converge
 * (enq_seq == deq_seq, stability-checked), then drains the ring.
 *
 * If @p discard is false, drained DL packets are SW-encapped and Tx'd
 * on N3 (the same path used for the FORW handover).  If @p discard is
 * true, drained packets are freed (DROP / DELETE).
 *
 * On quiesce timeout (100 ms), returns -1 and leaves the flow in
 * CLOSING state — the caller must NOT free or reuse the flow.
 *
 * @param ctx          Buffer context
 * @param hw_rule_id   Globally unique rule ID
 * @param discard      true = free drained packets; false = SW-encap + Tx
 * @return             Number of packets drained, or -1 on timeout / error
 */
int dpu_buffer_quiesce_and_drain(dpu_buffer_ctx_t *ctx,
                                 uint32_t hw_rule_id,
                                 bool discard);

/**
 * Buffer Rx loop — runs on a dedicated lcore.
 * Receives packets from ARM Rx queues, identifies the flow via pkt_meta,
 * and enqueues into per-flow bounded ring buffers (ACTIVE/CLOSING state).
 *
 * For DRAINING flows (BUFF→FORW), the loop:
 *   Phase 1: drains old ring packets in bounded chunks (no-traffic path)
 *   Phase 2: on per-packet encounter, bounded-drains ≤32 old packets;
 *            if ring still non-empty, re-enqueues new pkt at tail.
 *            Once ring is empty, pass-through reinjects directly.
 *
 * @param arg   Pointer to dpu_buffer_ctx_t
 * @return      0 on exit
 */
int dpu_buffer_rx_loop(void *arg);

/**
 * Signal the buffer loop to stop.
 */
void dpu_buffer_stop(dpu_buffer_ctx_t *ctx);

/**
 * Free all rte_ring objects and flush any remaining packets.
 * Call after dpu_buffer_stop() + rte_eal_wait_lcore().
 */
void dpu_buffer_destroy(dpu_buffer_ctx_t *ctx);

/**
 * Dump per-flow buffer counters and global occupancy.
 * For on-demand debugging (e.g., SIGUSR1).  Skips INACTIVE slots.
 */
void dpu_buffer_dump_stats(const dpu_buffer_ctx_t *ctx);

#ifdef __cplusplus
}
#endif
