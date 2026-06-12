/*
 * dpu_shaper.h — DPU ARM-side token-bucket shaper for GBR YELLOW packets
 *
 * When a GBR flow's trTCM meter marks a packet YELLOW (between GBR and
 * MBR), the SHAPED color-gate pipe forwards it to ARM Rx queues via RSS.
 * This module shapes those YELLOW packets at the Excess Information Rate
 * (EIR = MBR − GBR) using a per-flow token bucket, then finalises the
 * wire-form packet in software and Tx's it on the peer port:
 *
 *   UL YELLOW (Rx N3): SW GTP-U decap → Tx N6 (mirrors HW UL_DECAP).
 *   DL YELLOW (Rx N6): SW GTP-U + PSC encap → Tx N3 (mirrors DL_ENCAP).
 *
 * Both codec paths live in dpu_gtp_codec.{h,c} and are shared with the
 * buffer drain path.  SW finalisation is required because in DOCA Flow
 * VNF mode software-Tx'd packets traverse the EGRESS pipeline of the
 * Tx port and never re-enter the ingress ROOT — so the older "stamp
 * pkt_meta + Tx-on-same-port" reinject pattern is dead.
 *
 * Packets that exceed the token bucket are dropped (they've already
 * exceeded MBR since GREEN consumed GBR and shaped YELLOW consumed EIR).
 *
 * Thread model: shaper_loop runs on a dedicated lcore (Core 2),
 * polling Rx queues 4-7.  Registration/unregistration is called from
 * the Comch callback thread (Core 0), protected by rte_hash atomicity.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

#include <rte_mbuf.h>
#include <rte_hash.h>
#include <rte_ring.h>

#include "dpu_pipeline.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Limits ─────────────────────────────────────────────────────────── */
#define SHAPER_BURST_BYTES   (64 * 1024)   /* max burst: 64 KB per flow   */
#define SHAPER_RX_BURST      32             /* rte_eth_rx_burst batch size */

/* ── Buffered-shaper queue limits (compile-time; m-shape-bytes and
 *    shape-max-delay-ms are the only runtime knobs) ─────────────────── */
/* Per-flow rte_ring capacity (packets).  The per-flow queue is bounded by
 * BOTH q_max_bytes AND this packet count, whichever binds first.  Sized so the
 * byte cap governs for >=~1 KiB packets up to SHAPER_MAX_FLOW_BYTES
 * (16384 * 1500 B = 24 MiB > 16 MiB); for smaller packets the ring depth may
 * bind first (counted as queue_drop_ring). 16384 ptrs = 128 KiB/flow, and
 * rings are created lazily per ACTIVE GBR flow. */
#define SHAPER_RING_DEPTH          16384
#define SHAPER_MIN_FLOW_BYTES      16384  /* per-flow Q cap floor: a small
                                           * minimum burst allowance — NOT a
                                           * strict delay bound for very low
                                           * EIR (the floor governs there).  */
#define SHAPER_MAX_FLOW_BYTES   (16 * 1024 * 1024) /* per-flow Q cap ceiling */
#define SHAPER_DRAIN_FLOWS_PER_ITER  64   /* ready-ring pops per loop iter   */
#define SHAPER_DRAIN_PKTS_PER_FLOW   32   /* drained pkts per flow per visit */

/* ── Per-flow shaper lifecycle state (atomic; replaces the old bool) ──
 * INACTIVE: slot free / cleaned (ring may persist for reuse).
 * ACTIVE:   registered; Rx admits, drain paces.
 * CLOSING:  unregister requested; Rx drops new pkts, lcore frees backlog
 *           and returns the slot to INACTIVE (slot+key persist for reuse;
 *           lcore does NOT del_key — that would race Comch add_key).     */
enum shaper_flow_state {
    SHAPER_FLOW_INACTIVE = 0,
    SHAPER_FLOW_ACTIVE   = 1,
    SHAPER_FLOW_CLOSING  = 2,
};

/* ── Per-flow shaper slot ───────────────────────────────────────────── */
typedef struct {
    /* Cross-lcore synchronisation:
     *   state              — written with RELEASE by Comch thread (ACTIVE on
     *                        register, CLOSING on unregister) and by the
     *                        shaper lcore (INACTIVE after cleanup); read with
     *                        ACQUIRE by the shaper lcore.  Only ACTIVE is
     *                        admittable on the Rx path.
     *   rate_bytes_per_sec — written with RELAXED store by Comch thread,
     *                        read with RELAXED load by shaper lcore.
     *   in_ready           — CAS 0->1 dedupe for ready_ring membership
     *                        (both Comch and lcore may push; lcore pops).
     *   flush_pending      — set by Comch (FAR BUFF / EIR->0 nudge), cleared
     *                        by the lcore after it flushes the backlog.
     * Queue fields (queue/held_pkt/queued_bytes/q_max_bytes) are mutated
     * ONLY by the shaper lcore; queued_bytes/shape_global_bytes are atomic
     * for the dump path. */
    uint32_t state;              /* enum shaper_flow_state (atomic)        */
    uint32_t hw_rule_id;         /* unique rule ID for this flow           */
    uint8_t  direction;          /* HW_DIR_UPLINK / HW_DIR_DOWNLINK       */

    /* Token bucket (byte-based) */
    uint64_t rate_bytes_per_sec; /* EIR = (MBR − GBR), bytes/sec (atomic)  */
    uint64_t tokens;             /* current token count (bytes)            */
    uint64_t max_tokens;         /* = SHAPER_BURST_BYTES                  */
    uint64_t last_refill_tsc;    /* TSC at last refill                    */

    /* Buffered-shaper queue (lcore-owned; ring persists per slot for reuse).
     * held_pkt is the FIFO head kept across drain visits when tokens are
     * insufficient — avoids re-enqueueing the head at the tail. */
    struct rte_ring *queue;      /* per-slot rte_ring "shp_slot_<idx>"     */
    struct rte_mbuf *held_pkt;   /* FIFO head awaiting tokens (or NULL)     */
    uint32_t held_pkt_len;       /* received length of held_pkt            */
    uint32_t in_ready;           /* atomic: 1 = slot present in ready_ring  */
    uint32_t flush_pending;      /* atomic: 1 = drop backlog on next visit  */

    uint64_t queued_bytes;       /* atomic: bytes in queue + held_pkt       */
    uint64_t q_max_bytes;        /* EIR-derived per-flow cap (0 = drop all)  */

    /* Stats — reset on register; update_rate intentionally preserves
     * history.  Single-writer (shaper lcore) so plain ++ is sufficient. */
    uint64_t passed;       /* Tx'd successfully (counted *after* burst)   */
    uint64_t dropped;      /* token bucket said no (legacy/disabled mode)  */
    uint64_t mal_pkt;      /* SW codec rejected (bad GTP / IHL / headroom,
                            * direction mismatch, etc.)                   */
    uint64_t no_encap;     /* DL only: rule has no DL_ENCAP cache entry   */
    uint64_t tx_dropped;   /* rte_eth_tx_burst backpressure / link drops  */

    /* Queue-path counters */
    uint64_t queued_pkts;       /* admitted into the queue                  */
    uint64_t queue_drop_flow;   /* rejected: per-flow q_max_bytes / EIR==0  */
    uint64_t queue_drop_global; /* rejected: global m_shape_bytes           */
    uint64_t queue_drop_ring;   /* rejected: ring enqueue failed            */
    uint64_t flushed;           /* freed by FAR-BUFF / EIR->0 / CLOSING     */
    uint64_t max_queued_bytes_seen;
} shaper_flow_t;

/* ── Shaper context (single instance on ARM, dual-port in VNF mode) ── */
typedef struct {
    shaper_flow_t   *flows;           /* heap-allocated [max_flows]      */
    uint32_t         max_flows;
    struct rte_hash *rule_id_map;     /* hw_rule_id → flows[] index       */

    /* Rx side — symmetric per-port, indexed by direction at poll time. */
    uint16_t         n3_port_id;      /* UL YELLOW Rx (UL_COLOR_GATE_SHAPED) */
    uint16_t         n3_rx_queue_base;
    uint16_t         n3_nr_rx_queues;

    uint16_t         n6_port_id;      /* DL YELLOW Rx (DL_COLOR_GATE_SHAPED) */
    uint16_t         n6_rx_queue_base;
    uint16_t         n6_nr_rx_queues;

    /* Tx side — flipped vs. ingress port:
     *   UL: SW decap output → N6 wire (= n6_port_id, ul_tx_queue_id).
     *   DL: SW encap output → N3 wire (= n3_port_id, dl_tx_queue_id).
     * Tx-port flip is forced by VNF mode: software-Tx'd packets traverse
     * the EGRESS pipeline of the Tx port, never the ingress ROOT, so the
     * wire-form packet must be finalised in software before Tx on the
     * peer port.  See dpu_gtp_codec.{h,c}. */
    uint16_t         ul_tx_port_id;
    uint16_t         ul_tx_queue_id;
    uint16_t         dl_tx_port_id;
    uint16_t         dl_tx_queue_id;

    /* Back-reference for DL_ENCAP per-rule param lookup
     * (dpu_pipeline_get_dl_encap_params) and access to port_cfg
     * (gNB / DN_GW MACs, UPF N3/N6 IPs and MACs) used by the codec. */
    dpu_pipeline_ctx_t *pipeline;

    /* ── Buffered-shaper budget (logically separate from the buffer's
     *    M_op; both draw on the same physical mbuf pool) ──────────────── */
    uint64_t         m_shape_bytes;     /* global queued-byte budget;
                                         * 0 = buffering OFF (legacy
                                         * token-bucket pass/drop policer).   */
    uint32_t         shape_max_delay_ms;/* delay target for q_max_bytes       */
    uint64_t         shape_global_bytes;/* atomic: total queued bytes         */

    /* Ready ring of flow slot indexes with backlog or pending close/flush.
     * MP-enqueue (Comch + lcore), SC-dequeue (lcore).  Sized >= max_flows so
     * enqueue (deduped by flow->in_ready) can never fail. */
    struct rte_ring *ready_ring;

    volatile bool    running;
} shaper_ctx_t;


/* ═══════════════════════════════════════════════════════════════════════
 *  API
 * ═══════════════════════════════════════════════════════════════════════ */

/**
 * Initialise the shaper context and create the rte_hash lookup table.
 * VNF mode: the shaper polls Rx queues on BOTH physical PFs and Tx's
 * SW-finalised packets on the OTHER port (UL: Rx N3 → Tx N6;
 * DL: Rx N6 → Tx N3).
 *
 * @param ctx                Shaper context (caller-allocated, zero-initialised)
 * @param n3_port_id         DPDK ethdev ID for N3 (UL shaping Rx side)
 * @param n3_rx_queue_base   First shaper Rx queue on N3
 * @param n3_nr_rx_queues    Number of shaper Rx queues on N3
 * @param n6_port_id         DPDK ethdev ID for N6 (DL shaping Rx side)
 * @param n6_rx_queue_base   First shaper Rx queue on N6
 * @param n6_nr_rx_queues    Number of shaper Rx queues on N6
 * @param ul_tx_port_id      Tx port for UL SW-decap output (= N6)
 * @param ul_tx_queue_id     Tx queue id on @p ul_tx_port_id
 * @param dl_tx_port_id      Tx port for DL SW-encap output (= N3)
 * @param dl_tx_queue_id     Tx queue id on @p dl_tx_port_id
 * @param pipeline           Back-ref to the pipeline context (for the
 *                           DL-encap-params accessor and port_cfg)
 * @param max_flows          Maximum number of concurrent shaped flows
 * @param m_shape_bytes      Global queued-byte budget; 0 disables buffering
 *                           (legacy token-bucket pass/drop policer)
 * @param shape_max_delay_ms Delay target used to derive per-flow q_max_bytes
 * @return  0 on success, -1 on allocation failure
 */
int shaper_init(shaper_ctx_t *ctx,
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
                uint32_t shape_max_delay_ms);

/**
 * Register a GBR flow for shaping.
 *
 * @param ctx           Shaper context
 * @param hw_rule_id    Globally unique rule ID
 * @param direction     HW_DIR_UPLINK or HW_DIR_DOWNLINK
 * @param gbr_kbps      Guaranteed Bit Rate (kbps)
 * @param mbr_kbps      Maximum Bit Rate (kbps)
 * @return              0 on success, -1 on failure (table full / hash error)
 */
int shaper_register_flow(shaper_ctx_t *ctx,
                         uint32_t hw_rule_id,
                         uint8_t direction,
                         uint64_t gbr_kbps,
                         uint64_t mbr_kbps);

/**
 * Unregister a flow from the shaper (called on rule delete or GBR→0).
 *
 * @param ctx           Shaper context
 * @param hw_rule_id    Globally unique rule ID
 */
void shaper_unregister_flow(shaper_ctx_t *ctx,
                            uint32_t hw_rule_id);

/**
 * Update shaping rate for an existing flow (called on QER update).
 *
 * @param ctx           Shaper context
 * @param hw_rule_id    Globally unique rule ID
 * @param gbr_kbps      New GBR (kbps)
 * @param mbr_kbps      New MBR (kbps)
 * @return              0 on success, -1 if flow not found
 */
int shaper_update_rate(shaper_ctx_t *ctx,
                       uint32_t hw_rule_id,
                       uint64_t gbr_kbps,
                       uint64_t mbr_kbps);

/**
 * Request the shaper lcore to drop any queued backlog for a flow, keeping
 * the flow ACTIVE.  Used when a DL GBR flow enters FAR BUFF: future packets
 * are intercepted by the PFCP-BUFF override, so the stale shaper backlog must
 * not keep draining to the wire ("FAR BUFF overrides shaper backlog").  Safe
 * to call for a non-registered or non-GBR flow (no-op).  The actual mbuf
 * frees happen on the shaper lcore, never on the caller's thread.
 *
 * @param ctx           Shaper context
 * @param hw_rule_id    Globally unique rule ID
 */
void shaper_request_flush(shaper_ctx_t *ctx,
                          uint32_t hw_rule_id);

/**
 * Shaper Rx/Tx loop — runs on a dedicated lcore.
 * Polls shaper Rx queues, identifies flows via pkt_meta, applies
 * per-flow token bucket, and reinjects conforming packets via Tx.
 *
 * @param arg   Pointer to shaper_ctx_t
 * @return      0 on exit
 */
int shaper_loop(void *arg);

/**
 * Signal the shaper loop to stop.
 */
void shaper_stop(shaper_ctx_t *ctx);

/**
 * Destroy shaper context and free rte_hash.
 */
void shaper_destroy(shaper_ctx_t *ctx);

/**
 * Dump per-flow shaper counters and token-bucket state.  Used by both
 * the SIGUSR1 dispatcher (live status) and shaper_destroy (final state),
 * so the two paths share one format.
 */
void shaper_dump_stats(const shaper_ctx_t *ctx);

#ifdef __cplusplus
}
#endif
