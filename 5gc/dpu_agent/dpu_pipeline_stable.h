/*
 * dpu_pipeline.h — DOCA Flow pipeline for DPU Agent (vnf,hws mode)
 *
 * Up to 17-pipe hierarchy on BlueField-3 with priority-bucketed matching.
 * VNF mode: each port owns its ingress pipes; cross-port forwarding via
 * doca_flow_port_pair().
 *
 * Per-port pipe ownership:
 *
 *   N3 port (port_id=0):
 *     [DEFAULT — ingress]
 *     N3_ROOT              → control pipe (is_root=true), steers UL traffic
 *     UL_MATCH[0..3]       → basic pipes: TEID + inner src_ip
 *     UL_COLOR_GATE_POLICED → GREEN+YELLOW → FWD_PIPE(UL_DECAP), RED → DROP
 *     UL_COLOR_GATE_SHAPED  → GREEN → FWD_PIPE(UL_DECAP), YELLOW → RSS ARM
 *     UL_DECAP             → GTP decap + L2 inject → FWD_PORT(N6) via pair
 *     L2L3_RX_N3           → ARP from N3 → RSS to responder
 *     [EGRESS]
 *     DL_ENCAP             → egress_root: pkt_meta → GTP encap + PSC →
 *                            FWD_PORT(N3 wire).  GTP encap MUST live in
 *                            EGRESS — DEFAULT-domain encap on this HW
 *                            does NOT finalise GTP/UDP length fields.
 *                            Cross-port + cross-domain ingress→egress_root
 *                            forwards from N6 DEFAULT pipes are allowed.
 *     N3_EGRESS_PASSTHROUGH → DL_ENCAP's fwd_miss target.  Matches every
 *                            packet, FWD_PORT(N3 wire).  Lets non-DL Tx
 *                            on N3 (ARP responder, mgmt) escape unchanged.
 *
 *   N6 port (port_id=1, all DEFAULT domain):
 *     N6_ROOT              → control pipe (is_root=true), steers DL traffic
 *     DL_MATCH[0..3]       → basic pipes: outer dst_ip (UE IP)
 *     DL_COLOR_GATE_POLICED → GREEN+YELLOW → FWD_PIPE(DL_ENCAP@N3), RED → DROP
 *     DL_COLOR_GATE_SHAPED  → GREEN → FWD_PIPE(DL_ENCAP@N3), YELLOW → RSS ARM
 *     TO_DPU_ARM_DL        → RSS to ARM Rx queues (DL buffering)
 *     L2L3_RX_N6           → ARP from N6 → RSS to responder
 *
 * Cross-port forwarding for DL is FWD_PIPE from N6 DEFAULT-ingress pipes
 * into N3's egress_root (DL_ENCAP).  UL uses FWD_PORT via doca_flow_port_pair
 * (UL_DECAP → N6 wire) — DEFAULT-domain decap does work correctly on this HW.
 *
 * Precedence: 3GPP precedence mapped to 4 priority buckets (lower = higher prio).
 *   UL_MATCH[0].miss → UL_MATCH[1] → ... → UL_MATCH[3].miss → DROP (VNF miss → RSS)
 *   Same for DL_MATCH.
 *
 * Per-entry match_mask wildcards unused SDF fields for catch-all PDRs.
 *
 * Build order:
 *   N6 DEFAULT: TO_DPU_ARM_DL → L2L3_RX_N6 → DL POLICED gate
 *               → DL SHAPED gate → DL_MATCH[3..0] → N6_ROOT
 *   N3 DEFAULT: L2L3_RX_N3 → UL_DECAP → UL POLICED gate
 *               → UL SHAPED gate → UL_MATCH[3..0] → N3_ROOT
 *   N3 EGRESS:  N3_EGRESS_PASSTHROUGH → DL_ENCAP   (passthrough first
 *               so DL_ENCAP can reference its handle in fwd_miss)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <rte_hash.h>

#include <doca_dev.h>
#include <doca_error.h>
#include <doca_flow.h>

#include "hw_offload_msg.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Port configuration ─────────────────────────────────────────────── */
#define DPU_MAX_PORTS 2       /* N3 + N6 only (VNF mode, no representor) */
#define DPU_PORT_ID_N3 0      /* DOCA Flow port ID for N3 (first probed) */
#define DPU_PORT_ID_N6 1      /* DOCA Flow port ID for N6 (second probed) */
#define NUM_PRIO_BUCKETS 4    /* priority-bucketed match pipes          */
#define PRIO_BUCKET_RANGE 64  /* 3GPP precedence per bucket             */

/* ── ARM buffer / reinject metadata markers (two-bit scheme) ─────────── */
/*
 * Reinject packets get two marker bits in pkt_meta bits 0-1.
 *
 *   Bit 0 (REINJECT_MARKER_BIT) — set on ALL reinject packets.
 *   Bit 1 (REINJECT_UL_DIR_BIT) — set only on UL reinject.
 *
 * The drain path ALWAYS clears bits 0-1 of htonl(hw_rule_id) before
 * OR'ing the markers, so direction detection works regardless of
 * hw_rule_id magnitude.  (htonl puts input bits 24-25 into output
 * bits 0-1; for hw_rule_id ≥ 0x02000000 those bits are non-zero.)
 *
 *   UL drain: pkt_meta = (htonl(hw_rule_id) & ~0x03) | 0x03
 *   DL drain: pkt_meta = (htonl(hw_rule_id) & ~0x03) | 0x01
 *
 * VNF mode ROOT entries (per-port, no port_id matching needed):
 *   N3_ROOT prio 2: pkt_meta & REINJECT_BITS_MASK == 0x03 → UL_DECAP
 *   N6_ROOT prio 2: pkt_meta & REINJECT_BITS_MASK == 0x01 → DL_ENCAP
 *
 * Normal wire traffic arrives with pkt_meta == 0 at ROOT ingress,
 * so bits 0-1 == 00 and neither entry matches.
 *
 * DL_ENCAP pipe mask ignores bits 0-1 (~REINJECT_BITS_MASK) so that
 * both normal DL and DL-reinject packets match the same encap entry.
 *
 * CONSTRAINT: insert_rule rejects hw_rule_ids where
 * htonl(hw_rule_id) & REINJECT_BITS_MASK != 0, preventing DL_ENCAP
 * aliasing between two rules that differ only in bits 24-25.
 */
#define REINJECT_MARKER_BIT 0x00000001u /* bit 0: marks all reinject pkts */
#define REINJECT_UL_DIR_BIT 0x00000002u /* bit 1: UL direction flag       */
#define REINJECT_BITS_MASK 0x00000003u  /* mask for reinject bits 0-1     */

/* ── ARP responder reinject markers (bits 2-3 of pkt_meta) ─────────
 *
 * Orthogonal to REINJECT_* bits 0-1 (which belong to buffer drain).
 * Normal wire-ingress packets have pkt_meta == 0 at ROOT, so bits 0-3
 * are 0000 and neither responder entry matches.
 *
 * Responder Tx path (writes a literal constant — bits 0-1 are always
 * 0 in responder-originated packets):
 *   ARP reply via N3: pkt_meta = RESPONDER_MARKER_BIT           (0x04)
 *   ARP reply via N6: pkt_meta = RESPONDER_MARKER_BIT |
 *                                RESPONDER_N6_BIT               (0x0C)
 *
 * Per-port ROOT entries match a 4-bit window (bits 0-3):
 *   N3_ROOT prio 4: pkt_meta & 0x0F == 0x04 → FWD_PORT N3 wire (port 0)
 *   N6_ROOT prio 4: pkt_meta & 0x0F == 0x0C → FWD_PORT N6 wire (port 1)
 *
 * In VNF mode, FWD_PORT to the same port (port_id == self) sends
 * the packet out the port's own wire interface.
 */
#define RESPONDER_MARKER_BIT 0x00000004u /* bit 2: marks responder reinject */
#define RESPONDER_N6_BIT 0x00000008u     /* bit 3: 0=N3, 1=N6 egress        */
#define RESPONDER_BITS_MASK 0x0000000Fu  /* mask bits 0-3: forces 0-1 == 0  */

/* ── ARM buffer Rx/Tx configuration (DL buffering on N6 port) ────────── */
#define BUFFER_RX_QUEUES 4 /* RSS queues for DL buffered traffic (N6) */
#define BUFFER_TX_QUEUES 1 /* TX queue for DL buffer reinject (N6)    */
/*
 * Pool must cover: Rx ring descriptors (TOTAL_N6_RX_QUEUES * 512)
 * + DPU_BUFFER_GLOBAL_CAP (16384) + shaper in-flight + headroom.
 * 32767 = next power-of-two minus 1 (DPDK convention).
 */
#define BUFFER_NB_MBUFS 32767 /* packet buffer pool size             */
#define BUFFER_MBUF_CACHE 256 /* per-core cache for mbuf pool        */

/* ── ARM shaper Rx/Tx configuration (GBR YELLOW traffic) ─────────────── */
#define SHAPER_RX_QUEUES 4   /* RSS queues for shaped YELLOW traffic */
#define SHAPER_TX_QUEUES 1   /* TX queue for shaper reinject         */

/* ── ARP responder Rx/Tx configuration ──────────────────────────────── */
#define RESPONDER_RX_QUEUES 1   /* RSS queue(s) for responder traffic  */
#define RESPONDER_TX_QUEUES 1   /* TX queue for responder reinject     */

/* ── Per-port queue layout (VNF mode) ────────────────────────────────
 *
 * N3 port (UL ingress — no DL buffering here):
 *   Rx 0..3  = UL shaper Rx queues (YELLOW from UL_COLOR_GATE_SHAPED)
 *   Rx 4     = ARP responder Rx queue (N3 ARP)
 *   Tx 0     = UL shaper reinject Tx
 *   Tx 1     = N3 ARP responder reinject Tx
 *
 * N6 port (DL ingress — DL buffering + DL shaping here):
 *   Rx 0..3  = DL buffer Rx queues (from TO_DPU_ARM_DL)
 *   Rx 4..7  = DL shaper Rx queues (YELLOW from DL_COLOR_GATE_SHAPED)
 *   Rx 8     = ARP responder Rx queue (N6 ARP)
 *   Tx 0     = DL buffer reinject Tx
 *   Tx 1     = DL shaper reinject Tx
 *   Tx 2     = N6 ARP responder reinject Tx
 *
 * All queues must be configured before doca_flow_port_start().
 */
#define N3_RX_QUEUES (SHAPER_RX_QUEUES + RESPONDER_RX_QUEUES)  /* 5 */
#define N3_TX_QUEUES (SHAPER_TX_QUEUES + RESPONDER_TX_QUEUES)   /* 2 */

#define N6_RX_QUEUES (BUFFER_RX_QUEUES + SHAPER_RX_QUEUES + RESPONDER_RX_QUEUES)  /* 9 */
#define N6_TX_QUEUES (BUFFER_TX_QUEUES + SHAPER_TX_QUEUES + RESPONDER_TX_QUEUES)   /* 3 */

/* N3 port Tx queue indices */
#define N3_SHAPER_TX_QUEUE_ID    0
#define N3_RESPONDER_TX_QUEUE_ID 1

/* N6 port Tx queue indices */
#define N6_BUFFER_TX_QUEUE_ID    0
#define N6_SHAPER_TX_QUEUE_ID    1
#define N6_RESPONDER_TX_QUEUE_ID 2

/* ── Per-rule mode (for future buffering) ───────────────────────────── */
enum dpu_rule_mode {
        DPU_MODE_FAST = 0,   /* Normal wire-speed forwarding via COLOR_GATE */
        DPU_MODE_BUFFER = 1, /* Packets redirected to ARM for buffering     */
};

/* ── Per-rule entry-handle record ───────────────────────────────────── */
typedef struct {
        bool in_use;
        uint32_t hw_rule_id;

        struct doca_flow_pipe_entry *ul_entry;       /* UL_MATCH entry (or NULL)  */
        struct doca_flow_pipe_entry *dl_entry;       /* DL_MATCH entry (or NULL)  */
        struct doca_flow_pipe_entry *dl_encap_entry; /* DL_ENCAP entry (or NULL)  */

        uint8_t pipe_bucket;  /* which UL/DL_MATCH[0..3] bucket             */
        uint8_t direction;    /* HW_DIR_UPLINK / HW_DIR_DOWNLINK            */
        uint8_t current_mode; /* enum dpu_rule_mode                         */
        bool is_gbr_flow;     /* true if GBR > 0 (uses SHAPED color gate)   */
        uint32_t meter_id;    /* shared meter ID (for QER updates)          */
} dpu_rule_record_t;

typedef struct {
        uint16_t n3_port_id;      /* DOCA Flow port ID for N3 (always 0)   */
        uint16_t n6_port_id;      /* DOCA Flow port ID for N6 (always 1)   */

        /* DOCA devices — required by doca_flow_port_cfg_set_dev() */
        struct doca_dev *n3_dev;          /* device for N3 port                */
        struct doca_dev *n6_dev;          /* device for N6 port                */

        /* MAC addresses for L2 injection during UL decap */
        uint8_t upf_n6_mac[6]; /* UPF's N6 interface MAC (src in decap)  */
        uint8_t dn_gw_mac[6];  /* DN gateway MAC          (dst in decap) */

        /* MAC for DL GTP encap (outer header) */
        uint8_t upf_n3_mac[6]; /* UPF's N3 interface MAC (outer src)     */
        uint8_t gnb_mac[6];    /* gNB MAC                (outer dst)     */

        /* UPF N3 IP for GTP encap (NBO) */
        uint32_t upf_n3_ip; /* struct in_addr.s_addr equivalent       */

        /* UPF N6 IP for the ARP responder (NBO; 0 disables N6 side).
         * Used by the responder lcore to answer ARP "who-has upf_n6_ip"
         * and to gate the N6 ARP ROOT classifier. */
        uint32_t upf_n6_ip;
} dpu_port_cfg_t;

/* ── Pipeline context ───────────────────────────────────────────────── */
typedef struct {
        /* DOCA Flow ports (VNF mode — direct PF ports, no switch manager) */
        struct doca_flow_port *n3_port;  /* N3 port (port_id=0) */
        struct doca_flow_port *n6_port;  /* N6 port (port_id=1) */

        /* Pipe handles — per-port ownership in VNF mode */
        struct doca_flow_pipe *n3_root_pipe;  /* N3 ingress ROOT (control, is_root) */
        struct doca_flow_pipe *n6_root_pipe;  /* N6 ingress ROOT (control, is_root) */

        struct doca_flow_pipe *ul_match_pipes[NUM_PRIO_BUCKETS];  /* on N3 */
        struct doca_flow_pipe *dl_match_pipes[NUM_PRIO_BUCKETS];  /* on N6 */

        struct doca_flow_pipe *ul_color_gate_policed_pipe; /* on N3: GREEN+YELLOW → wire */
        struct doca_flow_pipe *dl_color_gate_policed_pipe; /* on N6 */
        struct doca_flow_pipe *ul_color_gate_shaped_pipe;  /* on N3: GREEN → wire, YELLOW → ARM RSS */
        struct doca_flow_pipe *dl_color_gate_shaped_pipe;  /* on N6 */

        struct doca_flow_pipe *ul_decap_pipe;     /* on N3 (DEFAULT): GTP decap + L2 → FWD_PORT(N6) */
        struct doca_flow_pipe *dl_encap_pipe;     /* on N3 (EGRESS, root): pkt_meta → GTP encap → FWD_PORT(N3 wire) */
        struct doca_flow_pipe *n3_egress_passthrough_pipe; /* on N3 (EGRESS, non-root): catch-all → FWD_PORT(N3 wire).
                                                            * Acts as DL_ENCAP's fwd_miss target so that non-DL Tx on
                                                            * N3 (ARP responder replies, mgmt frames) still escapes
                                                            * to the wire instead of being dropped. */

        struct doca_flow_pipe *to_dpu_arm_dl_pipe; /* on N6: RSS → ARM Rx (DL buffering) */

        struct doca_flow_pipe *l2l3_rx_n3_pipe;  /* on N3: ARP → RSS to responder */
        struct doca_flow_pipe *l2l3_rx_n6_pipe;  /* on N6: ARP → RSS to responder */

        /* Diagnostic entry handles — used by dpu_pipeline_dump_stats to
         * query per-entry hit counters without walking the rule hash. */
        struct doca_flow_pipe_entry *ul_decap_entry;
        struct doca_flow_pipe_entry *dl_encap_catchall_entry;
        /* prio-5 wire-ingress ARP classifiers (only populated when the ARP
         * responder is enabled). */
        struct doca_flow_pipe_entry *root_arp_n3_entry;
        struct doca_flow_pipe_entry *root_arp_n6_entry;

        /* Port configuration */
        dpu_port_cfg_t port_cfg;

        /* ── Per-port RSS config (populated during init) ─────────────── */

        /* N6 DL buffer RSS (TO_DPU_ARM_DL pipe target) */
        uint16_t n6_buffer_rss_queues[BUFFER_RX_QUEUES];
        uint32_t nr_n6_buffer_rss_queues;

        /* N3 UL shaper RSS (UL_COLOR_GATE_SHAPED YELLOW target) */
        uint16_t n3_shaper_rss_queues[SHAPER_RX_QUEUES];
        uint32_t nr_n3_shaper_rss_queues;

        /* N6 DL shaper RSS (DL_COLOR_GATE_SHAPED YELLOW target) */
        uint16_t n6_shaper_rss_queues[SHAPER_RX_QUEUES];
        uint32_t nr_n6_shaper_rss_queues;

        /* N3 ARP responder RSS */
        uint16_t n3_responder_rss_queues[RESPONDER_RX_QUEUES];
        uint32_t nr_n3_responder_rss_queues;

        /* N6 ARP responder RSS */
        uint16_t n6_responder_rss_queues[RESPONDER_RX_QUEUES];
        uint32_t nr_n6_responder_rss_queues;

        /* Entry tracking */
        uint32_t nb_entries;
        uint32_t max_hw_rules;
        dpu_rule_record_t *rules;     /* heap-allocated [max_hw_rules] */
        struct rte_hash *rule_id_map; /* hw_rule_id → rules[] index    */

        /* DOCA Flow capacity knobs (from JSON config) */
        uint32_t nr_counters;
        uint32_t nr_meters;
        uint32_t nr_shared_meters;
        uint32_t port_nr_encap;
        uint32_t port_nr_decap;
        uint32_t port_nr_meter;
        uint32_t port_actions_mem;
        uint32_t match_entries_per_bucket;
        uint32_t dl_encap_entries;

} dpu_pipeline_ctx_t;

/* ═══════════════════════════════════════════════════════════════════════
 *  API
 * ═══════════════════════════════════════════════════════════════════════ */

/**
 * Phase 1: Init DOCA Flow in VNF mode, create N3+N6 ports, pair them.
 * After this returns, the caller MUST have already configured DPDK Rx/Tx
 * queues on BOTH N3 and N6 ethdevs before calling dpu_pipeline_build_pipes().
 *
 * @param ctx                           Pipeline context (caller-allocated, zero-initialised)
 * @param port_cfg                      Port configuration (port IDs, MACs, IPs)
 * @param n6_buffer_rss_queues          Array of N6 Rx queue indices for TO_DPU_ARM_DL RSS
 *                                      (NULL to disable DL buffering)
 * @param nr_n6_buffer_rss_queues       Number of DL buffer RSS queues (0 to disable)
 * @param n3_shaper_rss_queues          Array of N3 Rx queue indices for UL SHAPED YELLOW RSS
 *                                      (NULL to disable UL shaping)
 * @param nr_n3_shaper_rss_queues       Number of UL shaper RSS queues (0 to disable)
 * @param n6_shaper_rss_queues          Array of N6 Rx queue indices for DL SHAPED YELLOW RSS
 *                                      (NULL to disable DL shaping)
 * @param nr_n6_shaper_rss_queues       Number of DL shaper RSS queues (0 to disable)
 * @param n3_responder_rss_queues       Array of N3 Rx queue indices for N3 ARP responder
 * @param nr_n3_responder_rss_queues    Number of N3 responder RSS queues
 * @param n6_responder_rss_queues       Array of N6 Rx queue indices for N6 ARP responder
 * @param nr_n6_responder_rss_queues    Number of N6 responder RSS queues
 * @return                              DOCA_SUCCESS on success
 */
doca_error_t
dpu_pipeline_create_ports(dpu_pipeline_ctx_t *ctx, const dpu_port_cfg_t *port_cfg,
                          uint16_t *n6_buffer_rss_queues, uint32_t nr_n6_buffer_rss_queues,
                          uint16_t *n3_shaper_rss_queues, uint32_t nr_n3_shaper_rss_queues,
                          uint16_t *n6_shaper_rss_queues, uint32_t nr_n6_shaper_rss_queues,
                          uint16_t *n3_responder_rss_queues, uint32_t nr_n3_responder_rss_queues,
                          uint16_t *n6_responder_rss_queues, uint32_t nr_n6_responder_rss_queues);

/**
 * Phase 2: Build the pipe hierarchy on both ports.  Must be called after
 * BOTH N3 and N6 Rx/Tx queues are configured and ports are started.
 *
 * @param ctx  Pipeline context (ports must already be created)
 * @return     DOCA_SUCCESS on success
 */
doca_error_t
dpu_pipeline_build_pipes(dpu_pipeline_ctx_t *ctx);

/**
 * Insert a PDR rule into the pipeline based on an hw_offload_msg.
 * Selects UL_MATCH or DL_MATCH based on msg->direction, creates
 * the meter, inserts the match entry, and (for DL) the encap entry.
 *
 * @param ctx  Pipeline context
 * @param msg  Hardware offload message (from Host Agent via Comch)
 * @return     DOCA_SUCCESS on success
 */
doca_error_t
dpu_pipeline_insert_rule(dpu_pipeline_ctx_t *ctx, const hw_offload_msg_t *msg);

/**
 * Tear down all pipes and ports. Called at shutdown.
 */
void
dpu_pipeline_destroy(dpu_pipeline_ctx_t *ctx);

/**
 * Delete a previously inserted rule by hw_rule_id.
 * Removes all associated DOCA Flow entries (UL/DL/ENCAP) and frees the record.
 */
doca_error_t
dpu_pipeline_delete_rule(dpu_pipeline_ctx_t *ctx, uint32_t hw_rule_id);

/**
 * Update the forwarding action of an existing rule (FAR action change).
 * Uses doca_flow_pipe_update_entry() to change the per-entry fwd target.
 * - BUFF: swaps per-entry fwd from COLOR_GATE → TO_DPU_ARM_DL (if available)
 * - FORW (from BUFFER): swaps per-entry fwd back to COLOR_GATE
 * - DROP: removes the HW rule entirely
 */
doca_error_t
dpu_pipeline_update_far(dpu_pipeline_ctx_t *ctx, const hw_offload_msg_t *msg);

/**
 * Update meter rates for an existing rule (QER rate change).
 * Destroys the old shared meter and creates a new one, then updates the entry.
 */
doca_error_t
dpu_pipeline_update_qer(dpu_pipeline_ctx_t *ctx, const hw_offload_msg_t *msg);

/**
 * Update PDR (match criteria may change).  Implemented as delete + re-create
 * since DOCA Flow does not support updating match fields of an existing entry.
 */
doca_error_t
dpu_pipeline_update_pdr(dpu_pipeline_ctx_t *ctx, const hw_offload_msg_t *msg);

/**
 * Downgrade a GBR flow from shaped to policed color gate.
 * Called when shaper registration fails — YELLOW packets go to wire
 * (slightly over-admitted) instead of being dropped on ARM.
 */
doca_error_t
dpu_pipeline_downgrade_to_policed(dpu_pipeline_ctx_t *ctx, uint32_t hw_rule_id);

/**
 * Update only the DL_ENCAP entry's encapsulation actions (target gNB IP,
 * TEID, QFI) without touching the match entry's fwd target.
 *
 * Must be called BEFORE dpu_buffer_begin_drain() during BUFF→FORW
 * transitions so that drained/reinjected packets hit the new encap
 * parameters.  Safe to call while the match entry still points to
 * TO_DPU_ARM_DL — no fast-path traffic reaches DL_ENCAP for this rule
 * until the fwd is swapped back to COLOR_GATE.
 *
 * No-op for UL rules or if encap params are unchanged.
 *
 * @param ctx  Pipeline context
 * @param msg  Message carrying new OHC params (ohc_ipv4, ohc_teid, encap_qfi)
 * @return     DOCA_SUCCESS, or error if the HW commit fails
 */
doca_error_t
dpu_pipeline_update_dlencap_only(dpu_pipeline_ctx_t *ctx, const hw_offload_msg_t *msg);

/**
 * Set the logical mode (FAST/BUFFER) for a rule record.
 * Used by the caller to update mode at the correct lifecycle point
 * (e.g., after quiesce completes for FORW transitions).
 */
void
dpu_pipeline_set_mode(dpu_pipeline_ctx_t *ctx, uint32_t hw_rule_id, uint8_t mode);

/**
 * Get the current logical mode for a rule record.
 * Returns DPU_MODE_FAST if the rule is not found.
 */
uint8_t
dpu_pipeline_get_mode(const dpu_pipeline_ctx_t *ctx, uint32_t hw_rule_id);

/**
 * Dump per-entry hit counts and per-pipe miss counts.
 * For on-demand debugging (e.g., SIGUSR1).
 */
void
dpu_pipeline_dump_stats(dpu_pipeline_ctx_t *ctx);

#ifdef __cplusplus
}
#endif
