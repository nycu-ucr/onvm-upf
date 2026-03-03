/*
 * dpu_pipeline.h — DOCA Flow pipeline for DPU Agent (switch,hws mode)
 *
 * 7-pipe hierarchy on BlueField-3:
 *   ROOT           → control pipe (is_root=true), steers by port+protocol
 *   UL_MATCH       → basic pipe: TEID + QFI + inner_src_ip (rest IGNORED)
 *                     inline GTP decap + L2 inject + set pkt_meta + meter
 *   DL_MATCH       → basic pipe: outer_dst_ip = UE IP (rest IGNORED)
 *                     set pkt_meta + meter
 *   UL_COLOR_GATE  → basic pipe: GREEN|YELLOW → FWD out N6, RED → DROP
 *   DL_COLOR_GATE  → basic pipe: GREEN|YELLOW → FWD out N3, RED → DROP
 *   DL_ENCAP       → basic pipe (EGRESS root, is_root=true): match pkt_meta → GTP encap
 *   TO_HOST        → basic pipe: catch-all → FWD to Host VF representor
 *
 * Build order: TO_HOST → UL_COLOR_GATE → DL_COLOR_GATE →
 *              UL_MATCH → DL_MATCH → DL_ENCAP → ROOT
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

#include <doca_flow.h>
#include <doca_dev.h>
#include <doca_error.h>

#include "hw_offload_msg.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Port configuration ─────────────────────────────────────────────── */
#define DPU_MAX_PORTS  8

typedef struct {
    uint16_t  n3_port_id;       /* physical port facing gNBs (uplink)     */
    uint16_t  n6_port_id;       /* physical port facing DN   (downlink)   */
    uint16_t  host_vf_port_id;  /* host VF representor for SW fallback    */

    /* MAC addresses for L2 injection during UL decap */
    uint8_t   upf_n6_mac[6];   /* UPF's N6 interface MAC (src in decap)  */
    uint8_t   dn_gw_mac[6];    /* DN gateway MAC          (dst in decap) */

    /* MAC for DL GTP encap (outer header) */
    uint8_t   upf_n3_mac[6];   /* UPF's N3 interface MAC (outer src)     */
    uint8_t   gnb_mac[6];      /* gNB MAC                (outer dst)     */

    /* UPF N3 IP for GTP encap (NBO) */
    uint32_t  upf_n3_ip;       /* struct in_addr.s_addr equivalent       */
} dpu_port_cfg_t;

/* ── Pipeline context ───────────────────────────────────────────────── */
typedef struct {
    /* DOCA Flow ports */
    struct doca_flow_port *ports[DPU_MAX_PORTS];
    struct doca_flow_port *switch_port;  /* switch manager port (switch,hws) */
    uint16_t              nb_ports;

    /* Pipe handles */
    struct doca_flow_pipe *root_pipe;
    struct doca_flow_pipe *ul_match_pipe;
    struct doca_flow_pipe *dl_match_pipe;
    struct doca_flow_pipe *ul_color_gate_pipe;
    struct doca_flow_pipe *dl_color_gate_pipe;
    struct doca_flow_pipe *dl_encap_pipe;
    struct doca_flow_pipe *to_host_pipe;

    /* Port configuration */
    dpu_port_cfg_t         port_cfg;

    /* Entry tracking */
    uint32_t               nb_entries;

} dpu_pipeline_ctx_t;


/* ═══════════════════════════════════════════════════════════════════════
 *  API
 * ═══════════════════════════════════════════════════════════════════════ */

/**
 * Initialise DOCA Flow in switch,hws mode and create the 7-pipe hierarchy.
 *
 * @param ctx       Pipeline context (caller-allocated, zero-initialised)
 * @param port_cfg  Port configuration (port IDs, MACs, IPs)
 * @return          DOCA_SUCCESS on success
 */
doca_error_t dpu_pipeline_init(dpu_pipeline_ctx_t *ctx,
                               const dpu_port_cfg_t *port_cfg);

/**
 * Insert a PDR rule into the pipeline based on an hw_offload_msg.
 * Selects UL_MATCH or DL_MATCH based on msg->direction, creates
 * the meter, inserts the match entry, and (for DL) the encap entry.
 *
 * @param ctx  Pipeline context
 * @param msg  Hardware offload message (from Host Agent via Comch)
 * @return     DOCA_SUCCESS on success
 */
doca_error_t dpu_pipeline_insert_rule(dpu_pipeline_ctx_t *ctx,
                                       const hw_offload_msg_t *msg);

/**
 * Tear down all pipes and ports. Called at shutdown.
 */
void dpu_pipeline_destroy(dpu_pipeline_ctx_t *ctx);

#ifdef __cplusplus
}
#endif
