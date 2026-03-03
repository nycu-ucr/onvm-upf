/*
 * dpu_pipeline.c — DOCA Flow 7-pipe switch,hws pipeline on BlueField-3
 *
 * Implements the Split-Agent DPU-side data plane for ICNP offload:
 *   - Multi-granularity wildcard pipes (IGNORED for don't-care fields)
 *   - trTCM RFC 2698 metering (CIR=GBR, PIR=MBR)
 *   - Color-gate enforcement (GREEN+YELLOW pass, RED drops)
 *   - Inline GTP decap + L2 injection for uplink
 *   - pkt_meta-based GTP encap for downlink
 *   - Batched entry insertion (DOCA_FLOW_WAIT_FOR_BATCH)
 *
 * Devargs: dv_flow_en=2,fdb_def_rule_en=0,vport_match=1,
 *          repr_matching_en=0,dv_xmeta_en=4
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <arpa/inet.h>

#include <doca_flow.h>
#include <doca_log.h>

#include "dpu_pipeline.h"

DOCA_LOG_REGISTER(DPU_PIPELINE);

/* ── GTP-U constants ────────────────────────────────────────────────── */
#define GTP_UDP_PORT   2152
#define GTP_V1_FLAGS   0x30   /* Version 1, PT=1 */
#define GTP_MSG_GPDU   0xFF   /* G-PDU message type */

/* ── Batch size for DOCA_FLOW_WAIT_FOR_BATCH ────────────────────────── */
#define BATCH_SIZE     16

/* ── Pipe entry callback (minimal) ──────────────────────────────────── */
static void
entry_process_cb(struct doca_flow_pipe_entry *entry,
                 uint16_t pipe_queue,
                 enum doca_flow_entry_status status,
                 enum doca_flow_entry_op op,
                 void *user_ctx)
{
    (void)entry;
    (void)pipe_queue;
    (void)user_ctx;
    if (status != DOCA_FLOW_ENTRY_STATUS_SUCCESS)
        DOCA_LOG_ERR("Entry op=%d failed with status=%d", op, status);
}


/* ═══════════════════════════════════════════════════════════════════════
 *  DOCA Flow Initialisation
 * ═══════════════════════════════════════════════════════════════════════ */

static doca_error_t
init_doca_flow(void)
{
    struct doca_flow_cfg *cfg;
    doca_error_t result;

    result = doca_flow_cfg_create(&cfg);
    if (result != DOCA_SUCCESS) return result;

    doca_flow_cfg_set_pipe_queues(cfg, 1);  /* single queue for control */
    doca_flow_cfg_set_nr_counters(cfg, 4096);
    doca_flow_cfg_set_nr_meters(cfg, 4096);
    doca_flow_cfg_set_mode_args(cfg, "switch,hws");
    doca_flow_cfg_set_cb_entry_process(cfg, entry_process_cb);
    doca_flow_cfg_set_nr_shared_resource(cfg,
                                          DOCA_FLOW_SHARED_RESOURCE_METER,
                                          4096);

    result = doca_flow_init(cfg);
    doca_flow_cfg_destroy(cfg);
    return result;
}


/* ═══════════════════════════════════════════════════════════════════════
 *  Port creation
 * ═══════════════════════════════════════════════════════════════════════ */

static doca_error_t
create_port(uint16_t port_id, struct doca_flow_port **port)
{
    struct doca_flow_port_cfg *port_cfg;
    doca_error_t result;

    result = doca_flow_port_cfg_create(&port_cfg);
    if (result != DOCA_SUCCESS) return result;

    doca_flow_port_cfg_set_port_id(port_cfg, port_id);

    /* devargs (dv_flow_en=2,...) are passed via EAL -a flag, not here */

    /* Per-port resource allocation for meters */
    result = doca_flow_port_cfg_set_nr_resources(port_cfg,
        DOCA_FLOW_RESOURCE_METER, 4096);
    if (result != DOCA_SUCCESS) {
        doca_flow_port_cfg_destroy(port_cfg);
        return result;
    }

    result = doca_flow_port_start(port_cfg, port);
    doca_flow_port_cfg_destroy(port_cfg);
    return result;
}


/* ═══════════════════════════════════════════════════════════════════════
 *  Pipe builders
 * ═══════════════════════════════════════════════════════════════════════ */

/* ── 7. TO_HOST pipe: catch-all → forward to Host VF representor ──── */
static doca_error_t
build_to_host_pipe(dpu_pipeline_ctx_t *ctx)
{
    doca_error_t result;
    struct doca_flow_pipe_cfg *pipe_cfg;

    result = doca_flow_pipe_cfg_create(&pipe_cfg, ctx->ports[0]);
    if (result != DOCA_SUCCESS) return result;

    doca_flow_pipe_cfg_set_name(pipe_cfg, "TO_HOST");
    doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);
    doca_flow_pipe_cfg_set_is_root(pipe_cfg, false);
    doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 1);

    /* No match — catch-all */
    struct doca_flow_match match = {};

    /* Action: forward to host VF representor port */
    struct doca_flow_fwd fwd = {
        .type = DOCA_FLOW_FWD_PORT,
        .port_id = ctx->port_cfg.host_vf_port_id,
    };

    doca_flow_pipe_cfg_set_match(pipe_cfg, &match, NULL);

    struct doca_flow_actions actions = {};
    struct doca_flow_actions *actions_arr[] = { &actions };
    doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL, NULL, 1);

    result = doca_flow_pipe_create(pipe_cfg, &fwd, NULL, &ctx->to_host_pipe);
    doca_flow_pipe_cfg_destroy(pipe_cfg);
    if (result != DOCA_SUCCESS) return result;

    /* Insert the single catch-all entry */
    struct doca_flow_pipe_entry *entry;
    result = doca_flow_pipe_add_entry(0, ctx->to_host_pipe,
                                       &match, 0, &actions, NULL, &fwd,
                                       0, NULL, &entry);
    if (result != DOCA_SUCCESS)
        DOCA_LOG_ERR("TO_HOST entry insert failed");

    doca_flow_entries_process(ctx->ports[0], 0, 0, 0);
    return result;
}


/* ── 4/5. Color-gate pipes (shared logic for UL and DL) ───────────── */
static doca_error_t
build_color_gate_pipe(dpu_pipeline_ctx_t *ctx,
                      const char *name,
                      uint16_t fwd_port_id,
                      struct doca_flow_pipe **pipe_out)
{
    doca_error_t result;
    struct doca_flow_pipe_cfg *pipe_cfg;

    result = doca_flow_pipe_cfg_create(&pipe_cfg, ctx->ports[0]);
    if (result != DOCA_SUCCESS) return result;

    doca_flow_pipe_cfg_set_name(pipe_cfg, name);
    doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);
    doca_flow_pipe_cfg_set_is_root(pipe_cfg, false);
    doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 4);

    /* Match on meter color (CHANGEABLE) */
    struct doca_flow_match match = {};
    match.parser_meta.meter_color = UINT32_MAX;  /* changeable sentinel */

    struct doca_flow_match mask = {};
    mask.parser_meta.meter_color = UINT32_MAX;

    doca_flow_pipe_cfg_set_match(pipe_cfg, &match, &mask);

    struct doca_flow_actions actions = {};
    struct doca_flow_actions *actions_arr[] = { &actions };
    doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL, NULL, 1);

    /* Hit → forward to output port */
    struct doca_flow_fwd fwd = {
        .type = DOCA_FLOW_FWD_PORT,
        .port_id = fwd_port_id,
    };

    /* Miss → DROP (RED packets) */
    struct doca_flow_fwd fwd_miss = {
        .type = DOCA_FLOW_FWD_DROP,
    };

    result = doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_miss, pipe_out);
    doca_flow_pipe_cfg_destroy(pipe_cfg);
    if (result != DOCA_SUCCESS) return result;

    /* Insert GREEN and YELLOW entries — both forward through */
    struct doca_flow_pipe_entry *entry;
    struct doca_flow_match green_match = {};
    green_match.parser_meta.meter_color = DOCA_FLOW_METER_COLOR_GREEN;

    result = doca_flow_pipe_add_entry(0, *pipe_out,
                                       &green_match, 0, &actions, NULL, &fwd,
                                       0, NULL, &entry);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("%s: GREEN entry failed", name);
        return result;
    }

    struct doca_flow_match yellow_match = {};
    yellow_match.parser_meta.meter_color = DOCA_FLOW_METER_COLOR_YELLOW;

    result = doca_flow_pipe_add_entry(0, *pipe_out,
                                       &yellow_match, 0, &actions, NULL, &fwd,
                                       0, NULL, &entry);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("%s: YELLOW entry failed", name);
        return result;
    }

    doca_flow_entries_process(ctx->ports[0], 0, 0, 0);

    DOCA_LOG_INFO("%s: GREEN+YELLOW→fwd, RED→drop", name);
    return DOCA_SUCCESS;
}


/* ── 2. UL_MATCH pipe ─────────────────────────────────────────────── */
static doca_error_t
build_ul_match_pipe(dpu_pipeline_ctx_t *ctx)
{
    doca_error_t result;
    struct doca_flow_pipe_cfg *pipe_cfg;

    result = doca_flow_pipe_cfg_create(&pipe_cfg, ctx->ports[0]);
    if (result != DOCA_SUCCESS) return result;

    doca_flow_pipe_cfg_set_name(pipe_cfg, "UL_MATCH");
    doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);
    doca_flow_pipe_cfg_set_is_root(pipe_cfg, false);
    doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 2048);

    /* Match template:
     *   CHANGEABLE: GTP TEID, GTP-ext QFI, inner IPv4 src
     *   IGNORED:    inner dst_ip, proto, ports (pipe mask = 0) */
    struct doca_flow_match match = {};
    match.tun.type = DOCA_FLOW_TUN_GTPU;
    match.tun.gtp_teid = UINT32_MAX;        /* changeable sentinel */
    match.tun.gtp_ext_psc_qfi = UINT8_MAX;  /* changeable */
    match.inner.l3_type = DOCA_FLOW_L3_TYPE_IP4;
    match.inner.ip4.src_ip = UINT32_MAX;     /* changeable */
    /* inner.ip4.dst_ip = 0, inner proto = 0, ports = 0 → IGNORED */

    struct doca_flow_match mask = {};
    mask.tun.type = DOCA_FLOW_TUN_GTPU;
    mask.tun.gtp_teid = UINT32_MAX;
    mask.tun.gtp_ext_psc_qfi = UINT8_MAX;
    mask.inner.l3_type = DOCA_FLOW_L3_TYPE_IP4;
    mask.inner.ip4.src_ip = UINT32_MAX;

    doca_flow_pipe_cfg_set_match(pipe_cfg, &match, &mask);

    /* Action template:
     *   - Decap GTP tunnel (inline)
     *   - Inject L2 header (src=UPF N6 MAC, dst=DN gateway MAC)
     *   - Set pkt_meta = hw_rule_id */
    struct doca_flow_actions actions = {};
    actions.decap_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
    actions.decap_cfg.is_l2 = false;   /* decap GTP, not L2 tunnel */
    actions.has_encap = true;          /* inject new L2 after decap */

    /* L2 injection: Ethernet header for post-decap packet */
    memcpy(actions.encap_cfg.encap.outer.eth.src_mac,
           ctx->port_cfg.upf_n6_mac, 6);
    memcpy(actions.encap_cfg.encap.outer.eth.dst_mac,
           ctx->port_cfg.dn_gw_mac, 6);
    actions.encap_cfg.encap.outer.eth.type = RTE_BE16(0x0800);  /* IPv4 */

    /* pkt_meta = UINT32_MAX → changeable per-entry */
    actions.meta.pkt_meta = UINT32_MAX;

    struct doca_flow_actions *actions_arr[] = { &actions };
    doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL, NULL, 1);

    /* Monitor: meter (will be set per-entry as shared resource) */
    struct doca_flow_monitor monitor = {};
    monitor.meter_type = DOCA_FLOW_RESOURCE_TYPE_SHARED;

    doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor);

    /* Hit → UL_COLOR_GATE */
    struct doca_flow_fwd fwd = {
        .type = DOCA_FLOW_FWD_PIPE,
        .next_pipe = ctx->ul_color_gate_pipe,
    };

    /* Miss → TO_HOST (software fallback) */
    struct doca_flow_fwd fwd_miss = {
        .type = DOCA_FLOW_FWD_PIPE,
        .next_pipe = ctx->to_host_pipe,
    };

    result = doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_miss,
                                    &ctx->ul_match_pipe);
    doca_flow_pipe_cfg_destroy(pipe_cfg);

    if (result != DOCA_SUCCESS)
        DOCA_LOG_ERR("UL_MATCH pipe creation failed: %s",
                     doca_error_get_descr(result));
    return result;
}


/* ── 3. DL_MATCH pipe ─────────────────────────────────────────────── */
static doca_error_t
build_dl_match_pipe(dpu_pipeline_ctx_t *ctx)
{
    doca_error_t result;
    struct doca_flow_pipe_cfg *pipe_cfg;

    result = doca_flow_pipe_cfg_create(&pipe_cfg, ctx->ports[0]);
    if (result != DOCA_SUCCESS) return result;

    doca_flow_pipe_cfg_set_name(pipe_cfg, "DL_MATCH");
    doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);
    doca_flow_pipe_cfg_set_is_root(pipe_cfg, false);
    doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 2048);

    /* Match template:
     *   CHANGEABLE: outer IPv4 dst (= UE IP)
     *   IGNORED:    src_ip, proto, ports */
    struct doca_flow_match match = {};
    match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
    match.outer.ip4.dst_ip = UINT32_MAX;   /* changeable sentinel */
    /* outer.ip4.src_ip = 0, proto = 0, ports = 0 → IGNORED */

    struct doca_flow_match mask = {};
    mask.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
    mask.outer.ip4.dst_ip = UINT32_MAX;

    doca_flow_pipe_cfg_set_match(pipe_cfg, &match, &mask);

    /* Action: set pkt_meta = hw_rule_id (changeable) */
    struct doca_flow_actions actions = {};
    actions.meta.pkt_meta = UINT32_MAX;

    struct doca_flow_actions *actions_arr[] = { &actions };
    doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL, NULL, 1);

    /* Monitor: shared meter */
    struct doca_flow_monitor monitor = {};
    monitor.meter_type = DOCA_FLOW_RESOURCE_TYPE_SHARED;

    doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor);

    /* Hit → DL_COLOR_GATE */
    struct doca_flow_fwd fwd = {
        .type = DOCA_FLOW_FWD_PIPE,
        .next_pipe = ctx->dl_color_gate_pipe,
    };

    /* Miss → TO_HOST */
    struct doca_flow_fwd fwd_miss = {
        .type = DOCA_FLOW_FWD_PIPE,
        .next_pipe = ctx->to_host_pipe,
    };

    result = doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_miss,
                                    &ctx->dl_match_pipe);
    doca_flow_pipe_cfg_destroy(pipe_cfg);

    if (result != DOCA_SUCCESS)
        DOCA_LOG_ERR("DL_MATCH pipe creation failed: %s",
                     doca_error_get_descr(result));
    return result;
}


/* ── 6. DL_ENCAP pipe (EGRESS on N3 port) ─────────────────────────── */
static doca_error_t
build_dl_encap_pipe(dpu_pipeline_ctx_t *ctx)
{
    doca_error_t result;
    struct doca_flow_pipe_cfg *pipe_cfg;

    result = doca_flow_pipe_cfg_create(&pipe_cfg, ctx->ports[0]);
    if (result != DOCA_SUCCESS) return result;

    doca_flow_pipe_cfg_set_name(pipe_cfg, "DL_ENCAP");
    doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);
    doca_flow_pipe_cfg_set_is_root(pipe_cfg, false);
    doca_flow_pipe_cfg_set_domain(pipe_cfg, DOCA_FLOW_PIPE_DOMAIN_EGRESS);
    doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 2048);

    /* Match: pkt_meta = hw_rule_id (changeable) */
    struct doca_flow_match match = {};
    match.meta.pkt_meta = UINT32_MAX;

    struct doca_flow_match mask = {};
    mask.meta.pkt_meta = UINT32_MAX;

    doca_flow_pipe_cfg_set_match(pipe_cfg, &match, &mask);

    /* Action: GTP-U encapsulation
     * Template with changeable outer dest-IP and TEID.
     * The encap template builds: Eth | IPv4 | UDP:2152 | GTP | ext(QFI) */
    struct doca_flow_actions actions = {};
    actions.has_encap = true;
    actions.encap_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;

    /* Outer Ethernet */
    memcpy(actions.encap_cfg.encap.outer.eth.src_mac,
           ctx->port_cfg.upf_n3_mac, 6);
    memcpy(actions.encap_cfg.encap.outer.eth.dst_mac,
           ctx->port_cfg.gnb_mac, 6);
    actions.encap_cfg.encap.outer.eth.type = RTE_BE16(0x0800);

    /* Outer IPv4: src = UPF N3 IP (fixed), dst = gNB IP (changeable) */
    actions.encap_cfg.encap.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
    actions.encap_cfg.encap.outer.ip4.src_ip = ctx->port_cfg.upf_n3_ip;
    actions.encap_cfg.encap.outer.ip4.dst_ip = UINT32_MAX;  /* changeable */
    actions.encap_cfg.encap.outer.ip4.ttl = 64;

    /* Outer UDP */
    actions.encap_cfg.encap.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
    actions.encap_cfg.encap.outer.udp.l4_port.dst_port = RTE_BE16(GTP_UDP_PORT);

    /* GTP-U tunnel */
    actions.encap_cfg.encap.tun.type = DOCA_FLOW_TUN_GTPU;
    actions.encap_cfg.encap.tun.gtp_teid = UINT32_MAX;      /* changeable */
    actions.encap_cfg.encap.tun.gtp_ext_psc_qfi = UINT8_MAX; /* changeable */

    struct doca_flow_actions *actions_arr[] = { &actions };
    doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL, NULL, 1);

    /* Forward: out the pipe (packet egresses on N3) */
    struct doca_flow_fwd fwd = {
        .type = DOCA_FLOW_FWD_PORT,
        .port_id = ctx->port_cfg.n3_port_id,
    };

    /* Miss → TO_HOST (shouldn't happen if pkt_meta is set correctly) */
    struct doca_flow_fwd fwd_miss = {
        .type = DOCA_FLOW_FWD_PIPE,
        .next_pipe = ctx->to_host_pipe,
    };

    result = doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_miss,
                                    &ctx->dl_encap_pipe);
    doca_flow_pipe_cfg_destroy(pipe_cfg);

    if (result != DOCA_SUCCESS)
        DOCA_LOG_ERR("DL_ENCAP pipe creation failed: %s",
                     doca_error_get_descr(result));
    return result;
}


/* ── 1. ROOT control pipe ─────────────────────────────────────────── */
static doca_error_t
build_root_pipe(dpu_pipeline_ctx_t *ctx)
{
    doca_error_t result;
    struct doca_flow_pipe_cfg *pipe_cfg;

    result = doca_flow_pipe_cfg_create(&pipe_cfg, ctx->ports[0]);
    if (result != DOCA_SUCCESS) return result;

    doca_flow_pipe_cfg_set_name(pipe_cfg, "ROOT");
    doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_CONTROL);
    doca_flow_pipe_cfg_set_is_root(pipe_cfg, true);

    /* Miss → TO_HOST */
    struct doca_flow_fwd fwd_miss = {
        .type = DOCA_FLOW_FWD_PIPE,
        .next_pipe = ctx->to_host_pipe,
    };

    result = doca_flow_pipe_create(pipe_cfg, NULL, &fwd_miss,
                                    &ctx->root_pipe);
    doca_flow_pipe_cfg_destroy(pipe_cfg);
    if (result != DOCA_SUCCESS) return result;

    /* Priority 0: GTP-U traffic from N3 → UL_MATCH */
    {
        struct doca_flow_match match = {};
        match.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
        match.outer.udp.l4_port.dst_port = RTE_BE16(GTP_UDP_PORT);

        struct doca_flow_match mask = {};
        mask.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
        mask.outer.udp.l4_port.dst_port = UINT16_MAX;

        struct doca_flow_fwd fwd = {
            .type = DOCA_FLOW_FWD_PIPE,
            .next_pipe = ctx->ul_match_pipe,
        };

        struct doca_flow_pipe_entry *entry;
        result = doca_flow_pipe_control_add_entry(0, 0, ctx->root_pipe,
                                                   &match, &mask,
                                                   NULL, NULL, NULL, NULL,
                                                   NULL, &fwd, NULL, &entry);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("ROOT: UL control entry failed");
            return result;
        }
    }

    /* Priority 1: Non-GTP traffic from N6 → DL_MATCH
     * (matches all traffic not caught by priority 0) */
    {
        struct doca_flow_match match = {};
        /* Match any IPv4 traffic (non-GTP) */
        match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;

        struct doca_flow_match mask = {};
        mask.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;

        struct doca_flow_fwd fwd = {
            .type = DOCA_FLOW_FWD_PIPE,
            .next_pipe = ctx->dl_match_pipe,
        };

        struct doca_flow_pipe_entry *entry;
        result = doca_flow_pipe_control_add_entry(0, 1, ctx->root_pipe,
                                                   &match, &mask,
                                                   NULL, NULL, NULL, NULL,
                                                   NULL, &fwd, NULL, &entry);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("ROOT: DL control entry failed");
            return result;
        }
    }

    doca_flow_entries_process(ctx->ports[0], 0, 0, 0);

    DOCA_LOG_INFO("ROOT pipe: prio0→UL_MATCH, prio1→DL_MATCH, miss→TO_HOST");
    return DOCA_SUCCESS;
}


/* ═══════════════════════════════════════════════════════════════════════
 *  Meter creation helper (trTCM RFC 2698)
 * ═══════════════════════════════════════════════════════════════════════ */

/**
 * Create a shared trTCM meter with CIR=GBR, PIR=MBR (both in kbps).
 * Uses port-level shared resource APIs matching upf_doca_pipeline pattern.
 * RFC 2698 (trTCM): CIR=GBR (committed/guaranteed), PIR=MBR (peak/max).
 * PIR must be >= CIR.  Packets exceeding PIR → RED, between CIR..PIR → YELLOW.
 *
 * @param port      DOCA Flow port
 * @param meter_id  [out] Allocated shared meter ID
 * @param gbr_kbps  Guaranteed Bit Rate (kbps) — maps to CIR
 * @param mbr_kbps  Maximum Bit Rate (kbps) — maps to PIR (must be >= gbr)
 * @return          DOCA_SUCCESS on success
 */
static doca_error_t
create_trtcm_meter(struct doca_flow_port *port,
                   uint32_t *meter_id,
                   uint64_t gbr_kbps,
                   uint64_t mbr_kbps)
{
    doca_error_t result;

    /* Convert kbps to bytes/sec for DOCA Flow */
    uint64_t cir_bps = gbr_kbps * 1000 / 8;   /* CIR = GBR in bytes/sec */
    uint64_t pir_bps = mbr_kbps * 1000 / 8;   /* PIR = MBR in bytes/sec */

    /* PIR must be >= CIR per RFC 2698 */
    if (pir_bps < cir_bps)
        pir_bps = cir_bps;

    /* If both are 0, create a permissive meter (minimal rate) */
    if (pir_bps == 0) {
        pir_bps = 1;
        cir_bps = 1;
    }

    struct doca_flow_shared_resource_cfg cfg = {};
    cfg.meter_cfg.limit_type = DOCA_FLOW_METER_LIMIT_TYPE_BYTES;
    cfg.meter_cfg.color_mode = DOCA_FLOW_METER_COLOR_MODE_BLIND;
    cfg.meter_cfg.alg = DOCA_FLOW_METER_ALGORITHM_TYPE_RFC2698;
    cfg.meter_cfg.cir = cir_bps;
    cfg.meter_cfg.cbs = (cir_bps / 100 > 4096) ? cir_bps / 100 : 4096;
    cfg.meter_cfg.pir = pir_bps;
    cfg.meter_cfg.pbs = (pir_bps / 100 > 4096) ? pir_bps / 100 : 4096;

    /* Allocate a meter ID from the port */
    result = doca_flow_port_shared_resource_get(port,
                                                 DOCA_FLOW_SHARED_RESOURCE_METER,
                                                 meter_id);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Meter alloc failed: %s", doca_error_get_descr(result));
        return result;
    }

    /* Configure the allocated meter */
    result = doca_flow_port_shared_resource_set_cfg(port,
                                                     DOCA_FLOW_SHARED_RESOURCE_METER,
                                                     *meter_id, &cfg);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Meter %u config failed: %s",
                     *meter_id, doca_error_get_descr(result));
    }
    return result;
}


/* ═══════════════════════════════════════════════════════════════════════
 *  Public API: Initialise the pipeline
 * ═══════════════════════════════════════════════════════════════════════ */

doca_error_t
dpu_pipeline_init(dpu_pipeline_ctx_t *ctx, const dpu_port_cfg_t *port_cfg)
{
    doca_error_t result;

    memset(ctx, 0, sizeof(*ctx));
    ctx->port_cfg = *port_cfg;

    /* Init DOCA Flow */
    result = init_doca_flow();
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("DOCA Flow init failed: %s", doca_error_get_descr(result));
        return result;
    }

    /* Create ports */
    result = create_port(port_cfg->n3_port_id, &ctx->ports[0]);
    if (result != DOCA_SUCCESS) return result;

    result = create_port(port_cfg->n6_port_id, &ctx->ports[1]);
    if (result != DOCA_SUCCESS) return result;

    result = create_port(port_cfg->host_vf_port_id, &ctx->ports[2]);
    if (result != DOCA_SUCCESS) return result;

    ctx->nb_ports = 3;

    /* Pair N3 and N6 ports for hairpin */
    result = doca_flow_port_pair(ctx->ports[0], ctx->ports[1]);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Port pair failed: %s", doca_error_get_descr(result));
        return result;
    }

    /* Build pipes in dependency order */
    DOCA_LOG_INFO("Building 7-pipe hierarchy...");

    result = build_to_host_pipe(ctx);
    if (result != DOCA_SUCCESS) return result;

    result = build_color_gate_pipe(ctx, "UL_COLOR_GATE",
                                    port_cfg->n6_port_id,
                                    &ctx->ul_color_gate_pipe);
    if (result != DOCA_SUCCESS) return result;

    result = build_color_gate_pipe(ctx, "DL_COLOR_GATE",
                                    port_cfg->n3_port_id,
                                    &ctx->dl_color_gate_pipe);
    if (result != DOCA_SUCCESS) return result;

    result = build_ul_match_pipe(ctx);
    if (result != DOCA_SUCCESS) return result;

    result = build_dl_match_pipe(ctx);
    if (result != DOCA_SUCCESS) return result;

    result = build_dl_encap_pipe(ctx);
    if (result != DOCA_SUCCESS) return result;

    result = build_root_pipe(ctx);
    if (result != DOCA_SUCCESS) return result;

    DOCA_LOG_INFO("Pipeline initialised: 7 pipes, %u ports", ctx->nb_ports);
    return DOCA_SUCCESS;
}


/* ═══════════════════════════════════════════════════════════════════════
 *  Public API: Insert a rule from hw_offload_msg
 * ═══════════════════════════════════════════════════════════════════════ */

doca_error_t
dpu_pipeline_insert_rule(dpu_pipeline_ctx_t *ctx, const hw_offload_msg_t *msg)
{
    doca_error_t result;

    if (!msg || msg->magic != HW_OFFLOAD_MAGIC) {
        DOCA_LOG_ERR("insert_rule: invalid message");
        return DOCA_ERROR_INVALID_VALUE;
    }

    if (msg->direction == HW_DIR_UPLINK) {
        /* ── UPLINK: TEID + QFI + inner_src_ip ───────────────────────── */

        /* Create trTCM meter: CIR=GBR_UL, PIR=MBR_UL */
        uint32_t meter_id;
        result = create_trtcm_meter(ctx->ports[0], &meter_id,
                                     msg->gbr_ul, msg->mbr_ul);
        if (result != DOCA_SUCCESS) return result;

        /* Build entry match — convert HOST order to NBO for DOCA Flow */
        struct doca_flow_match match = {};
        match.tun.type = DOCA_FLOW_TUN_GTPU;
        match.tun.gtp_teid = htonl(msg->teid);            /* HOST → NBO */
        match.tun.gtp_ext_psc_qfi = msg->qfi;
        match.inner.l3_type = DOCA_FLOW_L3_TYPE_IP4;
        /* inner.ip4.src_ip: UE IP is NBO in the msg (struct in_addr) */
        match.inner.ip4.src_ip = msg->ue_ipv4.s_addr;     /* already NBO */

        /* Actions: decap + L2 inject configured at pipe level,
         * only pkt_meta varies per entry */
        struct doca_flow_actions actions = {};
        actions.meta.pkt_meta = msg->hw_rule_id;

        /* Monitor: attach shared meter */
        struct doca_flow_monitor monitor = {};
        monitor.meter_type = DOCA_FLOW_RESOURCE_TYPE_SHARED;
        monitor.shared_meter.shared_meter_id = meter_id;

        struct doca_flow_pipe_entry *entry;
        result = doca_flow_pipe_add_entry(0, ctx->ul_match_pipe,
                                           &match, 0, &actions,
                                           &monitor, NULL,
                                           0, NULL, &entry);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("UL entry insert failed for hw_rule_id=%u: %s",
                         msg->hw_rule_id, doca_error_get_descr(result));
            return result;
        }

        doca_flow_entries_process(ctx->ports[0], 0, 0, 0);

        DOCA_LOG_INFO("UL rule inserted: hw_rule_id=%u teid=0x%x qfi=%u",
                      msg->hw_rule_id, msg->teid, msg->qfi);

    } else {
        /* ── DOWNLINK: outer_dst_ip (= UE IP) ───────────────────────── */

        /* Create trTCM meter: CIR=GBR_DL, PIR=MBR_DL */
        uint32_t meter_id;
        result = create_trtcm_meter(ctx->ports[0], &meter_id,
                                     msg->gbr_dl, msg->mbr_dl);
        if (result != DOCA_SUCCESS) return result;

        /* DL_MATCH entry: match on UE IP (already NBO) */
        struct doca_flow_match dl_match = {};
        dl_match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
        dl_match.outer.ip4.dst_ip = msg->ue_ipv4.s_addr;  /* NBO */

        struct doca_flow_actions dl_actions = {};
        dl_actions.meta.pkt_meta = msg->hw_rule_id;

        struct doca_flow_monitor dl_monitor = {};
        dl_monitor.meter_type = DOCA_FLOW_RESOURCE_TYPE_SHARED;
        dl_monitor.shared_meter.shared_meter_id = meter_id;

        struct doca_flow_pipe_entry *dl_entry;
        result = doca_flow_pipe_add_entry(0, ctx->dl_match_pipe,
                                           &dl_match, 0, &dl_actions,
                                           &dl_monitor, NULL,
                                           0, NULL, &dl_entry);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("DL_MATCH entry failed for hw_rule_id=%u: %s",
                         msg->hw_rule_id, doca_error_get_descr(result));
            return result;
        }

        /* DL_ENCAP entry: match pkt_meta → GTP encap */
        if (msg->ohc_desc == HW_OHC_GTPU_UDP_IPV4) {
            struct doca_flow_match encap_match = {};
            encap_match.meta.pkt_meta = msg->hw_rule_id;

            struct doca_flow_actions encap_actions = {};
            encap_actions.has_encap = true;
            encap_actions.encap_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;

            /* Outer: use MACs from port config (set at pipe level),
             * vary dst_ip and TEID per entry */
            encap_actions.encap_cfg.encap.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
            encap_actions.encap_cfg.encap.outer.ip4.dst_ip =
                msg->ohc_ipv4.s_addr;                       /* NBO */
            encap_actions.encap_cfg.encap.outer.ip4.src_ip =
                ctx->port_cfg.upf_n3_ip;                    /* NBO */
            encap_actions.encap_cfg.encap.outer.ip4.ttl = 64;

            encap_actions.encap_cfg.encap.outer.l4_type_ext =
                DOCA_FLOW_L4_TYPE_EXT_UDP;
            encap_actions.encap_cfg.encap.outer.udp.l4_port.dst_port =
                RTE_BE16(GTP_UDP_PORT);

            encap_actions.encap_cfg.encap.tun.type = DOCA_FLOW_TUN_GTPU;
            encap_actions.encap_cfg.encap.tun.gtp_teid =
                htonl(msg->ohc_teid);                       /* HOST → NBO */

            /* QFI in GTP extension — from QER, not PDI match QFI */
            encap_actions.encap_cfg.encap.tun.gtp_ext_psc_qfi = msg->encap_qfi;

            struct doca_flow_pipe_entry *encap_entry;
            result = doca_flow_pipe_add_entry(0, ctx->dl_encap_pipe,
                                               &encap_match, 0, &encap_actions,
                                               NULL, NULL,
                                               0, NULL, &encap_entry);
            if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("DL_ENCAP entry failed for hw_rule_id=%u: %s",
                             msg->hw_rule_id, doca_error_get_descr(result));
                return result;
            }
        }

        doca_flow_entries_process(ctx->ports[0], 0, 0, 0);

        DOCA_LOG_INFO("DL rule inserted: hw_rule_id=%u ue_ip=%08x "
                      "ohc_teid=0x%x",
                      msg->hw_rule_id, msg->ue_ipv4.s_addr, msg->ohc_teid);
    }

    ctx->nb_entries++;
    return DOCA_SUCCESS;
}


/* ═══════════════════════════════════════════════════════════════════════
 *  Public API: Teardown
 * ═══════════════════════════════════════════════════════════════════════ */

void
dpu_pipeline_destroy(dpu_pipeline_ctx_t *ctx)
{
    /* Destroy pipes (reverse build order) */
    if (ctx->root_pipe)
        doca_flow_pipe_destroy(ctx->root_pipe);
    if (ctx->dl_encap_pipe)
        doca_flow_pipe_destroy(ctx->dl_encap_pipe);
    if (ctx->dl_match_pipe)
        doca_flow_pipe_destroy(ctx->dl_match_pipe);
    if (ctx->ul_match_pipe)
        doca_flow_pipe_destroy(ctx->ul_match_pipe);
    if (ctx->dl_color_gate_pipe)
        doca_flow_pipe_destroy(ctx->dl_color_gate_pipe);
    if (ctx->ul_color_gate_pipe)
        doca_flow_pipe_destroy(ctx->ul_color_gate_pipe);
    if (ctx->to_host_pipe)
        doca_flow_pipe_destroy(ctx->to_host_pipe);

    /* Stop and destroy ports */
    for (int i = 0; i < ctx->nb_ports; i++) {
        if (ctx->ports[i])
            doca_flow_port_stop(ctx->ports[i]);
    }

    doca_flow_destroy();

    DOCA_LOG_INFO("Pipeline destroyed (%u entries were active)",
                  ctx->nb_entries);
}
