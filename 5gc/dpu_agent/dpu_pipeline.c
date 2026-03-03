/*
 * dpu_pipeline.c — DOCA Flow pipeline on BlueField-3 (switch,hws mode)
 *
 * Implements the Split-Agent DPU-side data plane for ICNP offload:
 *   - Full SDF matching (inner/outer IPs + protocol) with per-entry mask
 *   - 4 priority-bucketed pipes per direction for 3GPP precedence
 *   - trTCM RFC 2698 metering (CIR=GBR, PIR=MBR), skipped when no QER
 *   - Color-gate enforcement (GREEN+YELLOW pass, RED drops)
 *   - Inline GTP decap + L2 injection for uplink
 *   - pkt_meta-based GTP encap for downlink (with PSC extension)
 *
 * 13-pipe hierarchy:
 *   ROOT  → UL_MATCH[0..3] → UL_COLOR_GATE → fwd N6
 *         → DL_MATCH[0..3] → DL_COLOR_GATE → fwd N3 → DL_ENCAP (egress)
 *         → TO_HOST (catch-all)
 *
 * All pipes created on switch manager port (doca_flow_port_switch_get).
 * Devargs passed via EAL -a flag: dv_flow_en=2,fdb_def_rule_en=0,
 *   vport_match=1,repr_matching_en=0,dv_xmeta_en=4
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <arpa/inet.h>

#include <doca_flow.h>
#include <doca_log.h>

#include "dpu_pipeline.h"

DOCA_LOG_REGISTER(DPU_PIPELINE);

/* ── Constants ──────────────────────────────────────────────────────── */
#define GTP_UDP_PORT   2152
#define GTP_EXT_PSC    0x85   /* GTP next-ext-hdr-type for PDU Session Container */
#define NO_METER_ID    UINT32_MAX  /* sentinel: skip metering for this entry */

/* ── Helpers ────────────────────────────────────────────────────────── */

/** Convert prefix length (0-32) to a network-byte-order IPv4 mask. */
static inline uint32_t
prefix_to_netmask(uint8_t prefix_len)
{
    if (prefix_len == 0)  return 0;
    if (prefix_len >= 32) return UINT32_MAX;
    return htonl(~((1u << (32 - prefix_len)) - 1));
}

/** Map 3GPP precedence (lower = higher priority) to bucket index [0..3]. */
static inline int
precedence_to_bucket(uint32_t precedence)
{
    int bucket = (int)(precedence / PRIO_BUCKET_RANGE);
    if (bucket >= NUM_PRIO_BUCKETS)
        bucket = NUM_PRIO_BUCKETS - 1;
    return bucket;
}

/* ── Pipe entry callback ────────────────────────────────────────────── */
static void
entry_process_cb(struct doca_flow_pipe_entry *entry,
                 uint16_t pipe_queue,
                 enum doca_flow_entry_status status,
                 enum doca_flow_entry_op op,
                 void *user_ctx)
{
    (void)entry; (void)pipe_queue; (void)user_ctx;
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

    doca_flow_cfg_set_pipe_queues(cfg, 1);
    doca_flow_cfg_set_nr_counters(cfg, 4096);
    doca_flow_cfg_set_nr_meters(cfg, 4096);
    doca_flow_cfg_set_mode_args(cfg, "switch,hws");
    doca_flow_cfg_set_cb_entry_process(cfg, entry_process_cb);
    doca_flow_cfg_set_nr_shared_resource(cfg, 4096,
                                          DOCA_FLOW_SHARED_RESOURCE_METER);

    result = doca_flow_init(cfg);
    doca_flow_cfg_destroy(cfg);
    return result;
}


/* ═══════════════════════════════════════════════════════════════════════
 *  Port creation — binds logical ID + DOCA device + optional representor
 * ═══════════════════════════════════════════════════════════════════════ */

static doca_error_t
create_port(uint16_t port_id,
            struct doca_dev *dev,
            struct doca_dev_rep *dev_rep,
            struct doca_flow_port **port)
{
    struct doca_flow_port_cfg *port_cfg;
    doca_error_t result;

    result = doca_flow_port_cfg_create(&port_cfg);
    if (result != DOCA_SUCCESS) return result;

    doca_flow_port_cfg_set_port_id(port_cfg, port_id);

    /* Bind DOCA device — provides HW context for the port */
    result = doca_flow_port_cfg_set_dev(port_cfg, dev);
    if (result != DOCA_SUCCESS) {
        doca_flow_port_cfg_destroy(port_cfg);
        return result;
    }

    /* Bind representor if provided (e.g., Host VF) */
    if (dev_rep) {
        result = doca_flow_port_cfg_set_dev_rep(port_cfg, dev_rep);
        if (result != DOCA_SUCCESS) {
            doca_flow_port_cfg_destroy(port_cfg);
            return result;
        }
    }

    /* Per-port meter resources */
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

/* ── TO_HOST: catch-all → forward to Host VF representor ──────────── */
static doca_error_t
build_to_host_pipe(dpu_pipeline_ctx_t *ctx)
{
    doca_error_t result;
    struct doca_flow_pipe_cfg *pipe_cfg;

    result = doca_flow_pipe_cfg_create(&pipe_cfg, ctx->switch_port);
    if (result != DOCA_SUCCESS) return result;

    doca_flow_pipe_cfg_set_name(pipe_cfg, "TO_HOST");
    doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);
    doca_flow_pipe_cfg_set_is_root(pipe_cfg, false);
    doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 1);

    struct doca_flow_match match = {};
    doca_flow_pipe_cfg_set_match(pipe_cfg, &match, NULL);

    struct doca_flow_actions actions = {};
    struct doca_flow_actions *actions_arr[] = { &actions };
    doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL, NULL, 1);

    struct doca_flow_fwd fwd = {
        .type = DOCA_FLOW_FWD_PORT,
        .port_id = ctx->port_cfg.host_vf_port_id,
    };

    result = doca_flow_pipe_create(pipe_cfg, &fwd, NULL, &ctx->to_host_pipe);
    doca_flow_pipe_cfg_destroy(pipe_cfg);
    if (result != DOCA_SUCCESS) return result;

    struct doca_flow_pipe_entry *entry;
    result = doca_flow_pipe_add_entry(0, ctx->to_host_pipe,
                                       &match, 0, &actions, NULL, &fwd,
                                       0, NULL, &entry);
    if (result != DOCA_SUCCESS)
        DOCA_LOG_ERR("TO_HOST entry insert failed");

    doca_flow_entries_process(ctx->switch_port, 0, 0, 0);
    return result;
}


/* ── Color-gate: GREEN|YELLOW → FWD, RED → DROP ──────────────────── */
static doca_error_t
build_color_gate_pipe(dpu_pipeline_ctx_t *ctx,
                      const char *name,
                      uint16_t fwd_port_id,
                      struct doca_flow_pipe **pipe_out)
{
    doca_error_t result;
    struct doca_flow_pipe_cfg *pipe_cfg;

    result = doca_flow_pipe_cfg_create(&pipe_cfg, ctx->switch_port);
    if (result != DOCA_SUCCESS) return result;

    doca_flow_pipe_cfg_set_name(pipe_cfg, name);
    doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);
    doca_flow_pipe_cfg_set_is_root(pipe_cfg, false);
    doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 4);

    struct doca_flow_match match = {};
    match.parser_meta.meter_color = UINT32_MAX;

    struct doca_flow_match mask = {};
    mask.parser_meta.meter_color = UINT32_MAX;

    doca_flow_pipe_cfg_set_match(pipe_cfg, &match, &mask);

    struct doca_flow_actions actions = {};
    struct doca_flow_actions *actions_arr[] = { &actions };
    doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL, NULL, 1);

    struct doca_flow_fwd fwd = {
        .type = DOCA_FLOW_FWD_PORT,
        .port_id = fwd_port_id,
    };
    struct doca_flow_fwd fwd_miss = {
        .type = DOCA_FLOW_FWD_DROP,
    };

    result = doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_miss, pipe_out);
    doca_flow_pipe_cfg_destroy(pipe_cfg);
    if (result != DOCA_SUCCESS) return result;

    /* GREEN and YELLOW entries both forward */
    struct doca_flow_pipe_entry *entry;

    struct doca_flow_match green = {};
    green.parser_meta.meter_color = DOCA_FLOW_METER_COLOR_GREEN;
    result = doca_flow_pipe_add_entry(0, *pipe_out,
                                       &green, 0, &actions, NULL, &fwd,
                                       0, NULL, &entry);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("%s: GREEN entry failed", name);
        return result;
    }

    struct doca_flow_match yellow = {};
    yellow.parser_meta.meter_color = DOCA_FLOW_METER_COLOR_YELLOW;
    result = doca_flow_pipe_add_entry(0, *pipe_out,
                                       &yellow, 0, &actions, NULL, &fwd,
                                       0, NULL, &entry);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("%s: YELLOW entry failed", name);
        return result;
    }

    doca_flow_entries_process(ctx->switch_port, 0, 0, 0);
    DOCA_LOG_INFO("%s: GREEN+YELLOW→fwd, RED→drop", name);
    return DOCA_SUCCESS;
}


/* ── UL_MATCH pipes (4 priority buckets) ──────────────────────────── */
/*
 * Each pipe matches: GTP TEID + QFI + inner 5-tuple (src_ip, dst_ip,
 * proto, src_port, dst_port).  Per-entry match_mask wildcards unused
 * SDF fields for catch-all PDRs.
 * Actions: GTP decap + L2 inject + pkt_meta + shared meter.
 * Chain: P0.miss → P1 → P2 → P3.miss → TO_HOST.
 */
static doca_error_t
build_ul_match_pipes(dpu_pipeline_ctx_t *ctx)
{
    doca_error_t result;

    /* Build from lowest priority (P3) up to highest (P0) */
    for (int p = NUM_PRIO_BUCKETS - 1; p >= 0; p--) {
        struct doca_flow_pipe_cfg *pipe_cfg;
        result = doca_flow_pipe_cfg_create(&pipe_cfg, ctx->switch_port);
        if (result != DOCA_SUCCESS) return result;

        char name[32];
        snprintf(name, sizeof(name), "UL_MATCH_P%d", p);
        doca_flow_pipe_cfg_set_name(pipe_cfg, name);
        doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);
        doca_flow_pipe_cfg_set_is_root(pipe_cfg, false);
        doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 2048);

        /* Match: GTP tunnel + inner 5-tuple (all CHANGEABLE) */
        struct doca_flow_match match = {};
        match.tun.type = DOCA_FLOW_TUN_GTPU;
        match.tun.gtp_teid = UINT32_MAX;
        match.tun.gtp_ext_psc_qfi = UINT8_MAX;
        match.inner.l3_type = DOCA_FLOW_L3_TYPE_IP4;
        match.inner.ip4.src_ip = UINT32_MAX;                 /* UE IP */
        match.inner.ip4.dst_ip = UINT32_MAX;                 /* SDF remote IP */
        match.inner.ip4.next_proto = UINT8_MAX;              /* SDF protocol */
        match.inner.transport.src_port = UINT16_MAX;           /* SDF src port */
        match.inner.transport.dst_port = UINT16_MAX;           /* SDF dst port */

        struct doca_flow_match mask = {};
        mask.tun.type = DOCA_FLOW_TUN_GTPU;
        mask.tun.gtp_teid = UINT32_MAX;
        mask.tun.gtp_ext_psc_qfi = UINT8_MAX;
        mask.inner.l3_type = DOCA_FLOW_L3_TYPE_IP4;
        mask.inner.ip4.src_ip = UINT32_MAX;
        mask.inner.ip4.dst_ip = UINT32_MAX;
        mask.inner.ip4.next_proto = UINT8_MAX;
        mask.inner.transport.src_port = UINT16_MAX;
        mask.inner.transport.dst_port = UINT16_MAX;

        doca_flow_pipe_cfg_set_match(pipe_cfg, &match, &mask);

        /* Actions: decap + L2 inject + pkt_meta */
        struct doca_flow_actions actions = {};
        actions.decap_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
        actions.decap_cfg.is_l2 = false;

        memcpy(actions.decap_cfg.eth.src_mac,
               ctx->port_cfg.upf_n6_mac, 6);
        memcpy(actions.decap_cfg.eth.dst_mac,
               ctx->port_cfg.dn_gw_mac, 6);
        actions.decap_cfg.eth.type = RTE_BE16(0x0800);

        actions.meta.pkt_meta = UINT32_MAX;  /* changeable per-entry */

        struct doca_flow_actions *actions_arr[] = { &actions };
        doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL, NULL, 1);

        /* Monitor: shared meter (set per-entry; skipped when no QER) */
        struct doca_flow_monitor monitor = {};
        monitor.meter_type = DOCA_FLOW_RESOURCE_TYPE_SHARED;
        doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor);

        /* Hit → UL_COLOR_GATE */
        struct doca_flow_fwd fwd = {
            .type = DOCA_FLOW_FWD_PIPE,
            .next_pipe = ctx->ul_color_gate_pipe,
        };

        /* Miss → next lower priority bucket, or TO_HOST */
        struct doca_flow_fwd fwd_miss;
        if (p == NUM_PRIO_BUCKETS - 1) {
            fwd_miss.type = DOCA_FLOW_FWD_PIPE;
            fwd_miss.next_pipe = ctx->to_host_pipe;
        } else {
            fwd_miss.type = DOCA_FLOW_FWD_PIPE;
            fwd_miss.next_pipe = ctx->ul_match_pipes[p + 1];
        }

        result = doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_miss,
                                        &ctx->ul_match_pipes[p]);
        doca_flow_pipe_cfg_destroy(pipe_cfg);

        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("%s pipe creation failed: %s",
                         name, doca_error_get_descr(result));
            return result;
        }

        DOCA_LOG_INFO("%s: hit→UL_COLOR_GATE, miss→%s",
                      name,
                      (p == NUM_PRIO_BUCKETS - 1) ? "TO_HOST"
                          : "next bucket");
    }

    return DOCA_SUCCESS;
}


/* ── DL_MATCH pipes (4 priority buckets) ──────────────────────────── */
/*
 * Each pipe matches: outer 5-tuple (UE IP, remote IP, proto, src_port,
 * dst_port).  Per-entry match_mask wildcards unused SDF fields.
 * Actions: pkt_meta + shared meter.
 * Chain: P0.miss → P1 → P2 → P3.miss → TO_HOST.
 */
static doca_error_t
build_dl_match_pipes(dpu_pipeline_ctx_t *ctx)
{
    doca_error_t result;

    for (int p = NUM_PRIO_BUCKETS - 1; p >= 0; p--) {
        struct doca_flow_pipe_cfg *pipe_cfg;
        result = doca_flow_pipe_cfg_create(&pipe_cfg, ctx->switch_port);
        if (result != DOCA_SUCCESS) return result;

        char name[32];
        snprintf(name, sizeof(name), "DL_MATCH_P%d", p);
        doca_flow_pipe_cfg_set_name(pipe_cfg, name);
        doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);
        doca_flow_pipe_cfg_set_is_root(pipe_cfg, false);
        doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 2048);

        /* Match: outer 5-tuple (all CHANGEABLE) */
        struct doca_flow_match match = {};
        match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
        match.outer.ip4.dst_ip = UINT32_MAX;                 /* UE IP */
        match.outer.ip4.src_ip = UINT32_MAX;                 /* SDF remote IP (reversed) */
        match.outer.ip4.next_proto = UINT8_MAX;              /* SDF protocol */
        match.outer.transport.src_port = UINT16_MAX;           /* SDF src port */
        match.outer.transport.dst_port = UINT16_MAX;           /* SDF dst port */

        struct doca_flow_match mask = {};
        mask.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
        mask.outer.ip4.dst_ip = UINT32_MAX;
        mask.outer.ip4.src_ip = UINT32_MAX;
        mask.outer.ip4.next_proto = UINT8_MAX;
        mask.outer.transport.src_port = UINT16_MAX;
        mask.outer.transport.dst_port = UINT16_MAX;

        doca_flow_pipe_cfg_set_match(pipe_cfg, &match, &mask);

        /* Actions: pkt_meta (changeable) */
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

        /* Miss → next bucket or TO_HOST */
        struct doca_flow_fwd fwd_miss;
        if (p == NUM_PRIO_BUCKETS - 1) {
            fwd_miss.type = DOCA_FLOW_FWD_PIPE;
            fwd_miss.next_pipe = ctx->to_host_pipe;
        } else {
            fwd_miss.type = DOCA_FLOW_FWD_PIPE;
            fwd_miss.next_pipe = ctx->dl_match_pipes[p + 1];
        }

        result = doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_miss,
                                        &ctx->dl_match_pipes[p]);
        doca_flow_pipe_cfg_destroy(pipe_cfg);

        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("%s pipe creation failed: %s",
                         name, doca_error_get_descr(result));
            return result;
        }

        DOCA_LOG_INFO("%s: hit→DL_COLOR_GATE, miss→%s",
                      name,
                      (p == NUM_PRIO_BUCKETS - 1) ? "TO_HOST"
                          : "next bucket");
    }

    return DOCA_SUCCESS;
}


/* ── DL_ENCAP pipe (EGRESS on N3 port) ─────────────────────────────── */
static doca_error_t
build_dl_encap_pipe(dpu_pipeline_ctx_t *ctx)
{
    doca_error_t result;
    struct doca_flow_pipe_cfg *pipe_cfg;

    result = doca_flow_pipe_cfg_create(&pipe_cfg, ctx->switch_port);
    if (result != DOCA_SUCCESS) return result;

    doca_flow_pipe_cfg_set_name(pipe_cfg, "DL_ENCAP");
    doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);
    doca_flow_pipe_cfg_set_is_root(pipe_cfg, true);
    doca_flow_pipe_cfg_set_domain(pipe_cfg, DOCA_FLOW_PIPE_DOMAIN_EGRESS);
    doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 2048);

    /* Match pkt_meta (changeable) */
    struct doca_flow_match match = {};
    match.meta.pkt_meta = UINT32_MAX;

    struct doca_flow_match mask = {};
    mask.meta.pkt_meta = UINT32_MAX;

    doca_flow_pipe_cfg_set_match(pipe_cfg, &match, &mask);

    /* Action: GTP-U encapsulation with PSC extension */
    struct doca_flow_actions actions = {};
    actions.encap_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;

    /* Outer Ethernet */
    memcpy(actions.encap_cfg.encap.outer.eth.src_mac,
           ctx->port_cfg.upf_n3_mac, 6);
    memcpy(actions.encap_cfg.encap.outer.eth.dst_mac,
           ctx->port_cfg.gnb_mac, 6);
    actions.encap_cfg.encap.outer.eth.type = RTE_BE16(0x0800);

    /* Outer IPv4 */
    actions.encap_cfg.encap.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
    actions.encap_cfg.encap.outer.ip4.src_ip = ctx->port_cfg.upf_n3_ip;
    actions.encap_cfg.encap.outer.ip4.dst_ip = UINT32_MAX;   /* changeable */
    actions.encap_cfg.encap.outer.ip4.ttl = 64;

    /* Outer UDP */
    actions.encap_cfg.encap.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
    actions.encap_cfg.encap.outer.udp.l4_port.dst_port = RTE_BE16(GTP_UDP_PORT);

    /* GTP-U tunnel + PSC extension */
    actions.encap_cfg.encap.tun.type = DOCA_FLOW_TUN_GTPU;
    actions.encap_cfg.encap.tun.gtp_teid = UINT32_MAX;            /* changeable */
    actions.encap_cfg.encap.tun.gtp_next_ext_hdr_type = GTP_EXT_PSC;  /* PSC 0x85 */
    actions.encap_cfg.encap.tun.gtp_ext_psc_qfi = UINT8_MAX;     /* changeable */

    struct doca_flow_actions *actions_arr[] = { &actions };
    doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL, NULL, 1);

    /* Forward: out the pipe (egress on N3) */
    struct doca_flow_fwd fwd = {
        .type = DOCA_FLOW_FWD_PORT,
        .port_id = ctx->port_cfg.n3_port_id,
    };

    /* Miss → DROP (unmatched pkt_meta = not tagged by DL_MATCH) */
    struct doca_flow_fwd fwd_miss = {
        .type = DOCA_FLOW_FWD_DROP,
    };

    result = doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_miss,
                                    &ctx->dl_encap_pipe);
    doca_flow_pipe_cfg_destroy(pipe_cfg);

    if (result != DOCA_SUCCESS)
        DOCA_LOG_ERR("DL_ENCAP pipe creation failed: %s",
                     doca_error_get_descr(result));
    return result;
}


/* ── ROOT control pipe ─────────────────────────────────────────────── */
/*
 * Matches parser_meta.port_id + protocol to steer traffic:
 *   Prio 0: N3 port + GTP-U → UL_MATCH[0]
 *   Prio 1: N6 port + IPv4  → DL_MATCH[0]
 *   Miss:   → TO_HOST
 */
static doca_error_t
build_root_pipe(dpu_pipeline_ctx_t *ctx)
{
    doca_error_t result;
    struct doca_flow_pipe_cfg *pipe_cfg;

    result = doca_flow_pipe_cfg_create(&pipe_cfg, ctx->switch_port);
    if (result != DOCA_SUCCESS) return result;

    doca_flow_pipe_cfg_set_name(pipe_cfg, "ROOT");
    doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_CONTROL);
    doca_flow_pipe_cfg_set_is_root(pipe_cfg, true);

    struct doca_flow_fwd fwd_miss = {
        .type = DOCA_FLOW_FWD_PIPE,
        .next_pipe = ctx->to_host_pipe,
    };

    result = doca_flow_pipe_create(pipe_cfg, NULL, &fwd_miss,
                                    &ctx->root_pipe);
    doca_flow_pipe_cfg_destroy(pipe_cfg);
    if (result != DOCA_SUCCESS) return result;

    /* Priority 0: GTP-U from N3 → UL_MATCH[0] */
    {
        struct doca_flow_match match = {};
        match.parser_meta.port_id = ctx->port_cfg.n3_port_id;
        match.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
        match.outer.udp.l4_port.dst_port = RTE_BE16(GTP_UDP_PORT);

        struct doca_flow_match mask = {};
        mask.parser_meta.port_id = UINT16_MAX;
        mask.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
        mask.outer.udp.l4_port.dst_port = UINT16_MAX;

        struct doca_flow_fwd fwd = {
            .type = DOCA_FLOW_FWD_PIPE,
            .next_pipe = ctx->ul_match_pipes[0],
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

    /* Priority 1: IPv4 from N6 → DL_MATCH[0] */
    {
        struct doca_flow_match match = {};
        match.parser_meta.port_id = ctx->port_cfg.n6_port_id;
        match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;

        struct doca_flow_match mask = {};
        mask.parser_meta.port_id = UINT16_MAX;
        mask.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;

        struct doca_flow_fwd fwd = {
            .type = DOCA_FLOW_FWD_PIPE,
            .next_pipe = ctx->dl_match_pipes[0],
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

    doca_flow_entries_process(ctx->switch_port, 0, 0, 0);

    DOCA_LOG_INFO("ROOT pipe: N3+GTP→UL_MATCH[0], N6+IPv4→DL_MATCH[0], "
                  "miss→TO_HOST");
    return DOCA_SUCCESS;
}


/* ═══════════════════════════════════════════════════════════════════════
 *  Meter creation helper (trTCM RFC 2698)
 * ═══════════════════════════════════════════════════════════════════════ */

/**
 * Create a shared trTCM meter (CIR=GBR, PIR=MBR).
 * Returns NO_METER_ID if both rates are 0 (no QER → skip metering).
 */
static doca_error_t
create_trtcm_meter(struct doca_flow_port *port,
                   uint32_t *meter_id,
                   uint64_t gbr_kbps,
                   uint64_t mbr_kbps)
{
    /* No QER / no rate limit → skip metering entirely */
    if (gbr_kbps == 0 && mbr_kbps == 0) {
        *meter_id = NO_METER_ID;
        return DOCA_SUCCESS;
    }

    doca_error_t result;

    uint64_t cir_bps = gbr_kbps * 1000 / 8;
    uint64_t pir_bps = mbr_kbps * 1000 / 8;

    /* PIR must be >= CIR per RFC 2698 */
    if (pir_bps < cir_bps)
        pir_bps = cir_bps;

    /* If only GBR is 0, set CIR to a reasonable floor */
    if (cir_bps == 0)
        cir_bps = 1;
    if (pir_bps == 0)
        pir_bps = 1;

    struct doca_flow_shared_resource_cfg cfg = {};
    cfg.meter_cfg.limit_type = DOCA_FLOW_METER_LIMIT_TYPE_BYTES;
    cfg.meter_cfg.color_mode = DOCA_FLOW_METER_COLOR_MODE_BLIND;
    cfg.meter_cfg.alg = DOCA_FLOW_METER_ALGORITHM_TYPE_RFC2698;
    cfg.meter_cfg.cir = cir_bps;
    cfg.meter_cfg.cbs = (cir_bps / 100 > 4096) ? cir_bps / 100 : 4096;
    cfg.meter_cfg.pir = pir_bps;
    cfg.meter_cfg.pbs = (pir_bps / 100 > 4096) ? pir_bps / 100 : 4096;

    result = doca_flow_port_shared_resource_get(port,
                                                 DOCA_FLOW_SHARED_RESOURCE_METER,
                                                 meter_id);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Meter alloc failed: %s", doca_error_get_descr(result));
        return result;
    }

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

    result = init_doca_flow();
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("DOCA Flow init failed: %s", doca_error_get_descr(result));
        return result;
    }

    /* Create ports — each bound to a DOCA device */
    result = create_port(port_cfg->n3_port_id, port_cfg->n3_dev,
                          NULL, &ctx->ports[0]);
    if (result != DOCA_SUCCESS) return result;

    result = create_port(port_cfg->n6_port_id, port_cfg->n6_dev,
                          NULL, &ctx->ports[1]);
    if (result != DOCA_SUCCESS) return result;

    result = create_port(port_cfg->host_vf_port_id, port_cfg->host_vf_dev,
                          port_cfg->host_vf_rep, &ctx->ports[2]);
    if (result != DOCA_SUCCESS) return result;

    ctx->nb_ports = 3;

    ctx->switch_port = doca_flow_port_switch_get(ctx->ports[0]);
    if (!ctx->switch_port) {
        DOCA_LOG_ERR("Failed to get switch manager port");
        return DOCA_ERROR_INITIALIZATION;
    }

    result = doca_flow_port_pair(ctx->ports[0], ctx->ports[1]);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Port pair failed: %s", doca_error_get_descr(result));
        return result;
    }

    /* Build pipes in dependency order */
    DOCA_LOG_INFO("Building 13-pipe hierarchy...");

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

    result = build_ul_match_pipes(ctx);
    if (result != DOCA_SUCCESS) return result;

    result = build_dl_match_pipes(ctx);
    if (result != DOCA_SUCCESS) return result;

    result = build_dl_encap_pipe(ctx);
    if (result != DOCA_SUCCESS) return result;

    result = build_root_pipe(ctx);
    if (result != DOCA_SUCCESS) return result;

    DOCA_LOG_INFO("Pipeline initialised: 13 pipes, %u ports", ctx->nb_ports);
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

    /* Select priority bucket from 3GPP precedence */
    int bucket = precedence_to_bucket(msg->precedence);

    if (msg->direction == HW_DIR_UPLINK) {
        /* ── UPLINK ──────────────────────────────────────────────────── */

        /* Meter: skip if no QER (GBR + MBR both 0) */
        uint32_t meter_id;
        result = create_trtcm_meter(ctx->switch_port, &meter_id,
                                     msg->gbr_ul, msg->mbr_ul);
        if (result != DOCA_SUCCESS) return result;

        /* Match: TEID + QFI + inner IPs + proto */
        struct doca_flow_match match = {};
        match.tun.type = DOCA_FLOW_TUN_GTPU;
        match.tun.gtp_teid = htonl(msg->teid);
        match.tun.gtp_ext_psc_qfi = msg->qfi;
        match.inner.l3_type = DOCA_FLOW_L3_TYPE_IP4;
        match.inner.ip4.src_ip = msg->ue_ipv4.s_addr;  /* NBO */

        /* SDF fields (UL direction: sdf_dst = inner dst, sdf_src = inner src).
         * SDF is defined in UL direction per 3GPP TS 29.244. */
        if (msg->has_sdf) {
            if (msg->sdf_dst_ip != 0)
                match.inner.ip4.dst_ip = htonl(msg->sdf_dst_ip);
            if (msg->sdf_proto != 0)
                match.inner.ip4.next_proto = msg->sdf_proto;
            if (msg->sdf_src_port != 0)
                match.inner.transport.src_port = htons(msg->sdf_src_port);
            if (msg->sdf_dst_port != 0)
                match.inner.transport.dst_port = htons(msg->sdf_dst_port);
        }

        /* Per-entry match_mask: wildcard fields not present in SDF */
        struct doca_flow_match match_mask = {};
        match_mask.tun.type = DOCA_FLOW_TUN_GTPU;
        match_mask.tun.gtp_teid = UINT32_MAX;
        match_mask.tun.gtp_ext_psc_qfi = UINT8_MAX;
        match_mask.inner.l3_type = DOCA_FLOW_L3_TYPE_IP4;
        match_mask.inner.ip4.src_ip = UINT32_MAX;
        /* SDF dst_ip: use prefix mask if present, else wildcard (0) */
        if (msg->has_sdf && msg->sdf_dst_pref > 0)
            match_mask.inner.ip4.dst_ip = prefix_to_netmask(msg->sdf_dst_pref);
        /* SDF proto: full mask if present */
        if (msg->has_sdf && msg->sdf_proto > 0)
            match_mask.inner.ip4.next_proto = UINT8_MAX;
        /* SDF L4 ports: full mask if present */
        if (msg->has_sdf && msg->sdf_src_port > 0)
            match_mask.inner.transport.src_port = UINT16_MAX;
        if (msg->has_sdf && msg->sdf_dst_port > 0)
            match_mask.inner.transport.dst_port = UINT16_MAX;

        /* Actions: pkt_meta (decap + L2 inject from pipe template) */
        struct doca_flow_actions actions = {};
        actions.meta.pkt_meta = htonl(msg->hw_rule_id);

        /* Monitor: attach shared meter if allocated */
        struct doca_flow_monitor monitor = {};
        struct doca_flow_monitor *mon_ptr = NULL;
        if (meter_id != NO_METER_ID) {
            monitor.meter_type = DOCA_FLOW_RESOURCE_TYPE_SHARED;
            monitor.shared_meter.shared_meter_id = meter_id;
            mon_ptr = &monitor;
        }

        struct doca_flow_pipe_entry *entry;
        result = doca_flow_pipe_add_entry(0, ctx->ul_match_pipes[bucket],
                                           &match, &match_mask, &actions,
                                           mon_ptr, NULL,
                                           0, NULL, &entry);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("UL entry failed hw_rule_id=%u bucket=%d: %s",
                         msg->hw_rule_id, bucket,
                         doca_error_get_descr(result));
            return result;
        }

        doca_flow_entries_process(ctx->switch_port, 0, 0, 0);

        DOCA_LOG_INFO("UL rule: hw_rule=%u teid=0x%x qfi=%u bucket=P%d "
                      "meter=%s",
                      msg->hw_rule_id, msg->teid, msg->qfi, bucket,
                      (meter_id != NO_METER_ID) ? "yes" : "none");

    } else {
        /* ── DOWNLINK ────────────────────────────────────────────────── */

        uint32_t meter_id;
        result = create_trtcm_meter(ctx->switch_port, &meter_id,
                                     msg->gbr_dl, msg->mbr_dl);
        if (result != DOCA_SUCCESS) return result;

        /* DL_MATCH entry: UE IP + SDF (reversed for DL) */
        struct doca_flow_match dl_match = {};
        dl_match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
        dl_match.outer.ip4.dst_ip = msg->ue_ipv4.s_addr;  /* NBO */

        /* SDF: in DL, SDF direction is reversed (UL perspective).
         * SDF dst_ip → DL outer src_ip, SDF dst_port → DL outer src_port */
        if (msg->has_sdf) {
            if (msg->sdf_dst_ip != 0)
                dl_match.outer.ip4.src_ip = htonl(msg->sdf_dst_ip);
            if (msg->sdf_proto != 0)
                dl_match.outer.ip4.next_proto = msg->sdf_proto;
            if (msg->sdf_dst_port != 0)
                dl_match.outer.transport.src_port = htons(msg->sdf_dst_port);
            if (msg->sdf_src_port != 0)
                dl_match.outer.transport.dst_port = htons(msg->sdf_src_port);
        }

        /* Per-entry match_mask */
        struct doca_flow_match dl_mask = {};
        dl_mask.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
        dl_mask.outer.ip4.dst_ip = UINT32_MAX;
        if (msg->has_sdf && msg->sdf_dst_pref > 0)
            dl_mask.outer.ip4.src_ip = prefix_to_netmask(msg->sdf_dst_pref);
        if (msg->has_sdf && msg->sdf_proto > 0)
            dl_mask.outer.ip4.next_proto = UINT8_MAX;
        if (msg->has_sdf && msg->sdf_dst_port > 0)
            dl_mask.outer.transport.src_port = UINT16_MAX;
        if (msg->has_sdf && msg->sdf_src_port > 0)
            dl_mask.outer.transport.dst_port = UINT16_MAX;

        struct doca_flow_actions dl_actions = {};
        dl_actions.meta.pkt_meta = htonl(msg->hw_rule_id);

        struct doca_flow_monitor dl_monitor = {};
        struct doca_flow_monitor *dl_mon_ptr = NULL;
        if (meter_id != NO_METER_ID) {
            dl_monitor.meter_type = DOCA_FLOW_RESOURCE_TYPE_SHARED;
            dl_monitor.shared_meter.shared_meter_id = meter_id;
            dl_mon_ptr = &dl_monitor;
        }

        struct doca_flow_pipe_entry *dl_entry;
        result = doca_flow_pipe_add_entry(0, ctx->dl_match_pipes[bucket],
                                           &dl_match, &dl_mask, &dl_actions,
                                           dl_mon_ptr, NULL,
                                           0, NULL, &dl_entry);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("DL_MATCH entry failed hw_rule_id=%u bucket=%d: %s",
                         msg->hw_rule_id, bucket,
                         doca_error_get_descr(result));
            return result;
        }

        /* DL_ENCAP entry: pkt_meta → GTP encap */
        if (msg->ohc_desc == HW_OHC_GTPU_UDP_IPV4) {
            struct doca_flow_match encap_match = {};
            encap_match.meta.pkt_meta = htonl(msg->hw_rule_id);

            struct doca_flow_actions encap_actions = {};
            encap_actions.encap_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;

            encap_actions.encap_cfg.encap.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
            encap_actions.encap_cfg.encap.outer.ip4.dst_ip =
                msg->ohc_ipv4.s_addr;
            encap_actions.encap_cfg.encap.outer.ip4.src_ip =
                ctx->port_cfg.upf_n3_ip;
            encap_actions.encap_cfg.encap.outer.ip4.ttl = 64;

            encap_actions.encap_cfg.encap.outer.l4_type_ext =
                DOCA_FLOW_L4_TYPE_EXT_UDP;
            encap_actions.encap_cfg.encap.outer.udp.l4_port.dst_port =
                RTE_BE16(GTP_UDP_PORT);

            encap_actions.encap_cfg.encap.tun.type = DOCA_FLOW_TUN_GTPU;
            encap_actions.encap_cfg.encap.tun.gtp_teid =
                htonl(msg->ohc_teid);
            encap_actions.encap_cfg.encap.tun.gtp_next_ext_hdr_type = GTP_EXT_PSC;
            encap_actions.encap_cfg.encap.tun.gtp_ext_psc_qfi = msg->encap_qfi;

            struct doca_flow_pipe_entry *encap_entry;
            result = doca_flow_pipe_add_entry(0, ctx->dl_encap_pipe,
                                               &encap_match, 0, &encap_actions,
                                               NULL, NULL,
                                               0, NULL, &encap_entry);
            if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("DL_ENCAP entry failed hw_rule_id=%u: %s",
                             msg->hw_rule_id, doca_error_get_descr(result));
                return result;
            }
        }

        doca_flow_entries_process(ctx->switch_port, 0, 0, 0);

        DOCA_LOG_INFO("DL rule: hw_rule=%u ue_ip=%08x ohc_teid=0x%x "
                      "bucket=P%d meter=%s",
                      msg->hw_rule_id, msg->ue_ipv4.s_addr, msg->ohc_teid,
                      bucket, (meter_id != NO_METER_ID) ? "yes" : "none");
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
    if (ctx->root_pipe)
        doca_flow_pipe_destroy(ctx->root_pipe);
    if (ctx->dl_encap_pipe)
        doca_flow_pipe_destroy(ctx->dl_encap_pipe);

    for (int p = 0; p < NUM_PRIO_BUCKETS; p++) {
        if (ctx->dl_match_pipes[p])
            doca_flow_pipe_destroy(ctx->dl_match_pipes[p]);
    }
    for (int p = 0; p < NUM_PRIO_BUCKETS; p++) {
        if (ctx->ul_match_pipes[p])
            doca_flow_pipe_destroy(ctx->ul_match_pipes[p]);
    }

    if (ctx->dl_color_gate_pipe)
        doca_flow_pipe_destroy(ctx->dl_color_gate_pipe);
    if (ctx->ul_color_gate_pipe)
        doca_flow_pipe_destroy(ctx->ul_color_gate_pipe);
    if (ctx->to_host_pipe)
        doca_flow_pipe_destroy(ctx->to_host_pipe);

    for (int i = 0; i < ctx->nb_ports; i++) {
        if (ctx->ports[i])
            doca_flow_port_stop(ctx->ports[i]);
    }

    doca_flow_destroy();

    DOCA_LOG_INFO("Pipeline destroyed (%u entries were active)",
                  ctx->nb_entries);
}
