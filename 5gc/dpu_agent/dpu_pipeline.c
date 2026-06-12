/*
 * dpu_pipeline.c — DOCA Flow pipeline on BlueField-3 (vnf,hws mode)
 *
 * Implements the Split-Agent DPU-side data plane for ICNP offload:
 *   - Full SDF matching (inner/outer IPs + protocol) with per-entry mask
 *   - 4 priority-bucketed pipes per direction for 3GPP precedence
 *   - trTCM RFC 2698 metering (CIR=GBR, PIR=MBR), skipped when no QER
 *   - Color-gate enforcement (GREEN+YELLOW pass, RED drops)
 *   - Inline GTP decap + L2 injection for uplink
 *   - pkt_meta-based GTP encap for downlink (with PSC extension)
 *   - TO_DPU_ARM_DL pipe for DL buffering via RSS to ARM Rx queues
 *
 *   N3_ROOT → UL_MATCH[0..3] → UL_COLOR_GATE → UL_DECAP → FWD_PORT(N6)
 *   N6_ROOT → DL_*_MATCH chain → DL_COLOR_GATE → DL_ENCAP → FWD_PORT(N3)
 *   TO_DPU_ARM_DL: RSS → ARM Rx queues (reached via per-bucket DL override pipes on BUFF)
 *
 * VNF mode: each port owns its ingress pipes.  Cross-port forwarding
 * uses doca_flow_port_pair() + FWD_PORT with port_id ^ 1.  No switch
 * manager port, no representor port.
 *
 * Devargs are passed programmatically via doca_dpdk_port_probe()
 * in dpu_agent.c (not via EAL -a):
 *   dv_flow_en=2,dv_xmeta_en=4
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <arpa/inet.h>
#include <inttypes.h>
#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <stdlib.h>
#include <string.h>

#include <doca_flow.h>
#include <doca_log.h>

/* DOCA 3.3 compat: DOCA_FLOW_NO_WAIT = 0 is documented but may be
 * absent in some SDK builds; provide the constant if needed. */
#ifndef DOCA_FLOW_NO_WAIT
#define DOCA_FLOW_NO_WAIT 0
#endif

#include "dpu_pipeline.h"

DOCA_LOG_REGISTER(DPU_PIPELINE);

/* ── Constants ──────────────────────────────────────────────────────── */
/* GTP_UDP_PORT and GTP_EXT_PSC live in dpu_pipeline.h so the buffer
 * drain lcore (which builds the GTP-U + PSC outer header in software)
 * shares a single definition with the HW-encap path. */
#define NO_METER_ID UINT32_MAX /* sentinel: skip metering for this entry */
#define UPDATE_PDR_DELETE_RETRIES 5
#define UPDATE_PDR_DELETE_RETRY_DELAY_US 200
#define UPDATE_PDR_REINSERT_DELAY_US 50

/* ── Record helpers ─────────────────────────────────────────────────── */

static dpu_rule_record_t *
find_record(dpu_pipeline_ctx_t *ctx, uint32_t hw_rule_id) {
        int idx = rte_hash_lookup(ctx->rule_id_map, &hw_rule_id);
        if (idx < 0)
                return NULL;
        return &ctx->rules[idx];
}

static dpu_rule_record_t *
alloc_record(dpu_pipeline_ctx_t *ctx, uint32_t hw_rule_id) {
        int idx = rte_hash_add_key(ctx->rule_id_map, &hw_rule_id);
        if (idx < 0)
                return NULL;
        return &ctx->rules[idx];
}

static void
free_record(dpu_pipeline_ctx_t *ctx, dpu_rule_record_t *rec) {
        uint32_t id = rec->hw_rule_id;
        memset(rec, 0, sizeof(*rec));
        rte_hash_del_key(ctx->rule_id_map, &id);
}

/* Return the DOCA Flow port that owns the *MATCH* pipes for the given
 * direction.  This is the port to commit DL_MATCH / UL_MATCH entries on.
 *   UL pipes (UL_MATCH, UL_COLOR_GATE, UL_DECAP) live on N3 (DEFAULT).
 *   DL_MATCH, DL_COLOR_GATE, TO_DPU_ARM_DL live on N6 (DEFAULT).
 * NOTE: DL_ENCAP itself lives on N3 (EGRESS root) — its entries must be
 * committed via ctx->n3_port directly, NOT via this helper. */
static inline struct doca_flow_port *
port_for_direction(const dpu_pipeline_ctx_t *ctx, uint8_t direction) {
        return (direction == HW_DIR_UPLINK) ? ctx->n3_port : ctx->n6_port;
}

/* ── Helpers ────────────────────────────────────────────────────────── */

/** Map 3GPP precedence (lower = higher priority) to bucket index [0..3]. */
static inline int
precedence_to_bucket(uint32_t precedence) {
        int bucket = (int)(precedence / PRIO_BUCKET_RANGE);
        if (bucket >= NUM_PRIO_BUCKETS)
                bucket = NUM_PRIO_BUCKETS - 1;
        return bucket;
}

/** Resolve the DL match pipe a record's entry lives in.  Two families exist
 *  on N6: dl_sdf_match_pipes[] (src+dst) for peer-specific SDF rules, and
 *  dl_match_pipes[] (dst-only) for catch-all and reduced-SDF rules. */
static inline struct doca_flow_pipe *
dl_pipe_for_record(const dpu_pipeline_ctx_t *ctx, const dpu_rule_record_t *rec) {
        return rec->is_dl_sdf_match
                       ? ctx->dl_sdf_match_pipes[rec->pipe_bucket]
                       : ctx->dl_match_pipes[rec->pipe_bucket];
}

static inline struct doca_flow_pipe *
dl_buff_override_pipe_for_record(const dpu_pipeline_ctx_t *ctx, const dpu_rule_record_t *rec) {
        return rec->is_dl_sdf_match
                       ? ctx->dl_sdf_buff_override_pipes[rec->pipe_bucket]
                       : ctx->dl_buff_override_pipes[rec->pipe_bucket];
}

static inline uint32_t
ul_inner_src_ip_for_msg(const hw_offload_msg_t *msg)
{
        uint32_t ip = msg->ue_ipv4.s_addr; /* NBO */

        if (msg->has_sdf && msg->sdf_src_pref == 32) {
                uint32_t sdf_src_nbo = htonl(msg->sdf_src_ip);
                if (sdf_src_nbo != msg->ue_ipv4.s_addr)
                        ip = sdf_src_nbo;
        }

        return ip;
}

/* Build the per-entry DL_ENCAP actions (GTP-U + PSC outer header) for the
 * given OHC params.  Mirror the pipe-template fields exactly — version_ihl,
 * next_proto, and udp src_port included so the HW finalises GTP/UDP/IP
 * lengths and uses 2152 as src port.  Single source of truth shared by
 * insert_rule, update_dlencap_only, and reinsert_dl_encap_with_new_params
 * so all sites emit byte-identical encap descriptors.
 *   ohc_ipv4: network byte order; ohc_teid: host byte order. */
static void
build_dl_encap_actions(const dpu_pipeline_ctx_t *ctx,
                       uint32_t ohc_ipv4,
                       uint32_t ohc_teid,
                       uint8_t encap_qfi,
                       struct doca_flow_actions *actions) {
        memset(actions, 0, sizeof(*actions));
        actions->encap_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;

        actions->encap_cfg.encap.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
        actions->encap_cfg.encap.outer.ip4.version_ihl = 0x45;
        actions->encap_cfg.encap.outer.ip4.next_proto = DOCA_FLOW_PROTO_UDP;
        actions->encap_cfg.encap.outer.ip4.dst_ip = ohc_ipv4;
        actions->encap_cfg.encap.outer.ip4.src_ip = ctx->port_cfg.upf_n3_ip;
        actions->encap_cfg.encap.outer.ip4.ttl = 64;

        actions->encap_cfg.encap.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
        actions->encap_cfg.encap.outer.udp.l4_port.src_port = RTE_BE16(GTP_UDP_PORT);
        actions->encap_cfg.encap.outer.udp.l4_port.dst_port = RTE_BE16(GTP_UDP_PORT);

        actions->encap_cfg.encap.tun.type = DOCA_FLOW_TUN_GTPU;
        actions->encap_cfg.encap.tun.gtp_teid = htonl(ohc_teid);
        actions->encap_cfg.encap.tun.gtp_next_ext_hdr_type = GTP_EXT_PSC;
        actions->encap_cfg.encap.tun.gtp_ext_psc_qfi = encap_qfi;
}

/* ── Pipe entry callback ────────────────────────────────────────────── */
static void
entry_process_cb(struct doca_flow_pipe_entry *entry, uint16_t pipe_queue, enum doca_flow_entry_status status,
                 enum doca_flow_entry_op op, void *user_ctx) {
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
init_doca_flow(uint32_t pipe_queues, uint32_t nr_counters, uint32_t nr_meters, uint32_t nr_shared_meters) {
        struct doca_flow_cfg *cfg;
        doca_error_t result;

        result = doca_flow_cfg_create(&cfg);
        if (result != DOCA_SUCCESS)
                return result;

        doca_flow_cfg_set_pipe_queues(cfg, pipe_queues);
        doca_flow_cfg_set_nr_counters(cfg, nr_counters);
        doca_flow_cfg_set_nr_meters(cfg, nr_meters);
        doca_flow_cfg_set_mode_args(cfg, "vnf,hws");
        doca_flow_cfg_set_cb_entry_process(cfg, entry_process_cb);
        doca_flow_cfg_set_nr_shared_resource(cfg, nr_shared_meters, DOCA_FLOW_SHARED_RESOURCE_METER);

        /* Per-port resource tracking: required so that each port can
         * independently provision encap/decap/meter ARGUMENT buffers
         * via doca_flow_port_cfg_set_nr_resources() + actions_mem_size. */
        result = doca_flow_cfg_set_resource_mode(cfg, DOCA_FLOW_RESOURCE_MODE_PORT);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Failed to set resource mode PORT: %s", doca_error_get_descr(result));
                doca_flow_cfg_destroy(cfg);
                return result;
        }

        result = doca_flow_init(cfg);
        doca_flow_cfg_destroy(cfg);
        return result;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Port creation — binds logical ID + DOCA device + optional representor
 * ═══════════════════════════════════════════════════════════════════════ */

static doca_error_t
create_port(uint16_t port_id, struct doca_dev *dev, struct doca_dev_rep *dev_rep, uint32_t nr_encap, uint32_t nr_decap,
            uint32_t nr_meter, uint32_t nr_counters, uint32_t actions_mem, struct doca_flow_port **port) {
        struct doca_flow_port_cfg *port_cfg;
        doca_error_t result;

        result = doca_flow_port_cfg_create(&port_cfg);
        if (result != DOCA_SUCCESS)
                return result;

        doca_flow_port_cfg_set_port_id(port_cfg, port_id);

        /* In DOCA 3.3, PF ports use set_dev() only; representor ports use
         * set_dev_rep() only.  They are mutually exclusive on a port config. */
        if (dev_rep) {
                result = doca_flow_port_cfg_set_dev_rep(port_cfg, dev_rep);
                if (result != DOCA_SUCCESS) {
                        doca_flow_port_cfg_destroy(port_cfg);
                        return result;
                }
        } else {
                result = doca_flow_port_cfg_set_dev(port_cfg, dev);
                if (result != DOCA_SUCCESS) {
                        doca_flow_port_cfg_destroy(port_cfg);
                        return result;
                }
        }

        /* ── Per-port resource provisioning ─────────────────────────────
         * DOCA 3.3 HWS requires pre-allocation of action memory and
         * resource pools (encap/decap/meter) per port BEFORE port_start.
         * Without these, any pipe using REFORMAT actions fails with
         * "cannot get resource(ARGUMENT_64B)".
         *
         * All values are now configurable via JSON (port-actions-mem,
         * port-nr-encap, port-nr-decap, port-nr-meter).
         * ────────────────────────────────────────────────────────────────── */
        result = doca_flow_port_cfg_set_actions_mem_size(port_cfg, actions_mem);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Port %u: failed to set actions_mem_size=%u: %s", port_id, actions_mem,
                             doca_error_get_descr(result));
                doca_flow_port_cfg_destroy(port_cfg);
                return result;
        }

        result = doca_flow_port_cfg_set_nr_resources(port_cfg, DOCA_FLOW_RESOURCE_METER, nr_meter);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Port %u: failed to set meter resources=%u: %s", port_id, nr_meter,
                             doca_error_get_descr(result));
                doca_flow_port_cfg_destroy(port_cfg);
                return result;
        }

        result = doca_flow_port_cfg_set_nr_resources(port_cfg, DOCA_FLOW_RESOURCE_ENCAP, nr_encap);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Port %u: failed to set encap resources=%u: %s", port_id, nr_encap,
                             doca_error_get_descr(result));
                doca_flow_port_cfg_destroy(port_cfg);
                return result;
        }

        result = doca_flow_port_cfg_set_nr_resources(port_cfg, DOCA_FLOW_RESOURCE_DECAP, nr_decap);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Port %u: failed to set decap resources=%u: %s", port_id, nr_decap,
                             doca_error_get_descr(result));
                doca_flow_port_cfg_destroy(port_cfg);
                return result;
        }

        /* Counters are required per-port because doca_flow_cfg_set_resource_mode
         * selects DOCA_FLOW_RESOURCE_MODE_PORT.  Pipes that declare
         * monitor.counter_type = NON_SHARED (UL/DL match pipes) draw one
         * counter per entry from this pool. */
        result = doca_flow_port_cfg_set_nr_resources(port_cfg, DOCA_FLOW_RESOURCE_COUNTER, nr_counters);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Port %u: failed to set counter resources=%u: %s", port_id, nr_counters,
                             doca_error_get_descr(result));
                doca_flow_port_cfg_destroy(port_cfg);
                return result;
        }

        DOCA_LOG_INFO("Port %u resources: actions_mem=%u encap=%u decap=%u meter=%u counters=%u", port_id, actions_mem,
                      nr_encap, nr_decap, nr_meter, nr_counters);

        result = doca_flow_port_start(port_cfg, port);
        doca_flow_port_cfg_destroy(port_cfg);
        return result;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Pipe builders
 * ═══════════════════════════════════════════════════════════════════════ */

/* ── TO_HOST pipe REMOVED ─────────────────────────────────────────────
 * In VNF mode, there is no host representor port.  Unmatched traffic
 * goes to default RSS on its ingress port.  The TO_HOST pipe, its
 * entry, and all references to host_vf_port_id are removed.
 * ────────────────────────────────────────────────────────────────────── */

/* ── TO_DPU_ARM_DL: RSS to ARM Rx queues for DL buffering ─────────── */
/*
 * Catch-all pipe on N6 port that forwards every DL packet to ARM via RSS.
 * Reached only through the per-bucket DL_*_BUFF_OVERRIDE pipes installed
 * on UpdateFAR(BUFF).  The pkt_meta set by the override entry is preserved
 * across RSS.
 *
 * In VNF mode, this pipe is owned by the N6 port (DL ingress).
 * UL buffering is intentionally suppressed per policy.
 */
static doca_error_t
build_to_dpu_arm_dl_pipe(dpu_pipeline_ctx_t *ctx) {
        doca_error_t result;
        struct doca_flow_pipe_cfg *pipe_cfg;

        result = doca_flow_pipe_cfg_create(&pipe_cfg, ctx->n6_port);
        if (result != DOCA_SUCCESS)
                return result;

        doca_flow_pipe_cfg_set_name(pipe_cfg, "TO_DPU_ARM_DL");
        doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);
        doca_flow_pipe_cfg_set_is_root(pipe_cfg, false);
        doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 1);

        struct doca_flow_match match = {};
        doca_flow_pipe_cfg_set_match(pipe_cfg, &match, NULL);

        struct doca_flow_actions actions = {};
        struct doca_flow_actions *actions_arr[] = {&actions};
        doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL, NULL, 1);

        struct doca_flow_fwd fwd = {
            .type = DOCA_FLOW_FWD_RSS,
            .rss_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED,
            .rss =
                {
                    .queues_array = ctx->n6_buffer_rss_queues,
                    .nr_queues = (int)ctx->nr_n6_buffer_rss_queues,
                    .outer_flags = DOCA_FLOW_RSS_IPV4 | DOCA_FLOW_RSS_UDP,
                },
        };

        result = doca_flow_pipe_create(pipe_cfg, &fwd, NULL, &ctx->to_dpu_arm_dl_pipe);
        doca_flow_pipe_cfg_destroy(pipe_cfg);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("TO_DPU_ARM_DL pipe creation failed: %s", doca_error_get_descr(result));
                return result;
        }

        /* Insert a single wildcard catch-all entry */
        struct doca_flow_pipe_entry *entry;
        result =
            doca_flow_pipe_basic_add_entry(0, ctx->to_dpu_arm_dl_pipe, &match, 0, &actions, NULL, &fwd, 0, NULL, &entry);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("TO_DPU_ARM_DL entry insert failed");
                return result;
        }

        doca_flow_entries_process(ctx->n6_port, 0, 0, 0);
        DOCA_LOG_INFO("TO_DPU_ARM_DL: RSS to %u ARM Rx queues (on N6 port)", ctx->nr_n6_buffer_rss_queues);
        return DOCA_SUCCESS;
}

/* ── DL override pipes: per-bucket buffering intercepts on N6 ──────── */
/*
 * Buffering uses parallel override pipes instead of mutating the base
 * DL_MATCH/DL_SDF_MATCH entry.  The override must preserve both the rule's
 * original specificity (src+dst vs dst-only) and its precedence position in
 * the DL chain, otherwise a BUFF on one rule can steal traffic from some
 * other higher-priority or broader rule for the same UE.
 *
 * Two families therefore mirror the base classifier:
 *
 *   DL_SDF_BUFF_OVERRIDE_Px  → exact src+dst, checked before DL_SDF_MATCH_Px
 *   DL_BUFF_OVERRIDE_Px      → dst-only,      checked before DL_MATCH_Px
 *
 * All hits forward to TO_DPU_ARM_DL.  fwd_miss continues into the next stage
 * of the original DL chain.  At FAST→BUFF, exactly one entry is added to the
 * override pipe corresponding to the buffered rule's original base pipe; at
 * BUFF→FORW, that entry is removed and the base entry remains untouched.
 */
static doca_error_t
build_one_dl_buff_override_pipe(dpu_pipeline_ctx_t *ctx, const char *name, bool with_src,
                                struct doca_flow_pipe *miss_target,
                                struct doca_flow_pipe **pipe_out) {
        struct doca_flow_pipe_cfg *pipe_cfg;
        doca_error_t result;

        if (ctx->to_dpu_arm_dl_pipe == NULL)
                return DOCA_ERROR_INVALID_VALUE;

        result = doca_flow_pipe_cfg_create(&pipe_cfg, ctx->n6_port);
        if (result != DOCA_SUCCESS)
                return result;

        doca_flow_pipe_cfg_set_name(pipe_cfg, name);
        doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);
        doca_flow_pipe_cfg_set_is_root(pipe_cfg, false);
        doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, ctx->match_entries_per_bucket);

        struct doca_flow_match match = {};
        match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
        match.outer.ip4.dst_ip = UINT32_MAX;
        if (with_src)
                match.outer.ip4.src_ip = UINT32_MAX;

        struct doca_flow_match mask = {};
        mask.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
        mask.outer.ip4.dst_ip = UINT32_MAX;
        if (with_src)
                mask.outer.ip4.src_ip = UINT32_MAX;

        doca_flow_pipe_cfg_set_match(pipe_cfg, &match, &mask);

        struct doca_flow_actions actions = {};
        actions.meta.pkt_meta = UINT32_MAX;
        struct doca_flow_actions *actions_arr[] = {&actions};
        doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL, NULL, 1);

        struct doca_flow_fwd fwd = {
            .type = DOCA_FLOW_FWD_PIPE,
            .next_pipe = ctx->to_dpu_arm_dl_pipe,
        };
        struct doca_flow_fwd fwd_miss = {
            .type = DOCA_FLOW_FWD_PIPE,
            .next_pipe = miss_target,
        };

        result = doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_miss, pipe_out);
        doca_flow_pipe_cfg_destroy(pipe_cfg);

        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("%s pipe creation failed: %s", name, doca_error_get_descr(result));
                return result;
        }

        DOCA_LOG_INFO("%s: hit→TO_DPU_ARM_DL, miss→next pipe", name);
        return DOCA_SUCCESS;
}

/* ── L2L3_RX: RSS → responder lcore (ARP) ──────────────────────────── */
/*
 * Catch-all pipe that forwards matched ARP traffic (classified by
 * the ROOT pipe via priority-5 match entries) to the responder lcore
 * on the ARM via RSS.
 *
 * In VNF mode, one L2L3_RX pipe is created per port that needs ARP
 * handling.  The port parameter determines pipe ownership.
 */
static doca_error_t
build_l2l3_rx_pipe(dpu_pipeline_ctx_t *ctx, struct doca_flow_port *port,
                   const char *name, uint16_t *rss_queues, uint32_t nr_rss_queues,
                   struct doca_flow_pipe **pipe_out) {
        doca_error_t result;
        struct doca_flow_pipe_cfg *pipe_cfg;

        result = doca_flow_pipe_cfg_create(&pipe_cfg, port);
        if (result != DOCA_SUCCESS)
                return result;

        doca_flow_pipe_cfg_set_name(pipe_cfg, name);
        doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);
        doca_flow_pipe_cfg_set_is_root(pipe_cfg, false);
        doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 1);

        struct doca_flow_match match = {};
        doca_flow_pipe_cfg_set_match(pipe_cfg, &match, NULL);

        struct doca_flow_actions actions = {};
        struct doca_flow_actions *actions_arr[] = {&actions};
        doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL, NULL, 1);

        struct doca_flow_fwd fwd = {
            .type = DOCA_FLOW_FWD_RSS,
            .rss_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED,
            .rss =
                {
                    .queues_array = rss_queues,
                    .nr_queues = (int)nr_rss_queues,
                    .outer_flags = 0,
                },
        };

        result = doca_flow_pipe_create(pipe_cfg, &fwd, NULL, pipe_out);
        doca_flow_pipe_cfg_destroy(pipe_cfg);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("%s pipe creation failed: %s", name, doca_error_get_descr(result));
                return result;
        }

        struct doca_flow_pipe_entry *entry;
        result = doca_flow_pipe_basic_add_entry(0, *pipe_out, &match, 0, &actions, NULL, &fwd, 0, NULL, &entry);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("%s entry insert failed", name);
                return result;
        }

        doca_flow_entries_process(port, 0, 0, 0);
        DOCA_LOG_INFO("%s: RSS to %u responder Rx queue(s)", name, nr_rss_queues);
        return DOCA_SUCCESS;
}

/* ── Color-gate POLICED: GREEN+YELLOW → pipe, RED → DROP ─────────── */
/*
 * MBR-only flows (GBR == 0).  Both GREEN and YELLOW traffic forwards
 * to the next pipe (UL_DECAP or DL_ENCAP) at line rate.
 * RED (above MBR) is dropped in HW.
 */
static doca_error_t
build_color_gate_policed_pipe(dpu_pipeline_ctx_t *ctx, struct doca_flow_port *port,
                              const char *name, struct doca_flow_pipe *fwd_pipe,
                              struct doca_flow_pipe **pipe_out) {
        doca_error_t result;
        struct doca_flow_pipe_cfg *pipe_cfg;

        result = doca_flow_pipe_cfg_create(&pipe_cfg, port);
        if (result != DOCA_SUCCESS)
                return result;

        doca_flow_pipe_cfg_set_name(pipe_cfg, name);
        doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);
        doca_flow_pipe_cfg_set_is_root(pipe_cfg, false);
        doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 4);

        struct doca_flow_match match = {};
        match.parser_meta.meter_color = UINT8_MAX;

        struct doca_flow_match mask = {};
        mask.parser_meta.meter_color = UINT8_MAX;

        doca_flow_pipe_cfg_set_match(pipe_cfg, &match, &mask);

        struct doca_flow_actions actions = {};
        struct doca_flow_actions *actions_arr[] = {&actions};
        doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL, NULL, 1);

        struct doca_flow_fwd fwd = {
            .type = DOCA_FLOW_FWD_PIPE,
            .next_pipe = fwd_pipe,
        };
        struct doca_flow_fwd fwd_miss = {
            .type = DOCA_FLOW_FWD_DROP,
        };

        result = doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_miss, pipe_out);
        doca_flow_pipe_cfg_destroy(pipe_cfg);
        if (result != DOCA_SUCCESS)
                return result;

        /* GREEN and YELLOW entries both forward */
        struct doca_flow_pipe_entry *entry;

        struct doca_flow_match green = {};
        green.parser_meta.meter_color = DOCA_FLOW_METER_COLOR_GREEN;
        result = doca_flow_pipe_basic_add_entry(0, *pipe_out, &green, 0, &actions, NULL, &fwd, 0, NULL, &entry);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("%s: GREEN entry failed", name);
                return result;
        }

        struct doca_flow_match yellow = {};
        yellow.parser_meta.meter_color = DOCA_FLOW_METER_COLOR_YELLOW;
        result = doca_flow_pipe_basic_add_entry(0, *pipe_out, &yellow, 0, &actions, NULL, &fwd, 0, NULL, &entry);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("%s: YELLOW entry failed", name);
                return result;
        }

        doca_flow_entries_process(port, 0, 0, 0);
        DOCA_LOG_INFO("%s: GREEN+YELLOW→pipe, RED→drop (POLICED)", name);
        return DOCA_SUCCESS;
}

/* ── Color-gate SHAPED: GREEN → pipe, YELLOW → ARM RSS, RED → DROP ── */
/*
 * GBR flows (GBR > 0).  GREEN traffic (≤ GBR) forwards to the EGRESS
 * pipe (UL_DECAP or DL_ENCAP) at line rate.
 * YELLOW traffic (between GBR and MBR) is redirected to ARM via RSS for
 * software token-bucket shaping at EIR = MBR − GBR.  RED → DROP.
 */
static doca_error_t
build_color_gate_shaped_pipe(dpu_pipeline_ctx_t *ctx, struct doca_flow_port *port,
                             const char *name, struct doca_flow_pipe *fwd_pipe,
                             uint16_t *rss_queues, uint32_t nr_rss_queues, struct doca_flow_pipe **pipe_out) {
        doca_error_t result;
        struct doca_flow_pipe_cfg *pipe_cfg;

        result = doca_flow_pipe_cfg_create(&pipe_cfg, port);
        if (result != DOCA_SUCCESS)
                return result;

        doca_flow_pipe_cfg_set_name(pipe_cfg, name);
        doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);
        doca_flow_pipe_cfg_set_is_root(pipe_cfg, false);
        doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 4);

        struct doca_flow_match match = {};
        match.parser_meta.meter_color = UINT8_MAX;

        struct doca_flow_match mask = {};
        mask.parser_meta.meter_color = UINT8_MAX;

        doca_flow_pipe_cfg_set_match(pipe_cfg, &match, &mask);

        struct doca_flow_actions actions = {};
        struct doca_flow_actions *actions_arr[] = {&actions};
        doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL, NULL, 1);

        /* Pipe-level fwd: CHANGEABLE allows different per-entry fwd types
         * (GREEN uses FWD_PORT, YELLOW uses FWD_RSS) */
        struct doca_flow_fwd fwd_changeable = {
            .type = DOCA_FLOW_FWD_CHANGEABLE,
        };
        struct doca_flow_fwd fwd_miss = {
            .type = DOCA_FLOW_FWD_DROP,
        };

        result = doca_flow_pipe_create(pipe_cfg, &fwd_changeable, &fwd_miss, pipe_out);
        doca_flow_pipe_cfg_destroy(pipe_cfg);
        if (result != DOCA_SUCCESS)
                return result;

        struct doca_flow_pipe_entry *entry;

        /* GREEN → next pipe (UL_DECAP or DL_ENCAP) */
        struct doca_flow_fwd fwd_wire = {
            .type = DOCA_FLOW_FWD_PIPE,
            .next_pipe = fwd_pipe,
        };
        struct doca_flow_match green = {};
        green.parser_meta.meter_color = DOCA_FLOW_METER_COLOR_GREEN;
        result = doca_flow_pipe_basic_add_entry(0, *pipe_out, &green, 0, &actions, NULL, &fwd_wire, 0, NULL, &entry);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("%s: GREEN entry failed", name);
                return result;
        }

        /* YELLOW → RSS to ARM shaper Rx queues */
        struct doca_flow_fwd fwd_rss = {
            .type = DOCA_FLOW_FWD_RSS,
            .rss_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED,
            .rss =
                {
                    .queues_array = rss_queues,
                    .nr_queues = (int)nr_rss_queues,
                    .outer_flags = DOCA_FLOW_RSS_IPV4 | DOCA_FLOW_RSS_UDP,
                },
        };
        struct doca_flow_match yellow = {};
        yellow.parser_meta.meter_color = DOCA_FLOW_METER_COLOR_YELLOW;
        result = doca_flow_pipe_basic_add_entry(0, *pipe_out, &yellow, 0, &actions, NULL, &fwd_rss, 0, NULL, &entry);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("%s: YELLOW entry failed", name);
                return result;
        }

        doca_flow_entries_process(port, 0, 0, 0);
        DOCA_LOG_INFO("%s: GREEN→pipe, YELLOW→ARM RSS(%u queues), RED→drop (SHAPED)", name, nr_rss_queues);
        return DOCA_SUCCESS;
}

/* ── UL_MATCH pipes (4 priority buckets) ──────────────────────────── */
/*
 * Each pipe matches: GTP TEID + QFI + UE IP (inner src_ip).
 * SDF fields (dst_ip, proto, ports) are wildcarded at the pipe level.
 * Actions: GTP decap + L2 inject + pkt_meta + shared meter.
 * Chain: P0.miss → P1 → P2 → P3.miss → DROP (VNF: unmatched → default RSS).
 */
static doca_error_t
build_ul_match_pipes(dpu_pipeline_ctx_t *ctx) {
        doca_error_t result;

        /* Build from lowest priority (P3) up to highest (P0) */
        for (int p = NUM_PRIO_BUCKETS - 1; p >= 0; p--) {
                struct doca_flow_pipe_cfg *pipe_cfg;
                result = doca_flow_pipe_cfg_create(&pipe_cfg, ctx->n3_port);
                if (result != DOCA_SUCCESS)
                        return result;

                char name[32];
                snprintf(name, sizeof(name), "UL_MATCH_P%d", p);
                doca_flow_pipe_cfg_set_name(pipe_cfg, name);
                doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);
                doca_flow_pipe_cfg_set_is_root(pipe_cfg, false);
                doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, ctx->match_entries_per_bucket);

                /* Match: TEID + UE IP (CHANGEABLE per-entry).
                 * QFI is intentionally NOT matched — the UPF-C sends qfi=0
                 * as a wildcard sentinel, but DOCA Flow has no per-entry
                 * wildcard mechanism for pipe-level exact-match fields.
                 * Matching on QFI would require knowing the exact wire value
                 * at rule-insertion time, which the control plane doesn't
                 * guarantee.  TEID + UE IP is sufficient for session
                 * disambiguation.
                 * SDF fields (dst_ip, proto, ports) are intentionally omitted so
                 * that their pipe-level mask is 0 → IGNORED (wildcard).  This
                 * allows catch-all PDRs with no SDF filter to match all traffic. */
                struct doca_flow_match match = {};
                match.tun.type = DOCA_FLOW_TUN_GTPU;
                match.tun.gtp_teid = UINT32_MAX;
                match.inner.l3_type = DOCA_FLOW_L3_TYPE_IP4;
                match.inner.ip4.src_ip = UINT32_MAX; /* UE IP */

                struct doca_flow_match mask = {};
                mask.tun.type = DOCA_FLOW_TUN_GTPU;
                mask.tun.gtp_teid = UINT32_MAX;
                mask.inner.l3_type = DOCA_FLOW_L3_TYPE_IP4;
                mask.inner.ip4.src_ip = UINT32_MAX;

                doca_flow_pipe_cfg_set_match(pipe_cfg, &match, &mask);

                /* Actions: pkt_meta only.
                 * GTP decap is split into a separate UL_DECAP pipe to stay
                 * within the BF3 ARGUMENT_64B hardware descriptor limit.
                 * REFORMAT + pkt_meta + meter + changeable fwd exceeded 64B
                 * when combined in one pipe. */
                struct doca_flow_actions actions = {};
                actions.meta.pkt_meta = UINT32_MAX; /* changeable per-entry */

                struct doca_flow_actions *actions_arr[] = {&actions};
                doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL, NULL, 1);

                /* Monitor: shared meter + non-shared counter per entry */
                struct doca_flow_monitor monitor = {};
                monitor.meter_type = DOCA_FLOW_RESOURCE_TYPE_SHARED;
                monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
                doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor);

                /* Hit → CHANGEABLE (per-entry fast-path target: UL color gate
                 * or direct UL_DECAP when no meter is attached). */
                struct doca_flow_fwd fwd = {
                    .type = DOCA_FLOW_FWD_CHANGEABLE,
                };

                /* Miss → next lower priority bucket, or DROP (VNF mode) */
                struct doca_flow_fwd fwd_miss;
                if (p == NUM_PRIO_BUCKETS - 1) {
                        fwd_miss.type = DOCA_FLOW_FWD_DROP;
                } else {
                        fwd_miss.type = DOCA_FLOW_FWD_PIPE;
                        fwd_miss.next_pipe = ctx->ul_match_pipes[p + 1];
                }

                result = doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_miss, &ctx->ul_match_pipes[p]);
                doca_flow_pipe_cfg_destroy(pipe_cfg);

                if (result != DOCA_SUCCESS) {
                        DOCA_LOG_ERR("%s pipe creation failed: %s", name, doca_error_get_descr(result));
                        return result;
                }

                DOCA_LOG_INFO("%s: hit→CHANGEABLE(UL_COLOR_GATE), miss→%s", name,
                              (p == NUM_PRIO_BUCKETS - 1) ? "DROP" : "next bucket");
        }

        return DOCA_SUCCESS;
}

/* ── DL match pipes — two interleaved families (4 priority buckets each) ─ */
/*
 * Two parallel pipe families on N6 to support per-source SDF rules without
 * losing the catch-all dst-only behavior:
 *
 *   DL_SDF_MATCH_Px → matches outer src_ip + dst_ip (peer-specific entries)
 *   DL_MATCH_Px     → matches outer dst_ip only (catch-all UE entries)
 *
 * DOCA Flow BASIC pipes use a single pipe-template mask, so a "src wildcard"
 * entry and a "src exact" entry cannot share one pipe.  Two families is the
 * minimum-disruption fix and preserves precedence ordering across buckets:
 *
 *   N6_ROOT → DL_SDF_MATCH[0] → DL_MATCH[0] → DL_SDF_MATCH[1] → DL_MATCH[1] →
 *             … → DL_SDF_MATCH[3] → DL_MATCH[3] → DROP
 *
 * Within one bucket, an SDF (src+dst) rule wins over a dst-only rule — desired.
 *
 * Build order is reversed (lowest-priority first) so each pipe's fwd_miss
 * target already exists when we create it.
 */
static doca_error_t
build_one_dl_match_pipe(dpu_pipeline_ctx_t *ctx, const char *name, bool with_src,
                        struct doca_flow_pipe *miss_target,
                        struct doca_flow_pipe **pipe_out) {
        struct doca_flow_pipe_cfg *pipe_cfg;
        doca_error_t result = doca_flow_pipe_cfg_create(&pipe_cfg, ctx->n6_port);
        if (result != DOCA_SUCCESS)
                return result;

        doca_flow_pipe_cfg_set_name(pipe_cfg, name);
        doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);
        doca_flow_pipe_cfg_set_is_root(pipe_cfg, false);
        doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, ctx->match_entries_per_bucket);

        /* Match template.  with_src=false → dst-only (catch-all), src wildcarded
         * at pipe level (mask=0).  with_src=true → exact src+dst, peer-specific. */
        struct doca_flow_match match = {};
        match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
        match.outer.ip4.dst_ip = UINT32_MAX;
        if (with_src)
                match.outer.ip4.src_ip = UINT32_MAX;

        struct doca_flow_match mask = {};
        mask.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
        mask.outer.ip4.dst_ip = UINT32_MAX;
        if (with_src)
                mask.outer.ip4.src_ip = UINT32_MAX;

        doca_flow_pipe_cfg_set_match(pipe_cfg, &match, &mask);

        struct doca_flow_actions actions = {};
        actions.meta.pkt_meta = UINT32_MAX;
        struct doca_flow_actions *actions_arr[] = {&actions};
        doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL, NULL, 1);

        struct doca_flow_monitor monitor = {};
        monitor.meter_type = DOCA_FLOW_RESOURCE_TYPE_SHARED;
        monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
        doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor);

        struct doca_flow_fwd fwd = {
            .type = DOCA_FLOW_FWD_CHANGEABLE,
        };

        struct doca_flow_fwd fwd_miss;
        if (miss_target == NULL) {
                fwd_miss.type = DOCA_FLOW_FWD_DROP;
        } else {
                fwd_miss.type = DOCA_FLOW_FWD_PIPE;
                fwd_miss.next_pipe = miss_target;
        }

        result = doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_miss, pipe_out);
        doca_flow_pipe_cfg_destroy(pipe_cfg);

        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("%s pipe creation failed: %s", name, doca_error_get_descr(result));
                return result;
        }

        DOCA_LOG_INFO("%s: hit→CHANGEABLE(DL_COLOR_GATE), miss→%s", name,
                      (miss_target == NULL) ? "DROP" : "next pipe");
        return DOCA_SUCCESS;
}

static doca_error_t
build_dl_match_pipes(dpu_pipeline_ctx_t *ctx) {
        doca_error_t result;
        char name[32];
        const bool buffering_enabled = (ctx->to_dpu_arm_dl_pipe != NULL);

        /* Lowest-priority first.  Without buffering the chain is:
         *   DL_SDF_MATCH[p] -> DL_MATCH[p] -> next bucket
         *
         * With buffering enabled, per-bucket override pipes are inserted
         * immediately ahead of their matching base pipes:
         *   DL_SDF_BUFF_OVERRIDE[p] -> DL_SDF_MATCH[p] ->
         *   DL_BUFF_OVERRIDE[p]     -> DL_MATCH[p]     -> next bucket
         *
         * Build in reverse dependency order so every miss target already
         * exists when we create the next pipe. */
        struct doca_flow_pipe *prev_chain_head = NULL; /* bucket (p+1) head, or NULL for DROP */

        for (int p = NUM_PRIO_BUCKETS - 1; p >= 0; p--) {
                snprintf(name, sizeof(name), "DL_MATCH_P%d", p);
                result = build_one_dl_match_pipe(ctx, name, /*with_src=*/false, prev_chain_head,
                                                 &ctx->dl_match_pipes[p]);
                if (result != DOCA_SUCCESS)
                        return result;

                if (buffering_enabled) {
                        snprintf(name, sizeof(name), "DL_BUFF_OVERRIDE_P%d", p);
                        result = build_one_dl_buff_override_pipe(ctx, name, /*with_src=*/false,
                                                                 ctx->dl_match_pipes[p],
                                                                 &ctx->dl_buff_override_pipes[p]);
                        if (result != DOCA_SUCCESS)
                                return result;

                        snprintf(name, sizeof(name), "DL_SDF_MATCH_P%d", p);
                        result = build_one_dl_match_pipe(ctx, name, /*with_src=*/true,
                                                         ctx->dl_buff_override_pipes[p],
                                                         &ctx->dl_sdf_match_pipes[p]);
                        if (result != DOCA_SUCCESS)
                                return result;

                        snprintf(name, sizeof(name), "DL_SDF_BUFF_OVERRIDE_P%d", p);
                        result = build_one_dl_buff_override_pipe(ctx, name, /*with_src=*/true,
                                                                 ctx->dl_sdf_match_pipes[p],
                                                                 &ctx->dl_sdf_buff_override_pipes[p]);
                        if (result != DOCA_SUCCESS)
                                return result;

                        prev_chain_head = ctx->dl_sdf_buff_override_pipes[p];
                } else {
                        snprintf(name, sizeof(name), "DL_SDF_MATCH_P%d", p);
                        result = build_one_dl_match_pipe(ctx, name, /*with_src=*/true, ctx->dl_match_pipes[p],
                                                         &ctx->dl_sdf_match_pipes[p]);
                        if (result != DOCA_SUCCESS)
                                return result;

                        prev_chain_head = ctx->dl_sdf_match_pipes[p];
                }
        }

        return DOCA_SUCCESS;
}

/* ── UL_DECAP pipe (DEFAULT domain on N3 port) ──────────────────────── */
/*
 * Non-root pipe on N3 port (DEFAULT domain).  Performs GTP-U decap
 * with L2 header injection (src=upf_n6_mac, dst=dn_gw_mac, type=0x0800)
 * and forwards the resulting plain IPv4 packet to the N6 wire port
 * via FWD_PORT(1) through doca_flow_port_pair().
 *
 * VNF mode: DEFAULT domain, owned by N3 port.  FWD_PORT with port_id=1
 * sends the packet out the paired N6 port's wire interface.
 *
 * Decap + L2 injection is split from UL_MATCH to stay within the
 * BF3 ARGUMENT_64B hardware descriptor limit.  UL_MATCH handles
 * pkt_meta + meter; UL_DECAP handles the reformat.
 *
 * Reached from: UL_COLOR_GATE (FWD_PIPE) and N3_ROOT reinject.
 *
 * Data-plane path:
 *   UL_MATCH → meter+meta → UL_COLOR_GATE →(FWD_PIPE)→ UL_DECAP → decap → N6 wire
 *   Reinject: N3_ROOT prio2 →(FWD_PIPE)→ UL_DECAP → decap → N6 wire
 */
static doca_error_t
build_ul_decap_pipe(dpu_pipeline_ctx_t *ctx) {
        doca_error_t result;
        struct doca_flow_pipe_cfg *pipe_cfg;

        result = doca_flow_pipe_cfg_create(&pipe_cfg, ctx->n3_port);
        if (result != DOCA_SUCCESS)
                return result;

        doca_flow_pipe_cfg_set_name(pipe_cfg, "UL_DECAP");
        doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);
        doca_flow_pipe_cfg_set_is_root(pipe_cfg, false);
        /* DEFAULT domain (VNF mode) — FWD_PORT routes to the paired port. */
        doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 1);

        /* Match: GTP-U tunnel type — always true for traffic entering this pipe,
         * since only UL color gates and UL reinject forward here. */
        struct doca_flow_match match = {};
        match.tun.type = DOCA_FLOW_TUN_GTPU;

        struct doca_flow_match mask = {};
        mask.tun.type = DOCA_FLOW_TUN_GTPU;

        doca_flow_pipe_cfg_set_match(pipe_cfg, &match, &mask);

        /* Actions: GTP decap + L2 header injection (static).
         * is_l2=false → inner packet is L3 (no MAC inside GTP) → inject new L2.
         * src_mac = UPF N6 MAC, dst_mac = DN gateway MAC, type = 0x0800 (IPv4). */
        struct doca_flow_actions actions = {};
        actions.decap_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
        actions.decap_cfg.is_l2 = false;

        memcpy(actions.decap_cfg.eth.src_mac, ctx->port_cfg.upf_n6_mac, 6);
        memcpy(actions.decap_cfg.eth.dst_mac, ctx->port_cfg.dn_gw_mac, 6);
        actions.decap_cfg.eth.type = RTE_BE16(0x0800);

        struct doca_flow_actions *actions_arr[] = {&actions};
        doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL, NULL, 1);

        struct doca_flow_monitor monitor = {};
        monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
        doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor);

        /* Forward: out the N6 wire port via port_pair.
         * In VNF mode, FWD_PORT with port_id=1 (N6) sends the packet
         * to the paired port's wire interface. */
        struct doca_flow_fwd fwd = {
            .type = DOCA_FLOW_FWD_PORT,
            .port_id = DPU_PORT_ID_N6,
        };

        /* Miss → NULL.  This pipe has a single catch-all GTP-U entry that
         * matches everything forwarded here, so miss should never trigger. */

        result = doca_flow_pipe_create(pipe_cfg, &fwd, NULL, &ctx->ul_decap_pipe);
        doca_flow_pipe_cfg_destroy(pipe_cfg);

        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("UL_DECAP pipe creation failed: %s", doca_error_get_descr(result));
                return result;
        }

        /* Single catch-all entry: all GTP-U traffic gets decapped */
        struct doca_flow_match entry_match = {};
        entry_match.tun.type = DOCA_FLOW_TUN_GTPU;

        struct doca_flow_monitor entry_mon = {};
        entry_mon.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;

        struct doca_flow_pipe_entry *entry;
        result = doca_flow_pipe_basic_add_entry(0, ctx->ul_decap_pipe, &entry_match, 0, &actions, &entry_mon, NULL, 0,
                                                NULL, &entry);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("UL_DECAP: catch-all entry failed: %s", doca_error_get_descr(result));
                return result;
        }

        ctx->ul_decap_entry = entry;

        doca_flow_entries_process(ctx->n3_port, 0, 0, 0);
        DOCA_LOG_INFO("UL_DECAP: DEFAULT non-root (N3 port) — GTP decap + L2 inject → N6 (1 entry)");
        return DOCA_SUCCESS;
}

/* ── N3 EGRESS pass-through pipe ──────────────────────────────────
 *
 * Sits in EGRESS on N3 as a non-root CONTROL pipe with one catch-all
 * entry that FWD_PORTs to N3 (its own wire).  Its sole purpose is to
 * be DL_ENCAP's `fwd_miss` target: any non-DL-encap egress traffic
 * (ARP responder replies, future mgmt frames) lands here and is
 * passed through to the wire unchanged.
 *
 * Why this pipe is needed: when DL_ENCAP becomes the EGRESS root of
 * N3 (required — DEFAULT-domain GTP encap doesn't finalise lengths
 * on this HW), every packet Tx'd on N3 is funnelled through it.
 * Packets without a pkt_meta matching any DL rule miss the encap
 * pipe; HWS rejects `fwd_miss = FWD_PORT` (type 2 invalid) but does
 * accept `fwd_miss = FWD_PIPE`, so we hop into this pipe and exit
 * via its FWD_PORT entry.
 *
 * Must be built BEFORE build_dl_encap_pipe so DL_ENCAP can reference
 * its handle in fwd_miss.
 */
static doca_error_t
build_n3_egress_passthrough_pipe(dpu_pipeline_ctx_t *ctx) {
        doca_error_t result;
        struct doca_flow_pipe_cfg *pipe_cfg;

        result = doca_flow_pipe_cfg_create(&pipe_cfg, ctx->n3_port);
        if (result != DOCA_SUCCESS)
                return result;

        doca_flow_pipe_cfg_set_name(pipe_cfg, "N3_EGRESS_PASSTHROUGH");
        doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_CONTROL);
        doca_flow_pipe_cfg_set_is_root(pipe_cfg, false);
        doca_flow_pipe_cfg_set_domain(pipe_cfg, DOCA_FLOW_PIPE_DOMAIN_EGRESS);

        result = doca_flow_pipe_create(pipe_cfg, NULL, NULL,
                                       &ctx->n3_egress_passthrough_pipe);
        doca_flow_pipe_cfg_destroy(pipe_cfg);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("N3_EGRESS_PASSTHROUGH pipe creation failed: %s",
                             doca_error_get_descr(result));
                return result;
        }

        /* Catch-all entry: empty match + empty mask → matches every packet.
         * FWD_PORT to N3 = exit out the wire unchanged. */
        struct doca_flow_match m = {};
        struct doca_flow_match mm = {};
        struct doca_flow_fwd fwd = {
            .type = DOCA_FLOW_FWD_PORT,
            .port_id = DPU_PORT_ID_N3,
        };
        struct doca_flow_pipe_entry *entry;
        result = doca_flow_pipe_control_add_entry(0, ctx->n3_egress_passthrough_pipe,
                                                  &m, &mm, NULL, NULL, NULL, NULL,
                                                  NULL, 0, &fwd, NULL, &entry);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("N3_EGRESS_PASSTHROUGH catch-all entry failed: %s",
                             doca_error_get_descr(result));
                return result;
        }
        doca_flow_entries_process(ctx->n3_port, 0, 0, 0);
        DOCA_LOG_INFO("N3_EGRESS_PASSTHROUGH: catch-all → FWD_PORT(N3 wire)");
        return DOCA_SUCCESS;
}

/* ── DL_ENCAP pipe (EGRESS, root, on N3) ──────────────────────────
 *
 * GTP-U + PSC encap of DL traffic.  Required to be in EGRESS on the
 * port the packet leaves through (N3): DEFAULT-domain GTP encap on
 * this HW does NOT finalise the GTP length / UDP src port fields,
 * producing malformed packets that crash UERANSIM gNB
 * (std::length_error).  Every NVIDIA sample (flow_gtp_encap, upf_accel)
 * places GTP encap in EGRESS for the same reason.
 *
 * Pattern (from flow_gtp_encap_sample.c):
 *   ingress classifier (N6 DEFAULT)  →  FWD_PIPE  →
 *   DL_ENCAP (N3 EGRESS, is_root=true) → encap → FWD_PORT(N3 wire)
 *
 * Cross-port + cross-domain forwarding is allowed only INTO an
 * egress_root — DL_ENCAP is exactly that.
 *
 * fwd_miss = FWD_PIPE(N3_EGRESS_PASSTHROUGH).  Any Tx on N3 that
 * doesn't match a DL rule (ARP replies, mgmt) falls through to the
 * passthrough pipe and exits unchanged.  See passthrough builder
 * above for the reasoning.
 */
static doca_error_t
build_dl_encap_pipe(dpu_pipeline_ctx_t *ctx) {
        doca_error_t result;
        struct doca_flow_pipe_cfg *pipe_cfg;

        /* Owned by N3 — this is the EGRESS side of DL traffic. */
        result = doca_flow_pipe_cfg_create(&pipe_cfg, ctx->n3_port);
        if (result != DOCA_SUCCESS)
                return result;

        doca_flow_pipe_cfg_set_name(pipe_cfg, "DL_ENCAP");
        doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);
        doca_flow_pipe_cfg_set_is_root(pipe_cfg, true);
        doca_flow_pipe_cfg_set_domain(pipe_cfg, DOCA_FLOW_PIPE_DOMAIN_EGRESS);
        doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, ctx->dl_encap_entries);

        /* Match pkt_meta (changeable) — mask ignores reinject bits 0-1
         * so both normal DL and DL-reinject match the same encap entry */
        struct doca_flow_match match = {};
        match.meta.pkt_meta = UINT32_MAX;

        struct doca_flow_match mask = {};
        mask.meta.pkt_meta = ~REINJECT_BITS_MASK; /* 0xFFFFFFFC */

        doca_flow_pipe_cfg_set_match(pipe_cfg, &match, &mask);

        /* Action: GTP-U encapsulation with PSC extension.
         *
         * IMPORTANT: include version_ihl and next_proto on the outer IPv4,
         * and src_port on the outer UDP.  Without those fields the HW
         * encap engine emits version/IHL = 0 and proto = 0, which (per
         * NVIDIA's upf_accel sample) signals "headers are pre-built, do
         * not finalise lengths" — so the GTP length field stays at 0 and
         * UERANSIM aborts on the malformed packet.  src_port also needs
         * an explicit value or HW falls back to an ephemeral port. */
        struct doca_flow_actions actions = {};
        actions.encap_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;

        /* Outer Ethernet */
        memcpy(actions.encap_cfg.encap.outer.eth.src_mac, ctx->port_cfg.upf_n3_mac, 6);
        memcpy(actions.encap_cfg.encap.outer.eth.dst_mac, ctx->port_cfg.gnb_mac, 6);
        actions.encap_cfg.encap.outer.eth.type = RTE_BE16(0x0800);

        /* Outer IPv4 */
        actions.encap_cfg.encap.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
        actions.encap_cfg.encap.outer.ip4.version_ihl = 0x45;            /* IPv4, IHL=5 */
        actions.encap_cfg.encap.outer.ip4.next_proto = DOCA_FLOW_PROTO_UDP;
        actions.encap_cfg.encap.outer.ip4.src_ip = ctx->port_cfg.upf_n3_ip;
        actions.encap_cfg.encap.outer.ip4.dst_ip = UINT32_MAX; /* changeable */
        actions.encap_cfg.encap.outer.ip4.ttl = 64;

        /* Outer UDP — set BOTH ports.  3GPP recommends src_port=2152 too. */
        actions.encap_cfg.encap.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
        actions.encap_cfg.encap.outer.udp.l4_port.src_port = RTE_BE16(GTP_UDP_PORT);
        actions.encap_cfg.encap.outer.udp.l4_port.dst_port = RTE_BE16(GTP_UDP_PORT);

        /* GTP-U tunnel + PSC extension */
        actions.encap_cfg.encap.tun.type = DOCA_FLOW_TUN_GTPU;
        actions.encap_cfg.encap.tun.gtp_teid = UINT32_MAX;               /* changeable */
        actions.encap_cfg.encap.tun.gtp_next_ext_hdr_type = GTP_EXT_PSC; /* PSC 0x85 */
        actions.encap_cfg.encap.tun.gtp_ext_psc_qfi = UINT8_MAX;         /* changeable */

        struct doca_flow_actions *actions_arr[] = {&actions};
        doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL, NULL, 1);

        /* Forward: after encap, exit out N3's own wire.  port_id == self
         * is the natural egress target for an EGRESS root pipe — same
         * pattern as flow_gtp_encap (fwd.port_id = port_id on the encap
         * pipe owned by the egress port). */
        struct doca_flow_fwd fwd = {
            .type = DOCA_FLOW_FWD_PORT,
            .port_id = DPU_PORT_ID_N3,
        };

        /* Miss → FWD_PIPE(passthrough).  This pipe is the egress_root of
         * N3, so EVERY Tx on N3 traverses it — including ARP responder
         * replies whose pkt_meta doesn't match any DL rule.  HWS rejects
         * `fwd_miss = FWD_PORT` (type 2 invalid), so we hop into a tiny
         * non-root passthrough pipe whose only entry FWD_PORTs to the N3
         * wire.  Net effect is identical to "exit unchanged". */
        struct doca_flow_fwd fwd_miss = {
            .type = DOCA_FLOW_FWD_PIPE,
            .next_pipe = ctx->n3_egress_passthrough_pipe,
        };

        result = doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_miss, &ctx->dl_encap_pipe);
        doca_flow_pipe_cfg_destroy(pipe_cfg);

        if (result != DOCA_SUCCESS)
                DOCA_LOG_ERR("DL_ENCAP pipe creation failed: %s", doca_error_get_descr(result));
        else
                DOCA_LOG_INFO("DL_ENCAP: EGRESS root on N3 — pkt_meta → GTP encap + PSC → FWD_PORT(N3 wire), miss → passthrough (%u entries)",
                              ctx->dl_encap_entries);
        return result;
}

/* ── Per-port ROOT control pipes (VNF mode) ─────────────────────────── */
static doca_error_t
build_n3_root_pipe(dpu_pipeline_ctx_t *ctx) {
        doca_error_t result;
        struct doca_flow_pipe_cfg *pipe_cfg;
        result = doca_flow_pipe_cfg_create(&pipe_cfg, ctx->n3_port);
        if (result != DOCA_SUCCESS) return result;
        doca_flow_pipe_cfg_set_name(pipe_cfg, "N3_ROOT");
        doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_CONTROL);
        doca_flow_pipe_cfg_set_is_root(pipe_cfg, true);
        result = doca_flow_pipe_create(pipe_cfg, NULL, NULL, &ctx->n3_root_pipe);
        doca_flow_pipe_cfg_destroy(pipe_cfg);
        if (result != DOCA_SUCCESS) return result;

        /* Prio 0: GTP-U → UL_MATCH[0] */
        {
                struct doca_flow_match match = {};
                match.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
                match.outer.udp.l4_port.dst_port = RTE_BE16(GTP_UDP_PORT);
                struct doca_flow_match mask = {};
                mask.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
                mask.outer.udp.l4_port.dst_port = UINT16_MAX;
                struct doca_flow_fwd fwd = { .type = DOCA_FLOW_FWD_PIPE, .next_pipe = ctx->ul_match_pipes[0] };
                struct doca_flow_pipe_entry *entry;
                result = doca_flow_pipe_control_add_entry(0, ctx->n3_root_pipe, &match, &mask, NULL, NULL, NULL, NULL,
                                                          NULL, 0, &fwd, NULL, &entry);
                if (result != DOCA_SUCCESS) { DOCA_LOG_ERR("N3_ROOT: UL entry failed"); return result; }
        }
        doca_flow_entries_process(ctx->n3_port, 0, 0, 0);
        DOCA_LOG_INFO("N3_ROOT: prio 0 GTP-U → UL_MATCH[0]");

        /* Prio 2: UL reinject */
        if (ctx->to_dpu_arm_dl_pipe != NULL) {
                struct doca_flow_match rmatch = {};
                rmatch.meta.pkt_meta = REINJECT_MARKER_BIT | REINJECT_UL_DIR_BIT;
                struct doca_flow_match rmask = {};
                rmask.meta.pkt_meta = REINJECT_BITS_MASK;
                struct doca_flow_fwd rfwd = { .type = DOCA_FLOW_FWD_PIPE, .next_pipe = ctx->ul_decap_pipe };
                struct doca_flow_pipe_entry *re;
                result = doca_flow_pipe_control_add_entry(0, ctx->n3_root_pipe, &rmatch, &rmask, NULL, NULL, NULL,
                                                          NULL, NULL, 2, &rfwd, NULL, &re);
                if (result != DOCA_SUCCESS) { DOCA_LOG_ERR("N3_ROOT: UL reinject failed"); return result; }
                doca_flow_entries_process(ctx->n3_port, 0, 0, 0);
                DOCA_LOG_INFO("N3_ROOT: prio 2 — UL reinject → UL_DECAP");
        }

        /* Prio 5: ARP from wire → L2L3_RX_N3 (RSS to responder lcore).
         *
         * VNF-mode note: no prio-4 responder-reinject entry is needed here.
         * In switch mode, software-Tx'd replies re-entered the eSwitch and
         * needed a ROOT entry to FWD_PORT them to the right wire.  In VNF
         * mode, rte_eth_tx_burst on the N3 ethdev goes straight out the N3
         * wire — there is no ingress-side re-entry.  The responder simply
         * Tx's on its dedicated Tx queue; the pkt_meta marker is harmless
         * but unused. */
        if (ctx->l2l3_rx_n3_pipe != NULL && ctx->port_cfg.upf_n3_ip != 0) {
                /* Match by ethertype rather than parser_meta.outer_l3_type ==
                 * NONE.  parser_meta works on N3 in current testing but the
                 * symmetric N6 entry never fires from a cold start (DN's
                 * initial ARP doesn't get answered).  Switching to an explicit
                 * eth.type == 0x0806 match removes any HW-side parser quirk
                 * from the equation and is also the pattern dpu_pipeline_backed.c
                 * was using before. */
                struct doca_flow_match am = {};
                am.outer.eth.type = RTE_BE16(0x0806);
                struct doca_flow_match amm = {};
                amm.outer.eth.type = UINT16_MAX;
                struct doca_flow_monitor amon = {};
                amon.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
                struct doca_flow_fwd to_l2l3 = { .type = DOCA_FLOW_FWD_PIPE, .next_pipe = ctx->l2l3_rx_n3_pipe };
                result = doca_flow_pipe_control_add_entry(0, ctx->n3_root_pipe, &am, &amm, NULL, NULL, NULL, NULL,
                                                          &amon, 5, &to_l2l3, NULL, &ctx->root_arp_n3_entry);
                if (result != DOCA_SUCCESS) { DOCA_LOG_ERR("N3_ROOT: ARP failed"); return result; }
                DOCA_LOG_INFO("N3_ROOT: prio 5 — ARP (eth.type=0x0806) → L2L3_RX_N3");
                doca_flow_entries_process(ctx->n3_port, 0, 0, 0);
        }
        return DOCA_SUCCESS;
}

static doca_error_t
build_n6_root_pipe(dpu_pipeline_ctx_t *ctx) {
        doca_error_t result;
        struct doca_flow_pipe_cfg *pipe_cfg;
        result = doca_flow_pipe_cfg_create(&pipe_cfg, ctx->n6_port);
        if (result != DOCA_SUCCESS) return result;
        doca_flow_pipe_cfg_set_name(pipe_cfg, "N6_ROOT");
        doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_CONTROL);
        doca_flow_pipe_cfg_set_is_root(pipe_cfg, true);
        result = doca_flow_pipe_create(pipe_cfg, NULL, NULL, &ctx->n6_root_pipe);
        doca_flow_pipe_cfg_destroy(pipe_cfg);
        if (result != DOCA_SUCCESS) return result;

        /* Prio 0: IPv4 → DL chain head.  When DL buffering is provisioned,
         * route through the bucket-0 SDF override head; otherwise wire
         * straight to the legacy bucket-0 SDF base pipe. */
        {
                struct doca_flow_pipe *dl_head =
                    (ctx->to_dpu_arm_dl_pipe != NULL) ? ctx->dl_sdf_buff_override_pipes[0]
                                                       : ctx->dl_sdf_match_pipes[0];
                const char *dl_head_name =
                    (ctx->to_dpu_arm_dl_pipe != NULL) ? "DL_SDF_BUFF_OVERRIDE[0]"
                                                      : "DL_SDF_MATCH[0]";

                struct doca_flow_match match = {};
                match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
                struct doca_flow_match mask = {};
                mask.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
                struct doca_flow_fwd fwd = { .type = DOCA_FLOW_FWD_PIPE, .next_pipe = dl_head };
                struct doca_flow_pipe_entry *entry;
                result = doca_flow_pipe_control_add_entry(0, ctx->n6_root_pipe, &match, &mask, NULL, NULL, NULL, NULL,
                                                          NULL, 0, &fwd, NULL, &entry);
                if (result != DOCA_SUCCESS) { DOCA_LOG_ERR("N6_ROOT: DL entry failed"); return result; }
                doca_flow_entries_process(ctx->n6_port, 0, 0, 0);
                DOCA_LOG_INFO("N6_ROOT: prio 0 IPv4 → %s", dl_head_name);
        }

        /* Prio 2: DL reinject */
        if (ctx->to_dpu_arm_dl_pipe != NULL) {
                struct doca_flow_match rmatch = {};
                rmatch.meta.pkt_meta = REINJECT_MARKER_BIT;
                struct doca_flow_match rmask = {};
                rmask.meta.pkt_meta = REINJECT_BITS_MASK;
                struct doca_flow_fwd rfwd = { .type = DOCA_FLOW_FWD_PIPE, .next_pipe = ctx->dl_encap_pipe };
                struct doca_flow_pipe_entry *re;
                result = doca_flow_pipe_control_add_entry(0, ctx->n6_root_pipe, &rmatch, &rmask, NULL, NULL, NULL,
                                                          NULL, NULL, 2, &rfwd, NULL, &re);
                if (result != DOCA_SUCCESS) { DOCA_LOG_ERR("N6_ROOT: DL reinject failed"); return result; }
                doca_flow_entries_process(ctx->n6_port, 0, 0, 0);
                DOCA_LOG_INFO("N6_ROOT: prio 2 — DL reinject → DL_ENCAP");
        }

        /* Prio 5: ARP from wire → L2L3_RX_N6 (RSS to responder lcore).
         * Match by ethertype (see N3_ROOT for rationale).  If the counter
         * still stays at 0 after this change, the asymmetry is at the
         * firmware/flood-domain layer rather than the parser. */
        if (ctx->l2l3_rx_n6_pipe != NULL && ctx->port_cfg.upf_n6_ip != 0) {
                struct doca_flow_match am = {};
                am.outer.eth.type = RTE_BE16(0x0806);
                struct doca_flow_match amm = {};
                amm.outer.eth.type = UINT16_MAX;
                struct doca_flow_monitor amon = {};
                amon.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
                struct doca_flow_fwd to_l2l3 = { .type = DOCA_FLOW_FWD_PIPE, .next_pipe = ctx->l2l3_rx_n6_pipe };
                result = doca_flow_pipe_control_add_entry(0, ctx->n6_root_pipe, &am, &amm, NULL, NULL, NULL, NULL,
                                                          &amon, 5, &to_l2l3, NULL, &ctx->root_arp_n6_entry);
                if (result != DOCA_SUCCESS) { DOCA_LOG_ERR("N6_ROOT: ARP failed"); return result; }
                DOCA_LOG_INFO("N6_ROOT: prio 5 — ARP (eth.type=0x0806) → L2L3_RX_N6");
                doca_flow_entries_process(ctx->n6_port, 0, 0, 0);
        }
        return DOCA_SUCCESS;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Meter creation helper (trTCM RFC 2698)
 * ═══════════════════════════════════════════════════════════════════════ */

/**
 * Create a shared trTCM meter (CIR=GBR, PIR=MBR).
 * Returns NO_METER_ID if both rates are 0 (no QER → skip metering).
 *
 * NOTE (VNF-mode meter port): In VNF mode, meters are allocated on the
 * port that owns the pipe that carries the monitor.  Callers pick via
 * port_for_direction(): UL meters → n3_port, DL meters → n6_port.
 * NVIDIA meter samples (flow_shared_meter, upf_accel) follow the same
 * pattern.  Per-port meter capacity is set via port_nr_meter at port cfg.
 */
static doca_error_t
create_trtcm_meter(struct doca_flow_port *port, uint32_t *meter_id, uint64_t gbr_kbps, uint64_t mbr_kbps) {
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
        cfg.meter_cfg.rfc2698.pir = pir_bps;
        cfg.meter_cfg.rfc2698.pbs = (pir_bps / 100 > 4096) ? pir_bps / 100 : 4096;

        result = doca_flow_port_shared_resource_get(port, DOCA_FLOW_SHARED_RESOURCE_METER, meter_id);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Meter alloc failed: %s", doca_error_get_descr(result));
                return result;
        }

        result = doca_flow_port_shared_resource_set_cfg(port, DOCA_FLOW_SHARED_RESOURCE_METER, *meter_id, &cfg);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Meter %u config failed: %s", *meter_id, doca_error_get_descr(result));
        }
        return result;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Public API: Initialise the pipeline
 * ═══════════════════════════════════════════════════════════════════════ */

doca_error_t
dpu_pipeline_create_ports(dpu_pipeline_ctx_t *ctx, const dpu_port_cfg_t *port_cfg,
                          uint16_t *n6_buffer_rss_queues, uint32_t nr_n6_buffer_rss_queues,
                          uint16_t *n3_shaper_rss_queues, uint32_t nr_n3_shaper_rss_queues,
                          uint16_t *n6_shaper_rss_queues, uint32_t nr_n6_shaper_rss_queues,
                          uint16_t *n3_responder_rss_queues, uint32_t nr_n3_responder_rss_queues,
                          uint16_t *n6_responder_rss_queues, uint32_t nr_n6_responder_rss_queues) {
        doca_error_t result;

        /* Save capacity config (set by caller before this call) */
        uint32_t save_max_hw_rules = ctx->max_hw_rules;
        uint32_t save_nr_counters = ctx->nr_counters;
        uint32_t save_nr_meters = ctx->nr_meters;
        uint32_t save_nr_shared_meters = ctx->nr_shared_meters;
        uint32_t save_port_nr_encap = ctx->port_nr_encap;
        uint32_t save_port_nr_decap = ctx->port_nr_decap;
        uint32_t save_port_nr_meter = ctx->port_nr_meter;
        uint32_t save_port_actions_mem = ctx->port_actions_mem;
        uint32_t save_match_entries_per_bucket = ctx->match_entries_per_bucket;
        uint32_t save_dl_encap_entries = ctx->dl_encap_entries;

        memset(ctx, 0, sizeof(*ctx));

        /* Restore capacity config */
        ctx->max_hw_rules = save_max_hw_rules;
        ctx->nr_counters = save_nr_counters;
        ctx->nr_meters = save_nr_meters;
        ctx->nr_shared_meters = save_nr_shared_meters;
        ctx->port_nr_encap = save_port_nr_encap;
        ctx->port_nr_decap = save_port_nr_decap;
        ctx->port_nr_meter = save_port_nr_meter;
        ctx->port_actions_mem = save_port_actions_mem;
        ctx->match_entries_per_bucket = save_match_entries_per_bucket;
        ctx->dl_encap_entries = save_dl_encap_entries;

        ctx->port_cfg = *port_cfg;

        /* ── Heap-allocate rule records ─────────────────────────────────── */
        ctx->rules = calloc(ctx->max_hw_rules, sizeof(dpu_rule_record_t));
        if (!ctx->rules) {
                DOCA_LOG_ERR("Failed to allocate %u rule records", ctx->max_hw_rules);
                return DOCA_ERROR_NO_MEMORY;
        }

        /* ── rte_hash for O(1) rule lookup by hw_rule_id ────────────── */
        struct rte_hash_parameters hash_params = {
            .name = "pipeline_rule_id_map",
            .entries = ctx->max_hw_rules,
            .key_len = sizeof(uint32_t),
            .hash_func = rte_jhash,
            .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY,
        };
        ctx->rule_id_map = rte_hash_create(&hash_params);
        if (!ctx->rule_id_map) {
                DOCA_LOG_ERR("Failed to create rule_id_map rte_hash");
                free(ctx->rules);
                ctx->rules = NULL;
                return DOCA_ERROR_NO_MEMORY;
        }

        /* Store per-port RSS configs.  The queue indices refer to Rx queues
         * on each port's own DPDK ethdev (set up by dpu_agent.c before this). */

        /* N6 DL buffer RSS (TO_DPU_ARM_DL pipe target) */
        if (n6_buffer_rss_queues && nr_n6_buffer_rss_queues > 0) {
                uint32_t n = (nr_n6_buffer_rss_queues > BUFFER_RX_QUEUES) ? BUFFER_RX_QUEUES
                                                                         : nr_n6_buffer_rss_queues;
                for (uint32_t i = 0; i < n; i++)
                        ctx->n6_buffer_rss_queues[i] = n6_buffer_rss_queues[i];
                ctx->nr_n6_buffer_rss_queues = n;
        }

        /* N3 UL shaper RSS (UL_COLOR_GATE_SHAPED YELLOW target) */
        if (n3_shaper_rss_queues && nr_n3_shaper_rss_queues > 0) {
                uint32_t n = (nr_n3_shaper_rss_queues > SHAPER_RX_QUEUES) ? SHAPER_RX_QUEUES
                                                                         : nr_n3_shaper_rss_queues;
                for (uint32_t i = 0; i < n; i++)
                        ctx->n3_shaper_rss_queues[i] = n3_shaper_rss_queues[i];
                ctx->nr_n3_shaper_rss_queues = n;
        }

        /* N6 DL shaper RSS (DL_COLOR_GATE_SHAPED YELLOW target) */
        if (n6_shaper_rss_queues && nr_n6_shaper_rss_queues > 0) {
                uint32_t n = (nr_n6_shaper_rss_queues > SHAPER_RX_QUEUES) ? SHAPER_RX_QUEUES
                                                                         : nr_n6_shaper_rss_queues;
                for (uint32_t i = 0; i < n; i++)
                        ctx->n6_shaper_rss_queues[i] = n6_shaper_rss_queues[i];
                ctx->nr_n6_shaper_rss_queues = n;
        }

        /* N3 ARP responder RSS */
        if (n3_responder_rss_queues && nr_n3_responder_rss_queues > 0) {
                uint32_t n = (nr_n3_responder_rss_queues > RESPONDER_RX_QUEUES) ? RESPONDER_RX_QUEUES
                                                                                : nr_n3_responder_rss_queues;
                for (uint32_t i = 0; i < n; i++)
                        ctx->n3_responder_rss_queues[i] = n3_responder_rss_queues[i];
                ctx->nr_n3_responder_rss_queues = n;
        }

        /* N6 ARP responder RSS */
        if (n6_responder_rss_queues && nr_n6_responder_rss_queues > 0) {
                uint32_t n = (nr_n6_responder_rss_queues > RESPONDER_RX_QUEUES) ? RESPONDER_RX_QUEUES
                                                                                : nr_n6_responder_rss_queues;
                for (uint32_t i = 0; i < n; i++)
                        ctx->n6_responder_rss_queues[i] = n6_responder_rss_queues[i];
                ctx->nr_n6_responder_rss_queues = n;
        }

        /* pipe_queues must be >= the max Rx-queue count among started ports.
         * N6 hosts the most RSS endpoints (buffer + shaper + responder), so
         * N6_RX_QUEUES is the upper bound.  The caller configures both PFs
         * with this many Rx queues (extra queues on N3 are harmless). */
        uint32_t pq = N6_RX_QUEUES;

        result = init_doca_flow(pq, ctx->nr_counters, ctx->nr_meters, ctx->nr_shared_meters);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("DOCA Flow init failed (pipe_queues=%u): %s", pq, doca_error_get_descr(result));
                rte_hash_free(ctx->rule_id_map);
                free(ctx->rules);
                ctx->rules = NULL;
                ctx->rule_id_map = NULL;
                return result;
        }

        /* Create ports — VNF mode: 2 physical ports, no host representor */
        result = create_port(port_cfg->n3_port_id, port_cfg->n3_dev, NULL, ctx->port_nr_encap, ctx->port_nr_decap,
                             ctx->port_nr_meter, ctx->nr_counters, ctx->port_actions_mem, &ctx->n3_port);
        if (result != DOCA_SUCCESS)
                return result;

        result = create_port(port_cfg->n6_port_id, port_cfg->n6_dev, NULL, ctx->port_nr_encap, ctx->port_nr_decap,
                             ctx->port_nr_meter, ctx->nr_counters, ctx->port_actions_mem, &ctx->n6_port);
        if (result != DOCA_SUCCESS)
                return result;

        /* VNF mode: pair the two physical ports for cross-port forwarding.
         * Pairing is unidirectional per DOCA 3.3 docs, so we call it twice.
         * After pairing, FWD_PORT with port_id=DPU_PORT_ID_N6 from a pipe on
         * N3 sends the packet out N6's wire, and vice versa. */
        result = doca_flow_port_pair(ctx->n3_port, ctx->n6_port);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("doca_flow_port_pair(N3, N6) failed: %s", doca_error_get_descr(result));
                return result;
        }
        result = doca_flow_port_pair(ctx->n6_port, ctx->n3_port);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("doca_flow_port_pair(N6, N3) failed: %s", doca_error_get_descr(result));
                return result;
        }

        DOCA_LOG_INFO("DOCA Flow VNF ports created and paired: N3(port %u) <-> N6(port %u)",
                      port_cfg->n3_port_id, port_cfg->n6_port_id);
        return DOCA_SUCCESS;
}

doca_error_t
dpu_pipeline_build_pipes(dpu_pipeline_ctx_t *ctx) {
        doca_error_t result;

        /* Build pipes in dependency order (VNF mode) */
        uint32_t pipe_count = 15; /* UL_DECAP + N3_EGRESS_PASSTHROUGH + DL_ENCAP + UL/DL POLICED + UL/DL MATCH(4+4) + N3_ROOT + N6_ROOT */
        if (ctx->nr_n6_buffer_rss_queues > 0)
                pipe_count += 1 + (2 * NUM_PRIO_BUCKETS); /* TO_DPU_ARM_DL + per-bucket DL override pipes */
        if (ctx->nr_n3_shaper_rss_queues > 0)
                pipe_count++; /* UL shaped gate */
        if (ctx->nr_n6_shaper_rss_queues > 0)
                pipe_count++; /* DL shaped gate */
        if (ctx->nr_n3_responder_rss_queues > 0)
                pipe_count++; /* L2L3_RX_N3 */
        if (ctx->nr_n6_responder_rss_queues > 0)
                pipe_count++; /* L2L3_RX_N6 */
        DOCA_LOG_INFO("Building %u-pipe hierarchy (VNF mode)...", pipe_count);

        /* TO_DPU_ARM_DL: DL buffer pipe on N6 port (built early, before match pipes) */
        if (ctx->nr_n6_buffer_rss_queues > 0) {
                result = build_to_dpu_arm_dl_pipe(ctx);
                if (result != DOCA_SUCCESS)
                        return result;
        }

        /* L2L3_RX: per-port ARP responder pipe (built before ROOT) */
        if (ctx->nr_n3_responder_rss_queues > 0) {
                result = build_l2l3_rx_pipe(ctx, ctx->n3_port, "L2L3_RX_N3",
                                            ctx->n3_responder_rss_queues, ctx->nr_n3_responder_rss_queues,
                                            &ctx->l2l3_rx_n3_pipe);
                if (result != DOCA_SUCCESS)
                        return result;
        }
        if (ctx->nr_n6_responder_rss_queues > 0) {
                result = build_l2l3_rx_pipe(ctx, ctx->n6_port, "L2L3_RX_N6",
                                            ctx->n6_responder_rss_queues, ctx->nr_n6_responder_rss_queues,
                                            &ctx->l2l3_rx_n6_pipe);
                if (result != DOCA_SUCCESS)
                        return result;
        }

        /* UL_DECAP: non-root on N3 port (fwd → N6) */
        result = build_ul_decap_pipe(ctx);
        if (result != DOCA_SUCCESS)
                return result;

        /* N3_EGRESS_PASSTHROUGH must be built before DL_ENCAP — DL_ENCAP's
         * fwd_miss references this pipe.  See build_n3_egress_passthrough_pipe
         * for the rationale (non-DL Tx on N3 needs a wire-exit fall-through). */
        result = build_n3_egress_passthrough_pipe(ctx);
        if (result != DOCA_SUCCESS)
                return result;

        /* DL_ENCAP: EGRESS root on N3 (GTP encap; required to live in EGRESS
         * for HW length finalisation).  Cross-port + cross-domain forwarding
         * from DL_MATCH/DL_COLOR_GATE on N6 (DEFAULT) is permitted because
         * DL_ENCAP is the egress_root. */
        result = build_dl_encap_pipe(ctx);
        if (result != DOCA_SUCCESS)
                return result;

        /* POLICED color gates: per-port */
        result = build_color_gate_policed_pipe(ctx, ctx->n3_port, "UL_COLOR_GATE_POLICED", ctx->ul_decap_pipe,
                                               &ctx->ul_color_gate_policed_pipe);
        if (result != DOCA_SUCCESS)
                return result;

        result = build_color_gate_policed_pipe(ctx, ctx->n6_port, "DL_COLOR_GATE_POLICED", ctx->dl_encap_pipe,
                                               &ctx->dl_color_gate_policed_pipe);
        if (result != DOCA_SUCCESS)
                return result;

        /* SHAPED color gates: per-port */
        if (ctx->nr_n3_shaper_rss_queues > 0) {
                result = build_color_gate_shaped_pipe(ctx, ctx->n3_port, "UL_COLOR_GATE_SHAPED", ctx->ul_decap_pipe,
                                                      ctx->n3_shaper_rss_queues, ctx->nr_n3_shaper_rss_queues,
                                                      &ctx->ul_color_gate_shaped_pipe);
                if (result != DOCA_SUCCESS)
                        return result;
        }
        if (ctx->nr_n6_shaper_rss_queues > 0) {
                result = build_color_gate_shaped_pipe(ctx, ctx->n6_port, "DL_COLOR_GATE_SHAPED", ctx->dl_encap_pipe,
                                                      ctx->n6_shaper_rss_queues, ctx->nr_n6_shaper_rss_queues,
                                                      &ctx->dl_color_gate_shaped_pipe);
                if (result != DOCA_SUCCESS)
                        return result;
        }

        result = build_ul_match_pipes(ctx);
        if (result != DOCA_SUCCESS)
                return result;

        /* DL chain: base match pipes always; when buffering is provisioned,
         * per-bucket override pipes are built interleaved immediately ahead
         * of their corresponding base pipes. */
        result = build_dl_match_pipes(ctx);
        if (result != DOCA_SUCCESS)
                return result;

        /* Per-port ROOT pipes (must be built last — references all other pipes) */
        result = build_n3_root_pipe(ctx);
        if (result != DOCA_SUCCESS)
                return result;

        result = build_n6_root_pipe(ctx);
        if (result != DOCA_SUCCESS)
                return result;

        DOCA_LOG_INFO("Pipeline initialised: %u pipes, 2 ports (VNF)%s%s%s", pipe_count,
                      ctx->nr_n6_buffer_rss_queues > 0 ? ", DL buffering enabled" : "",
                      (ctx->nr_n3_shaper_rss_queues > 0 || ctx->nr_n6_shaper_rss_queues > 0)
                          ? ", shaping enabled"
                          : "",
                      (ctx->nr_n3_responder_rss_queues > 0 || ctx->nr_n6_responder_rss_queues > 0)
                          ? ", ARP responder enabled"
                          : "");
        return DOCA_SUCCESS;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Public API: Insert a rule from hw_offload_msg
 * ═══════════════════════════════════════════════════════════════════════ */

doca_error_t
dpu_pipeline_insert_rule(dpu_pipeline_ctx_t *ctx, const hw_offload_msg_t *msg) {
        doca_error_t result;

        if (!msg || msg->magic != HW_OFFLOAD_MAGIC) {
                DOCA_LOG_ERR("insert_rule: invalid message");
                return DOCA_ERROR_INVALID_VALUE;
        }

        /* Guard: reject hw_rule_id values whose htonl representation has
         * bits 0-1 set — these would collide with reinject markers and
         * cause DL_ENCAP pkt_meta aliasing (mask 0xFFFFFFFC). */
        if (htonl(msg->hw_rule_id) & REINJECT_BITS_MASK) {
                DOCA_LOG_ERR(
                    "insert_rule: hw_rule_id=%u unsafe — "
                    "htonl(id)=0x%08x has low bits set (reinject collision)",
                    msg->hw_rule_id, htonl(msg->hw_rule_id));
                return DOCA_ERROR_INVALID_VALUE;
        }

        /* Guard: reject duplicate hw_rule_id (24-bit wrapping can collide
         * with a still-active rule after 16.7M allocations) */
        if (find_record(ctx, msg->hw_rule_id)) {
                DOCA_LOG_ERR(
                    "insert_rule: hw_rule_id=%u already active — "
                    "ID collision after 24-bit wrap",
                    msg->hw_rule_id);
                return DOCA_ERROR_ALREADY_EXIST;
        }

        /* Guard: reject unsupported OHC types for DL rules.
         * Only GTP-U/UDP/IPv4 encap is implemented.  Unsupported types
         * (IPv6, UDP-only) must stay on the SW fallback path. */
        if (msg->direction == HW_DIR_DOWNLINK && msg->ohc_desc != HW_OHC_NONE &&
            msg->ohc_desc != HW_OHC_GTPU_UDP_IPV4) {
                DOCA_LOG_WARN(
                    "insert_rule: unsupported OHC type %u for DL "
                    "hw_rule_id=%u — keeping rule on SW path",
                    msg->ohc_desc, msg->hw_rule_id);
                return DOCA_ERROR_NOT_SUPPORTED;
        }

        /* Select priority bucket from 3GPP precedence */
        int bucket = precedence_to_bucket(msg->precedence);

        if (msg->direction == HW_DIR_UPLINK) {
                /* ── UPLINK ──────────────────────────────────────────────────── */

                /* Meter: skip if no QER (GBR + MBR both 0) */
                uint32_t meter_id;
                result = create_trtcm_meter(ctx->n3_port, &meter_id, msg->gbr_ul, msg->mbr_ul);
                if (result != DOCA_SUCCESS)
                        return result;

                /* Match: TEID + UE IP only (QFI excluded — see pipe comment).
                 * SDF fields are wildcarded at the pipe level (mask=0).
                 * Inner source: UE IP by default, exact-/32 SDF source when
                 * distinct (ul_inner_src_ip_for_msg). */
                struct doca_flow_match match = {};
                match.tun.type = DOCA_FLOW_TUN_GTPU;
                match.tun.gtp_teid = htonl(msg->teid);
                match.inner.l3_type = DOCA_FLOW_L3_TYPE_IP4;

                uint32_t ul_inner_src_ip = ul_inner_src_ip_for_msg(msg);
                match.inner.ip4.src_ip = ul_inner_src_ip;

                /* Actions: pkt_meta only (decap is in UL_DECAP pipe) */
                struct doca_flow_actions actions = {};
                actions.meta.pkt_meta = htonl(msg->hw_rule_id);

                /* Monitor: non-shared counter always; shared meter if QER present */
                struct doca_flow_monitor monitor = {};
                monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
                if (meter_id != NO_METER_ID) {
                        monitor.meter_type = DOCA_FLOW_RESOURCE_TYPE_SHARED;
                        monitor.shared_meter.shared_meter_id = meter_id;
                }

                /* Per-entry fwd: forward to color gate if metered, else skip directly to DECAP */
                bool ul_is_gbr = (msg->gbr_ul > 0 && ctx->ul_color_gate_shaped_pipe != NULL);
                struct doca_flow_pipe *next_pipe;
                if (meter_id == NO_METER_ID) {
                        next_pipe = ctx->ul_decap_pipe;
                } else {
                        next_pipe = ul_is_gbr ? ctx->ul_color_gate_shaped_pipe : ctx->ul_color_gate_policed_pipe;
                }
                struct doca_flow_fwd ul_fwd = {
                    .type = DOCA_FLOW_FWD_PIPE,
                    .next_pipe = next_pipe,
                };

                struct doca_flow_pipe_entry *entry;
                result = doca_flow_pipe_basic_add_entry(0, ctx->ul_match_pipes[bucket], &match, 0, &actions, &monitor,
                                                        &ul_fwd, 0, NULL, &entry);
                if (result != DOCA_SUCCESS) {
                        DOCA_LOG_ERR("UL entry failed hw_rule_id=%u bucket=%d: %s", msg->hw_rule_id, bucket,
                                     doca_error_get_descr(result));
                        if (meter_id != NO_METER_ID)
                                doca_flow_port_shared_resource_put(ctx->n3_port, DOCA_FLOW_SHARED_RESOURCE_METER,
                                                                   meter_id);
                        return result;
                }

                doca_flow_entries_process(ctx->n3_port, 0, 0, 0);

                /* Store entry handle in record for future update/delete */
                dpu_rule_record_t *rec = alloc_record(ctx, msg->hw_rule_id);
                if (!rec) {
                        DOCA_LOG_ERR("UL rule pool exhausted for hw_rule_id=%u", msg->hw_rule_id);
                        doca_flow_pipe_remove_entry(0, DOCA_FLOW_NO_WAIT, entry);
                        doca_flow_entries_process(ctx->n3_port, 0, 0, 0);
                        if (meter_id != NO_METER_ID)
                                doca_flow_port_shared_resource_put(ctx->n3_port, DOCA_FLOW_SHARED_RESOURCE_METER,
                                                                   meter_id);
                        return DOCA_ERROR_FULL;
                }
                rec->in_use = true;
                rec->hw_rule_id = msg->hw_rule_id;
                rec->ul_entry = entry;
                rec->dl_entry = NULL;
                rec->dl_encap_entry = NULL;
                rec->pipe_bucket = (uint8_t)bucket;
                rec->direction = HW_DIR_UPLINK;
                rec->current_mode = DPU_MODE_FAST;
                rec->meter_id = meter_id;
                rec->is_gbr_flow = ul_is_gbr;

                struct in_addr ul_match_src = { .s_addr = ul_inner_src_ip };
                DOCA_LOG_INFO(
                    "UL rule: hw_rule=%u teid=0x%x qfi=%u bucket=P%d "
                    "inner_src=%s meter=%s gbr=%s",
                    msg->hw_rule_id, msg->teid, msg->qfi, bucket,
                    inet_ntoa(ul_match_src),
                    (meter_id != NO_METER_ID) ? "yes" : "none",
                    ul_is_gbr ? "shaped" : "policed");

        } else {
                /* ── DOWNLINK ────────────────────────────────────────────────── */

                uint32_t meter_id;
                result = create_trtcm_meter(ctx->n6_port, &meter_id, msg->gbr_dl, msg->mbr_dl);
                if (result != DOCA_SUCCESS)
                        return result;

                /* Pick the DL pipe family.  Peer-specific SDF rules with an
                 * exact source (/32) go into DL_SDF_MATCH (matches src+dst);
                 * everything else goes into DL_MATCH (matches dst only).
                 *
                 * Reduced-coverage caveat: SDF rules with proto/ports/non-/32
                 * prefixes still install in the dst-only pipe and may
                 * over-match.  Warn once per such insert so it's visible. */
                const bool dl_use_sdf_pipe = (msg->has_sdf && msg->sdf_src_pref == 32);
                if (msg->has_sdf && !dl_use_sdf_pipe) {
                        DOCA_LOG_WARN(
                            "DL hw_rule=%u: SDF present but not exact-/32 source — "
                            "installing in dst-only DL_MATCH (over-match possible). "
                            "src_pref=%u proto=%u sports=%u dports=%u",
                            msg->hw_rule_id, msg->sdf_src_pref, msg->sdf_proto,
                            msg->sdf_src_port, msg->sdf_dst_port);
                }
                struct doca_flow_pipe *dl_pipe = dl_use_sdf_pipe
                                                         ? ctx->dl_sdf_match_pipes[bucket]
                                                         : ctx->dl_match_pipes[bucket];

                /* DL match entry.  dst_ip is always the UE.  In the SDF pipe we
                 * also pin src_ip to the SDF source (HOST order in the wire msg,
                 * NBO at the DOCA Flow API). */
                struct doca_flow_match dl_match = {};
                dl_match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
                dl_match.outer.ip4.dst_ip = msg->ue_ipv4.s_addr; /* NBO */
                if (dl_use_sdf_pipe)
                        dl_match.outer.ip4.src_ip = htonl(msg->sdf_src_ip);

                struct doca_flow_actions dl_actions = {};
                dl_actions.meta.pkt_meta = htonl(msg->hw_rule_id);

                struct doca_flow_monitor dl_monitor = {};
                dl_monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
                if (meter_id != NO_METER_ID) {
                        dl_monitor.meter_type = DOCA_FLOW_RESOURCE_TYPE_SHARED;
                        dl_monitor.shared_meter.shared_meter_id = meter_id;
                }

                /* Per-entry fwd: forward to color gate if metered, else skip directly to ENCAP */
                bool dl_is_gbr = (msg->gbr_dl > 0 && ctx->dl_color_gate_shaped_pipe != NULL);
                struct doca_flow_pipe *next_pipe;
                if (meter_id == NO_METER_ID) {
                        next_pipe = ctx->dl_encap_pipe;
                } else {
                        next_pipe = dl_is_gbr ? ctx->dl_color_gate_shaped_pipe : ctx->dl_color_gate_policed_pipe;
                }
                struct doca_flow_fwd dl_fwd = {
                    .type = DOCA_FLOW_FWD_PIPE,
                    .next_pipe = next_pipe,
                };

                struct doca_flow_pipe_entry *dl_entry;
                result = doca_flow_pipe_basic_add_entry(0, dl_pipe, &dl_match, 0, &dl_actions,
                                                        &dl_monitor, &dl_fwd, 0, NULL, &dl_entry);
                if (result != DOCA_SUCCESS) {
                        DOCA_LOG_ERR("%s entry failed hw_rule_id=%u bucket=%d: %s",
                                     dl_use_sdf_pipe ? "DL_SDF_MATCH" : "DL_MATCH",
                                     msg->hw_rule_id, bucket, doca_error_get_descr(result));
                        if (meter_id != NO_METER_ID)
                                doca_flow_port_shared_resource_put(ctx->n6_port, DOCA_FLOW_SHARED_RESOURCE_METER,
                                                                   meter_id);
                        return result;
                }

                /* Allocate record early so we can store DL + ENCAP handles together */
                dpu_rule_record_t *rec = alloc_record(ctx, msg->hw_rule_id);
                if (!rec) {
                        DOCA_LOG_ERR("DL rule pool exhausted for hw_rule_id=%u", msg->hw_rule_id);
                        doca_flow_pipe_remove_entry(0, DOCA_FLOW_NO_WAIT, dl_entry);
                        doca_flow_entries_process(ctx->n6_port, 0, 0, 0);
                        if (meter_id != NO_METER_ID)
                                doca_flow_port_shared_resource_put(ctx->n6_port, DOCA_FLOW_SHARED_RESOURCE_METER,
                                                                   meter_id);
                        return DOCA_ERROR_FULL;
                }
                rec->in_use = true;
                rec->hw_rule_id = msg->hw_rule_id;
                rec->ul_entry = NULL;
                rec->dl_entry = dl_entry;
                rec->dl_encap_entry = NULL;
                rec->pipe_bucket = (uint8_t)bucket;
                rec->direction = HW_DIR_DOWNLINK;
                rec->current_mode = DPU_MODE_FAST;
                rec->meter_id = meter_id;
                rec->is_gbr_flow = dl_is_gbr;
                rec->is_dl_sdf_match = dl_use_sdf_pipe;

                /* Cache the match for FORW reinsert (see cached_dl_match
                 * comment in dpu_pipeline.h).  Exactly the values passed to
                 * doca_flow_pipe_basic_add_entry above. */
                rec->cached_dl_match = dl_match;

                /* DL_ENCAP entry: pkt_meta → GTP encap (actions built by the
                 * shared helper — see build_dl_encap_actions). */
                if (msg->ohc_desc == HW_OHC_GTPU_UDP_IPV4) {
                        struct doca_flow_match encap_match = {};
                        encap_match.meta.pkt_meta = htonl(msg->hw_rule_id);

                        struct doca_flow_actions encap_actions;
                        build_dl_encap_actions(ctx, msg->ohc_ipv4.s_addr,
                                               msg->ohc_teid, msg->encap_qfi,
                                               &encap_actions);

                        struct doca_flow_pipe_entry *encap_entry;
                        result = doca_flow_pipe_basic_add_entry(0, ctx->dl_encap_pipe, &encap_match, 0, &encap_actions,
                                                                NULL, NULL, 0, NULL, &encap_entry);
                        if (result != DOCA_SUCCESS) {
                                DOCA_LOG_ERR("DL_ENCAP entry failed hw_rule_id=%u: %s", msg->hw_rule_id,
                                             doca_error_get_descr(result));
                                /* Roll back DL_MATCH entry, record, and meter */
                                doca_flow_pipe_remove_entry(0, DOCA_FLOW_NO_WAIT, dl_entry);
                                doca_flow_entries_process(ctx->n6_port, 0, 0, 0);
                                if (meter_id != NO_METER_ID)
                                        doca_flow_port_shared_resource_put(ctx->n6_port,
                                                                           DOCA_FLOW_SHARED_RESOURCE_METER, meter_id);
                                free_record(ctx, rec);
                                return result;
                        }
                        rec->dl_encap_entry = encap_entry;
                        /* Cache the encap params for the buffer drain lcore's
                         * SW GTP-U + PSC encap path (BUFF→FORW handover). */
                        rec->ohc_ipv4 = msg->ohc_ipv4.s_addr;
                        rec->ohc_teid = msg->ohc_teid;
                        rec->encap_qfi = msg->encap_qfi;
                }

                /* DL_MATCH lives on N6; DL_ENCAP lives on N3 (EGRESS root).
                 * Order matters: commit N3 (DL_ENCAP entry) FIRST, then N6
                 * (DL_MATCH entry).  Reversed, a wire packet can briefly
                 * pass through a DL_MATCH whose target DL_ENCAP entry is
                 * not yet installed → miss → passthrough → exit N3 wire
                 * un-encapped.  Forward order eliminates that window. */
                doca_flow_entries_process(ctx->n3_port, 0, 0, 0);
                doca_flow_entries_process(ctx->n6_port, 0, 0, 0);

                DOCA_LOG_INFO(
                    "DL rule: hw_rule=%u ue_ip=%s ohc_teid=0x%x "
                    "bucket=P%d pipe=%s meter=%s gbr=%s",
                    msg->hw_rule_id, inet_ntoa(msg->ue_ipv4), msg->ohc_teid, bucket,
                    dl_use_sdf_pipe ? "DL_SDF_MATCH" : "DL_MATCH",
                    (meter_id != NO_METER_ID) ? "yes" : "none", dl_is_gbr ? "shaped" : "policed");
        }

        ctx->nb_entries++;
        return DOCA_SUCCESS;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Public API: Delete a rule
 * ═══════════════════════════════════════════════════════════════════════ */

doca_error_t
dpu_pipeline_delete_rule(dpu_pipeline_ctx_t *ctx, uint32_t hw_rule_id) {
        dpu_rule_record_t *rec = find_record(ctx, hw_rule_id);
        if (!rec) {
                DOCA_LOG_WARN("delete_rule: hw_rule_id=%u not found", hw_rule_id);
                return DOCA_ERROR_NOT_FOUND;
        }

        doca_error_t result;
        bool any_remove_failed = false;

        /* Remove DOCA Flow entries (UL or DL+ENCAP).
         * On success, null out the handle so a retry after partial failure
         * skips already-removed entries instead of double-removing. */

        /* If the rule is currently in BUFFER mode, also tear down its
         * matching DL_*_BUFF_OVERRIDE entry.  Both this and the base
         * DL_MATCH entry are queued for removal and committed by the trailing
         * entries_process() — the rule is going away regardless, so commit
         * ordering between them does not affect correctness. */
        if (rec->buff_override_entry) {
                result = doca_flow_pipe_remove_entry(0, DOCA_FLOW_NO_WAIT, rec->buff_override_entry);
                if (result != DOCA_SUCCESS) {
                        DOCA_LOG_ERR("delete_rule: BUFF_OVERRIDE remove failed hw_rule_id=%u: %s",
                                     hw_rule_id, doca_error_get_descr(result));
                        any_remove_failed = true;
                } else {
                        rec->buff_override_entry = NULL;
                }
        }

        if (rec->ul_entry) {
                result = doca_flow_pipe_remove_entry(0, DOCA_FLOW_NO_WAIT, rec->ul_entry);
                if (result != DOCA_SUCCESS) {
                        DOCA_LOG_ERR("delete_rule: UL remove failed hw_rule_id=%u: %s", hw_rule_id,
                                     doca_error_get_descr(result));
                        any_remove_failed = true;
                } else {
                        rec->ul_entry = NULL;
                }
        }
        if (rec->dl_entry) {
                result = doca_flow_pipe_remove_entry(0, DOCA_FLOW_NO_WAIT, rec->dl_entry);
                if (result != DOCA_SUCCESS) {
                        DOCA_LOG_ERR("delete_rule: DL remove failed hw_rule_id=%u: %s", hw_rule_id,
                                     doca_error_get_descr(result));
                        any_remove_failed = true;
                } else {
                        rec->dl_entry = NULL;
                }
        }
        if (rec->dl_encap_entry) {
                result = doca_flow_pipe_remove_entry(0, DOCA_FLOW_NO_WAIT, rec->dl_encap_entry);
                if (result != DOCA_SUCCESS) {
                        DOCA_LOG_ERR("delete_rule: ENCAP remove failed hw_rule_id=%u: %s", hw_rule_id,
                                     doca_error_get_descr(result));
                        any_remove_failed = true;
                } else {
                        rec->dl_encap_entry = NULL;
                }
        }

        doca_flow_entries_process(port_for_direction(ctx, rec->direction), 0, 0, 0);
        /* DL_ENCAP entries live on N3 (EGRESS root), so for DL deletes we
         * also need to commit N3 to evict the encap entry from HW. */
        if (rec->direction == HW_DIR_DOWNLINK)
                doca_flow_entries_process(ctx->n3_port, 0, 0, 0);

        /* If any entry removal failed, do NOT release meter or free record.
         * HW entries may still reference the meter — releasing it could cause
         * the meter ID to be reused, leading to data-plane corruption.
         * Return error so caller can handle the partial failure. */
        if (any_remove_failed) {
                DOCA_LOG_ERR(
                    "delete_rule: hw_rule_id=%u partially failed — "
                    "record and meter retained to prevent UAF",
                    hw_rule_id);
                return DOCA_ERROR_DRIVER;
        }

        /* Release shared meter if allocated */
        if (rec->meter_id != NO_METER_ID) {
                doca_flow_port_shared_resource_put(port_for_direction(ctx, rec->direction), DOCA_FLOW_SHARED_RESOURCE_METER, rec->meter_id);
        }

        free_record(ctx, rec);
        if (ctx->nb_entries > 0)
                ctx->nb_entries--;

        DOCA_LOG_INFO("Deleted rule hw_rule_id=%u", hw_rule_id);
        return DOCA_SUCCESS;
}

/* Re-build the per-entry actions+monitor that a UL_MATCH / DL_MATCH /
 * DL_SDF_MATCH entry was originally inserted with.  Must be supplied on
 * every doca_flow_pipe_basic_update_entry() that changes fwd: HWS
 * regenerates the action descriptor and needs the per-entry pkt_meta
 * (modify-header opcode) plus monitor binding.  Passing actions=NULL
 * fails as engine_uds "invalid uds set configuration" / rc=-22.
 *
 * NOTE: counter_type must NOT be set on update_entry.  The non-shared
 * counter is allocated once at add_entry and DOCA leaves it alone if
 * counter_type is unset on update.  Re-asserting counter_type=NON_SHARED
 * on a second update of the same entry triggers re-allocation and the
 * HWS backend returns EBUSY ("failed to update entry action data, err
 * -16").  For meter, only assert the shared_meter binding when actually
 * metered; an empty meter_type leaves the existing meter alone too.
 */
static void
rebuild_match_entry_actions_monitor(const dpu_rule_record_t *rec,
                                    struct doca_flow_actions *actions,
                                    struct doca_flow_monitor *monitor) {
        memset(actions, 0, sizeof(*actions));
        actions->meta.pkt_meta = htonl(rec->hw_rule_id);

        memset(monitor, 0, sizeof(*monitor));
        if (rec->meter_id != NO_METER_ID) {
                monitor->meter_type = DOCA_FLOW_RESOURCE_TYPE_SHARED;
                monitor->shared_meter.shared_meter_id = rec->meter_id;
        }
}

/* Reinsert the DL_MATCH (or DL_SDF_MATCH) entry on its current pipe with
 * a new fwd target.
 *
 * Currently unused — BUFF/FORW transitions no longer touch the base
 * entry's fwd (they add/remove an entry on DL_BUFF_OVERRIDE instead).
 * Retained for the latent repeated-QER-update path: HWS allows exactly
 * one update_entry per entry lifetime, so the SECOND time update_qer is
 * called on the same DL match entry, update_entry returns EBUSY.  The
 * fix at that point will be to call this helper instead, which removes
 * and re-adds the entry to obtain a fresh update slot.
 * (reinsert_dl_encap_with_new_params below is the wired-in twin of this
 * pattern for the DL_ENCAP entry.)
 *
 * Caveat (still applies if this is ever wired in for QER): there is a
 * ~100µs HW commit window between remove and add during which DL packets
 * matching this rule fall through the bucket chain to DROP.  For an
 * always-on rule (no BUFF in progress, no override coverage) this means
 * a brief drop window during the meter swap.  Acceptable for QER rate
 * changes (rare, signaled events) but document at the call site.
 *
 * On success, *rec->dl_entry is updated to the new entry handle.  On
 * failure after the remove succeeded, rec->dl_entry is set to NULL —
 * the rule is effectively deleted from HW and the caller must treat
 * this as a non-recoverable rule loss.
 */
__attribute__((unused))
static doca_error_t
reinsert_dl_match_with_new_fwd(dpu_pipeline_ctx_t *ctx,
                               dpu_rule_record_t *rec,
                               struct doca_flow_pipe *new_fwd_target) {
        struct doca_flow_pipe *pipe = dl_pipe_for_record(ctx, rec);

        /* Build the same actions + monitor that add_entry used at insert. */
        struct doca_flow_actions actions = {};
        actions.meta.pkt_meta = htonl(rec->hw_rule_id);

        struct doca_flow_monitor monitor = {};
        monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
        if (rec->meter_id != NO_METER_ID) {
                monitor.meter_type = DOCA_FLOW_RESOURCE_TYPE_SHARED;
                monitor.shared_meter.shared_meter_id = rec->meter_id;
        }

        struct doca_flow_fwd fwd = {
            .type = DOCA_FLOW_FWD_PIPE,
            .next_pipe = new_fwd_target,
        };

        /* Remove the old entry first.  Commit on N6 before adding so the
         * HW slot for this match is freed and the add doesn't fail with
         * "duplicate match".
         *
         * HWS can transiently return EBUSY when removing an entry that was
         * just modified by update_entry (the BUFF swap a moment ago) —
         * same root cause as the update_pdr delete retry path
         * (UPDATE_PDR_DELETE_RETRIES).  Mirror that pattern: on every
         * attempt, call entries_process so any HWS state pending from
         * the prior BUFF update gets drained off the pipe queue — without
         * this drain, the remove just returns EBUSY again next iteration.
         * update_pdr gets this for free because it retries the wrapping
         * delete_rule(), which itself always processes the port. */
        doca_error_t result = DOCA_ERROR_AGAIN;
        for (uint32_t attempt = 0; attempt <= UPDATE_PDR_DELETE_RETRIES; attempt++) {
                result = doca_flow_pipe_remove_entry(0, DOCA_FLOW_NO_WAIT, rec->dl_entry);
                doca_flow_entries_process(ctx->n6_port, 0, 0, 0);

                if (result == DOCA_SUCCESS)
                        break;

                if (attempt == UPDATE_PDR_DELETE_RETRIES) {
                        DOCA_LOG_ERR("reinsert_dl_match: remove_entry failed hw_rule_id=%u after %u retries: %s",
                                     rec->hw_rule_id, UPDATE_PDR_DELETE_RETRIES, doca_error_get_descr(result));
                        return result;
                }

                DOCA_LOG_WARN("reinsert_dl_match: remove_entry busy hw_rule_id=%u: %s; "
                              "retrying in %uus (%u/%u)",
                              rec->hw_rule_id, doca_error_get_descr(result), UPDATE_PDR_DELETE_RETRY_DELAY_US,
                              attempt + 1, UPDATE_PDR_DELETE_RETRIES);
                rte_delay_us_block(UPDATE_PDR_DELETE_RETRY_DELAY_US);
        }
        rte_delay_us_block(UPDATE_PDR_REINSERT_DELAY_US);

        /* Add new entry with the new fwd target. */
        struct doca_flow_pipe_entry *new_entry = NULL;
        result = doca_flow_pipe_basic_add_entry(0, pipe, &rec->cached_dl_match, 0, &actions, &monitor, &fwd, 0, NULL,
                                                &new_entry);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("reinsert_dl_match: add_entry failed hw_rule_id=%u: %s — rule has been deleted from HW",
                             rec->hw_rule_id, doca_error_get_descr(result));
                rec->dl_entry = NULL;
                return result;
        }
        doca_flow_entries_process(ctx->n6_port, 0, 0, 0);

        rec->dl_entry = new_entry;
        return DOCA_SUCCESS;
}

/* Replace the DL_ENCAP entry for a rule with one carrying new OHC params.
 *
 * Fallback for update_dlencap_only when doca_flow_pipe_basic_update_entry
 * is refused — HWS grants ONE live update per entry lifetime, so the 2nd+
 * encap change on the same entry returns DOCA_ERROR_IN_USE (see invariant
 * #9 in CLAUDE.md / DPU_ARM_BUFFERING_STRATEGY.md §11).  A fresh entry
 * carries a fresh update slot, so update and reinsert alternate across
 * repeated BUFF→FORW handovers with no extra state.
 *
 * Window: between the remove and add commits, packets stamped with this
 * rule's pkt_meta miss DL_ENCAP and exit N3 un-encapped via
 * N3_EGRESS_PASSTHROUGH.  On the BUFF→FORW path that window is
 * traffic-free by construction — the DL_*_BUFF_OVERRIDE entry is still
 * steering the flow to the ARM buffer, and the buffer lcore's SW-encapped
 * Tx carries pkt_meta=0.  Only a FAST-mode FORW with changed OHC
 * (handover without buffering) pays the ~100µs gap — same exposure
 * update_pdr already accepts.
 *
 * On add failure after a successful remove, rec->dl_encap_entry is NULL:
 * the rule has lost HW encap (un-encapped egress; buffer drain refuses via
 * get_dl_encap_params) until the next UPDATE_PDR/CREATE — same
 * non-recoverable contract as reinsert_dl_match_with_new_fwd. */
static doca_error_t
reinsert_dl_encap_with_new_params(dpu_pipeline_ctx_t *ctx,
                                  dpu_rule_record_t *rec,
                                  struct doca_flow_actions *encap_actions) {
        doca_error_t result = DOCA_ERROR_AGAIN;

        /* Remove the old entry.  HWS can transiently EBUSY on a remove that
         * closely follows another op on the same entry — same retry +
         * entries_process pattern as the FORW override removal. */
        for (uint32_t attempt = 0; attempt <= UPDATE_PDR_DELETE_RETRIES; attempt++) {
                result = doca_flow_pipe_remove_entry(0, DOCA_FLOW_NO_WAIT, rec->dl_encap_entry);
                doca_flow_entries_process(ctx->n3_port, 0, 0, 0);

                if (result == DOCA_SUCCESS)
                        break;

                if (attempt == UPDATE_PDR_DELETE_RETRIES) {
                        DOCA_LOG_ERR(
                            "reinsert_dl_encap: remove_entry failed hw_rule_id=%u "
                            "after %u retries: %s (old encap params stay active)",
                            rec->hw_rule_id, UPDATE_PDR_DELETE_RETRIES,
                            doca_error_get_descr(result));
                        return result;
                }

                DOCA_LOG_WARN(
                    "reinsert_dl_encap: remove_entry busy hw_rule_id=%u: %s; "
                    "retrying in %uus (%u/%u)",
                    rec->hw_rule_id, doca_error_get_descr(result),
                    UPDATE_PDR_DELETE_RETRY_DELAY_US, attempt + 1,
                    UPDATE_PDR_DELETE_RETRIES);
                rte_delay_us_block(UPDATE_PDR_DELETE_RETRY_DELAY_US);
        }
        rte_delay_us_block(UPDATE_PDR_REINSERT_DELAY_US);

        /* Re-add with the same pkt_meta match and the new encap actions. */
        struct doca_flow_match encap_match = {};
        encap_match.meta.pkt_meta = htonl(rec->hw_rule_id);

        struct doca_flow_pipe_entry *new_entry = NULL;
        result = doca_flow_pipe_basic_add_entry(0, ctx->dl_encap_pipe, &encap_match, 0, encap_actions,
                                                NULL, NULL, 0, NULL, &new_entry);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR(
                    "reinsert_dl_encap: add_entry failed hw_rule_id=%u: %s — "
                    "DL_ENCAP entry deleted from HW; rule egress is "
                    "un-encapped until UPDATE_PDR/CREATE",
                    rec->hw_rule_id, doca_error_get_descr(result));
                rec->dl_encap_entry = NULL;
                return result;
        }
        doca_flow_entries_process(ctx->n3_port, 0, 0, 0);

        rec->dl_encap_entry = new_entry;
        return DOCA_SUCCESS;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Public API: Update FAR (forwarding action change)
 *
 *  BUFF and FORW are expressed via add/remove on DL_BUFF_OVERRIDE, NOT
 *  by mutating the base DL_*_MATCH entry.  The base entry is installed
 *  once at insert_rule time pointing at the fast-path target and is
 *  never delete+re-added for BUFF/FORW.  This eliminates the ~100µs
 *  HW commit window that the old reinsert path exposed between the
 *  base entry's remove and add.
 *
 *  - BUFF: add one override entry in the per-bucket override pipe that
 *    mirrors the rule's original DL base pipe (src+dst or dst-only).
 *    Until the add commits, packets continue on the base fast path;
 *    after it commits, only traffic that would have matched that exact
 *    rule is redirected to ARM for buffering.  Falls back to
 *    delete_rule if TO_DPU_ARM (and therefore the override pipe family)
 *    is not available.  UL BUFF is rejected (defense in depth).
 *  - FORW: remove that override entry.  During the remove
 *    commit window, packets either still hit the override (handled by
 *    the buffer lcore's pass-through path) or fall through fwd_miss
 *    to the base entry (still installed, pointing at fast path with
 *    encap already refreshed by update_dlencap_only).  Either path
 *    delivers a correctly-encapped packet — no drop window.
 *  - DROP: remove HW rule entirely (traffic falls to SW path).
 * ═══════════════════════════════════════════════════════════════════════ */

doca_error_t
dpu_pipeline_update_far(dpu_pipeline_ctx_t *ctx, const hw_offload_msg_t *msg) {
        dpu_rule_record_t *rec = find_record(ctx, msg->hw_rule_id);
        if (!rec) {
                DOCA_LOG_WARN("update_far: hw_rule_id=%u not found", msg->hw_rule_id);
                return DOCA_ERROR_NOT_FOUND;
        }

        /* ── DROP: remove HW rule entirely ───────────────────────────── */
        if (msg->apply_action & HW_ACTION_DROP) {
                DOCA_LOG_INFO(
                    "update_far: DROP for hw_rule_id=%u — removing HW rule "
                    "(traffic falls to SW path)",
                    msg->hw_rule_id);
                return dpu_pipeline_delete_rule(ctx, msg->hw_rule_id);
        }

        /* ── BUFF: install the matching per-bucket DL override entry ───── */
        if (msg->apply_action & HW_ACTION_BUFF) {
                if (rec->current_mode == DPU_MODE_BUFFER) {
                        DOCA_LOG_DBG("update_far: hw_rule_id=%u already in BUFFER mode", msg->hw_rule_id);
                        return DOCA_SUCCESS;
                }

                /* UL buffering is not supported.  TO_DPU_ARM_DL is owned by
                 * the N6 port and RSSes to the DL buffer Rx queues; routing
                 * a UL rule there would steer N3-ingress UL packets into a
                 * DL-only pipe.  UPF-C filters UL BUFF at the host layer
                 * (see upf_hw_offload.h), but defend in depth here so a
                 * stray UL BUFF cannot mis-program HW.
                 *
                 * Return NOT_SUPPORTED (not SUCCESS) so the comch handler
                 * in dpu_agent.c skips dpu_buffer_register_flow().  Returning
                 * SUCCESS would leak a buffer slot for the rule's lifetime:
                 * current_mode stays FAST, a later FORW takes the "already
                 * FAST" fast path and never closes the buffer flow. */
                if (rec->direction == HW_DIR_UPLINK) {
                        DOCA_LOG_WARN(
                            "update_far: BUFF for UL hw_rule_id=%u not supported "
                            "— ignoring (UL stays on fast path)",
                            msg->hw_rule_id);
                        return DOCA_ERROR_NOT_SUPPORTED;
                }

                /* If buffering is not provisioned, there is no override
                 * pipe chain to intercept this rule at its original
                 * classifier position.  Fall back to delete_rule
                 * (pre-Phase 2 behavior). */
                struct doca_flow_pipe *override_pipe = dl_buff_override_pipe_for_record(ctx, rec);
                if (ctx->to_dpu_arm_dl_pipe == NULL || override_pipe == NULL) {
                        DOCA_LOG_WARN(
                            "update_far: BUFF for hw_rule_id=%u but "
                            "buffering not provisioned — deleting rule "
                            "(SW fallback)",
                            msg->hw_rule_id);
                        return dpu_pipeline_delete_rule(ctx, msg->hw_rule_id);
                }

                /* Add an override entry whose match mirrors the rule's
                 * original base DL pipe exactly.  This preserves both
                 * family specificity (src+dst vs dst-only) and bucket
                 * precedence: a BUFF on hw_rule_id X only intercepts
                 * packets that would have matched hw_rule_id X on the
                 * fast path. */
                struct doca_flow_match override_match = rec->cached_dl_match;
                const char *override_pipe_name =
                    rec->is_dl_sdf_match ? "DL_SDF_BUFF_OVERRIDE" : "DL_BUFF_OVERRIDE";

                struct doca_flow_actions override_actions = {};
                override_actions.meta.pkt_meta = htonl(rec->hw_rule_id);

                doca_error_t result = doca_flow_pipe_basic_add_entry(
                    0, override_pipe, &override_match, 0, &override_actions, NULL, NULL,
                    0, NULL, &rec->buff_override_entry);
                if (result != DOCA_SUCCESS) {
                        DOCA_LOG_ERR(
                            "update_far: %s add_entry failed hw_rule_id=%u: %s",
                            override_pipe_name, msg->hw_rule_id,
                            doca_error_get_descr(result));
                        rec->buff_override_entry = NULL;
                        return result;
                }

                doca_flow_entries_process(ctx->n6_port, 0, 0, 0);
                rec->current_mode = DPU_MODE_BUFFER;

                DOCA_LOG_INFO(
                    "update_far: hw_rule_id=%u BUFF — %s entry added "
                    "(packets redirected to ARM; base entry untouched)",
                    msg->hw_rule_id, override_pipe_name);
                return DOCA_SUCCESS;
        }

        /* ── FORW: remove the matching per-bucket DL override entry ─── */
        if (msg->apply_action & HW_ACTION_FORW) {
                /* If coming from BUFFER mode, remove the per-UE override
                 * entry.  The base DL_*_MATCH entry was never touched, so
                 * once the override is gone packets fall through fwd_miss
                 * to the existing fast-path target.  UL BUFF is rejected
                 * upstream so this branch is DL-only in practice.  The
                 * caller (dpu_agent.c) drains buffered packets first. */
                if (rec->current_mode == DPU_MODE_BUFFER) {
                        if (rec->direction == HW_DIR_UPLINK) {
                                /* UL BUFFER not supported; current_mode should
                                 * never be BUFFER for a UL rule. */
                                DOCA_LOG_WARN(
                                    "update_far: FORW for UL hw_rule_id=%u "
                                    "in BUFFER state — unexpected, no-op",
                                    msg->hw_rule_id);
                                return DOCA_ERROR_NOT_SUPPORTED;
                        }

                        if (rec->buff_override_entry == NULL) {
                                /* Inconsistent state: rule says BUFFER but
                                 * no override entry recorded.  Treat as
                                 * already FORW-restored — base entry is
                                 * intact, traffic flows fast path. */
                                DOCA_LOG_WARN(
                                    "update_far: FORW hw_rule_id=%u in BUFFER "
                                    "mode but no override entry — treating "
                                    "as restored",
                                    msg->hw_rule_id);
                                return DOCA_SUCCESS;
                        }

                        /* Remove the override entry.  Retry mirrors
                         * reinsert_dl_match_with_new_fwd's pattern: an
                         * override entry that was just added may transiently
                         * return EBUSY on remove until HWS retires the prior
                         * op — entries_process between attempts drains the
                         * pipe queue.  No add follows, so no reinsert delay
                         * is needed. */
                        const char *override_pipe_name =
                            rec->is_dl_sdf_match ? "DL_SDF_BUFF_OVERRIDE" : "DL_BUFF_OVERRIDE";
                        doca_error_t result = DOCA_ERROR_AGAIN;
                        for (uint32_t attempt = 0; attempt <= UPDATE_PDR_DELETE_RETRIES; attempt++) {
                                result = doca_flow_pipe_remove_entry(0, DOCA_FLOW_NO_WAIT, rec->buff_override_entry);
                                doca_flow_entries_process(ctx->n6_port, 0, 0, 0);

                                if (result == DOCA_SUCCESS)
                                        break;

                                if (attempt == UPDATE_PDR_DELETE_RETRIES) {
                                        DOCA_LOG_ERR(
                                            "update_far: FORW %s remove_entry "
                                            "failed hw_rule_id=%u after %u "
                                            "retries: %s",
                                            override_pipe_name, msg->hw_rule_id,
                                            UPDATE_PDR_DELETE_RETRIES,
                                            doca_error_get_descr(result));
                                        return result;
                                }

                                DOCA_LOG_WARN(
                                    "update_far: FORW %s remove_entry busy "
                                    "hw_rule_id=%u: %s; retrying in %uus (%u/%u)",
                                    override_pipe_name, msg->hw_rule_id,
                                    doca_error_get_descr(result),
                                    UPDATE_PDR_DELETE_RETRY_DELAY_US,
                                    attempt + 1, UPDATE_PDR_DELETE_RETRIES);
                                rte_delay_us_block(UPDATE_PDR_DELETE_RETRY_DELAY_US);
                        }

                        rec->buff_override_entry = NULL;

                        DOCA_LOG_INFO(
                            "update_far: hw_rule_id=%u FORW — %s entry removed "
                            "(base entry catches packets, "
                            "fast path restored)",
                            msg->hw_rule_id, override_pipe_name);
                }

                /* Encap (OHC) is intentionally NOT updated here.  The
                 * caller (dpu_agent.c comch_recv_cb) is contractually
                 * responsible for invoking dpu_pipeline_update_dlencap_only()
                 * BEFORE update_far(FORW) when ohc_desc==GTPU_UDP_IPV4, so
                 * dl_encap_entry and the SW-encap cache (rec->ohc_*) are
                 * already current.
                 *
                 * current_mode is NOT set to FAST here — the caller flips it
                 * immediately after this returns (HW is FAST once the
                 * override is gone; the buffer slot retires independently). */
                return DOCA_SUCCESS;
        }

        DOCA_LOG_WARN("update_far: unknown apply_action=%u for hw_rule_id=%u", msg->apply_action, msg->hw_rule_id);
        return DOCA_SUCCESS;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Public API: Update QER (meter rate change)
 * ═══════════════════════════════════════════════════════════════════════ */

doca_error_t
dpu_pipeline_update_qer(dpu_pipeline_ctx_t *ctx, const hw_offload_msg_t *msg) {
        dpu_rule_record_t *rec = find_record(ctx, msg->hw_rule_id);
        if (!rec) {
                DOCA_LOG_WARN("update_qer: hw_rule_id=%u not found", msg->hw_rule_id);
                return DOCA_ERROR_NOT_FOUND;
        }

        doca_error_t result;

        /* Pick direction-appropriate rates */
        uint64_t gbr_kbps = (rec->direction == HW_DIR_UPLINK) ? msg->gbr_ul : msg->gbr_dl;
        uint64_t mbr_kbps = (rec->direction == HW_DIR_UPLINK) ? msg->mbr_ul : msg->mbr_dl;

        uint32_t old_meter_id = rec->meter_id;

        /* Create new meter FIRST (may set NO_METER_ID if rates are 0).
         * Old meter stays valid until we confirm the entry update succeeds. */
        uint32_t new_meter_id;
        result = create_trtcm_meter(port_for_direction(ctx, rec->direction), &new_meter_id, gbr_kbps, mbr_kbps);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("update_qer: meter creation failed hw_rule_id=%u: %s", msg->hw_rule_id,
                             doca_error_get_descr(result));
                return result;
        }

        /* Update the entry's monitor via doca_flow_pipe_update_entry() */
        struct doca_flow_pipe_entry *entry = rec->ul_entry ? rec->ul_entry : rec->dl_entry;
        struct doca_flow_pipe *pipe = (rec->direction == HW_DIR_UPLINK) ? ctx->ul_match_pipes[rec->pipe_bucket]
                                                                        : dl_pipe_for_record(ctx, rec);

        /*
         * Always pass a non-NULL monitor to update_entry so the entry's
         * meter attachment is explicitly updated.  When new_meter_id is
         * NO_METER_ID (rates → 0), the zeroed meter_type detaches the
         * shared meter from the entry, making it safe to release the
         * old meter below.  Passing NULL would leave the entry still
         * referencing the old meter — a use-after-release if we then
         * free it.
         *
         * Do NOT set counter_type here — see comment on
         * rebuild_match_entry_actions_monitor().  The non-shared
         * counter is preserved across update_entry as long as we don't
         * re-assert it; re-asserting triggers re-allocation and EBUSY.
         */
        struct doca_flow_monitor mon = {};
        if (new_meter_id != NO_METER_ID) {
                mon.meter_type = DOCA_FLOW_RESOURCE_TYPE_SHARED;
                mon.shared_meter.shared_meter_id = new_meter_id;
        }

        /* Detect meter or GBR mode transition: does the per-entry fwd target need
         * to change between policed gate, shaped gate, or bypass (no meter)? */
        bool was_metered = (old_meter_id != NO_METER_ID);
        bool now_metered = (new_meter_id != NO_METER_ID);
        bool was_gbr = rec->is_gbr_flow;
        bool now_gbr = (gbr_kbps > 0) && ((rec->direction == HW_DIR_UPLINK) ? (ctx->ul_color_gate_shaped_pipe != NULL)
                                                                            : (ctx->dl_color_gate_shaped_pipe != NULL));

        struct doca_flow_fwd *fwd_ptr = NULL;
        struct doca_flow_fwd gate_fwd = {};
        if ((was_metered != now_metered) || (was_gbr != now_gbr)) {
                /* Under the DL_BUFF_OVERRIDE design, the base match entry's
                 * fwd is NEVER swapped to TO_DPU_ARM — the override pipe
                 * carries the BUFF redirect.  So whether or not current_mode
                 * is BUFFER, the base entry always represents the intended
                 * fast-path target and must be kept consistent with the new
                 * meter/GBR state.  If we skipped this update while in BUFF,
                 * the eventual update_far(FORW) would expose a base entry
                 * pointing at the previous (now-wrong) gate. */
                struct doca_flow_pipe *next_pipe;
                if (rec->direction == HW_DIR_UPLINK) {
                        if (!now_metered)
                                next_pipe = ctx->ul_decap_pipe;
                        else
                                next_pipe =
                                    now_gbr ? ctx->ul_color_gate_shaped_pipe : ctx->ul_color_gate_policed_pipe;
                } else {
                        if (!now_metered)
                                next_pipe = ctx->dl_encap_pipe;
                        else
                                next_pipe =
                                    now_gbr ? ctx->dl_color_gate_shaped_pipe : ctx->dl_color_gate_policed_pipe;
                }

                gate_fwd.type = DOCA_FLOW_FWD_PIPE;
                gate_fwd.next_pipe = next_pipe;
                fwd_ptr = &gate_fwd;
        }

        /* Re-supply pkt_meta so HWS can regen the action descriptor.
         * NOTE: this is the entry's FIRST update_entry after add_entry
         * for typical flows (a single QER refresh on a fresh rule).  If
         * an update_qer is repeated on the same entry it WILL hit the
         * "2nd update_entry returns EBUSY" HWS limit — at that point
         * this site needs the try-update-else-reinsert fallback that
         * update_dlencap_only uses (reinsert_dl_match_with_new_fwd is
         * the ready-made helper).  Not exercised in current scope;
         * left as-is for minimal blast radius. */
        struct doca_flow_actions ent_actions = {};
        ent_actions.meta.pkt_meta = htonl(rec->hw_rule_id);

        /* Single update_entry call: updates meter AND fwd atomically when
         * a GBR mode transition occurs, eliminating the window where the
         * meter generates YELLOW but the fwd still points to the wrong gate. */
        result = doca_flow_pipe_basic_update_entry(0, pipe, 0,
                                                   &ent_actions,     /* actions: pkt_meta = hw_rule_id */
                                                   &mon,             /* monitor: new meter (or detach) */
                                                   fwd_ptr,          /* fwd: new gate or NULL */
                                                   DOCA_FLOW_NO_WAIT, entry);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("update_qer: update_entry failed hw_rule_id=%u: %s", msg->hw_rule_id,
                             doca_error_get_descr(result));
                /* Release the new meter we just created; old meter is still intact */
                if (new_meter_id != NO_METER_ID)
                        doca_flow_port_shared_resource_put(port_for_direction(ctx, rec->direction), DOCA_FLOW_SHARED_RESOURCE_METER,
                                                           new_meter_id);
                return result;
        }

        doca_flow_entries_process(port_for_direction(ctx, rec->direction), 0, 0, 0);

        /* Entry update succeeded — now safe to release the old meter */
        if (old_meter_id != NO_METER_ID) {
                doca_flow_port_shared_resource_put(port_for_direction(ctx, rec->direction), DOCA_FLOW_SHARED_RESOURCE_METER, old_meter_id);
        }
        rec->meter_id = new_meter_id;
        rec->is_gbr_flow = now_gbr;

        DOCA_LOG_INFO(
            "update_qer: hw_rule_id=%u meter=%u→%u "
            "mbr=%lu gbr=%lu kbps%s",
            msg->hw_rule_id, old_meter_id, new_meter_id, (unsigned long)mbr_kbps, (unsigned long)gbr_kbps,
            (was_gbr != now_gbr) ? (now_gbr ? " [policed→shaped]" : " [shaped→policed]") : "");
        return DOCA_SUCCESS;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Public API: Downgrade a flow from shaped to policed color gate.
 *  Called when shaper registration fails — YELLOW packets will go to wire
 *  (slightly over-admitted) rather than being black-holed on ARM.
 * ═══════════════════════════════════════════════════════════════════════ */

doca_error_t
dpu_pipeline_downgrade_to_policed(dpu_pipeline_ctx_t *ctx, uint32_t hw_rule_id) {
        dpu_rule_record_t *rec = find_record(ctx, hw_rule_id);
        if (!rec) {
                DOCA_LOG_WARN("downgrade_to_policed: hw_rule_id=%u not found", hw_rule_id);
                return DOCA_ERROR_NOT_FOUND;
        }

        if (!rec->is_gbr_flow) {
                /* Already on policed gate — nothing to do */
                return DOCA_SUCCESS;
        }

        /* Under the DL_BUFF_OVERRIDE design the base entry's fwd is never
         * TO_DPU_ARM, so a downgrade can update it directly regardless of
         * current_mode.  The BUFF redirect lives on the override pipe and
         * is unaffected by this update.  Today downgrade_to_policed only
         * fires at insert_rule's shaper-register-failure path (entry's
         * first update_entry — HWS-safe); kept generic for the future case
         * where shaper registration can fail on already-running flows. */

        struct doca_flow_pipe *pipe;
        struct doca_flow_pipe_entry *entry;
        struct doca_flow_pipe *policed_gate;

        if (rec->direction == HW_DIR_UPLINK) {
                pipe = ctx->ul_match_pipes[rec->pipe_bucket];
                entry = rec->ul_entry;
                policed_gate = ctx->ul_color_gate_policed_pipe;
        } else {
                pipe = dl_pipe_for_record(ctx, rec);
                entry = rec->dl_entry;
                policed_gate = ctx->dl_color_gate_policed_pipe;
        }

        struct doca_flow_fwd fwd = {
            .type = DOCA_FLOW_FWD_PIPE,
            .next_pipe = policed_gate,
        };

        struct doca_flow_actions ent_actions;
        struct doca_flow_monitor ent_monitor;
        rebuild_match_entry_actions_monitor(rec, &ent_actions, &ent_monitor);

        /* downgrade_to_policed runs at CREATE time when shaper_register_flow
         * fails — so this is the FIRST update_entry on a fresh entry and
         * HWS accepts it.  If shaper-register ever starts failing on
         * already-existing rules, this site needs the same
         * try-update-else-reinsert fallback as update_dlencap_only. */
        doca_error_t result = doca_flow_pipe_basic_update_entry(0, pipe, 0, &ent_actions, &ent_monitor,
                                                                &fwd, /* fwd: shaped → policed */
                                                                DOCA_FLOW_NO_WAIT, entry);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR(
                    "downgrade_to_policed: update_entry failed "
                    "hw_rule_id=%u: %s",
                    hw_rule_id, doca_error_get_descr(result));
                return result;
        }

        doca_flow_entries_process(port_for_direction(ctx, rec->direction), 0, 0, 0);
        rec->is_gbr_flow = false;

        DOCA_LOG_INFO(
            "downgrade_to_policed: hw_rule_id=%u fwd swapped "
            "shaped→policed (shaper unavailable)",
            hw_rule_id);
        return DOCA_SUCCESS;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Public API: Set logical mode for a rule record
 * ═══════════════════════════════════════════════════════════════════════ */

void
dpu_pipeline_set_mode(dpu_pipeline_ctx_t *ctx, uint32_t hw_rule_id, uint8_t mode) {
        dpu_rule_record_t *rec = find_record(ctx, hw_rule_id);
        if (rec)
                rec->current_mode = mode;
}

uint8_t
dpu_pipeline_get_mode(const dpu_pipeline_ctx_t *ctx, uint32_t hw_rule_id) {
        const dpu_rule_record_t *rec = find_record((dpu_pipeline_ctx_t *)(uintptr_t)ctx, hw_rule_id);
        return rec ? rec->current_mode : DPU_MODE_FAST;
}

bool
dpu_pipeline_get_dl_encap_params(const dpu_pipeline_ctx_t *ctx,
                                 uint32_t hw_rule_id,
                                 uint32_t *ohc_ipv4,
                                 uint32_t *ohc_teid,
                                 uint8_t *encap_qfi) {
        const dpu_rule_record_t *rec =
            find_record((dpu_pipeline_ctx_t *)(uintptr_t)ctx, hw_rule_id);
        if (!rec || !rec->dl_encap_entry)
                return false;
        if (ohc_ipv4)
                *ohc_ipv4 = rec->ohc_ipv4;
        if (ohc_teid)
                *ohc_teid = rec->ohc_teid;
        if (encap_qfi)
                *encap_qfi = rec->encap_qfi;
        return true;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Public API: Update DL_ENCAP only (encap-param refresh / BUFF→FORW)
 *
 *  Commits new target gNB IP/TEID/QFI to the rule's DL_ENCAP entry and
 *  mirrors them into the SW-encap cache (rec->ohc_*).  On the BUFF→FORW
 *  path this runs BEFORE begin_drain() so drained packets carry the new
 *  outer header.
 *
 *  No-op for UL rules, rules without a DL_ENCAP entry, non-GTPU OHC, or
 *  unchanged params (the common SMF re-FORW).
 *
 *  HWS grants ONE live update_entry per entry lifetime (invariant #9),
 *  so the commit is: try update_entry (atomic, no window), fall back to
 *  remove+re-add via reinsert_dl_encap_with_new_params() when refused
 *  (IN_USE from the 2nd change onwards).  The fresh entry restores the
 *  update slot, so the two paths alternate across repeated handovers.
 * ═══════════════════════════════════════════════════════════════════════ */

doca_error_t
dpu_pipeline_update_dlencap_only(dpu_pipeline_ctx_t *ctx, const hw_offload_msg_t *msg) {
        dpu_rule_record_t *rec = find_record(ctx, msg->hw_rule_id);
        if (!rec) {
                DOCA_LOG_WARN("update_dlencap_only: hw_rule_id=%u not found", msg->hw_rule_id);
                return DOCA_ERROR_NOT_FOUND;
        }

        /* Only applies to DL rules with an existing encap entry */
        if (!rec->dl_encap_entry || msg->ohc_desc != HW_OHC_GTPU_UDP_IPV4)
                return DOCA_SUCCESS;

        /* Unchanged params: nothing to commit.  Skipping also preserves the
         * entry's single HWS update slot for a change that needs it. */
        if (rec->ohc_ipv4 == msg->ohc_ipv4.s_addr &&
            rec->ohc_teid == msg->ohc_teid &&
            rec->encap_qfi == msg->encap_qfi) {
                DOCA_LOG_DBG("update_dlencap_only: hw_rule_id=%u params unchanged — no-op",
                             msg->hw_rule_id);
                return DOCA_SUCCESS;
        }

        struct doca_flow_actions encap_actions;
        build_dl_encap_actions(ctx, msg->ohc_ipv4.s_addr, msg->ohc_teid,
                               msg->encap_qfi, &encap_actions);

        bool reinserted = false;
        doca_error_t result = doca_flow_pipe_basic_update_entry(0, ctx->dl_encap_pipe, 0, &encap_actions, NULL, NULL,
                                                                DOCA_FLOW_NO_WAIT, rec->dl_encap_entry);
        if (result == DOCA_SUCCESS) {
                /* DL_ENCAP is on N3 (EGRESS root) — commit N3. */
                doca_flow_entries_process(ctx->n3_port, 0, 0, 0);
        } else {
                /* Expected from the 2nd change on this entry onwards
                 * (one-update-per-lifetime → IN_USE).  Falling back is safe
                 * on ANY update failure: a refused update leaves the old
                 * entry intact, and on the BUFF→FORW path the override is
                 * still detouring this flow to ARM, so the remove+add
                 * window is traffic-free. */
                DOCA_LOG_WARN(
                    "update_dlencap_only: update_entry refused hw_rule_id=%u "
                    "(%s) — falling back to remove+re-add",
                    msg->hw_rule_id, doca_error_get_descr(result));
                result = reinsert_dl_encap_with_new_params(ctx, rec, &encap_actions);
                if (result != DOCA_SUCCESS)
                        return result;
                reinserted = true;
        }

        /* Mirror the new params into the SW-encap cache so the buffer
         * drain lcore (which is about to begin draining) builds packets
         * with the post-handover gNB IP/TEID. */
        rec->ohc_ipv4 = msg->ohc_ipv4.s_addr;
        rec->ohc_teid = msg->ohc_teid;
        rec->encap_qfi = msg->encap_qfi;

        DOCA_LOG_INFO(
            "update_dlencap_only: hw_rule_id=%u ENCAP %s "
            "teid=0x%x dst_ip=%08x qfi=%u",
            msg->hw_rule_id, reinserted ? "reinserted" : "updated",
            msg->ohc_teid, msg->ohc_ipv4.s_addr, msg->encap_qfi);
        return DOCA_SUCCESS;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Public API: Update PDR (full rule rebuild)
 *
 *  The control plane sends UPDATE_PDR as a full rebuilt rule snapshot.
 *  Keep the established delete+reinsert behavior so DL_ENCAP, meter, fwd,
 *  priority bucket, and match state are all recreated from one coherent
 *  message.
 *
 *  DOCA HWS can transiently return EBUSY when a metered/cross-port DL rule
 *  is removed immediately after a create/FAR/encap update.  The delete path
 *  is retry-safe because successfully removed entry handles are nulled and
 *  retained records keep meters alive until all HW entries are gone.
 * ═══════════════════════════════════════════════════════════════════════ */


doca_error_t
dpu_pipeline_update_pdr(dpu_pipeline_ctx_t *ctx, const hw_offload_msg_t *msg) {
        DOCA_LOG_INFO("update_pdr: delete+reinsert for hw_rule_id=%u", msg->hw_rule_id);

        doca_error_t result = DOCA_SUCCESS;

        for (uint32_t attempt = 0; attempt <= UPDATE_PDR_DELETE_RETRIES; attempt++) {
                result = dpu_pipeline_delete_rule(ctx, msg->hw_rule_id);
                if (result == DOCA_SUCCESS || result == DOCA_ERROR_NOT_FOUND)
                        break;

                if (attempt == UPDATE_PDR_DELETE_RETRIES) {
                        DOCA_LOG_ERR("update_pdr: delete failed hw_rule_id=%u after %u retries: %s",
                                     msg->hw_rule_id, UPDATE_PDR_DELETE_RETRIES,
                                     doca_error_get_descr(result));
                        return result;
                }

                DOCA_LOG_WARN("update_pdr: delete busy/failed hw_rule_id=%u: %s; "
                              "retrying in %uus (%u/%u)",
                              msg->hw_rule_id, doca_error_get_descr(result),
                              UPDATE_PDR_DELETE_RETRY_DELAY_US, attempt + 1,
                              UPDATE_PDR_DELETE_RETRIES);
                rte_delay_us_block(UPDATE_PDR_DELETE_RETRY_DELAY_US);
        }

        if (result == DOCA_SUCCESS)
                rte_delay_us_block(UPDATE_PDR_REINSERT_DELAY_US);

        /* Re-insert with the same hw_rule_id (msg already contains it) */
        result = dpu_pipeline_insert_rule(ctx, msg);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR(
                    "update_pdr: reinsert FAILED hw_rule_id=%u: %s — "
                    "rule has been deleted from HW and is NOT restored. "
                    "Traffic for this PDR falls to SW path until next "
                    "session modification.",
                    msg->hw_rule_id, doca_error_get_descr(result));
        }
        return result;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Public API: Dump per-entry and per-pipe-miss statistics
 *
 *  Iterates over all active rule records, calls
 *  doca_flow_resource_query_entry() on each UL/DL match entry, and logs
 *  hit counts.  Also queries pipe-miss counters for each UL/DL_MATCH
 *  bucket.  Intended for on-demand debugging (e.g., via SIGUSR1).
 * ═══════════════════════════════════════════════════════════════════════ */

void
dpu_pipeline_dump_stats(dpu_pipeline_ctx_t *ctx) {
        DOCA_LOG_INFO("=== Pipeline Stats Dump (%u active entries) ===", ctx->nb_entries);

        uint32_t override_entries_active = 0;

        /* Per-entry counters */
        for (uint32_t i = 0; i < ctx->max_hw_rules; i++) {
                dpu_rule_record_t *rec = &ctx->rules[i];
                if (!rec->in_use)
                        continue;

                const char *dir_str = (rec->direction == HW_DIR_UPLINK) ? "UL" : "DL";
                const char *mode_str = (rec->current_mode == DPU_MODE_FAST) ? "FAST" : "BUFF";
                /* Report the HW override entry state alongside the SW
                 * lifecycle mode.  These can disagree transiently during
                 * the dpu_agent 7-step drain: the override entry is added
                 * before current_mode flips to BUFFER on activation, and
                 * the override entry is removed before current_mode flips
                 * back to FAST on restoration.  An asymmetry between them
                 * outside those windows indicates a bug. */
                const char *ovr_str = (rec->buff_override_entry != NULL) ? " +OVR" : "";
                if (rec->buff_override_entry != NULL)
                        override_entries_active++;

                /* Query UL match entry */
                if (rec->ul_entry) {
                        struct doca_flow_resource_query q = {};
                        doca_error_t r = doca_flow_resource_query_entry(rec->ul_entry, &q);
                        if (r == DOCA_SUCCESS) {
                                DOCA_LOG_INFO(
                                    "  hw_rule=%u UL_MATCH P%u %s %s%s "
                                    "pkts=%" PRIu64 " bytes=%" PRIu64,
                                    rec->hw_rule_id, rec->pipe_bucket, dir_str, mode_str, ovr_str,
                                    q.counter.total_pkts, q.counter.total_bytes);
                        } else {
                                DOCA_LOG_WARN("  hw_rule=%u UL_MATCH query failed: %s", rec->hw_rule_id,
                                              doca_error_get_descr(r));
                        }
                }

                /* Query DL match entry */
                if (rec->dl_entry) {
                        const char *dl_pipe_name = rec->is_dl_sdf_match ? "DL_SDF_MATCH" : "DL_MATCH";
                        struct doca_flow_resource_query q = {};
                        doca_error_t r = doca_flow_resource_query_entry(rec->dl_entry, &q);
                        if (r == DOCA_SUCCESS) {
                                DOCA_LOG_INFO(
                                    "  hw_rule=%u %s P%u %s %s%s "
                                    "pkts=%" PRIu64 " bytes=%" PRIu64,
                                    rec->hw_rule_id, dl_pipe_name, rec->pipe_bucket, dir_str, mode_str, ovr_str,
                                    q.counter.total_pkts, q.counter.total_bytes);
                        } else {
                                DOCA_LOG_WARN("  hw_rule=%u %s query failed: %s", rec->hw_rule_id,
                                              dl_pipe_name, doca_error_get_descr(r));
                        }
                }
        }

        if (ctx->to_dpu_arm_dl_pipe != NULL) {
                DOCA_LOG_INFO("  DL override entries: %u active", override_entries_active);
        }

        /* ROOT prio-5 ARP classifiers */
        if (ctx->root_arp_n3_entry) {
                struct doca_flow_resource_query q = {};
                doca_error_t r = doca_flow_resource_query_entry(ctx->root_arp_n3_entry, &q);
                if (r == DOCA_SUCCESS) {
                        DOCA_LOG_INFO(
                            "  N3_ROOT ARP → L2L3_RX_N3: "
                            "pkts=%" PRIu64 " bytes=%" PRIu64,
                            q.counter.total_pkts, q.counter.total_bytes);
                }
        }
        if (ctx->root_arp_n6_entry) {
                struct doca_flow_resource_query q = {};
                doca_error_t r = doca_flow_resource_query_entry(ctx->root_arp_n6_entry, &q);
                if (r == DOCA_SUCCESS) {
                        DOCA_LOG_INFO(
                            "  N6_ROOT ARP → L2L3_RX_N6: "
                            "pkts=%" PRIu64 " bytes=%" PRIu64,
                            q.counter.total_pkts, q.counter.total_bytes);
                }
        }

        if (ctx->ul_decap_entry) {
                struct doca_flow_resource_query q = {};
                doca_error_t r = doca_flow_resource_query_entry(ctx->ul_decap_entry, &q);
                if (r == DOCA_SUCCESS) {
                        DOCA_LOG_INFO(
                            "  UL_DECAP (catch-all): "
                            "pkts=%" PRIu64 " bytes=%" PRIu64,
                            q.counter.total_pkts, q.counter.total_bytes);
                } else {
                        DOCA_LOG_WARN("  UL_DECAP query failed: %s", doca_error_get_descr(r));
                }
        }

        DOCA_LOG_INFO("=== End Stats Dump ===");
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Public API: Teardown
 * ═══════════════════════════════════════════════════════════════════════ */

void
dpu_pipeline_destroy(dpu_pipeline_ctx_t *ctx) {
        /* DOCA Flow teardown sequence (VNF mode, flow_common.c pattern):
         *  1. Flush pipes + entries on each port, in reverse creation order
         *  2. Stop ports in reverse creation order
         *  3. doca_flow_destroy() releases global HW resources
         *
         * N3 was created first, N6 second — so stop N6 before N3. */
        if (ctx->n6_port)
                doca_flow_port_pipes_flush(ctx->n6_port);
        if (ctx->n3_port)
                doca_flow_port_pipes_flush(ctx->n3_port);

        if (ctx->n6_port)
                doca_flow_port_stop(ctx->n6_port);
        if (ctx->n3_port)
                doca_flow_port_stop(ctx->n3_port);

        doca_flow_destroy();

        /* Free heap-allocated resources */
        if (ctx->rule_id_map) {
                rte_hash_free(ctx->rule_id_map);
                ctx->rule_id_map = NULL;
        }
        free(ctx->rules);
        ctx->rules = NULL;

        DOCA_LOG_INFO("Pipeline destroyed (%u entries were active)", ctx->nb_entries);
}
