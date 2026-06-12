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
 *   N6_ROOT → DL_MATCH[0..3] → DL_COLOR_GATE → DL_ENCAP → FWD_PORT(N3)
 *   TO_DPU_ARM_DL: RSS → ARM Rx queues (entered via per-entry fwd swap on BUFF)
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
#define GTP_UDP_PORT 2152
#define GTP_EXT_PSC 0x85       /* GTP next-ext-hdr-type for PDU Session Container */
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
 * Entered when a per-entry fwd in DL_MATCH is swapped from
 * COLOR_GATE → TO_DPU_ARM_DL on UpdateFAR(BUFF).
 * The pkt_meta set by the match pipe is preserved across RSS.
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

                /* Hit → CHANGEABLE (per-entry fwd target: UL_COLOR_GATE or TO_DPU_ARM) */
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

/* ── DL_MATCH pipes (4 priority buckets) ──────────────────────────── */
/*
 * Each pipe matches: UE destination IP (outer dst_ip).
 * SDF fields (src_ip, proto, ports) are wildcarded at the pipe level.
 * Actions: pkt_meta + shared meter.
 * Chain: P0.miss → P1 → P2 → P3.miss → DROP (VNF).
 */
static doca_error_t
build_dl_match_pipes(dpu_pipeline_ctx_t *ctx) {
        doca_error_t result;

        for (int p = NUM_PRIO_BUCKETS - 1; p >= 0; p--) {
                struct doca_flow_pipe_cfg *pipe_cfg;
                result = doca_flow_pipe_cfg_create(&pipe_cfg, ctx->n6_port);
                if (result != DOCA_SUCCESS)
                        return result;

                char name[32];
                snprintf(name, sizeof(name), "DL_MATCH_P%d", p);
                doca_flow_pipe_cfg_set_name(pipe_cfg, name);
                doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);
                doca_flow_pipe_cfg_set_is_root(pipe_cfg, false);
                doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, ctx->match_entries_per_bucket);

                /* Match: UE destination IP only (CHANGEABLE per-entry).
                 * SDF fields (src_ip, proto, ports) are intentionally omitted so
                 * that their pipe-level mask is 0 → IGNORED (wildcard).  This
                 * allows catch-all PDRs with no SDF filter to match all traffic. */
                struct doca_flow_match match = {};
                match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
                match.outer.ip4.dst_ip = UINT32_MAX; /* UE IP */

                struct doca_flow_match mask = {};
                mask.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
                mask.outer.ip4.dst_ip = UINT32_MAX;

                doca_flow_pipe_cfg_set_match(pipe_cfg, &match, &mask);

                /* Actions: pkt_meta (changeable) */
                struct doca_flow_actions actions = {};
                actions.meta.pkt_meta = UINT32_MAX;

                struct doca_flow_actions *actions_arr[] = {&actions};
                doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL, NULL, 1);

                /* Monitor: shared meter + non-shared counter per entry */
                struct doca_flow_monitor monitor = {};
                monitor.meter_type = DOCA_FLOW_RESOURCE_TYPE_SHARED;
                monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
                doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor);

                /* Hit → CHANGEABLE (per-entry fwd target: DL_COLOR_GATE or TO_DPU_ARM_DL) */
                struct doca_flow_fwd fwd = {
                    .type = DOCA_FLOW_FWD_CHANGEABLE,
                };

                /* Miss → next bucket or DROP (VNF mode) */
                struct doca_flow_fwd fwd_miss;
                if (p == NUM_PRIO_BUCKETS - 1) {
                        fwd_miss.type = DOCA_FLOW_FWD_DROP;
                } else {
                        fwd_miss.type = DOCA_FLOW_FWD_PIPE;
                        fwd_miss.next_pipe = ctx->dl_match_pipes[p + 1];
                }

                result = doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_miss, &ctx->dl_match_pipes[p]);
                doca_flow_pipe_cfg_destroy(pipe_cfg);

                if (result != DOCA_SUCCESS) {
                        DOCA_LOG_ERR("%s pipe creation failed: %s", name, doca_error_get_descr(result));
                        return result;
                }

                DOCA_LOG_INFO("%s: hit→CHANGEABLE(DL_COLOR_GATE), miss→%s", name,
                              (p == NUM_PRIO_BUCKETS - 1) ? "DROP" : "next bucket");
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

        /* Prio 0: IPv4 → DL_MATCH[0] */
        {
                struct doca_flow_match match = {};
                match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
                struct doca_flow_match mask = {};
                mask.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
                struct doca_flow_fwd fwd = { .type = DOCA_FLOW_FWD_PIPE, .next_pipe = ctx->dl_match_pipes[0] };
                struct doca_flow_pipe_entry *entry;
                result = doca_flow_pipe_control_add_entry(0, ctx->n6_root_pipe, &match, &mask, NULL, NULL, NULL, NULL,
                                                          NULL, 0, &fwd, NULL, &entry);
                if (result != DOCA_SUCCESS) { DOCA_LOG_ERR("N6_ROOT: DL entry failed"); return result; }
        }
        doca_flow_entries_process(ctx->n6_port, 0, 0, 0);
        DOCA_LOG_INFO("N6_ROOT: prio 0 IPv4 → DL_MATCH[0]");

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
        uint32_t pipe_count = 13; /* UL_DECAP + N3_EGRESS_PASSTHROUGH + DL_ENCAP + UL/DL POLICED + UL/DL MATCH(4+4) + N3_ROOT + N6_ROOT */
        if (ctx->nr_n6_buffer_rss_queues > 0)
                pipe_count++; /* TO_DPU_ARM_DL */
        if (ctx->nr_n3_shaper_rss_queues > 0)
                pipe_count += 2; /* UL+DL shaped gates */
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
                 * SDF fields are wildcarded at the pipe level (mask=0). */
                struct doca_flow_match match = {};
                match.tun.type = DOCA_FLOW_TUN_GTPU;
                match.tun.gtp_teid = htonl(msg->teid);
                match.inner.l3_type = DOCA_FLOW_L3_TYPE_IP4;
                //match.inner.ip4.src_ip = msg->ue_ipv4.s_addr; /* NBO */

                /*
                * UL reduced-SDF policy:
                * default to UE source IP, but if the rule carries an exact SDF source
                * that is different from UE IP, use that as the inner source match.
                *
                * msg->sdf_src_ip is HOST order.
                * DOCA match wants NBO, same as msg->ue_ipv4.s_addr.
                */
                /* uint32_t ul_inner_src_ip = msg->ue_ipv4.s_addr;

                if (msg->has_sdf && msg->sdf_src_pref == 32) {
                        uint32_t sdf_src_nbo = htonl(msg->sdf_src_ip);

                        if (sdf_src_nbo != msg->ue_ipv4.s_addr)
                                ul_inner_src_ip = sdf_src_nbo;
                } */

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

                doca_flow_entries_process(ctx->n3_port, 0, 0, 0);

                // DOCA_LOG_INFO(
                //     "UL rule: hw_rule=%u teid=0x%x qfi=%u bucket=P%d "
                //     "meter=%s gbr=%s",
                //     msg->hw_rule_id, msg->teid, msg->qfi, bucket, (meter_id != NO_METER_ID) ? "yes" : "none",
                //     ul_is_gbr ? "shaped" : "policed");

                // Comment these lines later
                struct in_addr ul_match_src = {
                        .s_addr = ul_inner_src_ip,
                };

                DOCA_LOG_INFO(
                        "UL rule: hw_rule=%u teid=0x%x qfi=%u bucket=P%d "
                        "inner_src=%s meter=%s gbr=%s",
                        msg->hw_rule_id, msg->teid, msg->qfi, bucket,
                        inet_ntoa(ul_match_src),
                        (meter_id != NO_METER_ID) ? "yes" : "none",
                        ul_is_gbr ? "shaped" : "policed");

                // till here

        } else {
                /* ── DOWNLINK ────────────────────────────────────────────────── */

                uint32_t meter_id;
                result = create_trtcm_meter(ctx->n6_port, &meter_id, msg->gbr_dl, msg->mbr_dl);
                if (result != DOCA_SUCCESS)
                        return result;

                /* DL_MATCH entry: UE destination IP only.
                 * SDF fields are wildcarded at the pipe level (mask=0). */
                struct doca_flow_match dl_match = {};
                dl_match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
                dl_match.outer.ip4.dst_ip = msg->ue_ipv4.s_addr; /* NBO */

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
                result = doca_flow_pipe_basic_add_entry(0, ctx->dl_match_pipes[bucket], &dl_match, 0, &dl_actions,
                                                        &dl_monitor, &dl_fwd, 0, NULL, &dl_entry);
                if (result != DOCA_SUCCESS) {
                        DOCA_LOG_ERR("DL_MATCH entry failed hw_rule_id=%u bucket=%d: %s", msg->hw_rule_id, bucket,
                                     doca_error_get_descr(result));
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

                /* DL_ENCAP entry: pkt_meta → GTP encap.
                 * Mirror the pipe-template fields exactly — version_ihl,
                 * next_proto, and udp src_port included so the HW finalises
                 * GTP/UDP/IP lengths and uses 2152 as src port. */
                if (msg->ohc_desc == HW_OHC_GTPU_UDP_IPV4) {
                        struct doca_flow_match encap_match = {};
                        encap_match.meta.pkt_meta = htonl(msg->hw_rule_id);

                        struct doca_flow_actions encap_actions = {};
                        encap_actions.encap_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;

                        encap_actions.encap_cfg.encap.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
                        encap_actions.encap_cfg.encap.outer.ip4.version_ihl = 0x45;
                        encap_actions.encap_cfg.encap.outer.ip4.next_proto = DOCA_FLOW_PROTO_UDP;
                        encap_actions.encap_cfg.encap.outer.ip4.dst_ip = msg->ohc_ipv4.s_addr;
                        encap_actions.encap_cfg.encap.outer.ip4.src_ip = ctx->port_cfg.upf_n3_ip;
                        encap_actions.encap_cfg.encap.outer.ip4.ttl = 64;

                        encap_actions.encap_cfg.encap.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
                        encap_actions.encap_cfg.encap.outer.udp.l4_port.src_port = RTE_BE16(GTP_UDP_PORT);
                        encap_actions.encap_cfg.encap.outer.udp.l4_port.dst_port = RTE_BE16(GTP_UDP_PORT);

                        encap_actions.encap_cfg.encap.tun.type = DOCA_FLOW_TUN_GTPU;
                        encap_actions.encap_cfg.encap.tun.gtp_teid = htonl(msg->ohc_teid);
                        encap_actions.encap_cfg.encap.tun.gtp_next_ext_hdr_type = GTP_EXT_PSC;
                        encap_actions.encap_cfg.encap.tun.gtp_ext_psc_qfi = msg->encap_qfi;

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
                    "bucket=P%d meter=%s gbr=%s",
                    msg->hw_rule_id, inet_ntoa(msg->ue_ipv4), msg->ohc_teid, bucket,
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

/* ═══════════════════════════════════════════════════════════════════════
 *  Public API: Update FAR (forwarding action change)
 *
 *  - BUFF: swap per-entry fwd from COLOR_GATE → TO_DPU_ARM so packets
 *    are redirected to ARM Rx queues for buffering.  Falls back to
 *    deleting the rule if TO_DPU_ARM pipe is not available.
 *  - FORW: if in BUFFER mode, swap per-entry fwd back to COLOR_GATE
 *    (caller is responsible for draining buffered packets first).
 *    If OHC params changed, update the DL_ENCAP entry in-place.
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

        /* ── BUFF: swap per-entry fwd to TO_DPU_ARM ──────────────────── */
        if (msg->apply_action & HW_ACTION_BUFF) {
                if (rec->current_mode == DPU_MODE_BUFFER) {
                        DOCA_LOG_DBG("update_far: hw_rule_id=%u already in BUFFER mode", msg->hw_rule_id);
                        return DOCA_SUCCESS;
                }

                /* If TO_DPU_ARM pipe is available, swap fwd. Otherwise, fall
                 * back to deleting the rule (pre-Phase 2 behavior). */
                if (ctx->to_dpu_arm_dl_pipe == NULL) {
                        DOCA_LOG_WARN(
                            "update_far: BUFF for hw_rule_id=%u but "
                            "TO_DPU_ARM not available — deleting rule "
                            "(SW fallback)",
                            msg->hw_rule_id);
                        return dpu_pipeline_delete_rule(ctx, msg->hw_rule_id);
                }

                /* Determine which match pipe and entry handle */
                struct doca_flow_pipe *pipe;
                struct doca_flow_pipe_entry *entry;
                if (rec->direction == HW_DIR_UPLINK) {
                        pipe = ctx->ul_match_pipes[rec->pipe_bucket];
                        entry = rec->ul_entry;
                } else {
                        pipe = ctx->dl_match_pipes[rec->pipe_bucket];
                        entry = rec->dl_entry;
                }

                /* Swap fwd: COLOR_GATE → TO_DPU_ARM */
                struct doca_flow_fwd buf_fwd = {
                    .type = DOCA_FLOW_FWD_PIPE,
                    .next_pipe = ctx->to_dpu_arm_dl_pipe,
                };

                doca_error_t result = doca_flow_pipe_basic_update_entry(0, pipe, 0, NULL, /* actions: unchanged */
                                                                        NULL,             /* monitor: unchanged */
                                                                        &buf_fwd,         /* fwd: swap to TO_DPU_ARM */
                                                                        DOCA_FLOW_NO_WAIT, entry);
                if (result != DOCA_SUCCESS) {
                        DOCA_LOG_ERR(
                            "update_far: fwd swap to TO_DPU_ARM failed "
                            "hw_rule_id=%u: %s",
                            msg->hw_rule_id, doca_error_get_descr(result));
                        return result;
                }

                doca_flow_entries_process(port_for_direction(ctx, rec->direction), 0, 0, 0);
                rec->current_mode = DPU_MODE_BUFFER;

                DOCA_LOG_INFO(
                    "update_far: hw_rule_id=%u BUFF — fwd swapped to "
                    "TO_DPU_ARM (packets redirected to ARM)",
                    msg->hw_rule_id);
                return DOCA_SUCCESS;
        }

        /* ── FORW: restore fast path ─────────────────────────────────── */
        if (msg->apply_action & HW_ACTION_FORW) {
                /* If coming from BUFFER mode, swap fwd back to COLOR_GATE.
                 * The caller (dpu_agent.c) is responsible for draining buffered
                 * packets before calling this, so we don't drain here. */
                if (rec->current_mode == DPU_MODE_BUFFER) {
                        struct doca_flow_pipe *pipe;
                        struct doca_flow_pipe_entry *entry;
                        struct doca_flow_pipe *next_pipe;

                        if (rec->direction == HW_DIR_UPLINK) {
                                pipe = ctx->ul_match_pipes[rec->pipe_bucket];
                                entry = rec->ul_entry;
                                if (rec->meter_id == NO_METER_ID)
                                        next_pipe = ctx->ul_decap_pipe;
                                else
                                        next_pipe = rec->is_gbr_flow ? ctx->ul_color_gate_shaped_pipe
                                                                     : ctx->ul_color_gate_policed_pipe;
                        } else {
                                pipe = ctx->dl_match_pipes[rec->pipe_bucket];
                                entry = rec->dl_entry;
                                if (rec->meter_id == NO_METER_ID)
                                        next_pipe = ctx->dl_encap_pipe;
                                else
                                        next_pipe = rec->is_gbr_flow ? ctx->dl_color_gate_shaped_pipe
                                                                     : ctx->dl_color_gate_policed_pipe;
                        }

                        /* Swap fwd: TO_DPU_ARM → COLOR_GATE or DECAP/ENCAP */
                        struct doca_flow_fwd fast_fwd = {
                            .type = DOCA_FLOW_FWD_PIPE,
                            .next_pipe = next_pipe,
                        };

                        doca_error_t result =
                            doca_flow_pipe_basic_update_entry(0, pipe, 0, NULL, /* actions: unchanged */
                                                              NULL,             /* monitor: unchanged */
                                                              &fast_fwd,        /* fwd: swap back to COLOR_GATE */
                                                              DOCA_FLOW_NO_WAIT, entry);
                        if (result != DOCA_SUCCESS) {
                                DOCA_LOG_ERR(
                                    "update_far: fwd swap back to COLOR_GATE "
                                    "failed hw_rule_id=%u: %s",
                                    msg->hw_rule_id, doca_error_get_descr(result));
                                return result;
                        }

                        doca_flow_entries_process(port_for_direction(ctx, rec->direction), 0, 0, 0);

                        DOCA_LOG_INFO(
                            "update_far: hw_rule_id=%u FORW — fwd swapped "
                            "back to COLOR_GATE (fast path restored)",
                            msg->hw_rule_id);
                }

                /* OHC update: only meaningful for DL rules with an encap entry.
                 * Same field set as the pipe template (see build_dl_encap_pipe). */
                if (rec->dl_encap_entry && msg->ohc_desc == HW_OHC_GTPU_UDP_IPV4) {
                        struct doca_flow_actions encap_actions = {};
                        encap_actions.encap_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;

                        encap_actions.encap_cfg.encap.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
                        encap_actions.encap_cfg.encap.outer.ip4.version_ihl = 0x45;
                        encap_actions.encap_cfg.encap.outer.ip4.next_proto = DOCA_FLOW_PROTO_UDP;
                        encap_actions.encap_cfg.encap.outer.ip4.dst_ip = msg->ohc_ipv4.s_addr;
                        encap_actions.encap_cfg.encap.outer.ip4.src_ip = ctx->port_cfg.upf_n3_ip;
                        encap_actions.encap_cfg.encap.outer.ip4.ttl = 64;

                        encap_actions.encap_cfg.encap.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
                        encap_actions.encap_cfg.encap.outer.udp.l4_port.src_port = RTE_BE16(GTP_UDP_PORT);
                        encap_actions.encap_cfg.encap.outer.udp.l4_port.dst_port = RTE_BE16(GTP_UDP_PORT);

                        encap_actions.encap_cfg.encap.tun.type = DOCA_FLOW_TUN_GTPU;
                        encap_actions.encap_cfg.encap.tun.gtp_teid = htonl(msg->ohc_teid);
                        encap_actions.encap_cfg.encap.tun.gtp_next_ext_hdr_type = GTP_EXT_PSC;
                        encap_actions.encap_cfg.encap.tun.gtp_ext_psc_qfi = msg->encap_qfi;

                        doca_error_t result =
                            doca_flow_pipe_basic_update_entry(0, ctx->dl_encap_pipe, 0, &encap_actions, NULL, NULL,
                                                              DOCA_FLOW_NO_WAIT, rec->dl_encap_entry);
                        if (result != DOCA_SUCCESS) {
                                DOCA_LOG_ERR(
                                    "update_far: encap update failed "
                                    "hw_rule_id=%u: %s",
                                    msg->hw_rule_id, doca_error_get_descr(result));
                                return result;
                        }
                        /* DL_ENCAP is on N3 (EGRESS root) — commit N3, not N6. */
                        doca_flow_entries_process(ctx->n3_port, 0, 0, 0);

                        DOCA_LOG_INFO(
                            "update_far: hw_rule_id=%u ENCAP updated "
                            "teid=0x%x dst_ip=%08x",
                            msg->hw_rule_id, msg->ohc_teid, msg->ohc_ipv4.s_addr);
                }

                /* NOTE: current_mode is NOT set to FAST here.  The caller\n         * (comch_recv_cb) sets it after
                 * buffer quiesce completes,\n         * so that current_mode accurately reflects the lifecycle\n
                 * * state during the quiesce window. */
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
                                                                        : ctx->dl_match_pipes[rec->pipe_bucket];

        /*
         * Always pass a non-NULL monitor to update_entry so the entry's
         * meter attachment is explicitly updated.  When new_meter_id is
         * NO_METER_ID (rates → 0), the zeroed monitor detaches the meter
         * from the entry, making it safe to release the old meter below.
         * Passing NULL would leave the entry still referencing the old
         * meter — a use-after-release if we then free it.
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
                /* If the rule is currently buffered, the entry's fwd points to
                 * TO_DPU_ARM and must stay that way.  We still record the new
                 * state below so that update_far(FORW) will pick the
                 * correct path when the buffer drains.  Changing fwd here
                 * would break the buffer path by redirecting traffic away from
                 * ARM before the buffer has been drained. */
                if (rec->current_mode == DPU_MODE_BUFFER) {
                        DOCA_LOG_INFO(
                            "update_qer: hw_rule_id=%u fwd transition "
                            "deferred — rule is in BUFFER mode",
                            msg->hw_rule_id);
                } else {
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
        }

        /* Single update_entry call: updates meter AND fwd atomically when
         * a GBR mode transition occurs, eliminating the window where the
         * meter generates YELLOW but the fwd still points to the wrong gate. */
        result = doca_flow_pipe_basic_update_entry(0, pipe, 0, NULL, /* actions: unchanged */
                                                   &mon,             /* monitor: new or zeroed */
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

        /* If the rule is currently buffered, fwd points to TO_DPU_ARM.
         * Don't touch the fwd — just clear is_gbr_flow so that
         * update_far(FORW) will restore to the policed gate later. */
        if (rec->current_mode == DPU_MODE_BUFFER) {
                rec->is_gbr_flow = false;
                DOCA_LOG_INFO(
                    "downgrade_to_policed: hw_rule_id=%u deferred — "
                    "rule is in BUFFER mode (is_gbr_flow cleared)",
                    hw_rule_id);
                return DOCA_SUCCESS;
        }

        struct doca_flow_pipe *pipe;
        struct doca_flow_pipe_entry *entry;
        struct doca_flow_pipe *policed_gate;

        if (rec->direction == HW_DIR_UPLINK) {
                pipe = ctx->ul_match_pipes[rec->pipe_bucket];
                entry = rec->ul_entry;
                policed_gate = ctx->ul_color_gate_policed_pipe;
        } else {
                pipe = ctx->dl_match_pipes[rec->pipe_bucket];
                entry = rec->dl_entry;
                policed_gate = ctx->dl_color_gate_policed_pipe;
        }

        struct doca_flow_fwd fwd = {
            .type = DOCA_FLOW_FWD_PIPE,
            .next_pipe = policed_gate,
        };

        doca_error_t result = doca_flow_pipe_basic_update_entry(0, pipe, 0, NULL, /* actions: unchanged */
                                                                NULL,             /* monitor: unchanged */
                                                                &fwd,             /* fwd: shaped → policed */
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

/* ═══════════════════════════════════════════════════════════════════════
 *  Public API: Update DL_ENCAP only (for BUFF→FORW handover)
 *
 *  Updates the DL_ENCAP entry's encap actions (target gNB IP, TEID, QFI)
 *  without changing the match entry fwd.  Called before begin_drain() so
 *  that drained packets get the new outer header.
 *
 *  No-op for UL rules, rules without a DL_ENCAP entry, or when encap
 *  params haven't changed.
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

        struct doca_flow_actions encap_actions = {};
        encap_actions.encap_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;

        encap_actions.encap_cfg.encap.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
        encap_actions.encap_cfg.encap.outer.ip4.version_ihl = 0x45;
        encap_actions.encap_cfg.encap.outer.ip4.next_proto = DOCA_FLOW_PROTO_UDP;
        encap_actions.encap_cfg.encap.outer.ip4.dst_ip = msg->ohc_ipv4.s_addr;
        encap_actions.encap_cfg.encap.outer.ip4.src_ip = ctx->port_cfg.upf_n3_ip;
        encap_actions.encap_cfg.encap.outer.ip4.ttl = 64;

        encap_actions.encap_cfg.encap.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
        encap_actions.encap_cfg.encap.outer.udp.l4_port.src_port = RTE_BE16(GTP_UDP_PORT);
        encap_actions.encap_cfg.encap.outer.udp.l4_port.dst_port = RTE_BE16(GTP_UDP_PORT);

        encap_actions.encap_cfg.encap.tun.type = DOCA_FLOW_TUN_GTPU;
        encap_actions.encap_cfg.encap.tun.gtp_teid = htonl(msg->ohc_teid);
        encap_actions.encap_cfg.encap.tun.gtp_next_ext_hdr_type = GTP_EXT_PSC;
        encap_actions.encap_cfg.encap.tun.gtp_ext_psc_qfi = msg->encap_qfi;

        doca_error_t result = doca_flow_pipe_basic_update_entry(0, ctx->dl_encap_pipe, 0, &encap_actions, NULL, NULL,
                                                                DOCA_FLOW_NO_WAIT, rec->dl_encap_entry);
        if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR(
                    "update_dlencap_only: encap update failed "
                    "hw_rule_id=%u: %s",
                    msg->hw_rule_id, doca_error_get_descr(result));
                return result;
        }
        /* DL_ENCAP is on N3 (EGRESS root) — commit N3. */
        doca_flow_entries_process(ctx->n3_port, 0, 0, 0);

        DOCA_LOG_INFO(
            "update_dlencap_only: hw_rule_id=%u ENCAP updated "
            "teid=0x%x dst_ip=%08x qfi=%u (before drain)",
            msg->hw_rule_id, msg->ohc_teid, msg->ohc_ipv4.s_addr, msg->encap_qfi);
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

        /* Per-entry counters */
        for (uint32_t i = 0; i < ctx->max_hw_rules; i++) {
                dpu_rule_record_t *rec = &ctx->rules[i];
                if (!rec->in_use)
                        continue;

                const char *dir_str = (rec->direction == HW_DIR_UPLINK) ? "UL" : "DL";
                const char *mode_str = (rec->current_mode == DPU_MODE_FAST) ? "FAST" : "BUFF";

                /* Query UL match entry */
                if (rec->ul_entry) {
                        struct doca_flow_resource_query q = {};
                        doca_error_t r = doca_flow_resource_query_entry(rec->ul_entry, &q);
                        if (r == DOCA_SUCCESS) {
                                DOCA_LOG_INFO(
                                    "  hw_rule=%u UL_MATCH P%u %s %s "
                                    "pkts=%" PRIu64 " bytes=%" PRIu64,
                                    rec->hw_rule_id, rec->pipe_bucket, dir_str, mode_str, q.counter.total_pkts,
                                    q.counter.total_bytes);
                        } else {
                                DOCA_LOG_WARN("  hw_rule=%u UL_MATCH query failed: %s", rec->hw_rule_id,
                                              doca_error_get_descr(r));
                        }
                }

                /* Query DL match entry */
                if (rec->dl_entry) {
                        struct doca_flow_resource_query q = {};
                        doca_error_t r = doca_flow_resource_query_entry(rec->dl_entry, &q);
                        if (r == DOCA_SUCCESS) {
                                DOCA_LOG_INFO(
                                    "  hw_rule=%u DL_MATCH P%u %s %s "
                                    "pkts=%" PRIu64 " bytes=%" PRIu64,
                                    rec->hw_rule_id, rec->pipe_bucket, dir_str, mode_str, q.counter.total_pkts,
                                    q.counter.total_bytes);
                        } else {
                                DOCA_LOG_WARN("  hw_rule=%u DL_MATCH query failed: %s", rec->hw_rule_id,
                                              doca_error_get_descr(r));
                        }
                }
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
