/*
 * dpu_agent_config.c — DOCA Arg Parser parameter registration for DPU Agent
 *
 * Registers all application-specific CLI / JSON parameters with doca_argp.
 * Each parameter has a callback that writes the value into dpu_agent_cfg_t.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "dpu_agent_config.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <doca_argp.h>
#include <doca_error.h>
#include <doca_log.h>

DOCA_LOG_REGISTER(DPU_AGENT_CONFIG);


/* ═══════════════════════════════════════════════════════════════════════
 *  Callback macros — every STRING/INT callback follows the same pattern
 * ═══════════════════════════════════════════════════════════════════════ */

#define STRING_CB(func_name, field, max_len)                               \
    static doca_error_t func_name(void *param, void *config)               \
    {                                                                      \
        dpu_agent_cfg_t *cfg = (dpu_agent_cfg_t *)config;                  \
        snprintf(cfg->field, (max_len), "%s", (const char *)param);        \
        return DOCA_SUCCESS;                                               \
    }

#define INT_CB(func_name, field)                                           \
    static doca_error_t func_name(void *param, void *config)               \
    {                                                                      \
        dpu_agent_cfg_t *cfg = (dpu_agent_cfg_t *)config;                  \
        cfg->field = *(int *)param;                                        \
        return DOCA_SUCCESS;                                               \
    }

/* For 64-bit values that can exceed INT_MAX (e.g. byte budgets).  Registered
 * as a STRING param and parsed with strtoull (accepts decimal and 0x...). */
#define UINT64_CB(func_name, field)                                        \
    static doca_error_t func_name(void *param, void *config)               \
    {                                                                      \
        dpu_agent_cfg_t *cfg = (dpu_agent_cfg_t *)config;                  \
        cfg->field = strtoull((const char *)param, NULL, 0);               \
        return DOCA_SUCCESS;                                               \
    }


/* ── STRING callbacks ─────────────────────────────────────────────── */
STRING_CB(cb_comch_pci,      comch_pci,       32)
STRING_CB(cb_rep_pci,        rep_pci,         32)
STRING_CB(cb_server_name,    server_name,     64)
STRING_CB(cb_n3_pci,         n3_pci,          32)
STRING_CB(cb_n6_pci,         n6_pci,          32)
STRING_CB(cb_upf_n3_ip,      upf_n3_ip_str,   64)
STRING_CB(cb_upf_n6_ip,      upf_n6_ip_str,   64)
STRING_CB(cb_gnb_ip,         gnb_ip_str,      64)
STRING_CB(cb_dn_gw_ip,       dn_gw_ip_str,    64)
STRING_CB(cb_upf_n3_mac,     upf_n3_mac_str,  20)
STRING_CB(cb_gnb_mac,        gnb_mac_str,     20)
STRING_CB(cb_upf_n6_mac,     upf_n6_mac_str,  20)
STRING_CB(cb_dn_gw_mac,      dn_gw_mac_str,   20)

/* ── Pipeline capacity INT callbacks ─────────────────────────────── */
INT_CB(cb_max_hw_rules,           max_hw_rules)
INT_CB(cb_nr_counters,            nr_counters)
INT_CB(cb_nr_meters,              nr_meters)
INT_CB(cb_nr_shared_meters,       nr_shared_meters)
INT_CB(cb_port_nr_encap,          port_nr_encap)
INT_CB(cb_port_nr_decap,          port_nr_decap)
INT_CB(cb_port_nr_meter,          port_nr_meter)
INT_CB(cb_port_actions_mem,       port_actions_mem)
INT_CB(cb_match_entries_per_bucket, match_entries_per_bucket)
INT_CB(cb_dl_encap_entries,       dl_encap_entries)
INT_CB(cb_enable_arp_responder,   enable_arp_responder)

/* ── BDP buffer allocator callbacks ──────────────────────────────── */
UINT64_CB(cb_m_op_bytes,             m_op_bytes)
INT_CB(cb_default_seed_rate_kbps,    default_seed_rate_kbps)
INT_CB(cb_t_hold_ms,                 t_hold_ms)
INT_CB(cb_tick_ms,                   tick_ms)
INT_CB(cb_ewma_alpha_pct,            ewma_alpha_pct)
INT_CB(cb_measure_demand,            measure_demand)

/* ── GBR YELLOW buffered shaper callbacks ────────────────────────── */
UINT64_CB(cb_m_shape_bytes,          m_shape_bytes)
INT_CB(cb_shape_max_delay_ms,        shape_max_delay_ms)


/* ═══════════════════════════════════════════════════════════════════════
 *  Registration helpers
 * ═══════════════════════════════════════════════════════════════════════ */

static doca_error_t
reg_str(const char *sname, const char *lname, const char *desc,
        doca_error_t (*cb)(void *, void *), bool mandatory)
{
    struct doca_argp_param *p;
    doca_error_t r;

    r = doca_argp_param_create(&p);
    if (r != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create argp param '%s': %s",
                     lname, doca_error_get_descr(r));
        return r;
    }

    if (sname)
        doca_argp_param_set_short_name(p, sname);
    doca_argp_param_set_long_name(p, lname);
    doca_argp_param_set_description(p, desc);
    doca_argp_param_set_callback(p, cb);
    doca_argp_param_set_type(p, DOCA_ARGP_TYPE_STRING);
    if (mandatory)
        doca_argp_param_set_mandatory(p);

    return doca_argp_register_param(p);
}

static doca_error_t
reg_int(const char *sname, const char *lname, const char *desc,
        doca_error_t (*cb)(void *, void *))
{
    struct doca_argp_param *p;
    doca_error_t r;

    r = doca_argp_param_create(&p);
    if (r != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create argp param '%s': %s",
                     lname, doca_error_get_descr(r));
        return r;
    }

    if (sname)
        doca_argp_param_set_short_name(p, sname);
    doca_argp_param_set_long_name(p, lname);
    doca_argp_param_set_description(p, desc);
    doca_argp_param_set_callback(p, cb);
    doca_argp_param_set_type(p, DOCA_ARGP_TYPE_INT);

    return doca_argp_register_param(p);
}


/* ═══════════════════════════════════════════════════════════════════════
 *  Public API
 * ═══════════════════════════════════════════════════════════════════════ */

doca_error_t
register_dpu_agent_params(void)
{
    doca_error_t r;

    /* ── Comch ────────────────────────────────────────────────── */
    r = reg_str("p", "comch-pci",
                "BF3 PCI for Comch device (default: 03:00.0)",
                cb_comch_pci, false);
    if (r != DOCA_SUCCESS) return r;

    r = reg_str("r", "rep-pci",
                "Host PF representor PCI on BF3 (required)",
                cb_rep_pci, true);
    if (r != DOCA_SUCCESS) return r;

    r = reg_str("s", "server-name",
                "Comch server name (default: dpu_agent)",
                cb_server_name, false);
    if (r != DOCA_SUCCESS) return r;

    /* ── DOCA Flow ports ──────────────────────────────────────── */
    r = reg_str(NULL, "n3-pci",
                "N3 physical port PCI address (default: 03:00.0)",
                cb_n3_pci, false);
    if (r != DOCA_SUCCESS) return r;

    r = reg_str(NULL, "n6-pci",
                "N6 physical port PCI address (default: 03:00.1)",
                cb_n6_pci, false);
    if (r != DOCA_SUCCESS) return r;

    /* ── Network addresses ────────────────────────────────────── */
    r = reg_str(NULL, "upf-n3-ip",
                "UPF N3 IPv4 address for DL GTP encap (required)",
                cb_upf_n3_ip, true);
    if (r != DOCA_SUCCESS) return r;

    r = reg_str(NULL, "upf-n6-ip",
                "UPF N6 IPv4 address for ARP responder "
                "(optional; empty disables N6-side ARP responder)",
                cb_upf_n6_ip, false);
    if (r != DOCA_SUCCESS) return r;

    r = reg_str(NULL, "gnb-ip",
                "gNB IPv4 address (peer on N3 wire) — used for proactive "
                "unicast-ARP-reply refresh.  Optional; empty disables.",
                cb_gnb_ip, false);
    if (r != DOCA_SUCCESS) return r;

    r = reg_str(NULL, "dn-gw-ip",
                "DN gateway IPv4 address (peer on N6 wire) — used for "
                "proactive unicast-ARP-reply refresh.  Optional; empty disables.",
                cb_dn_gw_ip, false);
    if (r != DOCA_SUCCESS) return r;

    r = reg_str(NULL, "upf-n3-mac",
                "UPF N3 MAC for DL encap outer src (xx:xx:xx:xx:xx:xx)",
                cb_upf_n3_mac, false);
    if (r != DOCA_SUCCESS) return r;

    r = reg_str(NULL, "gnb-mac",
                "gNB MAC for DL encap outer dst (xx:xx:xx:xx:xx:xx)",
                cb_gnb_mac, false);
    if (r != DOCA_SUCCESS) return r;

    r = reg_str(NULL, "upf-n6-mac",
                "UPF N6 MAC for UL L2 inject src (xx:xx:xx:xx:xx:xx)",
                cb_upf_n6_mac, false);
    if (r != DOCA_SUCCESS) return r;

    r = reg_str(NULL, "dn-gw-mac",
                "DN gateway MAC for UL L2 inject dst (xx:xx:xx:xx:xx:xx)",
                cb_dn_gw_mac, false);
    if (r != DOCA_SUCCESS) return r;

    /* ── Pipeline capacity ────────────────────────────────────── */
    r = reg_int(NULL, "max-hw-rules",
                "Max tracked HW-offloaded rules (default: 4096)",
                cb_max_hw_rules);
    if (r != DOCA_SUCCESS) return r;

    r = reg_int(NULL, "nr-counters",
                "DOCA Flow global counter resources (default: 4096)",
                cb_nr_counters);
    if (r != DOCA_SUCCESS) return r;

    r = reg_int(NULL, "nr-meters",
                "DOCA Flow global meter resources (default: 4096)",
                cb_nr_meters);
    if (r != DOCA_SUCCESS) return r;

    r = reg_int(NULL, "nr-shared-meters",
                "DOCA Flow shared meter pool size (default: 4096)",
                cb_nr_shared_meters);
    if (r != DOCA_SUCCESS) return r;

    r = reg_int(NULL, "port-nr-encap",
                "Per-port ENCAP resource count (default: 4096)",
                cb_port_nr_encap);
    if (r != DOCA_SUCCESS) return r;

    r = reg_int(NULL, "port-nr-decap",
                "Per-port DECAP resource count (default: 4096)",
                cb_port_nr_decap);
    if (r != DOCA_SUCCESS) return r;

    r = reg_int(NULL, "port-nr-meter",
                "Per-port METER resource count (default: 4096)",
                cb_port_nr_meter);
    if (r != DOCA_SUCCESS) return r;

    r = reg_int(NULL, "port-actions-mem",
                "Per-port action memory in bytes (default: 1048576)",
                cb_port_actions_mem);
    if (r != DOCA_SUCCESS) return r;

    r = reg_int(NULL, "match-entries-per-bucket",
                "Nr entries per UL/DL_MATCH pipe (default: 2048)",
                cb_match_entries_per_bucket);
    if (r != DOCA_SUCCESS) return r;

    r = reg_int(NULL, "dl-encap-entries",
                "Nr entries for DL_ENCAP pipe (default: 2048)",
                cb_dl_encap_entries);
    if (r != DOCA_SUCCESS) return r;

    /* ── Feature toggles ──────────────────────────────────────── */
    r = reg_int(NULL, "enable-arp-responder",
                "Answer ARP on BF3 ARM (1) vs fall through to host "
                "kernel via catch-all (0, default)",
                cb_enable_arp_responder);
    if (r != DOCA_SUCCESS) return r;

    /* ── BDP buffer allocator (byte-budget + EWMA max-min) ──────── */
    r = reg_str(NULL, "m-op-bytes",
                "Buffer allocator global byte budget (string; omit or "
                "0xFFFFFFFFFFFFFFFF = OFF → legacy packet caps)",
                cb_m_op_bytes, false);
    if (r != DOCA_SUCCESS) return r;

    r = reg_int(NULL, "default-seed-rate-kbps",
                "Cold-start seed rate for no-QoS buffered flows, kbps "
                "(default: 10000)",
                cb_default_seed_rate_kbps);
    if (r != DOCA_SUCCESS) return r;

    r = reg_int(NULL, "t-hold-ms",
                "Buffer allocator demand horizon T_hold, ms (default: 1000)",
                cb_t_hold_ms);
    if (r != DOCA_SUCCESS) return r;

    r = reg_int(NULL, "tick-ms",
                "Buffer allocator control-tick interval, ms (default: 100)",
                cb_tick_ms);
    if (r != DOCA_SUCCESS) return r;

    r = reg_int(NULL, "ewma-alpha",
                "Buffer allocator EWMA weight, percent 0..100 (default: 30)",
                cb_ewma_alpha_pct);
    if (r != DOCA_SUCCESS) return r;

    r = reg_int(NULL, "measure-demand",
                "Buffer allocator: 1 = EWMA-measured demand (default); "
                "0 = static QoS-seed demand (v1 ablation)",
                cb_measure_demand);
    if (r != DOCA_SUCCESS) return r;

    /* ── GBR YELLOW buffered shaper ───────────────────────────────── */
    r = reg_str(NULL, "m-shape-bytes",
                "GBR shaper global queued-byte budget (string; "
                "0 = OFF → legacy token-bucket pass/drop policer; "
                "default: 1073741824 = 1 GiB)",
                cb_m_shape_bytes, false);
    if (r != DOCA_SUCCESS) return r;

    r = reg_int(NULL, "shape-max-delay-ms",
                "GBR shaper per-flow delay target deriving q_max_bytes = "
                "EIR * delay / 1000 (default: 50)",
                cb_shape_max_delay_ms);
    if (r != DOCA_SUCCESS) return r;

    return DOCA_SUCCESS;
}
