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


/* ── STRING callbacks ─────────────────────────────────────────────── */
STRING_CB(cb_comch_pci,      comch_pci,       32)
STRING_CB(cb_rep_pci,        rep_pci,         32)
STRING_CB(cb_server_name,    server_name,     64)
STRING_CB(cb_n3_pci,         n3_pci,          32)
STRING_CB(cb_n6_pci,         n6_pci,          32)
STRING_CB(cb_vf_pci,         vf_pci,          32)
STRING_CB(cb_upf_n3_ip,      upf_n3_ip_str,   64)
STRING_CB(cb_upf_n3_mac,     upf_n3_mac_str,  20)
STRING_CB(cb_gnb_mac,        gnb_mac_str,     20)
STRING_CB(cb_upf_n6_mac,     upf_n6_mac_str,  20)
STRING_CB(cb_dn_gw_mac,      dn_gw_mac_str,   20)

/* ── INT callbacks ────────────────────────────────────────────────── */
INT_CB(cb_n3_port,           n3_port_id)
INT_CB(cb_n6_port,           n6_port_id)
INT_CB(cb_vf_port,           host_vf_port_id)


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

    r = reg_str(NULL, "vf-pci",
                "Host VF PCI address (optional; falls back to N3 device)",
                cb_vf_pci, false);
    if (r != DOCA_SUCCESS) return r;

    r = reg_int(NULL, "n3-port",
                "N3 physical port ID (default: 0)",
                cb_n3_port);
    if (r != DOCA_SUCCESS) return r;

    r = reg_int(NULL, "n6-port",
                "N6 physical port ID (default: 1)",
                cb_n6_port);
    if (r != DOCA_SUCCESS) return r;

    r = reg_int(NULL, "vf-port",
                "Host VF representor port ID (default: 2)",
                cb_vf_port);
    if (r != DOCA_SUCCESS) return r;

    /* ── Network addresses ────────────────────────────────────── */
    r = reg_str(NULL, "upf-n3-ip",
                "UPF N3 IPv4 address for DL GTP encap (required)",
                cb_upf_n3_ip, true);
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

    return DOCA_SUCCESS;
}
