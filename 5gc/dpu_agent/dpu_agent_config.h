/*
 * dpu_agent_config.h — DOCA Arg Parser configuration for DPU Agent
 *
 * Defines the configuration struct populated by doca_argp callbacks
 * (CLI flags and/or JSON config file via -j / --json).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DPU_AGENT_CONFIG_H
#define DPU_AGENT_CONFIG_H

#include <stdint.h>
#include <doca_error.h>

/**
 * DPU Agent runtime configuration.
 *
 * String fields are filled by doca_argp STRING callbacks.
 * Integer fields are filled by doca_argp INT callbacks.
 * Binary fields (MAC, IP) are derived from strings after argp_start
 * by calling finalize_config().
 */
typedef struct dpu_agent_cfg {
    /* ── Comch ────────────────────────────────────────────────── */
    char     comch_pci[32];          /* BF3 PCI for Comch device       */
    char     rep_pci[32];            /* Host PF representor PCI        */
    char     server_name[64];        /* Comch server name              */

    /* ── DOCA Flow port PCI addresses ─────────────────────────── */
    char     n3_pci[32];             /* N3 physical port (PF0)         */
    char     n6_pci[32];             /* N6 physical port (PF1)         */
    char     vf_pci[32];             /* Host VF PCI (optional)         */

    /* ── Port IDs ─────────────────────────────────────────────── */
    int      n3_port_id;
    int      n6_port_id;
    int      host_vf_port_id;

    /* ── Network (string form — populated by argp callbacks) ──── */
    char     upf_n3_ip_str[64];      /* UPF N3 IPv4 dotted-quad        */
    char     upf_n3_mac_str[20];     /* xx:xx:xx:xx:xx:xx              */
    char     gnb_mac_str[20];
    char     upf_n6_mac_str[20];
    char     dn_gw_mac_str[20];

    /* ── Network (binary form — set by finalize_config) ────────── */
    uint32_t upf_n3_ip;              /* NBO                            */
    uint8_t  upf_n3_mac[6];
    uint8_t  gnb_mac[6];
    uint8_t  upf_n6_mac[6];
    uint8_t  dn_gw_mac[6];
} dpu_agent_cfg_t;

/**
 * Register all DPU Agent parameters with doca_argp.
 * Must be called after doca_argp_init() and before doca_argp_start().
 */
doca_error_t register_dpu_agent_params(void);

#endif /* DPU_AGENT_CONFIG_H */
