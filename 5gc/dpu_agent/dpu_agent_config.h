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
    /* Probe order determines DPDK ethdev IDs and DOCA Flow port IDs:
     *   N3 PF is probed first  → DPDK port 0 → DOCA Flow port 0
     *   N6 PF is probed second → DPDK port 1 → DOCA Flow port 1
     * Port IDs are therefore NOT configurable — they come from
     * DPU_PORT_ID_N3 / DPU_PORT_ID_N6 in dpu_pipeline.h. */
    char     n3_pci[32];             /* N3 physical port (PF0)         */
    char     n6_pci[32];             /* N6 physical port (PF1)         */

    /* ── Network (string form — populated by argp callbacks) ──── */
    char     upf_n3_ip_str[64];      /* UPF N3 IPv4 dotted-quad        */
    char     upf_n6_ip_str[64];      /* UPF N6 IPv4 dotted-quad
                                      * (used by the ARP responder to
                                      *  answer ARP on the N6 side;
                                      *  empty disables N6 responder)  */
    char     gnb_ip_str[64];         /* gNB IPv4 (peer on the N3 wire)
                                      * — used to craft proactive
                                      *  unicast-ARP-reply refreshes on
                                      *  N3.  Empty disables.          */
    char     dn_gw_ip_str[64];       /* DN gateway IPv4 (peer on N6
                                      *  wire) — same purpose for N6.  */
    char     upf_n3_mac_str[20];     /* xx:xx:xx:xx:xx:xx              */
    char     gnb_mac_str[20];
    char     upf_n6_mac_str[20];
    char     dn_gw_mac_str[20];

    /* ── Network (binary form — set by finalize_config) ────────── */
    uint32_t upf_n3_ip;              /* NBO                            */
    uint32_t upf_n6_ip;              /* NBO (0 disables N6 responder)  */
    uint32_t gnb_ip;                 /* NBO (0 disables N3 unicast
                                      *  ARP-reply refresh)             */
    uint32_t dn_gw_ip;               /* NBO (0 disables N6 unicast
                                      *  ARP-reply refresh)             */
    uint8_t  upf_n3_mac[6];
    uint8_t  gnb_mac[6];
    uint8_t  upf_n6_mac[6];
    uint8_t  dn_gw_mac[6];

    /* ── Pipeline capacity (populated by JSON / CLI, or defaults) ── */
    int      max_hw_rules;           /* software rule array capacity    */
    int      nr_counters;            /* DOCA Flow global counters       */
    int      nr_meters;              /* DOCA Flow global meters         */
    int      nr_shared_meters;       /* DOCA Flow shared meter pool     */
    int      port_nr_encap;          /* per-port ENCAP resources        */
    int      port_nr_decap;          /* per-port DECAP resources        */
    int      port_nr_meter;          /* per-port METER resources        */
    int      port_actions_mem;       /* per-port action memory (bytes)  */
    int      match_entries_per_bucket; /* nr_entries per UL/DL_MATCH pipe */
    int      dl_encap_entries;       /* nr_entries for DL_ENCAP pipe    */

    /* ── BDP buffer allocator (byte-budget + EWMA max-min) ──────── */
    uint64_t m_op_bytes;             /* global byte budget;
                                      * UINT64_MAX = OFF (legacy caps)  */
    int      default_seed_rate_kbps; /* cold-start seed, no-QoS flows   */
    int      t_hold_ms;              /* demand horizon (ms)             */
    int      tick_ms;                /* control-tick interval (ms)      */
    int      ewma_alpha_pct;         /* EWMA weight 0..100              */
    int      measure_demand;         /* 1 = EWMA (product);
                                      * 0 = static seed (v1 ablation)   */

    /* ── GBR YELLOW buffered shaper ─────────────────────────────── */
    uint64_t m_shape_bytes;          /* global queued-byte budget for the
                                      * shaper; 0 = buffering OFF (legacy
                                      * token-bucket pass/drop policer)  */
    int      shape_max_delay_ms;     /* delay target deriving per-flow
                                      * q_max_bytes = EIR * delay / 1000 */

    /* ── Feature toggles ──────────────────────────────────────── */
    int      enable_arp_responder;   /* 0 = ARP falls through to catch-
                                      * all / TO_HOST → host kernel
                                      * (simpler path when the host PF
                                      * owns the UPF-facing IP).
                                      * 1 = BF3 ARM answers ARP itself
                                      * via the responder lcore.      */
} dpu_agent_cfg_t;

/**
 * Register all DPU Agent parameters with doca_argp.
 * Must be called after doca_argp_init() and before doca_argp_start().
 */
doca_error_t register_dpu_agent_params(void);

#endif /* DPU_AGENT_CONFIG_H */
