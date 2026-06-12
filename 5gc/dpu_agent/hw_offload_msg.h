/*
 * hw_offload_msg.h — Hardware-offload message exchanged between UPF-C,
 *                     Host Agent, and DPU Agent.
 *
 * This flat C struct is allocated by UPF-C via rte_malloc (hugepage-visible
 * to all ONVM secondaries), sent over the lockless ONVM ring to the Host
 * Agent, serialised across PCIe via DOCA Comch, and finally consumed by the
 * DPU Agent to program DOCA Flow entries in switch,hws mode.
 *
 * Byte-order contract  (DPU Agent converts to NBO for DOCA Flow):
 *   - teid, ohc_teid          : HOST order  (ntohl already applied by UPDK)
 *   - fteid_ipv4, ue_ipv4,
 *     ohc_ipv4                : NBO         (struct in_addr, raw copy)
 *   - sdf_src_ip, sdf_dst_ip  : HOST order  (phb_parse_flow_description)
 *   - sdf_src_port, sdf_dst_port : HOST order
 *   - mbr_N, gbr_N (N=ul,dl)  : HOST order, kbps
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdint.h>
#include <arpa/inet.h>   /* struct in_addr */

#ifdef __cplusplus
extern "C" {
#endif

/* ── Operation type ─────────────────────────────────────────────────── */
enum hw_offload_op {
    HW_OP_CREATE      = 1,   /* create a new rule                          */
    HW_OP_DELETE      = 2,   /* delete a rule by hw_rule_id                */
    HW_OP_UPDATE_FAR  = 3,   /* update FAR (action/fwd change, BUFF⇄FORW)  */
    HW_OP_UPDATE_QER  = 4,   /* update QER (meter rates / gate)             */
    HW_OP_UPDATE_PDR  = 5,   /* update PDR (match fields / precedence)      */
};

/* ── Direction (derived from PDI sourceInterface) ──────────────────── */
enum hw_offload_dir {
    HW_DIR_UPLINK   = 0,  /* N3 → N6  (access → core)                  */
    HW_DIR_DOWNLINK = 1,  /* N6 → N3  (core → access)                  */
};

/* ── FAR apply-action flags (mirrors UPDK, kept for DPU self-contained) */
enum hw_far_action {
    HW_ACTION_DROP = 1,
    HW_ACTION_FORW = 2,
    HW_ACTION_BUFF = 4,
    HW_ACTION_NOCP = 8,
};

/* ── Outer-header-creation description ─────────────────────────────── */
enum hw_ohc_desc {
    HW_OHC_NONE            = 0,
    HW_OHC_GTPU_UDP_IPV4   = 1,
    HW_OHC_GTPU_UDP_IPV6   = 2,
    HW_OHC_UDP_IPV4         = 3,
    HW_OHC_UDP_IPV6         = 4,
};

/* ═══════════════════════════════════════════════════════════════════════
 *  The flat message — fits in a single DOCA Comch payload (< 4 KiB).
 * ═══════════════════════════════════════════════════════════════════════ */
typedef struct __attribute__((packed)) hw_offload_msg {
    /* ── Header ──────────────────────────────────────────────────────── */
    uint32_t  magic;           /* HW_OFFLOAD_MAGIC — quick sanity check  */
    uint8_t   op;              /* enum hw_offload_op                      */
    uint8_t   direction;       /* enum hw_offload_dir                     */
    uint16_t  pdr_id;          /* per-session PDR ID (for logging only)   */
    uint32_t  hw_rule_id;      /* globally unique ID (survives domain
                                * crossing via pkt_meta / dv_xmeta_en=4) */
    uint32_t  precedence;      /* 3GPP precedence (lower = higher prio)   */

    /* ── Match: GTP tunnel (UL only) ─────────────────────────────────── */
    uint32_t       teid;       /* HOST order                              */
    struct in_addr fteid_ipv4; /* NBO — local F-TEID IPv4                 */

    /* ── Match: UE address ───────────────────────────────────────────── */
    struct in_addr ue_ipv4;    /* NBO — UE IP address                     */

    /* ── Match: QoS Flow Identifier ──────────────────────────────────── */
    uint8_t   qfi;             /* PDI match QFI (UL pipe), 0 = wildcard   */
    uint8_t   encap_qfi;       /* QER QFI for GTP ext hdr (DL encap)      */

    /* ── Match: SDF 5-tuple (from flowDescription parsing) ───────────── */
    uint8_t   has_sdf;         /* 1 if SDF filter present                 */
    uint8_t   sdf_proto;       /* IP protocol (0 = any)                   */
    uint8_t   sdf_src_pref;    /* source prefix len (0 = wildcard)        */
    uint8_t   sdf_dst_pref;    /* dest prefix len   (0 = wildcard)        */
    uint8_t   _pad1[2];        /* alignment padding                       */
    uint32_t  sdf_src_ip;      /* HOST order                              */
    uint32_t  sdf_dst_ip;      /* HOST order                              */
    uint16_t  sdf_src_port;    /* HOST order (0 = wildcard)               */
    uint16_t  sdf_dst_port;    /* HOST order (0 = wildcard)               */

    /* ── FAR: Forwarding Action ──────────────────────────────────────── */
    uint8_t   apply_action;    /* enum hw_far_action                      */
    uint8_t   outer_hdr_removal; /* OUTER_HEADER_REMOVAL_GTP_IP4 etc.
                                  * 0xFF = not present                     */

    /* ── FAR: Outer Header Creation (DL encap) ───────────────────────── */
    uint8_t   ohc_desc;        /* enum hw_ohc_desc                        */
    uint8_t   _pad2;
    uint32_t  ohc_teid;        /* HOST order                              */
    struct in_addr ohc_ipv4;   /* NBO — remote gNB F-TEID IPv4            */

    uint8_t   _pad3[4];        /* align uint64_t block to 8-byte boundary */

    /* ── QER: bit-rate enforcement (trTCM RFC 2698) ──────────────────── */
    uint64_t  mbr_ul;          /* Maximum Bit Rate uplink   (kbps)        */
    uint64_t  mbr_dl;          /* Maximum Bit Rate downlink (kbps)        */
    uint64_t  gbr_ul;          /* Guaranteed Bit Rate uplink   (kbps)     */
    uint64_t  gbr_dl;          /* Guaranteed Bit Rate downlink (kbps)     */

} hw_offload_msg_t;

/* Magic value for quick validation */
#define HW_OFFLOAD_MAGIC  0x48574F46u   /* "HWOF" in ASCII                */

/* Sanity: ensure the struct fits in a DOCA Comch message (typically 4 KiB) */
_Static_assert(sizeof(hw_offload_msg_t) <= 4096,
               "hw_offload_msg_t exceeds DOCA Comch payload limit");

#ifdef __cplusplus
}
#endif
