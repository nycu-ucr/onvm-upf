/*
 * dpu_gtp_codec.h — Software GTP-U + PSC encap/decap helpers
 *
 * Shared between dpu_buffer (DL BUFF→FORW drain) and dpu_shaper (UL/DL
 * GBR YELLOW shaping).  Both call sites finalise wire-form packets in
 * software and Tx them on the peer port: in DOCA Flow VNF mode,
 * software-Tx'd packets traverse the EGRESS pipeline of the Tx port,
 * never re-entering the ingress ROOT.  Hardware-only encap therefore
 * does not work for these slow-path packets.
 *
 * Both helpers also clear the dynamic-metadata Tx flag and field on
 * the mbuf.  Without this, an inherited Rx pkt_meta value (stamped by
 * UL_MATCH/DL_MATCH on ingress) would be re-injected into HW pkt_meta
 * on egress.  On N3 that would re-match DL_ENCAP and double-encap a
 * SW-encapped DL frame; on N6 it is harmless today but cleared for
 * symmetry.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdint.h>

#include <rte_mbuf.h>

#include "dpu_pipeline.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Build a wire-form DL GTP-U + PSC outer header in place of the
 * mbuf's current outer Ethernet.
 *
 * On entry, @p m starts with the wire-form outer Ethernet (DN→UPF)
 * followed by the inner IPv4 datagram destined to the UE — i.e. the
 * exact byte layout received by the buffer/shaper on N6 RSS.  On
 * success, the original outer Ethernet is removed and replaced with:
 *
 *   [Ethernet (UPF_N3 → gNB)] [outer IPv4 (UPF_N3_IP → gNB_IP)]
 *   [UDP (2152 → 2152)] [GTP-U fixed (8B)]
 *   [opt-word (4B, next-ext = 0x85)] [PSC type-0 (PDU=DL, QFI)]
 *   [inner IPv4 ...]
 *
 * Outer IPv4 checksum is computed in software.  UDP checksum is set
 * to zero (RFC 768 permits this for IPv4; GTP-U traffic typically
 * carries zero UDP checksums).
 *
 * @return  0 on success, -1 on mbuf manipulation failure (no
 *          headroom).  On failure @p m is left in a possibly-stripped
 *          state; the caller is expected to free it.
 */
int dpu_gtp_encap_dl(struct rte_mbuf *m,
                     const dpu_port_cfg_t *port_cfg,
                     uint32_t ohc_ipv4_nbo,
                     uint32_t ohc_teid_host,
                     uint8_t  encap_qfi);

/**
 * Strip a UL GTP-U + (optional ext) outer envelope and prepend a
 * UPF_N6 → DN_GW outer Ethernet so the packet can be Tx'd as a
 * normal IPv4 frame on N6 — equivalent to the hardware UL_DECAP
 * action.
 *
 * On entry, @p m starts with [outer Eth (gNB→UPF)] [outer IPv4]
 * [UDP 2152] [GTP-U] [optional word, if any] [extensions, if any]
 * [inner IPv4].  On success, the outer envelope is removed and a
 * fresh Ethernet header is prepended:
 *
 *   [Ethernet (UPF_N6 → DN_GW, type=0x0800)] [inner IPv4 ...]
 *
 * Constraints (v1; violations return -1 and the caller increments
 * mal_pkt then frees the mbuf):
 *   - Outer IPv4 IHL must be 5 (no options).
 *   - GTP-U version must be 1.
 *   - GTP extension chain (when E=1) walked at most 4 hops; any
 *     extension with length 0, an unterminated chain longer than
 *     the cap, or a length that overruns the packet aborts.
 *   - Inner length must remain non-zero after stripping.
 *
 * @return  0 on success, -1 on parse / mbuf failure.
 */
int dpu_gtp_decap_ul(struct rte_mbuf *m,
                     const dpu_port_cfg_t *port_cfg);

#ifdef __cplusplus
}
#endif
