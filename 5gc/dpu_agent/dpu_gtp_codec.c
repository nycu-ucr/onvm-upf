/*
 * dpu_gtp_codec.c — Software GTP-U + PSC encap/decap helpers
 *
 * See dpu_gtp_codec.h for the rationale.  The encap helper was
 * originally in dpu_buffer.c (build_gtpu_psc_outer); it is here so
 * that dpu_shaper.c can share the same byte layout for DL YELLOW.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include <arpa/inet.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_flow.h>
#include <rte_gtp.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_udp.h>

#include "dpu_gtp_codec.h"

/* Bytes prepended after stripping the original outer Ethernet:
 *   Ethernet (14) + IPv4 (20) + UDP (8) + GTP-U (8) + opt (4) + PSC (4)
 *   = 58 bytes.
 * Net mbuf-length delta per packet for DL encap: +44 bytes. */
#define DPU_GTP_ENCAP_DL_TOTAL                                                     \
    (sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +                  \
     sizeof(struct rte_udp_hdr) + sizeof(struct rte_gtp_hdr) +                     \
     sizeof(struct rte_gtp_hdr_ext_word) + sizeof(struct rte_gtp_psc_type0_hdr) +  \
     1 /* trailing next-ext-hdr type */)

/* Byte offsets for UL decap parsing.  Computed from struct sizes so
 * the layout is locked to the DPDK headers. */
#define DPU_GTP_OUTER_PRE_GTP_LEN                              \
    (sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + \
     sizeof(struct rte_udp_hdr))

#define DPU_GTP_DECAP_MAX_EXT_HOPS 4 /* defensive cap on ext chain walk */

/* ---------------------------------------------------------------------------
 *  DL encap
 * ------------------------------------------------------------------------- */

int
dpu_gtp_encap_dl(struct rte_mbuf *m,
                 const dpu_port_cfg_t *port_cfg,
                 uint32_t ohc_ipv4_nbo,
                 uint32_t ohc_teid_host,
                 uint8_t encap_qfi)
{
    /* Strip the original outer Ethernet (DN→UPF). */
    if (rte_pktmbuf_adj(m, (uint16_t)sizeof(struct rte_ether_hdr)) == NULL)
        return -1;

    const uint16_t inner_len = rte_pktmbuf_pkt_len(m);

    char *enc = rte_pktmbuf_prepend(m, (uint16_t)DPU_GTP_ENCAP_DL_TOTAL);
    if (enc == NULL)
        return -1;

    /* Outer Ethernet — UPF_N3 → gNB. */
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)enc;
    memcpy(eth->src_addr.addr_bytes, port_cfg->upf_n3_mac, RTE_ETHER_ADDR_LEN);
    memcpy(eth->dst_addr.addr_bytes, port_cfg->gnb_mac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    /* Outer IPv4. */
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
    const uint16_t ip_total =
        (uint16_t)(sizeof(*ip) + sizeof(struct rte_udp_hdr) +
                   sizeof(struct rte_gtp_hdr) + sizeof(struct rte_gtp_hdr_ext_word) +
                   sizeof(struct rte_gtp_psc_type0_hdr) + 1 + inner_len);
    ip->version_ihl = 0x45;
    ip->type_of_service = 0;
    ip->total_length = rte_cpu_to_be_16(ip_total);
    ip->packet_id = 0;
    ip->fragment_offset = 0;
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_UDP;
    ip->hdr_checksum = 0;
    ip->src_addr = port_cfg->upf_n3_ip;
    ip->dst_addr = ohc_ipv4_nbo;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    /* Outer UDP — GTP-U on 2152, both ports. */
    struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(ip + 1);
    const uint16_t udp_len =
        (uint16_t)(sizeof(*udp) + sizeof(struct rte_gtp_hdr) +
                   sizeof(struct rte_gtp_hdr_ext_word) +
                   sizeof(struct rte_gtp_psc_type0_hdr) + 1 + inner_len);
    udp->src_port = rte_cpu_to_be_16(GTP_UDP_PORT);
    udp->dst_port = rte_cpu_to_be_16(GTP_UDP_PORT);
    udp->dgram_len = rte_cpu_to_be_16(udp_len);
    udp->dgram_cksum = 0;

    /* GTP-U fixed header.  ver=1, PT=1, E=1, S=0, PN=0; msg = G-PDU. */
    struct rte_gtp_hdr *gtp = (struct rte_gtp_hdr *)(udp + 1);
    memset(gtp, 0, sizeof(*gtp));
    gtp->ver = 1;
    gtp->pt = 1;
    gtp->e = 1;
    gtp->s = 0;
    gtp->pn = 0;
    gtp->msg_type = 0xff;
    gtp->plen = rte_cpu_to_be_16(
        (uint16_t)(sizeof(struct rte_gtp_hdr_ext_word) +
                   sizeof(struct rte_gtp_psc_type0_hdr) + 1 + inner_len));
    gtp->teid = rte_cpu_to_be_32(ohc_teid_host);

    /* Optional word: Sequence/N-PDU = 0; next ext = 0x85 (PSC). */
    struct rte_gtp_hdr_ext_word *opt = (struct rte_gtp_hdr_ext_word *)(gtp + 1);
    opt->sqn = 0;
    opt->npdu = 0;
    opt->next_ext = GTP_EXT_PSC;

    /* PSC type-0 (DL): ext_hdr_len=1 (4 bytes total), PDU type=0 (DL),
     * QFI in low 6 bits.  Trailing byte is next-ext-hdr-type = 0. */
    struct rte_gtp_psc_type0_hdr *psc =
        (struct rte_gtp_psc_type0_hdr *)(opt + 1);
    memset(psc, 0, sizeof(*psc));
    psc->ext_hdr_len = 1;
    psc->type = 0;
    psc->qfi = encap_qfi & 0x3f;
    uint8_t *psc_tail = (uint8_t *)(psc + 1);
    *psc_tail = 0;

    /* Clear inherited Rx pkt_meta + dyn-metadata flag so DL_ENCAP
     * does not re-match this frame on N3 EGRESS. */
    rte_flow_dynf_metadata_set(m, 0);
    m->ol_flags &= ~RTE_MBUF_DYNFLAG_TX_METADATA;

    return 0;
}

/* ---------------------------------------------------------------------------
 *  UL decap
 * ------------------------------------------------------------------------- */

int
dpu_gtp_decap_ul(struct rte_mbuf *m, const dpu_port_cfg_t *port_cfg)
{
    /* Need at least outer Eth + IPv4 + UDP + GTP-U fixed in one segment. */
    if (rte_pktmbuf_pkt_len(m) <
        DPU_GTP_OUTER_PRE_GTP_LEN + sizeof(struct rte_gtp_hdr))
        return -1;

    const uint8_t *base = rte_pktmbuf_mtod(m, const uint8_t *);

    /* v1 simplification: outer IPv4 IHL must be 5.  IPv4 options are
     * not expected on UPF↔gNB traffic; if we ever see them, mal_pkt
     * gets bumped on the caller side. */
    const struct rte_ipv4_hdr *ip =
        (const struct rte_ipv4_hdr *)(base + sizeof(struct rte_ether_hdr));
    if ((ip->version_ihl & 0x0f) != 5)
        return -1;

    /* GTP-U fixed header sits at offset 42. */
    const struct rte_gtp_hdr *gtp =
        (const struct rte_gtp_hdr *)(base + DPU_GTP_OUTER_PRE_GTP_LEN);
    if (gtp->ver != 1)
        return -1;

    uint16_t gtp_skip = sizeof(struct rte_gtp_hdr);

    if (gtp->e || gtp->s || gtp->pn) {
        /* Optional word (SQN/NPDU/NextExt) is present whenever any of
         * E/S/PN is set. */
        if (rte_pktmbuf_pkt_len(m) <
            DPU_GTP_OUTER_PRE_GTP_LEN + gtp_skip +
                sizeof(struct rte_gtp_hdr_ext_word))
            return -1;
        const struct rte_gtp_hdr_ext_word *opt =
            (const struct rte_gtp_hdr_ext_word *)
                (base + DPU_GTP_OUTER_PRE_GTP_LEN + gtp_skip);
        gtp_skip += (uint16_t)sizeof(struct rte_gtp_hdr_ext_word);

        if (gtp->e) {
            uint8_t next_ext = opt->next_ext;
            for (int hop = 0; next_ext != 0 && hop < DPU_GTP_DECAP_MAX_EXT_HOPS;
                 hop++) {
                /* Need at least the length byte. */
                if (rte_pktmbuf_pkt_len(m) <
                    DPU_GTP_OUTER_PRE_GTP_LEN + gtp_skip + 1)
                    return -1;
                const uint8_t *ext_hdr =
                    base + DPU_GTP_OUTER_PRE_GTP_LEN + gtp_skip;
                uint8_t ext_words = ext_hdr[0]; /* length in 4-byte words */
                if (ext_words == 0)
                    return -1;
                uint16_t ext_bytes = (uint16_t)ext_words * 4;
                if (rte_pktmbuf_pkt_len(m) <
                    DPU_GTP_OUTER_PRE_GTP_LEN + gtp_skip + ext_bytes)
                    return -1;
                /* Last byte of the extension is the next-ext-hdr-type. */
                next_ext = ext_hdr[ext_bytes - 1];
                gtp_skip += ext_bytes;
            }
            if (next_ext != 0)
                return -1; /* chain longer than the cap */
        }
    }

    const uint16_t total_strip =
        (uint16_t)(DPU_GTP_OUTER_PRE_GTP_LEN + gtp_skip);

    if (rte_pktmbuf_pkt_len(m) <= total_strip)
        return -1;

    if (rte_pktmbuf_adj(m, total_strip) == NULL)
        return -1;

    char *eth_p =
        rte_pktmbuf_prepend(m, (uint16_t)sizeof(struct rte_ether_hdr));
    if (eth_p == NULL)
        return -1;

    struct rte_ether_hdr *new_eth = (struct rte_ether_hdr *)eth_p;
    memcpy(new_eth->src_addr.addr_bytes, port_cfg->upf_n6_mac,
           RTE_ETHER_ADDR_LEN);
    memcpy(new_eth->dst_addr.addr_bytes, port_cfg->dn_gw_mac,
           RTE_ETHER_ADDR_LEN);
    new_eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    rte_flow_dynf_metadata_set(m, 0);
    m->ol_flags &= ~RTE_MBUF_DYNFLAG_TX_METADATA;

    return 0;
}
