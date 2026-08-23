/*
# Copyright 2026 University of California, Riverside and National Yang Ming Chiao Tung University
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
*/

#include <rte_byteorder.h>
#include <rte_icmp.h>
#include <rte_ip.h>
#include <rte_cksum.h>

#include "upf_u_config.h"
#include "upf_u_helper.h"
#include "upf_u_icmp.h"
#include "utlt_debug.h"

static inline int
upf_is_local_ipv4(uint32_t dst_ip_be) {
    return (dst_ip_be == g_n3_ip_be || dst_ip_be == g_n6_ip_be);
}

static inline uint32_t
upf_local_ip_for_port(uint16_t port) {
    if (port == g_n3_port) return g_n3_ip_be;
    if (port == g_n6_port) return g_n6_ip_be;
    return 0;
}

static inline uint16_t
raw_cksum_fold(uint32_t sum) {
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum);
}

static inline uint16_t
icmp_checksum(const void *buf, size_t len) {
    uint32_t sum = rte_raw_cksum(buf, len);
    return raw_cksum_fold(sum);
}

/*
 * Handle ICMP echo request sent to UPF-U local IP.
 *
 * Return:
 *   1 -> packet consumed here (either replied or dropped)
 *   0 -> not handled, caller should continue normal pipeline
 */
int
handle_local_icmp_echo(struct rte_mbuf *pkt,
                       struct onvm_pkt_meta *meta,
                       struct onvm_nf_local_ctx *nf_local_ctx) {
    struct rte_ether_hdr *eth;
    struct rte_ipv4_hdr *iph;
    struct rte_icmp_hdr *icmp;
    uint16_t ip_hdr_len;
    uint16_t icmp_len;
    uint32_t old_src_ip, old_dst_ip;
    struct rte_ether_addr old_src_mac, old_dst_mac;

    if (pkt == NULL || meta == NULL || nf_local_ctx == NULL || nf_local_ctx->nf == NULL)
        return 0;

    eth = onvm_pkt_ether_hdr(pkt);
    if (eth == NULL)
        return 0;

    if (rte_be_to_cpu_16(eth->ether_type) != RTE_ETHER_TYPE_IPV4)
        return 0;

    iph = onvm_pkt_ipv4_hdr(pkt);
    if (iph == NULL)
        return 0;

    if (iph->next_proto_id != IPPROTO_ICMP)
        return 0;

    if (!upf_is_local_ipv4(iph->dst_addr))
        return 0;

    /* NAT public-IP traffic on N6 must stay in the UPF datapath (DNAT),
     * not be consumed by local ICMP handling. */
    if (g_nat_enabled && pkt->port == g_n6_port &&
        iph->dst_addr == g_nat_public_ip_be)
        return 0;

    ip_hdr_len = (uint16_t)((iph->version_ihl & 0x0f) * 4);
    if (unlikely(ip_hdr_len < sizeof(struct rte_ipv4_hdr))) {
        meta->action = ONVM_NF_ACTION_DROP;
        return 1;
    }

    if (unlikely(pkt->pkt_len < sizeof(struct rte_ether_hdr) + ip_hdr_len + sizeof(struct rte_icmp_hdr))) {
        meta->action = ONVM_NF_ACTION_DROP;
        return 1;
    }

    icmp = rte_pktmbuf_mtod_offset(pkt, struct rte_icmp_hdr *,
                                   sizeof(struct rte_ether_hdr) + ip_hdr_len);
    if (icmp == NULL) {
        meta->action = ONVM_NF_ACTION_DROP;
        return 1;
    }

    if (icmp->icmp_type != RTE_ICMP_TYPE_ECHO_REQUEST) {
        /* Destination is local UPF-U, but not Echo Request.
         * For now consume locally to avoid falling into GTP/PDR path. */
        UTLT_Debug("ICMP to local UPF-U is not echo request (type=%u), drop", icmp->icmp_type);
        meta->action = ONVM_NF_ACTION_DROP;
        return 1;
    }

    /* total_length is IPv4 header + payload */
    uint16_t total_len = rte_be_to_cpu_16(iph->total_length);
    if (unlikely(total_len < ip_hdr_len + sizeof(struct rte_icmp_hdr))) {
        meta->action = ONVM_NF_ACTION_DROP;
        return 1;
    }

    icmp_len = total_len - ip_hdr_len;

    /*
     * Build Echo Reply in-place.
     * Ethernet: swap src/dst MAC
     * IPv4:     swap src/dst IP, refresh checksum
     * ICMP:     request -> reply, refresh checksum
     */
    old_src_ip = iph->src_addr;
    old_dst_ip = iph->dst_addr;

    rte_ether_addr_copy(&eth->src_addr, &old_src_mac);
    rte_ether_addr_copy(&eth->dst_addr, &old_dst_mac);

    rte_ether_addr_copy(&old_dst_mac, &eth->src_addr);
    rte_ether_addr_copy(&old_src_mac, &eth->dst_addr);

    iph->src_addr = old_dst_ip;
    iph->dst_addr = old_src_ip;
    iph->time_to_live = 64;
    iph->hdr_checksum = 0;
    iph->hdr_checksum = rte_ipv4_cksum(iph);

    icmp->icmp_type = RTE_ICMP_TYPE_ECHO_REPLY;
    icmp->icmp_code = 0;
    icmp->icmp_cksum = 0;
    icmp->icmp_cksum = icmp_checksum(icmp, icmp_len);

    meta->destination = pkt->port;
    meta->action = ONVM_NF_ACTION_OUT;

    UTLT_Info("Locally generated ICMP Echo Reply on port=%u, src=%s dst=%s",
              pkt->port,
              convertToIpAddressString(iph->src_addr),
              convertToIpAddressString(iph->dst_addr));

    return 1;
}