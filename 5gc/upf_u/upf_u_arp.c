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

#include <string.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>

#include "upf_u_arp.h"
#include "upf_u_config.h"
#include "upf_u_helper.h"
#include "utlt_debug.h"

#define PKTMBUF_POOL_NAME "MProc_pktmbuf_pool"
#define NEIGH_TIMEOUT_SEC 300

/* Broadcast MAC address */
static const struct rte_ether_addr broadcast_mac = {
    .addr_bytes = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
};

/* ARP Neighbor Table */
static struct neigh_entry neigh_tbl[NEIGH_MAX];

/* ARP Reply mbuf pool */
static struct rte_mempool *g_pktmbuf_pool = NULL;

/* Check if the given IP is one of our local IPs on the specified port */
static int
is_local_ip_on_port(uint16_t port, uint32_t ip_be) {
    if (port == g_n3_port) return g_n3_ip_be == ip_be;
    if (port == g_n6_port)   return g_n6_ip_be == ip_be;
    return 0;
}

int
upf_arp_init(void) {
    memset(neigh_tbl, 0, sizeof(neigh_tbl));
    g_pktmbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
    return (g_pktmbuf_pool != NULL) ? 0 : -1;
}

/* Add UE table entry by UE IP, return 0 on success, -1 on failure */
static uint32_t
neigh_hash(uint16_t port, uint32_t ip_be) {
    return (ip_be ^ ((uint32_t)port << 16) ^ ((uint32_t)port << 3)) % NEIGH_MAX;
}

/* Lookup neighbor entry by port and IP, return NULL if not found */
static struct neigh_entry *
neigh_lookup(uint16_t port, uint32_t ip_be) {
    uint32_t start = neigh_hash(port, ip_be);
    uint32_t idx = start;

    do {
        struct neigh_entry *e = &neigh_tbl[idx];

        if (!e->in_use) {
            return NULL;   /* linear probing stop */
        }

        if (e->port_id == port && e->ip_be == ip_be) {
            /* Optional stale marking */
            uint64_t now = rte_get_tsc_cycles();
            uint64_t hz = rte_get_tsc_hz();
            if (e->state == NEIGH_REACHABLE &&
                hz > 0 &&
                now - e->last_update_tsc > (uint64_t)NEIGH_TIMEOUT_SEC * hz) {
                e->state = NEIGH_STALE;
            }
            return e;
        }

        idx = (idx + 1) % NEIGH_MAX;
    } while (idx != start);

    return NULL;
}

/* Update neighbor entry */
static void
neigh_update(uint16_t port, uint32_t ip_be, const struct rte_ether_addr *mac) {
    if (mac == NULL)
        return;

    uint32_t start = neigh_hash(port, ip_be);
    uint32_t idx = start;
    struct neigh_entry *free_slot = NULL;

    do {
        struct neigh_entry *e = &neigh_tbl[idx];

        if (!e->in_use) {
            free_slot = e;
            break;
        }

        if (e->port_id == port && e->ip_be == ip_be) {
            rte_ether_addr_copy(mac, &e->mac);
            e->last_update_tsc = rte_get_tsc_cycles();
            e->state = NEIGH_REACHABLE;
            return;
        }

        idx = (idx + 1) % NEIGH_MAX;
    } while (idx != start);

    if (free_slot) {
        free_slot->in_use = 1;
        free_slot->port_id = port;
        free_slot->ip_be = ip_be;
        rte_ether_addr_copy(mac, &free_slot->mac);
        free_slot->last_update_tsc = rte_get_tsc_cycles();
        free_slot->state = NEIGH_REACHABLE;
        return;
    }

    /* Table full: simple replacement policy */
    idx = start;
    neigh_tbl[idx].in_use = 1;
    neigh_tbl[idx].port_id = port;
    neigh_tbl[idx].ip_be = ip_be;
    rte_ether_addr_copy(mac, &neigh_tbl[idx].mac);
    neigh_tbl[idx].last_update_tsc = rte_get_tsc_cycles();
    neigh_tbl[idx].state = NEIGH_REACHABLE;
}

/* Lookup neighbor MAC by port and IP, returns NULL if not found or stale */
static int
send_arp_request(uint16_t port,
                 uint32_t sip_be,
                 uint32_t tip_be,
                 struct onvm_nf *nf) {
    struct rte_mbuf *out_pkt = NULL;
    struct onvm_pkt_meta *pmeta = NULL;
    struct rte_ether_hdr *eth_hdr = NULL;
    struct rte_arp_hdr *arp_hdr = NULL;
    struct rte_ether_addr src_mac;
    size_t pkt_size;

    if (nf == NULL)
        return -1;

    if (g_pktmbuf_pool == NULL) {
        g_pktmbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
        if (g_pktmbuf_pool == NULL) {
            UTLT_Error("Cannot find mbuf pool %s", PKTMBUF_POOL_NAME);
            return -1;
        }
    }

    if (rte_eth_macaddr_get(port, &src_mac) < 0) {
        UTLT_Error("Failed to get MAC for port %u", port);
        return -1;
    }

    out_pkt = rte_pktmbuf_alloc(g_pktmbuf_pool);
    if (out_pkt == NULL)
        return -1;

    pkt_size = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
    char *data = rte_pktmbuf_append(out_pkt, pkt_size);
    if (data == NULL) {
        rte_pktmbuf_free(out_pkt);
        return -1;
    }

    eth_hdr = (struct rte_ether_hdr *)data;
    arp_hdr = (struct rte_arp_hdr *)(eth_hdr + 1);

    /* Ethernet */
    rte_ether_addr_copy(&src_mac, &eth_hdr->src_addr);
    rte_ether_addr_copy(&broadcast_mac, &eth_hdr->dst_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

    /* ARP request */
    arp_hdr->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
    arp_hdr->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    arp_hdr->arp_hlen = RTE_ETHER_ADDR_LEN;
    arp_hdr->arp_plen = sizeof(uint32_t);
    arp_hdr->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REQUEST);

    rte_ether_addr_copy(&src_mac, &arp_hdr->arp_data.arp_sha);
    arp_hdr->arp_data.arp_sip = sip_be;

    memset(&arp_hdr->arp_data.arp_tha, 0, sizeof(struct rte_ether_addr));
    arp_hdr->arp_data.arp_tip = tip_be;

    /* Mark neighbor INCOMPLETE if not already there */
    struct neigh_entry *e = neigh_lookup(port, tip_be);
    if (e == NULL) {
        uint32_t start = neigh_hash(port, tip_be);
        uint32_t idx = start;
        do {
            if (!neigh_tbl[idx].in_use) {
                neigh_tbl[idx].in_use = 1;
                neigh_tbl[idx].port_id = port;
                neigh_tbl[idx].ip_be = tip_be;
                memset(&neigh_tbl[idx].mac, 0, sizeof(struct rte_ether_addr));
                neigh_tbl[idx].last_update_tsc = rte_get_tsc_cycles();
                neigh_tbl[idx].state = NEIGH_INCOMPLETE;
                break;
            }
            idx = (idx + 1) % NEIGH_MAX;
        } while (idx != start);
    } else if (e->state == NEIGH_STALE) {
        e->state = NEIGH_INCOMPLETE;
        e->last_update_tsc = rte_get_tsc_cycles();
    }

    pmeta = onvm_get_pkt_meta(out_pkt, nf->dynfield_offset);
    pmeta->destination = port;
    pmeta->action = ONVM_NF_ACTION_OUT;

    return onvm_nflib_return_pkt(nf, out_pkt);
}

/* Handle incoming ARP packets, send reply if it's a request for our IP */
int
handle_arp_packet(struct rte_mbuf *pkt,
                  struct onvm_pkt_meta *meta,
                  struct onvm_nf_local_ctx *ctx) {
    struct rte_ether_hdr *eth_hdr = NULL;
    struct rte_arp_hdr *arp_hdr = NULL;
    struct rte_ether_addr local_mac;
    uint16_t op;
    uint16_t port;
    uint32_t target_ip_be;
    uint32_t sender_ip_be;

    if (pkt == NULL || meta == NULL || ctx == NULL || ctx->nf == NULL) {
        UTLT_Error("handle_arp_packet: invalid input pkt=%p meta=%p ctx=%p nf=%p",
               pkt, meta, ctx, (ctx ? ctx->nf : NULL));
        return 0;
    }

    if (pkt->pkt_len < sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr)) {
        UTLT_Debug("handle_arp_packet: short ARP packet len=%u port=%u",
               pkt->pkt_len, pkt->port);
        meta->action = ONVM_NF_ACTION_DROP;
        return 0;
    }

    eth_hdr = onvm_pkt_ether_hdr(pkt);
    if (eth_hdr == NULL) {
        UTLT_Warning("handle_arp_packet: failed to get ethernet header, len=%u port=%u",
                 pkt->pkt_len, pkt->port);
        meta->action = ONVM_NF_ACTION_DROP;
        return 0;
    }

    if (rte_be_to_cpu_16(eth_hdr->ether_type) != RTE_ETHER_TYPE_ARP) {
        meta->action = ONVM_NF_ACTION_DROP;
        return 0;
    }

    arp_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_arp_hdr *,
                                      sizeof(struct rte_ether_hdr));
    if (arp_hdr == NULL) {
        UTLT_Warning("handle_arp_packet: failed to get ARP header, len=%u port=%u",
                 pkt->pkt_len, pkt->port);
        meta->action = ONVM_NF_ACTION_DROP;
        return 0;
    }

    /* Basic sanity */
    if (rte_be_to_cpu_16(arp_hdr->arp_hardware) != RTE_ARP_HRD_ETHER ||
        rte_be_to_cpu_16(arp_hdr->arp_protocol) != RTE_ETHER_TYPE_IPV4 ||
        arp_hdr->arp_hlen != RTE_ETHER_ADDR_LEN ||
        arp_hdr->arp_plen != sizeof(uint32_t)) {
        UTLT_Debug("handle_arp_packet: invalid ARP hdr port=%u hrd=%u pro=0x%04x hlen=%u plen=%u",
               pkt->port,
               rte_be_to_cpu_16(arp_hdr->arp_hardware),
               rte_be_to_cpu_16(arp_hdr->arp_protocol),
               arp_hdr->arp_hlen,
               arp_hdr->arp_plen);
        meta->action = ONVM_NF_ACTION_DROP;
        return 0;
    }

    port = pkt->port;
    op = rte_be_to_cpu_16(arp_hdr->arp_opcode);
    sender_ip_be = arp_hdr->arp_data.arp_sip;
    target_ip_be = arp_hdr->arp_data.arp_tip;

    /* Learn sender on both request and reply */
    neigh_update(port, sender_ip_be, &arp_hdr->arp_data.arp_sha);

    switch (op) {
    case RTE_ARP_OP_REQUEST: {
        if (!is_local_ip_on_port(port, target_ip_be)) {
            UTLT_Debug("handle_arp_packet: ARP request not for local IP, port=%u target_ip=%s",
               port, convertToIpAddressString(target_ip_be));
            meta->action = ONVM_NF_ACTION_DROP;
            return 0;
        }

        if (rte_eth_macaddr_get(port, &local_mac) < 0) {
            UTLT_Error("handle_arp_packet: failed to get local MAC for port=%u", port);
            meta->action = ONVM_NF_ACTION_DROP;
            return 0;
        }

        if (g_pktmbuf_pool == NULL) {
            g_pktmbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
            if (g_pktmbuf_pool == NULL) {
                UTLT_Error("Cannot find mbuf pool %s", PKTMBUF_POOL_NAME);
                meta->action = ONVM_NF_ACTION_DROP;
                return 0;
            }
        }

        /* Build and send ARP reply */
        struct rte_mbuf *out_pkt = rte_pktmbuf_alloc(g_pktmbuf_pool);
        if (out_pkt == NULL) {
            meta->action = ONVM_NF_ACTION_DROP;
            return 0;
        }

        size_t pkt_size = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
        char *data = rte_pktmbuf_append(out_pkt, pkt_size);
        if (data == NULL) {
            rte_pktmbuf_free(out_pkt);
            meta->action = ONVM_NF_ACTION_DROP;
            return 0;
        }

        struct rte_ether_hdr *out_eth = (struct rte_ether_hdr *)data;
        struct rte_arp_hdr *out_arp = (struct rte_arp_hdr *)(out_eth + 1);

        /* Ethernet */
        rte_ether_addr_copy(&local_mac, &out_eth->src_addr);
        rte_ether_addr_copy(&arp_hdr->arp_data.arp_sha, &out_eth->dst_addr);
        out_eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

        /* ARP reply */
        out_arp->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
        out_arp->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
        out_arp->arp_hlen = RTE_ETHER_ADDR_LEN;
        out_arp->arp_plen = sizeof(uint32_t);
        out_arp->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);

        /* sender = me */
        rte_ether_addr_copy(&local_mac, &out_arp->arp_data.arp_sha);
        out_arp->arp_data.arp_sip = target_ip_be;

        /* target = original requester */
        rte_ether_addr_copy(&arp_hdr->arp_data.arp_sha, &out_arp->arp_data.arp_tha);
        out_arp->arp_data.arp_tip = sender_ip_be;

        struct onvm_pkt_meta *pmeta =
            onvm_get_pkt_meta(out_pkt, ctx->nf->dynfield_offset);
        pmeta->destination = port;
        pmeta->action = ONVM_NF_ACTION_OUT;

        int rc = onvm_nflib_return_pkt(ctx->nf, out_pkt);
        if (rc < 0) {
            char sip_buf[16], tip_buf[16];
            UTLT_Warning("handle_arp_packet: failed to send ARP reply on port=%u rc=%d sip=%s tip=%s",
                        port, rc,
                        ipv4_to_buf(out_arp->arp_data.arp_sip, sip_buf),
                        ipv4_to_buf(out_arp->arp_data.arp_tip, tip_buf));
        } else {
            char sip_buf[16], tip_buf[16];
            UTLT_Trace("handle_arp_packet: sent ARP reply on port=%u sip=%s tip=%s",
                        port,
                        ipv4_to_buf(out_arp->arp_data.arp_sip, sip_buf),
                        ipv4_to_buf(out_arp->arp_data.arp_tip, tip_buf));
        }

        // This ARP Request packet is consumed by us, no need to pass to other NFs
        meta->action = ONVM_NF_ACTION_DROP;
        return 0;
    }

    case RTE_ARP_OP_REPLY:
        /* already learned above */
        meta->action = ONVM_NF_ACTION_DROP;
        return 0;

    default:
        meta->action = ONVM_NF_ACTION_DROP;
        return 0;
    }
}

/* Attach L2 header or send ARP request if next-hop MAC unknown */
int
attach_l2_or_arp(struct rte_mbuf *pkt,
                 uint16_t out_port,
                 uint32_t local_ip_be,
                 uint32_t next_hop_ip_be,
                 struct onvm_nf *nf) {
    struct rte_ether_hdr *eth_hdr;
    struct neigh_entry *ne;
    struct rte_ether_addr local_mac;

    ne = neigh_lookup(out_port, next_hop_ip_be);
    if (ne == NULL || ne->state != NEIGH_REACHABLE) {
        (void)send_arp_request(out_port, local_ip_be, next_hop_ip_be, nf);
        return -1;
    }

    eth_hdr = (struct rte_ether_hdr *)
        rte_pktmbuf_prepend(pkt, sizeof(struct rte_ether_hdr));
    if (eth_hdr == NULL)
        return -1;

    if (rte_eth_macaddr_get(out_port, &local_mac) < 0)
        return -1;

    rte_ether_addr_copy(&local_mac, &eth_hdr->src_addr);
    rte_ether_addr_copy(&ne->mac, &eth_hdr->dst_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    return 0;
}