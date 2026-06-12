/*
 * dpu_l2l3_responder.c — BF3 ARM-side ARP responder (Option C)
 *
 * Runs on one DPDK lcore.  The ROOT pipe pre-classifies ARP
 * (ether_type 0x0806) arriving on wires whose local IP is configured,
 * and steers the packets via FWD_RSS into the Rx queue this lcore
 * polls.
 *
 * The responder transforms the request in place:
 *   - flip opcode to reply
 *   - swap (sender ↔ target) IP/MAC
 *   - set sender_hw_addr to our local MAC
 *   - set Ethernet dst_addr to the original requester MAC, src_addr
 *     to our local MAC
 *
 * No L3 / ICMP processing.  Tunneled pings and N6 transit pings
 * traverse the existing UL_DECAP / DL_ENCAP GTP fast path untouched.
 *
 * Egress-wire tagging:
 *   pkt_meta = RESPONDER_MARKER_BIT          → N3  (0x04)
 *   pkt_meta = RESPONDER_MARKER_BIT | N6_BIT → N6  (0x0C)
 * ROOT matches with mask RESPONDER_BITS_MASK (0x0F) and FWD_PORTs
 * the packet to the selected wire.  FWD_PORT is terminal — replies
 * leave the box byte-for-byte identical to what we crafted.
 *
 * Design notes:
 *   - No L3 routing: we only answer ARPs for our own configured IPs.
 *     Any packet that the ROOT shouldn't have forwarded (shouldn't
 *     happen — the classifier is narrow) or whose ARP target is
 *     not ours is silently dropped.
 *   - mbuf lifetime: the responder owns each mbuf from rx_burst
 *     until either tx_burst succeeds (NIC owns it thereafter) or we
 *     free it on the same lcore (mempool cache stays hot).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <arpa/inet.h>

#include <rte_arp.h>
#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_flow.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>

#include <doca_log.h>

#include "dpu_l2l3_responder.h"
#include "dpu_pipeline.h"

DOCA_LOG_REGISTER(DPU_L2L3_RESP);

#define RX_BURST_SIZE 32

/* ──────────────────────────────────────────────────────────────────
 *  Helpers
 * ──────────────────────────────────────────────────────────────── */

/**
 * Decide the egress-wire pkt_meta marker from the target IP.
 * Returns:
 *   >0  — marker to stamp on the reply
 *    0  — IP is not local; caller must drop the packet
 */
static inline uint32_t
pick_egress_marker(const l2l3_responder_ctx_t *ctx, uint32_t target_ip_nbo)
{
    if (ctx->upf_n3_ip != 0 && target_ip_nbo == ctx->upf_n3_ip)
        return RESPONDER_MARKER_BIT;
    if (ctx->upf_n6_ip != 0 && target_ip_nbo == ctx->upf_n6_ip)
        return RESPONDER_MARKER_BIT | RESPONDER_N6_BIT;
    return 0;
}

/**
 * Pick the local MAC that corresponds to the chosen egress wire
 * (encoded in the marker).  Returns a pointer into ctx — do not free.
 */
static inline const uint8_t *
local_mac_for_marker(const l2l3_responder_ctx_t *ctx, uint32_t marker)
{
    if (marker & RESPONDER_N6_BIT)
        return ctx->upf_n6_mac;
    return ctx->upf_n3_mac;
}

/**
 * Stamp pkt_meta + Tx metadata flag, then Tx-burst a single packet on
 * the given (port, tx_queue).  Frees the mbuf on failure so the caller
 * doesn't have to.
 * @return  true on successful enqueue, false otherwise.
 */
static bool
tx_reply(l2l3_responder_ctx_t *ctx, struct rte_mbuf *pkt, uint32_t marker,
         uint16_t port_id, uint16_t tx_queue_id)
{
    rte_flow_dynf_metadata_set(pkt, marker);
    pkt->ol_flags |= RTE_MBUF_DYNFLAG_TX_METADATA;

    uint16_t sent = rte_eth_tx_burst(port_id, tx_queue_id, &pkt, 1);
    if (sent != 1) {
        rte_pktmbuf_free(pkt);
        ctx->tx_failed++;
        return false;
    }
    return true;
}


/* ──────────────────────────────────────────────────────────────────
 *  ARP handling
 * ──────────────────────────────────────────────────────────────── */

/**
 * Transform an ARP request mbuf into an ARP reply *in place*.
 *
 * Preconditions:
 *   - pkt begins with an Ethernet header whose ether_type == 0x0806.
 *   - pkt_len is large enough to hold ETH + rte_arp_hdr.
 *
 * @return  pkt_meta marker to stamp on Tx, or 0 if the packet should
 *          be dropped (not for us / malformed).
 */
static uint32_t
arp_build_reply(l2l3_responder_ctx_t *ctx, struct rte_mbuf *pkt)
{
    const size_t needed = sizeof(struct rte_ether_hdr) +
                          sizeof(struct rte_arp_hdr);
    if (rte_pktmbuf_pkt_len(pkt) < needed) {
        ctx->arp_ignored++;
        return 0;
    }

    struct rte_ether_hdr *eth =
        rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    struct rte_arp_hdr *arp =
        (struct rte_arp_hdr *)(eth + 1);

    /* Only respond to IPv4-over-Ethernet ARP requests. */
    if (arp->arp_hardware != rte_cpu_to_be_16(RTE_ARP_HRD_ETHER) ||
        arp->arp_protocol != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4) ||
        arp->arp_hlen != RTE_ETHER_ADDR_LEN ||
        arp->arp_plen != 4 ||
        arp->arp_opcode != rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)) {
        ctx->arp_ignored++;
        return 0;
    }

    /* Is the target IP one of ours?  If not, drop. */
    uint32_t target_ip = arp->arp_data.arp_tip;  /* NBO */
    uint32_t marker    = pick_egress_marker(ctx, target_ip);
    if (marker == 0) {
        ctx->arp_ignored++;
        return 0;
    }
    const uint8_t *local_mac = local_mac_for_marker(ctx, marker);

    /*
     * Build the reply in place.
     * ARP payload layout (RFC 826):
     *   sender_hw_addr = local_mac
     *   sender_ip      = target_ip (was the one we're answering for)
     *   target_hw_addr = original sender_hw_addr
     *   target_ip      = original sender_ip
     */
    struct rte_ether_addr requester_mac;
    rte_ether_addr_copy(&arp->arp_data.arp_sha, &requester_mac);
    uint32_t requester_ip = arp->arp_data.arp_sip;

    /* Sender fields → us */
    memcpy(arp->arp_data.arp_sha.addr_bytes, local_mac, RTE_ETHER_ADDR_LEN);
    arp->arp_data.arp_sip = target_ip;

    /* Target fields → original requester */
    rte_ether_addr_copy(&requester_mac, &arp->arp_data.arp_tha);
    arp->arp_data.arp_tip = requester_ip;

    arp->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);

    /* Ethernet header: unicast back to the requester. */
    rte_ether_addr_copy(&eth->src_addr, &eth->dst_addr);
    memcpy(eth->src_addr.addr_bytes, local_mac, RTE_ETHER_ADDR_LEN);
    /* ether_type stays 0x0806 — no change needed. */

    return marker;
}


/* ──────────────────────────────────────────────────────────────────
 *  Per-packet dispatch
 * ──────────────────────────────────────────────────────────────── */

/**
 * Classify a single mbuf and transform it into a reply.
 * The caller handles Tx + stats; this function returns a marker
 * suitable for pkt_meta, or 0 if the packet should be dropped.
 */
static uint32_t
process_one(l2l3_responder_ctx_t *ctx, struct rte_mbuf *pkt)
{
    if (rte_pktmbuf_pkt_len(pkt) < sizeof(struct rte_ether_hdr)) {
        ctx->rx_unknown++;
        return 0;
    }

    struct rte_ether_hdr *eth =
        rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    uint16_t etype = rte_be_to_cpu_16(eth->ether_type);

    if (etype == RTE_ETHER_TYPE_ARP) {
        ctx->arp_requests_rx++;
        uint32_t m = arp_build_reply(ctx, pkt);
        if (m) ctx->arp_replies_tx++;
        return m;
    }

    ctx->rx_unknown++;
    return 0;
}


/* ──────────────────────────────────────────────────────────────────
 *  Gratuitous ARP — proactive neighbour-cache population
 *
 * When DN's broadcast ARPs do not reach BF3's N6 DOCA Flow pipeline
 * (firmware-level eSwitch flood-domain quirk on PF1), DN never learns
 * the UPF's N6 MAC and DL traffic stalls.  We work around this by
 * Tx'ing unsolicited "gratuitous" ARPs from the BF3 side: announce
 * "192.168.3.2 is at <upf_n6_mac>" to the wire periodically.  Linux's
 * kernel updates its neigh cache from any ARP it sees, so DN learns
 * the entry without ever needing DN→BF3 broadcasts to work.
 *
 * Same reasoning applies to N3 (cheap insurance against gNB-side
 * cache loss) — we send on every IP-configured port.
 * ──────────────────────────────────────────────────────────────── */

static void
send_gratuitous_arp(l2l3_responder_ctx_t *ctx,
                    uint16_t port_id, uint16_t tx_queue_id,
                    const uint8_t our_mac[6], uint32_t our_ip_nbo,
                    uint32_t marker)
{
    struct rte_mbuf *m = rte_pktmbuf_alloc(ctx->mbuf_pool);
    if (!m) {
        ctx->tx_failed++;
        return;
    }

    const size_t pkt_len = sizeof(struct rte_ether_hdr) +
                           sizeof(struct rte_arp_hdr);
    char *data = rte_pktmbuf_append(m, pkt_len);
    if (!data) {
        rte_pktmbuf_free(m);
        ctx->tx_failed++;
        return;
    }

    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)data;
    /* Broadcast dst MAC: every neighbour on the L2 segment learns */
    memset(eth->dst_addr.addr_bytes, 0xff, RTE_ETHER_ADDR_LEN);
    memcpy(eth->src_addr.addr_bytes, our_mac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

    struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(eth + 1);
    arp->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
    arp->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    arp->arp_hlen     = RTE_ETHER_ADDR_LEN;
    arp->arp_plen     = 4;
    /* Gratuitous-ARP convention: opcode = REQUEST, sender_ip == target_ip
     * (announce ourselves rather than ask).  Using REQUEST (rather than
     * REPLY) is the more widely-honoured form on Linux. */
    arp->arp_opcode   = rte_cpu_to_be_16(RTE_ARP_OP_REQUEST);
    memcpy(arp->arp_data.arp_sha.addr_bytes, our_mac, RTE_ETHER_ADDR_LEN);
    arp->arp_data.arp_sip = our_ip_nbo;
    /* target_hw is conventionally zero in a gratuitous ARP request. */
    memset(arp->arp_data.arp_tha.addr_bytes, 0, RTE_ETHER_ADDR_LEN);
    arp->arp_data.arp_tip = our_ip_nbo;

    /* Stamp the same metadata marker the responder uses for replies.
     * The marker is consumed by the egress_root passthrough miss path
     * on N3 (transparent) and ignored on N6 (no EGRESS pipeline). */
    rte_flow_dynf_metadata_set(m, marker);
    m->ol_flags |= RTE_MBUF_DYNFLAG_TX_METADATA;

    uint16_t sent = rte_eth_tx_burst(port_id, tx_queue_id, &m, 1);
    if (sent != 1) {
        rte_pktmbuf_free(m);
        ctx->tx_failed++;
        return;
    }
    ctx->garp_tx++;
}

/* Send a GARP burst on every IP-configured port.  Cheap (≤ 2 packets). */
static void
send_gratuitous_arps_all(l2l3_responder_ctx_t *ctx)
{
    if (ctx->upf_n3_ip != 0)
        send_gratuitous_arp(ctx,
                            ctx->n3_dpdk_port, ctx->n3_tx_queue_id,
                            ctx->upf_n3_mac, ctx->upf_n3_ip,
                            RESPONDER_MARKER_BIT);
    if (ctx->upf_n6_ip != 0)
        send_gratuitous_arp(ctx,
                            ctx->n6_dpdk_port, ctx->n6_tx_queue_id,
                            ctx->upf_n6_mac, ctx->upf_n6_ip,
                            RESPONDER_MARKER_BIT | RESPONDER_N6_BIT);
}


/**
 * Send a unicast ARP REPLY to a peer, formatted exactly as a reply to
 * a (possibly never-seen) probe from that peer.  Linux's NUD machine
 * transitions PROBE→REACHABLE for a neighbour entry whenever an ARP
 * reply arrives that has sender_hw matching the neighbour's MAC and
 * target_ip matching the requesting host's own IP.
 *
 * On BF3 PF1, the firmware diverts ARP frames (broadcast or unicast)
 * to the host PCIe representor, so DN's actual unicast probes never
 * reach BF3 ARM and would otherwise time out → DN's neigh entry goes
 * FAILED → DL traffic stalls.  Tx'ing this reply periodically keeps
 * DN's entry confirmed in REACHABLE without us ever needing to see
 * its probes.
 *
 * No-op if peer_ip is zero (caller chose not to enable refresh on
 * this side).
 */
static void
send_unicast_arp_reply(l2l3_responder_ctx_t *ctx,
                       uint16_t port_id, uint16_t tx_queue_id,
                       const uint8_t our_mac[6], uint32_t our_ip_nbo,
                       const uint8_t peer_mac[6], uint32_t peer_ip_nbo,
                       uint32_t marker)
{
    if (peer_ip_nbo == 0)
        return;

    struct rte_mbuf *m = rte_pktmbuf_alloc(ctx->mbuf_pool);
    if (!m) {
        ctx->tx_failed++;
        return;
    }

    const size_t pkt_len = sizeof(struct rte_ether_hdr) +
                           sizeof(struct rte_arp_hdr);
    char *data = rte_pktmbuf_append(m, pkt_len);
    if (!data) {
        rte_pktmbuf_free(m);
        ctx->tx_failed++;
        return;
    }

    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)data;
    /* Unicast L2 to peer — this is what makes the reply look like a
     * direct response to peer's probe (vs the broadcast GARP form). */
    memcpy(eth->dst_addr.addr_bytes, peer_mac, RTE_ETHER_ADDR_LEN);
    memcpy(eth->src_addr.addr_bytes, our_mac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

    struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(eth + 1);
    arp->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
    arp->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    arp->arp_hlen     = RTE_ETHER_ADDR_LEN;
    arp->arp_plen     = 4;
    arp->arp_opcode   = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
    /* sender = us, target = peer.  This is the form Linux's NUD
     * recognises as "reply to my probe": target_(hw,ip) match the
     * requesting host's identity. */
    memcpy(arp->arp_data.arp_sha.addr_bytes, our_mac, RTE_ETHER_ADDR_LEN);
    arp->arp_data.arp_sip = our_ip_nbo;
    memcpy(arp->arp_data.arp_tha.addr_bytes, peer_mac, RTE_ETHER_ADDR_LEN);
    arp->arp_data.arp_tip = peer_ip_nbo;

    rte_flow_dynf_metadata_set(m, marker);
    m->ol_flags |= RTE_MBUF_DYNFLAG_TX_METADATA;

    uint16_t sent = rte_eth_tx_burst(port_id, tx_queue_id, &m, 1);
    if (sent != 1) {
        rte_pktmbuf_free(m);
        ctx->tx_failed++;
        return;
    }
    ctx->unicast_arp_replies_tx++;
}

/* Refresh the peer-side neighbour cache on every IP-configured port.
 * Called once per tick alongside the GARP burst. */
static void
refresh_neighbor_caches(l2l3_responder_ctx_t *ctx)
{
    if (ctx->upf_n3_ip != 0 && ctx->gnb_ip != 0)
        send_unicast_arp_reply(ctx,
                               ctx->n3_dpdk_port, ctx->n3_tx_queue_id,
                               ctx->upf_n3_mac, ctx->upf_n3_ip,
                               ctx->gnb_mac, ctx->gnb_ip,
                               RESPONDER_MARKER_BIT);
    if (ctx->upf_n6_ip != 0 && ctx->dn_gw_ip != 0)
        send_unicast_arp_reply(ctx,
                               ctx->n6_dpdk_port, ctx->n6_tx_queue_id,
                               ctx->upf_n6_mac, ctx->upf_n6_ip,
                               ctx->dn_gw_mac, ctx->dn_gw_ip,
                               RESPONDER_MARKER_BIT | RESPONDER_N6_BIT);
}


/* ──────────────────────────────────────────────────────────────────
 *  Public API
 * ──────────────────────────────────────────────────────────────── */

int
l2l3_responder_init(l2l3_responder_ctx_t *ctx,
                    uint16_t n3_dpdk_port,
                    uint16_t n3_rx_queue_base,
                    uint16_t n3_nr_rx_queues,
                    uint16_t n3_tx_queue_id,
                    uint16_t n6_dpdk_port,
                    uint16_t n6_rx_queue_base,
                    uint16_t n6_nr_rx_queues,
                    uint16_t n6_tx_queue_id,
                    uint16_t n3_port_id,
                    uint16_t n6_port_id,
                    const uint8_t upf_n3_mac[6],
                    const uint8_t upf_n6_mac[6],
                    uint32_t upf_n3_ip,
                    uint32_t upf_n6_ip,
                    const uint8_t gnb_mac[6],
                    const uint8_t dn_gw_mac[6],
                    uint32_t gnb_ip,
                    uint32_t dn_gw_ip,
                    struct rte_mempool *mbuf_pool)
{
    if (!ctx || !upf_n3_mac || !upf_n6_mac || !gnb_mac || !dn_gw_mac ||
        !mbuf_pool) {
        DOCA_LOG_ERR("l2l3_responder_init: invalid arguments");
        return -1;
    }
    if (n3_nr_rx_queues == 0 && n6_nr_rx_queues == 0) {
        DOCA_LOG_ERR("l2l3_responder_init: at least one port must have "
                     "responder Rx queues");
        return -1;
    }
    if (upf_n3_ip == 0 && upf_n6_ip == 0) {
        DOCA_LOG_ERR("l2l3_responder_init: at least one of "
                     "upf_n3_ip / upf_n6_ip must be non-zero");
        return -1;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->n3_dpdk_port     = n3_dpdk_port;
    ctx->n3_rx_queue_base = n3_rx_queue_base;
    ctx->n3_nr_rx_queues  = n3_nr_rx_queues;
    ctx->n3_tx_queue_id   = n3_tx_queue_id;
    ctx->n6_dpdk_port     = n6_dpdk_port;
    ctx->n6_rx_queue_base = n6_rx_queue_base;
    ctx->n6_nr_rx_queues  = n6_nr_rx_queues;
    ctx->n6_tx_queue_id   = n6_tx_queue_id;
    ctx->n3_port_id       = n3_port_id;
    ctx->n6_port_id       = n6_port_id;
    memcpy(ctx->upf_n3_mac, upf_n3_mac, 6);
    memcpy(ctx->upf_n6_mac, upf_n6_mac, 6);
    memcpy(ctx->gnb_mac,    gnb_mac,    6);
    memcpy(ctx->dn_gw_mac,  dn_gw_mac,  6);
    ctx->upf_n3_ip = upf_n3_ip;
    ctx->upf_n6_ip = upf_n6_ip;
    ctx->gnb_ip    = gnb_ip;
    ctx->dn_gw_ip  = dn_gw_ip;
    ctx->mbuf_pool = mbuf_pool;
    ctx->running   = true;

    char n3_ip_str[INET_ADDRSTRLEN] = "<disabled>";
    char n6_ip_str[INET_ADDRSTRLEN] = "<disabled>";
    char gnb_ip_str[INET_ADDRSTRLEN] = "<disabled>";
    char dn_ip_str[INET_ADDRSTRLEN] = "<disabled>";
    if (upf_n3_ip) inet_ntop(AF_INET, &upf_n3_ip, n3_ip_str, sizeof(n3_ip_str));
    if (upf_n6_ip) inet_ntop(AF_INET, &upf_n6_ip, n6_ip_str, sizeof(n6_ip_str));
    if (gnb_ip)    inet_ntop(AF_INET, &gnb_ip,    gnb_ip_str, sizeof(gnb_ip_str));
    if (dn_gw_ip)  inet_ntop(AF_INET, &dn_gw_ip,  dn_ip_str,  sizeof(dn_ip_str));

    DOCA_LOG_INFO("ARP responder init: N3 port=%u rx=[%u..%u] tx=%u | "
                  "N6 port=%u rx=[%u..%u] tx=%u | n3_ip=%s n6_ip=%s | "
                  "peer gnb_ip=%s dn_gw_ip=%s (unicast-reply refresh: %s/%s)",
                  n3_dpdk_port,
                  n3_rx_queue_base,
                  n3_nr_rx_queues ? n3_rx_queue_base + n3_nr_rx_queues - 1
                                   : n3_rx_queue_base,
                  n3_tx_queue_id,
                  n6_dpdk_port,
                  n6_rx_queue_base,
                  n6_nr_rx_queues ? n6_rx_queue_base + n6_nr_rx_queues - 1
                                   : n6_rx_queue_base,
                  n6_tx_queue_id,
                  n3_ip_str, n6_ip_str,
                  gnb_ip_str, dn_ip_str,
                  (upf_n3_ip && gnb_ip)   ? "on" : "off",
                  (upf_n6_ip && dn_gw_ip) ? "on" : "off");
    return 0;
}

/**
 * Resolve the Tx (port, queue) pair for a reinjected ARP reply from the
 * marker (which was derived from the ARP target IP, not the ingress port).
 *
 * This keeps the design consistent even when ARP for the N3 IP happens
 * to arrive on N6 or vice versa — the reply ALWAYS egresses on the port
 * whose ROOT carries the matching responder-reinject entry, so FWD_PORT
 * sends it out the correct wire.
 *
 *   marker bit 3 (RESPONDER_N6_BIT) set  → Tx on N6
 *   marker bit 3 clear                    → Tx on N3
 */
static inline void
pick_tx_for_marker(const l2l3_responder_ctx_t *ctx, uint32_t marker,
                   uint16_t *out_port, uint16_t *out_queue)
{
    if (marker & RESPONDER_N6_BIT) {
        *out_port  = ctx->n6_dpdk_port;
        *out_queue = ctx->n6_tx_queue_id;
    } else {
        *out_port  = ctx->n3_dpdk_port;
        *out_queue = ctx->n3_tx_queue_id;
    }
}

/**
 * Poll one port's responder Rx queues and Tx replies.  Each reply's Tx
 * port is chosen from its marker (see pick_tx_for_marker), NOT from the
 * ingress port.  This makes reinject routing consistent and correct even
 * when a packet arrives on the "wrong" port.
 */
static bool
responder_poll_port(l2l3_responder_ctx_t *ctx,
                    uint16_t rx_port_id,
                    uint16_t rx_queue_base,
                    uint16_t nr_rx_queues,
                    bool *logged_first_rx,
                    bool *logged_first_tx)
{
    struct rte_mbuf *rx_bufs[RX_BURST_SIZE];
    bool any = false;

    for (uint16_t q = 0; q < nr_rx_queues; q++) {
        uint16_t qid = rx_queue_base + q;
        uint16_t nb = rte_eth_rx_burst(rx_port_id, qid,
                                       rx_bufs, RX_BURST_SIZE);
        if (nb == 0)
            continue;
        any = true;

        if (!*logged_first_rx) {
            struct rte_ether_hdr *eth0 =
                rte_pktmbuf_mtod(rx_bufs[0], struct rte_ether_hdr *);
            DOCA_LOG_INFO("ARP responder: first Rx burst on port=%u q=%u "
                          "nb=%u etype=0x%04x",
                          rx_port_id, qid, nb,
                          rte_be_to_cpu_16(eth0->ether_type));
            *logged_first_rx = true;
        }

        for (uint16_t i = 0; i < nb; i++) {
            uint32_t marker = process_one(ctx, rx_bufs[i]);
            if (marker == 0) {
                rte_pktmbuf_free(rx_bufs[i]);
                continue;
            }
            uint16_t tx_port, tx_queue;
            pick_tx_for_marker(ctx, marker, &tx_port, &tx_queue);

            bool ok = tx_reply(ctx, rx_bufs[i], marker, tx_port, tx_queue);
            if (ok && !*logged_first_tx) {
                DOCA_LOG_INFO("ARP responder: first Tx reply accepted "
                              "by NIC (rx_port=%u tx_port=%u "
                              "marker=0x%02x tx_q=%u)",
                              rx_port_id, tx_port, marker, tx_queue);
                *logged_first_tx = true;
            }
        }
    }

    return any;
}

int
l2l3_responder_loop(void *arg)
{
    l2l3_responder_ctx_t *ctx = (l2l3_responder_ctx_t *)arg;

    DOCA_LOG_INFO("ARP responder loop started on lcore %u: "
                  "N3 port=%u rx_q=[%u..%u] tx_q=%u | "
                  "N6 port=%u rx_q=[%u..%u] tx_q=%u",
                  rte_lcore_id(),
                  ctx->n3_dpdk_port,
                  ctx->n3_rx_queue_base,
                  ctx->n3_nr_rx_queues ? ctx->n3_rx_queue_base +
                                         ctx->n3_nr_rx_queues - 1
                                       : ctx->n3_rx_queue_base,
                  ctx->n3_tx_queue_id,
                  ctx->n6_dpdk_port,
                  ctx->n6_rx_queue_base,
                  ctx->n6_nr_rx_queues ? ctx->n6_rx_queue_base +
                                         ctx->n6_nr_rx_queues - 1
                                       : ctx->n6_rx_queue_base,
                  ctx->n6_tx_queue_id);

    bool logged_first_rx = false;
    bool logged_first_tx = false;

    /* Cold-start announce: GARP populates the entry on the peer side,
     * unicast-reply pushes it straight to REACHABLE on the very first
     * iteration so the peer never needs to broadcast-ARP us. */
    send_gratuitous_arps_all(ctx);
    refresh_neighbor_caches(ctx);
    DOCA_LOG_INFO("ARP responder: initial GARP + unicast-reply burst sent");

    /* Periodic refresh.  1 s is comfortably below the Linux NUD probe
     * window (3 retries × 1 s = 3 s before FAILED), so DN's entry stays
     * confirmed in REACHABLE between our refreshes. */
    
    const uint64_t hz = rte_get_tsc_hz();
    /* const uint64_t refresh_interval_tsc = hz;   // 1 second
    uint64_t last_refresh_tsc = rte_rdtsc(); */
    
    const uint64_t uarp_interval_tsc = hz * 3;   /* unicast ARP reply every 3s */
    const uint64_t garp_interval_tsc = hz * 30;  /* GARP every 30s */

    uint64_t last_uarp_tsc = rte_rdtsc();
    uint64_t last_garp_tsc = rte_rdtsc();
    
    

    while (ctx->running) {
        bool any = false;
        if (ctx->n3_nr_rx_queues > 0)
            any |= responder_poll_port(ctx, ctx->n3_dpdk_port,
                                       ctx->n3_rx_queue_base,
                                       ctx->n3_nr_rx_queues,
                                       &logged_first_rx, &logged_first_tx);
        if (ctx->n6_nr_rx_queues > 0)
            any |= responder_poll_port(ctx, ctx->n6_dpdk_port,
                                       ctx->n6_rx_queue_base,
                                       ctx->n6_nr_rx_queues,
                                       &logged_first_rx, &logged_first_tx);

        uint64_t now = rte_rdtsc();
        // if (now - last_refresh_tsc >= refresh_interval_tsc) {
        //     /* GARP creates the peer's entry from cold start (announce);
        //      * unicast-reply keeps it in REACHABLE between ticks. */
        //     send_gratuitous_arps_all(ctx);
        //     refresh_neighbor_caches(ctx);
        //     last_refresh_tsc = now;
        // }

        if (now - last_uarp_tsc >= uarp_interval_tsc) {
            refresh_neighbor_caches(ctx);
            last_uarp_tsc = now;
        }

        // if (now - last_garp_tsc >= garp_interval_tsc) {
        //     send_gratuitous_arps_all(ctx);
        //     last_garp_tsc = now;
        // }

        if (!any)
            rte_pause();
    }

    DOCA_LOG_INFO("ARP responder loop exiting on lcore %u",
                  rte_lcore_id());
    return 0;
}

void
l2l3_responder_stop(l2l3_responder_ctx_t *ctx)
{
    if (ctx)
        ctx->running = false;
}

void
l2l3_responder_destroy(l2l3_responder_ctx_t *ctx)
{
    if (!ctx) return;
    l2l3_responder_dump_stats(ctx);
    memset(ctx, 0, sizeof(*ctx));
}

void
l2l3_responder_dump_stats(const l2l3_responder_ctx_t *ctx)
{
    if (!ctx) return;
    DOCA_LOG_INFO("ARP responder stats: "
                  "rx=%lu tx=%lu ignored=%lu | "
                  "tx_fail=%lu unknown=%lu | garp_tx=%lu uarp_reply_tx=%lu",
                  (unsigned long)ctx->arp_requests_rx,
                  (unsigned long)ctx->arp_replies_tx,
                  (unsigned long)ctx->arp_ignored,
                  (unsigned long)ctx->tx_failed,
                  (unsigned long)ctx->rx_unknown,
                  (unsigned long)ctx->garp_tx,
                  (unsigned long)ctx->unicast_arp_replies_tx);
}
