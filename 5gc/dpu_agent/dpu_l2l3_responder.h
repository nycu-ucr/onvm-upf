/*
 * dpu_l2l3_responder.h — BF3 ARM-side ARP responder (Option C)
 *
 * DOCA Flow HWS in switch mode cannot build a pure-hardware ARP
 * responder (ARP payload fields are not matchable or modifiable in
 * DOCA 3.2).  Instead, the ROOT pipe classifies ARP requests arriving
 * on each wire whose local IP is configured and steers them via RSS
 * to this responder lcore.
 *
 * The lcore runs on an ARM core, polls the dedicated Rx queue on the
 * proxy port (DPDK port 0), crafts the reply in software, tags the
 * egress wire via pkt_meta bits 2-3 (RESPONDER_MARKER_BIT +
 * RESPONDER_N6_BIT) — with bits 0-1 always zero — and Tx-injects on a
 * dedicated responder Tx queue.  ROOT matches a 4-bit window so
 * buffer-drain reinject (bit 0 always set) can never alias.
 *
 * Reinjected packets re-enter ROOT, match one of the two
 * responder-reinject entries, and FWD_PORT directly to the target
 * wire port (FWD_PORT is terminal — EGRESS / DL_ENCAP is never
 * traversed, so the reply leaves the box unchanged).
 *
 * Scope: ARP only.  Tunneled UE pings and all subscriber data take
 * the existing UL_DECAP / DL_ENCAP GTP fast path and do NOT touch
 * this module.
 *
 * Design invariants:
 *   - Responder never touches the fast path.  Data-plane packets
 *     (GTP-U on N3, plain IPv4 on N6 not addressed to BF3) never
 *     reach this module.
 *   - Single producer / single consumer on the responder Tx queue —
 *     the responder lcore is the only caller.  The buffer (Tx 0) and
 *     shaper (Tx 1) use different Tx queues, so there is no ring
 *     contention.
 *   - Responder mbufs are owned by this lcore from rx_burst to
 *     tx_burst; unsent / rejected mbufs are freed on the same lcore
 *     to keep the mempool cache hot.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <rte_mempool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward-declarations to keep this header light.  The responder does
 * not depend on the pipeline's runtime state — only its static port
 * configuration (MACs, IPs, port IDs) plus the DPDK queue topology. */
typedef struct {
    /* N3 DPDK queue topology — polls N3 Rx for ARP from UE/RAN side. */
    uint16_t n3_dpdk_port;
    uint16_t n3_rx_queue_base;
    uint16_t n3_nr_rx_queues;
    uint16_t n3_tx_queue_id;

    /* N6 DPDK queue topology — polls N6 Rx for ARP from DN side. */
    uint16_t n6_dpdk_port;
    uint16_t n6_rx_queue_base;
    uint16_t n6_nr_rx_queues;
    uint16_t n6_tx_queue_id;

    /* Wire port IDs (DOCA Flow eSwitch vport IDs, not DPDK port ids).
     * Used by the FWD_PORT re-entry of reinjected replies. */
    uint16_t n3_port_id;
    uint16_t n6_port_id;

    /* Local addresses — MACs and IPs in network byte order where
     * indicated.  A zero ip disables that side of the responder. */
    uint8_t  upf_n3_mac[6];
    uint8_t  upf_n6_mac[6];
    uint32_t upf_n3_ip;        /* NBO */
    uint32_t upf_n6_ip;        /* NBO (0 disables the N6 responder)   */

    /* Peer L2/L3 addresses — destination of proactive unicast-ARP-reply
     * refreshes.  Used to keep the peer's neighbour cache in REACHABLE
     * state without depending on the peer's broadcast ARP arriving at
     * BF3 ARM (firmware on PF1 routes ARP frames to the host kernel,
     * not to DPDK).  A zero peer_ip disables that side's refresh. */
    uint8_t  gnb_mac[6];       /* peer on the N3 wire                 */
    uint8_t  dn_gw_mac[6];     /* peer on the N6 wire                 */
    uint32_t gnb_ip;           /* NBO; 0 disables N3 refresh          */
    uint32_t dn_gw_ip;         /* NBO; 0 disables N6 refresh          */

    /* Mempool for allocating gratuitous-ARP Tx mbufs.  Owned by the
     * caller (g_mbuf_pool in dpu_agent.c). */
    struct rte_mempool *mbuf_pool;

    /* Runtime */
    volatile bool running;

    /* Counters (written only by the responder lcore) */
    uint64_t arp_requests_rx;
    uint64_t arp_replies_tx;
    uint64_t arp_ignored;          /* not for us / malformed          */
    uint64_t tx_failed;
    uint64_t rx_unknown;           /* non-ARP ether_type seen on queue */
    uint64_t garp_tx;              /* gratuitous ARP REQUESTs Tx'd    */
    uint64_t unicast_arp_replies_tx; /* proactive unicast ARP REPLYs Tx'd */
} l2l3_responder_ctx_t;


/**
 * Initialise the responder context (VNF mode — dual-port poll).
 *
 * The caller must have already registered the dynamic metadata field
 * via rte_flow_dynf_metadata_register() (the DPU Agent's N3 port setup
 * does this once for the buffer / shaper / responder reinject paths).
 *
 * @param ctx                Responder context (caller-allocated, zero'd)
 * @param n3_dpdk_port       DPDK ethdev ID of the N3 PF
 * @param n3_rx_queue_base   First Rx queue for N3 responder
 * @param n3_nr_rx_queues    Number of N3 responder Rx queues (0 to disable N3)
 * @param n3_tx_queue_id     Tx queue on N3 for responder reinject
 * @param n6_dpdk_port       DPDK ethdev ID of the N6 PF
 * @param n6_rx_queue_base   First Rx queue for N6 responder
 * @param n6_nr_rx_queues    Number of N6 responder Rx queues (0 to disable N6)
 * @param n6_tx_queue_id     Tx queue on N6 for responder reinject
 * @param n3_port_id         DOCA Flow eSwitch port id of the N3 wire
 * @param n6_port_id         DOCA Flow eSwitch port id of the N6 wire
 * @param upf_n3_mac         Local MAC on the N3 wire (6 bytes)
 * @param upf_n6_mac         Local MAC on the N6 wire (6 bytes)
 * @param upf_n3_ip          Local IPv4 on N3 (NBO; non-zero to enable)
 * @param upf_n6_ip          Local IPv4 on N6 (NBO; 0 disables N6 replies)
 * @param mbuf_pool          DPDK mempool for allocating gratuitous-ARP
 *                            Tx mbufs.  Must be non-NULL.
 * @return  0 on success, -1 on invalid arguments
 */
int l2l3_responder_init(l2l3_responder_ctx_t *ctx,
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
                        struct rte_mempool *mbuf_pool);

/**
 * Responder Rx/Tx lcore loop.
 * Runs until l2l3_responder_stop() is called.
 *
 * @param arg  Pointer to l2l3_responder_ctx_t
 * @return     0 on clean exit
 */
int l2l3_responder_loop(void *arg);

/** Signal the responder loop to exit at the next iteration. */
void l2l3_responder_stop(l2l3_responder_ctx_t *ctx);

/** Destroy / reset the responder context.  Call after the lcore exits. */
void l2l3_responder_destroy(l2l3_responder_ctx_t *ctx);

/** Log the responder counters (DOCA_LOG_INFO). */
void l2l3_responder_dump_stats(const l2l3_responder_ctx_t *ctx);

#ifdef __cplusplus
}
#endif
