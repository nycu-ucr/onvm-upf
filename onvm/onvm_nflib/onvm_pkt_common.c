/*********************************************************************
 *                     openNetVM
 *              https://sdnfv.github.io
 *
 *   BSD LICENSE
 *
 *   Copyright(c)
 *            2015-2019 George Washington University
 *            2015-2019 University of California Riverside
 *            2010-2019 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * The name of the author may not be used to endorse or promote
 *       products derived from this software without specific prior
 *       written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 ********************************************************************/

/******************************************************************************
                                 onvm_pkt_common.c

            This file contains all functions related to receiving or
            transmitting packets.

******************************************************************************/

#include "onvm_pkt_common.h"

#define UPFU_TAG_BIT (1u << 7)

#define TRACE_MIN_FRAME (RTE_ETHER_MIN_LEN - RTE_ETHER_CRC_LEN)

/**********************Internal Functions Prototypes**************************/

/*
 * Function to enqueue a packet on one port's queue.
 *
 * Inputs : a pointer to the tx queue responsible
 *          the number of the port
 *          a pointer to the packet
 *
 */
static inline void
onvm_pkt_enqueue_port(struct queue_mgr *tx_mgr, uint16_t port, struct rte_mbuf *buf);

/*
 * Function to process a single packet.
 *
 * Inputs : a pointer to the tx queue responsible
 *          a pointer to the packet
 *          a pointer to the NF involved
 *
 */
static inline void
onvm_pkt_process_next_action(struct queue_mgr *tx_mgr, struct rte_mbuf *pkt, int pkt_meta_offset, struct onvm_nf *nf);

/*
 * Helper function to drop a packet.
 *
 * Input : a pointer to the packet
 *
 * Ouput : an error code
 *
 */
static int
onvm_pkt_drop(struct rte_mbuf *pkt);


static inline struct onvm_pkt_meta *
pkt_meta_from_txmgr(const struct queue_mgr *tx_mgr, struct rte_mbuf *m) {
        if (tx_mgr->pkt_meta_offset < 0)
                return NULL;
        return onvm_get_pkt_meta(m, tx_mgr->pkt_meta_offset);
}

static uint64_t g_tx_shortfall = 0, g_tx_shortfall_firstlen_lt60 = 0;
static uint64_t g_tx_shortfall_firstlen_gt1518 = 0, g_tx_shortfall_multiseg = 0;

static inline void dbg_dump_refused(const char* tag, uint16_t port, uint16_t qid,
                                    struct rte_mbuf *m,
                                    uint16_t sent, uint16_t count) {
    uint16_t len   = rte_pktmbuf_pkt_len(m);
    uint8_t *base  = rte_pktmbuf_mtod(m, uint8_t*);
    uint16_t eth_t = (len >= 14) ? rte_be_to_cpu_16(*(uint16_t*)(base + 12)) : 0xffff;

    printf("[%s] TX shortfall p%u q%u: sent %u/%u len=%u nb_segs=%u first=%02x %02x ethertype=0x%04x data_off=%u buf_len=%u tailroom=%u\n",
           tag, port, qid, sent, count, len, m->nb_segs,
           base[0], (len>1?base[1]:0), eth_t,
           m->data_off, m->buf_len, rte_pktmbuf_tailroom(m));

    g_tx_shortfall++;
    if (len < 60) g_tx_shortfall_firstlen_lt60++;
    if (len > 1518) g_tx_shortfall_firstlen_gt1518++;
    if (m->nb_segs > 1) g_tx_shortfall_multiseg++;
}

static inline void
trace_short_mbuf(const char *stage, struct rte_mbuf *m, int pkt_meta_offset) {
        const uint16_t len = rte_pktmbuf_pkt_len(m);
        if (likely(len >= TRACE_MIN_FRAME))
                return;

        struct onvm_pkt_meta *meta = NULL;
        if (pkt_meta_offset >= 0)
                meta = onvm_get_pkt_meta(m, pkt_meta_offset);

        printf("[trace] %s m=%p len=%u magic=0x%08x orig=%u id=%u tag=%u src=%u dst=%u ref=%u data_off=%u\n",
               stage, (void *)m, len,
               m->dynfield1[UPFU_STAMP_DYNIDX],
               m->dynfield1[UPFU_STAMP_LEN_IDX],
               m->dynfield1[UPFU_STAMP_ID_IDX],
               meta ? !!(meta->flags & UPFU_TAG_BIT) : 0,
               meta ? meta->src : 0,
               meta ? meta->destination : 0,
               rte_mbuf_refcnt_read(m),
               m->data_off);
}



static struct rte_eth_stats g_prev_stats[RTE_MAX_ETHPORTS];
static uint64_t g_shortfall_events[RTE_MAX_ETHPORTS];

static inline void dump_tx_stats_delta(uint16_t port, uint16_t qid, const char* tag) {
    struct rte_eth_stats now;
    if (rte_eth_stats_get(port, &now) < 0) return;

    const struct rte_eth_stats *prev = &g_prev_stats[port];

    uint64_t d_op = now.opackets - prev->opackets;
    uint64_t d_ob = now.obytes   - prev->obytes;
    uint64_t d_oe = now.oerrors  - prev->oerrors;

    // per-queue arrays only exist up to RTE_ETHDEV_QUEUE_STAT_CNTRS
    uint64_t d_qop = 0, d_qob = 0;
    if (qid < RTE_ETHDEV_QUEUE_STAT_CNTRS) {
        d_qop = now.q_opackets[qid] - prev->q_opackets[qid];
        d_qob = now.q_obytes[qid]   - prev->q_obytes[qid];
    }

    printf("[%s] p%u q%u Δ: opk=%" PRIu64 " obytes=%" PRIu64 " oerr=%" PRIu64
           " | q_opk=%" PRIu64 " q_obytes=%" PRIu64 " (events=%" PRIu64 ")\n",
           tag, port, qid, d_op, d_ob, d_oe, d_qop, d_qob, ++g_shortfall_events[port]);

    g_prev_stats[port] = now; // update snapshot
}


static inline const char* dstat2s(int s){
  return s==RTE_ETH_TX_DESC_FULL?"FULL":
         s==RTE_ETH_TX_DESC_DONE?"DONE":
         s==RTE_ETH_TX_DESC_UNAVAIL?"UNAVAIL":"?";
}

static inline void dump_desc_sample(uint16_t port, uint16_t qid) {
  const uint16_t idxs[] = {0, 32, 64, 128};
  for (unsigned i=0; i<sizeof(idxs)/sizeof(idxs[0]); i++) {
    int st = rte_eth_tx_descriptor_status(port, qid, idxs[i]);
    if (st >= 0) printf("[desc] p%u q%u d%u=%s\n", port, qid, idxs[i], dstat2s(st));
  }
}

static inline void dump_link(uint16_t port) {
  struct rte_eth_link lk;
  rte_eth_link_get_nowait(port, &lk);
  printf("[link] p%u up=%d speed=%u duplex=%u\n",
         port, lk.link_status, lk.link_speed, lk.link_duplex);
}



/**********************************Interfaces*********************************/

void
onvm_pkt_process_tx_batch(struct queue_mgr *tx_mgr, struct rte_mbuf *pkts[], int pkt_meta_offset, uint16_t tx_count, struct onvm_nf *nf) {
        uint16_t i;
        struct onvm_pkt_meta *meta;
        struct packet_buf *out_buf;
        uint32_t out_count = 0, tonf_count = 0, drop_count = 0, next_count = 0;

        if (tx_mgr == NULL || pkts == NULL || nf == NULL)
                return;

        {
            uint16_t zeros = 0, dups = 0;
            for (uint16_t a = 0; a < tx_count; a++) {
                struct rte_mbuf *ma = pkts[a];
                if (rte_pktmbuf_pkt_len(ma) == 0) zeros++;
                for (uint16_t b = a + 1; b < tx_count; b++) {
                    if (pkts[b] == ma) dups++;
                }
            }
            if (zeros || dups)
                printf("[nf-batch-sum] zeros=%u dups=%u count=%u\n", zeros, dups, tx_count);
        }

        for (i = 0; i < tx_count; i++) {
            struct rte_mbuf *m_chk = pkts[i];
            if (unlikely(rte_pktmbuf_pkt_len(m_chk) == 0)) {
                printf("[nf-batch-drop-zero] m=%p len=0 ref=%u\n", (void*)m_chk, rte_mbuf_refcnt_read(m_chk));
                continue;
            }
            int _dup = 0;
            for (uint16_t _j=0; _j<i; _j++) {
                if (pkts[_j] == m_chk) {
                    printf("[nf-batch-dup-skip] m=%p first=%u again=%u len=%u\n", (void*)m_chk, _j, i, rte_pktmbuf_pkt_len(m_chk));
                    _dup = 1;
                    break;
                }
            }
            if (_dup) continue;
            // printf("[nf-batch-start] m=%p len=%u\n", pkts[i], rte_pktmbuf_pkt_len(pkts[i]));
            meta = onvm_get_pkt_meta(pkts[i], pkt_meta_offset);
            // printf("[nf-batch-meta] m=%p len=%u meta=%p off=%d action=%u\n", pkts[i], rte_pktmbuf_pkt_len(pkts[i]), (void*)meta, pkt_meta_offset, meta->action);
            meta->src = nf->instance_id;
            // printf("[nf-batch-after-src] m=%p len=%u\n", pkts[i], rte_pktmbuf_pkt_len(pkts[i]));
            if (meta->action == ONVM_NF_ACTION_OUT) {
                //trace_short_mbuf(tx_mgr->mgr_type_t == MGR ? "mgr-process" : "nf-process", pkts[i], pkt_meta_offset);
                uint32_t id = pkts[i]->dynfield1[UPFU_STAMP_ID_IDX];
                uint16_t len = rte_pktmbuf_pkt_len(pkts[i]);
                out_count++;

                /* if (len >= 1400 && (id % 10000u) == 0) {
                        printf("[nf-sample] id=%u len=%u src=%u dst=%u\n",
                        id, len, meta->src, meta->destination);
                } */

                if (meta->destination == 0) {
                        static uint64_t ul_tx = 0;
                        ul_tx++;
                        if (ul_tx % 10000 == 0) {
                                printf("[mgr-tx-thread] id=%u ul_tx=%" PRIu64 " last_len=%u\n",
                                id, ul_tx, len);
                        }
                }

                if (nf->instance_id == 1) {
                        static uint64_t out_log = 0;
                        if ((++out_log % 10000) == 0) {
                                printf("[mgr-tx-out] id=%u dst=%u len=%u\n", id, meta->destination, len);
                        }
                }

            }
            if (meta->action == ONVM_NF_ACTION_DROP) {
                    // if the packet is drop, then <return value> is 0
                    // and !<return value> is 1.
                    drop_count++;
                    nf->stats.act_drop++;
                    nf->stats.tx += !onvm_pkt_drop(pkts[i]);
            } else if (meta->action == ONVM_NF_ACTION_NEXT) {
                    /* TODO: Here we drop the packet : there will be a flow table
                    in the future to know what to do with the packet next */
                    next_count++;
                    nf->stats.act_next++;
                    onvm_pkt_process_next_action(tx_mgr, pkts[i], pkt_meta_offset, nf);
            } else if (meta->action == ONVM_NF_ACTION_TONF) {
                    tonf_count++;
                    nf->stats.act_tonf++;
                    if (nf->instance_id == 1) {
                            uint32_t id = pkts[i]->dynfield1[UPFU_STAMP_ID_IDX];
                            static uint64_t tonf_log = 0;
                            if ((++tonf_log % 10000) == 0) {
                                    printf("[mgr-tx-tonf] id=%u dst_service=%u\n", id, meta->destination);
                            }
                    }
                    onvm_pkt_enqueue_nf(tx_mgr, meta->destination, pkts[i], nf);
            } else if (meta->action == ONVM_NF_ACTION_OUT) {
                    if (tx_mgr->mgr_type_t != MGR) {
                            nf->stats.act_out++;
                            out_buf = tx_mgr->to_tx_buf;
                            out_buf->buffer[out_buf->count++] = pkts[i];
                            if (out_buf->count == PACKET_READ_SIZE) {
                                    onvm_pkt_enqueue_tx_thread(out_buf, nf);
                            }
                    } else {
                            onvm_pkt_enqueue_port(tx_mgr, meta->destination, pkts[i]);
                    }
            } else {
                    printf("ERROR invalid action : this shouldn't happen.\n");
                    onvm_pkt_drop(pkts[i]);
                    return;
            }
        }

        if (nf->instance_id == 1) {
                static uint64_t batch_log = 0;
                if ((++batch_log % 1000) == 0) {
                        printf("[mgr-tx-batch] total=%u out=%u tonf=%u drop=%u next=%u\n",
                               tx_count, out_count, tonf_count, drop_count, next_count);
                }
        }
}

void
onvm_pkt_flush_all_nfs(struct queue_mgr *tx_mgr, struct onvm_nf *source_nf) {
        uint16_t i;

        if (tx_mgr == NULL)
                return;

        for (i = 0; i < MAX_NFS; i++)
                onvm_pkt_flush_nf_queue(tx_mgr, i, source_nf);
}

void
onvm_pkt_flush_nf_queue(struct queue_mgr *tx_mgr, uint16_t nf_id, struct onvm_nf *source_nf) {
        uint16_t i;
        struct onvm_nf *nf;
        struct packet_buf *nf_buf;

        if (tx_mgr == NULL)
                return;

        nf_buf = &tx_mgr->nf_rx_bufs[nf_id];
        if (nf_buf->count == 0)
                return;

        nf = &nfs[nf_id];

        // Ensure destination NF is running and ready to receive packets
        if (!onvm_nf_is_valid(nf))
                return;

        /* uint16_t dups = 0, zeros = 0;
        for (i = 0; i < nf_buf->count; i++) {
                struct rte_mbuf *mi = nf_buf->buffer[i];
                if (rte_pktmbuf_pkt_len(mi) == 0) zeros++;
                for (uint16_t j = i + 1; j < nf_buf->count; j++) {
                        if (nf_buf->buffer[j] == mi) dups++;
                }
        }
        if (dups || zeros) {
                printf("[mgr-nf-flush] nf_id=%u count=%u zeros=%u dups=%u\n", nf_id, nf_buf->count, zeros, dups);
        } */
        if (rte_ring_enqueue_bulk(nf->rx_q, (void **)nf_buf->buffer, nf_buf->count, NULL) == 0) {
                        for (i = 0; i < nf_buf->count; i++) {
                                onvm_pkt_drop(nf_buf->buffer[i]);
                        }
                        nf->stats.rx_drop += nf_buf->count;
                        if (source_nf != NULL)
                                source_nf->stats.tx_drop += nf_buf->count;
                } else {
                        nf->stats.rx += nf_buf->count;
                        if (source_nf != NULL)
                                source_nf->stats.tx += nf_buf->count;
                }
                nf_buf->count = 0;
}

void
onvm_pkt_enqueue_nf(struct queue_mgr *tx_mgr, uint16_t dst_service_id, struct rte_mbuf *pkt,
                    struct onvm_nf *source_nf) {
        struct onvm_nf *nf;
        uint16_t dst_instance_id;
        struct packet_buf *nf_buf;

        if (tx_mgr == NULL || pkt == NULL)
                return;

        // map service to instance and check one exists
        dst_instance_id = onvm_sc_service_to_nf_map(dst_service_id, pkt);
        if (dst_instance_id == 0) {
                onvm_pkt_drop(pkt);
                if (source_nf != NULL)
                        source_nf->stats.tx_drop++;
                return;
        }

        // Ensure destination NF is running and ready to receive packets
        nf = &nfs[dst_instance_id];
        if (!onvm_nf_is_valid(nf)) {
                onvm_pkt_drop(pkt);
                if (source_nf != NULL)
                        source_nf->stats.tx_drop++;
                return;
        }

        nf_buf = &tx_mgr->nf_rx_bufs[dst_instance_id];

        if (nf->service_id == 1) {
                static uint64_t to_upf = 0;
                to_upf++;
                if (to_upf % 10000 == 0) {
                        //printf("[mgr-to-upf] count=%" PRIu64 " nf_rx_buf_count=%u\n", to_upf, nf_buf->count);
                }
        }

        nf_buf->buffer[nf_buf->count++] = pkt;
        if (nf_buf->count == PACKET_READ_SIZE) {
                onvm_pkt_flush_nf_queue(tx_mgr, dst_instance_id, source_nf);
        }
}


void
onvm_pkt_flush_port_queue(struct queue_mgr *tx_mgr, uint16_t port) {
        uint16_t i, sent;
        volatile struct tx_stats *tx_stats;
        struct packet_buf *port_buf;

        if (tx_mgr == NULL || tx_mgr->mgr_type_t != MGR)
                return;

        port_buf = &tx_mgr->tx_thread_info->port_tx_bufs[port];
        if (port_buf->count == 0)
                return;

        tx_stats = &(ports->tx_stats);

        // optional: keep batch-level prepare for the entire burst
        int ok = rte_eth_tx_prepare(port, tx_mgr->id, port_buf->buffer, port_buf->count);
        if (ok != (int)port_buf->count) {
                printf("[prepare] p%u q%u ok=%d/%u rte_errno=%d\n",
                       port, (unsigned)tx_mgr->id, ok, port_buf->count, rte_errno);

                if (ok <= 0) {
                        for (i = 0; i < port_buf->count; i++)
                                onvm_pkt_drop(port_buf->buffer[i]);
                        tx_stats->tx_drop[port] += port_buf->count;
                        port_buf->count = 0;
                        return;
                }

                for (i = ok; i < port_buf->count; i++)
                        onvm_pkt_drop(port_buf->buffer[i]);
                tx_stats->tx_drop[port] += (port_buf->count - ok);
                port_buf->count = ok;
        }

        for (uint16_t i = 0; i < port_buf->count; i++) {
            struct rte_mbuf *m = port_buf->buffer[i];
            uint16_t len = rte_pktmbuf_pkt_len(m);
            /* if (len >= 1400) {
                uint32_t id = m->dynfield1[UPFU_STAMP_ID_IDX];
                if ((id % 10000u) == 0) {
                    printf("[mgr-sample] p%u q%u id=%u len=%u\n",
                        port, tx_mgr->id, id, len);
                }
            } */
        }

        sent = rte_eth_tx_burst(port, tx_mgr->id, port_buf->buffer, port_buf->count);

        if (unlikely(sent < port_buf->count)) {
                uint16_t total = sent;
                uint16_t n = port_buf->count;

                int reclaimed = rte_eth_tx_done_cleanup(port, (uint16_t)tx_mgr->id, 0);
                struct rte_mbuf *first_refused = port_buf->buffer[total];

                /* printf("[mbuf] m=%p ol=0x%lx l2=%u l3=%u tso=%u vlan=%u\n",
                       (void *)first_refused,
                       (unsigned long)first_refused->ol_flags,
                       first_refused->l2_len, first_refused->l3_len,
                       first_refused->tso_segsz, first_refused->vlan_tci); */

                int ok1 = rte_eth_tx_prepare(port, (uint16_t)tx_mgr->id, &first_refused, 1);

                if (port == 0 && sent == 0) {
                        uint16_t f_len = rte_pktmbuf_pkt_len(first_refused);
                        uint16_t f_l2 = first_refused->l2_len;
                        uint16_t f_l3 = first_refused->l3_len;
                        uint32_t f_ol = (uint32_t)first_refused->ol_flags;
                        uint16_t f_ref = rte_mbuf_refcnt_read(first_refused);

                        struct rte_eth_link lk;
                        rte_eth_link_get_nowait(port, &lk);

                        struct rte_eth_txq_info qi_dbg;
                        int qi_ok = rte_eth_tx_queue_info_get(port, (uint16_t)tx_mgr->id, &qi_dbg);

                        printf("[port0-tx-debug] ok1=%d errno=%d len=%u l2=%u l3=%u nb_segs=%u ol=0x%x ref=%u link_up=%d speed=%u duplex=%u txq_ok=%d desc=%u\n",
                               ok1, rte_errno, f_len, f_l2, f_l3, first_refused->nb_segs, f_ol, f_ref,
                               lk.link_status, lk.link_speed, lk.link_duplex,
                               qi_ok, qi_ok == 0 ? qi_dbg.nb_desc : 0);

                        if (qi_ok == 0) {
                                uint16_t mid_idx = qi_dbg.nb_desc / 2;
                                uint16_t tail_idx = qi_dbg.nb_desc ? (qi_dbg.nb_desc - 1) : 0;

                                int s0 = rte_eth_tx_descriptor_status(port, (uint16_t)tx_mgr->id, 0);
                                int sm = rte_eth_tx_descriptor_status(port, (uint16_t)tx_mgr->id, mid_idx);
                                int st = rte_eth_tx_descriptor_status(port, (uint16_t)tx_mgr->id, tail_idx);

                                int reclaimed_all = rte_eth_tx_done_cleanup(port, (uint16_t)tx_mgr->id, UINT32_MAX);

                                int s0b = rte_eth_tx_descriptor_status(port, (uint16_t)tx_mgr->id, 0);
                                int smb = rte_eth_tx_descriptor_status(port, (uint16_t)tx_mgr->id, mid_idx);
                                int stb = rte_eth_tx_descriptor_status(port, (uint16_t)tx_mgr->id, tail_idx);

                                const char *stat_str0  = (s0  == RTE_ETH_TX_DESC_FULL) ? "FULL" : (s0  == RTE_ETH_TX_DESC_DONE) ? "DONE" : "UNAVAIL";
                                const char *stat_strm  = (sm  == RTE_ETH_TX_DESC_FULL) ? "FULL" : (sm  == RTE_ETH_TX_DESC_DONE) ? "DONE" : "UNAVAIL";
                                const char *stat_strt  = (st  == RTE_ETH_TX_DESC_FULL) ? "FULL" : (st  == RTE_ETH_TX_DESC_DONE) ? "DONE" : "UNAVAIL";
                                const char *stat_str0b = (s0b == RTE_ETH_TX_DESC_FULL) ? "FULL" : (s0b == RTE_ETH_TX_DESC_DONE) ? "DONE" : "UNAVAIL";
                                const char *stat_strmb = (smb == RTE_ETH_TX_DESC_FULL) ? "FULL" : (smb == RTE_ETH_TX_DESC_DONE) ? "DONE" : "UNAVAIL";
                                const char *stat_strtb = (stb == RTE_ETH_TX_DESC_FULL) ? "FULL" : (stb == RTE_ETH_TX_DESC_DONE) ? "DONE" : "UNAVAIL";

                                struct rte_eth_stats stx;
                                rte_eth_stats_get(port, &stx);
                                uint64_t qerr = (tx_mgr->id < RTE_ETHDEV_QUEUE_STAT_CNTRS) ? stx.q_errors[tx_mgr->id] : 0;

                                printf("[port0-tx-desc] pre d0=%s dm=%s dt=%s | post d0=%s dm=%s dt=%s | reclaimed_all=%d oerr=%" PRIu64 " qerr=%" PRIu64 "\n",
                                       stat_str0, stat_strm, stat_strt,
                                       stat_str0b, stat_strmb, stat_strtb,
                                       reclaimed_all, stx.oerrors, qerr);
                        }
                }

                // dbg_dump_refused("flush", port, tx_mgr->id, first_refused, total, n);
                //dump_tx_stats_delta(port, tx_mgr->id, "flush-shortfall");

                struct rte_eth_txq_info qi;
                if (rte_eth_tx_queue_info_get(port, (uint16_t)tx_mgr->id, &qi) == 0) {
                        uint16_t mid = qi.nb_desc / 2;
                        uint16_t tail = qi.nb_desc ? (qi.nb_desc - 1) : 0;

                        int s0 = rte_eth_tx_descriptor_status(port, (uint16_t)tx_mgr->id, 0);
                        int sm = rte_eth_tx_descriptor_status(port, (uint16_t)tx_mgr->id, mid);
                        int st = rte_eth_tx_descriptor_status(port, (uint16_t)tx_mgr->id, tail);

                        /* printf("[desc] p%u q%u d0=%s d%u=%s d%u=%s\n",
                               port, (unsigned)tx_mgr->id,
                               s0==RTE_ETH_TX_DESC_FULL?"FULL":s0==RTE_ETH_TX_DESC_DONE?"DONE":"UNAVAIL",
                               mid, sm==RTE_ETH_TX_DESC_FULL?"FULL":sm==RTE_ETH_TX_DESC_DONE?"DONE":"UNAVAIL",
                               tail,st==RTE_ETH_TX_DESC_FULL?"FULL":st==RTE_ETH_TX_DESC_DONE?"DONE":"UNAVAIL"); */
                }

                // dump_link(port);

                for (i = total; i < n; i++)
                        onvm_pkt_drop(port_buf->buffer[i]);
                tx_stats->tx_drop[port] += (n - total);
        }

        tx_stats->tx[port] += sent;

        if (port == 0) {
                static uint64_t flush_log;
                if ((++flush_log % 10000) == 0) {
                        printf("[port0-flush] queued=%" PRIu16 " sent=%" PRIu16 " drop_total=%" PRIu64 "\n",
                               port_buf->count, sent, tx_stats->tx_drop[port]);
                }
        }
        port_buf->count = 0;
}

void
onvm_pkt_enqueue_tx_thread(struct packet_buf *pkt_buf, struct onvm_nf *nf) {


        uint16_t i;

        uint16_t counter_for_log;

        if (pkt_buf->count == 0)
                return;

        int pkt_meta_offset = (nf && nf->nf_tx_mgr) ? nf->nf_tx_mgr->pkt_meta_offset : -1;
        /* for (i = 0; i < pkt_buf->count; i++) {
                trace_short_mbuf("nf-enqueue", pkt_buf->buffer[i], pkt_meta_offset);
        } */

        struct onvm_pkt_meta *meta = NULL;
        if (pkt_meta_offset >= 0 && nf->instance_id == 1) {
                for (counter_for_log = 0; counter_for_log < pkt_buf->count; counter_for_log++) {
                        meta = onvm_get_pkt_meta(pkt_buf->buffer[counter_for_log], pkt_meta_offset);
                        //meta->src = nf->instance_id;
                        uint32_t id = pkt_buf->buffer[counter_for_log]->dynfield1[UPFU_STAMP_ID_IDX];
                        uint16_t len = rte_pktmbuf_pkt_len(pkt_buf->buffer[counter_for_log]);

                        static uint64_t ul_tx_enqueue = 0;
                        ul_tx_enqueue++;
                        if (ul_tx_enqueue % 10000 == 0) {
                                printf("[enqueue_tx_thread] id=%u ul_tx_enqueue=%" PRIu64 " last_len=%u\n",
                                id, ul_tx_enqueue, len);
                        }
                }
                
        }
                

        if (unlikely(pkt_buf->count > 0 &&
                     rte_ring_enqueue_bulk(nf->tx_q, (void **)pkt_buf->buffer, pkt_buf->count, NULL) == 0)) {
                nf->stats.tx_drop += pkt_buf->count;
                for (i = 0; i < pkt_buf->count; i++) {
                        rte_pktmbuf_free(pkt_buf->buffer[i]);
                }
        } else {
                nf->stats.tx += pkt_buf->count;
        }
        pkt_buf->count = 0;
}

/****************************Internal functions*******************************/

inline static void
onvm_pkt_enqueue_port(struct queue_mgr *tx_mgr, uint16_t port, struct rte_mbuf *buf) {
        struct packet_buf *port_buf;
        if (tx_mgr == NULL || buf == NULL || !ports->init[port]) {
                return;

        }

        if (!ports->init[port]) {
            static uint8_t warned[RTE_MAX_ETHPORTS];
            if (!warned[port]) {
                printf("[mgr] port %u init=%u (dropping packet m=%p)\n",
                    port, ports->init[port], (void *)buf);
                warned[port] = 1;
            }
            return;
        }

        // trace_short_mbuf("mgr-queue", buf, tx_mgr ? tx_mgr->pkt_meta_offset : -1);
        port_buf = &tx_mgr->tx_thread_info->port_tx_bufs[port];
        port_buf->buffer[port_buf->count++] = buf;
        if (port_buf->count == PACKET_READ_SIZE) {
                onvm_pkt_flush_port_queue(tx_mgr, port);
        }

}

inline static void
onvm_pkt_process_next_action(struct queue_mgr *tx_mgr, struct rte_mbuf *pkt, int pkt_meta_offset, struct onvm_nf *nf) {
        if (tx_mgr == NULL || pkt == NULL || nf == NULL)
                return;

        struct onvm_flow_entry *flow_entry;
        struct onvm_service_chain *sc;
        struct onvm_pkt_meta *meta = onvm_get_pkt_meta(pkt, pkt_meta_offset);
        int ret;

        ret = onvm_flow_dir_get_pkt(pkt, &flow_entry);
        if (ret >= 0) {
                sc = flow_entry->sc;
                meta->action = onvm_sc_next_action(sc, pkt, pkt_meta_offset);
                meta->destination = onvm_sc_next_destination(sc, pkt, pkt_meta_offset);
        } else {
                meta->action = onvm_sc_next_action(default_chain, pkt, pkt_meta_offset);
                meta->destination = onvm_sc_next_destination(default_chain, pkt, pkt_meta_offset);
        }

        switch (meta->action) {
                case ONVM_NF_ACTION_DROP:
                        // if the packet is drop, then <return value> is 0
                        // and !<return value> is 1.
                        nf->stats.act_drop += !onvm_pkt_drop(pkt);
                        break;
                case ONVM_NF_ACTION_TONF:
                        nf->stats.act_tonf++;
                        onvm_pkt_enqueue_nf(tx_mgr, meta->destination, pkt, nf);
                        break;
                case ONVM_NF_ACTION_OUT:
                        nf->stats.act_out++;
                        onvm_pkt_enqueue_port(tx_mgr, meta->destination, pkt);
                        break;
                default:
                        break;
        }
        (meta->chain_index)++;
}

/*******************************Helper function*******************************/

static int
onvm_pkt_drop(struct rte_mbuf *pkt) {
        rte_pktmbuf_free(pkt);
        if (pkt != NULL) {
                return 1;
        }
        return 0;
}
