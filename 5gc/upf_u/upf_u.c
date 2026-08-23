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

#include <errno.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_gtp.h>
#include <rte_ip.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_meter.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_tcp.h>

#include "gtp.h"
#include "upf_context.h"
#include "utlt_debug.h"
#include "onvm_flow_table.h"
#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include "list.h"

#include "upf_events.h"
#include "upf_cls_ctrl.h"
#include "upf_sess_buf.h"

#include "../classifiers/upf_cls_adapter.h"
#include "../classifiers/classifier_wrapper.h"

#include "upf_u_helper.h"
#include "upf_u_config.h"
#include "upf_u_arp.h"
#include "upf_u_icmp.h"
#include "upf_u_nat.h"
#include "upf_u_shaper.h"
#include "upf_u_trtcm.h"

#define NF_TAG "upf_u"

/* Used for buffering */
#define INLINE_DRAIN_BATCH       8    /* pkts drained per INLINE (FORW)  */
#define DRAIN_CHUNK             128   /* max pkts dequeued per drain call */

uint64_t seid = 0;
uint16_t pdrId = 0;


typedef struct {
    void    *ptr;          // current active snapshot (cls_handle_t*)
    uint32_t ver;          // last applied version
    uint32_t pending_ver;  // version announced by UPF-C via REQ
    uint8_t  flip_pending; // 1 when a flip is requested; cleared after flip
} upf_cls_local_t;

static upf_cls_local_t g_cls_local = {0};

// Flip to the latest published snapshot (called at burst boundary)
static inline void
UpfClsMaybeFlipAndAck(void) {
    if (likely(!g_cls_local.flip_pending))
        return;

    // Seqlock read: accept only a stable, even version that doesn't change
    void *new_ptr = NULL;
    uint32_t v1, v2;

    for (;;) {
        v1 = __atomic_load_n(&g_upf_cls_ctrl->version, __ATOMIC_ACQUIRE);
        if (unlikely(v1 & 1u)) {          // writer in progress
            rte_pause();                   // be polite to the core
            continue;
        }

        // Load pointer after seeing an even version
        new_ptr  = __atomic_load_n((void * const *)&g_upf_cls_ctrl->active, __ATOMIC_ACQUIRE);

        // Re-check version; must be the same even number
        v2 = __atomic_load_n(&g_upf_cls_ctrl->version, __ATOMIC_ACQUIRE);
        if (likely(v1 == v2 && !(v2 & 1u)))
            break;

        // Changed under us; retry
        rte_pause();
    }

    if (unlikely(!new_ptr)) {
        UTLT_Warning("CLS flip requested but ctrl.active==NULL (ctrl.ver=%u)", v2);
        return;
    }

    // Commit locally & ACK the exact stable version observed
    g_cls_local.ptr  = new_ptr;
    g_cls_local.ver  = v2;
    g_cls_local.flip_pending = 0;

    (void)UpfSendEvt1(UPF_C_SERVICE_ID, EVT_CLS_GC_ACK, (uintptr_t)v2);
}

/* static inline const UPDK_PDR *
UpfLookupPdr(const ps_packet_t *key) {
    const cls_handle_t *snap = (const cls_handle_t *)g_cls_local.ptr;
    if (unlikely(!snap)) return NULL;

    uint32_t  precedence = 0;
    uintptr_t cookie     = 0;
    int hit = cls_classify_packet((cls_handle_t *)snap, key, &precedence, &cookie);
    if (!hit) return NULL;

    return (const UPDK_PDR *)cookie;
} */

static inline uint16_t
UpfClassifyGetPdrId(const ps_packet_t *key) {
    const cls_handle_t *snap = (const cls_handle_t *)g_cls_local.ptr;
    if (unlikely(!snap)) {
        UTLT_Warning("CLS classify: no snapshot yet (ver=%u) — dropping", g_cls_local.ver);
        return 0;
    }

    // logging block
    void *engine = *(void**)snap;
    UTLT_Debug("CLS classify: snap=%p engine=%p ver=%u", (void*)snap, engine, g_cls_local.ver);

    uint32_t  precedence = 0;
    uintptr_t pdrId     = 0;
    int hit = cls_classify_packet((cls_handle_t *)snap, key, &precedence, &pdrId);
    if (hit != 1) {
        return 0;
    }

    return (uint16_t)pdrId;
}

static inline const UPDK_PDR *
UpfClassifyGetPdrPtr(const ps_packet_t *key) {
    const cls_handle_t *snap = (const cls_handle_t *)g_cls_local.ptr;
    if (unlikely(!snap)) {
        UTLT_Warning("CLS classify: no snapshot yet (ver=%u) — dropping", g_cls_local.ver);
        return NULL;
    }
    uint32_t  precedence = 0;
    uintptr_t descriptor     = 0;
    int hit = cls_classify_packet((cls_handle_t *)snap, key, &precedence, &descriptor);
    if (hit != 1 || descriptor == 0) return NULL;
    return (const UPDK_PDR *)descriptor;
}

static inline uint64_t
saturating_add_u64(uint64_t lhs, uint64_t rhs) {
    return UINT64_MAX - lhs < rhs ? UINT64_MAX : lhs + rhs;
}

UPDK_PDR *
GetPdrByUeIpAddress(struct rte_mbuf *pkt, uint32_t ue_ip)
{
    /* ── 1) Build classifier key ─────────────────────────────── */
    ps_packet_t key = {0};
    uint8_t *pkt_data = rte_pktmbuf_mtod(pkt, uint8_t *);

    /* Outer (N6 / Core) IPv4 + UDP */
    struct rte_ipv4_hdr *outer4 = onvm_pkt_ipv4_hdr(pkt);
    if (!outer4) return NULL;
    struct rte_udp_hdr  *outerU = onvm_pkt_udp_hdr(pkt);

    key.src_ip = rte_be_to_cpu_32(outer4->src_addr);
    key.dst_ip = rte_be_to_cpu_32(outer4->dst_addr);
    key.tos_tc = outer4->type_of_service;

    key.teid    = 0;        /* Downlink: no GTP */
    key.ue_ip   = ue_ip;

    uint16_t sp = 0, dp = 0;

    key.proto = outer4->next_proto_id;

    if (key.proto == IPPROTO_UDP) {
        const struct rte_udp_hdr *uh = onvm_pkt_udp_hdr(pkt);
        if (uh) {
            sp = rte_be_to_cpu_16(uh->src_port);
            dp = rte_be_to_cpu_16(uh->dst_port);
        }
    }

    key.src_port= sp;
    key.dst_port= dp;
    key.proto   = outer4->next_proto_id;

    /* SPI (ESP) */
    key.spi = 0;


    // Flow-label (only applicable to IPv6 traffic)
    key.flow_label = 0;
    key.ni_hash = 0;    // packet is not GTP‑encapsulated
    key.qfi = 0;        // no QFI in plain-IP downlink path

    //key.source_if = PortToSourceInterface(pkt->port);

    key.source_if = SRC_IF_CORE;
    key.is_uplink = false;

    /* ── 2) PartitionSort classifier ────────────────────────── */
    const UPDK_PDR *pdr = UpfClassifyGetPdrPtr(&key);
    if (!pdr) {
        UTLT_Error("Couldn't classify the packet to a PDR");
        return NULL;
    }

    ConfigureQerFlows(pdr, false);
    return pdr;
}

UPDK_PDR *
GetPdrByTeid(struct rte_mbuf *pkt, const gtp_parse_result_t *gtp_info) {
    // Locate inner IP header using pre-computed offset
    size_t inner_offset = sizeof(struct rte_ether_hdr) + gtp_info->outer_hdr_len;

    uint16_t data_len = rte_pktmbuf_data_len(pkt);
    if (data_len < inner_offset + sizeof(struct rte_ipv4_hdr)) return NULL;

    struct rte_ipv4_hdr *inner4 = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *, inner_offset);

    // Verify it looks like IPv4
    if ((inner4->version_ihl >> 4) != 4) return NULL;

    uint8_t inner_ihl = (inner4->version_ihl & 0x0F) * 4;
    struct rte_udp_hdr *innerU = rte_pktmbuf_mtod_offset(pkt, struct rte_udp_hdr *,
        inner_offset + inner_ihl);

    // Build classifier key using pre-parsed values
    ps_packet_t key = {0};
    key.teid      = gtp_info->teid;
    key.qfi       = gtp_info->qfi;
    key.ue_ip     = rte_be_to_cpu_32(inner4->src_addr);
    key.src_ip    = key.ue_ip;
    key.dst_ip    = rte_be_to_cpu_32(inner4->dst_addr);
    key.src_port  = rte_be_to_cpu_16(innerU->src_port);
    key.dst_port  = rte_be_to_cpu_16(innerU->dst_port);
    key.proto     = inner4->next_proto_id;
    key.tos_tc    = inner4->type_of_service;
    key.source_if = SRC_IF_ACCESS;
    key.is_uplink = true;

    /* ── PartitionSort classifier ──────────────────────────── */
    const UPDK_PDR *pdr = UpfClassifyGetPdrPtr(&key);
    if (!pdr) {
        UTLT_Error("Couldn't classify the packet to a PDR");
        return NULL;
    }

    ConfigureQerFlows(pdr, true);

    return pdr;
}

static inline void
AccumulateQerDlRates(const UPDK_QER *q, uint64_t *ambr64,
                     uint64_t *gbr64, uint64_t *mbr64,
                     bool *has_gbr_qer)
{
    if (!q || !q->flags.maximumBitrate)
        return;

    if (q->flags.guaranteedBitrate) {
        *has_gbr_qer = true;
        *gbr64 = saturating_add_u64(*gbr64, q->guaranteedBitrate.dl);
        *mbr64 = saturating_add_u64(*mbr64, q->maximumBitrate.dl);
        return;
    }

    if (q->maximumBitrate.dl > *ambr64)
        *ambr64 = q->maximumBitrate.dl;
}

static inline bool
GetQerRatesFromSession(UpfSession *session, uint64_t *ambr64,
                       uint64_t *gbr64, uint64_t *mbr64,
                       bool *has_gbr_qer)
{
    list_iterator_t *it;
    list_node_t *node;
    bool found = false;

    if (!session || !session->qer_list)
        return false;

    it = list_iterator_new(session->qer_list, LIST_HEAD);
    if (!it)
        return false;

    while ((node = list_iterator_next(it)) != NULL) {
        const UPDK_QER *q = (const UPDK_QER *)node->val;
        if (!q || !q->flags.maximumBitrate)
            continue;

        found = true;
        AccumulateQerDlRates(q, ambr64, gbr64, mbr64, has_gbr_qer);
    }

    list_iterator_destroy(it);
    return found;
}

static inline bool
GetQerRatesFromPdr(const UPDK_PDR *pdr, uint64_t *ambr64,
                   uint64_t *gbr64, uint64_t *mbr64,
                   bool *has_gbr_qer)
{
    bool found = false;

    if (!pdr || pdr->qer_count == 0)
        return false;

    int n = (int)pdr->qer_count;
    if (n > 2) n = 2; /* safety; struct currently supports 2 */

    for (int i = 0; i < n; i++) {
        const UPDK_QER *q = pdr->qers[i];
        if (!q || !q->flags.maximumBitrate)
            continue;

        found = true;
        AccumulateQerDlRates(q, ambr64, gbr64, mbr64, has_gbr_qer);
    }

    return found;
}

/* Populate UE table from the owning session when possible. The session-level
 * non-GBR QER carries AMBR; GBR-bearing QERs carry QoS flow GBR/MBR. */
static inline int
GetQerByUEIpAddressFromPdr(uint32_t ue_ip, UpfSession *session,
                           const UPDK_PDR *pdr, const char *ip_str)
{
    if ((!session || !session->qer_list) && (!pdr || pdr->qer_count == 0)) {
        UTLT_Trace("UE %s: No PDR or PDR has no QERs, skip UE table entry",
                   ip_str ? ip_str : "<unknown>");
        return -1;
    }

    uint64_t ambr64 = 0;
    uint64_t gbr64  = 0;
    uint64_t mbr64  = 0;
    bool has_gbr_qer = false;

    if (!GetQerRatesFromSession(session, &ambr64, &gbr64, &mbr64,
                                &has_gbr_qer)) {
        GetQerRatesFromPdr(pdr, &ambr64, &gbr64, &mbr64, &has_gbr_qer);
    }
    if (ambr64 == 0 && mbr64 > 0)
        ambr64 = mbr64;

    if (ambr64 == 0) {
        UTLT_Trace("UE %s: no DL MBR across PDR QERs, skip UE table entry",
                   ip_str ? ip_str : "<unknown>");
        return -1;
    }

    /* Clamp PFCP 64-bit rates into 32-bit UE table fields */
    uint32_t ambr = (ambr64 > UINT32_MAX) ? UINT32_MAX : (uint32_t)ambr64;
    uint32_t gbr  = (gbr64  > UINT32_MAX) ? UINT32_MAX : (uint32_t)gbr64;
    uint32_t mbr  = (mbr64  > UINT32_MAX) ? UINT32_MAX : (uint32_t)mbr64;

    if (!has_gbr_qer)
        mbr = 0;
    if (mbr && gbr > mbr) gbr = mbr;

    UTLT_Warning("Add UE IP: %s, AMBR: %u GBR: %u, MBR: %u",
                 ip_str ? ip_str : "<unknown>", ambr, gbr, mbr);

    return addEntrybyUeIp(ue_ip, ambr, gbr, mbr);
}


void
Encap(struct rte_mbuf *pkt, UPDK_FAR *far, UPDK_QER *qer) {
    UPDK_OuterHeaderCreation *outerHeaderCreation = &(far->forwardingParameters.outerHeaderCreation);
    uint16_t outerHeaderLen = 0;
    uint16_t payloadLen = pkt->data_len;
    if (qer) {
        outerHeaderLen = sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) + sizeof(gtpv1_t) +
                 sizeof(gtpv1_hdr_opt_t) + sizeof(pdu_sess_container_hdr_t);
        payloadLen += sizeof(gtpv1_hdr_opt_t) + sizeof(pdu_sess_container_hdr_t);

    } else {
        outerHeaderLen = sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) + sizeof(gtpv1_t);
    }

    gtpv1_t *gtp_hdr = (gtpv1_t *)rte_pktmbuf_prepend(pkt, outerHeaderLen);
    gtp_hdr = rte_pktmbuf_mtod_offset(pkt, gtpv1_t *, sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr));
    gtpv1_set_header(gtp_hdr, payloadLen, outerHeaderCreation->teid);

    if (qer) {
        gtp_hdr->flags |= GTP1_F_EXTHDR;  // enable extension header
        gtpv1_hdr_opt_t *gtp_opt_hdr = rte_pktmbuf_mtod_offset(
            pkt, gtpv1_hdr_opt_t *, sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) + sizeof(gtpv1_t));
        gtp_opt_hdr->seq_number = 0;
        gtp_opt_hdr->NPDU = 0;
        gtp_opt_hdr->next_ehdr_type = GTPV1_NEXT_EXT_HDR_TYPE_85;

        pdu_sess_container_hdr_t *pdu_ss_ctr =
            rte_pktmbuf_mtod_offset(pkt, pdu_sess_container_hdr_t *,
                        sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) + sizeof(gtpv1_t) +
                        sizeof(gtpv1_hdr_opt_t));
        pdu_ss_ctr->length = 0x01;
        pdu_ss_ctr->pdu_sess_ctr = rte_cpu_to_be_16(QERGetQFI(qer));
        pdu_ss_ctr->next_hdr = 0x00;
    }

    struct rte_udp_hdr *udp_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_udp_hdr *, sizeof(struct rte_ipv4_hdr));
    onvm_pkt_fill_udp(udp_hdr, UDP_PORT_FOR_GTP, UDP_PORT_FOR_GTP,
              payloadLen + sizeof(gtpv1_t));  // pktdatalen-outerheaderlen=rawpacket_len, but here,
                              // udppayloadlen should be raw + gtp header

    struct rte_ipv4_hdr *ipv4_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *, 0);
    memset(ipv4_hdr, 0, sizeof(*ipv4_hdr));
    onvm_pkt_fill_ipv4(ipv4_hdr, rte_cpu_to_be_32(g_n3_ip_be), rte_cpu_to_be_32(outerHeaderCreation->ipv4.s_addr),
               IPPROTO_UDP);
    ipv4_hdr->total_length = rte_cpu_to_be_16(payloadLen + sizeof(gtpv1_t) + sizeof(struct rte_udp_hdr) +
                          sizeof(struct rte_ipv4_hdr));  // raw+gtp8+udp8+ip20
    ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
}

static int
HandlePacketWithFar(struct rte_mbuf *pkt, UPDK_FAR *far, UPDK_QER *qer, 
                    uint16_t out_port, struct onvm_pkt_meta *meta) {
    int buff = 0;
#define FAR_ACTION_MASK 0x07
    if (far->flags.applyAction) {
        switch (far->applyAction & FAR_ACTION_MASK) {
            case UPDK_FAR_APPLY_ACTION_DROP:
                meta->action = ONVM_NF_ACTION_DROP;
                break;
            case UPDK_FAR_APPLY_ACTION_FORW:
                if (far->flags.forwardingParameters) {
                    if (far->forwardingParameters.flags.outerHeaderCreation) {
                        UPDK_OuterHeaderCreation *outerHeaderCreation =
                            &(far->forwardingParameters.outerHeaderCreation);
                        switch (outerHeaderCreation->description) {
                            case UPDK_OUTER_HEADER_CREATION_DESCRIPTION_GTPU_UDP_IPV4: {
                                Encap(pkt, far, qer);
                            } break;
                            case UPDK_OUTER_HEADER_CREATION_DESCRIPTION_GTPU_UDP_IPV6:
                            case UPDK_OUTER_HEADER_CREATION_DESCRIPTION_UDP_IPV4:
                            case UPDK_OUTER_HEADER_CREATION_DESCRIPTION_UDP_IPV6:
                            default:
                                UTLT_Error("Unknown outer header creation info");
                        }
                    }
                }
                // meta->destination = pkt->port ^ 1;
                meta->destination = out_port;
                meta->action = ONVM_NF_ACTION_OUT;
                break;
            case UPDK_FAR_APPLY_ACTION_BUFF:
                /* UL should never hit BUFF; DL uses per-session rings.
                 * If we get here unexpectedly, just drop the packet. */
                meta->action = ONVM_NF_ACTION_DROP;
                break;
            default:
                UTLT_Error("Unspec apply action[%u] in FAR[%u]", far->applyAction, far->farId);
        }
        // TODO(vivek): Complete these actions:
        if (far->applyAction & UPDK_FAR_APPLY_ACTION_NOCP) {
            // Send message to UPF-C
            Event *msg = (Event *)rte_calloc(NULL, 1, sizeof(Event), 0);
            msg->type = UPF_EVENT_SESSION_REPORT;
            msg->arg0 = seid;
            msg->arg1 = pdrId;
            /*
            struct ReportMsg *msg= (struct ReportMsg *) rte_calloc(NULL, 1, sizeof(struct ReportMsg), 0);
            msg->seid = seid;
            msg->pdrId = pdrId;
            */
            UTLT_Debug("Send to upf-c, namely service id is 2\n");
            onvm_nflib_send_msg_to_nf(2, msg);
        }
        if (far->applyAction & UPDK_FAR_APPLY_ACTION_DUPL) {
            UTLT_Error("Duplicate Apply action: %u not supported, dropping the packet", far->applyAction);
        }
    }
    return buff;
}

/* Per-session drain helper
 * Dequeue up to max_pkts from session ring, set meta OUT, and TX.
 * Returns the number of packets actually transmitted. */
static uint32_t
drain_session_batch(int sess_idx, uint32_t max_pkts, struct onvm_nf *nf) {
    UpfSessBuf *sb = &g_sess_buf[sess_idx];
    if (!sb->ring_created || !sb->ring)
        return 0;

    struct onvm_configuration *onvm_config = onvm_nflib_get_onvm_config();
    struct rte_mbuf *drain_buf[DRAIN_CHUNK];
    uint32_t total = 0;

    while (total < max_pkts) {
        uint32_t want = max_pkts - total;
        if (want > DRAIN_CHUNK) want = DRAIN_CHUNK;
        uint32_t n = rte_ring_sc_dequeue_burst(sb->ring,
                        (void **)drain_buf, want, NULL);
        if (n == 0) break;

        /* Restore action to OUT so onvm_pkt_process_tx_batch sends them */
        for (uint32_t j = 0; j < n; j++) {
            struct onvm_pkt_meta *m =
                onvm_get_pkt_meta(drain_buf[j],
                                  onvm_config->dynfield_offset);
            m->action = ONVM_NF_ACTION_OUT;
        }

        onvm_pkt_process_tx_batch(nf->nf_tx_mgr, drain_buf,
                                  onvm_config->dynfield_offset, n, nf);
        onvm_pkt_flush_all_nfs(nf->nf_tx_mgr, nf);
        total += n;
    }
    if (rte_ring_count(sb->ring) == 0)
        sb->touched = 0;
    return total;
}

static int
packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta, struct onvm_nf_local_ctx *nf_local_ctx) {
    if (pkt == NULL || meta == NULL) {
        return 0;
    }

    /* Get Ethernet header */
    struct rte_ether_hdr *eth = onvm_pkt_ether_hdr(pkt);
    if (!eth) {
        meta->action = ONVM_NF_ACTION_DROP;
        return 0;
    }

    /* Handle ARP packets */
    if (rte_be_to_cpu_16(eth->ether_type) == RTE_ETHER_TYPE_ARP) {
        handle_arp_packet(pkt, meta, nf_local_ctx);
        return 0;
    }

    /* Handle local ICMP echo request to UPF-U itself */
    if (handle_local_icmp_echo(pkt, meta, nf_local_ctx)) {
        return 0;
    }

    uint32_t cal_pktlen = 0;
    bool cal_pktlen_valid = false;
    UTLT_Trace("Get packet\n");
    UTLT_Info("Handle PKT from port: %d [len: %d]", pkt->port, pkt->pkt_len);

    bool is_dl = false;
    meta->action = ONVM_NF_ACTION_DROP;

    /* Get IPv4 header */
    struct rte_ipv4_hdr *iph = onvm_pkt_ipv4_hdr(pkt);
    if (iph == NULL) {
        UTLT_Info("Not IP packet, ignore it\n");
        return 0;
    }
    cal_pktlen_valid =
        upf_u_shaper_dl_packet_len(pkt, iph, &cal_pktlen);

    // Flip to a newly published snapshot if a REQ was received
    UpfClsMaybeFlipAndAck();

    UPDK_PDR *pdr = NULL;
    gtp_parse_result_t gtp_info = {0};
    int ue_idx = -1;
    UpfSession *owner_session = NULL;
    uint32_t ue_key = 0;
    struct upf_u_shaper_flow_key dl_flow_key = {0};

    /* char *src_address = convertToIpAddressString(iph->src_addr);
    UTLT_Info("Src IP is %s\n", src_address);
    char *dst_address = convertToIpAddressString(iph->dst_addr);
    UTLT_Info("Dst IP is %s\n", dst_address); */

    if (iph->dst_addr == g_n3_ip_be) {  //
        UTLT_Info("It is uplink\n");

        struct rte_udp_hdr *udp_header = onvm_pkt_udp_hdr(pkt);
        if (udp_header == NULL) {
            return 0;
        }

        if (parse_gtpu_once(pkt, &gtp_info) < 0 || !gtp_info.valid) {
            return 0;
        }
        pdr = GetPdrByTeid(pkt, &gtp_info);

    } else {
        UTLT_Trace("DL ingress: port=%u dst=%s proto=%u",
                   pkt->port,
                   convertToIpAddressString(iph->dst_addr),
                   iph->next_proto_id);

        if (pkt->port == g_n6_port && g_nat_enabled) {
            int dnat_rc = nat_apply_dnat(iph);
            UTLT_Trace("DL NAT: rc=%d post-dnat dst=%s proto=%u",
                       dnat_rc,
                       convertToIpAddressString(iph->dst_addr),
                       iph->next_proto_id);
            if (dnat_rc < 0 && iph->dst_addr == g_nat_public_ip_be) {
                UTLT_Warning("NAT DNAT miss for public packet %s:%u",
                             convertToIpAddressString(iph->dst_addr),
                             nat_dst_port(iph));
                meta->action = ONVM_NF_ACTION_DROP;
                return 0;
            }
        }

        pdr = GetPdrByUeIpAddress(pkt, rte_cpu_to_be_32(iph->dst_addr));
        is_dl = true;
    }

    if (!pdr) {
        UTLT_Error("no PDR found for %s, skip\n", convertToIpAddressString(iph->dst_addr));
        meta->action = ONVM_NF_ACTION_DROP;
        return 0;
    }
    UTLT_Info("Got PDR ID is %u\n", pdr->pdrId);

    if (is_dl) {
        ue_key = rte_cpu_to_be_32(iph->dst_addr);
        if (!cal_pktlen_valid) {
            UTLT_Warning("Invalid DL IPv4/L4 length for UE %s, drop",
                         convertToIpAddressString(iph->dst_addr));
            meta->action = ONVM_NF_ACTION_DROP;
            return 0;
        }
        owner_session = UpfSessionFindByUeIP(ue_key);
        ue_idx = findIndexByUeIpAddress(ue_key);
        if (ue_idx < 0) {
            ue_idx = GetQerByUEIpAddressFromPdr(ue_key, owner_session, pdr,
                                                convertToIpAddressString(iph->dst_addr));
        }
        if (!upf_u_shaper_build_dl_flow_key(pkt, pdr, ue_key, pdr->has_fd,
                                            &dl_flow_key)) {
            UTLT_Error("Failed to build DL shaper flow key");
            meta->action = ONVM_NF_ACTION_DROP;
            return 0;
        }
    }

    rte_pktmbuf_adj(pkt, sizeof(struct rte_ether_hdr));

    UPDK_FAR *far;
    far = pdr->far;
    if (!far) {
        UTLT_Error("There is no FAR related to PDR[%u]\n", pdr->pdrId);
        meta->action = ONVM_NF_ACTION_DROP;
        return 0;
    }

    if (pdr->flags.outerHeaderRemoval) {
        switch (pdr->outerHeaderRemoval) {
            case OUTER_HEADER_REMOVAL_GTP_IP4: {
                rte_pktmbuf_adj(pkt, gtp_info.outer_hdr_len);
            } break;
            case OUTER_HEADER_REMOVAL_GTP_IP6:
            case OUTER_HEADER_REMOVAL_UDP_IP4:
            case OUTER_HEADER_REMOVAL_UDP_IP6:
            case OUTER_HEADER_REMOVAL_IP4:
            case OUTER_HEADER_REMOVAL_IP6:
            case OUTER_HEADER_REMOVAL_GTP:
            case OUTER_HEADER_REMOVAL_S_TAG:
            case OUTER_HEADER_REMOVAL_S_C_TAG:
            default:
                printf("unknown or not implement\n");
        }
    }

    if (is_dl) {
        /* ── DL: split BUFF vs FORW ─────────────────────────── */
        uint8_t far_action = far->applyAction & FAR_ACTION_MASK;
        struct onvm_nf *nf = nf_local_ctx->nf;
        int32_t sess_idx = pdr->session_index;

        /* DROP → just let the framework free the pkt */
        if (far_action == UPDK_FAR_APPLY_ACTION_DROP) {
            meta->action = ONVM_NF_ACTION_DROP;
            goto dl_nocp;
        }
         /* Validate session ring */
        if (sess_idx < 0 || sess_idx >= SESS_BUF_MAX_USERS) {
            meta->action = ONVM_NF_ACTION_DROP;
            goto dl_nocp;
        }
        UpfSessBuf *sb = &g_sess_buf[sess_idx];
        if (!sb->ring_created || !sb->ring) {
            meta->action = ONVM_NF_ACTION_DROP;
            goto dl_nocp;
        }

        /* Encap (GTP-U outer header) */
        if (far->flags.forwardingParameters &&
            far->forwardingParameters.flags.outerHeaderCreation) {
            UPDK_OuterHeaderCreation *ohc =
                &far->forwardingParameters.outerHeaderCreation;
            if (ohc->description ==
                UPDK_OUTER_HEADER_CREATION_DESCRIPTION_GTPU_UDP_IPV4)
                Encap(pkt, far, pdr->qer);
        }

        uint32_t gnb_n3_ip_be = g_nat_enabled 
            ? g_an_peer_n3_ip_be
            : far->forwardingParameters.outerHeaderCreation.ipv4.s_addr;
        UTLT_Trace("gNB N3 IP: %s\n", convertToIpAddressString(gnb_n3_ip_be));

        // Regardless of BUFF vs FORW, we need to attach L2 (or ARP) header
        // before sending to N3 port.
        if (attach_l2_or_arp(pkt, g_n3_port, g_n3_ip_be, gnb_n3_ip_be,
                            nf_local_ctx->nf) < 0) {
            meta->action = ONVM_NF_ACTION_DROP;   /* or buffer */
            return 0;
        }
        meta->destination = g_n3_port; // DL always goes to N3 port after FAR processing (may be modified by QoS policing below)

        if (far_action == UPDK_FAR_APPLY_ACTION_BUFF) {
            /* Buffer-only: prepare packet for later TX, enqueue, then DROP */
            sb->is_buffering = 1;

            /* Enqueue into session ring.
             * Bump refcnt so the framework's rte_pktmbuf_free (DROP below)
             * only decrements 2→1 — the ring holds the other reference. */
            rte_mbuf_refcnt_update(pkt, 1);
            if (rte_ring_sp_enqueue(sb->ring, pkt) != 0) {
                rte_mbuf_refcnt_update(pkt, -1);
                meta->action = ONVM_NF_ACTION_DROP;
                goto dl_nocp;
            }

            sb->touched = 1;
            meta->action = ONVM_NF_ACTION_DROP;
            goto dl_nocp;
        }

        /* QoS shaping — FORW only, after GTP-U/L2 TX prep is complete.
         * Over-token packets wait in bounded per-flow FIFOs; only red,
         * invalid, or queue-overflow packets drop. */
        if (far_action == UPDK_FAR_APPLY_ACTION_FORW) {
            if (ue_idx < 0) {
                UTLT_Error("No UE IP found in the table");
                meta->action = ONVM_NF_ACTION_DROP;
                goto dl_nocp;
            }

            int color_result = 0;
            bool isQos = false;
            uint64_t curr_time = rte_get_tsc_cycles();

            if (pdr->has_fd) {
                isQos = true;
                int ft_idx = ftSearch(pdr->meter_key);
                struct rte_meter_trtcm_profile *trtcm_profile;
                if (unlikely(ft_idx < 0 || ft_idx >= (int)APP_FLOWS_MAX)) {
                    UTLT_Warning("DL QoS: no trTCM flow for meter_key=%u (ft_idx=%d) pdr=%u seid=%lu; dropping",
                                 pdr->meter_key, ft_idx, pdr->pdrId, seid);
                    meta->flags = RTE_COLOR_RED;
                    meta->action = ONVM_NF_ACTION_DROP;
                    goto dl_nocp;
                }
                trtcm_profile = trtcmProfileForFlow(ft_idx);
                if (unlikely(trtcm_profile == NULL)) {
                    UTLT_Warning("DL QoS: no trTCM profile for meter_key=%u ft_idx=%d pdr=%u seid=%lu; dropping",
                                 pdr->meter_key, ft_idx, pdr->pdrId, seid);
                    meta->flags = RTE_COLOR_RED;
                    meta->action = ONVM_NF_ACTION_DROP;
                    goto dl_nocp;
                }
                color_result = trtcmColorHandle(cal_pktlen, curr_time,
                                                ft_idx, trtcm_profile);
                if (unlikely(color_result < 0)) {
                    meta->flags = RTE_COLOR_RED;
                    meta->action = ONVM_NF_ACTION_DROP;
                    goto dl_nocp;
                }
                // set the meta action to out for now, and trtcmPolicer will update it to drop if color is red
                meta->action = ONVM_NF_ACTION_OUT;
                if (trtcmPolicer(meta, color_result) > 0)
                    UTLT_Error("trTCM Policer error");
            }

            if (isQos) {
                if (meta->flags == RTE_COLOR_RED) {
                    upf_u_shaper_drop_red(meta);
                    goto dl_nocp;
                }
                if (meta->flags == RTE_COLOR_GREEN ||
                    meta->flags == RTE_COLOR_YELLOW) {
                    enum upf_u_shaper_pkt_color color =
                        (meta->flags == RTE_COLOR_GREEN) ?
                        UPF_U_SHAPER_COLOR_GREEN :
                        UPF_U_SHAPER_COLOR_YELLOW;
                    enum upf_u_shaper_decision decision =
                        upf_u_shaper_shape_or_enqueue(
                            ue_idx, &dl_flow_key, true, color, pkt,
                            cal_pktlen, meta);
                    if (decision != UPF_U_SHAPER_PASS)
                        goto dl_nocp;
                }
            } else {
                enum upf_u_shaper_decision decision =
                    upf_u_shaper_shape_or_enqueue(
                        ue_idx, &dl_flow_key, false,
                        UPF_U_SHAPER_COLOR_NQOS, pkt, cal_pktlen, meta);
                if (decision != UPF_U_SHAPER_PASS)
                    goto dl_nocp;
            }
        }

        /* Non-BUFF (typically FORW): drain any previously queued packets,
         * then forward the current packet immediately (no enqueue). */
        sb->is_buffering = 0;
        if (sb->touched)
            drain_session_batch(sess_idx, INLINE_DRAIN_BATCH, nf);

        meta->action = ONVM_NF_ACTION_OUT;

        goto dl_nocp;

    dl_nocp:
        if (far->applyAction & UPDK_FAR_APPLY_ACTION_NOCP) {
            Event *msg = (Event *)rte_calloc(NULL, 1, sizeof(Event), 0);
            msg->type = UPF_EVENT_SESSION_REPORT;
            msg->arg0 = seid;
            msg->arg1 = pdrId;
            UTLT_Debug("Send to upf-c, namely service id is 2\n");
            onvm_nflib_send_msg_to_nf(2, msg);
        } 
        return 0;
    } else {
        /* ── UL: original HandlePacketWithFar path (unchanged) ── */
        int status = HandlePacketWithFar(pkt, far, pdr->qer, g_n6_port, meta);

        /* Get Inner IPv4 header */
        struct rte_ipv4_hdr *inner_iph = rte_pktmbuf_mtod(pkt, struct rte_ipv4_hdr *);
        if (inner_iph == NULL) {
            UTLT_Warning("Inner packet is NULL, drop it\n");
            meta->action = ONVM_NF_ACTION_DROP;
            return 0;
        }

        if ((inner_iph->version_ihl >> 4) != 4) {
            UTLT_Warning("Inner packet is not IPv4, drop it\n");
            meta->action = ONVM_NF_ACTION_DROP;
            return 0;
        }

        if (g_nat_enabled && meta->action == ONVM_NF_ACTION_OUT) {
            char src_buf[16];
            char dst_buf[16];
            UTLT_Trace("UL ingress: port=%u src=%s dst=%s proto=%u",
                       pkt->port,
                       ipv4_to_buf(inner_iph->src_addr, src_buf),
                       ipv4_to_buf(inner_iph->dst_addr, dst_buf),
                       inner_iph->next_proto_id);
            if (nat_apply_snat(inner_iph) < 0) {
                meta->action = ONVM_NF_ACTION_DROP;
                return 0;
            }
            UTLT_Trace("UL NAT: post-snat src=%s dst=%s proto=%u",
                       ipv4_to_buf(inner_iph->src_addr, src_buf),
                       ipv4_to_buf(inner_iph->dst_addr, dst_buf),
                       inner_iph->next_proto_id);
        }

        if (meta->action == ONVM_NF_ACTION_OUT) {
            /* Get the DN server IP address */
            uint32_t dn_server_ip_be = inner_iph->dst_addr;
            UTLT_Trace("DN server IP: %s\n", convertToIpAddressString(dn_server_ip_be));

            /* UL QoS policing (flow-level): applies when CP provided SDF (has_fd)
             * and per-flow QER contains MBR/GBR. For UDP tests, you must check
             * server-side throughput/loss or use TCP to observe the cap. */
            if (pdr && pdr->has_fd && pdr->qer && pdr->qer->flags.maximumBitrate) {
                uint32_t dst_ip_host = rte_be_to_cpu_32(dn_server_ip_be);
                if (!pdr->has_fd_to || (dst_ip_host & pdr->fd_to_mask) == pdr->fd_to_net) {
                    int ft_idx = ftSearch(pdr->meter_key);
                    if (unlikely(ft_idx < 0 || ft_idx >= (int)APP_FLOWS_MAX)) {
                        UTLT_Warning("UL QoS: no trTCM flow for meter_key=%u (ft_idx=%d) pdr=%u seid=%lu; dropping",
                                    pdr->meter_key, ft_idx, pdr->pdrId, seid);
                        meta->flags = RTE_COLOR_RED;
                        meta->action = ONVM_NF_ACTION_DROP;
                        return 0;
                    }

                    uint64_t curr_time = rte_get_tsc_cycles();
                    struct rte_meter_trtcm_profile *trtcm_profile =
                        trtcmProfileForFlow(ft_idx);
                    if (unlikely(trtcm_profile == NULL)) {
                        UTLT_Warning("UL QoS: no trTCM profile for meter_key=%u ft_idx=%d pdr=%u seid=%lu; dropping",
                                    pdr->meter_key, ft_idx, pdr->pdrId, seid);
                        meta->flags = RTE_COLOR_RED;
                        meta->action = ONVM_NF_ACTION_DROP;
                        return 0;
                    }
                    int color_result = trtcmColorHandle(pkt->pkt_len, curr_time,
                                                        ft_idx, trtcm_profile);
                    if (unlikely(color_result < 0)) {
                        meta->flags = RTE_COLOR_RED;
                        meta->action = ONVM_NF_ACTION_DROP;
                        return 0;
                    }
                    if (trtcmPolicer(meta, color_result) > 0)
                        UTLT_Error("UL trTCM Policer error");

                    if (meta->action == ONVM_NF_ACTION_DROP)
                        return 0;
                }
            }

            /* Attach L2 (or ARP) header for the N6-bound packet */
            dn_server_ip_be = g_nat_enabled ? g_dn_peer_n6_ip_be : dn_server_ip_be;

            if (attach_l2_or_arp(pkt, g_n6_port, g_n6_ip_be, dn_server_ip_be,
                                nf_local_ctx->nf) < 0) {
                meta->action = ONVM_NF_ACTION_DROP;
                return 0;
            }
        }
        return status;
    }
}

void
msg_handler(void *msg_data, struct onvm_nf_local_ctx *nf_local_ctx) {

    Event *e = (Event *)msg_data;

    /* Our NF→NF control path: CP tells us to flip */
    if (e && (uint32_t)e->type == EVT_CLS_GC_REQ) {
        g_cls_local.pending_ver = (uint32_t)e->arg0;
        g_cls_local.flip_pending = 1;      // The actual flip happens at burst boundary

        // logging block

        UTLT_Info("EVT_CLS_GC_REQ: requested_ver=%u ctrl.active=%p ctrl.ver=%u",
          (uint32_t)e->arg0,
          (void*)(g_upf_cls_ctrl ? g_upf_cls_ctrl->active : NULL),
          (g_upf_cls_ctrl ? g_upf_cls_ctrl->version : 0));

        rte_free(e);
        return;
    }

    /* EVENT drain: CP tells us BUFF→FORW for a specific session */
    if (e && (uint32_t)e->type == UPF_EVENT_CLEAR_AND_DRAIN) {
        struct onvm_nf *nf = nf_local_ctx->nf;
        int sess_idx = (int)(uintptr_t)e->arg0;
        if (sess_idx >= 0 && sess_idx < SESS_BUF_MAX_USERS) {
            g_sess_buf[sess_idx].is_buffering = 0;
            uint32_t n = drain_session_batch(sess_idx, UINT32_MAX, nf);
            UTLT_Debug("EVENT drain: sess %d, sent %u pkts\n", sess_idx, n);
        }
        rte_free(e);
        return;
    }

    if (e) rte_free(e);
}

static uint64_t last_p = 0;

static int
callback_handler(struct onvm_nf_local_ctx *nf_local_ctx) {
    struct onvm_nf *nf;
    uint64_t cur_p;

    if (unlikely(nf_local_ctx == NULL || nf_local_ctx->nf == NULL))
        return 0;

    nf = nf_local_ctx->nf;
    if (unlikely(!last_p)) last_p = rte_get_tsc_cycles();
    cur_p = rte_get_tsc_cycles();

    upf_u_shaper_drain(nf);

    if (unlikely(cur_p - last_p > rte_get_timer_hz())) {
        last_p = cur_p;
        UTLT_Debug("Stats perform: ");
        UTLT_Debug("act out: %d", nf->stats.act_out);
        UTLT_Debug("buffered: %d", nf->stats.tx_buffer);
        upf_u_shaper_log_stats();
    }

    return 0;
}

int
main(int argc, char *argv[]) {
    int arg_offset;
    struct onvm_nf_local_ctx *nf_local_ctx;
    struct onvm_nf_function_table *nf_function_table;
    UTLT_SetLogLevel("warning"); // temporary default before config is loaded

    nf_local_ctx = onvm_nflib_init_nf_local_ctx();
    onvm_nflib_start_signal_handler(nf_local_ctx, NULL);
    nf_function_table = onvm_nflib_init_nf_function_table();
    nf_function_table->pkt_handler = &packet_handler;
    nf_function_table->msg_handler = &msg_handler;
    nf_function_table->user_actions = &callback_handler;

    if ((arg_offset = onvm_nflib_init(argc, argv, NF_TAG, nf_local_ctx, nf_function_table)) < 0) {
        onvm_nflib_stop(nf_local_ctx);
        if (arg_offset == ONVM_SIGNAL_TERMINATION) {
            printf("Exiting due to user termination\n");
            return 0;
        } else {
            rte_exit(EXIT_FAILURE, "Failed ONVM init\n");
        }
    }

    /* Initialize dynamic field offset */
    struct onvm_configuration *onvm_config = onvm_nflib_get_onvm_config();
    nf_local_ctx->nf->dynfield_offset = onvm_config->dynfield_offset;

    const char *config_path = "config/upf_u.yaml";

    if (argc > arg_offset + 1) {
        config_path = argv[arg_offset + 1];
    }

    printf("[UPF-U] Using config: %s\n", config_path);
    if (UpfU_LoadAndParseConfig(config_path) != 0) {
        rte_exit(EXIT_FAILURE, "Failed to load/parse UPF-U YAML config.\n");
    }

    UTLT_SetLogLevel(g_log_level);
    printf("[UPF-U] Log level: %s\n", g_log_level);

    if (UpfClsCtrlInit() < 0) {
        rte_exit(EXIT_FAILURE, "CLS_CTRL memzone init failed\n");
    }

    if (UpfSessBufInit() < 0) {
        rte_exit(EXIT_FAILURE, "SESS_BUF memzone init failed\n");
    }

    // Initialize L2 addresses, must be done after config is loaded (UpfU_LoadAndParseConfig)
    init_l2_addrs();

    // trTCM
    trtcmConfigFlowTables();
    initUeTable();
    ueHashInit();

    UpfSessionPoolInit();
    UeIpToUpfSessionMapInit();
    TeidToUpfSessionMapInit();

    /* ARP module init */
    if (upf_arp_init() < 0) {
        rte_exit(EXIT_FAILURE, "failed to init ARP module\n");
    }

    /* NAT module init (only if enabled in config) */
    if (g_nat_enabled) {
        nat_init();
    }

    if (upf_u_shaper_init(nf_local_ctx->nf) < 0) {
        rte_exit(EXIT_FAILURE, "Failed to init UPF-U shaper entry pool.\n");
    }

    onvm_nflib_run(nf_local_ctx);

    upf_u_shaper_cleanup();
    onvm_nflib_stop(nf_local_ctx);
    return 0;
}
