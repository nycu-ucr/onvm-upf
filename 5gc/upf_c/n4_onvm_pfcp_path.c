/*
# Copyright 2025 University of California, Riverside and National Yang Ming Chiao Tung University
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

#include "n4_onvm_pfcp_path.h"

#include <errno.h>
#include "utlt_buff.h"
#include "utlt_debug.h"
#include "pfcp_path.h"
#include "pfcp_message.h"
#include "pfcp_types.h"
#include "pfcp_xact.h"

#include "upf_events.h"
#include "upf_context.h"
#include "upf_cls_ctrl.h"

#include "n4_dispatcher.h"

#include "n4_onvm_pfcp_handler.h"

#define ETHER_IP_UDP_HDR_LEN \
  (RTE_ETHER_HDR_LEN + 20 + sizeof(struct rte_udp_hdr))

// UpfClsOnAckFree is defined in n4_onvm_pfcp_handler.c
extern void UpfClsOnAckFree(uint32_t ver);

void
msg_handler(void *msg_data, struct onvm_nf_local_ctx *nf_local_ctx) {
    //struct ReportMsg *msg = (struct ReportMsg *) msg_data;
    Event *msg = (Event *)msg_data;
    if (!msg) {
        UTLT_Error("received msg is NULL");
        return;
    }

    switch ((uint32_t)msg->type) {

        case EVT_CLS_GC_ACK: {
            uint32_t ver = (uint32_t)msg->arg0;
            UpfClsOnAckFree(ver);    /* frees retired snapshot if version matches */
            //rte_free(msg);           /* receiver frees Event on success */
            return;
        }
        default:
            break;
    }



    Event event;

    event.type = msg->type;
    event.arg0 = msg->arg0;
    event.arg1 = msg->arg1;
    event.arg2 = msg->arg2;
    event.arg3 = msg->arg3;
    event.arg4 = msg->arg4;

    //event.type = UPF_EVENT_SESSION_REPORT;
    //event.arg0 = msg->seid;
    //event.arg1 = msg->pdrId;

    UpfDispatcher(&event);

}

int packet_handler(
    struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
    __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
    if (pkt == NULL && meta == NULL){
        return 0;
    }

    meta->action = ONVM_NF_ACTION_DROP;

    PfcpHeader *pfcpHeader = NULL;
    uint32_t outerHeader = ETHER_IP_UDP_HDR_LEN;

    pfcpHeader = (PfcpHeader *)rte_pktmbuf_mtod_offset(pkt, PfcpHeader *, outerHeader);
    pfcpHeader->length = ntohs(pfcpHeader->length);

    if (pfcpHeader->version > PFCP_VERSION) {
        unsigned char vFail[8];
        PfcpHeader *pfcpOut = (PfcpHeader *)vFail;

        UTLT_Info("Unsupported PFCP version: %d", pfcpHeader->version);
        pfcpOut->flags = (PFCP_VERSION << 5);
        pfcpOut->type = PFCP_VERSION_NOT_SUPPORTED_RESPONSE;
        pfcpOut->length = htons(4);
        pfcpOut->sqn_only = pfcpHeader->sqn_only;
        // TODO(vivek): Send to back to SMF
        // SockSendTo(sock, vFail, 8);
        printf("Unsupported PFCP version: %d", pfcpHeader->version);
        return 0;
    }

    struct rte_ipv4_hdr * iph;
    iph = (struct rte_ipv4_hdr *) rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    
    // struct rte_udp_hdr *udp_h = (struct rte_udp_hdr *)rte_pktmbuf_mtod(pkt, uint8_t *) + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr);
    // printf("Src: (%d:%d)\tDst: (%d:%d)\n", iph->src_addr, udp_h->src_port, iph->dst_addr, udp_h->dst_port);

    SockAddr from;
    memset(&from, 0, sizeof(from));
    from.s4.sin_family = AF_INET;
    from.s4.sin_addr.s_addr = rte_le_to_cpu_32(iph->src_addr);
    from.s4.sin_port = rte_be_to_cpu_16(8805);

    PfcpNode *upf = NULL;
    Sock *sock;
    upf = PfcpFindNodeSockAddr(&Self()->upfN4List, &from);
    if (!upf) {
        PfcpFSeid fSeid;
        memset(&fSeid, 0, sizeof(fSeid));
        // IPv4
        if (from._family == AF_INET) {
            fSeid.v4 = 1;
            //fSeid.seid = 0; // TOOD: check SEID value
            fSeid.addr4 = from.s4.sin_addr;

            // TODO: check noIpv4, noIpv6, preferIpv4, originally from context.no_ipv4
            upf = PfcpAddNodeWithSeid(&Self()->upfN4List, &fSeid,
                    Self()->pfcpPort, 0, 1, 1);
            if (!upf) {
                // if upf == NULL (allocate error)
                // Count size of upfN4List
                int numOfUpf = 0;
                PfcpNode *n4Node , *nextNode = NULL;

                ListForEachSafe(n4Node, nextNode, &Self()->upfN4List) {
                    ++numOfUpf;
                }

                UTLT_Error("PFCP Node allocate error, "
                            "there may be too many SMF: %d", numOfUpf);
                return 0;
            }

            upf->sock = Self()->pfcpSock;
        }
        upf->sock = Self()->pfcpSock;
	    memcpy(&(upf->sock->remoteAddr), &from, sizeof(from));
    }

    Event event;
    Status status;
    Bufblk *bufBlk = NULL;
    uint32_t pfcpPayloadLen = pkt->pkt_len - outerHeader;
    bufBlk = BufblkAlloc(1, pfcpPayloadLen);
    if (bufBlk == NULL) {
        return 0;
    }
    memcpy(bufBlk->buf, pfcpHeader, pfcpPayloadLen);
    bufBlk->len = pfcpPayloadLen;

    event.type = UPF_EVENT_N4_MESSAGE;
    event.arg0 = (uintptr_t)bufBlk;
    event.arg1 = (uintptr_t)upf;

    UpfDispatcher(&event);

    return 0;
}

static int _pfcpReceiveCB(Sock *sock, void *data) {}

Status PfcpServerInit() {
    Status status;
    status = PfcpServerList(&Self()->pfcpIPList, _pfcpReceiveCB, Self()->epfd);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
                "Create PFCP Server for IPv4 error");

    if (&Self()->pfcpIPList != NULL) {
        Self()->pfcpSock = PfcpLocalSockFirst(&Self()->pfcpIPList);
    }
    if (&Self()->pfcpIPList != NULL) {
        Self()->pfcpAddr = PfcpLocalAddrFirst(&Self()->pfcpIPList);
    }
    UTLT_Assert(Self()->pfcpAddr || Self()->pfcpAddr6, return STATUS_ERROR, "No PFCP Server");

    return STATUS_OK;
}

Status PfcpServerTerminate() {
    SockListFree(&Self()->pfcpIPList);
    return STATUS_OK;
}
