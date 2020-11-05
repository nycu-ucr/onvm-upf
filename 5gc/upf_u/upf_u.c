/*********************************************************************
 *                     openNetVM
 *              https://sdnfv.github.io
 *
 *   BSD LICENSE
 *
 *   Copyright(c)
 *            2015-2019 George Washington University
 *            2015-2019 University of California Riverside
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

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <rte_common.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <unistd.h>

#include "5gc/gtp.h"
#include "5gc/upf.h"
#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"

#define NF_TAG "upf_u"

#define SELF_IP 0

upf_pdr_t *GetPdrByUeIpAddress(struct rte_mbuf *pkt, uint32_t addr) {
  return NULL;
}

upf_pdr_t *GetPdrByTeid(struct rte_mbuf *pkt, uint32_t td) {
  UpfSession *session = UpfSessionFindBySeid(td);
  if (!session) {
    return NULL;
  }
  int i = 0;
  for (i = 0; i < MAX_PDR_RULE; i++) {
    if (session->pdr_list[i].active == 1) {
      return &session->pdr_list[i];
    }
  }
  return NULL;
}

upf_far_t *GetFarById(uint16_t id) { return NULL; }

static int packet_handler(
    __attribute__((unused)) struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
    __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
  meta->action = ONVM_NF_ACTION_DROP;

  struct rte_ipv4_hdr *iph = onvm_pkt_ipv4_hdr(pkt);
  struct rte_udp_hdr *udp_header = onvm_pkt_udp_hdr(pkt);

  if (!iph) {
    printf("IP header null\n");
    iph = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *, 16);
  }

  if (!iph) {
    printf("IP header null\n");
    return 0;
  } else {
    onvm_pkt_print_ipv4(iph);
  }

  upf_pdr_t *pdr;

  // Step 1: Identify if it is a uplink packet or downlink packet
  if (iph->dst_addr == SELF_IP) {  //
    // invariant(dst_port == GTPV1_PORT);
    // Step 2: Get PDR rule
    pdr = GetPdrByUeIpAddress(pkt, iph->dst_addr);
  } else {
    // extract TEID from
    // Step 2: Get PDR rule
    uint32_t teid = get_teid_gtp_packet(pkt, udp_header, meta);
    printf("TEID %u\n", teid);
    pdr = GetPdrByTeid(pkt, teid);
  }

  if (!pdr) {
    printf("no PDR found for %pI4, skip\n", &iph->dst_addr);
    // TODO(vivek): what to do?
    return 0;
  }

  upf_far_t *far;
  far = pdr->far;

  if (!far) {
    printf("There is no FAR related to PDR[%u]\n", pdr->id);
    meta->action = ONVM_NF_ACTION_DROP;
    return 0;
  }

  // TODO(vivek): implement the removal policy
  switch (pdr->outer_header_removal) {
    case OUTER_HEADER_REMOVAL_GTP_IP4: {
      printf("Removing GTP Header\n");
      const int outer_hdr_len = sizeof(struct rte_ether_hdr) +
                                sizeof(struct rte_ipv4_hdr) +
                                sizeof(struct rte_udp_hdr) + sizeof(gtpv1_t);
      rte_pktmbuf_adj(pkt, (uint16_t)outer_hdr_len);

      // Prepend ethernet header
      struct rte_ether_hdr *eth_hdr =
          (struct rte_ether_hdr *)rte_pktmbuf_prepend(
              pkt, (uint16_t)sizeof(struct rte_ether_hdr));

      eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
      int j = 0;
      for (j = 0; j < RTE_ETHER_ADDR_LEN; ++j) {
        eth_hdr->d_addr.addr_bytes[j] = j;
      }
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
      printf("unknown\n");
  }

  if (far) {
    switch (far->apply_action) {
      case FAR_DROP:
        printf("Dropping the packet based on PDR\n");
        break;
      case FAR_FORWARD:
        printf("Forwarding the packet based on PDR\n");
        // TODO(vivek): Implement forward policy
        break;
      case FAR_BUFFER:
      // TODO(vivek): Implement buffering policy
      case FAR_NOTIFY_CP:
      // TODO(vivek): Implement notify CP policy
      case FAR_DUPLICATE:
      // TODO(vivek): Implement duplicate policy
      default:
        printf("Unspec apply action[%u] in FAR[%u] and related to PDR[%u]",
               far->apply_action, far->id, pdr->id);
    }
  }

  return 0;
}

int main(int argc, char *argv[]) {
  int arg_offset;
  struct onvm_nf_local_ctx *nf_local_ctx;
  struct onvm_nf_function_table *nf_function_table;

  nf_local_ctx = onvm_nflib_init_nf_local_ctx();
  onvm_nflib_start_signal_handler(nf_local_ctx, NULL);

  nf_function_table = onvm_nflib_init_nf_function_table();
  nf_function_table->pkt_handler = &packet_handler;

  if ((arg_offset = onvm_nflib_init(argc, argv, NF_TAG, nf_local_ctx,
                                    nf_function_table)) < 0) {
    onvm_nflib_stop(nf_local_ctx);
    if (arg_offset == ONVM_SIGNAL_TERMINATION) {
      printf("Exiting due to user termination\n");
      return 0;
    } else {
      rte_exit(EXIT_FAILURE, "Failed ONVM init\n");
    }
  }

  argc -= arg_offset;
  argv += arg_offset;

  PfcpSessionTableNFInit();

  onvm_nflib_run(nf_local_ctx);

  onvm_nflib_stop(nf_local_ctx);
  printf("If we reach here, program is ending\n");
  return 0;
}
