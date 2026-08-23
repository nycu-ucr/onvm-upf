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

#ifndef UPF_U_ARP_H
#define UPF_U_ARP_H

#include <stdint.h>
#include <rte_arp.h>
#include <rte_ether.h>
#include <rte_mbuf.h>

#include "onvm_nflib.h"

#define NEIGH_MAX 64

enum neigh_state {
    NEIGH_EMPTY = 0,
    NEIGH_INCOMPLETE,
    NEIGH_REACHABLE,
    NEIGH_STALE,
};

struct neigh_entry {
    uint32_t ip_be;                 /* next-hop IP, network byte order */
    uint16_t port_id;               /* egress port */
    struct rte_ether_addr mac;
    uint64_t last_update_tsc;
    uint8_t state;
    uint8_t in_use;
};

int
upf_arp_init(void);

int
handle_arp_packet(struct rte_mbuf *pkt,
                  struct onvm_pkt_meta *meta,
                  struct onvm_nf_local_ctx *ctx);

int
attach_l2_or_arp(struct rte_mbuf *pkt,
                 uint16_t out_port,
                 uint32_t local_ip_be,
                 uint32_t next_hop_ip_be,
                 struct onvm_nf *nf);

#endif