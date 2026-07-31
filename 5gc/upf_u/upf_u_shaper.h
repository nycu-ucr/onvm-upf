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

#ifndef UPF_U_SHAPER_H
#define UPF_U_SHAPER_H

#include <stdbool.h>
#include <stdint.h>

#include <rte_ip.h>
#include <rte_mbuf.h>

#include "onvm_nflib.h"
#include "upf_context.h"

enum upf_u_shaper_decision {
    UPF_U_SHAPER_PASS = 0,
    UPF_U_SHAPER_QUEUED,
    UPF_U_SHAPER_DROP
};

enum upf_u_shaper_pkt_color {
    UPF_U_SHAPER_COLOR_NQOS = 0,
    UPF_U_SHAPER_COLOR_GREEN,
    UPF_U_SHAPER_COLOR_YELLOW
};

struct upf_u_shaper_flow_key {
    uint32_t ue_ip;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;
    uint8_t qfi;
    uint8_t is_qos;
};

int
upf_u_shaper_init(struct onvm_nf *nf);

void
upf_u_shaper_cleanup(void);

bool
upf_u_shaper_build_dl_flow_key(struct rte_mbuf *pkt, const UPDK_PDR *pdr,
                               uint32_t ue_ip, bool is_qos,
                               struct upf_u_shaper_flow_key *key);

bool
upf_u_shaper_dl_packet_len(struct rte_mbuf *pkt,
                           const struct rte_ipv4_hdr *iph,
                           uint32_t *metered_len);

enum upf_u_shaper_decision
upf_u_shaper_shape_or_enqueue(int ue_idx,
                              const struct upf_u_shaper_flow_key *key,
                              bool is_qos,
                              enum upf_u_shaper_pkt_color color,
                              struct rte_mbuf *pkt, uint32_t pkt_len,
                              struct onvm_pkt_meta *meta);

void
upf_u_shaper_drop_red(struct onvm_pkt_meta *meta);

uint32_t
upf_u_shaper_drain(struct onvm_nf *nf);

void
upf_u_shaper_log_stats(void);

#endif
