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

#ifndef UPF_U_CONFIG_H
#define UPF_U_CONFIG_H

#include <stdint.h>
#include <rte_ether.h>

extern uint32_t g_n3_ip_be;     // UPF local IP on the access-facing port
extern uint32_t g_n6_ip_be;     // UPF local IP on the core/SGi-facing port

extern uint32_t g_an_peer_n3_ip_be;  // Next-hop IP of the AN/gNB peer
extern uint32_t g_dn_peer_n6_ip_be;  // Next-hop IP of the DN/upstream router peer

extern uint16_t  g_n3_port;      // UPF-U DPDK port connected to the access side (AN/gNB)
extern uint16_t  g_n6_port;      // UPF-U DPDK port connected to the core side (SGi)
extern uint16_t  g_sgi_port;     // UPF-U DPDK port connected to the SGi side

extern struct rte_ether_addr g_cn_ue_eth;  // Ethernet address for access-facing side of UPF (used when sending to UE)
extern struct rte_ether_addr g_cn_dn_eth;  // Ethernet address for core-facing side of UPF (used when sending to DN)

extern char g_log_level[16]; // Log level for UPF-U (e.g., "trace", "debug", "info", "warning", "error")

int
UpfU_LoadAndParseConfig(const char *path);

void
init_l2_addrs(void);

#endif