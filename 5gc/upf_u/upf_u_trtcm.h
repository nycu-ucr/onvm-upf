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

#ifndef UPF_U_TRTCM_H
#define UPF_U_TRTCM_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include <rte_meter.h>

#include "onvm_nflib.h"

#define APP_FLOWS_MAX 256
#define MAX_UE 256 // Max number of UEs

/* Flow Separation*/
struct flow_entry {
    uint32_t subnet;  // (Network & Mask_bits)
    int flow_idx;     // maps to trTCM flows table
    bool in_use;      // to track if the slot is occupied
} typedef flow_entry_t;

/* ── UE-IP → ue_table index hash (O(1) avg, replaces linear scan) ── */
struct ue_hash_entry {
    uint32_t ue_ip;
    int      ue_idx;   /* index into ue_table[] */
    bool     in_use;
};

/* Token Bucket */
struct tb_config {
    uint64_t tb_rate;    // token generation rate in Kbps
    uint64_t tb_depth;   // depth of the token bucket (in bytes)
    uint64_t tb_tokens;  // number of the tokens in the bucket at any given time (in bytes)
    uint64_t last_cycle;
    uint64_t cur_cycles;
    uint16_t used;
};

enum ue_bucket_class {
    UE_BUCKET_GREEN = 0,
    UE_BUCKET_YELLOW,
    UE_BUCKET_NQOS,
    UE_BUCKET_COUNT
};

struct ue_tb {
    uint32_t ue_ip;
    uint32_t ue_ambr;
    uint32_t ue_gbr;
    uint32_t ue_mbr;
    struct tb_config ue_green_tb_params;
    struct tb_config ue_excess_tb_params;
    struct tb_config ue_yellow_cap_tb_params;
};

extern flow_entry_t iPFlows[APP_FLOWS_MAX];
extern uint32_t iPFlowsLen;
extern uint32_t trTCMidx;

extern struct rte_meter_trtcm_profile app_trtcm_profile;
extern struct rte_meter_trtcm_profile app_flow_trtcm_profiles[APP_FLOWS_MAX];
extern struct rte_meter_trtcm app_flows[APP_FLOWS_MAX];

extern struct rte_meter_trtcm_params app_trtcm_params;

extern struct ue_tb ue_table[MAX_UE];

int
trtcmConfigFlowTables(void);

int
trtcmColorHandle(uint32_t pkt_len, uint64_t time, int flow_idx, struct rte_meter_trtcm_profile *target_profile);

struct rte_meter_trtcm_profile *
trtcmProfileForFlow(int flow_idx);

int
trtcmPolicer(struct onvm_pkt_meta *meta, int color_result);

void
initUeTable();

void
ueHashInit(void);

void
ConfigureQerFlows(const UPDK_PDR *pdr, bool is_uplink);

int
ftSearch(uint32_t subnet);

int
findIndexByUeIpAddress(uint32_t ue_ip);

void
updateTokenbyIndex(int index);

bool
ueBucketCanFitPacket(int index, enum ue_bucket_class bucket_class, uint32_t pkt_len);

bool
consumeUeBucketTokens(int index, enum ue_bucket_class bucket_class, uint32_t pkt_len);

int
addEntrybyUeIp(uint32_t ue_ip, uint32_t ue_ambr, uint32_t ue_gbr, uint32_t ue_mbr);

#endif
