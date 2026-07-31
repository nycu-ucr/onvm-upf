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

#include "upf_context.h"
#include "upf_u_trtcm.h"
#include "utlt_debug.h"
#include "upf_u_config.h"

#include <stdint.h>
#include <string.h>

#include <rte_spinlock.h>

#include "../classifiers/classifier_wrapper.h"

#define MIN_TOKEN_BUCKET_DEPTH 2048
#define TOKEN_BUCKET_BURST_MS 100
#define TRTCM_BURST_MS 100

flow_entry_t iPFlows[APP_FLOWS_MAX];
uint32_t iPFlowsLen = 0;
uint32_t trTCMidx = 0;

struct rte_meter_trtcm_profile app_trtcm_profile;
struct rte_meter_trtcm_profile app_flow_trtcm_profiles[APP_FLOWS_MAX];
struct rte_meter_trtcm app_flows[APP_FLOWS_MAX];
static bool app_flow_has_gbr[APP_FLOWS_MAX];

static struct ue_hash_entry ue_hash[MAX_UE];
struct ue_tb ue_table[MAX_UE];
static rte_spinlock_t ue_table_lock;
static rte_spinlock_t ue_tb_locks[MAX_UE];

/* trTCM */
struct rte_meter_trtcm_params app_trtcm_params = {
	.cir = 125000,    // bytes per secs
	.pir = 625000,    // bytes per secs
	.cbs = 2048,
	.pbs = 2048
};

int
trtcmConfigFlowTables(void) {
    uint32_t i;
    int rtn;
    if (likely(app_flows[0].tc > 0))
        return 0;

    // config trtcm profile
    rtn = rte_meter_trtcm_profile_config(&app_trtcm_profile,
		&app_trtcm_params);
	if (rtn)
		return rtn;

    // config flow meters with trtcm profiles
    for (i = 0; i < APP_FLOWS_MAX; i++){
        app_flow_trtcm_profiles[i] = app_trtcm_profile;
        app_flow_has_gbr[i] = true;
        rtn = rte_meter_trtcm_config(&app_flows[i],
                                     &app_flow_trtcm_profiles[i]);
        if (rtn)
            return rtn;
    }

    UTLT_Info("Flow table configured.");
    return 0;
}

int
trtcmColorHandle(uint32_t pkt_len, uint64_t time, int flow_idx, struct rte_meter_trtcm_profile *target_profile) {
    uint8_t out_color = 0;
    // check configured flow
    if (unlikely(flow_idx < 0 || flow_idx >= (int)APP_FLOWS_MAX ||
                 target_profile == NULL)) {
        UTLT_Info("flow index/profile set err");
        return -1;
    }
    if (unlikely(target_profile->cir_period == 0)) {
        UTLT_Info("flow cir_period set err");
        return -1;
    }
    if (unlikely(target_profile->pir_period == 0)) {
        UTLT_Info("flow pir_period set err");
        return -1;
    }
    out_color = (uint8_t) rte_meter_trtcm_color_blind_check(&app_flows[flow_idx],
        target_profile,
        time,
        pkt_len);
    if (!app_flow_has_gbr[flow_idx] && out_color == RTE_COLOR_GREEN)
        out_color = RTE_COLOR_YELLOW;
    return out_color;
}

struct rte_meter_trtcm_profile *
trtcmProfileForFlow(int flow_idx) {
    if (unlikely(flow_idx < 0 || flow_idx >= (int)APP_FLOWS_MAX))
        return NULL;

    return &app_flow_trtcm_profiles[flow_idx];
}

int
trtcmPolicer(struct onvm_pkt_meta *meta, int color_result) {
    if (meta->action == ONVM_NF_ACTION_DROP) {
        meta->flags = RTE_COLOR_RED;
        UTLT_Info("TB not enough & traffic flow");
        return 0;
    }
    switch (color_result) {
        case RTE_COLOR_RED:
            UTLT_Info("\033[0;31mRED(%d)\033[0m, drop pkt", RTE_COLOR_RED);
            meta->flags = RTE_COLOR_RED;
            meta->action = ONVM_NF_ACTION_DROP;
            break;
        case RTE_COLOR_YELLOW:
            UTLT_Info("\033[0;32mYELLOW(%d)\033[0m, best effort pkt fwd", RTE_COLOR_YELLOW);
            meta->flags = RTE_COLOR_YELLOW;
	        meta->action = ONVM_NF_ACTION_OUT;
            break;
        case RTE_COLOR_GREEN:
            UTLT_Info("\033[0;33mGREEEN(%d)\033[0m, guaranted pkt fwd.", RTE_COLOR_GREEN);
            meta->flags = RTE_COLOR_GREEN;
            meta->action = ONVM_NF_ACTION_OUT;
            break;
        default:
            UTLT_Error("Unexpected trTCM color output.");
            return 1;
    }
    return 0;
}

// static inline source_interface_t
// PortToSourceInterface(uint16_t port) {
//     if (port == g_n3_port)  return SRC_IF_ACCESS;
//     if (port == g_n6_port)    return SRC_IF_CORE;
//     if (port == g_sgi_port)     return SRC_IF_SGI_LAN;
//     UTLT_Warning("PortToSourceInterface: unknown port %" PRIu16
//              " (N3=%" PRIu16 " N6=%" PRIu16 " SGI=%" PRIu16
//              ") — defaulting to ACCESS",
//              port, g_n3_port, g_n6_port, g_sgi_port);

//     return SRC_IF_ACCESS;
// }

static inline uint16_t
SourceInterfaceToPort(source_interface_t srcIf) {
    switch (srcIf) {
      case SRC_IF_ACCESS:   return g_n3_port;
      case SRC_IF_CORE:     return g_n6_port;
      case SRC_IF_SGI_LAN:  return g_sgi_port;
      case SRC_IF_CP_FUNC:
      case SRC_IF_LI_FUNC:
      default:
        return -1; // Invalid/unsupported source interface
    }
}

static inline int
hashFunc(uint32_t subnet) {
    return subnet % APP_FLOWS_MAX;
}

int
ftSearch(uint32_t subnet) {
    int index = hashFunc(subnet);
    int original_index = index;

    while (iPFlows[index].in_use) {
        if (iPFlows[index].subnet == subnet) {
            return iPFlows[index].flow_idx;
        }
        index = (index + 1) % APP_FLOWS_MAX;  // Linear Probing

        if (index == original_index) {
            break;
        }
    }

    return -1;  // Not found
}

static inline bool
ftAddEntry(uint32_t subnet, int flow_idx) {
    if (iPFlowsLen >= APP_FLOWS_MAX) {
        printf("Error: Maximum flow entries reached.\n");
        return false;
    }

    if (ftSearch(subnet) != -1) {
        printf("Error: Subnet %u already exists.\n", subnet);
        return false;
    }

    int index = hashFunc(subnet);
    while (iPFlows[index].in_use) {         // Linear Probing
        index = (index + 1) % APP_FLOWS_MAX;
    }

    // Insert the entry
    iPFlows[index].subnet = subnet;
    iPFlows[index].flow_idx = flow_idx;
    iPFlows[index].in_use = true;
    iPFlowsLen++;

    return true;
}

void
initUeTable() {
    rte_spinlock_init(&ue_table_lock);
    for (int i = 0; i < MAX_UE; i++) {
        uint64_t now = rte_get_tsc_cycles();

        rte_spinlock_init(&ue_tb_locks[i]);
        ue_table[i].ue_ip = 0;
        ue_table[i].ue_ambr = 0;
        ue_table[i].ue_gbr = 0;
        ue_table[i].ue_mbr = 0;

        ue_table[i].ue_green_tb_params.tb_rate = 0;
        ue_table[i].ue_green_tb_params.tb_depth = 0;
        ue_table[i].ue_green_tb_params.tb_tokens = 0;
        ue_table[i].ue_green_tb_params.last_cycle = now;
        ue_table[i].ue_green_tb_params.cur_cycles = now;

        ue_table[i].ue_excess_tb_params.tb_rate = 0;
        ue_table[i].ue_excess_tb_params.tb_depth = 0;
        ue_table[i].ue_excess_tb_params.tb_tokens = 0;
        ue_table[i].ue_excess_tb_params.last_cycle = now;
        ue_table[i].ue_excess_tb_params.cur_cycles = now;

        ue_table[i].ue_yellow_cap_tb_params.tb_rate = 0;
        ue_table[i].ue_yellow_cap_tb_params.tb_depth = 0;
        ue_table[i].ue_yellow_cap_tb_params.tb_tokens = 0;
        ue_table[i].ue_yellow_cap_tb_params.last_cycle = now;
        ue_table[i].ue_yellow_cap_tb_params.cur_cycles = now;
    }
}

static inline int
ueHashFunc(uint32_t ip) { return ip % MAX_UE; }

static inline bool
ueHashSlotInUse(int idx) {
    return __atomic_load_n(&ue_hash[idx].in_use, __ATOMIC_ACQUIRE);
}

static inline void
ueHashSetInUse(int idx, bool in_use) {
    __atomic_store_n(&ue_hash[idx].in_use, in_use, __ATOMIC_RELEASE);
}

static inline uint64_t
shaper_bucket_depth(uint32_t rate_kbps) {
    uint64_t depth_bytes;

    if (rate_kbps == 0)
        return 0;

    depth_bytes = ((uint64_t)rate_kbps * TOKEN_BUCKET_BURST_MS + 7) / 8;
    return depth_bytes < MIN_TOKEN_BUCKET_DEPTH ?
           MIN_TOKEN_BUCKET_DEPTH : depth_bytes;
}

static inline uint64_t
trtcm_bucket_depth(uint32_t rate_kbps) {
    uint64_t depth_bytes;

    if (rate_kbps == 0)
        return MIN_TOKEN_BUCKET_DEPTH;

    depth_bytes = ((uint64_t)rate_kbps * TRTCM_BURST_MS + 7) / 8;
    return depth_bytes < MIN_TOKEN_BUCKET_DEPTH ?
           MIN_TOKEN_BUCKET_DEPTH : depth_bytes;
}

static inline void
shaper_update_bucket_tokens(struct tb_config *tb, uint64_t cur_cycles) {
    uint64_t elapsed_cycles;
    uint64_t tokens_produced;
    __uint128_t produced;

    if (tb->tb_rate == 0 || tb->tb_depth == 0) {
        tb->tb_tokens = 0;
        tb->last_cycle = cur_cycles;
        return;
    }

    if (tb->tb_tokens >= tb->tb_depth) {
        tb->tb_tokens = tb->tb_depth;
        tb->last_cycle = cur_cycles;
        return;
    }

    elapsed_cycles = cur_cycles - tb->last_cycle;
    produced = ((__uint128_t)elapsed_cycles * tb->tb_rate * 125) /
               rte_get_tsc_hz();
    tokens_produced = produced > UINT64_MAX ? UINT64_MAX :
                      (uint64_t)produced;
    if (tokens_produced == 0)
        return;

    tb->tb_tokens += tokens_produced;
    if (tb->tb_tokens > tb->tb_depth)
        tb->tb_tokens = tb->tb_depth;
    tb->last_cycle = cur_cycles;
}

static inline bool
ueTokenIndexValid(int index) {
    return index > -1 && index < MAX_UE && ue_table[index].ue_ip != 0;
}

static inline void
updateTokenbyIndexLocked(int index, uint64_t cur_cycles) {
    shaper_update_bucket_tokens(&ue_table[index].ue_green_tb_params,
                                cur_cycles);
    shaper_update_bucket_tokens(&ue_table[index].ue_excess_tb_params,
                                cur_cycles);
    shaper_update_bucket_tokens(&ue_table[index].ue_yellow_cap_tb_params,
                                cur_cycles);
}

static inline void
initBucket(struct tb_config *tb, uint32_t rate, uint64_t now) {
    tb->tb_rate = rate;
    tb->tb_depth = shaper_bucket_depth(rate);
    tb->tb_tokens = tb->tb_depth;
    tb->last_cycle = now;
    tb->cur_cycles = now;
}

static inline bool
bucketCanFitPacket(const struct tb_config *tb, uint32_t pkt_len) {
    return tb->tb_depth > 0 && pkt_len <= tb->tb_depth;
}

void
ueHashInit(void) {
    for (int i = 0; i < MAX_UE; i++)
        ueHashSetInUse(i, false);
}

void
ConfigureQerFlows(const UPDK_PDR *pdr, bool is_uplink) {
    /* pdr->qer is the QFI-bearing (per-flow) QER selected by CP.
     * It carries the correct MBR/GBR for flow-level trTCM metering. */
    const UPDK_QER *qer = pdr ? pdr->qer : NULL;
    if (!qer || !qer->flags.maximumBitrate) return;

    bool has_fd = pdr->has_fd;

    /* Use the same key that the DL policing path uses for ftSearch().
     * pdr->meter_key was precomputed by UPF-C from the same port mapping,
     * so insert and lookup are always consistent. */
    uint32_t key = has_fd ? pdr->meter_key
                          : (uint32_t)SourceInterfaceToPort(pdr->pdi.sourceInterface);

    /* Only add on first miss — subsequent packets for the same key are a no-op */
    if (ftSearch(key) >= 0) return;
    if (unlikely(trTCMidx >= APP_FLOWS_MAX)) {
        UTLT_Warning("TRTCM flow table full; cannot add key %u", key);
        return;
    }

    UTLT_Info("QER ID: %u key: %u", qer->qerId, key);

    struct rte_meter_trtcm_params trtcm_params = app_trtcm_params;
    bool has_gbr = qer->flags.guaranteedBitrate;

    uint32_t mbr = is_uplink ? qer->maximumBitrate.ul : qer->maximumBitrate.dl;
    trtcm_params.pir = (uint64_t)mbr * 1000 / 8;
    trtcm_params.pbs = trtcm_bucket_depth(mbr);

    if (has_gbr) {
        uint32_t gbr = is_uplink ? qer->guaranteedBitrate.ul : qer->guaranteedBitrate.dl;
        trtcm_params.cir = (uint64_t)gbr * 1000 / 8;
        trtcm_params.cbs = trtcm_bucket_depth(gbr);
    } else {
        trtcm_params.cir = 1;
        trtcm_params.cbs = MIN_TOKEN_BUCKET_DEPTH;
    }

    int rtn = rte_meter_trtcm_profile_config(&app_flow_trtcm_profiles[trTCMidx],
                                             &trtcm_params);
    if (rtn) {
        UTLT_Warning("TRTCM profile config failed for key %u: %d", key, rtn);
        return;
    }
    rtn = rte_meter_trtcm_config(&app_flows[trTCMidx],
                                 &app_flow_trtcm_profiles[trTCMidx]);
    if (rtn) {
        UTLT_Warning("TRTCM flow config failed for key %u: %d", key, rtn);
        return;
    }
    app_flow_has_gbr[trTCMidx] = has_gbr;

    if (!ftAddEntry(key, trTCMidx)) {
        UTLT_Warning("FT add failed");
        return;
    }
    UTLT_Info("Successfully add %u(%d) %u", key, hashFunc(key), trTCMidx);

    if (is_uplink) {
        UTLT_Info("Find MBR (UL: %lu) in QERs", qer->maximumBitrate.ul);
        if (qer->flags.guaranteedBitrate)
            UTLT_Info("Find GBR (UL: %lu) in QERs", qer->guaranteedBitrate.ul);
    } else {
        UTLT_Info("Find MBR (DL: %lu) in QERs", qer->maximumBitrate.dl);
        if (qer->flags.guaranteedBitrate)
            UTLT_Info("Find GBR (DL: %lu) in QERs", qer->guaranteedBitrate.dl);
    }

    UTLT_Info("TRTCM params: %lu %lu %lu %lu\n",
              (unsigned long)trtcm_params.cir,
              (unsigned long)trtcm_params.pir,
              (unsigned long)trtcm_params.cbs,
              (unsigned long)trtcm_params.pbs);

    trTCMidx++;
}

/* Return ue_table index, or -1 */
static inline int
ueHashSearch(uint32_t ue_ip) {
    int idx = ueHashFunc(ue_ip);
    int start = idx;
    while (ueHashSlotInUse(idx)) {
        if (ue_hash[idx].ue_ip == ue_ip)
            return ue_hash[idx].ue_idx;
        idx = (idx + 1) % MAX_UE;
        if (idx == start) break;
    }
    return -1;
}

static inline bool
ueHashInsert(uint32_t ue_ip, int ue_idx) {
    if (ueHashSearch(ue_ip) >= 0) return false; /* already present */
    int idx = ueHashFunc(ue_ip);
    int start = idx;

    while (ueHashSlotInUse(idx)) {
        idx = (idx + 1) % MAX_UE;
        if (idx == start)
            return false;
    }
    ue_hash[idx].ue_ip  = ue_ip;
    ue_hash[idx].ue_idx = ue_idx;
    ueHashSetInUse(idx, true);
    return true;
}

/* Legacy wrapper — now O(1) via hash */
int
findIndexByUeIpAddress(uint32_t ue_ip) {
    return ueHashSearch(ue_ip);
}

int
addEntrybyUeIp(uint32_t ue_ip, uint32_t ue_ambr, uint32_t ue_gbr, uint32_t ue_mbr) {
    int added_idx = -1;
    int existing_idx;

    if (ue_ambr == 0) {
        UTLT_Warning("Reject UE %u shaper config with zero AMBR", ue_ip);
        return -1;
    }

    if (ue_gbr > ue_ambr)
        ue_gbr = ue_ambr;
    if (ue_mbr == 0 || ue_mbr > ue_ambr)
        ue_mbr = ue_ambr;
    if (ue_gbr > ue_mbr)
        ue_gbr = ue_mbr;

    rte_spinlock_lock(&ue_table_lock);
    existing_idx = ueHashSearch(ue_ip);
    if (existing_idx >= 0) {
        rte_spinlock_unlock(&ue_table_lock);
        return existing_idx;
    }

    for (int i = 0; i < MAX_UE; i++) {
        if (ue_table[i].ue_ip == 0) { // find unused
            uint64_t now = rte_get_tsc_cycles();
            uint32_t green_rate = ue_gbr;
            uint32_t excess_rate = ue_ambr > ue_gbr ?
                                   ue_ambr - ue_gbr : 0;
            uint32_t yellow_cap_rate = ue_mbr > ue_gbr ?
                                       ue_mbr - ue_gbr : 0;

            rte_spinlock_lock(&ue_tb_locks[i]);
            ue_table[i].ue_ambr = ue_ambr;
            ue_table[i].ue_gbr = ue_gbr;
            ue_table[i].ue_mbr = ue_mbr;

            initBucket(&ue_table[i].ue_green_tb_params, green_rate, now);
            initBucket(&ue_table[i].ue_excess_tb_params, excess_rate, now);
            initBucket(&ue_table[i].ue_yellow_cap_tb_params,
                       yellow_cap_rate, now);

            UTLT_Info("Green GFBR Rate: %u", green_rate);
            UTLT_Info("Shared Excess Rate: %u", excess_rate);
            UTLT_Info("Yellow Cap Rate: %u", yellow_cap_rate);

            ue_table[i].ue_ip = ue_ip;
            rte_spinlock_unlock(&ue_tb_locks[i]);
            if (ueHashInsert(ue_ip, i)) {
                added_idx = i;
            } else {
                rte_spinlock_lock(&ue_tb_locks[i]);
                memset(&ue_table[i], 0, sizeof(ue_table[i]));
                rte_spinlock_unlock(&ue_tb_locks[i]);
                added_idx = ueHashSearch(ue_ip);
            }
            break;
        }
    }
    rte_spinlock_unlock(&ue_table_lock);
    return added_idx;  // Return the allocated index, or -1 if table full
}

void
updateTokenbyIndex(int index) {
    uint64_t cur_cycles;

    if (unlikely(index < 0 || index >= MAX_UE)) {
        UTLT_Error("UE IP not found in the table");
        return;
    }

    rte_spinlock_lock(&ue_tb_locks[index]);
    if (ueTokenIndexValid(index)) {
        cur_cycles = rte_get_tsc_cycles();
        updateTokenbyIndexLocked(index, cur_cycles);
        rte_spinlock_unlock(&ue_tb_locks[index]);
        return;
    }
    rte_spinlock_unlock(&ue_tb_locks[index]);
    UTLT_Error("UE IP not found in the table");
}

bool
ueBucketCanFitPacket(int index, enum ue_bucket_class bucket_class, uint32_t pkt_len) {
    bool can_fit;

    if (unlikely(index < 0 || index >= MAX_UE))
        return false;

    rte_spinlock_lock(&ue_tb_locks[index]);
    if (unlikely(!ueTokenIndexValid(index))) {
        rte_spinlock_unlock(&ue_tb_locks[index]);
        return false;
    }

    switch (bucket_class) {
    case UE_BUCKET_GREEN:
        can_fit = bucketCanFitPacket(&ue_table[index].ue_green_tb_params,
                                     pkt_len);
        break;
    case UE_BUCKET_YELLOW:
        can_fit = bucketCanFitPacket(&ue_table[index].ue_excess_tb_params,
                                     pkt_len) &&
                  bucketCanFitPacket(&ue_table[index].ue_yellow_cap_tb_params,
                                     pkt_len);
        break;
    case UE_BUCKET_NQOS:
        can_fit = bucketCanFitPacket(&ue_table[index].ue_excess_tb_params,
                                     pkt_len);
        break;
    default:
        can_fit = false;
        break;
    }
    rte_spinlock_unlock(&ue_tb_locks[index]);
    return can_fit;
}

bool
consumeUeBucketTokens(int index, enum ue_bucket_class bucket_class, uint32_t pkt_len) {
    struct tb_config *green_tb;
    struct tb_config *excess_tb;
    struct tb_config *yellow_cap_tb;
    bool consumed = false;

    if (unlikely(index < 0 || index >= MAX_UE))
        return false;

    rte_spinlock_lock(&ue_tb_locks[index]);
    if (unlikely(!ueTokenIndexValid(index))) {
        rte_spinlock_unlock(&ue_tb_locks[index]);
        return false;
    }

    updateTokenbyIndexLocked(index, rte_get_tsc_cycles());

    green_tb = &ue_table[index].ue_green_tb_params;
    excess_tb = &ue_table[index].ue_excess_tb_params;
    yellow_cap_tb = &ue_table[index].ue_yellow_cap_tb_params;

    switch (bucket_class) {
    case UE_BUCKET_GREEN:
        if (green_tb->tb_tokens >= pkt_len) {
            green_tb->tb_tokens -= pkt_len;
            consumed = true;
        }
        break;
    case UE_BUCKET_YELLOW:
        if (excess_tb->tb_tokens >= pkt_len &&
            yellow_cap_tb->tb_tokens >= pkt_len) {
            excess_tb->tb_tokens -= pkt_len;
            yellow_cap_tb->tb_tokens -= pkt_len;
            consumed = true;
        }
        break;
    case UE_BUCKET_NQOS:
        if (excess_tb->tb_tokens >= pkt_len) {
            excess_tb->tb_tokens -= pkt_len;
            consumed = true;
        }
        break;
    default:
        break;
    }

    rte_spinlock_unlock(&ue_tb_locks[index]);
    return consumed;
}
