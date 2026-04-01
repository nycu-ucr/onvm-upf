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

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <time.h>
#include <unistd.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_gtp.h>
#include <rte_ip.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_meter.h>

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

#include "upf_u_config.h"

#define NF_TAG "upf_u"

// #if 0
// #define SELF_IP RTE_IPV4(10, 100, 200, 3)
// #else
// #define SELF_IP 33622538  // 10.10.1.2

// #endif

// #define SRC_INTF_ACCESS 0
// #define SRC_INTF_CORE 1
// #define SRC_INTF_SGI_LAN 2
// #define SRC_INTF_CP 3
// #define SRC_INTF_NUM (SRC_INTF_CP + 1)
#define FIX_BUFFER
#define DEFAULT_TB_RATE 10         // (Mbps)
#define DEFAULT_TB_DEPTH 10000  // Max proceed length
#define DEFAULT_TB_TOKENS 10000
#define APP_FLOWS_MAX 256
#define IP_MASKED(BIGENDIINT, LEN) (BIGENDIINT & (0xFFFFFFFF << (32-LEN)))
#define MAX_UE 256 // Max number of UEs
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#define INLINE_DRAIN_BATCH       8    /* pkts drained per INLINE (FORW)  */
#define DRAIN_CHUNK             64    /* max pkts dequeued per drain call */

/* mask for 20-bit IPv6 flow label */
#ifndef IPV6_FLOWLABEL_MASK
#define IPV6_FLOWLABEL_MASK 0x000FFFFFu
#endif


static inline int UpfSendEvt1(uint16_t dest_sid, uint32_t type, uintptr_t a0) {
    Event *e = (Event *)rte_calloc("upf_evt", 1, sizeof(*e), 0);
    if (!e) return -1;
    e->type = (uintptr_t)type;
    e->argc = 1;
    e->arg0 = a0;
    int rc = onvm_nflib_send_msg_to_nf(dest_sid, e);
    if (rc < 0) rte_free(e);
    return rc;
}

static struct rte_ether_addr dn_eth;
static struct rte_ether_addr an_eth;
static struct rte_ether_addr cn_dn_eth;
static struct rte_ether_addr cn_ue_eth;

uint8_t DnMac[RTE_ETHER_ADDR_LEN];
uint8_t AnMac[RTE_ETHER_ADDR_LEN];
int SELF_IP;

enum { IF_UNKNOWN = -1 };

int16_t g_access_port = 0;
int16_t g_core_port   = 0;
int16_t g_sgi_port    = 0;


struct rte_meter_trtcm_profile app_trtcm_profile;
struct rte_meter_trtcm_profile app_flow_trtcm_profile;
struct rte_meter_trtcm app_flows[APP_FLOWS_MAX];

/* trTCM */
struct rte_meter_trtcm_params app_trtcm_params = {
	.cir = 125000,    // bytes per secs
	.pir = 625000,    // bytes per secs
	.cbs = 2048,
	.pbs = 2048
};


/* Flow Separation*/
struct flow_entry {
    uint32_t subnet;  // (Network & Mask_bits)
    int flow_idx;     // maps to trTCM flows table
    bool in_use;      // to track if the slot is occupied
}typedef flow_entry_t;

flow_entry_t iPFlows[APP_FLOWS_MAX];
uint32_t iPFlowsLen = 0;
uint32_t trTCMidx = 0;


typedef struct {
    void    *ptr;          // current active snapshot (cls_handle_t*)
    uint32_t ver;          // last applied version
    uint32_t pending_ver;  // version announced by UPF-C via REQ
    uint8_t  flip_pending; // 1 when a flip is requested; cleared after flip
} upf_cls_local_t;

static upf_cls_local_t g_cls_local = {0};

// Flip to the latest published snapshot (called at burst boundary)
static inline void UpfClsMaybeFlipAndAck(void) {
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


/* static inline const UPDK_PDR *UpfLookupPdr(const ps_packet_t *key) {
    const cls_handle_t *snap = (const cls_handle_t *)g_cls_local.ptr;
    if (unlikely(!snap)) return NULL;

    uint32_t  precedence = 0;
    uintptr_t cookie     = 0;
    int hit = cls_classify_packet((cls_handle_t *)snap, key, &precedence, &cookie);
    if (!hit) return NULL;

    return (const UPDK_PDR *)cookie;
} */

static inline uint16_t UpfClassifyGetPdrId(const ps_packet_t *key) {
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

static inline const UPDK_PDR *UpfClassifyGetPdrPtr(const ps_packet_t *key) {
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



bool ftAddEntry(uint32_t subnet, int flow_idx) {
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

const char *ip4(uint32_t host_ip) {
    static char buf[16];
    struct in_addr a = { .s_addr = htonl(host_ip) };
    return inet_ntop(AF_INET, &a, buf, sizeof(buf)) ? buf : "<err>";
}

uint32_t charStr2MaskedIP(char *str, uint32_t *prefix_val){
    char ip_str[INET_ADDRSTRLEN];
    uint32_t prefix_len, subnet;

    sscanf(str, "%[^/]/%d", ip_str, &prefix_len);
    struct in_addr ip_addr;
    inet_pton(AF_INET, ip_str, &ip_addr);

    if (prefix_val) *prefix_val = prefix_len;
    return IP_MASKED(ip_addr.s_addr, prefix_len);
}

static inline int SourceInterfaceToPort(source_interface_t srcIf) {
    switch (srcIf) {
      case SRC_IF_ACCESS:   return g_access_port;
      case SRC_IF_CORE:     return g_core_port;
      case SRC_IF_SGI_LAN:  return g_sgi_port;
      case SRC_IF_CP_FUNC:
      case SRC_IF_LI_FUNC:
      default:
        return IF_UNKNOWN;
    }
}

static inline void
ConfigureQerFlows(const UPDK_PDR *pdr, bool is_uplink)
{
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

    UTLT_Info("QER ID: %u key: %u", qer->qerId, key);

    struct rte_meter_trtcm_params trtcm_params = app_trtcm_params;

    uint32_t mbr = is_uplink ? qer->maximumBitrate.ul : qer->maximumBitrate.dl;
    trtcm_params.pir = mbr * 1000 / 8;

    if (qer->flags.guaranteedBitrate) {
        uint32_t gbr = is_uplink ? qer->guaranteedBitrate.ul : qer->guaranteedBitrate.dl;
        trtcm_params.cir = gbr * 1000 / 8;
    } else {
        trtcm_params.cir = is_uplink ? 0 : 1;
    }

    if (!ftAddEntry(key, trTCMidx)) {
        UTLT_Warning("FT add failed");
    }
    UTLT_Info("Successfully add %u(%d) %u", key, hashFunc(key), trTCMidx);

    // Match config profile to what color-check later uses:
    // DL + SDF present → app_flow_trtcm_profile; else app_trtcm_profile
    if (!is_uplink && has_fd) {
        rte_meter_trtcm_profile_config(&app_flow_trtcm_profile, &trtcm_params);
        rte_meter_trtcm_config(&app_flows[trTCMidx], &app_flow_trtcm_profile);
    } else {
        rte_meter_trtcm_profile_config(&app_trtcm_profile, &trtcm_params);
        rte_meter_trtcm_config(&app_flows[trTCMidx], &app_trtcm_profile);
    }

    if (is_uplink) {
        UTLT_Info("Find MBR (UL: %lu) in QERs", qer->maximumBitrate.ul);
        if (qer->flags.guaranteedBitrate)
            UTLT_Info("Find GBR (UL: %lu) in QERs", qer->guaranteedBitrate.ul);
    } else {
        UTLT_Info("Find MBR (DL: %lu) in QERs", qer->maximumBitrate.dl);
        if (qer->flags.guaranteedBitrate)
            UTLT_Info("Find GBR (DL: %lu) in QERs", qer->guaranteedBitrate.dl);
    }

    UTLT_Info("TRTCM params: %d %d %d %d\n",
              trtcm_params.cir, trtcm_params.pir,
              trtcm_params.cbs, trtcm_params.pbs);

    trTCMidx++;
}

char *
convertToIpAddress(uint32_t big_endian_value) {
    static char ip_string[16];

    uint8_t ip_address[4];
    ip_address[0] = (big_endian_value >> 24) & 0xFF;
    ip_address[1] = (big_endian_value >> 16) & 0xFF;
    ip_address[2] = (big_endian_value >> 8) & 0xFF;
    ip_address[3] = big_endian_value & 0xFF;

    sprintf(ip_string, "%d.%d.%d.%d", ip_address[3], ip_address[2], ip_address[1], ip_address[0]);

    return ip_string;
}

int
parseIpv4Address(const char *addrStr) {
    const char *p = addrStr;
    char *endp;

    unsigned long a = strtoul(p, &endp, 10);
    if (*endp != '.')
        return -1;
    unsigned long b = strtoul(p = endp + 1, &endp, 10);
    if (*endp != '.')
        return -1;
    unsigned long c = strtoul(p = endp + 1, &endp, 10);
    if (*endp != '.')
        return -1;
    unsigned long d = strtoul(p = endp + 1, &endp, 10);

    SELF_IP = (uint32_t)((d << 24) | (c << 16) | (b << 8) | a);
    UTLT_Info("IP Address: %s -> %d\n", addrStr, SELF_IP);
    return 0;
}

static inline source_interface_t PortToSourceInterface(uint8_t port) {
    if ((int)port == g_access_port)  return SRC_IF_ACCESS;
    if ((int)port == g_core_port)    return SRC_IF_CORE;
    if ((int)port == g_sgi_port)     return SRC_IF_SGI_LAN;
    UTLT_Warning("PortToSourceInterface: unknown port %u (ACCESS=%d CORE=%d SGI=%d) — defaulting to ACCESS",
                 port, g_access_port, g_core_port, g_sgi_port);
    return SRC_IF_ACCESS;
}

static int
trtcmConfigFlowTables(void){
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
    for (i=0; i<APP_FLOWS_MAX; i++){
        rtn = rte_meter_trtcm_config(&app_flows[i], &app_trtcm_profile);
        if (rtn)
            return rtn;
    }

    UTLT_Info("Flow table configured.");
    return 0;
}

static inline int
trtcmColorHandle(uint32_t pkt_len, uint64_t time, uint8_t qfi, struct rte_meter_trtcm_profile *target_profile){
    uint8_t out_color = 0;
    // check configured flow
    if (unlikely(app_trtcm_profile.cir_period == 0)){
        UTLT_Info("flow cir_period set err");
        return -1;
    }
    if (unlikely(app_trtcm_profile.pir_period == 0)) {
        UTLT_Info("flow pir_period set err");    
        return -1;
    }
    out_color = (uint8_t) rte_meter_trtcm_color_blind_check(&app_flows[qfi], 
        target_profile, 
        time, 
        pkt_len);
    return out_color;
}

static inline int
trtcmPolicer(struct onvm_pkt_meta *meta, int color_result){
    if (meta->action == ONVM_NF_ACTION_DROP) {
        meta->flags = RTE_COLOR_RED;
        UTLT_Info("TB not enough & traffic flow");
        return 0;
    }
    switch (color_result){
    case RTE_COLOR_RED:
        UTLT_Info("\033[0;31mRED(%d)\033[0m, drop pkt", RTE_COLOR_RED);
        meta->flags = RTE_COLOR_RED;
        meta->action = ONVM_NF_ACTION_DROP;
        break;
    case RTE_COLOR_YELLOW:
        UTLT_Info("\033[0;32mYELLOW(%d)\033[0m, best effort pkt fwd", RTE_COLOR_YELLOW);
        meta->flags = RTE_COLOR_YELLOW;
        meta->action = ONVM_NF_ACTION_DROP;
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


int hashFunc(uint32_t subnet) {
    return subnet % APP_FLOWS_MAX;
}

int ftSearch(uint32_t subnet) {
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



void ftInit() {
    for (int i = 0; i < APP_FLOWS_MAX; i++) {
        iPFlows[i].in_use = false;
    }
}

/* Token Bucket */
struct tb_config {
    uint64_t tb_rate;    // rate at which tokens are generated (in MBps)
    uint64_t tb_depth;   // depth of the token bucket (in bytes)
    uint64_t tb_tokens;  // number of the tokens in the bucket at any given time (in bytes)
    uint64_t last_cycle;
    uint64_t cur_cycles;
    uint16_t used;
};

struct ue_tb {
    uint32_t ue_ip;
    uint32_t ue_ambr;
    uint32_t ue_gbr;
    uint32_t ue_mbr;
    struct tb_config ue_nqos_tb_params;
    struct tb_config ue_qos_tb_params;
};

struct ue_tb ue_table[MAX_UE];

void 
initUeTable(){
    for (int i = 0; i < MAX_UE; i++) {
        ue_table[i].ue_ip = 0;
        ue_table[i].ue_ambr = 0;
        ue_table[i].ue_gbr = 0;
        ue_table[i].ue_mbr = 0;

        ue_table[i].ue_nqos_tb_params.tb_rate = 0;
        ue_table[i].ue_nqos_tb_params.tb_depth = 0;
        ue_table[i].ue_nqos_tb_params.tb_tokens = 0;
        ue_table[i].ue_nqos_tb_params.last_cycle = rte_get_tsc_cycles();
        ue_table[i].ue_nqos_tb_params.cur_cycles = rte_get_tsc_cycles();

        ue_table[i].ue_qos_tb_params.tb_rate = 0;
        ue_table[i].ue_qos_tb_params.tb_depth = 0;
        ue_table[i].ue_qos_tb_params.tb_tokens = 0;
        ue_table[i].ue_qos_tb_params.last_cycle = rte_get_tsc_cycles();
        ue_table[i].ue_qos_tb_params.cur_cycles = rte_get_tsc_cycles();
    }
}

/* ── UE-IP → ue_table index hash (O(1) avg, replaces linear scan) ── */
struct ue_hash_entry {
    uint32_t ue_ip;
    int      ue_idx;   /* index into ue_table[] */
    bool     in_use;
};
static struct ue_hash_entry ue_hash[MAX_UE];

static inline int ueHashFunc(uint32_t ip) { return ip % MAX_UE; }

static void ueHashInit(void) {
    for (int i = 0; i < MAX_UE; i++)
        ue_hash[i].in_use = false;
}

/* Return ue_table index, or -1 */
static inline int ueHashSearch(uint32_t ue_ip) {
    int idx = ueHashFunc(ue_ip);
    int start = idx;
    while (ue_hash[idx].in_use) {
        if (ue_hash[idx].ue_ip == ue_ip)
            return ue_hash[idx].ue_idx;
        idx = (idx + 1) % MAX_UE;
        if (idx == start) break;
    }
    return -1;
}

static inline bool ueHashInsert(uint32_t ue_ip, int ue_idx) {
    if (ueHashSearch(ue_ip) >= 0) return false; /* already present */
    int idx = ueHashFunc(ue_ip);
    while (ue_hash[idx].in_use)
        idx = (idx + 1) % MAX_UE;
    ue_hash[idx].ue_ip  = ue_ip;
    ue_hash[idx].ue_idx = ue_idx;
    ue_hash[idx].in_use = true;
    return true;
}

/* Legacy wrapper — now O(1) via hash */
uint32_t 
findIndexByUeIpAddress(uint32_t ue_ip) {
    return ueHashSearch(ue_ip);
}

int
addEntrybyUeIp(uint32_t ue_ip, uint32_t ue_ambr, uint32_t ue_gbr, uint32_t ue_mbr) {
    for (int i = 0; i < MAX_UE; i++) {
        if (ue_table[i].ue_ip == 0) { // find unused
            ue_table[i].ue_ip = ue_ip;
            ue_table[i].ue_ambr = ue_ambr;
            ue_table[i].ue_gbr = ue_gbr;

            uint32_t qos_rate = MIN((ue_gbr + (ue_ambr - ue_gbr) / 2), ue_mbr);

            ue_table[i].ue_qos_tb_params.tb_rate = qos_rate / 1000;
            ue_table[i].ue_qos_tb_params.tb_depth = qos_rate;
            ue_table[i].ue_qos_tb_params.tb_tokens = qos_rate;
            ue_table[i].ue_qos_tb_params.last_cycle = rte_get_tsc_cycles();
            ue_table[i].ue_qos_tb_params.cur_cycles = rte_get_tsc_cycles();
            UTLT_Info("QoS Rate: %d", qos_rate);

            uint32_t nqos_rate = ue_ambr - qos_rate;

            ue_table[i].ue_nqos_tb_params.tb_rate = nqos_rate / 1000;
            ue_table[i].ue_nqos_tb_params.tb_depth = nqos_rate;
            ue_table[i].ue_nqos_tb_params.tb_tokens = nqos_rate;
            ue_table[i].ue_nqos_tb_params.last_cycle = rte_get_tsc_cycles();
            ue_table[i].ue_nqos_tb_params.cur_cycles = rte_get_tsc_cycles();
            UTLT_Info("non QoS Rate: %d", nqos_rate);

            ueHashInsert(ue_ip, i);
            return i;  // Return the allocated index
        }
    }
    return -1;  // Table full
}

void 
updateTokenbyIndex(int index) {
    if (index > -1) {
        uint64_t cur_cycles;
        uint64_t elapsed_cycles;
        uint64_t tokens_produced;

        cur_cycles = rte_get_tsc_cycles();
        elapsed_cycles = cur_cycles - ue_table[index].ue_nqos_tb_params.last_cycle;

        tokens_produced = (elapsed_cycles * ue_table[index].ue_nqos_tb_params.tb_rate * 125000) / rte_get_tsc_hz();
        ue_table[index].ue_nqos_tb_params.tb_tokens += tokens_produced;
        if (ue_table[index].ue_nqos_tb_params.tb_tokens > ue_table[index].ue_nqos_tb_params.tb_depth)
            ue_table[index].ue_nqos_tb_params.tb_tokens = ue_table[index].ue_nqos_tb_params.tb_depth;
        ue_table[index].ue_nqos_tb_params.last_cycle = cur_cycles;

        elapsed_cycles = cur_cycles - ue_table[index].ue_qos_tb_params.last_cycle;
        tokens_produced = (elapsed_cycles * ue_table[index].ue_qos_tb_params.tb_rate * 125000) / rte_get_tsc_hz();
        ue_table[index].ue_qos_tb_params.tb_tokens += tokens_produced;
        if (ue_table[index].ue_qos_tb_params.tb_tokens > ue_table[index].ue_qos_tb_params.tb_depth)
            ue_table[index].ue_qos_tb_params.tb_tokens = ue_table[index].ue_qos_tb_params.tb_depth;
        ue_table[index].ue_qos_tb_params.last_cycle = cur_cycles;

        return;
    }
    UTLT_Error("UE IP not found in the table");
    return;
}

uint64_t seid = 0;
uint16_t pdrId = 0;

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

static inline const char *
ip4_to_buf(uint32_t be_addr, char buf[16]) {
  inet_ntop(AF_INET, &be_addr, buf, 16);
  return buf;
}

static void dump_gtpu(const uint8_t *start, size_t len, size_t gtp_off) {
    printf("---- GTPU Dump (offset %zu, %zu bytes) ----\n", gtp_off, len);
    for (size_t i = 0; i < len; i++) {
        if (i % 16 == 0) printf("\n%04zu : ", i);
        printf("%02x ", start[i]);
    }
    printf("\n------------------------------------------\n");
}

UPDK_PDR *GetPdrByTeid(struct rte_mbuf *pkt, const gtp_parse_result_t *gtp_info) {
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

void *
GetQerByUEIpAddress(uint32_t ue_ip, char *IP) {
    if (findIndexByUeIpAddress(ue_ip) == -1) {        
        UpfSession *session = UpfSessionFindByUeIP(ue_ip);
        UTLT_Assert(session, return NULL, "session not found error");
        UTLT_Assert(session->pdr_list, return NULL, "PDR list not initialized");
        UTLT_Assert(session->pdr_list->len, return NULL, "PDR list contains 0 rules");

        list_node_t *pnode = session->pdr_list->head;
        list_node_t *qnode = NULL;
        UpfPDR *pdr = NULL, *target_pdr = NULL;
        uint32_t ambr = 0;
        uint32_t gbr = 0;
        uint32_t mbr = 0;

        while (pnode) {
            pdr = (UpfPDR *)pnode->val;
            pnode = pnode->next;
            for (int i =0;i<2;i++){
                if (!pdr->qerId[i]) continue;
                UpfQER * qer = UpfQERFindByID(session, pdr->qerId[i]);

                if (ambr < qer->maximumBitrate.dl) {
                    ambr = qer->maximumBitrate.dl;
                }
                if (qer->flags.guaranteedBitrate && qer->flags.maximumBitrate) {
                    gbr = qer->guaranteedBitrate.dl;
                    mbr = qer->maximumBitrate.dl;
                }
            }
        }
        if (ambr) {
            UTLT_Warning("Add UE IP: %s, AMBR: %u GBR: %u, MBR: %u" , IP, ambr, gbr, mbr);
            addEntrybyUeIp(ue_ip, ambr, gbr, mbr);
            return NULL;
        }
    }
    else {
        UTLT_Trace("The UE IP already exists in the table");
        return NULL;
    }
}

/* Populate UE table using the already-classified UPDK_PDR (no session/pdr_list scan)*/
static inline int
GetQerByUEIpAddressFromPdr(uint32_t ue_ip, const UPDK_PDR *pdr, const char *ip_str)
{
    if (!pdr || pdr->qer_count == 0) {
        UTLT_Trace("UE %s: No PDR or PDR has no QERs, skip UE table entry",
                   ip_str ? ip_str : "<unknown>");
        return -1;
    }

    uint64_t ambr64 = 0;
    uint64_t gbr64  = 0;
    uint64_t mbr64  = 0;

    int n = (int)pdr->qer_count;
    if (n > 2) n = 2; /* safety; struct currently supports 2 */

    for (int i = 0; i < n; i++) {
        const UPDK_QER *q = pdr->qers[i];
        if (!q) continue;

        if (q->flags.maximumBitrate && q->maximumBitrate.dl > ambr64)
            ambr64 = q->maximumBitrate.dl;

        /* old behavior: only set gbr/mbr when both flags are present */
        if (q->flags.guaranteedBitrate && q->flags.maximumBitrate) {
            gbr64 = q->guaranteedBitrate.dl;
            mbr64 = q->maximumBitrate.dl;
        }
    }

    if (ambr64 == 0) {
        UTLT_Trace("UE %s: no DL MBR across PDR QERs, skip UE table entry",
                   ip_str ? ip_str : "<unknown>");
        return -1;
    }

    /* Clamp PFCP 64-bit rates into 32-bit UE table fields */
    uint32_t ambr = (ambr64 > UINT32_MAX) ? UINT32_MAX : (uint32_t)ambr64;
    uint32_t gbr  = (gbr64  > UINT32_MAX) ? UINT32_MAX : (uint32_t)gbr64;
    uint32_t mbr  = (mbr64  > UINT32_MAX) ? UINT32_MAX : (uint32_t)mbr64;

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
    onvm_pkt_fill_ipv4(ipv4_hdr, rte_cpu_to_be_32(SELF_IP), rte_cpu_to_be_32(outerHeaderCreation->ipv4.s_addr),
               IPPROTO_UDP);
    ipv4_hdr->total_length = rte_cpu_to_be_16(payloadLen + sizeof(gtpv1_t) + sizeof(struct rte_udp_hdr) +
                          sizeof(struct rte_ipv4_hdr));  // raw+gtp8+udp8+ip20
    ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
}

static int
HandlePacketWithFar(struct rte_mbuf *pkt, UPDK_FAR *far, UPDK_QER *qer, struct onvm_pkt_meta *meta) {
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
                meta->destination = pkt->port ^ 1;
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

static inline void
AttachL2Header(struct rte_mbuf *pkt, bool is_dl) {
    // Prepend ethernet header
    struct rte_ether_hdr *eth_hdr =
        (struct rte_ether_hdr *)rte_pktmbuf_prepend(pkt, (uint16_t)sizeof(struct rte_ether_hdr));

    // next hop's mac address
    if (is_dl == true) {
        rte_ether_addr_copy(&cn_ue_eth, &eth_hdr->src_addr);
        rte_ether_addr_copy(&an_eth, &eth_hdr->dst_addr);

    } else {
        rte_ether_addr_copy(&cn_dn_eth, &eth_hdr->src_addr);
        rte_ether_addr_copy(&dn_eth, &eth_hdr->dst_addr);
    }

    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
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
    uint32_t cal_pktlen = 0;
    UTLT_Trace("Get packet\n");
    UTLT_Info("Handle PKT from port: %d [len: %d]", pkt->port, pkt->pkt_len);
    cal_pktlen = pkt->pkt_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr) - sizeof(struct rte_udp_hdr);

    bool is_dl = false;
    meta->action = ONVM_NF_ACTION_DROP;
    struct rte_ipv4_hdr *iph = onvm_pkt_ipv4_hdr(pkt);

    if (iph == NULL) {
        UTLT_Info("Not IP packet, ignore it\n");
        return 0;
    }

    // Flip to a newly published snapshot if a REQ was received
    UpfClsMaybeFlipAndAck();

    UPDK_PDR *pdr = NULL;
    gtp_parse_result_t gtp_info = {0};
    int ue_idx = -1;

    /* char *src_address = convertToIpAddress(iph->src_addr);
    UTLT_Info("Src IP is %s\n", src_address);
    char *dst_address = convertToIpAddress(iph->dst_addr);
    UTLT_Info("Dst IP is %s\n", dst_address); */

    if (iph->dst_addr == SELF_IP) {  //
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
        // UTLT_Info("It is downlink, dst is %s\n", convertToIpAddress(iph->dst_addr));
        pdr = GetPdrByUeIpAddress(pkt, rte_cpu_to_be_32(iph->dst_addr));
        is_dl = true;
    }

    if (!pdr) {
        UTLT_Error("no PDR found for %s, skip\n", convertToIpAddress(iph->dst_addr));
        // TODO(vivek): what to do?
        return 0;
    }
    UTLT_Info("Got PDR ID is %u\n", pdr->pdrId);

    if (is_dl) {
        uint32_t ue_key = rte_cpu_to_be_32(iph->dst_addr);
        ue_idx = (int)findIndexByUeIpAddress(ue_key);
        if (ue_idx < 0) {
            ue_idx = GetQerByUEIpAddressFromPdr(ue_key, pdr, convertToIpAddress(iph->dst_addr));
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

        meta->destination = pkt->port ^ 1;
        AttachL2Header(pkt, true);

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

        /* QoS policing — FORW only */
        if (far_action == UPDK_FAR_APPLY_ACTION_FORW) {
            if (ue_idx < 0) {
                UTLT_Error("No UE IP found in the table");
                meta->action = ONVM_NF_ACTION_DROP;
                goto dl_nocp;
            }

            int color_result = 0;
            bool isQos = false;
            uint64_t curr_time = rte_get_tsc_cycles();
            struct rte_meter_trtcm_profile *trtcm_profile = NULL;

            if (pdr->has_fd) {
                isQos = true;
                trtcm_profile = &app_flow_trtcm_profile;
                int ft_idx = ftSearch(pdr->meter_key);
                color_result = trtcmColorHandle(cal_pktlen, curr_time,
                                                ft_idx, trtcm_profile);
                if (trtcmPolicer(meta, color_result) > 0)
                    UTLT_Error("trTCM Policer error");
            }

            if (isQos) {
                if (meta->flags == RTE_COLOR_RED) {
                    meta->action = ONVM_NF_ACTION_DROP;
                    goto dl_nocp;
                }
                if (meta->flags == RTE_COLOR_GREEN) {
                    ue_table[ue_idx].ue_qos_tb_params.tb_tokens -= cal_pktlen;
                }
                if (meta->flags == RTE_COLOR_YELLOW) {
                    while (ue_table[ue_idx].ue_qos_tb_params.tb_tokens < cal_pktlen) {
                        updateTokenbyIndex(ue_idx);
                        usleep(1);
                    }
                    ue_table[ue_idx].ue_qos_tb_params.tb_tokens -= cal_pktlen;
                }
            } else {
                while (ue_table[ue_idx].ue_nqos_tb_params.tb_tokens < cal_pktlen) {
                    updateTokenbyIndex(ue_idx);
                    usleep(1);
                }
                ue_table[ue_idx].ue_nqos_tb_params.tb_tokens -= cal_pktlen;
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
        int status = HandlePacketWithFar(pkt, far, pdr->qer, meta);
        AttachL2Header(pkt, is_dl);
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

uint64_t last_p = NULL;

static int 
callback_handler(struct onvm_nf_local_ctx *nf_local_ctx) {
    if (unlikely(!last_p)) last_p = rte_get_tsc_cycles();
    uint64_t cur_p = rte_get_tsc_cycles(), before;
    struct onvm_nf *nf;
    struct onvm_pkt_meta *meta;
    struct packet_buf *out_buf;
    nf = nf_local_ctx->nf;

    // if (buffer_length > 0){
    //     for (int i = 0; i < buffer_length; i++) {
    //         meta = onvm_get_pkt_meta(buffer[i]);
    //         meta->action = ONVM_NF_ACTION_OUT;
    //     }
    //     onvm_pkt_process_tx_batch(nf->nf_tx_mgr, buffer, buffer_length, nf);
    //     onvm_pkt_enqueue_tx_thread(nf->nf_tx_mgr->to_tx_buf, nf);
    //     UTLT_Debug("Sending out %u packets\n", buffer_length);
    //     buffer_length = 0;
    // } 

    if (unlikely((cur_p - last_p)/(double)rte_get_timer_hz() > 1)){
        last_p = cur_p;
        UTLT_Debug("Stats perform: ");
        UTLT_Debug("act out: %d", nf->stats.act_out);
        UTLT_Debug("buffered: %d", nf->stats.tx_buffer);
    }

    return 0;
}

int
main(int argc, char *argv[]) {
    int arg_offset;
    struct onvm_nf_local_ctx *nf_local_ctx;
    struct onvm_nf_function_table *nf_function_table;
    // UTLT_SetLogLevel("Panic"); // to eliminate log print influenced jitter
    UTLT_SetLogLevel("warning"); // to eliminate log print influenced jitter

    nf_local_ctx = onvm_nflib_init_nf_local_ctx();
    onvm_nflib_start_signal_handler(nf_local_ctx, NULL);
    nf_function_table = onvm_nflib_init_nf_function_table();
    nf_function_table->pkt_handler = &packet_handler;
    nf_function_table->msg_handler = &msg_handler;
    // nf_function_table->user_actions = &callback_handler;

    if ((arg_offset = onvm_nflib_init(argc, argv, NF_TAG, nf_local_ctx, nf_function_table)) < 0) {
        onvm_nflib_stop(nf_local_ctx);
        if (arg_offset == ONVM_SIGNAL_TERMINATION) {
            printf("Exiting due to user termination\n");
            return 0;
        } else {
            rte_exit(EXIT_FAILURE, "Failed ONVM init\n");
        }
    }

    const char *config_path = "config/upf_u.yaml";

    if (argc > arg_offset + 1) {
        config_path = argv[arg_offset + 1];
    }
    printf("[UPF-U] Using config: %s\n", config_path);
    UpfU_LoadAndParseConfig(config_path);

    if (UpfClsCtrlInit() < 0) {
        rte_exit(EXIT_FAILURE, "CLS_CTRL memzone init failed\n");
    }

    if (UpfSessBufInit() < 0) {
        rte_exit(EXIT_FAILURE, "SESS_BUF memzone init failed\n");
    }

    int ret;
    ret = rte_eth_macaddr_get(g_access_port, &cn_ue_eth);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Cannot get MAC address: err=%d, port=%d\n", ret, g_access_port);
    ret = rte_eth_macaddr_get(g_core_port, &cn_dn_eth);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Cannot get MAC address: err=%d, port=%d\n", ret, g_core_port);

    /* UTLT_Info("[UPF-U][CONFIG] Port map: ACCESS=%d CORE=%d SGI=%d",
          g_access_port, g_core_port, g_sgi_port); */

    // 8c:dc:d4:ac:6c:7d
    memcpy(dn_eth.addr_bytes, DnMac, RTE_ETHER_ADDR_LEN);
    memcpy(an_eth.addr_bytes, AnMac, RTE_ETHER_ADDR_LEN);

    // trTCM
    trtcmConfigFlowTables();
    initUeTable();
    ueHashInit();

    UpfSessionPoolInit();
    UeIpToUpfSessionMapInit();
    TeidToUpfSessionMapInit();

    onvm_nflib_run(nf_local_ctx);

    onvm_nflib_stop(nf_local_ctx);
    printf("If we reach here, program is ending\n");
    return 0;
}
