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
#include <rte_ring.h>

#include "gtp.h"
#include "upf_context.h"
#include "utlt_debug.h"
#include "onvm_flow_table.h"
#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include "list.h"

#include "upf_events.h"
#include "upf_cls_ctrl.h"
#include "upf_session_dl.h"
#include "upf_u_common.h"

#include "../classifiers/upf_cls_adapter.h"
#include "../classifiers/classifier_wrapper.h"

#include "upf_u_config.h"

#define NF_TAG "upf_ingress"

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
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#define MAX_OF_BUFFER_PACKET_SIZE 30000

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

static inline int UpfSendEvt2(uint16_t dest_sid, uint32_t type, uintptr_t a0, uintptr_t a1) {
    Event *e = (Event *)rte_calloc("upf_evt", 1, sizeof(*e), 0);
    if (!e) return -1;
    e->type = (uintptr_t)type;
    e->argc = 2;
    e->arg0 = a0;
    e->arg1 = a1;
    int rc = onvm_nflib_send_msg_to_nf(dest_sid, e);
    if (rc < 0) rte_free(e);
    return rc;
}

struct rte_ether_addr dn_eth;
struct rte_ether_addr cn_dn_eth;
struct rte_ether_addr cn_ue_eth;

uint8_t DnMac[RTE_ETHER_ADDR_LEN];
uint8_t AnMac[RTE_ETHER_ADDR_LEN];
uint32_t SELF_IP;

enum { IF_UNKNOWN = -1 };

int16_t g_access_port = 0;
int16_t g_core_port   = 0;
int16_t g_sgi_port    = 0;


struct rte_meter_trtcm_profile app_trtcm_profile;
struct rte_meter_trtcm_profile app_flow_trtcm_profile;
struct rte_meter_trtcm app_flows[APP_FLOWS_MAX];

struct rte_mbuf *buffer[MAX_OF_BUFFER_PACKET_SIZE];
uint32_t buffer_length = 0;

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


upf_cls_local_t g_cls_local = {0};

// Flip to the latest published snapshot (called at burst boundary)
void UpfClsMaybeFlipAndAck(uint32_t consumer_id) {
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
        new_ptr = __atomic_load_n((void * const *)&g_upf_cls_ctrl->active, __ATOMIC_ACQUIRE);

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
    g_cls_local.ptr = new_ptr;
    g_cls_local.ver = v2;
    g_cls_local.flip_pending = 0;

    (void)UpfSendEvt2(UPF_C_SERVICE_ID, EVT_CLS_GC_ACK, (uintptr_t)v2, (uintptr_t)consumer_id);
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

int SourceInterfaceToPort(source_interface_t srcIf) {
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
ConfigureQerFlows(UpfSession *session,
                  const UPDK_PDR *pdr,
                  uint8_t port,
                  bool is_uplink)
{
    if (!session || !pdr || !session->qer_list) return;

    int prefix_len = 0;
    uint32_t fd_target = 0;
    bool has_fd = false;

    if (pdr->pdi.flags.sdfFilter && pdr->pdi.sdfFilter.flowDescription) {
        const char *fd = pdr->pdi.sdfFilter.flowDescription;
        const char *ip_str = strstr(fd, "from");
        if (ip_str) {
            ip_str += 5; // skip "from "
            const char *end_ptr = strchr(ip_str, ' ');
            size_t n = end_ptr ? (size_t)(end_ptr - ip_str) : strlen(ip_str);
            if (n > 0 && n < 64) {
                char tmp[64];
                memcpy(tmp, ip_str, n);
                tmp[n] = '\0';
                if (strcmp(tmp, "any") != 0) {
                    fd_target = charStr2MaskedIP(tmp, &prefix_len);
                    has_fd = true;
                }
            }
        }
    }

    uint32_t base = SourceInterfaceToPort(pdr->pdi.sourceInterface);
    uint32_t key  = has_fd ? (base + fd_target) : base;

    for (int i = 0; i < 2; i++) {
        uint32_t qerId = pdr->qerId[i];
        if (!qerId) continue;

        for (list_node_t *node = session->qer_list->head; node; node = node->next) {
            UpfQER *qer = (UpfQER *)node->val;
            if (!qer || qer->qerId != qerId) continue;

            /* int idx = ftSearch(key);
            if (idx >= 0) {
                UTLT_Info("QER flow already exists: key=%u idx=%d (is_uplink=%d)", key, idx, (int)is_uplink);
                continue; // nothing to configure
            }

            if (qer->flags.maximumBitrate) {
                UTLT_Info("QER ID: %u key: %u", qerId, key);
            } */

            // only add on miss, and only if MBR exists
            if (ftSearch(key) < 0 && qer->flags.maximumBitrate) {
                UTLT_Info("QER ID: %u key: %u", qerId, key);

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
        }
    }
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

int
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

int
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

int
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
            return index;
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

uint32_t 
findIndexByUeIpAddress(uint32_t ue_ip) {
    int index = -1;
    for (int i = 0; i < MAX_UE; i++) {
        if (ue_table[i].ue_ip == ue_ip) {
            index = i;
        }
    }
    return index;
}

void
addEntrybyUeIp(uint32_t ue_ip, uint32_t ue_ambr, uint32_t ue_gbr,uint32_t ue_mbr) {
    for (int i = 0; i < MAX_UE; i++) {
        if (ue_table[i].ue_ip == 0) { // find unused
            ue_table[i].ue_ip = ue_ip;
            ue_table[i].ue_ambr = ue_ambr;
            ue_table[i].ue_gbr = ue_gbr;

            uint32_t qos_rate = MIN((ue_gbr + (ue_ambr-ue_gbr)/2), ue_mbr);

            ue_table[i].ue_qos_tb_params.tb_rate = qos_rate/1000;
            ue_table[i].ue_qos_tb_params.tb_depth = qos_rate;
            ue_table[i].ue_qos_tb_params.tb_tokens = qos_rate;
            ue_table[i].ue_qos_tb_params.last_cycle = rte_get_tsc_cycles();
            ue_table[i].ue_qos_tb_params.cur_cycles = rte_get_tsc_cycles(); 
            UTLT_Info("QoS Rate: %d", qos_rate);

            uint32_t nqos_rate = ue_ambr - qos_rate;

            ue_table[i].ue_nqos_tb_params.tb_rate = nqos_rate/1000;
            ue_table[i].ue_nqos_tb_params.tb_depth = nqos_rate;
            ue_table[i].ue_nqos_tb_params.tb_tokens = nqos_rate;
            ue_table[i].ue_nqos_tb_params.last_cycle = rte_get_tsc_cycles();
            ue_table[i].ue_nqos_tb_params.cur_cycles = rte_get_tsc_cycles();
            UTLT_Info("non QoS Rate: %d", nqos_rate); 


            break;
        }
    }
    return;
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

    // printf("DBG2: srcIf=%u (port=%u)\n", key.source_if, pkt->port);

    /* UTLT_Debug("DL key → teid=%u UE_IP=%s/%u sport=%u dport=%u proto=%u "
               "spi=%u flow_label=%u ni=0x%08x qfi=%u srcIf=%u",
        key.teid,
        ip4(key.ue_ip),
        key.src_port, key.dst_port,
        key.proto,
        key.spi,
        key.flow_label,
        key.ni_hash,
        key.qfi,
        (unsigned)key.source_if
    ); */

    /* uint16_t pdr_id = UpfClassifyGetPdrId(&key);
    if (pdr_id == 0) {
        UTLT_Error("Couldn't classify the packet to a PDR");
        return NULL;
    } */

    const UPDK_PDR *pdr = UpfClassifyGetPdrPtr(&key);
    if (!pdr) {
        UTLT_Error("Couldn't classify the packet to a PDR");
        return NULL;
    }

    UpfSession *session = UpfSessionFindByUeIP(ue_ip);
    if (session) {
        ConfigureQerFlows(session, pdr, pkt->port, false);
    }
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

UPDK_PDR *GetPdrByTeid(struct rte_mbuf *pkt, uint32_t td) {
    char o_src[16], o_dst[16], i_src[16], i_dst[16], ue_s[16], dn_s[16];
    uint16_t data_len = rte_pktmbuf_data_len(pkt);

    // Outer IPv4
    struct rte_ipv4_hdr *outer4 = onvm_pkt_ipv4_hdr(pkt);
    if (!outer4) return NULL;
    UTLT_Debug("Outer IPv4 src=%s dst=%s totlen=%u",
               ip4_to_buf(outer4->src_addr, o_src),
               ip4_to_buf(outer4->dst_addr, o_dst),
               data_len);

    // Outer UDP
    struct rte_udp_hdr *outerU = onvm_pkt_udp_hdr(pkt);
    if (!outerU) return NULL;
    if (outerU->dst_port != rte_cpu_to_be_16(2152)) return NULL;

    // TEID extraction
    uint32_t teid = get_teid_gtp_packet(pkt, outerU);
    UTLT_Debug("Extracted TEID (host order): %u", teid);

    // GTP-U header length + QFI
    uint8_t qfi = 0;
    uint16_t payload_offset = get_gtpu_header_len_with_qfi(pkt, &qfi);
    UTLT_Debug("Computed GTP-U payload_offset=%u QFI=%u", payload_offset, qfi);

    // Base pointer to GTP header
    uint8_t *base = rte_pktmbuf_mtod(pkt, uint8_t *) +
                    sizeof(struct rte_ether_hdr) +
                    ((outer4->version_ihl & 0x0F) * 4) +
                    sizeof(*outerU);

    // Dump for verification
    size_t dbg_len = (data_len > 64) ? 64 : data_len;
    // dump_gtpu(base, dbg_len, (size_t)(base - rte_pktmbuf_mtod(pkt, uint8_t *)));

    // Fallback: verify payload start looks like IPv4, else scan nearby
    uint8_t *inner_ptr = base + payload_offset;

    if ((inner_ptr[0] >> 4) != 4 || (inner_ptr[0] & 0x0F) < 5) {
        UTLT_Info("Non-IPv4 start at offset %u (0x%02x), scanning for IPv4...",
                     payload_offset, inner_ptr[0]);
        int found = 0;
        for (int delta = -4; delta <= 4; delta++) {
            if ((int)payload_offset + delta < 0) continue;
            uint8_t *cand = base + payload_offset + delta;
            if ((cand[0] >> 4) == 4 && (cand[0] & 0x0F) >= 5) {
                UTLT_Info("Adjusted payload_offset from %u to %u",
                             payload_offset, payload_offset + delta);
                payload_offset += delta;
                inner_ptr = cand;
                found = 1;
                break;
            }
        }
        if (!found) {
            UTLT_Error("Failed to locate a valid IPv4 header near offset %u", payload_offset);
            return NULL;
        }
    }

    // Inner IPv4
    if (data_len < (inner_ptr - rte_pktmbuf_mtod(pkt, uint8_t *)) + sizeof(struct rte_ipv4_hdr))
        return NULL;
    struct rte_ipv4_hdr *inner4 = (struct rte_ipv4_hdr *)inner_ptr;
    uint8_t inner_ihl = (inner4->version_ihl & 0x0F) * 4;

    // Inner UDP
    if (data_len < (inner_ptr - rte_pktmbuf_mtod(pkt, uint8_t *)) + inner_ihl + sizeof(struct rte_udp_hdr))
        return NULL;
    struct rte_udp_hdr *innerU = (struct rte_udp_hdr *)(inner_ptr + inner_ihl);

    UTLT_Debug("Inner IPv4 src=%s dst=%s proto=%u QFI=%u",
               ip4_to_buf(inner4->src_addr, i_src),
               ip4_to_buf(inner4->dst_addr, i_dst),
               inner4->next_proto_id, qfi);

    // Build classifier key
    ps_packet_t key = {0};
    key.teid      = teid;
    key.ue_ip     = rte_be_to_cpu_32(inner4->src_addr);
    key.src_ip    = key.ue_ip;
    key.dst_ip    = rte_be_to_cpu_32(inner4->dst_addr);
    key.src_port  = rte_be_to_cpu_16(innerU->src_port);
    key.dst_port  = rte_be_to_cpu_16(innerU->dst_port);
    key.proto     = inner4->next_proto_id;
    key.tos_tc    = inner4->type_of_service;
    key.qfi       = qfi;
    key.source_if = SRC_IF_ACCESS;
    key.is_uplink = true;

    //  printf(
    // "DBG→Classifier Key:\n"
    // "    teid        = %u\n"
    // "    ue_ip       = %s\n"
    // "    src_ip      = %s\n"
    // "    dst_ip      = %s\n"
    // "    src_port    = %u\n"
    // "    dst_port    = %u\n"
    // "    proto       = %u\n"
    // "    tos_tc      = %u\n"
    // "    spi         = %u\n"
    // "    flow_label  = %u\n"
    // "    ni_hash     = 0x%08x\n"
    // "    qfi         = %u\n"
    // "    source_if   = %u\n"
    // "    is_uplink   = %s\n",
    // key.teid,
    // ip4_to_buf(htonl(key.ue_ip), ue_s),
    // ip4_to_buf(htonl(key.src_ip), o_dst),   // reuse buffers or add new ones
    // ip4_to_buf(htonl(key.dst_ip), dn_s),
    // key.src_port,
    // key.dst_port,
    // key.proto,
    // key.tos_tc,
    // key.spi,
    // key.flow_label,
    // key.ni_hash,
    // key.qfi,
    // key.source_if,
    // key.is_uplink ? "true" : "false");


    /* uint16_t pdr_id = UpfClassifyGetPdrId(&key);
    if (pdr_id == 0) {
        UTLT_Error("Couldn't classify the packet to a PDR");
        return NULL;
    } */

    // printf("PDR ID from Classifier = %" PRIu16 "\n", pdr_id);

    const UPDK_PDR *pdr = UpfClassifyGetPdrPtr(&key);
    if (!pdr) {
        UTLT_Error("Couldn't classify the packet to a PDR");
        return NULL;
    }

    UpfSession *session = UpfSessionFindByTeid(td);
    if (session) {
        ConfigureQerFlows(session, pdr, pkt->port, true);
    }

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

int
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
                meta->destination = pkt->port ^ 1;
                meta->action = ONVM_NF_ACTION_DROP;
                if (buffer_length < MAX_OF_BUFFER_PACKET_SIZE) {
                    Encap(pkt, far, qer);
                    buffer[buffer_length++] = pkt;
                    buff = 1;
                }
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

void
AttachL2Header(struct rte_mbuf *pkt, bool is_dl) {
    // Prepend ethernet header
    struct rte_ether_hdr *eth_hdr =
        (struct rte_ether_hdr *)rte_pktmbuf_prepend(pkt, (uint16_t)sizeof(struct rte_ether_hdr));

    // next hop's mac address
    if (is_dl == true) {
        rte_ether_addr_copy(&cn_ue_eth, &eth_hdr->src_addr);
        eth_hdr->dst_addr.addr_bytes[0] = AnMac[0];
        eth_hdr->dst_addr.addr_bytes[1] = AnMac[1];
        eth_hdr->dst_addr.addr_bytes[2] = AnMac[2];
        eth_hdr->dst_addr.addr_bytes[3] = AnMac[3];
        eth_hdr->dst_addr.addr_bytes[4] = AnMac[4];
        eth_hdr->dst_addr.addr_bytes[5] = AnMac[5];

    } else {
        rte_ether_addr_copy(&cn_dn_eth, &eth_hdr->src_addr);
        rte_ether_addr_copy(&dn_eth, &eth_hdr->dst_addr);
    }

    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
}
