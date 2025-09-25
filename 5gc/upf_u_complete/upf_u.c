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
#include <rte_common.h>
#include <rte_gtp.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <time.h>
#include <unistd.h>

#include "gtp.h"
#include "upf_context.h"

#include "onvm_flow_table.h"
#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include "rte_meter.h"

#define NF_TAG "upf_u"

// #if 0
// #define SELF_IP RTE_IPV4(10, 100, 200, 3)
// #else
// #define SELF_IP 33622538  // 10.10.1.2

// #endif

#define SRC_INTF_ACCESS 0
#define SRC_INTF_CORE 1
#define SRC_INTF_SGI_LAN 2
#define SRC_INTF_CP 3
#define SRC_INTF_NUM (SRC_INTF_CP + 1)
#define FIX_BUFFER
#define DEFAULT_TB_RATE 10         // (Mbps)
#define DEFAULT_TB_DEPTH 10000  // Max proceed length
#define DEFAULT_TB_TOKENS 10000
#define APP_FLOWS_MAX 256
#define IP_MASKED(BIGENDIINT, LEN) (BIGENDIINT & (0xFFFFFFFF << (32-LEN)))
#define MAX_UE 256 // Max number of UEs
#define MIN(x, y) (((x) < (y)) ? (x) : (y))


static struct rte_ether_addr dn_eth;
static struct rte_ether_addr cn_dn_eth;
static struct rte_ether_addr cn_ue_eth;

uint8_t DnMac[RTE_ETHER_ADDR_LEN];
uint8_t AnMac[RTE_ETHER_ADDR_LEN];
int SELF_IP;

/* --- Runtime port map (deploy-time configurable) --- */
enum { IF_UNKNOWN = -1 };

static int16_t g_access_port = 0;
static int16_t g_core_port   = 1;
static int16_t g_sgi_port    = 1;



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

void
parseMAC(const char *config_path) {
    FILE *file = fopen(config_path, "r");
    if (file == NULL) {
        fprintf(stderr, "Error: failed to open file %s\n", config_path);
        exit(EXIT_FAILURE);
    }

    char line[256];
    int linenum = 0;
    int DNvalues[6];
    int ANvalues[6];

    while (fgets(line, sizeof(line), file) != NULL) {
        linenum++;

        char *p = line;
        while (*p == ' ' || *p == '\t') p++;

        if (strncmp(p, "ACCESS_PORT=", 12) == 0) {
            int v = atoi(p + 12);
            if (v >= 0 && v <= UINT8_MAX) g_access_port = (int16_t)v;
            continue;
        }
        if (strncmp(p, "CORE_PORT=", 10) == 0) {
            int v = atoi(p + 10);
            if (v >= 0 && v <= UINT8_MAX) {
                g_core_port = (int16_t)v;
                g_sgi_port  = (int16_t)v;
            }
            continue;
        }

        if (linenum == 2) {
            /* DN MAC Address */
            if (sscanf(p, "%x:%x:%x:%x:%x:%x%*c",
                       &DNvalues[0], &DNvalues[1], &DNvalues[2],
                       &DNvalues[3], &DNvalues[4], &DNvalues[5]) == 6) {
                for (int i = 0; i < 6; ++i) DnMac[i] = (uint8_t)DNvalues[i];
            } else {
                fprintf(stderr, "[Parse MAC] could not parse DN MAC from: %s", p);
            }
        }

        if (linenum == 4) {
            /* AN MAC Address */
            if (sscanf(p, "%x:%x:%x:%x:%x:%x%*c",
                       &ANvalues[0], &ANvalues[1], &ANvalues[2],
                       &ANvalues[3], &ANvalues[4], &ANvalues[5]) == 6) {
                for (int j = 0; j < 6; ++j) AnMac[j] = (uint8_t)ANvalues[j];
            } else {
                fprintf(stderr, "[Parse MAC] could not parse AN MAC from: %s", p);
            }
        }

        if (linenum == 6) {
            if (parseIpv4Address(p)) {
                UTLT_Error("Parse IP address failed\n");
            }
        }
    }

    fclose(file);

    UTLT_Debug("UPF port map (from upf_u.txt): ACCESS=%d CORE=%d SGI=%d",
              g_access_port, g_core_port, g_sgi_port);
}


#define MAX_OF_BUFFER_PACKET_SIZE 30000
struct rte_mbuf *buffer[MAX_OF_BUFFER_PACKET_SIZE];
uint32_t buffer_length = 0;

static inline int16_t
SourceInterfaceToPort(uint8_t interface) {
    switch (interface) {
        case SRC_INTF_ACCESS:   return g_access_port;
        case SRC_INTF_CORE:     return g_core_port;
        case SRC_INTF_SGI_LAN:  return g_sgi_port;
        case SRC_INTF_CP:
        default:                return IF_UNKNOWN;
    }
}


/* trTCM */
struct rte_meter_trtcm_params app_trtcm_params = {
	.cir = 125000,    // bytes per secs
	.pir = 625000,    // bytes per secs
	.cbs = 2048,
	.pbs = 2048
};
struct rte_meter_trtcm_profile app_trtcm_profile;
struct rte_meter_trtcm_profile app_flow_trtcm_profile;
struct rte_meter_trtcm app_flows[APP_FLOWS_MAX];

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

/* Flow Separation*/
struct flow_entry {
    uint32_t subnet;  // (Network & Mask_bits)
    int flow_idx;     // maps to trTCM flows table
    bool in_use;      // to track if the slot is occupied
}typedef flow_entry_t;
flow_entry_t iPFlows[APP_FLOWS_MAX];
uint32_t iPFlowsLen = 0;
uint32_t trTCMidx = 0; 

uint32_t charStr2MaskedIP(char *str, uint32_t *prefix_val){
    char ip_str[INET_ADDRSTRLEN];
    uint32_t prefix_len, subnet;

    sscanf(str, "%[^/]/%d", ip_str, &prefix_len);
    struct in_addr ip_addr;
    inet_pton(AF_INET, ip_str, &ip_addr);
    
    if (prefix_val) *prefix_val = prefix_len;
    return IP_MASKED(ip_addr.s_addr, prefix_len);
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

uint32_t 
findIndexByUeIpAddress(uint32_t ue_ip) {
    int index = -1;
    for (int i = 0; i < MAX_UE; i++)
    {
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
        //
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
GetPdrByUeIpAddress(struct rte_mbuf *pkt, uint32_t ue_ip) { // dl
    UpfSession *session = UpfSessionFindByUeIP(ue_ip);
    UTLT_Assert(session, return NULL, "session not found error");
    UTLT_Assert(session->pdr_list, return NULL, "PDR list not initialized");
    UTLT_Assert(session->pdr_list->len, return NULL, "PDR list contains 0 rules");

    list_node_t *node = session->pdr_list->head;
    UpfPDR *pdr = NULL, *target_pdr = NULL;
    struct rte_ipv4_hdr *iph = NULL;
    uint32_t prefix_len = 0, fd_target = 0;
    while (node) {
        pdr = (UpfPDR *)node->val;
        node = node->next;
        if (pdr->flags.pdi) {
            if (pdr->pdi.flags.sourceInterface) {
                if (SourceInterfaceToPort(pdr->pdi.sourceInterface) == pkt->port) {
                    char *ip_str = strstr(pdr->pdi.sdfFilter.flowDescription, "from");
                    if (ip_str != NULL) {
                        ip_str += 5; // Skip "from "
                        char *end_ptr = strchr(ip_str, ' ');
                        if (end_ptr != NULL) {
                            *end_ptr = '\0'; // Null-terminate the extracted IP
                        }
                        if (strlen(ip_str) > 5) {
                            iph = onvm_pkt_ipv4_hdr(pkt);
                            fd_target = charStr2MaskedIP(ip_str, &prefix_len);
                            if (IP_MASKED(iph->src_addr, prefix_len) == fd_target) {
                                target_pdr = pdr; // Use the found pdr
                                break;
                            }
                        }
                    }
                    if(!target_pdr) {
                        target_pdr = pdr;
                    }
                }
            }
        }
    }
    pdr = target_pdr;
    if (pdr) {
        seid = session->smfSeid;
        pdrId = pdr->pdrId;
        for (int i=0; i<2; i++){
            if (!pdr->qerId[i]) continue;
            UpfQER *qer = NULL;
            uint32_t key = 0, qerId = pdr->qerId[i];
            node = session->qer_list->head;
            while (node) {
                qer = (UpfQER *) node->val;
                node = node->next;
                if (qer->qerId != qerId) continue;
                // new ft entry
                key = pdr->pdi.flags.sdfFilter ? pkt->port + fd_target : pkt->port;
                if (ftSearch(key) < 0 && qer->flags.maximumBitrate) {
                    UTLT_Info("QER ID: %d key: %d", qerId, key);
                    struct rte_meter_trtcm_params trtcm_params = app_trtcm_params;
                    if (!ftAddEntry(key, trTCMidx)) {
                        UTLT_Warning("FT add failed");
                    }
                    UTLT_Info("Successfully add %d(%d) %d", key, hashFunc(key), trTCMidx);
                    UTLT_Info("Find MBR (DL: %lu) in QERs", qer->maximumBitrate.dl);
                    trtcm_params.pir = qer->maximumBitrate.dl * 1000 / 8;
                    if (qer->flags.guaranteedBitrate) {
                        UTLT_Info("Find GBR (DL: %lu) in QERs", qer->guaranteedBitrate.dl);
                        trtcm_params.cir = qer->guaranteedBitrate.dl * 1000 / 8;
                        rte_meter_trtcm_profile_config(&app_flow_trtcm_profile, &trtcm_params);
                        rte_meter_trtcm_config(&app_flows[trTCMidx], &app_flow_trtcm_profile);
                    }
                    else {
                        trtcm_params.cir = 1;
                        rte_meter_trtcm_profile_config(&app_trtcm_profile, &trtcm_params);
                        rte_meter_trtcm_config(&app_flows[trTCMidx], &app_trtcm_profile);
                    }
                    // config trtcm table 
                    UTLT_Info("TRTCM params: %d %d %d %d\n", trtcm_params.cir, trtcm_params.pir, trtcm_params.cbs, trtcm_params.pbs);
                    trTCMidx ++;
                }
            }
        }
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

UPDK_PDR *
GetPdrByTeid(struct rte_mbuf *pkt, uint32_t td) {
    UpfSession *session = UpfSessionFindByTeid(td);
    UTLT_Assert(session, return NULL, "session not found error");
    UTLT_Assert(session->pdr_list, return NULL, "PDR list not initialized");
    UTLT_Assert(session->pdr_list->len, return NULL, "PDR list contains 0 rules");

    list_node_t *node = session->pdr_list->head;
    UpfPDR *pdr = NULL, *target_pdr = NULL;
    struct rte_ipv4_hdr *iph = NULL;
    uint32_t prefix_len = 0, fd_target = 0;
    while (node) {
        pdr = (UpfPDR *)node->val;
        node = node->next;
        if (pdr->flags.pdi) {
            if (pdr->pdi.flags.sourceInterface) {
                if (SourceInterfaceToPort(pdr->pdi.sourceInterface) == pkt->port) {
                    char *ip_str = strstr(pdr->pdi.sdfFilter.flowDescription, "from");
                    if (ip_str != NULL) {
                        ip_str += 5; // Skip "from "
                        char *end_ptr = strchr(ip_str, ' ');
                        if (end_ptr != NULL) {
                            *end_ptr = '\0'; // Null-terminate the extracted IP
                        }
                        if (strlen(ip_str) > 5) {
                            iph = onvm_pkt_ipv4_hdr(pkt);
                            fd_target = charStr2MaskedIP(ip_str, &prefix_len);
                            if (IP_MASKED(iph->src_addr, prefix_len) == fd_target) {
                                target_pdr = pdr; // Use the found pdr
                                break;
                            }
                        }
                    }
                    if(!target_pdr) {
                        target_pdr = pdr;
                    }
                }
            }
        }
    }
    pdr = target_pdr;
    if (pdr) {
        seid = session->smfSeid;
        pdrId = pdr->pdrId;
        for (int i=0; i<2; i++){
            if (!pdr->qerId[i]) continue;
            UpfQER *qer = NULL;
            uint32_t key = 0, qerId = pdr->qerId[i];
            node = session->qer_list->head;
            while (node) {
                qer = (UpfQER *) node->val;
                node = node->next;
                if (qer->qerId != qerId) continue;
                // new ft entry
                key = pdr->pdi.flags.sdfFilter ? pkt->port + fd_target : pkt->port;
                if (ftSearch(key) < 0 && qer->flags.maximumBitrate) {
                    UTLT_Info("QER ID: %d key: %d", qerId, key);
                    struct rte_meter_trtcm_params trtcm_params = app_trtcm_params;
                    if (!ftAddEntry(key, trTCMidx)) {
                        UTLT_Warning("FT add failed");
                    }
                    UTLT_Info("Successfully add %d(%d) %d", key, hashFunc(key), trTCMidx);
                    UTLT_Info("Find MBR (UL: %lu) in QERs", qer->maximumBitrate.ul);
                    trtcm_params.pir = qer->maximumBitrate.ul * 1000 / 8;
                    if (qer->flags.guaranteedBitrate) {
                        UTLT_Info("Find GBR (UL: %lu) in QERs", qer->guaranteedBitrate.ul);
                        trtcm_params.cir = qer->guaranteedBitrate.ul * 1000 / 8;
                    }
                    else {
                        trtcm_params.cir = 0;
                    }
                    // config trtcm table 
                    UTLT_Info("TRTCM params: %d %d %d %d\n", trtcm_params.cir, trtcm_params.pir, trtcm_params.cbs, trtcm_params.pbs);
                    rte_meter_trtcm_profile_config(&app_trtcm_profile, &trtcm_params);
                    rte_meter_trtcm_config(&app_flows[trTCMidx], &app_trtcm_profile);
                    trTCMidx ++;
                }
            }
        }
    }
    return pdr;
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

static inline void
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

    UPDK_PDR *pdr = NULL;
    // Step 1: Identify if it is a uplink packet or downlink packet
    char *src_address = convertToIpAddress(iph->src_addr);
    UTLT_Info("Src IP is %s\n", src_address);
    char *dst_address = convertToIpAddress(iph->dst_addr);
    UTLT_Info("Dst IP is %s\n", dst_address);

    if (iph->dst_addr == SELF_IP) {  //
        UTLT_Info("It is uplink\n");
        struct rte_udp_hdr *udp_header = onvm_pkt_udp_hdr(pkt);
        if (udp_header == NULL) {
            return 0;
        }
        // invariant(dst_port == GTPV1_PORT);
        // extract TEID from
        // Step 2: Get PDR rule
        uint32_t teid = get_teid_gtp_packet(pkt, udp_header);
        pdr = GetPdrByTeid(pkt, teid);

    } else {
        // UTLT_Info("It is downlink, dst is %d\n", rte_cpu_to_be_32(iph->dst_addr));
        UTLT_Info("It is downlink, dst is %s\n", convertToIpAddress(iph->dst_addr));

        struct timespec ts;
        timespec_get(&ts, TIME_UTC);
        // UTLT_Info("(%d) Time: %ld.%09ld\n", rte_cpu_to_be_32(iph->dst_addr), ts.tv_sec, ts.tv_nsec);
        UTLT_Info("(%s) Time: %ld.%09ld\n", convertToIpAddress(iph->dst_addr), ts.tv_sec, ts.tv_nsec);
        //  Step 2: Get PDR rule
        pdr = GetPdrByUeIpAddress(pkt, rte_cpu_to_be_32(iph->dst_addr));
        GetQerByUEIpAddress(rte_cpu_to_be_32(iph->dst_addr), convertToIpAddress(iph->dst_addr));
        is_dl = true;
    }

    if (!pdr) {
        // UTLT_Error("no PDR found for %d, skip\n", rte_cpu_to_be_32(iph->dst_addr));
        UTLT_Error("no PDR found for %s, skip\n", convertToIpAddress(iph->dst_addr));
        // TODO(vivek): what to do?
        return 0;
    }
    UTLT_Info("Got PDR ID is %u\n", pdr->pdrId);
    rte_pktmbuf_adj(pkt, sizeof(struct rte_ether_hdr));

    UPDK_FAR *far;
    far = pdr->far;
    if (!far) {
        UTLT_Error("There is no FAR related to PDR[%u]\n", pdr->pdrId);
        meta->action = ONVM_NF_ACTION_DROP;
        return 0;
    }

    if (pdr->flags.outerHeaderRemoval) {
        uint16_t outerHeaderLen = 0;
        switch (pdr->outerHeaderRemoval) {
            case OUTER_HEADER_REMOVAL_GTP_IP4: {
                outerHeaderLen = sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr);

                // get gtp_header length
                uint16_t gtp_length = get_gtpu_header_len(pkt);
                outerHeaderLen += gtp_length;

                rte_pktmbuf_adj(pkt, outerHeaderLen);
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

    int status = 0, color_result = 0;
    status = HandlePacketWithFar(pkt, far, pdr->qer, meta);
    if (meta->action == ONVM_NF_ACTION_DROP) {
        UTLT_Info("Action is drop\n");
    } else if (meta->action == ONVM_NF_ACTION_OUT) {
        UTLT_Info("Action is out\n");
    } else {
        UTLT_Trace("Action is unknown\n");
    }
    AttachL2Header(pkt, is_dl);
    if (meta->action == ONVM_NF_ACTION_OUT && is_dl) {
        // check if the UE IP exists in the table and update the token
        int index = findIndexByUeIpAddress(rte_cpu_to_be_32(iph->dst_addr));
        if (index != -1) {
            UTLT_Trace("Update token for UE IP: %s", convertToIpAddress(iph->dst_addr));
            updateTokenbyIndex(index);
        }
        else {
            UTLT_Error("No UE IP found in the table");
            return status;
        }

        // Step 1. trTCM (QoS flow)
        int key, fd_target, prefix_len;
        bool isQos = false;
        uint64_t curr_time = rte_get_tsc_cycles();
        struct rte_meter_trtcm_profile *trtcm_profile = NULL;

        char *ip_str = strstr(pdr->pdi.sdfFilter.flowDescription, "from");
        if (ip_str != NULL) {
            ip_str += 5; // Skip "from "
            char *end_ptr = strchr(ip_str, ' ');
            if (end_ptr != NULL) {
                *end_ptr = '\0'; // Null-terminate the extracted IP
            }
        }

        if (ip_str != NULL && strcmp(ip_str, "any") != 0) {
            isQos = true;
            fd_target = charStr2MaskedIP(ip_str, &prefix_len);
            trtcm_profile = &app_flow_trtcm_profile;
            key = (pdr->pdi.flags.sdfFilter) ? SourceInterfaceToPort(pdr->pdi.sourceInterface) + fd_target : SourceInterfaceToPort(pdr->pdi.sourceInterface);
            color_result = trtcmColorHandle(cal_pktlen, curr_time, ftSearch(key), trtcm_profile);
            if (trtcmPolicer(meta, color_result) > 0)
                UTLT_Error("trTCM Policer error");
        }
        
        // Step 2. bucket (QoS flow)
        if (isQos) {
            if (meta->flags == RTE_COLOR_RED) {
                meta->action = ONVM_NF_ACTION_DROP;
            }
            if (meta->flags == RTE_COLOR_GREEN) {
                ue_table[index].ue_qos_tb_params.tb_tokens -= cal_pktlen;
                meta->action = ONVM_NF_ACTION_OUT;
            }
            if (meta->flags == RTE_COLOR_YELLOW) {
                while (ue_table[index].ue_qos_tb_params.tb_tokens < cal_pktlen) {
                    updateTokenbyIndex(index);
                    usleep(1);
                }
                ue_table[index].ue_qos_tb_params.tb_tokens -= cal_pktlen;
                meta->action = ONVM_NF_ACTION_OUT;      
            }
        }
        // Step 2. bucket (non QoS flow)
        else {
            while (ue_table[index].ue_nqos_tb_params.tb_tokens < cal_pktlen) {
                updateTokenbyIndex(index);
                usleep(1);
            }
            ue_table[index].ue_nqos_tb_params.tb_tokens -= cal_pktlen;
            meta->action = ONVM_NF_ACTION_OUT;
        }
    }
    return status;
}

void
msg_handler(void *msg_data, struct onvm_nf_local_ctx *nf_local_ctx) {
    struct onvm_nf *nf;
    nf = nf_local_ctx->nf;

    if (buffer_length <= 0) {
        return;
    }

    // struct onvm_pkt_meta *meta;
//#ifdef FIX_BUFFER
//    for (i = 0; i < buffer_length; i++) {
        // TODO: (@vivek fix it)
//        Encap(buffer[i]);
//        AttachL2Header(buffer[i], 1); // 1 == Downlink packet
//        meta = onvm_get_pkt_meta(buffer[i]);
//        meta = ONVM_NF_ACTION_OUT;
//    }
//#endif

    struct onvm_configuration *onvm_config = onvm_nflib_get_onvm_config();
    if (onvm_config == NULL) {
        fprintf(stderr, "Error: onvm_nflib_get_onvm_config() returned NULL\n");
        exit(EXIT_FAILURE);
    }
    onvm_pkt_process_tx_batch(nf->nf_tx_mgr, buffer, onvm_config->dynfield_offset, buffer_length, nf);
    onvm_pkt_flush_all_nfs(nf->nf_tx_mgr, nf);
    UTLT_Debug("Sending out %u packets\n", buffer_length);
    buffer_length = 0;
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

    int ret;
    ret = rte_eth_macaddr_get(0, &cn_ue_eth);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Cannot get MAC address: err=%d, port=%u\n", ret, 0);
    ret = rte_eth_macaddr_get(1, &cn_dn_eth);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Cannot get MAC address: err=%d, port=%u\n", ret, 1);

    // Parse DN & AN MAC address from upf_u.txt
    const char *config_path = "upf_u.txt";  // default
    if (argc > arg_offset + 1) {
        config_path = argv[arg_offset + 1];
    }
    printf("Using config path: %s\n", config_path);  // print the path
    parseMAC(config_path);

    // 8c:dc:d4:ac:6c:7d
    dn_eth.addr_bytes[0] = DnMac[0];
    dn_eth.addr_bytes[1] = DnMac[1];
    dn_eth.addr_bytes[2] = DnMac[2];
    dn_eth.addr_bytes[3] = DnMac[3];
    dn_eth.addr_bytes[4] = DnMac[4];
    dn_eth.addr_bytes[5] = DnMac[5];

    // trTCM
    trtcmConfigFlowTables();
    initUeTable();

    UpfSessionPoolInit();
    UeIpToUpfSessionMapInit();
    TeidToUpfSessionMapInit();

    onvm_nflib_run(nf_local_ctx);

    onvm_nflib_stop(nf_local_ctx);
    printf("If we reach here, program is ending\n");
    return 0;
}