#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <rte_mbuf.h>
#include <rte_ether.h>

#include "upf_context.h"
#include "onvm_common.h"
#include "upf_events.h"

#ifndef MAX_UE
#define MAX_UE 256
#endif

typedef struct {
    void    *ptr;          // current active snapshot (cls_handle_t*)
    uint32_t ver;          // last applied version
    uint32_t pending_ver;  // version announced by UPF-C via REQ
    uint8_t  flip_pending; // 1 when a flip is requested; cleared after flip
} upf_cls_local_t;

extern upf_cls_local_t g_cls_local;

extern uint8_t  DnMac[RTE_ETHER_ADDR_LEN];
extern uint8_t  AnMac[RTE_ETHER_ADDR_LEN];
extern uint32_t SELF_IP;
extern int16_t  g_access_port;
extern int16_t  g_core_port;
extern int16_t  g_sgi_port;

extern struct rte_ether_addr dn_eth;
extern struct rte_ether_addr cn_dn_eth;
extern struct rte_ether_addr cn_ue_eth;

struct tb_config {
    uint64_t tb_rate;
    uint64_t tb_depth;
    uint64_t tb_tokens;
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

extern struct ue_tb ue_table[MAX_UE];
extern struct rte_meter_trtcm_profile app_trtcm_profile;
extern struct rte_meter_trtcm_profile app_flow_trtcm_profile;
extern struct rte_meter_trtcm app_flows[];

void UpfClsMaybeFlipAndAck(uint32_t consumer_id);

UPDK_PDR *GetPdrByTeid(struct rte_mbuf *pkt, uint32_t td);
UPDK_PDR *GetPdrByUeIpAddress(struct rte_mbuf *pkt, uint32_t ue_ip);
void *GetQerByUEIpAddress(uint32_t ue_ip, char *IP);

void Encap(struct rte_mbuf *pkt, UPDK_FAR *far, UPDK_QER *qer);
int HandlePacketWithFar(struct rte_mbuf *pkt, UPDK_FAR *far, UPDK_QER *qer, struct onvm_pkt_meta *meta);
void AttachL2Header(struct rte_mbuf *pkt, bool is_dl);

int findIndexByUeIpAddress(uint32_t ue_ip);
void updateTokenbyIndex(int index);
char *convertToIpAddress(uint32_t big_endian_value);
uint32_t charStr2MaskedIP(char *str, uint32_t *prefix_val);
int SourceInterfaceToPort(source_interface_t srcIf);
int trtcmConfigFlowTables(void);
int trtcmColorHandle(uint32_t pkt_len, uint64_t time, uint8_t qfi, struct rte_meter_trtcm_profile *target_profile);
int trtcmPolicer(struct onvm_pkt_meta *meta, int color_result);
int ftSearch(uint32_t subnet);
