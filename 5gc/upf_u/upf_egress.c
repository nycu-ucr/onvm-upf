#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_pause.h>
#include <rte_ring.h>

#include "gtp.h"
#include "upf_context.h"
#include "upf_session_dl.h"
#include "upf_u_common.h"
#include "upf_u_config.h"
#include "upf_cls_ctrl.h"

#include "onvm_nflib.h"
#include "onvm_threading.h"
#include "onvm_pkt_helper.h"
#include "utlt_debug.h"

#define NF_TAG "upf_egress"

#define MAX_SESS_REG 4096
#define DL_DEQ_BURST 32

struct session_registry {
    uint32_t ids[MAX_SESS_REG];
    uint32_t count;
    uint32_t cursor;
};

static struct session_registry g_registry = {0};
static uint16_t g_dynfield_offset = 0;

static inline void registry_add(uint32_t sess_id) {
    for (uint32_t i = 0; i < g_registry.count; i++) {
        if (g_registry.ids[i] == sess_id) return;
    }
    if (g_registry.count >= MAX_SESS_REG) {
        UTLT_Warning("Session registry full, cannot add sess_id=%u", sess_id);
        return;
    }
    g_registry.ids[g_registry.count++] = sess_id;
}

static inline void registry_remove(uint32_t sess_id) {
    for (uint32_t i = 0; i < g_registry.count; i++) {
        if (g_registry.ids[i] != sess_id) continue;
        g_registry.ids[i] = g_registry.ids[g_registry.count - 1];
        g_registry.count--;
        if (g_registry.cursor >= g_registry.count) g_registry.cursor = 0;
        return;
    }
}

static inline void registry_next_cursor(void) {
    if (g_registry.count == 0) {
        g_registry.cursor = 0;
        return;
    }
    g_registry.cursor = (g_registry.cursor + 1) % g_registry.count;
}

static int
process_downlink_pkt(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta) {
    if (!pkt || !meta) return 0;

    uint32_t cal_pktlen = pkt->pkt_len - sizeof(struct rte_ether_hdr) -
                          sizeof(struct rte_ipv4_hdr) - sizeof(struct rte_udp_hdr);

    struct rte_ipv4_hdr *iph = onvm_pkt_ipv4_hdr(pkt);
    if (!iph) {
        rte_pktmbuf_free(pkt);
        return 0;
    }

    uint32_t ue_ip = rte_be_to_cpu_32(iph->dst_addr);
    UPDK_PDR *pdr = GetPdrByUeIpAddress(pkt, ue_ip);
    GetQerByUEIpAddress(ue_ip, convertToIpAddress(iph->dst_addr));
    if (!pdr) {
        UTLT_Error("no DL PDR found for %s, drop", convertToIpAddress(iph->dst_addr));
        rte_pktmbuf_free(pkt);
        return 0;
    }

    rte_pktmbuf_adj(pkt, sizeof(struct rte_ether_hdr));

    UPDK_FAR *far = pdr->far;
    if (!far) {
        UTLT_Error("There is no FAR related to PDR[%u]\n", pdr->pdrId);
        rte_pktmbuf_free(pkt);
        return 0;
    }

    if (pdr->flags.outerHeaderRemoval) {
        uint16_t outerHeaderLen = 0;
        switch (pdr->outerHeaderRemoval) {
            case OUTER_HEADER_REMOVAL_GTP_IP4: {
                outerHeaderLen = sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr);
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
                UTLT_Warning("Unknown or unsupported outer header removal: %u", pdr->outerHeaderRemoval);
        }
    }

    int status = HandlePacketWithFar(pkt, far, pdr->qer, meta);
    AttachL2Header(pkt, true);

    if (meta->action == ONVM_NF_ACTION_OUT) {
        /* QoS handling copied from legacy fast path */
        int index = findIndexByUeIpAddress(ue_ip);
        if (index != -1) {
            updateTokenbyIndex(index);
        }

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
            int color_result = trtcmColorHandle(cal_pktlen, curr_time, ftSearch(key), trtcm_profile);
            if (trtcmPolicer(meta, color_result) > 0)
                UTLT_Error("trTCM Policer error");
        }

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
        } else {
            while (ue_table[index].ue_nqos_tb_params.tb_tokens < cal_pktlen) {
                updateTokenbyIndex(index);
                usleep(1);
            }
            ue_table[index].ue_nqos_tb_params.tb_tokens -= cal_pktlen;
            meta->action = ONVM_NF_ACTION_OUT;
        }
    }

    if (meta->action != ONVM_NF_ACTION_OUT) {
        rte_pktmbuf_free(pkt);
        return 0;
    }
    return 1;
}

static void
drain_session(uint32_t sess_id, struct onvm_nf_local_ctx *nf_local_ctx,
              struct rte_mbuf **tx_buf, uint16_t *tx_count) {
    UpfSession *session = UpfSessionFindBySeid(sess_id);
    if (!session) {
        registry_remove(sess_id);
        return;
    }

    if (UpfSessionIsBuffered(session)) {
        return;
    }

    struct rte_ring *ring = __atomic_load_n(&session->dl_ring, __ATOMIC_ACQUIRE);
    if (!ring) return;

    struct rte_mbuf *burst[DL_DEQ_BURST];
    while (rte_ring_sc_dequeue_burst(ring, (void **)burst, DL_DEQ_BURST, NULL) > 0) {
        for (uint16_t i = 0; i < DL_DEQ_BURST; i++) {
            struct rte_mbuf *pkt = burst[i];
            if (!pkt) break;

            struct onvm_pkt_meta *meta = onvm_get_pkt_meta(pkt, g_dynfield_offset);
            meta->action = ONVM_NF_ACTION_DROP;
            if (process_downlink_pkt(pkt, meta)) {
                tx_buf[(*tx_count)++] = pkt;
            }

            if (*tx_count == PACKET_READ_SIZE) {
                struct onvm_nf *nf = nf_local_ctx->nf;
                onvm_pkt_process_tx_batch(nf->nf_tx_mgr, tx_buf, g_dynfield_offset, *tx_count, nf);
                *tx_count = 0;
            }
        }
    }
}

void
msg_handler(void *msg_data, struct onvm_nf_local_ctx *nf_local_ctx) {
    Event *e = (Event *)msg_data;
    if (!e) return;

    switch ((uint32_t)e->type) {
        case EVT_CLS_GC_REQ:
            g_cls_local.pending_ver = (uint32_t)e->arg0;
            g_cls_local.flip_pending = 1;
            UTLT_Info("EVT_CLS_GC_REQ: requested_ver=%u ctrl.active=%p ctrl.ver=%u",
                (uint32_t)e->arg0,
                (void*)(g_upf_cls_ctrl ? g_upf_cls_ctrl->active : NULL),
                (g_upf_cls_ctrl ? g_upf_cls_ctrl->version : 0));
            rte_free(e);
            return;
        case UPF_EVENT_REGISTER_SESSION:
            registry_add((uint32_t)e->arg0);
            break;
        case UPF_EVENT_DELETE_SESSION:
            registry_remove((uint32_t)e->arg0);
            break;
        case UPF_EVENT_SET_BUFFER:
        case UPF_EVENT_CLEAR_AND_DRAIN: {
            uint32_t sess_id = (uint32_t)e->arg0;
            UpfSession *s = UpfSessionFindBySeid(sess_id);
            if (s) {
                UpfSessionSetBuffering(s, (e->type == UPF_EVENT_SET_BUFFER) ? 1 : 0);
            }
            break;
        }
        default:
            break;
    }

    rte_free(e);
}

static int
pkt_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta, struct onvm_nf_local_ctx *nf_local_ctx) {
    // Egress polls rings; any stray packets from manager are dropped.
    if (pkt) rte_pktmbuf_free(pkt);
    return 0;
}

static int
egress_tick(struct onvm_nf_local_ctx *nf_local_ctx) {
    UpfClsMaybeFlipAndAck(UPF_CLS_CONS_EGRESS);

    if (g_registry.count == 0)
        return 0;

    struct rte_mbuf *tx_buf[PACKET_READ_SIZE];
    uint16_t tx_count = 0;

    uint32_t visits = g_registry.count;
    while (visits--) {
        uint32_t idx = g_registry.cursor;
        uint32_t sess_id = g_registry.ids[idx];
        registry_next_cursor();
        drain_session(sess_id, nf_local_ctx, tx_buf, &tx_count);
    }

    if (tx_count > 0) {
        struct onvm_nf *nf = nf_local_ctx->nf;
        onvm_pkt_process_tx_batch(nf->nf_tx_mgr, tx_buf, g_dynfield_offset, tx_count, nf);
        onvm_pkt_flush_all_nfs(nf->nf_tx_mgr, nf);
    }

    return 0;
}

int
main(int argc, char *argv[]) {
    int arg_offset;
    struct onvm_nf_local_ctx *nf_local_ctx;
    struct onvm_nf_function_table *nf_function_table;
    UTLT_SetLogLevel("warning"); // to eliminate log print influenced jitter

    nf_local_ctx = onvm_nflib_init_nf_local_ctx();
    onvm_nflib_start_signal_handler(nf_local_ctx, NULL);
    nf_function_table = onvm_nflib_init_nf_function_table();
    nf_function_table->msg_handler = &msg_handler;

    if ((arg_offset = onvm_nflib_init(argc, argv, NF_TAG, nf_local_ctx, nf_function_table)) < 0) {
        onvm_nflib_stop(nf_local_ctx);
        if (arg_offset == ONVM_SIGNAL_TERMINATION) {
            printf("Exiting due to user termination\n");
            return 0;
        } else {
            rte_exit(EXIT_FAILURE, "Failed ONVM init\n");
        }
    }

    struct onvm_configuration *onvm_config = onvm_nflib_get_onvm_config();
    if (!onvm_config) {
        rte_exit(EXIT_FAILURE, "onvm_nflib_get_onvm_config() returned NULL\n");
    }
    g_dynfield_offset = onvm_config->dynfield_offset;

    if (UpfClsCtrlInit() < 0) {
        rte_exit(EXIT_FAILURE, "CLS_CTRL memzone init failed\n");
    }

    int ret;
    ret = rte_eth_macaddr_get(0, &cn_ue_eth);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Cannot get MAC address: err=%d, port=%u\n", ret, 0);
    ret = rte_eth_macaddr_get(1, &cn_dn_eth);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Cannot get MAC address: err=%d, port=%u\n", ret, 1);

    const char *config_path = "config/upf_u.yaml";
    if (argc > arg_offset + 1) {
        config_path = argv[arg_offset + 1];
    }
    printf("[UPF-Egress] Using config: %s\n", config_path);
    UpfU_LoadAndParseConfig(config_path);

    dn_eth.addr_bytes[0] = DnMac[0];
    dn_eth.addr_bytes[1] = DnMac[1];
    dn_eth.addr_bytes[2] = DnMac[2];
    dn_eth.addr_bytes[3] = DnMac[3];
    dn_eth.addr_bytes[4] = DnMac[4];
    dn_eth.addr_bytes[5] = DnMac[5];

    trtcmConfigFlowTables();
    initUeTable();

    UpfSessionPoolInit();
    UeIpToUpfSessionMapInit();
    TeidToUpfSessionMapInit();

    struct onvm_nf *nf = nf_local_ctx->nf;
    onvm_threading_core_affinitize(nf->thread_info.core);

    printf("Sending NF_READY message to manager...\n");
    if (onvm_nflib_nf_ready(nf) != 0) {
        rte_exit(EXIT_FAILURE, "Unable to message manager\n");
    }

    while (rte_atomic16_read(&nf_local_ctx->keep_running)) {
        onvm_nflib_dequeue_messages(nf_local_ctx);
        egress_tick(nf_local_ctx);
        rte_pause();
    }

    onvm_nflib_stop(nf_local_ctx);
    printf("If we reach here, program is ending\n");
    return 0;
}
