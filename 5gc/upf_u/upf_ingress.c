#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>

#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include "upf_u_common.h"
#include "upf_session_dl.h"
#include "upf_cls_ctrl.h"

#include "gtp.h"
#include "upf_context.h"
#include "utlt_debug.h"
#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"

#include "upf_u_config.h"

#define NF_TAG "upf_ingress"

static int
packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta, struct onvm_nf_local_ctx *nf_local_ctx) {
    if (!pkt || !meta) {
        return 0;
    }
    meta->action = ONVM_NF_ACTION_DROP;

    struct rte_ipv4_hdr *iph = onvm_pkt_ipv4_hdr(pkt);
    if (!iph) {
        UTLT_Info("Not IP packet, ignore it\n");
        return 0;
    }

    // Flip to a newly published snapshot if a REQ was received
    UpfClsMaybeFlipAndAck(UPF_CLS_CONS_INGRESS);

    UPDK_PDR *pdr = NULL;

    if (iph->dst_addr == SELF_IP) {
        /* ── Uplink: handle inline ───────────────────────────────────── */
        struct rte_udp_hdr *udp_header = onvm_pkt_udp_hdr(pkt);
        if (!udp_header) {
            return 0;
        }

        uint32_t teid = get_teid_gtp_packet(pkt, udp_header);
        pdr = GetPdrByTeid(pkt, teid);
        if (!pdr) {
            UTLT_Error("no UL PDR found for TEID %u", teid);
            return 0;
        }

        rte_pktmbuf_adj(pkt, sizeof(struct rte_ether_hdr));

        UPDK_FAR *far = pdr->far;
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
                    UTLT_Warning("Unknown or unsupported outer header removal: %u", pdr->outerHeaderRemoval);
            }
        }

        int status = HandlePacketWithFar(pkt, far, pdr->qer, meta);
        AttachL2Header(pkt, false);
        return status;
    }

    /* ── Downlink: enqueue to per-session ring, ownership moves to egress ── */
    uint32_t ue_ip = rte_be_to_cpu_32(iph->dst_addr);
    pdr = GetPdrByUeIpAddress(pkt, ue_ip);
    GetQerByUEIpAddress(ue_ip, convertToIpAddress(iph->dst_addr));
    if (!pdr) {
        UTLT_Error("no DL PDR found for %s, drop", convertToIpAddress(iph->dst_addr));
        return 0;
    }

    UpfSession *session = UpfSessionFindByUeIP(ue_ip);
    if (!session) {
        UTLT_Error("DL PDR found but session missing for UE %s", convertToIpAddress(iph->dst_addr));
        return 0;
    }

    struct rte_ring *ring = UpfSessionEnsureDlRing(session);
    if (!ring) {
        UTLT_Error("DL ring missing for sess_id=%u ue=%s", session->sess_id, convertToIpAddress(iph->dst_addr));
        return 0;
    }

    if (likely(onvm_dl_ts_offset >= 0)) {
        uint64_t *ts = RTE_MBUF_DYNFIELD(pkt, onvm_dl_ts_offset, uint64_t *);
        if (ts) *ts = rte_get_tsc_cycles();
    }

    int rc = rte_ring_mp_enqueue(ring, pkt);
    if (rc < 0) {
        meta->action = ONVM_NF_ACTION_DROP;
        UTLT_Warning("DL enqueue failed (sess_id=%u ring=%p rc=%d)", session->sess_id, (void *)ring, rc);
        return 0;  // manager will free
    }

    // Ownership transferred to egress; do not return it to ONVM TX path
    return 1;
}

void
msg_handler(void *msg_data, struct onvm_nf_local_ctx *nf_local_ctx) {
    Event *e = (Event *)msg_data;

    /* Our NF→NF control path: CP tells us to flip */
    if (e && (uint32_t)e->type == EVT_CLS_GC_REQ) {
        g_cls_local.pending_ver = (uint32_t)e->arg0;
        g_cls_local.flip_pending = 1;      // The actual flip happens at burst boundary

        UTLT_Info("EVT_CLS_GC_REQ: requested_ver=%u ctrl.active=%p ctrl.ver=%u",
          (uint32_t)e->arg0,
          (void*)(g_upf_cls_ctrl ? g_upf_cls_ctrl->active : NULL),
          (g_upf_cls_ctrl ? g_upf_cls_ctrl->version : 0));

        rte_free(e);
        return;
    }

    if (e) rte_free(e);
}

int
main(int argc, char *argv[]) {
    int arg_offset;
    struct onvm_nf_local_ctx *nf_local_ctx;
    struct onvm_nf_function_table *nf_function_table;
    UTLT_SetLogLevel("info");

    nf_local_ctx = onvm_nflib_init_nf_local_ctx();
    onvm_nflib_start_signal_handler(nf_local_ctx, NULL);
    nf_function_table = onvm_nflib_init_nf_function_table();
    nf_function_table->pkt_handler = &packet_handler;
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

    /* Parse DN & AN MAC address from config/upf_u.yaml */
    const char *config_path = "config/upf_u.yaml";

    if (argc > arg_offset + 1) {
        config_path = argv[arg_offset + 1];
    }
    printf("[UPF-Ingress] Using config: %s\n", config_path);
    UpfU_LoadAndParseConfig(config_path);

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
