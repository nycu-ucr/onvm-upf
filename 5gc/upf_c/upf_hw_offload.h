/*
 * upf_hw_offload.h — UPF-C helper: build an hw_offload_msg from a
 *                     committed PDR and send it to the Host Agent.
 *
 * Included by n4_onvm_pfcp_handler.c *only*.  Pure inline, no .c file.
 * Keeps upf_c free of any DOCA headers — only uses DPDK + ONVM + UPDK.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#include <rte_malloc.h>
#include <rte_atomic.h>

#include "onvm_nflib.h"

#include "upf_context.h"
#include "upf_events.h"
#include "updk/rule_pdr.h"
#include "updk/rule_far.h"
#include "updk/rule_qer.h"

#include "hw_offload_msg.h"
#include "pdr_hash_bypass.h"   /* phb_parse_flow_description, phb_candidate_t */

#ifdef __cplusplus
extern "C" {
#endif

/* ── Globally unique hw_rule_id counter (atomic, never reused) ──── */
static rte_atomic32_t g_hw_rule_id_gen = RTE_ATOMIC32_INIT(0);

static inline uint32_t hw_offload_next_rule_id(void) {
    return (uint32_t)rte_atomic32_add_return(&g_hw_rule_id_gen, 1);
}


/* ═══════════════════════════════════════════════════════════════════
 *  upf_build_and_send_hw_offload() — called from UpfN4HandleCreatePdr
 *  AFTER the PDR is fully resolved (FAR, QER, SDF precompiled) and
 *  registered to the session.
 *
 *  Only sends for FORWARD rules with a valid TEID (UL) or UE-IP (DL).
 * ═══════════════════════════════════════════════════════════════════ */
static inline int
upf_build_and_send_hw_offload(const UPDK_PDR *pdr)
{
    /* ── Guard: only offload FORWARD rules ─────────────────────────── */
    if (!pdr || !pdr->far)
        return 0;

    const UPDK_FAR *far = pdr->far;
    if (!(far->applyAction & UPDK_FAR_APPLY_ACTION_FORW))
        return 0;   /* DROP / BUFF / NOCP — not offloadable Phase 1 */

    /* ── Determine direction from sourceInterface ──────────────────── */
    uint8_t direction;
    if (pdr->pdi.sourceInterface == UPDK_INTERFACE_VALUE_ACCESS) {
        direction = HW_DIR_UPLINK;
        /* UL needs a TEID to match on */
        if (!pdr->pdi.flags.fTeid || pdr->pdi.fTeid.teid == 0)
            return 0;
    } else if (pdr->pdi.sourceInterface == UPDK_INTERFACE_VALUE_CORE ||
               pdr->pdi.sourceInterface == UPDK_INTERFACE_VALUE_N6_LAN) {
        direction = HW_DIR_DOWNLINK;
        /* DL needs a UE IP to match on */
        if (!pdr->pdi.flags.ueIpAddress || !pdr->pdi.ueIpAddress.flags.v4)
            return 0;
    } else {
        return 0;   /* CP / LI interface — not offloaded */
    }

    /* ── Allocate message from hugepage (visible to Host Agent) ────── */
    hw_offload_msg_t *msg = (hw_offload_msg_t *)rte_calloc(
        "hw_offload", 1, sizeof(hw_offload_msg_t), RTE_CACHE_LINE_SIZE);
    if (!msg) {
        UTLT_Error("hw_offload: rte_calloc failed for PDR %u", pdr->pdrId);
        return -1;
    }

    /* ── Header ─────────────────────────────────────────────────────── */
    msg->magic       = HW_OFFLOAD_MAGIC;
    msg->op          = HW_OP_CREATE;
    msg->direction   = direction;
    msg->pdr_id      = pdr->pdrId;
    msg->hw_rule_id  = hw_offload_next_rule_id();
    msg->precedence  = pdr->precedence;

    /* ── Match: GTP tunnel (TEID is HOST order in UPDK) ────────────── */
    if (pdr->pdi.flags.fTeid) {
        msg->teid      = pdr->pdi.fTeid.teid;       /* HOST order */
        msg->fteid_ipv4 = pdr->pdi.fTeid.ipv4;       /* NBO */
    }

    /* ── Match: UE IP (NBO in UPDK) ────────────────────────────────── */
    if (pdr->pdi.flags.ueIpAddress && pdr->pdi.ueIpAddress.flags.v4)
        msg->ue_ipv4 = pdr->pdi.ueIpAddress.ipv4;   /* NBO */

    /* ── Match: QFI ────────────────────────────────────────────────── */
    if (pdr->pdi.flags.qfi)
        msg->qfi = pdr->pdi.qfi;

    /* ── Encap QFI (from QER, for GTP extension header in DL encap) ── */
    if (pdr->qer && pdr->qer->flags.qosFlowIdentifier)
        msg->encap_qfi = pdr->qer->qosFlowIdentifier & 0x3F;

    /* ── Match: SDF 5-tuple ────────────────────────────────────────── */
    if (pdr->pdi.flags.sdfFilter && pdr->pdi.sdfFilter.flags.fd) {
        phb_candidate_t tmp;
        memset(&tmp, 0, sizeof(tmp));

        /* ue_ip must be set for "assigned" keyword resolution */
        if (pdr->pdi.flags.ueIpAddress && pdr->pdi.ueIpAddress.flags.v4)
            tmp.ue_ip = ntohl(pdr->pdi.ueIpAddress.ipv4.s_addr);

        phb_parse_flow_description(pdr->pdi.sdfFilter.flowDescription, &tmp);

        msg->has_sdf      = 1;
        msg->sdf_proto    = tmp.sdf_proto;
        msg->sdf_src_ip   = tmp.sdf_src_ip;      /* HOST order */
        msg->sdf_dst_ip   = tmp.sdf_dst_ip;      /* HOST order */
        msg->sdf_src_pref = tmp.sdf_src_pref;
        msg->sdf_dst_pref = tmp.sdf_dst_pref;
        msg->sdf_src_port = tmp.sdf_src_port;     /* HOST order */
        msg->sdf_dst_port = tmp.sdf_dst_port;     /* HOST order */
    }

    /* ── FAR: action + outer header ────────────────────────────────── */
    msg->apply_action = far->applyAction;

    if (pdr->flags.outerHeaderRemoval)
        msg->outer_hdr_removal = pdr->outerHeaderRemoval;
    else
        msg->outer_hdr_removal = 0xFF;   /* not present */

    if (far->flags.forwardingParameters &&
        far->forwardingParameters.flags.outerHeaderCreation) {
        const UPDK_OuterHeaderCreation *ohc =
            &far->forwardingParameters.outerHeaderCreation;
        msg->ohc_desc = (uint8_t)ohc->description;
        msg->ohc_teid = ohc->teid;           /* HOST order (ntohl in UPDK) */
        msg->ohc_ipv4 = ohc->ipv4;           /* NBO */
    }

    /* ── QER: bit-rates ────────────────────────────────────────────── */
    if (pdr->qer_count > 0 && pdr->qers[0]) {
        const UPDK_QER *qer = pdr->qers[0];
        if (qer->flags.maximumBitrate) {
            msg->mbr_ul = qer->maximumBitrate.ul;
            msg->mbr_dl = qer->maximumBitrate.dl;
        }
        if (qer->flags.guaranteedBitrate) {
            msg->gbr_ul = qer->guaranteedBitrate.ul;
            msg->gbr_dl = qer->guaranteedBitrate.dl;
        }
    }

    /* ── Send to Host Agent via ONVM lockless ring ─────────────────── */
    int rc = onvm_nflib_send_msg_to_nf(HOST_AGENT_SERVICE_ID, msg);
    if (rc < 0) {
        UTLT_Warning("hw_offload: send to Host Agent failed (rc=%d) for "
                     "PDR %u, hw_rule_id %u — SW fallback active",
                     rc, msg->pdr_id, msg->hw_rule_id);
        rte_free(msg);   /* sender frees on failure per ONVM convention */
        return rc;
    }

    UTLT_Info("hw_offload: sent %s PDR %u → hw_rule_id %u, teid=0x%x, "
              "ue_ip=%08x, action=%u",
              direction == HW_DIR_UPLINK ? "UL" : "DL",
              msg->pdr_id, msg->hw_rule_id, msg->teid,
              msg->ue_ipv4.s_addr, msg->apply_action);

    return 0;
}

#ifdef __cplusplus
}
#endif
