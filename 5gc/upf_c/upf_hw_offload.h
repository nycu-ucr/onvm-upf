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

#ifdef __cplusplus
extern "C" {
#endif

/* ── SDF flow-description parser ── */

typedef struct {
    uint32_t ue_ip;         /* UE IP in host byte order (for "assigned") */
    uint8_t  sdf_proto;     /* IP protocol (0 = any/"ip")               */
    uint32_t sdf_src_ip;    /* source IP host order (0 = any)            */
    uint32_t sdf_dst_ip;    /* dest IP host order (0 = any)              */
    uint8_t  sdf_src_pref;  /* source prefix length (32 = exact)         */
    uint8_t  sdf_dst_pref;  /* dest prefix length (32 = exact)           */
    uint16_t sdf_src_port;  /* source port (0 = wildcard)                */
    uint16_t sdf_dst_port;  /* dest port (0 = wildcard)                  */
} sdf_parsed_t;

static inline uint32_t
sdf_parse_ip_prefix(const char *s, uint8_t *pref_out)
{
    char buf[32];
    size_t len = strlen(s);
    if (len >= sizeof(buf)) return 0;
    memcpy(buf, s, len + 1);

    char *slash = strchr(buf, '/');
    if (slash) {
        *slash = '\0';
        int p = atoi(slash + 1);
        *pref_out = (p > 0 && p <= 32) ? (uint8_t)p : 32;
    } else {
        *pref_out = 32;
    }

    struct in_addr a;
    if (inet_pton(AF_INET, buf, &a) != 1) {
        *pref_out = 0;
        return 0;
    }
    return ntohl(a.s_addr);
}

/* Parse a 3GPP flow description (IPFilterRule per TS 29.212 / RFC 6733)
 * into the SDF fields for the HW offload message.
 *
 * Format:  action dir proto from src [srcport] to dst [dstport]
 * c->ue_ip must already be set before calling. */
static inline void
sdf_parse_flow_description(const char *fd, sdf_parsed_t *c)
{
    if (!fd || !*fd) return;

    char buf[64];
    size_t fdlen = strlen(fd);
    if (fdlen >= sizeof(buf)) fdlen = sizeof(buf) - 1;
    memcpy(buf, fd, fdlen);
    buf[fdlen] = '\0';

    char *saveptr = NULL;
    char *tok;

    tok = strtok_r(buf, " ", &saveptr); if (!tok) return;  /* action */
    tok = strtok_r(NULL, " ", &saveptr); if (!tok) return; /* dir    */

    tok = strtok_r(NULL, " ", &saveptr); if (!tok) return; /* proto  */
    c->sdf_proto = (strcmp(tok, "ip") == 0) ? 0 : (uint8_t)atoi(tok);

    tok = strtok_r(NULL, " ", &saveptr); if (!tok) return; /* "from" */

    tok = strtok_r(NULL, " ", &saveptr); if (!tok) return; /* src    */
    if (strcmp(tok, "any") == 0) {
        c->sdf_src_ip = 0; c->sdf_src_pref = 0;
    } else if (strcmp(tok, "assigned") == 0) {
        c->sdf_src_ip = c->ue_ip; c->sdf_src_pref = c->ue_ip ? 32 : 0;
    } else {
        c->sdf_src_ip = sdf_parse_ip_prefix(tok, &c->sdf_src_pref);
    }

    tok = strtok_r(NULL, " ", &saveptr); if (!tok) return;
    if (strcmp(tok, "to") != 0) {
        c->sdf_src_port = (uint16_t)atoi(tok);
        tok = strtok_r(NULL, " ", &saveptr); if (!tok) return; /* "to" */
    }

    tok = strtok_r(NULL, " ", &saveptr); if (!tok) return; /* dst    */
    if (strcmp(tok, "any") == 0) {
        c->sdf_dst_ip = 0; c->sdf_dst_pref = 0;
    } else if (strcmp(tok, "assigned") == 0) {
        c->sdf_dst_ip = c->ue_ip; c->sdf_dst_pref = c->ue_ip ? 32 : 0;
    } else {
        c->sdf_dst_ip = sdf_parse_ip_prefix(tok, &c->sdf_dst_pref);
    }

    tok = strtok_r(NULL, " ", &saveptr);
    if (tok && tok[0] >= '0' && tok[0] <= '9')
        c->sdf_dst_port = (uint16_t)atoi(tok);
}

/* ── hw_rule_id generator (atomic, 24-bit, wrapping) ────────────── */
/*
 * IDs are masked to 24 bits (max 16.7M) so that byte 3 is always 0x00.
 * This guarantees htonl(id) has bits 0-1 == 0 on LE, which the DPU
 * pipeline needs for reinject marker tagging (bits 0-1 of pkt_meta).
 *
 * With at most MAX_HW_RULES (4096) concurrently active rules,
 * wrap-around reuse after 16.7M allocations is safe.  The DPU-side
 * insert_rule uniqueness check (find_record) prevents collision.
 */
static rte_atomic32_t g_hw_rule_id_gen = RTE_ATOMIC32_INIT(0);

static inline uint32_t hw_offload_next_rule_id(void) {
    uint32_t id = (uint32_t)rte_atomic32_add_return(&g_hw_rule_id_gen, 1)
                  & 0x00FFFFFFu;
    return id ? id : 1;  /* 0 is reserved for "not offloaded" */
}

/* ── hw_qer_id generator (atomic, 64-bit, never wraps) ──────────────
 * Minted at CreateQER and stored on the QER object.  The enforcement
 * identity is one QoS flow in one direction — (SEID, PFCP qer_id) —
 * for which this is the globally unique handle: the PFCP qer_id alone
 * repeats across sessions, so two UEs would collide on one enforcement
 * instance.  The DPU keys its shared meter and shaper slot on
 * (hw_qer_id, direction).  0 = "no QER identity". */
static rte_atomic64_t g_hw_qer_id_gen = RTE_ATOMIC64_INIT(0);

static inline uint64_t hw_offload_next_qer_id(void) {
    return (uint64_t)rte_atomic64_add_return(&g_hw_qer_id_gen, 1);
}

/* ── Session-QER derivation (per direction) ─────────────────────────
 * PFCP carries no Session-AMBR IE; the SMF expresses it as a QER.  Take
 * a QER with a maximum bit rate present and a guaranteed bit rate
 * absent as the session QER, largest maximum rate (in this direction)
 * winning if several match.  Assumption on record: no flow-level
 * non-GBR QER carries a maximum rate larger than the session's own —
 * the chosen id and rate are logged so the question is answerable from
 * a run. */
static inline UpfQER *
upf_session_qer_for_dir(UpfSession *session, uint8_t direction)
{
    if (!session || !session->qer_list)
        return NULL;

    UpfQER *best = NULL;
    uint64_t best_mbr = 0;
    list_iterator_t *it = list_iterator_new(session->qer_list, LIST_HEAD);
    list_node_t *n;
    while (it && (n = list_iterator_next(it))) {
        UpfQER *q = (UpfQER *)n->val;
        if (!q || !q->flags.maximumBitrate || q->flags.guaranteedBitrate)
            continue;
        uint64_t mbr = (direction == HW_DIR_UPLINK)
                     ? q->maximumBitrate.ul : q->maximumBitrate.dl;
        if (mbr > best_mbr) {
            best_mbr = mbr;
            best = q;
        }
    }
    if (it) list_iterator_destroy(it);

    if (best)
        UTLT_Debug("hw_offload: session QER derived (%s): qerId=%u "
                   "hw_qer_id=%lu mbr=%lu kbps",
                   direction == HW_DIR_UPLINK ? "UL" : "DL",
                   best->qerId, (unsigned long)best->hw_qer_id,
                   (unsigned long)best_mbr);
    return best;
}

/* Does this PDR belong to the GBR tier (its resolved QER carries a
 * nonzero guaranteed rate)? */
static inline int
upf_pdr_is_gbr(const UPDK_PDR *pdr)
{
    return pdr && pdr->qer && pdr->qer->flags.guaranteedBitrate &&
           (pdr->qer->guaranteedBitrate.ul || pdr->qer->guaranteedBitrate.dl);
}

/* ── QER identity + rate stamping ───────────────────────────────────
 * One resolution used by every sender so all messages of a QoS flow
 * carry the same identity and rates:
 *   GBR PDR      → the flow QER's hw_qer_id and its MBR/GBR.
 *   non-GBR PDR  → the session QER's hw_qer_id and its MBR (gbr=0) —
 *                  UpfPdrSelectQfiQer resolves at most one QER per PDR
 *                  and discards the session QER whenever a flow-level
 *                  QER is present, so the DPU cannot recover the
 *                  binding on its own.  Falls back to the flow QER's
 *                  own identity/rates when no session QER exists.
 * session == NULL suppresses the session-QER derivation (used by the
 * RemoveQER path, which intentionally sends zero rates to detach). */
static inline void
upf_stamp_qer_identity(UpfSession *session, const UPDK_PDR *pdr,
                       uint8_t direction, hw_offload_msg_t *msg)
{
    const UPDK_QER *qer = pdr ? pdr->qer : NULL;

    if (!upf_pdr_is_gbr(pdr)) {
        UpfQER *sq = upf_session_qer_for_dir(session, direction);
        if (sq)
            qer = sq;
    }
    if (!qer)
        return;   /* no QER at all → no meter, hw_qer_id stays 0 */

    msg->hw_qer_id = qer->hw_qer_id;
    if (qer->flags.maximumBitrate) {
        msg->mbr_ul = qer->maximumBitrate.ul;
        msg->mbr_dl = qer->maximumBitrate.dl;
    }
    if (qer->flags.guaranteedBitrate) {
        msg->gbr_ul = qer->guaranteedBitrate.ul;
        msg->gbr_dl = qer->guaranteedBitrate.dl;
    }
}


/* ═══════════════════════════════════════════════════════════════════
 *  upf_build_and_send_hw_offload() — called from UpfN4HandleCreatePdr
 *  AFTER the PDR is fully resolved (FAR, QER, SDF precompiled) and
 *  registered to the session.
 *
 *  Only sends for FORWARD rules with a valid TEID (UL) or UE-IP (DL).
 * ═══════════════════════════════════════════════════════════════════ */
static inline int
upf_build_and_send_hw_offload(UpfSession *session, UPDK_PDR *pdr)
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

    if (!Self()->hostAgentOffload)
        return 0;

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
        sdf_parsed_t tmp;
        memset(&tmp, 0, sizeof(tmp));

        /* ue_ip must be set for "assigned" keyword resolution */
        if (pdr->pdi.flags.ueIpAddress && pdr->pdi.ueIpAddress.flags.v4)
            tmp.ue_ip = ntohl(pdr->pdi.ueIpAddress.ipv4.s_addr);

        sdf_parse_flow_description(pdr->pdi.sdfFilter.flowDescription, &tmp);

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

    /* ── QER: identity + bit-rates ─────────────────────────────────── */
    /* GBR PDR: pdr->qer (resolved by UpfPdrSelectQfiQer — the same QER
     * used for encap_qfi above).  Non-GBR PDR: the derived session QER's
     * identity and MBR ride instead, so all of the session's non-GBR
     * PDRs share one DPU meter. */
    upf_stamp_qer_identity(session, pdr, direction, msg);

    uint16_t pdr_id = msg->pdr_id;
    uint32_t hw_rule_id = msg->hw_rule_id;
    uint32_t teid = msg->teid;
    uint32_t ue_ip = msg->ue_ipv4.s_addr;
    uint8_t apply_action = msg->apply_action;

    /* ── Send to Host Agent via ONVM lockless ring ─────────────────── */
    int rc = onvm_nflib_send_msg_to_nf(HOST_AGENT_SERVICE_ID, msg);
    if (rc < 0) {
        UTLT_Info("hw_offload: Host Agent unavailable (rc=%d) for "
                  "PDR %u, hw_rule_id %u — continuing with SW fallback",
                  rc, pdr_id, hw_rule_id);
        rte_free(msg);   /* sender frees on failure per ONVM convention */
        return 0;
    }

    UTLT_Info("hw_offload: sent %s PDR %u → hw_rule_id %u, teid=0x%x, "
              "ue_ip=%08x, action=%u",
              direction == HW_DIR_UPLINK ? "UL" : "DL",
              pdr_id, hw_rule_id, teid, ue_ip, apply_action);

    /* Store hw_rule_id back into PDR for future update/delete references */
    pdr->hw_rule_id = hw_rule_id;

    return 0;
}


/* ═══════════════════════════════════════════════════════════════════
 *  upf_send_hw_offload_delete() — send HW_OP_DELETE for a rule
 * ═══════════════════════════════════════════════════════════════════ */
static inline int
upf_send_hw_offload_delete(uint32_t hw_rule_id)
{
    if (!Self()->hostAgentOffload)
        return 0;

    hw_offload_msg_t *msg = (hw_offload_msg_t *)rte_calloc(
        "hw_offload", 1, sizeof(hw_offload_msg_t), RTE_CACHE_LINE_SIZE);
    if (!msg) {
        UTLT_Error("hw_offload_delete: rte_calloc failed for hw_rule_id %u",
                   hw_rule_id);
        return -1;
    }

    msg->magic      = HW_OFFLOAD_MAGIC;
    msg->op         = HW_OP_DELETE;
    msg->hw_rule_id = hw_rule_id;

    int rc = onvm_nflib_send_msg_to_nf(HOST_AGENT_SERVICE_ID, msg);
    if (rc < 0) {
        UTLT_Warning("hw_offload_delete: send failed (rc=%d) hw_rule_id %u",
                     rc, hw_rule_id);
        rte_free(msg);
        return rc;
    }

    UTLT_Info("hw_offload: sent DELETE hw_rule_id %u", hw_rule_id);
    return 0;
}


/* ═══════════════════════════════════════════════════════════════════
 *  upf_send_hw_offload_update_far() — send HW_OP_UPDATE_FAR
 *  Called when UpdateFAR changes apply_action or OHC parameters.
 *  Iterates through pdr_list externally; this sends for ONE PDR.
 * ═══════════════════════════════════════════════════════════════════ */
static inline int
upf_send_hw_offload_update_far(UpfSession *session, UPDK_PDR *pdr,
                               const UPDK_FAR *far)
{
    if (!pdr || pdr->hw_rule_id == 0 || !far)
        return 0;

    if (!Self()->hostAgentOffload)
        return 0;

    /* ── UL buffering omission ──────────────────────────────────────
     * When the UE is idle/suspended (BUFF asserted by SMF), only
     * downlink traffic needs buffering — the UE cannot send uplink
     * while idle.  Skip the BUFF notification so the DPU keeps the
     * UL flow on its fast path, avoiding pointless ARM-side buffer
     * registration and the BUFF→FORW drain/reinject overhead.      */
    if ((far->applyAction & UPDK_FAR_APPLY_ACTION_BUFF) &&
        pdr->pdi.sourceInterface == UPDK_INTERFACE_VALUE_ACCESS) {
        UTLT_Info("hw_offload: skip BUFF for UL PDR %u (hw_rule_id %u) "
                  "— UL buffering not applicable",
                  pdr->pdrId, pdr->hw_rule_id);
        return 0;
    }

    hw_offload_msg_t *msg = (hw_offload_msg_t *)rte_calloc(
        "hw_offload", 1, sizeof(hw_offload_msg_t), RTE_CACHE_LINE_SIZE);
    if (!msg) {
        UTLT_Error("hw_offload_update_far: rte_calloc failed hw_rule_id %u",
                   pdr->hw_rule_id);
        return -1;
    }

    msg->magic       = HW_OFFLOAD_MAGIC;
    msg->op          = HW_OP_UPDATE_FAR;
    msg->hw_rule_id  = pdr->hw_rule_id;
    msg->pdr_id      = pdr->pdrId;

    /* Direction from PDI sourceInterface */
    if (pdr->pdi.sourceInterface == UPDK_INTERFACE_VALUE_ACCESS)
        msg->direction = HW_DIR_UPLINK;
    else
        msg->direction = HW_DIR_DOWNLINK;

    /* FAR action + OHC */
    msg->apply_action = far->applyAction;
    if (far->flags.forwardingParameters &&
        far->forwardingParameters.flags.outerHeaderCreation) {
        const UPDK_OuterHeaderCreation *ohc =
            &far->forwardingParameters.outerHeaderCreation;
        msg->ohc_desc = (uint8_t)ohc->description;
        msg->ohc_teid = ohc->teid;
        msg->ohc_ipv4 = ohc->ipv4;
    }

    /* QER identity + rates — carry MBR/GBR on the BUFF/FORW message so
     * the DPU buffer allocator has a per-flow cold-start seed at BUFF
     * entry (no DPU-side QoS cache needed).  Mirrors
     * upf_send_hw_offload_update_qer. */
    upf_stamp_qer_identity(session, pdr, msg->direction, msg);

    int rc = onvm_nflib_send_msg_to_nf(HOST_AGENT_SERVICE_ID, msg);
    if (rc < 0) {
        UTLT_Warning("hw_offload_update_far: send failed (rc=%d) "
                     "hw_rule_id %u", rc, pdr->hw_rule_id);
        rte_free(msg);
        return rc;
    }

    UTLT_Info("hw_offload: sent UPDATE_FAR hw_rule_id %u action=%u",
              pdr->hw_rule_id, far->applyAction);
    return 0;
}


/* ═══════════════════════════════════════════════════════════════════
 *  upf_send_hw_offload_update_qer() — send HW_OP_UPDATE_QER
 *  Re-reads the QER pointer already resolved in the PDR.
 *  session == NULL suppresses the session-QER derivation so a PDR whose
 *  qer was intentionally cleared (RemoveQER) sends zero rates → the DPU
 *  detaches the meter.
 * ═══════════════════════════════════════════════════════════════════ */
static inline int
upf_send_hw_offload_update_qer(UpfSession *session, UPDK_PDR *pdr)
{
    if (!pdr || pdr->hw_rule_id == 0)
        return 0;

    if (!Self()->hostAgentOffload)
        return 0;

    hw_offload_msg_t *msg = (hw_offload_msg_t *)rte_calloc(
        "hw_offload", 1, sizeof(hw_offload_msg_t), RTE_CACHE_LINE_SIZE);
    if (!msg) {
        UTLT_Error("hw_offload_update_qer: rte_calloc failed hw_rule_id %u",
                   pdr->hw_rule_id);
        return -1;
    }

    msg->magic       = HW_OFFLOAD_MAGIC;
    msg->op          = HW_OP_UPDATE_QER;
    msg->hw_rule_id  = pdr->hw_rule_id;
    msg->pdr_id      = pdr->pdrId;

    if (pdr->pdi.sourceInterface == UPDK_INTERFACE_VALUE_ACCESS)
        msg->direction = HW_DIR_UPLINK;
    else
        msg->direction = HW_DIR_DOWNLINK;

    /* QER identity + rates */
    upf_stamp_qer_identity(session, pdr, msg->direction, msg);

    int rc = onvm_nflib_send_msg_to_nf(HOST_AGENT_SERVICE_ID, msg);
    if (rc < 0) {
        UTLT_Warning("hw_offload_update_qer: send failed (rc=%d) "
                     "hw_rule_id %u", rc, pdr->hw_rule_id);
        rte_free(msg);
        return rc;
    }

    UTLT_Info("hw_offload: sent UPDATE_QER hw_rule_id %u", pdr->hw_rule_id);
    return 0;
}


/* ═══════════════════════════════════════════════════════════════════
 *  upf_send_hw_offload_update_pdr() — send HW_OP_UPDATE_PDR
 *  Full rebuild of all fields (same as CREATE but op=UPDATE_PDR).
 *  Reuses the existing hw_rule_id so the DPU can delete + reinsert.
 * ═══════════════════════════════════════════════════════════════════ */
static inline int
upf_send_hw_offload_update_pdr(UpfSession *session, UPDK_PDR *pdr)
{
    if (!pdr || pdr->hw_rule_id == 0)
        return 0;

    /* Re-check offloadability (FAR must be FORW) */
    if (!pdr->far || !(pdr->far->applyAction & UPDK_FAR_APPLY_ACTION_FORW))
        return 0;

    if (!Self()->hostAgentOffload)
        return 0;

    uint32_t saved_rule_id = pdr->hw_rule_id;

    /* Temporarily clear hw_rule_id so build_and_send generates a fresh msg,
     * then we override the op and hw_rule_id. */
    hw_offload_msg_t *msg = (hw_offload_msg_t *)rte_calloc(
        "hw_offload", 1, sizeof(hw_offload_msg_t), RTE_CACHE_LINE_SIZE);
    if (!msg) {
        UTLT_Error("hw_offload_update_pdr: rte_calloc failed hw_rule_id %u",
                   saved_rule_id);
        return -1;
    }

    /* Determine direction */
    uint8_t direction;
    if (pdr->pdi.sourceInterface == UPDK_INTERFACE_VALUE_ACCESS) {
        direction = HW_DIR_UPLINK;
        if (!pdr->pdi.flags.fTeid || pdr->pdi.fTeid.teid == 0) {
            rte_free(msg);
            return 0;
        }
    } else if (pdr->pdi.sourceInterface == UPDK_INTERFACE_VALUE_CORE ||
               pdr->pdi.sourceInterface == UPDK_INTERFACE_VALUE_N6_LAN) {
        direction = HW_DIR_DOWNLINK;
        if (!pdr->pdi.flags.ueIpAddress || !pdr->pdi.ueIpAddress.flags.v4) {
            rte_free(msg);
            return 0;
        }
    } else {
        rte_free(msg);
        return 0;
    }

    /* Header */
    msg->magic       = HW_OFFLOAD_MAGIC;
    msg->op          = HW_OP_UPDATE_PDR;
    msg->direction   = direction;
    msg->pdr_id      = pdr->pdrId;
    msg->hw_rule_id  = saved_rule_id;   /* reuse existing ID */
    msg->precedence  = pdr->precedence;

    /* Match: GTP tunnel */
    if (pdr->pdi.flags.fTeid) {
        msg->teid       = pdr->pdi.fTeid.teid;
        msg->fteid_ipv4 = pdr->pdi.fTeid.ipv4;
    }

    /* Match: UE IP */
    if (pdr->pdi.flags.ueIpAddress && pdr->pdi.ueIpAddress.flags.v4)
        msg->ue_ipv4 = pdr->pdi.ueIpAddress.ipv4;

    /* Match: QFI */
    if (pdr->pdi.flags.qfi)
        msg->qfi = pdr->pdi.qfi;

    /* Encap QFI */
    if (pdr->qer && pdr->qer->flags.qosFlowIdentifier)
        msg->encap_qfi = pdr->qer->qosFlowIdentifier & 0x3F;

    /* Match: SDF 5-tuple */
    if (pdr->pdi.flags.sdfFilter && pdr->pdi.sdfFilter.flags.fd) {
        sdf_parsed_t tmp;
        memset(&tmp, 0, sizeof(tmp));
        if (pdr->pdi.flags.ueIpAddress && pdr->pdi.ueIpAddress.flags.v4)
            tmp.ue_ip = ntohl(pdr->pdi.ueIpAddress.ipv4.s_addr);
        sdf_parse_flow_description(pdr->pdi.sdfFilter.flowDescription, &tmp);
        msg->has_sdf      = 1;
        msg->sdf_proto    = tmp.sdf_proto;
        msg->sdf_src_ip   = tmp.sdf_src_ip;
        msg->sdf_dst_ip   = tmp.sdf_dst_ip;
        msg->sdf_src_pref = tmp.sdf_src_pref;
        msg->sdf_dst_pref = tmp.sdf_dst_pref;
        msg->sdf_src_port = tmp.sdf_src_port;
        msg->sdf_dst_port = tmp.sdf_dst_port;
    }

    /* FAR action + outer header */
    const UPDK_FAR *far = pdr->far;
    msg->apply_action = far->applyAction;
    if (pdr->flags.outerHeaderRemoval)
        msg->outer_hdr_removal = pdr->outerHeaderRemoval;
    else
        msg->outer_hdr_removal = 0xFF;
    if (far->flags.forwardingParameters &&
        far->forwardingParameters.flags.outerHeaderCreation) {
        const UPDK_OuterHeaderCreation *ohc =
            &far->forwardingParameters.outerHeaderCreation;
        msg->ohc_desc = (uint8_t)ohc->description;
        msg->ohc_teid = ohc->teid;
        msg->ohc_ipv4 = ohc->ipv4;
    }

    /* QER identity + rates */
    upf_stamp_qer_identity(session, pdr, direction, msg);

    int rc = onvm_nflib_send_msg_to_nf(HOST_AGENT_SERVICE_ID, msg);
    if (rc < 0) {
        UTLT_Warning("hw_offload_update_pdr: send failed (rc=%d) "
                     "hw_rule_id %u", rc, saved_rule_id);
        rte_free(msg);
        return rc;
    }

    UTLT_Info("hw_offload: sent UPDATE_PDR hw_rule_id %u PDR %u",
              saved_rule_id, pdr->pdrId);
    return 0;
}

#ifdef __cplusplus
}
#endif
