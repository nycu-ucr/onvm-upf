#define TRACE_MODULE _upf_context

#include "upf_context.h"

#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <netinet/in.h>
#include <net/if.h>

#include <rte_byteorder.h>
#include <rte_memzone.h>
#include <rte_malloc.h>

#include "utlt_debug.h"
#include "utlt_pool.h"
#include "utlt_index.h"
#include "utlt_hash.h"
#include "utlt_network.h"
#include "utlt_netheader.h"

#include "pfcp_message.h"
#include "pfcp_types.h"
#include "pfcp_xact.h"

#include "updk/env.h"
#include "updk/init.h"
#include "updk/rule.h"

#include "upf_cls_ctrl.h"

/* // for logging

#include <inttypes.h>
#include <rte_hexdump.h> */


#define MAX_NUM_OF_SUBNET       16

static UpfContext self;
static _Bool upfContextInitialized = 0;
static uint64_t g_sessionIdPool = 1;

upf_cls_ctrl_t *g_upf_cls_ctrl = NULL;

list_t *g_all_pdr_list = NULL;

static int
UpfSessionFindDlPathSlot(const UpfSession *session, uint32_t far_id) {
    if (!session) {
        return -1;
    }

    for (uint8_t i = 0; i < session->dl_paths.count; i++) {
        if (session->dl_paths.entries[i].far_id == far_id) {
            return (int)i;
        }
    }

    return -1;
}

bool UpfFarIsDlAccessCandidate(const UpfFAR *far) {
    const UPDK_ForwardingParameters *forwarding;

    if (!far) {
        return false;
    }
    if (!far->flags.applyAction || !(far->applyAction & UPDK_FAR_APPLY_ACTION_FORW)) {
        return false;
    }
    if (!far->flags.forwardingParameters) {
        return false;
    }

    forwarding = &far->forwardingParameters;
    if (!forwarding->flags.outerHeaderCreation) {
        return false;
    }
    if (forwarding->flags.destinationInterface &&
        forwarding->destinationInterface != UPDK_INTERFACE_VALUE_ACCESS) {
        return false;
    }
    if (forwarding->outerHeaderCreation.description !=
        UPDK_OUTER_HEADER_CREATION_DESCRIPTION_GTPU_UDP_IPV4) {
        return false;
    }

    return true;
}

Status UpfSessionUpsertDlPathFromFar(UpfSession *session, const UpfFAR *far) {
    int slot;
    UpfDlPathEntry *entry;

    UTLT_Assert(session, return STATUS_ERROR, "session not found");
    UTLT_Assert(far, return STATUS_ERROR, "far not found");

    if (!UpfFarIsDlAccessCandidate(far)) {
        return UpfSessionRemoveDlPathByFarID(session, far->farId);
    }

    slot = UpfSessionFindDlPathSlot(session, far->farId);
    if (slot < 0) {
        if (session->dl_paths.count >= MAX_DL_PATHS) {
            UTLT_Warning("DL path cache full for session=%d; cannot add FAR ID[%u]",
                         session->index, far->farId);
            return STATUS_ERROR;
        }
        slot = session->dl_paths.count++;
    }

    entry = &session->dl_paths.entries[slot];
    entry->far_id = far->farId;
    entry->teid = far->forwardingParameters.outerHeaderCreation.teid;
    entry->outer_ip = far->forwardingParameters.outerHeaderCreation.ipv4;

    {
        char ipbuf[INET_ADDRSTRLEN];
        UTLT_Info("DL path upsert: session=%d slot=%d far_id=%u outer_dst=%s teid=%u count=%u",
                  session->index,
                  slot,
                  entry->far_id,
                  inet_ntop(AF_INET, &entry->outer_ip, ipbuf, sizeof(ipbuf)) ? ipbuf : "invalid",
                  entry->teid,
                  session->dl_paths.count);
    }

    return STATUS_OK;
}

Status UpfSessionRemoveDlPathByFarID(UpfSession *session, uint32_t far_id) {
    int slot;

    UTLT_Assert(session, return STATUS_ERROR, "session not found");

    slot = UpfSessionFindDlPathSlot(session, far_id);
    if (slot < 0) {
        return STATUS_OK;
    }

    if ((uint8_t)(slot + 1) < session->dl_paths.count) {
        memmove(&session->dl_paths.entries[slot],
                &session->dl_paths.entries[slot + 1],
                sizeof(session->dl_paths.entries[0]) *
                    (session->dl_paths.count - (uint8_t)(slot + 1)));
    }

    session->dl_paths.count--;
    memset(&session->dl_paths.entries[session->dl_paths.count], 0,
           sizeof(session->dl_paths.entries[session->dl_paths.count]));

    UTLT_Info("DL path remove: session=%d far_id=%u count=%u",
              session->index, far_id, session->dl_paths.count);

    return STATUS_OK;
}

const UpfDlPathEntry *UpfSessionGetDlPathByHash(const UpfSession *session, uint32_t hash) {
    if (!session || session->dl_paths.count == 0) {
        return NULL;
    }

    return &session->dl_paths.entries[hash % session->dl_paths.count];
}


void UpfPDRGlobalInit(void) {
    if (!g_all_pdr_list) {
        g_all_pdr_list = list_new();
    }
}

void UpfPDRGlobalAdd(UpfPDR *pdr) {
    if (!pdr) {
        return;
    }
    if (!g_all_pdr_list) {
        g_all_pdr_list = list_new();
    }
    list_rpush(g_all_pdr_list, list_node_new(pdr));
}

void UpfPDRGlobalRemove(UpfPDR *pdr) {
    if (!g_all_pdr_list || !pdr) {
        return;
    }
    list_iterator_t *it = list_iterator_new(g_all_pdr_list, LIST_HEAD);
    for (list_node_t *n; (n = list_iterator_next(it)); ) {
        if ((UpfPDR *)n->val == pdr) { 
            list_remove(g_all_pdr_list, n);
            break;
        }
    }
    list_iterator_destroy(it);
}


int UpfClsCtrlInit(void) {
    const struct rte_memzone *mz = rte_memzone_lookup(MZ_UPF_CLS_CTRL);
    if (!mz) {
        mz = rte_memzone_reserve_aligned(
            MZ_UPF_CLS_CTRL, sizeof(upf_cls_ctrl_t),
            SOCKET_ID_ANY, RTE_MEMZONE_2MB, RTE_CACHE_LINE_SIZE);
        if (!mz) return -1;

        /* We are the creator: initialize to a stable, empty state.
           version must be EVEN (stable). 0 is perfect. */
        upf_cls_ctrl_t *ctrl = (upf_cls_ctrl_t *)mz->addr;
        __atomic_store_n(&ctrl->active,  NULL, __ATOMIC_RELEASE);
        __atomic_store_n(&ctrl->version, 0u,   __ATOMIC_RELEASE);
    }

    g_upf_cls_ctrl = (upf_cls_ctrl_t *)mz->addr;

    // logging block
    /* UTLT_Info("CLS_CTRL mapped: slot=%p iova=%" PRIu64 " active=%p ver=%u",
          (void*)g_upf_cls_ctrl,
          (uint64_t)rte_mem_virt2iova(g_upf_cls_ctrl),
          (void*)g_upf_cls_ctrl->active,
          g_upf_cls_ctrl->version); */

    return 0;
}

UpfContext *Self() {
    return &self;
}

Status UpfContextInit() {
    UTLT_Assert(upfContextInitialized == 0, return STATUS_ERROR,
                "UPF context has been initialized!");

    memset(&self, 0, sizeof(UpfContext));

    // TODO : Add GTPv1 init here
    self.envParams = AllocEnvParams();
    UTLT_Assert(self.envParams, return STATUS_ERROR,
        "EnvParams alloc failed");

    self.upSock.fd = -1;
    SockSetEpollMode(&self.upSock, EPOLLIN);

    // TODO : Add PFCP init here
    ListHeadInit(&self.pfcpIPList);

    ListHeadInit(&self.ranS1uList);
    ListHeadInit(&self.upfN4List);
    ListHeadInit(&self.dnnList);

    self.recoveryTime = htonl(time((time_t *)NULL));

    // Set Default Value
    self.gtpDevNamePrefix = "upfgtp";
    // defined in utlt_3gpptypes instead of GTP_V1_PORT defined in GTP_PATH;
    self.gtpv1Port = GTPV1_U_UDP_PORT;
    self.pfcpPort = PFCP_UDP_PORT;
    strcpy(self.envParams->virtualDevice->deviceID, self.gtpDevNamePrefix);

    // Init Resource
    UpfSessionPoolInit();
    UeIpToUpfSessionMapInit();
    TeidToUpfSessionMapInit();

    PfcpNodeInit(); // init pfcp node for upfN4List (it will used pfcp node)
    TimerListInit(&self.timerServiceList);

    upfContextInitialized = 1;

    return STATUS_OK;
}

// TODO : Need to Remove List Members iterativelyatively
Status UpfContextTerminate() {
    UTLT_Assert(upfContextInitialized == 1, return STATUS_ERROR,
                "UPF context has been terminated!");

    Status status = STATUS_OK;

    // Terminate resource
    // TODO(vivek)
    // IndexTerminate(&upfSessionPool);

    PfcpRemoveAllNodes(&self.upfN4List);
    PfcpNodeTerminate();

    SockNodeListFree(&self.pfcpIPList);
    FreeVirtualDevice(self.envParams->virtualDevice);

    upfContextInitialized = 0;

    return status;
}

Status UpfPDRDeregisterToSessionByID(UpfSession *session, uint16_t id) {
    UTLT_Assert(session, return STATUS_ERROR, "session not found error");
    UTLT_Assert(session->pdr_list, return STATUS_ERROR, "PDR list not initialized");

    list_node_t *node = NULL;
    list_iterator_t *it;
    it = list_iterator_new(session->pdr_list, LIST_HEAD);
    while ((node = list_iterator_next(it))) {
        UpfPDR *pdr_i = (UpfPDR *) node->val;
        if (pdr_i->pdrId == id) {
            break;
        }
    }
    list_iterator_destroy(it);
    UTLT_Assert(node, return STATUS_ERROR, "PDR ID[%u] does NOT exist in UPF Context", id);
    list_remove(session->pdr_list, node);
    return STATUS_OK;
}


UpfDeregResult UpfPDRDeregisterToSessionByIDEx(UpfSession *session, uint16_t id) {
    
    UpfDeregResult  res = { 
        .status = STATUS_ERROR,
        .pdr = NULL
    };

    UTLT_Assert(session, return res, "session not found");
    UTLT_Assert(session->pdr_list, return res, "PDR list not initialized");

    list_node_t *node = NULL;
    list_iterator_t *it = list_iterator_new(session->pdr_list, LIST_HEAD);
    
    while ((node = list_iterator_next(it))) {
        UpfPDR *p = (UpfPDR *)node->val;
        if (p->pdrId == id) {
            res.pdr = p;      // stash it
            break;
        }
    }
    list_iterator_destroy(it);

    UTLT_Assert(node, return res, "PDR ID[%u] does NOT exist", id);
    list_remove(session->pdr_list, node);
    res.status = STATUS_OK;
    return res;
}



Status UpfFARDeregisterToSessionByID(UpfSession *session, uint16_t id) {
    UTLT_Assert(session, return STATUS_ERROR, "session not found error");
    UTLT_Assert(session->far_list, return STATUS_ERROR, "FAR list not initialized");

    list_node_t *node = NULL;
    list_iterator_t *it;
    it = list_iterator_new(session->far_list, LIST_HEAD);
    while ((node = list_iterator_next(it))) {
        UpfFAR *far = (UpfFAR *) node->val;
        if (far->farId == id) {
            break;
        }
    }
    UTLT_Assert(node, return STATUS_ERROR, "FAR ID[%u] does NOT exist in UPF Context", id);
    list_remove(session->far_list, node);
    return STATUS_OK;
}

Status UpfQERDeregisterToSessionByID(UpfSession *session, uint16_t id) {
    UTLT_Assert(session, return STATUS_ERROR, "session not found error");
    UTLT_Assert(session->qer_list, return STATUS_ERROR, "QER list not initialized");

    list_node_t *node = NULL;
    list_iterator_t *it;
    it = list_iterator_new(session->qer_list, LIST_HEAD);
    while ((node = list_iterator_next(it))) {
        UpfQER *qer = (UpfQER *) node->val;
        if (qer->qerId == id) {
            break;
        }
    }
    UTLT_Assert(node, return STATUS_ERROR, "QER ID[%u] does NOT exist in UPF Context", id);
    list_remove(session->qer_list, node);
    return STATUS_OK;
}

Status UpfPDRRegisterToSession(UpfSession *session, UpfPDR *pdr) {
    UTLT_Assert(session, return STATUS_ERROR, "session not found error");
    UTLT_Assert(session->pdr_list, return STATUS_ERROR, "PDR list not initialized");

    list_rpush(session->pdr_list, list_node_new(pdr));

    if (pdr->pdi.flags.fTeid) {
        /* pdr->pdi.fTeid.teid is stored in host byte order after PFCP decode,
           while session->teid_list and the TEID hash map use network byte order. */
        uint32_t teid = rte_cpu_to_be_32(pdr->pdi.fTeid.teid);
        UTLT_Info("UpfPDRRegisterToSession: session=%d pdr=%u host_teid=%u net_teid=%u teid_count=%u",
                  session->index, pdr->pdrId, pdr->pdi.fTeid.teid, teid, session->teid_count);

        /* Check if this TEID is already registered (e.g. during session establishment
           where UpfSessionAdd already inserted the first PDR's TEID). */
        bool already_registered = false;
        for (int i = 0; i < session->teid_count; i++) {
            if (session->teid_list[i] == teid) {
                already_registered = true;
                UTLT_Info("UpfPDRRegisterToSession: TEID already present in session at slot %d", i);
                break;
            }
        }

        if (!already_registered) {
            UTLT_Info("Registering additional TEID %u for session (count=%d)",
                      teid, session->teid_count);
            UTLT_Assert(InsertTEIDtoSessionMap(teid, session) == STATUS_OK,
                return STATUS_ERROR, "Failed to map TEID %u to session", teid);
        }
    }

    return STATUS_OK;
}

Status UpfFARRegisterToSession(UpfSession *session, UpfFAR * far) {
    UTLT_Assert(session, return STATUS_ERROR, "session not found error");
    UTLT_Assert(session->far_list, return STATUS_ERROR, "FAR list not initialized");

    list_rpush(session->far_list, list_node_new(far));
    return STATUS_OK;
}

Status UpfQERRegisterToSession(UpfSession *session, UpfQER *qer){
    UTLT_Assert(session, return STATUS_ERROR, "session not found error");
    UTLT_Assert(session->qer_list, return STATUS_ERROR, "QER list not initialized");

    list_rpush(session->qer_list, list_node_new(qer));
    return STATUS_OK;
}

UpfPDR *UpfPDRFindByID(UpfSession *session, uint16_t id) {
    UTLT_Assert(session, return NULL, "session not found error");
    UTLT_Assert(session->pdr_list, return NULL, "PDR list not initialized");

    list_node_t *node;
    list_iterator_t *it;
    it = list_iterator_new(session->pdr_list, LIST_HEAD);
    while ((node = list_iterator_next(it))) {
        UpfPDR *pdr = (UpfPDR *) node->val;
        if (pdr->pdrId == id) {
            list_iterator_destroy(it);
            return pdr;
        }
    }
    list_iterator_destroy(it);
    return NULL;
}

UpfFAR *UpfFARFindByID(UpfSession *session, uint16_t id) {
    UTLT_Assert(session, return NULL, "session not found error");
    UTLT_Assert(session->far_list, return NULL, "FAR list not initialized");

    list_node_t *node;
    list_iterator_t *it;
    it = list_iterator_new(session->far_list, LIST_HEAD);
    while ((node = list_iterator_next(it))) {
        UpfFAR *far = (UpfFAR *) node->val;
        if (far->farId == id) {
            list_iterator_destroy(it);
            return far;
        }
    }
    list_iterator_destroy(it);
    return NULL;
}

UpfQER *UpfQERFindByID(UpfSession *session, uint16_t id){
    UTLT_Assert(session, return NULL, "session not found error");
    UTLT_Assert(session->qer_list, return NULL, "QER list not initialized");

    list_node_t *node;
    list_iterator_t *it;
    it = list_iterator_new(session->qer_list, LIST_HEAD);
    while ((node = list_iterator_next(it))) {
        UpfQER *qer = (UpfQER *) node->val;
        if (qer->qerId == id) {
            list_iterator_destroy(it);
            return qer;
        }
    }
    list_iterator_destroy(it);
    return NULL;
}

UpfSession *UpfSessionAdd(PfcpUeIpAddr *ueIp,
                          PfcpFTeid *teid,
                          uint8_t *dnn,
                          uint8_t pdnType) {
    UTLT_Assert(teid, return NULL, "teid is null");
    UTLT_Assert(ueIp, return NULL, "ueIp");
    UpfSession *session = NULL;

    session = UpfSessionAlloc(g_sessionIdPool);
    // UTLT_Debug("Session return from UpfSessionAlloc: %p\n", session);
    UTLT_Assert(session, return NULL, "session alloc error");

    strncpy((char*)session->pdn.dnn, (char*)dnn, MAX_DNN_LEN + 1);

    session->pdr_list = list_new();
    session->far_list = list_new();
    session->qer_list = list_new();
    memset(&session->dl_paths, 0, sizeof(session->dl_paths));
    // DumpUpfSession();
    //use to check srr flag
    session->srr_flag = false;

    session->teid_count = 0;
    /* The PFCP parser leaves F-TEID in network byte order here. Keep that
       representation so it matches session->teid_list and the TEID hash map. */
    uint32_t first_teid = teid->teid;
    UTLT_Info("UpfSessionAdd: session=%d first_teid_raw=%u", session->index, first_teid);
    session->pdn.paa.pdnType = pdnType;
    if (pdnType == PFCP_PDN_TYPE_IPV4) {
        session->ueIpv4.addr4.s_addr = rte_cpu_to_be_32(ueIp->addr4.s_addr);
    } else {
        UpfSessionRemove(session);
        UTLT_Assert(0, return NULL, "UnSupported PDN Type(%d)", pdnType);
    }

    UTLT_Assert(InsertTEIDtoSessionMap(first_teid, session) == STATUS_OK,
                UpfSessionRemove(session); return NULL, "Unable to create Uplink data for TEID (%u)", first_teid);
    UTLT_Assert(InsertUEIPtoSessionMap(session->ueIpv4.addr4.s_addr, session) == STATUS_OK,
                UpfSessionRemove(session); return NULL, "Unable to create Downlink data for UE IP (%u)", ueIp->addr4.s_addr);

    g_sessionIdPool++;
    return session;
}

Status UpfSessionRemove(UpfSession *session) {
    UTLT_Assert(session, return STATUS_ERROR, "session error");

    memset(&session->dl_paths, 0, sizeof(session->dl_paths));

    if (session->far_list) {
        list_destroy(session->far_list);
    }

    if (session->pdr_list) {
        list_destroy(session->pdr_list);
    }
    UeIpToUpfSessionMapFree(session->ueIpv4.addr4.s_addr);
    /* Remove TEIDs directly from the current session. Using the hash lookup
       helper here can fail after partial setup/rollback and leave teid_count
       unchanged, which traps teardown in an infinite loop. */
    while (session->teid_count > 0) {
        uint32_t teid = session->teid_list[session->teid_count - 1];
        session->teid_count--;
        TeidToUpfSessionMapFree(teid);
    }
    UpfSessionFree(session);
    return STATUS_OK;
}

UpfSession *UpfSessionAddByMessage(PfcpMessage *message) {
    UTLT_Debug("UpfSessionAddByMessage"); 
    UpfSession *session;

    PFCPSessionEstablishmentRequest *request =
      &message->pFCPSessionEstablishmentRequest;
    printf("PDN Type(%d)\n",((int8_t *)request->pDNType.value)[0]);
    if (!request->nodeID.presence) {
        UTLT_Error("no NodeID");
        return NULL;
    }
    if (!request->cPFSEID.presence) {
        UTLT_Error("No cp F-SEID");
        return NULL;
    }
    if (!request->createPDR[0].presence) {
        UTLT_Error("No PDR");
        return NULL;
    }
    
    if (!request->createFAR[0].presence) {
        UTLT_Error("No FAR");
        return NULL;
    }
    
    if (!request->pDNType.presence) {
        UTLT_Error("No PDN Type");
        return NULL;
    }
    if (!request->createPDR[0].pDI.presence) {
        UTLT_Error("PDR PDI error");
        return NULL;
    }
    if (!request->createPDR[0].pDI.uEIPAddress.presence) {
        UTLT_Error("UE IP Address error");
        return NULL;
    }
    if (!request->createPDR[0].pDI.networkInstance.presence) {
        UTLT_Error("Interface error");
        return NULL;
    }

    if (!request->createPDR[0].pDI.localFTEID.presence) {
        UTLT_Error("TEID error");
        return NULL;
    }

    session = UpfSessionAdd((PfcpUeIpAddr *)
                            request->createPDR[0].pDI.uEIPAddress.value,
                            (PfcpFTeid *) request->createPDR[0].pDI.localFTEID.value,
                            request->createPDR[0].pDI.networkInstance.value,
                            ((int8_t *)request->pDNType.value)[0]);
    UTLT_Assert(session, return NULL, "session add error");

    session->smfSeid = *(uint64_t*)request->cPFSEID.value;
    // DumpUpfSession();
    UTLT_Debug("UPF Establishment UPF SEID: %lu", session->upfSeid);
    UTLT_Debug("UPF Establishment SMF SEID: %lu", session->smfSeid);

    return session;
}
