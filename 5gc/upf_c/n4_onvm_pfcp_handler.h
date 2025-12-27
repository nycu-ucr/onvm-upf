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

#ifndef __N4_PFCP_HANDLER_H__
#define __N4_PFCP_HANDLER_H__

#include "upf_context.h"
#include "pfcp_message.h"
#include "pfcp_xact.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

void UpfN4HandleCreatePdr(UpfSession *session, CreatePDR *createPdr);
void UpfN4HandleCreateFar(UpfSession *session, CreateFAR *createFar);
void UpfN4HandleCreateQer(UpfSession *session, CreateQER *createQER);
void UpfN4HandleUpdatePdr(UpfSession *session, UpdatePDR *updatePdr);
void UpfN4HandleUpdateFar(UpfSession *session, UpdateFAR *updateFar);
void UpfN4HandleUpdateQer(UpfSession *session, UpdateQER *updateQer);
Status UpfN4HandleRemovePdr(UpfSession *session, uint16_t nPDRID);
Status UpfN4HandleRemoveFar(UpfSession *session, uint32_t nFARID);
Status UpfN4HandleRemoveQer(UpfSession *session, uint32_t nQERID);
void UpfN4HandleSessionEstablishmentRequest(
        UpfSession *session, PfcpXact *pfcpXact, PFCPSessionEstablishmentRequest *request);
void UpfN4HandleSessionModificationRequest(
        UpfSession *session, PfcpXact *xact, PFCPSessionModificationRequest *request);
void UpfN4HandleSessionDeletionRequest(UpfSession *session, PfcpXact *xact, PFCPSessionDeletionRequest *request);
void UpfN4HandleSessionReportResponse(
        UpfSession *session, PfcpXact *xact, PFCPSessionReportResponse *response);
void UpfN4HandleAssociationSetupRequest(PfcpXact *xact, PFCPAssociationSetupRequest *request);
void UpfN4HandleAssociationUpdateRequest(PfcpXact *xact, PFCPAssociationUpdateRequest *request);
void UpfN4HandleAssociationReleaseRequest(PfcpXact *xact, PFCPAssociationReleaseRequest *request);
void UpfN4HandleHeartbeatRequest(PfcpXact *xact, HeartbeatRequest *request);
void UpfN4HandleHeartbeatResponse(PfcpXact *xact, HeartbeatResponse *response);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __N4_PFCP_HANDLER_H__ */
