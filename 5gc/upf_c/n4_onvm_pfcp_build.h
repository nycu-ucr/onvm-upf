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

#ifndef __N4_PFCP_BUILD_H__
#define __N4_PFCP_BUILD_H__

#include "utlt_debug.h"
#include "utlt_buff.h"
#include "upf_context.h"
#include "pfcp_message.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

Status UpfN4BuildSessionEstablishmentResponse(
        Bufblk **bufBlk, uint8_t type, UpfSession *session, uint8_t cause,
        PFCPSessionEstablishmentRequest *establishRequest);
Status UpfN4BuildSessionModificationResponse(
        Bufblk **bufBlkPtr, uint8_t type, UpfSession *session,
        PFCPSessionModificationRequest *modifyRequest);
Status UpfN4BuildSessionDeletionResponse(
        Bufblk **bufBlkPtr, uint8_t type, UpfSession *session,
        PFCPSessionDeletionRequest *deletionRequest);
Status UpfN4BuildSessionReportRequestDownlinkDataReport (
        Bufblk **bufBlkPtr, uint8_t type, UpfSession *session, uint16_t pdrId);
Status UpfN4BuildAssociationSetupResponse(
        Bufblk **bufBlkPtr, uint8_t type);
Status UpfN4BuildAssociationReleaseResponse(
        Bufblk **bufBlkPtr, uint8_t type);
Status UpfN4BuildHeartbeatResponse (
        Bufblk **bufBlkPtr, uint8_t type);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __N4_PFCP_BUILD_H__ */
