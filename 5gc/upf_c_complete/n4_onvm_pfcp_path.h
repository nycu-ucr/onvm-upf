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

#ifndef __N4_ONVM_PFCP_PATH_H__
#define __N4_ONVM_PFCP_PATH_H__

#include <rte_mbuf.h>

#include "utlt_debug.h"

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"

void msg_handler(void *msg_data, struct onvm_nf_local_ctx *nf_local_ctx);
int packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta, struct onvm_nf_local_ctx *nf_local_ctx);

Status PfcpServerInit();
Status PfcpServerTerminate();

#endif /* __N4_PFCP_PATH_H__ */
