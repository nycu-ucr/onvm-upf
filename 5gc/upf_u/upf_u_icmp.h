/*
# Copyright 2026 University of California, Riverside and National Yang Ming Chiao Tung University
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

#ifndef UPF_U_ICMP_H
#define UPF_U_ICMP_H

#include <stdint.h>
#include <rte_mbuf.h>

#include "onvm_nflib.h"

/*
 * Handle ICMP echo request sent to UPF-U local IP.
 *
 * Return:
 *   1 -> packet consumed here (either replied or dropped)
 *   0 -> not handled, caller should continue normal pipeline
 */
int
handle_local_icmp_echo(struct rte_mbuf *pkt,
                       struct onvm_pkt_meta *meta,
                       struct onvm_nf_local_ctx *nf_local_ctx);

#endif