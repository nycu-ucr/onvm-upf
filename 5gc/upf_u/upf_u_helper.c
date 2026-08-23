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

#include "upf_u_helper.h"

#define IP_MASKED(BIGENDIINT, LEN) (BIGENDIINT & (0xFFFFFFFF << (32-LEN)))

const char *
ipv4_to_buf(uint32_t be_addr, char buf[16]) {
    inet_ntop(AF_INET, &be_addr, buf, 16);
    return buf;
}

void
dump_gtpu(const uint8_t *start, size_t len, size_t gtp_off) {
    printf("---- GTPU Dump (offset %zu, %zu bytes) ----\n", gtp_off, len);
    for (size_t i = 0; i < len; i++) {
        if (i % 16 == 0) printf("\n%04zu : ", i);
        printf("%02x ", start[i]);
    }
    printf("\n------------------------------------------\n");
}

const char*
ip4(uint32_t host_ip) {
    static char buf[16];
    struct in_addr a = { .s_addr = htonl(host_ip) };
    return inet_ntop(AF_INET, &a, buf, sizeof(buf)) ? buf : "<err>";
}

uint32_t
charStr2MaskedIP(char *str, uint32_t *prefix_val) {
    char ip_str[INET_ADDRSTRLEN];
    uint32_t prefix_len, subnet;

    sscanf(str, "%[^/]/%d", ip_str, &prefix_len);
    struct in_addr ip_addr;
    inet_pton(AF_INET, ip_str, &ip_addr);

    if (prefix_val) *prefix_val = prefix_len;
    return IP_MASKED(ip_addr.s_addr, prefix_len);
}

char *
convertToIpAddressString(uint32_t big_endian_value) {
    static char ip_string[16];

    uint8_t ip_address[4];
    ip_address[0] = (big_endian_value >> 24) & 0xFF;
    ip_address[1] = (big_endian_value >> 16) & 0xFF;
    ip_address[2] = (big_endian_value >> 8) & 0xFF;
    ip_address[3] = big_endian_value & 0xFF;

    sprintf(ip_string, "%d.%d.%d.%d", ip_address[3], ip_address[2], ip_address[1], ip_address[0]);

    return ip_string;
}