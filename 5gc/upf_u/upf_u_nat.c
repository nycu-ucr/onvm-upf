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

#include <stdint.h>
#include <string.h>
#include <time.h>

#include <rte_common.h>
#include <rte_cksum.h>
#include <rte_icmp.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "utlt_debug.h"

#include "upf_u_config.h"
#include "upf_u_helper.h"
#include "upf_u_nat.h"

#define NAT_TABLE_MAX 1024
#define NAT_HASH_BUCKETS 2048
#define NAT_IDLE_TIMEOUT_SEC 300

struct nat_binding {
    uint8_t  in_use;
    uint8_t  proto;
    uint16_t ue_port;
    uint16_t remote_port;
    uint16_t public_port;
    uint32_t ue_ip;
    uint32_t remote_ip;
    time_t   last_seen;
    int32_t  hash_next;
};

static struct nat_binding g_nat_bindings[NAT_TABLE_MAX];
static int32_t g_nat_tuple_buckets[NAT_HASH_BUCKETS];
static int32_t g_nat_port_map[UINT16_MAX + 1];
static uint16_t g_nat_free_stack[NAT_TABLE_MAX];
static uint16_t g_nat_free_top = 0;
static uint16_t g_nat_next_port = 0;

void
nat_init(void)
{
    memset(g_nat_bindings, 0, sizeof(g_nat_bindings));
    for (size_t i = 0; i < RTE_DIM(g_nat_tuple_buckets); i++) {
        g_nat_tuple_buckets[i] = -1;
    }
    for (size_t i = 0; i < RTE_DIM(g_nat_port_map); i++) {
        g_nat_port_map[i] = -1;
    }
    g_nat_free_top = NAT_TABLE_MAX;
    for (size_t i = 0; i < NAT_TABLE_MAX; i++) {
        g_nat_bindings[i].hash_next = -1;
        g_nat_free_stack[i] = (uint16_t)(NAT_TABLE_MAX - 1 - i);
    }
    g_nat_next_port = g_nat_port_min;
}

static inline int
nat_supported_proto(uint8_t proto)
{
    return proto == IPPROTO_UDP || proto == IPPROTO_TCP || proto == IPPROTO_ICMP;
}

static inline void *
nat_l4_hdr(const struct rte_ipv4_hdr *iph)
{
    uint16_t ihl = (uint16_t)(iph->version_ihl & 0x0F) * 4;
    return ((uint8_t *)iph) + ihl;
}

static inline uint16_t
nat_src_port(const struct rte_ipv4_hdr *iph)
{
    if (iph->next_proto_id == IPPROTO_UDP) {
        const struct rte_udp_hdr *udp = (const struct rte_udp_hdr *)nat_l4_hdr(iph);
        return rte_be_to_cpu_16(udp->src_port);
    }
    if (iph->next_proto_id == IPPROTO_TCP) {
        const struct rte_tcp_hdr *tcp = (const struct rte_tcp_hdr *)nat_l4_hdr(iph);
        return rte_be_to_cpu_16(tcp->src_port);
    }
    if (iph->next_proto_id == IPPROTO_ICMP) {
        const struct rte_icmp_hdr *icmp = (const struct rte_icmp_hdr *)nat_l4_hdr(iph);
        return rte_be_to_cpu_16(icmp->icmp_ident);
    }
    return 0;
}

uint16_t
nat_dst_port(const struct rte_ipv4_hdr *iph)
{
    if (iph->next_proto_id == IPPROTO_UDP) {
        const struct rte_udp_hdr *udp = (const struct rte_udp_hdr *)nat_l4_hdr(iph);
        return rte_be_to_cpu_16(udp->dst_port);
    }
    if (iph->next_proto_id == IPPROTO_TCP) {
        const struct rte_tcp_hdr *tcp = (const struct rte_tcp_hdr *)nat_l4_hdr(iph);
        return rte_be_to_cpu_16(tcp->dst_port);
    }
    if (iph->next_proto_id == IPPROTO_ICMP) {
        const struct rte_icmp_hdr *icmp = (const struct rte_icmp_hdr *)nat_l4_hdr(iph);
        return rte_be_to_cpu_16(icmp->icmp_ident);
    }
    return 0;
}

static inline void
nat_set_src_port(struct rte_ipv4_hdr *iph, uint16_t port)
{
    if (iph->next_proto_id == IPPROTO_UDP) {
        struct rte_udp_hdr *udp = (struct rte_udp_hdr *)nat_l4_hdr(iph);
        udp->src_port = rte_cpu_to_be_16(port);
        return;
    }
    if (iph->next_proto_id == IPPROTO_TCP) {
        struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)nat_l4_hdr(iph);
        tcp->src_port = rte_cpu_to_be_16(port);
        return;
    }
    if (iph->next_proto_id == IPPROTO_ICMP) {
        struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)nat_l4_hdr(iph);
        icmp->icmp_ident = rte_cpu_to_be_16(port);
    }
}

static inline void
nat_set_dst_port(struct rte_ipv4_hdr *iph, uint16_t port)
{
    if (iph->next_proto_id == IPPROTO_UDP) {
        struct rte_udp_hdr *udp = (struct rte_udp_hdr *)nat_l4_hdr(iph);
        udp->dst_port = rte_cpu_to_be_16(port);
        return;
    }
    if (iph->next_proto_id == IPPROTO_TCP) {
        struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)nat_l4_hdr(iph);
        tcp->dst_port = rte_cpu_to_be_16(port);
        return;
    }
    if (iph->next_proto_id == IPPROTO_ICMP) {
        struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)nat_l4_hdr(iph);
        icmp->icmp_ident = rte_cpu_to_be_16(port);
    }
}

static uint16_t
nat_raw_checksum(const void *buf, size_t len)
{
    uint32_t sum = rte_raw_cksum(buf, len);

    while (sum >> 16) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}

static inline void
nat_recompute_checksums(struct rte_ipv4_hdr *iph)
{
    iph->hdr_checksum = 0;
    iph->hdr_checksum = rte_ipv4_cksum(iph);

    if (iph->next_proto_id == IPPROTO_UDP) {
        struct rte_udp_hdr *udp = (struct rte_udp_hdr *)nat_l4_hdr(iph);
        if (udp->dgram_cksum != 0) {
            udp->dgram_cksum = 0;
            udp->dgram_cksum = rte_ipv4_udptcp_cksum(iph, udp);
        }
        return;
    }

    if (iph->next_proto_id == IPPROTO_TCP) {
        struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)nat_l4_hdr(iph);
        tcp->cksum = 0;
        tcp->cksum = rte_ipv4_udptcp_cksum(iph, tcp);
        return;
    }

    if (iph->next_proto_id == IPPROTO_ICMP) {
        struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)nat_l4_hdr(iph);
        uint16_t total_len = rte_be_to_cpu_16(iph->total_length);
        uint16_t ihl = (uint16_t)(iph->version_ihl & 0x0F) * 4;
        uint16_t icmp_len = total_len > ihl ? (uint16_t)(total_len - ihl) : 0;
        icmp->icmp_cksum = 0;
        icmp->icmp_cksum = nat_raw_checksum(icmp, icmp_len);
    }
}

static inline int
nat_binding_matches(const struct nat_binding *b, uint8_t proto, uint32_t ue_ip,
                    uint16_t ue_port, uint32_t remote_ip, uint16_t remote_port)
{
    return b->in_use &&
           b->proto == proto &&
           b->ue_ip == ue_ip &&
           b->ue_port == ue_port &&
           b->remote_ip == remote_ip &&
           b->remote_port == remote_port;
}

static inline uint32_t
nat_mix32(uint32_t x)
{
    x ^= x >> 16;
    x *= 0x7feb352dU;
    x ^= x >> 15;
    x *= 0x846ca68bU;
    x ^= x >> 16;
    return x;
}

static inline uint32_t
nat_tuple_hash(uint8_t proto, uint32_t ue_ip, uint16_t ue_port,
               uint32_t remote_ip, uint16_t remote_port)
{
    uint32_t h = ue_ip;
    h ^= nat_mix32(remote_ip);
    h ^= ((uint32_t)ue_port << 16) | remote_port;
    h ^= (uint32_t)proto * 0x9e3779b1U;
    return nat_mix32(h) & (NAT_HASH_BUCKETS - 1);
}

static void
nat_unlink_from_tuple_hash(int idx)
{
    struct nat_binding *b = &g_nat_bindings[idx];
    uint32_t bucket = nat_tuple_hash(b->proto, b->ue_ip, b->ue_port,
                                     b->remote_ip, b->remote_port);
    int32_t *cur = &g_nat_tuple_buckets[bucket];

    while (*cur >= 0) {
        if (*cur == idx) {
            *cur = g_nat_bindings[idx].hash_next;
            return;
        }
        cur = &g_nat_bindings[*cur].hash_next;
    }
}

static void
nat_release_binding(int idx)
{
    if (idx < 0 || idx >= NAT_TABLE_MAX || !g_nat_bindings[idx].in_use) {
        return;
    }

    nat_unlink_from_tuple_hash(idx);
    g_nat_port_map[g_nat_bindings[idx].public_port] = -1;
    memset(&g_nat_bindings[idx], 0, sizeof(g_nat_bindings[idx]));
    g_nat_bindings[idx].hash_next = -1;

    if (g_nat_free_top < NAT_TABLE_MAX) {
        g_nat_free_stack[g_nat_free_top++] = (uint16_t)idx;
    }
}

static inline int
nat_binding_expired(const struct nat_binding *b, time_t now)
{
    return (now - b->last_seen) > NAT_IDLE_TIMEOUT_SEC;
}

static int
nat_find_binding(uint8_t proto, uint32_t ue_ip, uint16_t ue_port,
                 uint32_t remote_ip, uint16_t remote_port, time_t now)
{
    uint32_t bucket = nat_tuple_hash(proto, ue_ip, ue_port, remote_ip, remote_port);
    int32_t idx = g_nat_tuple_buckets[bucket];

    while (idx >= 0) {
        struct nat_binding *b = &g_nat_bindings[idx];
        int32_t next = b->hash_next;

        if (nat_binding_expired(b, now)) {
            nat_release_binding(idx);
            idx = next;
            continue;
        }

        if (nat_binding_matches(b, proto, ue_ip, ue_port, remote_ip, remote_port)) {
            b->last_seen = now;
            return idx;
        }

        idx = next;
    }
    return -1;
}

static int
nat_alloc_binding_slot(time_t now)
{
    if (g_nat_free_top > 0) {
        return g_nat_free_stack[--g_nat_free_top];
    }

    for (int i = 0; i < NAT_TABLE_MAX; i++) {
        if (g_nat_bindings[i].in_use && nat_binding_expired(&g_nat_bindings[i], now)) {
            nat_release_binding(i);
            return g_nat_free_stack[--g_nat_free_top];
        }
    }

    return -1;
}

static int
nat_alloc_port(time_t now)
{
    if (!g_nat_enabled || g_nat_port_min > g_nat_port_max) {
        return -1;
    }

    uint32_t range = (uint32_t)g_nat_port_max - (uint32_t)g_nat_port_min + 1;
    if (range == 0) {
        return -1;
    }

    if (g_nat_next_port < g_nat_port_min || g_nat_next_port > g_nat_port_max) {
        g_nat_next_port = g_nat_port_min;
    }

    for (uint32_t i = 0; i < range; i++) {
        uint16_t candidate = (uint16_t)(g_nat_port_min + ((g_nat_next_port - g_nat_port_min + i) % range));
        int32_t idx = g_nat_port_map[candidate];
        if (idx >= 0 && idx < NAT_TABLE_MAX &&
            g_nat_bindings[idx].in_use &&
            nat_binding_expired(&g_nat_bindings[idx], now)) {
            nat_release_binding(idx);
            idx = -1;
        }
        if (idx < 0 || idx >= NAT_TABLE_MAX || !g_nat_bindings[idx].in_use) {
            g_nat_next_port = (candidate == g_nat_port_max) ? g_nat_port_min : (uint16_t)(candidate + 1);
            return candidate;
        }
    }
    return -1;
}

static int
nat_create_binding(uint8_t proto, uint32_t ue_ip, uint16_t ue_port,
                   uint32_t remote_ip, uint16_t remote_port, time_t now)
{
    int free_idx = nat_alloc_binding_slot(now);

    if (free_idx < 0) {
        return -1;
    }

    int public_port = nat_alloc_port(now);
    if (public_port < 0) {
        g_nat_free_stack[g_nat_free_top++] = (uint16_t)free_idx;
        return -1;
    }

    struct nat_binding *b = &g_nat_bindings[free_idx];
    b->in_use = 1;
    b->proto = proto;
    b->ue_ip = ue_ip;
    b->ue_port = ue_port;
    b->remote_ip = remote_ip;
    b->remote_port = remote_port;
    b->public_port = (uint16_t)public_port;
    b->last_seen = now;
    uint32_t bucket = nat_tuple_hash(proto, ue_ip, ue_port, remote_ip, remote_port);
    b->hash_next = g_nat_tuple_buckets[bucket];
    g_nat_tuple_buckets[bucket] = free_idx;
    g_nat_port_map[b->public_port] = free_idx;

    char ue_buf[16];
    char pub_buf[16];
    char remote_buf[16];
    UTLT_Info("NAT create: UE %s:%u <-> public %s:%u remote %s:%u proto=%u",
              ipv4_to_buf(ue_ip, ue_buf), ue_port,
              ipv4_to_buf(g_nat_public_ip_be, pub_buf), b->public_port,
              ipv4_to_buf(remote_ip, remote_buf), remote_port, proto);
    return free_idx;
}

static int
nat_get_or_create_binding(uint8_t proto, uint32_t ue_ip, uint16_t ue_port,
                          uint32_t remote_ip, uint16_t remote_port)
{
    time_t now = time(NULL);
    int idx = nat_find_binding(proto, ue_ip, ue_port, remote_ip, remote_port, now);
    if (idx >= 0) {
        return idx;
    }
    return nat_create_binding(proto, ue_ip, ue_port, remote_ip, remote_port, now);
}

static int
nat_find_binding_by_public(uint8_t proto, uint16_t public_port)
{
    int32_t idx = g_nat_port_map[public_port];
    if (idx < 0 || idx >= NAT_TABLE_MAX) {
        return -1;
    }

    struct nat_binding *b = &g_nat_bindings[idx];
    if (!b->in_use || b->proto != proto) {
        return -1;
    }

    time_t now = time(NULL);
    if (nat_binding_expired(b, now)) {
        nat_release_binding(idx);
        return -1;
    }

    b->last_seen = now;
    return idx;
}

int
nat_apply_snat(struct rte_ipv4_hdr *iph)
{
    if (!g_nat_enabled || !iph || !nat_supported_proto(iph->next_proto_id)) {
        return 0;
    }

    uint32_t ue_ip = iph->src_addr;
    uint32_t remote_ip = iph->dst_addr;
    uint16_t ue_port = nat_src_port(iph);
    uint16_t remote_port = nat_dst_port(iph);

    int idx = nat_get_or_create_binding(iph->next_proto_id, ue_ip, ue_port, remote_ip, remote_port);
    if (idx < 0) {
        UTLT_Error("NAT SNAT: unable to allocate binding");
        return -1;
    }

    struct nat_binding *b = &g_nat_bindings[idx];
    iph->src_addr = g_nat_public_ip_be;
    nat_set_src_port(iph, b->public_port);
    nat_recompute_checksums(iph);
    return 0;
}

int
nat_apply_dnat(struct rte_ipv4_hdr *iph)
{
    if (!g_nat_enabled || !iph) {
        return 0;
    }

    if (iph->dst_addr != g_nat_public_ip_be) {
        return 0;
    }

    if (!nat_supported_proto(iph->next_proto_id)) {
        return -1;
    }

    uint16_t public_port = nat_dst_port(iph);
    int idx = nat_find_binding_by_public(iph->next_proto_id, public_port);
    if (idx < 0) {
        return -1;
    }

    struct nat_binding *b = &g_nat_bindings[idx];
    iph->dst_addr = b->ue_ip;
    nat_set_dst_port(iph, b->ue_port);
    nat_recompute_checksums(iph);
    return 1;
}
