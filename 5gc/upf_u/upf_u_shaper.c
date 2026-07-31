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

#include <inttypes.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_spinlock.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "onvm_pkt_helper.h"
#include "upf_context.h"
#include "utlt_debug.h"

#include "upf_u_shaper.h"
#include "upf_u_trtcm.h"

#define SHAPER_SCAN_BUDGET       32
#define SHAPER_DRAIN_BUDGET      64
#define SHAPER_CLASS_BURST        8
#define SHAPER_DRAIN_CHUNK       64
#define SHAPER_MAX_FLOWS_PER_UE  64
#define SHAPER_MAX_PKTS_PER_FLOW 256
#define SHAPER_MAX_PKTS_PER_UE   1024
#define SHAPER_ENTRY_POOL_CACHE  256
#define SHAPER_UE_BITMAP_WORDS   ((MAX_UE + 63) / 64)

enum shaper_active_list_id {
    SHAPER_ACTIVE_NONE = 0,
    SHAPER_ACTIVE_GREEN,
    SHAPER_ACTIVE_YELLOW,
    SHAPER_ACTIVE_NQOS,
    SHAPER_ACTIVE_COUNT
};

struct shaper_entry {
    struct rte_mbuf *pkt;
    uint32_t pkt_len;
    uint16_t destination;
    enum upf_u_shaper_pkt_color color;
    struct shaper_entry *next;
};

struct shaper_flow {
    bool in_use;
    struct upf_u_shaper_flow_key key;
    struct shaper_entry *head;
    struct shaper_entry *tail;
    uint32_t queued_pkts;
    uint32_t queued_bytes;
    enum shaper_active_list_id active_list;
    uint64_t last_active_tsc;
    TAILQ_ENTRY(shaper_flow) active_node;
};

TAILQ_HEAD(shaper_flow_head, shaper_flow);

struct ue_shaper {
    rte_spinlock_t lock;
    struct shaper_flow flows[SHAPER_MAX_FLOWS_PER_UE];
    struct shaper_flow_head active[SHAPER_ACTIVE_COUNT];
    uint32_t active_count[SHAPER_ACTIVE_COUNT];
    uint32_t queued_pkts;
    uint8_t next_excess_is_yellow;
};

static struct ue_shaper g_ue_shaper[MAX_UE];
static struct rte_mempool *g_shaper_entry_pool;
static uint64_t g_shaper_active_ue_bitmap[SHAPER_UE_BITMAP_WORDS];
static uint32_t g_shaper_active_ue_cursor;
static uint64_t g_shaper_queued;
static uint64_t g_shaper_drained;
static uint64_t g_shaper_drop_invalid;
static uint64_t g_shaper_drop_red;
static uint64_t g_shaper_drop_green_overflow;
static uint64_t g_shaper_drop_yellow_overflow;
static uint64_t g_shaper_drop_nqos_overflow;
static uint64_t g_shaper_drop_flow_table_full;
static uint64_t g_shaper_drop_flow_queue_full;
static uint64_t g_shaper_drop_ue_queue_full;
static uint64_t g_shaper_drop_mempool_empty;

static int
shaper_init_entry_pool(struct onvm_nf *nf) {
    char name[64];
    uint64_t entry_count64 = (uint64_t)MAX_UE * SHAPER_MAX_PKTS_PER_UE;
    unsigned int entry_count;
    uint16_t instance_id = nf ? nf->instance_id : 0;

    if (g_shaper_entry_pool != NULL)
        return 0;

    if (entry_count64 == 0 || entry_count64 > UINT_MAX) {
        UTLT_Error("Invalid shaper entry pool size: %" PRIu64,
                   entry_count64);
        return -1;
    }
    entry_count = (unsigned int)entry_count64;

    snprintf(name, sizeof(name), "us_entry_%03u", instance_id);
    g_shaper_entry_pool = rte_mempool_lookup(name);
    if (g_shaper_entry_pool != NULL)
        return 0;

    g_shaper_entry_pool = rte_mempool_create(name, entry_count,
                                             sizeof(struct shaper_entry),
                                             SHAPER_ENTRY_POOL_CACHE, 0,
                                             NULL, NULL, NULL, NULL,
                                             SOCKET_ID_ANY, 0);
    if (g_shaper_entry_pool == NULL)
        g_shaper_entry_pool = rte_mempool_lookup(name);
    if (g_shaper_entry_pool == NULL) {
        UTLT_Error("Failed to create shaper entry pool %s", name);
        return -1;
    }
    return 0;
}

static void
shaper_init_state(void) {
    for (uint32_t word_idx = 0; word_idx < SHAPER_UE_BITMAP_WORDS; word_idx++)
        __atomic_store_n(&g_shaper_active_ue_bitmap[word_idx], 0,
                         __ATOMIC_RELEASE);
    g_shaper_active_ue_cursor = 0;

    for (int ue_idx = 0; ue_idx < MAX_UE; ue_idx++) {
        rte_spinlock_init(&g_ue_shaper[ue_idx].lock);
        for (int list_id = 0; list_id < SHAPER_ACTIVE_COUNT; list_id++)
            TAILQ_INIT(&g_ue_shaper[ue_idx].active[list_id]);
        g_ue_shaper[ue_idx].next_excess_is_yellow = 1;
    }
}

int
upf_u_shaper_init(struct onvm_nf *nf) {
    shaper_init_state();
    return shaper_init_entry_pool(nf);
}

static inline void
shaper_free_entry(struct shaper_entry *entry) {
    if (entry != NULL && g_shaper_entry_pool != NULL)
        rte_mempool_put(g_shaper_entry_pool, entry);
}

static inline uint64_t
shaper_ue_bitmap_valid_mask(uint32_t word_idx) {
    uint32_t used_bits;

    if (word_idx + 1 < SHAPER_UE_BITMAP_WORDS)
        return UINT64_MAX;

    used_bits = MAX_UE & 63;
    return used_bits == 0 ? UINT64_MAX : ((1ULL << used_bits) - 1);
}

static inline void
shaper_mark_ue_active(int ue_idx) {
    uint32_t word_idx = (uint32_t)ue_idx / 64;
    uint64_t bit = 1ULL << ((uint32_t)ue_idx & 63);

    __atomic_fetch_or(&g_shaper_active_ue_bitmap[word_idx], bit,
                      __ATOMIC_RELEASE);
}

static inline void
shaper_clear_ue_active(int ue_idx) {
    uint32_t word_idx = (uint32_t)ue_idx / 64;
    uint64_t bit = 1ULL << ((uint32_t)ue_idx & 63);

    __atomic_fetch_and(&g_shaper_active_ue_bitmap[word_idx], ~bit,
                       __ATOMIC_RELEASE);
}

static int
shaper_next_active_ue(const uint64_t *skip_bitmap) {
    uint32_t start = g_shaper_active_ue_cursor % MAX_UE;
    uint32_t start_word = start / 64;
    uint32_t start_bit = start & 63;

    for (uint32_t pass = 0; pass < 2; pass++) {
        uint32_t first_word = pass == 0 ? start_word : 0;
        uint32_t last_word = pass == 0 ? SHAPER_UE_BITMAP_WORDS
                                       : start_word + 1;

        for (uint32_t word_idx = first_word; word_idx < last_word; word_idx++) {
            uint64_t word = __atomic_load_n(&g_shaper_active_ue_bitmap[word_idx],
                                            __ATOMIC_ACQUIRE);
            word &= shaper_ue_bitmap_valid_mask(word_idx);
            if (skip_bitmap != NULL)
                word &= ~skip_bitmap[word_idx];
            if (pass == 0 && word_idx == start_word) {
                if (start_bit > 0)
                    word &= UINT64_MAX << start_bit;
            } else if (pass == 1 && word_idx == start_word) {
                if (start_bit == 0)
                    word = 0;
                else
                    word &= (1ULL << start_bit) - 1;
            }
            if (word == 0)
                continue;

            uint32_t bit = (uint32_t)__builtin_ctzll(word);
            uint32_t ue_idx = word_idx * 64 + bit;
            g_shaper_active_ue_cursor = (ue_idx + 1) % MAX_UE;
            return (int)ue_idx;
        }
    }

    return -1;
}

static inline bool
shaper_flow_key_equal(const struct upf_u_shaper_flow_key *a,
                      const struct upf_u_shaper_flow_key *b) {
    return a->ue_ip == b->ue_ip &&
           a->src_ip == b->src_ip &&
           a->dst_ip == b->dst_ip &&
           a->src_port == b->src_port &&
           a->dst_port == b->dst_port &&
           a->proto == b->proto &&
           a->qfi == b->qfi &&
           a->is_qos == b->is_qos;
}

static inline uint32_t
shaper_flow_hash(const struct upf_u_shaper_flow_key *key) {
    uint32_t h = 2166136261u;

    h = (h ^ key->ue_ip) * 16777619u;
    h = (h ^ key->src_ip) * 16777619u;
    h = (h ^ key->dst_ip) * 16777619u;
    h = (h ^ (((uint32_t)key->src_port << 16) | key->dst_port)) * 16777619u;
    h = (h ^ (((uint32_t)key->proto << 16) |
              ((uint32_t)key->qfi << 8) | key->is_qos)) * 16777619u;
    return h;
}

static struct shaper_flow *
shaper_lookup_flow(struct ue_shaper *ue,
                   const struct upf_u_shaper_flow_key *key, bool create) {
    uint32_t start = shaper_flow_hash(key) % SHAPER_MAX_FLOWS_PER_UE;
    int free_idx = -1;

    for (uint32_t probe = 0; probe < SHAPER_MAX_FLOWS_PER_UE; probe++) {
        uint32_t idx = (start + probe) % SHAPER_MAX_FLOWS_PER_UE;
        struct shaper_flow *flow = &ue->flows[idx];

        if (flow->in_use) {
            if (shaper_flow_key_equal(&flow->key, key))
                return flow;
            continue;
        }
        if (free_idx < 0)
            free_idx = (int)idx;
    }

    if (!create || free_idx < 0)
        return NULL;

    struct shaper_flow *flow = &ue->flows[free_idx];
    memset(flow, 0, sizeof(*flow));
    flow->in_use = true;
    flow->key = *key;
    flow->active_list = SHAPER_ACTIVE_NONE;
    return flow;
}

static inline enum shaper_active_list_id
shaper_active_list_for_head(const struct shaper_flow *flow) {
    if (flow == NULL || flow->head == NULL)
        return SHAPER_ACTIVE_NONE;
    if (!flow->key.is_qos)
        return SHAPER_ACTIVE_NQOS;
    switch (flow->head->color) {
    case UPF_U_SHAPER_COLOR_GREEN:
        return SHAPER_ACTIVE_GREEN;
    case UPF_U_SHAPER_COLOR_YELLOW:
        return SHAPER_ACTIVE_YELLOW;
    default:
        return SHAPER_ACTIVE_NONE;
    }
}

static inline void
shaper_activate_flow(struct ue_shaper *ue, struct shaper_flow *flow) {
    enum shaper_active_list_id list_id = shaper_active_list_for_head(flow);

    if (list_id == SHAPER_ACTIVE_NONE)
        return;

    if (flow->active_list != SHAPER_ACTIVE_NONE) {
        TAILQ_REMOVE(&ue->active[flow->active_list], flow, active_node);
        ue->active_count[flow->active_list]--;
    }
    TAILQ_INSERT_TAIL(&ue->active[list_id], flow, active_node);
    ue->active_count[list_id]++;
    flow->active_list = list_id;
    flow->last_active_tsc = rte_get_tsc_cycles();
}

static inline void
shaper_deactivate_flow(struct ue_shaper *ue, struct shaper_flow *flow) {
    if (flow->active_list == SHAPER_ACTIVE_NONE)
        return;
    TAILQ_REMOVE(&ue->active[flow->active_list], flow, active_node);
    ue->active_count[flow->active_list]--;
    flow->active_list = SHAPER_ACTIVE_NONE;
}

static inline void
shaper_release_empty_flow(struct ue_shaper *ue, struct shaper_flow *flow) {
    shaper_deactivate_flow(ue, flow);
    memset(flow, 0, sizeof(*flow));
}

static inline void
shaper_count_overflow(enum upf_u_shaper_pkt_color color) {
    if (color == UPF_U_SHAPER_COLOR_GREEN)
        __atomic_fetch_add(&g_shaper_drop_green_overflow, 1, __ATOMIC_RELAXED);
    else if (color == UPF_U_SHAPER_COLOR_YELLOW)
        __atomic_fetch_add(&g_shaper_drop_yellow_overflow, 1, __ATOMIC_RELAXED);
    else
        __atomic_fetch_add(&g_shaper_drop_nqos_overflow, 1, __ATOMIC_RELAXED);
}

static inline bool
shaper_class_has_backlog_locked(const struct ue_shaper *ue,
                                enum ue_bucket_class bucket_class) {
    switch (bucket_class) {
    case UE_BUCKET_GREEN:
        return ue->active_count[SHAPER_ACTIVE_GREEN] > 0;
    case UE_BUCKET_YELLOW:
    case UE_BUCKET_NQOS:
        return ue->active_count[SHAPER_ACTIVE_GREEN] > 0 ||
               ue->active_count[SHAPER_ACTIVE_YELLOW] > 0 ||
               ue->active_count[SHAPER_ACTIVE_NQOS] > 0;
    default:
        return false;
    }
}

static inline enum ue_bucket_class
shaper_bucket_for_packet(bool is_qos,
                         enum upf_u_shaper_pkt_color color) {
    if (!is_qos)
        return UE_BUCKET_NQOS;
    if (color == UPF_U_SHAPER_COLOR_GREEN)
        return UE_BUCKET_GREEN;
    if (color == UPF_U_SHAPER_COLOR_YELLOW)
        return UE_BUCKET_YELLOW;
    return UE_BUCKET_NQOS;
}

enum upf_u_shaper_decision
upf_u_shaper_shape_or_enqueue(int ue_idx,
                              const struct upf_u_shaper_flow_key *key,
                              bool is_qos,
                              enum upf_u_shaper_pkt_color color,
                              struct rte_mbuf *pkt, uint32_t pkt_len,
                              struct onvm_pkt_meta *meta) {
    struct ue_shaper *ue;
    struct shaper_flow *flow;
    struct shaper_entry *entry;
    enum ue_bucket_class bucket_class =
        shaper_bucket_for_packet(is_qos, color);

    if (!ueBucketCanFitPacket(ue_idx, bucket_class, pkt_len)) {
        meta->action = ONVM_NF_ACTION_DROP;
        __atomic_fetch_add(&g_shaper_drop_invalid, 1, __ATOMIC_RELAXED);
        return UPF_U_SHAPER_DROP;
    }
    if (unlikely(pkt == NULL || key == NULL || g_shaper_entry_pool == NULL)) {
        meta->action = ONVM_NF_ACTION_DROP;
        shaper_count_overflow(color);
        return UPF_U_SHAPER_DROP;
    }

    ue = &g_ue_shaper[ue_idx];
    rte_spinlock_lock(&ue->lock);

    flow = shaper_lookup_flow(ue, key, false);
    if (flow == NULL &&
        !shaper_class_has_backlog_locked(ue, bucket_class) &&
        consumeUeBucketTokens(ue_idx, bucket_class, pkt_len)) {
        rte_spinlock_unlock(&ue->lock);
        return UPF_U_SHAPER_PASS;
    }

    if (flow == NULL)
        flow = shaper_lookup_flow(ue, key, true);
    if (flow == NULL) {
        rte_spinlock_unlock(&ue->lock);
        meta->action = ONVM_NF_ACTION_DROP;
        __atomic_fetch_add(&g_shaper_drop_flow_table_full, 1,
                           __ATOMIC_RELAXED);
        shaper_count_overflow(color);
        return UPF_U_SHAPER_DROP;
    }
    if (flow->queued_pkts >= SHAPER_MAX_PKTS_PER_FLOW) {
        rte_spinlock_unlock(&ue->lock);
        meta->action = ONVM_NF_ACTION_DROP;
        __atomic_fetch_add(&g_shaper_drop_flow_queue_full, 1,
                           __ATOMIC_RELAXED);
        shaper_count_overflow(color);
        return UPF_U_SHAPER_DROP;
    }
    if (ue->queued_pkts >= SHAPER_MAX_PKTS_PER_UE) {
        rte_spinlock_unlock(&ue->lock);
        meta->action = ONVM_NF_ACTION_DROP;
        __atomic_fetch_add(&g_shaper_drop_ue_queue_full, 1,
                           __ATOMIC_RELAXED);
        shaper_count_overflow(color);
        return UPF_U_SHAPER_DROP;
    }
    if (rte_mempool_get(g_shaper_entry_pool, (void **)&entry) != 0) {
        rte_spinlock_unlock(&ue->lock);
        meta->action = ONVM_NF_ACTION_DROP;
        __atomic_fetch_add(&g_shaper_drop_mempool_empty, 1,
                           __ATOMIC_RELAXED);
        shaper_count_overflow(color);
        return UPF_U_SHAPER_DROP;
    }

    entry->pkt = pkt;
    entry->pkt_len = pkt_len;
    entry->destination = meta->destination;
    entry->color = color;
    entry->next = NULL;

    rte_mbuf_refcnt_update(pkt, 1);
    if (flow->tail != NULL)
        flow->tail->next = entry;
    else
        flow->head = entry;
    flow->tail = entry;
    flow->queued_pkts++;
    flow->queued_bytes += pkt_len;
    ue->queued_pkts++;

    if (flow->queued_pkts == 1)
        shaper_activate_flow(ue, flow);
    shaper_mark_ue_active(ue_idx);

    rte_spinlock_unlock(&ue->lock);

    __atomic_fetch_add(&g_shaper_queued, 1, __ATOMIC_RELAXED);
    meta->action = ONVM_NF_ACTION_DROP;
    return UPF_U_SHAPER_QUEUED;
}

void
upf_u_shaper_drop_red(struct onvm_pkt_meta *meta) {
    if (meta != NULL)
        meta->action = ONVM_NF_ACTION_DROP;
    __atomic_fetch_add(&g_shaper_drop_red, 1, __ATOMIC_RELAXED);
}

static bool
shaper_drain_one_from_list_locked(int ue_idx,
                                  enum shaper_active_list_id list_id,
                                  enum ue_bucket_class bucket_class,
                                  struct rte_mbuf **tx_buf,
                                  uint32_t *nb_tx,
                                  struct onvm_configuration *onvm_config) {
    struct ue_shaper *ue = &g_ue_shaper[ue_idx];
    uint32_t attempts = ue->active_count[list_id];

    while (attempts-- > 0) {
        struct shaper_flow *flow = TAILQ_FIRST(&ue->active[list_id]);
        struct shaper_entry *entry;
        struct rte_mbuf *pkt;

        if (flow == NULL)
            return false;

        shaper_deactivate_flow(ue, flow);
        entry = flow->head;
        if (entry == NULL) {
            shaper_release_empty_flow(ue, flow);
            continue;
        }

        if (!ueBucketCanFitPacket(ue_idx, bucket_class, entry->pkt_len)) {
            flow->head = entry->next;
            if (flow->head == NULL)
                flow->tail = NULL;
            flow->queued_pkts--;
            flow->queued_bytes -= entry->pkt_len;
            ue->queued_pkts--;
            rte_pktmbuf_free(entry->pkt);
            shaper_free_entry(entry);
            __atomic_fetch_add(&g_shaper_drop_invalid, 1, __ATOMIC_RELAXED);
            if (flow->head != NULL)
                shaper_activate_flow(ue, flow);
            else
                shaper_release_empty_flow(ue, flow);
            continue;
        }

        if (!consumeUeBucketTokens(ue_idx, bucket_class, entry->pkt_len)) {
            shaper_activate_flow(ue, flow);
            continue;
        }

        flow->head = entry->next;
        if (flow->head == NULL)
            flow->tail = NULL;
        flow->queued_pkts--;
        flow->queued_bytes -= entry->pkt_len;
        ue->queued_pkts--;

        pkt = entry->pkt;
        struct onvm_pkt_meta *m =
            onvm_get_pkt_meta(pkt, onvm_config->dynfield_offset);
        m->action = ONVM_NF_ACTION_OUT;
        m->destination = entry->destination;
        tx_buf[(*nb_tx)++] = pkt;

        shaper_free_entry(entry);
        if (flow->head != NULL)
            shaper_activate_flow(ue, flow);
        else
            shaper_release_empty_flow(ue, flow);

        __atomic_fetch_add(&g_shaper_drained, 1, __ATOMIC_RELAXED);
        return true;
    }

    return false;
}

static uint32_t
shaper_drain_service_locked(int ue_idx,
                            enum shaper_active_list_id list_id,
                            enum ue_bucket_class bucket_class,
                            struct rte_mbuf **tx_buf,
                            uint32_t *nb_tx,
                            struct onvm_configuration *onvm_config,
                            uint32_t budget) {
    uint32_t sent = 0;

    while (sent < budget &&
           g_ue_shaper[ue_idx].active_count[list_id] > 0) {
        if (!shaper_drain_one_from_list_locked(ue_idx, list_id,
                                               bucket_class, tx_buf, nb_tx,
                                               onvm_config))
            break;
        sent++;
    }

    return sent;
}

static uint32_t
shaper_drain_green_locked(int ue_idx, struct rte_mbuf **tx_buf,
                          uint32_t *nb_tx,
                          struct onvm_configuration *onvm_config,
                          uint32_t budget) {
    return shaper_drain_service_locked(ue_idx, SHAPER_ACTIVE_GREEN,
                                       UE_BUCKET_GREEN, tx_buf, nb_tx,
                                       onvm_config, budget);
}

static uint32_t
shaper_drain_excess_locked(int ue_idx, struct rte_mbuf **tx_buf,
                           uint32_t *nb_tx,
                           struct onvm_configuration *onvm_config,
                           uint32_t budget) {
    struct ue_shaper *ue = &g_ue_shaper[ue_idx];
    uint32_t sent = 0;

    while (sent < budget &&
           (ue->active_count[SHAPER_ACTIVE_YELLOW] > 0 ||
            ue->active_count[SHAPER_ACTIVE_NQOS] > 0)) {
        bool prefer_yellow = ue->next_excess_is_yellow != 0;
        enum shaper_active_list_id list_id = prefer_yellow ?
            SHAPER_ACTIVE_YELLOW : SHAPER_ACTIVE_NQOS;
        enum ue_bucket_class bucket_class = prefer_yellow ?
            UE_BUCKET_YELLOW : UE_BUCKET_NQOS;
        uint32_t n;

        n = shaper_drain_service_locked(ue_idx, list_id, bucket_class,
                                        tx_buf, nb_tx, onvm_config, 1);
        ue->next_excess_is_yellow = !ue->next_excess_is_yellow;
        if (n == 0) {
            list_id = prefer_yellow ? SHAPER_ACTIVE_NQOS :
                                      SHAPER_ACTIVE_YELLOW;
            bucket_class = prefer_yellow ? UE_BUCKET_NQOS :
                                           UE_BUCKET_YELLOW;
            n = shaper_drain_service_locked(ue_idx, list_id, bucket_class,
                                            tx_buf, nb_tx, onvm_config, 1);
            if (n == 0)
                break;
        }
        sent += n;
    }

    return sent;
}

static uint32_t
drain_ue_shaper(int ue_idx, struct onvm_nf *nf, uint32_t budget) {
    struct rte_mbuf *tx_buf[SHAPER_DRAIN_CHUNK];
    struct onvm_configuration *onvm_config;
    struct ue_shaper *ue;
    uint32_t nb_tx = 0;
    uint32_t total = 0;

    if (ue_idx < 0 || ue_idx >= MAX_UE || nf == NULL || budget == 0)
        return 0;

    ue = &g_ue_shaper[ue_idx];
    onvm_config = onvm_nflib_get_onvm_config();
    rte_spinlock_lock(&ue->lock);
    if (ue->queued_pkts == 0) {
        shaper_clear_ue_active(ue_idx);
        rte_spinlock_unlock(&ue->lock);
        return 0;
    }

    while (budget > 0 && nb_tx < SHAPER_DRAIN_CHUNK &&
           ue->queued_pkts > 0) {
        bool sent = false;
        uint32_t tx_room = SHAPER_DRAIN_CHUNK - nb_tx;
        uint32_t burst = RTE_MIN(budget, (uint32_t)SHAPER_CLASS_BURST);
        uint32_t n;

        burst = RTE_MIN(burst, tx_room);
        if (burst == 0)
            break;

        n = shaper_drain_green_locked(ue_idx, tx_buf, &nb_tx,
                                      onvm_config, burst);
        if (n > 0) {
            total += n;
            budget -= n;
            sent = true;
            if (budget == 0 || nb_tx == SHAPER_DRAIN_CHUNK)
                break;
        }

        tx_room = SHAPER_DRAIN_CHUNK - nb_tx;
        burst = RTE_MIN(budget, (uint32_t)SHAPER_CLASS_BURST);
        burst = RTE_MIN(burst, tx_room);
        if (burst == 0)
            break;

        n = shaper_drain_excess_locked(ue_idx, tx_buf, &nb_tx,
                                       onvm_config, burst);
        if (n > 0) {
            total += n;
            budget -= n;
            sent = true;
        }

        if (!sent)
            break;
    }
    if (ue->queued_pkts == 0)
        shaper_clear_ue_active(ue_idx);
    else
        shaper_mark_ue_active(ue_idx);
    rte_spinlock_unlock(&ue->lock);

    if (nb_tx > 0) {
        onvm_pkt_process_tx_batch(nf->nf_tx_mgr, tx_buf,
                                  onvm_config->dynfield_offset, nb_tx, nf);
        onvm_pkt_enqueue_tx_thread(nf->nf_tx_mgr->to_tx_buf, nf);
    }
    return total;
}

uint32_t
upf_u_shaper_drain(struct onvm_nf *nf) {
    uint64_t tried_ue_bitmap[SHAPER_UE_BITMAP_WORDS] = {0};
    uint32_t total = 0;
    uint32_t budget = SHAPER_DRAIN_BUDGET;

    for (uint32_t visited = 0;
         visited < SHAPER_SCAN_BUDGET && budget > 0;
         visited++) {
        int ue_idx = shaper_next_active_ue(tried_ue_bitmap);
        uint32_t drained;

        if (ue_idx < 0)
            break;

        tried_ue_bitmap[(uint32_t)ue_idx / 64] |=
            1ULL << ((uint32_t)ue_idx & 63);
        drained = drain_ue_shaper(ue_idx, nf, budget);
        total += drained;
        budget -= drained;
    }

    return total;
}

void
upf_u_shaper_cleanup(void) {
    for (int ue_idx = 0; ue_idx < MAX_UE; ue_idx++) {
        struct ue_shaper *ue = &g_ue_shaper[ue_idx];

        rte_spinlock_lock(&ue->lock);
        for (int flow_idx = 0;
             flow_idx < SHAPER_MAX_FLOWS_PER_UE;
             flow_idx++) {
            struct shaper_flow *flow = &ue->flows[flow_idx];
            struct shaper_entry *entry = flow->head;

            while (entry != NULL) {
                struct shaper_entry *next = entry->next;
                if (entry->pkt != NULL)
                    rte_pktmbuf_free(entry->pkt);
                shaper_free_entry(entry);
                entry = next;
            }
            memset(flow, 0, sizeof(*flow));
        }
        ue->queued_pkts = 0;
        ue->next_excess_is_yellow = 1;
        for (int list_id = 0; list_id < SHAPER_ACTIVE_COUNT; list_id++) {
            TAILQ_INIT(&ue->active[list_id]);
            ue->active_count[list_id] = 0;
        }
        rte_spinlock_unlock(&ue->lock);
    }
    for (uint32_t word_idx = 0; word_idx < SHAPER_UE_BITMAP_WORDS; word_idx++)
        __atomic_store_n(&g_shaper_active_ue_bitmap[word_idx], 0,
                         __ATOMIC_RELEASE);
    g_shaper_active_ue_cursor = 0;
}

bool
upf_u_shaper_build_dl_flow_key(struct rte_mbuf *pkt, const UPDK_PDR *pdr,
                               uint32_t ue_ip, bool is_qos,
                               struct upf_u_shaper_flow_key *key) {
    struct rte_ipv4_hdr *iph;
    uint16_t l4_off;
    uint32_t pkt_len;

    if (pkt == NULL || key == NULL)
        return false;

    iph = onvm_pkt_ipv4_hdr(pkt);
    if (iph == NULL || ((iph->version_ihl >> 4) != 4))
        return false;

    memset(key, 0, sizeof(*key));
    key->ue_ip = ue_ip;
    key->src_ip = rte_be_to_cpu_32(iph->src_addr);
    key->dst_ip = rte_be_to_cpu_32(iph->dst_addr);
    key->proto = iph->next_proto_id;
    key->is_qos = is_qos ? 1 : 0;
    key->qfi = (is_qos && pdr != NULL && pdr->qer != NULL) ?
               QERGetQFI(pdr->qer) : 0;

    l4_off = sizeof(struct rte_ether_hdr) +
             ((iph->version_ihl & 0x0f) * 4);
    pkt_len = rte_pktmbuf_pkt_len(pkt);
    if (key->proto == IPPROTO_UDP &&
        pkt_len >= l4_off + sizeof(struct rte_udp_hdr)) {
        struct rte_udp_hdr udp_hdr;
        const struct rte_udp_hdr *uh =
            rte_pktmbuf_read(pkt, l4_off, sizeof(udp_hdr), &udp_hdr);
        if (uh == NULL)
            return false;
        key->src_port = rte_be_to_cpu_16(uh->src_port);
        key->dst_port = rte_be_to_cpu_16(uh->dst_port);
    } else if (key->proto == IPPROTO_TCP &&
               pkt_len >= l4_off + sizeof(struct rte_tcp_hdr)) {
        struct rte_tcp_hdr tcp_hdr;
        const struct rte_tcp_hdr *th =
            rte_pktmbuf_read(pkt, l4_off, sizeof(tcp_hdr), &tcp_hdr);
        if (th == NULL)
            return false;
        key->src_port = rte_be_to_cpu_16(th->src_port);
        key->dst_port = rte_be_to_cpu_16(th->dst_port);
    }

    return true;
}

uint32_t
upf_u_shaper_dl_packet_len(struct rte_mbuf *pkt,
                           const struct rte_ipv4_hdr *iph) {
    uint16_t ip_total_len;
    uint16_t ip_hdr_len;
    uint16_t l4_payload_len;
    uint16_t l4_off;
    uint32_t pkt_len;

    if (pkt == NULL || iph == NULL)
        return 0;

    ip_hdr_len = (uint16_t)((iph->version_ihl & 0x0f) * 4);
    ip_total_len = rte_be_to_cpu_16(iph->total_length);
    pkt_len = rte_pktmbuf_pkt_len(pkt);

    if (ip_hdr_len < sizeof(struct rte_ipv4_hdr) ||
        ip_total_len < ip_hdr_len ||
        pkt_len < sizeof(struct rte_ether_hdr) + ip_hdr_len)
        return 0;

    l4_payload_len = ip_total_len - ip_hdr_len;
    l4_off = sizeof(struct rte_ether_hdr) + ip_hdr_len;

    if (iph->next_proto_id == IPPROTO_UDP) {
        if (l4_payload_len >= sizeof(struct rte_udp_hdr) &&
            pkt_len >= l4_off + sizeof(struct rte_udp_hdr))
            return l4_payload_len - sizeof(struct rte_udp_hdr);
        return l4_payload_len;
    }

    if (iph->next_proto_id == IPPROTO_TCP) {
        struct rte_tcp_hdr tcp_hdr;
        const struct rte_tcp_hdr *th;
        uint16_t tcp_hdr_len;

        if (l4_payload_len < sizeof(struct rte_tcp_hdr) ||
            pkt_len < l4_off + sizeof(struct rte_tcp_hdr))
            return l4_payload_len;

        th = rte_pktmbuf_read(pkt, l4_off, sizeof(tcp_hdr), &tcp_hdr);
        if (th == NULL)
            return l4_payload_len;

        tcp_hdr_len = (uint16_t)((th->data_off >> 4) * 4);
        if (tcp_hdr_len < sizeof(struct rte_tcp_hdr) ||
            tcp_hdr_len > l4_payload_len)
            return l4_payload_len;

        return l4_payload_len - tcp_hdr_len;
    }

    return l4_payload_len;
}

void
upf_u_shaper_log_stats(void) {
    UTLT_Debug("shaper queued: %" PRIu64,
               __atomic_load_n(&g_shaper_queued, __ATOMIC_RELAXED));
    UTLT_Debug("shaper drained: %" PRIu64,
               __atomic_load_n(&g_shaper_drained, __ATOMIC_RELAXED));
    UTLT_Debug("shaper invalid drops: %" PRIu64,
               __atomic_load_n(&g_shaper_drop_invalid, __ATOMIC_RELAXED));
    UTLT_Debug("shaper red drops: %" PRIu64,
               __atomic_load_n(&g_shaper_drop_red, __ATOMIC_RELAXED));
    UTLT_Debug("shaper green overflow drops: %" PRIu64,
               __atomic_load_n(&g_shaper_drop_green_overflow,
                               __ATOMIC_RELAXED));
    UTLT_Debug("shaper yellow overflow drops: %" PRIu64,
               __atomic_load_n(&g_shaper_drop_yellow_overflow,
                               __ATOMIC_RELAXED));
    UTLT_Debug("shaper non-QoS overflow drops: %" PRIu64,
               __atomic_load_n(&g_shaper_drop_nqos_overflow,
                               __ATOMIC_RELAXED));
    UTLT_Debug("shaper flow table full drops: %" PRIu64,
               __atomic_load_n(&g_shaper_drop_flow_table_full,
                               __ATOMIC_RELAXED));
    UTLT_Debug("shaper flow queue full drops: %" PRIu64,
               __atomic_load_n(&g_shaper_drop_flow_queue_full,
                               __ATOMIC_RELAXED));
    UTLT_Debug("shaper UE queue full drops: %" PRIu64,
               __atomic_load_n(&g_shaper_drop_ue_queue_full,
                               __ATOMIC_RELAXED));
    UTLT_Debug("shaper mempool empty drops: %" PRIu64,
               __atomic_load_n(&g_shaper_drop_mempool_empty,
                               __ATOMIC_RELAXED));
}
