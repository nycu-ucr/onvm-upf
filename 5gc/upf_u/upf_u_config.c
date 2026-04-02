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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <yaml.h>

#include "upf_u_config.h"
#include "utlt_debug.h"

struct rte_ether_addr g_cn_ue_eth;
struct rte_ether_addr g_cn_dn_eth;

uint16_t g_access_port = 0;
uint16_t g_core_port   = 0;
uint16_t g_sgi_port    = 0;

uint32_t g_access_ip_be = 0;
uint32_t g_core_ip_be   = 0;
uint32_t g_an_peer_ip_be = 0;
uint32_t g_dn_peer_ip_be = 0;

char g_log_level[16] = "warning";

static int
parse_mac(const char *input_string, uint8_t out_mac_addr[6]) {
    int v[6];
    if (sscanf(input_string, " %x:%x:%x:%x:%x:%x ", &v[0],&v[1],&v[2],&v[3],&v[4],&v[5]) != 6) return -1;
    for (int i = 0; i < 6; i++) out_mac_addr[i] = (uint8_t)v[i];
    return 0;
}

static int
parse_ipv4_address(const char *addrStr, uint32_t *out_ip_be) {
    const char *p = addrStr;
    char *endp;

    unsigned long a = strtoul(p, &endp, 10);
    if (*endp != '.')
        return -1;
    unsigned long b = strtoul(p = endp + 1, &endp, 10);
    if (*endp != '.')
        return -1;
    unsigned long c = strtoul(p = endp + 1, &endp, 10);
    if (*endp != '.')
        return -1;
    unsigned long d = strtoul(p = endp + 1, &endp, 10);

    *out_ip_be = (uint32_t)((d << 24) | (c << 16) | (b << 8) | a);
    UTLT_Info("IP Address: %s -> %d\n", addrStr, *out_ip_be);
    return 0;
}

// --- libyaml DOM helpers ---

static yaml_node_t*
doc_root(yaml_document_t *doc) {
    // The first (and only) document's root is node id 1 for libyaml DOM
    if (!doc || doc->nodes.top <= doc->nodes.start) return NULL;
    return yaml_document_get_root_node(doc);
}

// Look up a mapping value by 'key' string. Returns the value node or NULL.
static yaml_node_t*
map_get(yaml_document_t *doc, yaml_node_t *map, const char *key) {
    if (!map || map->type != YAML_MAPPING_NODE) return NULL;
    for (yaml_node_pair_t *p = map->data.mapping.pairs.start;
         p < map->data.mapping.pairs.top; ++p) {
        yaml_node_t *k = yaml_document_get_node(doc, p->key);
        yaml_node_t *v = yaml_document_get_node(doc, p->value);
        if (!k || k->type != YAML_SCALAR_NODE) continue;
        if (k->data.scalar.value && strcmp((const char*)k->data.scalar.value, key) == 0)
            return v;
    }
    return NULL;
}

static const char*
scalar_str(yaml_node_t *n) {
    if (!n || n->type != YAML_SCALAR_NODE) return NULL;
    return (const char*)n->data.scalar.value;
}

// --- Parse logic: configuration -> dataplane -> fields ---

static int
do_parse(yaml_document_t *doc) {
    yaml_node_t *root = doc_root(doc);
    if (!root || root->type != YAML_MAPPING_NODE)
        return -1;

    yaml_node_t *info = map_get(doc, root, "info");           // optional
    (void)info;

    yaml_node_t *cfg  = map_get(doc, root, "configuration");
    if (!cfg || cfg->type != YAML_MAPPING_NODE)
        return -1;

    // log_level (optional)
    {
        yaml_node_t *n = map_get(doc, cfg, "log_level");
        const char *s = scalar_str(n);

        if (s && *s) {
            size_t len = strlen(s);
            if (len >= sizeof(g_log_level))
                len = sizeof(g_log_level) - 1;
            memcpy(g_log_level, s, len);
            g_log_level[len] = '\0';
        }
    }

    yaml_node_t *dp   = map_get(doc, cfg,  "dataplane");
    if (!dp || dp->type != YAML_MAPPING_NODE)
        return -1;

    // upf_access_ip
    {
        yaml_node_t *n = map_get(doc, dp, "upf_access_ip");
        if (!n || n->type != YAML_SCALAR_NODE) {
            fprintf(stderr, "[UPF-U][CONFIG] missing upf_access_ip\n");
            return -1;
        }
        const unsigned char *p = n->data.scalar.value;
        size_t len = n->data.scalar.length;

        char buf[64];
        if (len >= sizeof(buf)) len = sizeof(buf) - 1;
        memcpy(buf, p, len);
        buf[len] = '\0';

        if (parse_ipv4_address(buf, &g_access_ip_be) != 0) {
            fprintf(stderr, "[UPF-U][CONFIG] invalid upf_access_ip\n");
            return -1;
        }
    }

    // upf_core_ip
    {
        yaml_node_t *n = map_get(doc, dp, "upf_core_ip");
        if (!n || n->type != YAML_SCALAR_NODE) {
            fprintf(stderr, "[UPF-U][CONFIG] missing upf_core_ip\n");
            return -1;
        }
        const unsigned char *p = n->data.scalar.value;
        size_t len = n->data.scalar.length;

        char buf[64];
        if (len >= sizeof(buf)) len = sizeof(buf) - 1;
        memcpy(buf, p, len);
        buf[len] = '\0';

        if (parse_ipv4_address(buf, &g_core_ip_be) != 0) {
            fprintf(stderr, "[UPF-U][CONFIG] invalid upf_core_ip\n");
            return -1;
        }
    }

    // an_peer_ip
    {
        yaml_node_t *n = map_get(doc, dp, "an_peer_ip");
        if (!n || n->type != YAML_SCALAR_NODE) {
            fprintf(stderr, "[UPF-U][CONFIG] missing an_peer_ip\n");
            return -1;
        }
        const unsigned char *p = n->data.scalar.value;
        size_t len = n->data.scalar.length;

        char buf[64];
        if (len >= sizeof(buf)) len = sizeof(buf) - 1;
        memcpy(buf, p, len);
        buf[len] = '\0';

        if (parse_ipv4_address(buf, &g_an_peer_ip_be) != 0) {
            fprintf(stderr, "[UPF-U][CONFIG] invalid an_peer_ip\n");
            return -1;
        }
    }

    // dn_peer_ip
    {
        yaml_node_t *n = map_get(doc, dp, "dn_peer_ip");
        if (!n || n->type != YAML_SCALAR_NODE) {
            fprintf(stderr, "[UPF-U][CONFIG] missing dn_peer_ip\n");
            return -1;
        }
        const unsigned char *p = n->data.scalar.value;
        size_t len = n->data.scalar.length;

        char buf[64];
        if (len >= sizeof(buf)) len = sizeof(buf) - 1;
        memcpy(buf, p, len);
        buf[len] = '\0';

        if (parse_ipv4_address(buf, &g_dn_peer_ip_be) != 0) {
            fprintf(stderr, "[UPF-U][CONFIG] invalid dn_peer_ip\n");
            return -1;
        }
    }

    // ports
    {
        yaml_node_t *ports = map_get(doc, dp, "ports");
        if (!ports || ports->type != YAML_MAPPING_NODE) {
            fprintf(stderr, "[UPF-U][CONFIG] missing dataplane.ports\n");
            return -1;
        }
        // access
        {
            yaml_node_t *n = map_get(doc, ports, "access");
            const char *s = scalar_str(n);
            if (!s) { fprintf(stderr, "[UPF-U][CONFIG] missing ports.access\n"); return -1; }
            int v = atoi(s);
            if (v < 0 || v > 255) { fprintf(stderr, "[UPF-U][CONFIG] bad ports.access\n"); return -1; }
            g_access_port = (uint16_t)v;
        }
        // core  (SGi follows CORE)
        {
            yaml_node_t *n = map_get(doc, ports, "core");
            const char *s = scalar_str(n);
            if (!s) { fprintf(stderr, "[UPF-U][CONFIG] missing ports.core\n"); return -1; }
            int v = atoi(s);
            if (v < 0 || v > 255) { fprintf(stderr, "[UPF-U][CONFIG] bad ports.core\n"); return -1; }
            g_core_port = (uint16_t)v;
            g_sgi_port  = (uint16_t)v;
        }
    }

    return 0;
}

int
UpfU_LoadAndParseConfig(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "[UPF-U][CONFIG] cannot open config file: %s\n", path);
        return -1;
    }

    yaml_parser_t parser;
    yaml_document_t document;
    if (!yaml_parser_initialize(&parser)) {
        fclose(fp);
        fprintf(stderr, "[UPF-U][CONFIG] yaml_parser_initialize failed\n");
        return -1;
    }
    yaml_parser_set_input_file(&parser, fp);

    // Load a full DOM (single-document expected)
    if (!yaml_parser_load(&parser, &document)) {
        yaml_parser_delete(&parser);
        fclose(fp);
        fprintf(stderr, "[UPF-U][CONFIG] yaml_parser_load failed (malformed YAML?)\n");
        return -1;
    }

    int rc = do_parse(&document);

    yaml_document_delete(&document);
    yaml_parser_delete(&parser);
    fclose(fp);

    return rc == 0 ? 0 : -1;
}

void
init_l2_addrs(void) {
    int ret;

    ret = rte_eth_macaddr_get(g_access_port, &g_cn_ue_eth);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE,
                 "Cannot get MAC address: err=%d, port=%" PRIu16 "\n",
                 ret, g_access_port);
    }

    ret = rte_eth_macaddr_get(g_core_port, &g_cn_dn_eth);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE,
                 "Cannot get MAC address: err=%d, port=%" PRIu16 "\n",
                 ret, g_core_port);
    }
}