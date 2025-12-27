#include "upf_u_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <yaml.h>

extern uint8_t  DnMac[6];
extern uint8_t  AnMac[6];
extern uint32_t SELF_IP;
extern int16_t  g_access_port;
extern int16_t  g_core_port;
extern int16_t  g_sgi_port;


static void fatal(const char *msg) {
    fprintf(stderr, "[UPF-U][CONFIG] %s\n", msg);
    exit(EXIT_FAILURE);
}

static int parse_mac(const char *txt, uint8_t out[6]) {
    int v[6];
    if (sscanf(txt, " %x:%x:%x:%x:%x:%x ", &v[0],&v[1],&v[2],&v[3],&v[4],&v[5]) != 6) return -1;
    for (int i=0;i<6;i++) out[i] = (uint8_t)v[i];
    return 0;
}


int parseIpv4Address(const char *s);

// --- libyaml DOM helpers ---

static yaml_node_t* doc_root(yaml_document_t *doc) {
    // The first (and only) document's root is node id 1 for libyaml DOM
    if (!doc || doc->nodes.top <= doc->nodes.start) return NULL;
    return yaml_document_get_root_node(doc);
}

// Look up a mapping value by 'key' string. Returns the value node or NULL.
static yaml_node_t* map_get(yaml_document_t *doc, yaml_node_t *map, const char *key) {
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

static const char* scalar_str(yaml_node_t *n) {
    if (!n || n->type != YAML_SCALAR_NODE) return NULL;
    return (const char*)n->data.scalar.value;
}

// --- Parse logic: configuration -> dataplane -> fields ---

static int do_parse(yaml_document_t *doc) {
    yaml_node_t *root = doc_root(doc);
    if (!root || root->type != YAML_MAPPING_NODE)
        return -1;

    yaml_node_t *info = map_get(doc, root, "info");           // optional
    (void)info;

    yaml_node_t *cfg  = map_get(doc, root, "configuration");
    if (!cfg || cfg->type != YAML_MAPPING_NODE)
        return -1;

    yaml_node_t *dp   = map_get(doc, cfg,  "dataplane");
    if (!dp || dp->type != YAML_MAPPING_NODE)
        return -1;

    // dn_mac
    {
        yaml_node_t *n = map_get(doc, dp, "dn_mac");
        const char *s = scalar_str(n);
        if (!s || parse_mac(s, DnMac) != 0) {
            fprintf(stderr, "[UPF-U][CONFIG] invalid dn_mac\n");
            return -1;
        }
    }

    // an_mac
    {
        yaml_node_t *n = map_get(doc, dp, "an_mac");
        const char *s = scalar_str(n);
        if (!s || parse_mac(s, AnMac) != 0) {
            fprintf(stderr, "[UPF-U][CONFIG] invalid an_mac\n");
            return -1;
        }
    }

    // upf_ip
    {
        yaml_node_t *n = map_get(doc, dp, "upf_ip");
        if (!n || n->type != YAML_SCALAR_NODE) {
            fprintf(stderr, "[UPF-U][CONFIG] missing upf_ip\n");
            return -1;
        }
        const unsigned char *p = n->data.scalar.value;
        size_t len = n->data.scalar.length;

        char buf[64];
        if (len >= sizeof(buf)) len = sizeof(buf) - 1;
        memcpy(buf, p, len);
        buf[len] = '\0';

        if (parseIpv4Address(buf)) {
            fprintf(stderr, "[UPF-U][CONFIG] invalid upf_ip\n");
            return -1;
        }
    }

    // dataplane.ports
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
            g_access_port = (int16_t)v;
        }
        // core  (SGi follows CORE)
        {
            yaml_node_t *n = map_get(doc, ports, "core");
            const char *s = scalar_str(n);
            if (!s) { fprintf(stderr, "[UPF-U][CONFIG] missing ports.core\n"); return -1; }
            int v = atoi(s);
            if (v < 0 || v > 255) { fprintf(stderr, "[UPF-U][CONFIG] bad ports.core\n"); return -1; }
            g_core_port = (int16_t)v;
            g_sgi_port  = (int16_t)v;
        }
    }

    return 0;
}

int UpfU_TryLoadAndParseConfig(const char *path) {
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

void UpfU_LoadAndParseConfig(const char *path) {
    if (UpfU_TryLoadAndParseConfig(path) != 0) {
        fatal("Failed to load/parse UPF-U YAML config.");
    }
}
