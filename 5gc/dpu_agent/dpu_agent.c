/*
 * dpu_agent.c — DPU Offload Agent (standalone DOCA application on BF3 ARM)
 *
 * Runs natively on the BlueField-3 ARM cores. Naturally initialises as the
 * primary owner of the physical HW devices (no --proc-type flag needed).
 *
 * Lifecycle:
 *   1. Parse CLI for PCI device, port IDs, MAC addresses
 *   2. Open DOCA Comch server — waits for Host Agent connection
 *   3. Initialise DOCA Flow pipeline (7-pipe switch,hws hierarchy)
 *   4. Main loop: drive DOCA PE for Comch events
 *      - On recv: deserialise hw_offload_msg → dpu_pipeline_insert_rule()
 *   5. On SIGINT: destroy pipeline, close Comch, exit
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <doca_comch.h>
#include <doca_dev.h>
#include <doca_error.h>
#include <doca_log.h>
#include <doca_pe.h>

#include "hw_offload_msg.h"
#include "dpu_pipeline.h"

DOCA_LOG_REGISTER(DPU_AGENT);

/* ── Globals ────────────────────────────────────────────────────────── */
static volatile bool g_running = true;
static dpu_pipeline_ctx_t g_pipeline;

/* DOCA Comch server state */
static struct doca_dev          *g_comch_dev;
static struct doca_comch_server *g_comch_server;
static struct doca_pe           *g_comch_pe;

/* Counters */
static uint64_t g_msgs_received;
static uint64_t g_rules_inserted;
static uint64_t g_rules_failed;

/* ── CLI defaults ───────────────────────────────────────────────────── */
static char g_pci_addr[32]    = "03:00.0";
static char g_server_name[64] = "dpu_agent";

/* Port IDs (explicitly assigned via doca_flow_port_cfg_set_port_id) */
static uint16_t g_n3_port_id      = 0;
static uint16_t g_n6_port_id      = 1;
static uint16_t g_host_vf_port_id = 2;

/* MAC addresses (configurable via CLI) */
static uint8_t g_upf_n6_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
static uint8_t g_dn_gw_mac[6]  = {0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
static uint8_t g_upf_n3_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x03};
static uint8_t g_gnb_mac[6]    = {0x00, 0x00, 0x00, 0x00, 0x00, 0x04};
static uint32_t g_upf_n3_ip    = 0;  /* NBO, set via CLI */


/* ── Signal handler ─────────────────────────────────────────────────── */
static void
signal_handler(int sig)
{
    (void)sig;
    DOCA_LOG_INFO("Signal received — shutting down");
    g_running = false;
}


/* ═══════════════════════════════════════════════════════════════════════
 *  DOCA Comch callbacks
 * ═══════════════════════════════════════════════════════════════════════ */

static void
comch_server_connection_cb(struct doca_comch_event_connection_status_changed *event,
                           struct doca_comch_connection *conn,
                           uint8_t change_successful)
{
    if (change_successful)
        DOCA_LOG_INFO("Host Agent connected via Comch");
    else
        DOCA_LOG_WARN("Comch connection status change failed");
    (void)event;
    (void)conn;
}

static void
comch_server_disconnect_cb(struct doca_comch_event_connection_status_changed *event,
                           struct doca_comch_connection *conn,
                           uint8_t change_successful)
{
    DOCA_LOG_WARN("Host Agent disconnected from Comch");
    (void)event;
    (void)conn;
    (void)change_successful;
}

/**
 * Main Comch recv callback — this is where hw_offload_msg arrives
 * from the Host Agent and gets programmed into DOCA Flow silicon.
 */
static void
comch_recv_cb(struct doca_comch_event_msg_recv *event,
              uint8_t *recv_buffer,
              uint32_t msg_len,
              struct doca_comch_connection *conn)
{
    (void)event;
    (void)conn;

    g_msgs_received++;

    if (msg_len < sizeof(hw_offload_msg_t)) {
        DOCA_LOG_WARN("Comch recv: msg too short (%u < %zu)",
                      msg_len, sizeof(hw_offload_msg_t));
        return;
    }

    const hw_offload_msg_t *msg = (const hw_offload_msg_t *)recv_buffer;

    if (msg->magic != HW_OFFLOAD_MAGIC) {
        DOCA_LOG_WARN("Comch recv: bad magic 0x%08x", msg->magic);
        return;
    }

    DOCA_LOG_INFO("Comch recv: op=%u dir=%s pdr=%u hw_rule=%u",
                  msg->op,
                  msg->direction == HW_DIR_UPLINK ? "UL" : "DL",
                  msg->pdr_id, msg->hw_rule_id);

    switch (msg->op) {
    case HW_OP_CREATE: {
        doca_error_t result = dpu_pipeline_insert_rule(&g_pipeline, msg);
        if (result == DOCA_SUCCESS) {
            g_rules_inserted++;
        } else {
            g_rules_failed++;
            DOCA_LOG_ERR("Rule insert failed for hw_rule_id=%u: %s",
                         msg->hw_rule_id, doca_error_get_descr(result));
        }
        break;
    }
    case HW_OP_DELETE:
        /* Phase 2: implement rule deletion by hw_rule_id */
        DOCA_LOG_WARN("HW_OP_DELETE not implemented (Phase 2)");
        break;
    case HW_OP_UPDATE:
        DOCA_LOG_WARN("HW_OP_UPDATE not implemented (Phase 2)");
        break;
    default:
        DOCA_LOG_WARN("Unknown op=%u", msg->op);
        break;
    }
}

/* Comch send task completion callback (task-based model) */
static void
comch_send_complete_cb(struct doca_comch_task_send *task,
                       union doca_data task_user_data,
                       union doca_data ctx_user_data)
{
    (void)task;
    (void)task_user_data;
    (void)ctx_user_data;
}


/* ═══════════════════════════════════════════════════════════════════════
 *  DOCA Comch server init
 * ═══════════════════════════════════════════════════════════════════════ */

/* Open device by PCI address */
static doca_error_t
open_doca_device_by_pci(const char *pci_addr, struct doca_dev **dev)
{
    struct doca_devinfo **dev_list;
    uint32_t nb_devs;
    doca_error_t result;

    result = doca_devinfo_create_list(&dev_list, &nb_devs);
    if (result != DOCA_SUCCESS) return result;

    for (uint32_t i = 0; i < nb_devs; i++) {
        char addr_buf[DOCA_DEVINFO_PCI_ADDR_SIZE] = {};
        result = doca_devinfo_get_pci_addr_str(dev_list[i], addr_buf);
        if (result != DOCA_SUCCESS)
            continue;
        if (strcmp(addr_buf, pci_addr) == 0) {
            result = doca_dev_open(dev_list[i], dev);
            doca_devinfo_destroy_list(dev_list);
            return result;
        }
    }

    doca_devinfo_destroy_list(dev_list);
    return DOCA_ERROR_NOT_FOUND;
}

static int
comch_server_init(void)
{
    doca_error_t result;

    result = open_doca_device_by_pci(g_pci_addr, &g_comch_dev);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Cannot open device %s: %s",
                     g_pci_addr, doca_error_get_descr(result));
        return -1;
    }

    result = doca_pe_create(&g_comch_pe);
    if (result != DOCA_SUCCESS) return -1;

    /* Server create: (dev, rep_dev, server_name, &server)
     * rep_dev = NULL — DPU runs natively, no representor needed */
    result = doca_comch_server_create(g_comch_dev, NULL, g_server_name,
                                      &g_comch_server);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Comch server create failed: %s",
                     doca_error_get_descr(result));
        return -1;
    }

    struct doca_ctx *ctx = doca_comch_server_as_ctx(g_comch_server);

    /* Connect PE to server context */
    result = doca_pe_connect_ctx(g_comch_pe, ctx);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to connect PE to server ctx: %s",
                     doca_error_get_descr(result));
        return -1;
    }

    /* Set max message size */
    result = doca_comch_server_set_max_msg_size(g_comch_server,
                                                 sizeof(hw_offload_msg_t) + 64);
    if (result != DOCA_SUCCESS) return -1;

    /* Configure send task callbacks (required for task-based send) */
    result = doca_comch_server_task_send_set_conf(g_comch_server,
                                                   comch_send_complete_cb,
                                                   comch_send_complete_cb,
                                                   8);
    if (result != DOCA_SUCCESS) return -1;

    /* Register recv event callback */
    result = doca_comch_server_event_msg_recv_register(g_comch_server,
                                                        comch_recv_cb);
    if (result != DOCA_SUCCESS) return -1;

    /* Register connection + disconnection callbacks (both in one call) */
    result = doca_comch_server_event_connection_status_changed_register(
                g_comch_server,
                comch_server_connection_cb,
                comch_server_disconnect_cb);
    if (result != DOCA_SUCCESS) return -1;

    /* Start the server context */
    result = doca_ctx_start(ctx);
    if (result != DOCA_SUCCESS && result != DOCA_ERROR_IN_PROGRESS) {
        DOCA_LOG_ERR("Comch server start failed: %s",
                     doca_error_get_descr(result));
        return -1;
    }

    DOCA_LOG_INFO("Comch server started: name=%s dev=%s",
                  g_server_name, g_pci_addr);
    return 0;
}

static void
comch_server_destroy(void)
{
    if (g_comch_server) {
        doca_ctx_stop(doca_comch_server_as_ctx(g_comch_server));
        doca_comch_server_destroy(g_comch_server);
        g_comch_server = NULL;
    }
    if (g_comch_pe) {
        doca_pe_destroy(g_comch_pe);
        g_comch_pe = NULL;
    }
    if (g_comch_dev) {
        doca_dev_close(g_comch_dev);
        g_comch_dev = NULL;
    }
}


/* ═══════════════════════════════════════════════════════════════════════
 *  CLI parsing
 * ═══════════════════════════════════════════════════════════════════════ */

static int
parse_mac(const char *str, uint8_t mac[6])
{
    unsigned int m[6];
    if (sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
               &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++)
        mac[i] = (uint8_t)m[i];
    return 0;
}

static void
usage(const char *progname)
{
    printf("Usage: %s [options]\n\n", progname);
    printf("Options:\n");
    printf("  -d <PCI>          BF3 PCI address         (default: %s)\n", g_pci_addr);
    printf("  -s <name>         Comch server name        (default: %s)\n", g_server_name);
    printf("  --n3-port <id>    N3 physical port ID      (default: %u)\n", g_n3_port_id);
    printf("  --n6-port <id>    N6 physical port ID      (default: %u)\n", g_n6_port_id);
    printf("  --vf-port <id>    Host VF representor ID   (default: %u)\n", g_host_vf_port_id);
    printf("  --upf-n3-ip <IP>  UPF N3 IP (for encap)   (required)\n");
    printf("  --upf-n6-mac <M>  UPF N6 MAC (for UL L2 inject)\n");
    printf("  --dn-gw-mac <M>   DN gateway MAC\n");
    printf("  --upf-n3-mac <M>  UPF N3 MAC (for DL encap)\n");
    printf("  --gnb-mac <M>     gNB MAC (for DL encap)\n");
    printf("  -h                Show this help\n");
}

static int
parse_args(int argc, char *argv[])
{
    static struct option long_opts[] = {
        {"n3-port",     required_argument, NULL, 0},
        {"n6-port",     required_argument, NULL, 0},
        {"vf-port",     required_argument, NULL, 0},
        {"upf-n3-ip",   required_argument, NULL, 0},
        {"upf-n6-mac",  required_argument, NULL, 0},
        {"dn-gw-mac",   required_argument, NULL, 0},
        {"upf-n3-mac",  required_argument, NULL, 0},
        {"gnb-mac",     required_argument, NULL, 0},
        {NULL,          0,                 NULL, 0},
    };

    int c, opt_idx;
    while ((c = getopt_long(argc, argv, "d:s:h", long_opts, &opt_idx)) != -1) {
        if (c == 0) {
            const char *name = long_opts[opt_idx].name;
            if (strcmp(name, "n3-port") == 0)
                g_n3_port_id = (uint16_t)atoi(optarg);
            else if (strcmp(name, "n6-port") == 0)
                g_n6_port_id = (uint16_t)atoi(optarg);
            else if (strcmp(name, "vf-port") == 0)
                g_host_vf_port_id = (uint16_t)atoi(optarg);
            else if (strcmp(name, "upf-n3-ip") == 0) {
                struct in_addr a;
                if (inet_pton(AF_INET, optarg, &a) == 1)
                    g_upf_n3_ip = a.s_addr;  /* NBO */
                else {
                    fprintf(stderr, "Invalid IP: %s\n", optarg);
                    return -1;
                }
            }
            else if (strcmp(name, "upf-n6-mac") == 0)
                parse_mac(optarg, g_upf_n6_mac);
            else if (strcmp(name, "dn-gw-mac") == 0)
                parse_mac(optarg, g_dn_gw_mac);
            else if (strcmp(name, "upf-n3-mac") == 0)
                parse_mac(optarg, g_upf_n3_mac);
            else if (strcmp(name, "gnb-mac") == 0)
                parse_mac(optarg, g_gnb_mac);
        } else if (c == 'd') {
            snprintf(g_pci_addr, sizeof(g_pci_addr), "%s", optarg);
        } else if (c == 's') {
            snprintf(g_server_name, sizeof(g_server_name), "%s", optarg);
        } else if (c == 'h') {
            usage(argv[0]);
            return -1;
        } else {
            usage(argv[0]);
            return -1;
        }
    }

    if (g_upf_n3_ip == 0) {
        fprintf(stderr, "ERROR: --upf-n3-ip is required\n");
        usage(argv[0]);
        return -1;
    }

    return 0;
}


/* ═══════════════════════════════════════════════════════════════════════
 *  main
 * ═══════════════════════════════════════════════════════════════════════ */

int
main(int argc, char *argv[])
{
    signal(SIGINT,  signal_handler);
    signal(SIGTERM, signal_handler);

    if (parse_args(argc, argv) < 0)
        return EXIT_FAILURE;

    /* ── Comch server ──────────────────────────────────────────────── */
    if (comch_server_init() < 0) {
        DOCA_LOG_ERR("Failed to init Comch server");
        return EXIT_FAILURE;
    }

    /* ── DOCA Flow pipeline ────────────────────────────────────────── */
    dpu_port_cfg_t port_cfg = {};
    port_cfg.n3_port_id      = g_n3_port_id;
    port_cfg.n6_port_id      = g_n6_port_id;
    port_cfg.host_vf_port_id = g_host_vf_port_id;
    port_cfg.upf_n3_ip       = g_upf_n3_ip;
    memcpy(port_cfg.upf_n6_mac, g_upf_n6_mac, 6);
    memcpy(port_cfg.dn_gw_mac,  g_dn_gw_mac,  6);
    memcpy(port_cfg.upf_n3_mac, g_upf_n3_mac, 6);
    memcpy(port_cfg.gnb_mac,    g_gnb_mac,    6);

    doca_error_t result = dpu_pipeline_init(&g_pipeline, &port_cfg);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Pipeline init failed: %s", doca_error_get_descr(result));
        comch_server_destroy();
        return EXIT_FAILURE;
    }

    /* ── Main loop: drive Comch event loop ─────────────────────────── */
    DOCA_LOG_INFO("DPU Agent running — waiting for hw_offload_msg from Host");

    while (g_running) {
        doca_pe_progress(g_comch_pe);
        /* Optionally add usleep(100) to reduce CPU burn on ARM cores */
    }

    /* ── Cleanup ───────────────────────────────────────────────────── */
    dpu_pipeline_destroy(&g_pipeline);
    comch_server_destroy();

    DOCA_LOG_INFO("DPU Agent exiting: recv=%lu inserted=%lu failed=%lu",
                  g_msgs_received, g_rules_inserted, g_rules_failed);
    return EXIT_SUCCESS;
}
