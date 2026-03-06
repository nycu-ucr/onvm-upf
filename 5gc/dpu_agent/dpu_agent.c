/*
 * dpu_agent.c — DPU Offload Agent (standalone DOCA application on BF3 ARM)
 *
 * Runs natively on the BlueField-3 ARM cores. Naturally initialises as the
 * primary owner of the physical HW devices (no --proc-type flag needed).
 *
 * Lifecycle:
 *   1. doca_argp parses CLI / JSON config, calls DPDK EAL init callback
 *   2. Open DOCA Comch server — waits for Host Agent connection
 *   3. Initialise DOCA Flow pipeline (7-pipe switch,hws hierarchy)
 *   4. Main loop: drive DOCA PE for Comch events
 *      - On recv: deserialise hw_offload_msg → dpu_pipeline_insert_rule()
 *   5. On SIGINT: destroy pipeline, close Comch, exit
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <rte_eal.h>

#include <doca_argp.h>
#include <doca_comch.h>
#include <doca_dev.h>
#include <doca_error.h>
#include <doca_log.h>
#include <doca_pe.h>

#include "hw_offload_msg.h"
#include "dpu_pipeline.h"
#include "dpu_agent_config.h"

DOCA_LOG_REGISTER(DPU_AGENT);

/* ── Globals ────────────────────────────────────────────────────────── */
static volatile bool g_running = true;
static dpu_pipeline_ctx_t g_pipeline;

/* DOCA Comch server state */
static struct doca_dev          *g_comch_dev;
static struct doca_dev_rep      *g_comch_rep;   /* host PF/VF representor */
static struct doca_comch_server *g_comch_server;
static struct doca_pe           *g_comch_pe;

/* Counters */
static uint64_t g_msgs_received;
static uint64_t g_rules_inserted;
static uint64_t g_rules_failed;

/* Opened DOCA devices for Flow ports */
static struct doca_dev *g_n3_dev;
static struct doca_dev *g_n6_dev;
static struct doca_dev *g_vf_dev;

/* ── Configuration (populated by doca_argp from CLI / JSON) ─────────── */
static dpu_agent_cfg_t g_cfg = {
    .comch_pci       = "03:00.0",
    .rep_pci         = "",
    .server_name     = "dpu_agent",
    .n3_pci          = "03:00.0",
    .n6_pci          = "03:00.1",
    .vf_pci          = "",
    .n3_port_id      = 0,
    .n6_port_id      = 1,
    .host_vf_port_id = 2,
    .upf_n3_ip_str   = "",
    .upf_n3_mac_str  = "00:00:00:00:00:03",
    .gnb_mac_str     = "00:00:00:00:00:04",
    .upf_n6_mac_str  = "00:00:00:00:00:01",
    .dn_gw_mac_str   = "00:00:00:00:00:02",
};


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

/* Comch send task completion callbacks (task-based model) */
static void
comch_send_complete_cb(struct doca_comch_task_send *task,
                       union doca_data task_user_data,
                       union doca_data ctx_user_data)
{
    (void)task;
    (void)task_user_data;
    (void)ctx_user_data;
}

static void
comch_send_error_cb(struct doca_comch_task_send *task,
                    union doca_data task_user_data,
                    union doca_data ctx_user_data)
{
    (void)task_user_data;
    (void)ctx_user_data;
    DOCA_LOG_WARN("Comch send task failed");
    doca_task_free(doca_comch_task_send_as_task(task));
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

/* Open representor device by PCI address (server-side, for Comch) */
static doca_error_t
open_doca_device_rep_by_pci(struct doca_dev *dev, const char *rep_pci_addr,
                            struct doca_dev_rep **rep_dev)
{
    struct doca_devinfo_rep **rep_list;
    uint32_t nb_reps;
    doca_error_t result;

    result = doca_devinfo_rep_create_list(dev, DOCA_DEVINFO_REP_FILTER_NET,
                                          &rep_list, &nb_reps);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to list representors: %s",
                     doca_error_get_descr(result));
        return result;
    }

    for (uint32_t i = 0; i < nb_reps; i++) {
        char addr_buf[DOCA_DEVINFO_REP_PCI_ADDR_SIZE] = {};
        result = doca_devinfo_rep_get_pci_addr_str(rep_list[i], addr_buf);
        if (result != DOCA_SUCCESS)
            continue;
        if (strcmp(addr_buf, rep_pci_addr) == 0) {
            result = doca_dev_rep_open(rep_list[i], rep_dev);
            doca_devinfo_rep_destroy_list(rep_list);
            return result;
        }
    }

    doca_devinfo_rep_destroy_list(rep_list);
    DOCA_LOG_ERR("Representor %s not found on device", rep_pci_addr);
    return DOCA_ERROR_NOT_FOUND;
}

static int
comch_server_init(void)
{
    doca_error_t result;

    result = open_doca_device_by_pci(g_cfg.comch_pci, &g_comch_dev);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Cannot open device %s: %s",
                     g_cfg.comch_pci, doca_error_get_descr(result));
        return -1;
    }

    result = doca_pe_create(&g_comch_pe);
    if (result != DOCA_SUCCESS) return -1;

    /* Open the host PF/VF representor — required by DOCA Comch server to
     * identify which host-side PCIe function is allowed to connect.
     * See DOCA Comch docs §"Security Considerations": "Only clients on the
     * PF/VF/SF represented by the doca_dev_rep provided upon server creation
     * can connect to the server." */
    result = open_doca_device_rep_by_pci(g_comch_dev, g_cfg.rep_pci, &g_comch_rep);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Cannot open representor %s: %s",
                     g_cfg.rep_pci, doca_error_get_descr(result));
        return -1;
    }

    result = doca_comch_server_create(g_comch_dev, g_comch_rep, g_cfg.server_name,
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

    /* Configure send task callbacks (success + error) */
    result = doca_comch_server_task_send_set_conf(g_comch_server,
                                                   comch_send_complete_cb,
                                                   comch_send_error_cb,
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

    DOCA_LOG_INFO("Comch server started: name=%s dev=%s rep=%s",
                  g_cfg.server_name, g_cfg.comch_pci, g_cfg.rep_pci);
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
    if (g_comch_rep) {
        doca_dev_rep_close(g_comch_rep);
        g_comch_rep = NULL;
    }
    if (g_comch_dev) {
        doca_dev_close(g_comch_dev);
        g_comch_dev = NULL;
    }
}


/* ═══════════════════════════════════════════════════════════════════════
 *  DPDK EAL init callback + config finalization
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

/**
 * DPDK EAL init callback — registered via doca_argp_set_dpdk_program().
 * Called by doca_argp_start() after it separates DPDK flags from app flags.
 */
static doca_error_t
dpdk_init_cb(int argc, char **argv)
{
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        DOCA_LOG_ERR("EAL initialization failed");
        return DOCA_ERROR_DRIVER;
    }
    return DOCA_SUCCESS;
}

/**
 * Parse string config values → binary after doca_argp_start() completes.
 * MAC strings → 6-byte arrays, IP string → NBO uint32_t.
 * Also validates required fields as defence-in-depth (doca_argp_param_set_mandatory
 * already ensures they are provided, but an empty string could slip through).
 */
static int
finalize_config(dpu_agent_cfg_t *cfg)
{
    /* MAC strings → binary */
    if (cfg->upf_n3_mac_str[0] != '\0' &&
        parse_mac(cfg->upf_n3_mac_str, cfg->upf_n3_mac) < 0) {
        DOCA_LOG_ERR("Invalid upf-n3-mac: %s", cfg->upf_n3_mac_str);
        return -1;
    }
    if (cfg->gnb_mac_str[0] != '\0' &&
        parse_mac(cfg->gnb_mac_str, cfg->gnb_mac) < 0) {
        DOCA_LOG_ERR("Invalid gnb-mac: %s", cfg->gnb_mac_str);
        return -1;
    }
    if (cfg->upf_n6_mac_str[0] != '\0' &&
        parse_mac(cfg->upf_n6_mac_str, cfg->upf_n6_mac) < 0) {
        DOCA_LOG_ERR("Invalid upf-n6-mac: %s", cfg->upf_n6_mac_str);
        return -1;
    }
    if (cfg->dn_gw_mac_str[0] != '\0' &&
        parse_mac(cfg->dn_gw_mac_str, cfg->dn_gw_mac) < 0) {
        DOCA_LOG_ERR("Invalid dn-gw-mac: %s", cfg->dn_gw_mac_str);
        return -1;
    }

    /* IP string → NBO */
    if (cfg->upf_n3_ip_str[0] != '\0') {
        struct in_addr a;
        if (inet_pton(AF_INET, cfg->upf_n3_ip_str, &a) == 1) {
            cfg->upf_n3_ip = a.s_addr;
        } else {
            DOCA_LOG_ERR("Invalid upf-n3-ip: %s", cfg->upf_n3_ip_str);
            return -1;
        }
    }

    /* Validate required fields (defence-in-depth) */
    if (cfg->rep_pci[0] == '\0') {
        DOCA_LOG_ERR("rep-pci is required (--rep-pci or JSON doca_program_flags)");
        return -1;
    }
    if (cfg->upf_n3_ip == 0) {
        DOCA_LOG_ERR("upf-n3-ip is required (--upf-n3-ip or JSON doca_program_flags)");
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
    doca_error_t result;

    signal(SIGINT,  signal_handler);
    signal(SIGTERM, signal_handler);

    /* ── doca_argp: init → register → start ────────────────────────── */
    result = doca_argp_init(NULL, &g_cfg);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("doca_argp_init failed: %s", doca_error_get_descr(result));
        return EXIT_FAILURE;
    }

    doca_argp_set_dpdk_program(dpdk_init_cb);

    result = register_dpu_agent_params();
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to register argp params: %s",
                     doca_error_get_descr(result));
        doca_argp_destroy();
        return EXIT_FAILURE;
    }

    result = doca_argp_start(argc, argv);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("doca_argp_start failed: %s",
                     doca_error_get_descr(result));
        doca_argp_destroy();
        return EXIT_FAILURE;
    }

    /* Parse string config values → binary (MACs, IP) and validate */
    if (finalize_config(&g_cfg) < 0) {
        doca_argp_destroy();
        return EXIT_FAILURE;
    }

    /* ── Open DOCA devices for Flow ports ──────────────────────────── */
    doca_error_t dev_result;
    dev_result = open_doca_device_by_pci(g_cfg.n3_pci, &g_n3_dev);
    if (dev_result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Cannot open N3 device %s: %s",
                     g_cfg.n3_pci, doca_error_get_descr(dev_result));
        doca_argp_destroy();
        return EXIT_FAILURE;
    }
    dev_result = open_doca_device_by_pci(g_cfg.n6_pci, &g_n6_dev);
    if (dev_result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Cannot open N6 device %s: %s",
                     g_cfg.n6_pci, doca_error_get_descr(dev_result));
        doca_argp_destroy();
        return EXIT_FAILURE;
    }
    /* VF device: open by PCI if specified, else use N3 device */
    if (g_cfg.vf_pci[0] != '\0') {
        dev_result = open_doca_device_by_pci(g_cfg.vf_pci, &g_vf_dev);
        if (dev_result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Cannot open VF device %s: %s",
                         g_cfg.vf_pci, doca_error_get_descr(dev_result));
            doca_argp_destroy();
            return EXIT_FAILURE;
        }
    } else {
        g_vf_dev = g_n3_dev;  /* fallback: same device as N3 */
    }

    /* ── Comch server ──────────────────────────────────────────────── */
    if (comch_server_init() < 0) {
        DOCA_LOG_ERR("Failed to init Comch server");
        doca_argp_destroy();
        return EXIT_FAILURE;
    }

    /* ── DOCA Flow pipeline ────────────────────────────────────────── */
    dpu_port_cfg_t port_cfg = {};
    port_cfg.n3_port_id      = (uint16_t)g_cfg.n3_port_id;
    port_cfg.n6_port_id      = (uint16_t)g_cfg.n6_port_id;
    port_cfg.host_vf_port_id = (uint16_t)g_cfg.host_vf_port_id;
    port_cfg.n3_dev          = g_n3_dev;
    port_cfg.n6_dev          = g_n6_dev;
    port_cfg.host_vf_dev     = g_vf_dev;
    port_cfg.host_vf_rep     = NULL;  /* set by caller if probing representors */
    port_cfg.upf_n3_ip       = g_cfg.upf_n3_ip;
    memcpy(port_cfg.upf_n6_mac, g_cfg.upf_n6_mac, 6);
    memcpy(port_cfg.dn_gw_mac,  g_cfg.dn_gw_mac,  6);
    memcpy(port_cfg.upf_n3_mac, g_cfg.upf_n3_mac, 6);
    memcpy(port_cfg.gnb_mac,    g_cfg.gnb_mac,    6);

    result = dpu_pipeline_init(&g_pipeline, &port_cfg);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Pipeline init failed: %s", doca_error_get_descr(result));
        comch_server_destroy();
        doca_argp_destroy();
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

    /* Close port devices (VF may alias N3, only close if distinct) */
    if (g_vf_dev && g_vf_dev != g_n3_dev)
        doca_dev_close(g_vf_dev);
    if (g_n6_dev)
        doca_dev_close(g_n6_dev);
    if (g_n3_dev)
        doca_dev_close(g_n3_dev);

    rte_eal_cleanup();
    doca_argp_destroy();

    DOCA_LOG_INFO("DPU Agent exiting: recv=%lu inserted=%lu failed=%lu",
                  g_msgs_received, g_rules_inserted, g_rules_failed);
    return EXIT_SUCCESS;
}
