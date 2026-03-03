/*
 * host_agent.c — Host Offload Agent (ONVM secondary NF)
 *
 * Bridges hw_offload_msg structs from UPF-C to the DPU Agent via
 * DOCA Comch (Comm Channel).  Runs as DPDK secondary so it inherits
 * hugepage visibility for rte_malloc'd payloads.
 *
 * Lifecycle:
 *   1. Initialises as ONVM NF with SERVICE_ID = HOST_AGENT_SERVICE_ID (3)
 *   2. Opens DOCA Comch client connection to the DPU Agent
 *   3. Registers msg_handler callback for ONVM inter-NF messages
 *   4. On each message: validate, serialise, transmit via Comch, rte_free
 *   5. Idle callback keeps Comch event loop alive
 *
 * Build: linked as a standard ONVM NF (DPDK secondary, no DOCA Flow
 *        headers needed — only DOCA Comch client).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"

#include "upf_events.h"
#include "hw_offload_msg.h"

/* ── DOCA Comch client (control-path only) ──────────────────────────── */
#include <doca_comch.h>
#include <doca_dev.h>
#include <doca_error.h>
#include <doca_log.h>
#include <doca_pe.h>

DOCA_LOG_REGISTER(HOST_AGENT);

#define NF_TAG "host_agent"

/* ── Comch state ────────────────────────────────────────────────────── */
static struct doca_dev         *comch_dev;
static struct doca_comch_client *comch_client;
static struct doca_pe          *comch_pe;

/* Counters */
static uint64_t g_msgs_received;
static uint64_t g_msgs_sent;
static uint64_t g_msgs_failed;

/* ── CLI options ────────────────────────────────────────────────────── */
static char g_pci_addr[32] = "03:00.0";   /* BF3 PF on host (default)  */
static char g_server_name[64] = "dpu_agent"; /* Comch server name       */

/* ═══════════════════════════════════════════════════════════════════════
 *  DOCA Comch helpers
 * ═══════════════════════════════════════════════════════════════════════ */

/* Callback invoked when the Comch connection is established */
static void
comch_connection_cb(struct doca_comch_event_connection_status_changed *event,
                    struct doca_comch_connection *conn,
                    uint8_t change_successful)
{
    if (change_successful)
        DOCA_LOG_INFO("Comch connection established to DPU Agent");
    else
        DOCA_LOG_ERR("Comch connection failed");
    (void)event;
    (void)conn;
}

/* Callback invoked when a message is received from DPU (ACKs, etc.) */
static void
comch_recv_cb(struct doca_comch_event_msg_recv *event,
              uint8_t *recv_buffer,
              uint32_t msg_len,
              struct doca_comch_connection *conn)
{
    DOCA_LOG_DBG("Comch recv: %u bytes from DPU Agent", msg_len);
    (void)event;
    (void)recv_buffer;
    (void)conn;
}

/* Callback for Comch send completion */
static void
comch_send_complete_cb(struct doca_comch_event_msg_send *event,
                       struct doca_comch_connection *conn,
                       doca_error_t status)
{
    if (status != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Comch send failed: %s", doca_error_get_descr(status));
        __atomic_fetch_add(&g_msgs_failed, 1, __ATOMIC_RELAXED);
    }
    (void)event;
    (void)conn;
}

/* Open device by PCI address */
static doca_error_t
open_doca_device_by_pci(const char *pci_addr, struct doca_dev **dev)
{
    struct doca_devinfo **dev_list;
    uint32_t nb_devs;
    doca_error_t result;

    result = doca_devinfo_create_list(&dev_list, &nb_devs);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create devinfo list: %s",
                     doca_error_get_descr(result));
        return result;
    }

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
    DOCA_LOG_ERR("Device %s not found", pci_addr);
    return DOCA_ERROR_NOT_FOUND;
}

/* Initialise the DOCA Comch client connection to the DPU Agent */
static int
comch_init(void)
{
    doca_error_t result;

    /* Open the BF3 PF device */
    result = open_doca_device_by_pci(g_pci_addr, &comch_dev);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Cannot open device %s: %s",
                     g_pci_addr, doca_error_get_descr(result));
        return -1;
    }

    /* Create progress engine */
    result = doca_pe_create(&comch_pe);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create PE: %s", doca_error_get_descr(result));
        return -1;
    }

    /* Create Comch client */
    result = doca_comch_client_create(comch_dev, g_server_name,
                                      comch_pe, &comch_client);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create Comch client: %s",
                     doca_error_get_descr(result));
        return -1;
    }

    /* Set max message size to accommodate hw_offload_msg_t */
    result = doca_comch_client_set_max_msg_size(comch_client,
                                                 sizeof(hw_offload_msg_t) + 64);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set max msg size: %s",
                     doca_error_get_descr(result));
        return -1;
    }

    /* Register event callbacks */
    result = doca_comch_client_event_msg_recv_register(comch_client,
                                                        comch_recv_cb);
    if (result != DOCA_SUCCESS)
        return -1;

    result = doca_comch_client_event_send_completion_register(comch_client,
                                                               comch_send_complete_cb);
    if (result != DOCA_SUCCESS)
        return -1;

    result = doca_comch_client_event_connection_status_changed_register(
                comch_client, comch_connection_cb);
    if (result != DOCA_SUCCESS)
        return -1;

    /* Start the client context (initiates connection handshake) */
    result = doca_ctx_start(doca_comch_client_as_ctx(comch_client));
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to start Comch client: %s",
                     doca_error_get_descr(result));
        return -1;
    }

    /* Drive progress engine until connection is established */
    for (int i = 0; i < 100; i++) {
        doca_pe_progress(comch_pe);
        usleep(10000);   /* 10 ms */
    }

    DOCA_LOG_INFO("Comch client initialised — server=%s dev=%s",
                  g_server_name, g_pci_addr);
    return 0;
}

static void
comch_destroy(void)
{
    if (comch_client) {
        doca_ctx_stop(doca_comch_client_as_ctx(comch_client));
        doca_comch_client_destroy(comch_client);
        comch_client = NULL;
    }
    if (comch_pe) {
        doca_pe_destroy(comch_pe);
        comch_pe = NULL;
    }
    if (comch_dev) {
        doca_dev_close(comch_dev);
        comch_dev = NULL;
    }
}

/* ═══════════════════════════════════════════════════════════════════════
 *  ONVM message handler — receives hw_offload_msg from UPF-C
 * ═══════════════════════════════════════════════════════════════════════ */
static void
msg_handler(void *msg_data,
            __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx)
{
    if (!msg_data) return;

    hw_offload_msg_t *msg = (hw_offload_msg_t *)msg_data;

    /* Validate magic */
    if (msg->magic != HW_OFFLOAD_MAGIC) {
        DOCA_LOG_WARN("msg_handler: bad magic 0x%08x — ignoring", msg->magic);
        rte_free(msg);
        return;
    }

    __atomic_fetch_add(&g_msgs_received, 1, __ATOMIC_RELAXED);

    DOCA_LOG_INFO("msg_handler: op=%u dir=%s pdr=%u hw_rule=%u teid=0x%x",
                  msg->op,
                  msg->direction == HW_DIR_UPLINK ? "UL" : "DL",
                  msg->pdr_id, msg->hw_rule_id, msg->teid);

    /* Transmit over DOCA Comch to the DPU Agent */
    if (comch_client) {
        struct doca_comch_connection *conn = NULL;
        doca_error_t result;

        /* Get the first (only) connection */
        result = doca_comch_client_get_connection(comch_client, &conn);
        if (result != DOCA_SUCCESS || !conn) {
            DOCA_LOG_ERR("No active Comch connection — dropping msg "
                         "hw_rule_id=%u", msg->hw_rule_id);
            __atomic_fetch_add(&g_msgs_failed, 1, __ATOMIC_RELAXED);
            rte_free(msg);
            return;
        }

        /* Send the flat struct as-is — DPU Agent has the same header */
        result = doca_comch_connection_send_msg(conn,
                                                 (const uint8_t *)msg,
                                                 sizeof(hw_offload_msg_t));
        if (result == DOCA_SUCCESS) {
            __atomic_fetch_add(&g_msgs_sent, 1, __ATOMIC_RELAXED);
        } else {
            DOCA_LOG_ERR("Comch send failed for hw_rule_id=%u: %s",
                         msg->hw_rule_id, doca_error_get_descr(result));
            __atomic_fetch_add(&g_msgs_failed, 1, __ATOMIC_RELAXED);
        }
    } else {
        DOCA_LOG_WARN("Comch not connected — dropping hw_rule_id=%u",
                      msg->hw_rule_id);
        __atomic_fetch_add(&g_msgs_failed, 1, __ATOMIC_RELAXED);
    }

    /* Sender (UPF-C) allocated, receiver (us) frees — ONVM convention */
    rte_free(msg);
}

/* ── Packet handler: Host Agent does not process packets ───────────── */
static int
packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
               __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx)
{
    /* We shouldn't receive data-plane packets, but if we do, drop them */
    meta->action = ONVM_NF_ACTION_DROP;
    (void)pkt;
    return 0;
}

/* ── Idle callback: drives Comch progress engine ───────────────────── */
static int
callback_handler(__attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx)
{
    /* Drive DOCA Comch event loop (send completions, recv callbacks) */
    if (comch_pe)
        doca_pe_progress(comch_pe);

    return 0;
}

/* ── CLI parsing ───────────────────────────────────────────────────── */
static void
usage(const char *progname) {
    printf("Usage:\n");
    printf("  %s [EAL args] -- [NF_LIB args] -- [HOST_AGENT args]\n", progname);
    printf("\nHost Agent args:\n");
    printf("  -d <PCI_ADDR>   BF3 PF PCI address (default: %s)\n", g_pci_addr);
    printf("  -s <NAME>       Comch server name   (default: %s)\n", g_server_name);
}

static int
parse_app_args(int argc, char *argv[], const char *progname) {
    int c;
    while ((c = getopt(argc, argv, "d:s:h")) != -1) {
        switch (c) {
            case 'd':
                snprintf(g_pci_addr, sizeof(g_pci_addr), "%s", optarg);
                break;
            case 's':
                snprintf(g_server_name, sizeof(g_server_name), "%s", optarg);
                break;
            case 'h':
                usage(progname);
                return -1;
            default:
                usage(progname);
                return -1;
        }
    }
    return optind;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  main
 * ═══════════════════════════════════════════════════════════════════════ */
int
main(int argc, char *argv[]) {
    struct onvm_nf_local_ctx *nf_local_ctx;
    struct onvm_nf_function_table *nf_function_table;
    int arg_offset;
    const char *progname = argv[0];

    nf_local_ctx = onvm_nflib_init_nf_local_ctx();
    onvm_nflib_start_signal_handler(nf_local_ctx, NULL);

    nf_function_table = onvm_nflib_init_nf_function_table();
    nf_function_table->pkt_handler  = &packet_handler;
    nf_function_table->msg_handler  = &msg_handler;
    nf_function_table->user_actions = &callback_handler;

    if ((arg_offset = onvm_nflib_init(argc, argv, NF_TAG,
                                       nf_local_ctx,
                                       nf_function_table)) < 0) {
        onvm_nflib_stop(nf_local_ctx);
        if (arg_offset == ONVM_SIGNAL_TERMINATION) {
            printf("Host Agent: exiting due to signal\n");
            return 0;
        } else {
            rte_exit(EXIT_FAILURE, "Failed ONVM init\n");
        }
    }

    argc -= arg_offset;
    argv += arg_offset;

    if (parse_app_args(argc, argv, progname) < 0) {
        onvm_nflib_stop(nf_local_ctx);
        rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");
    }

    /* Initialise DOCA Comch client to DPU */
    if (comch_init() < 0) {
        DOCA_LOG_ERR("Comch init failed — running without DPU offload");
        /* Non-fatal: packets will fall through to SW path */
    }

    printf("Host Agent running — PCI=%s server=%s\n", g_pci_addr, g_server_name);

    /* Enter ONVM run loop — calls msg_handler + callback_handler */
    onvm_nflib_run(nf_local_ctx);

    /* Cleanup */
    comch_destroy();
    onvm_nflib_stop(nf_local_ctx);

    printf("Host Agent: recv=%lu sent=%lu failed=%lu\n",
           g_msgs_received, g_msgs_sent, g_msgs_failed);
    return 0;
}
