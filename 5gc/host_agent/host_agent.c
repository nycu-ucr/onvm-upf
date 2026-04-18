/*
 * host_agent.c — Host Offload Agent (ONVM secondary NF)
 *
 * Bridges hw_offload_msg structs from UPF-C to the DPU Agent via
 * DOCA Comch (Comm Channel).  Runs as DPDK secondary so it inherits
 * hugepage visibility for rte_malloc'd payloads.
 *
 * Lifecycle:
 *   1. Initialises as ONVM NF with SERVICE_ID = HOST_AGENT_SERVICE_ID (14)
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

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
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
#include "host_agent_config.h"

/* ── DOCA Comch client (control-path only) ──────────────────────────── */
#include <doca_comch.h>
#include <doca_compat.h>  /* Must precede doca_ctx.h on some DOCA releases */
#include <doca_ctx.h>
#include <doca_dev.h>
#include <doca_error.h>
#include <doca_log.h>
#include <doca_pe.h>

DOCA_LOG_REGISTER(HOST_AGENT);

#define NF_TAG "host_agent"
#define DEFAULT_PCI_ADDR "03:00.0"
#define DEFAULT_SERVER_NAME "dpu_agent"
#define DEFAULT_HOST_AGENT_CONFIG_PATH "config/host_agent.yaml"
#define COMCH_CONNECT_RETRIES 100
#define COMCH_CONNECT_POLL_US 10000
#define COMCH_SHUTDOWN_RETRIES 1000

/* ── Comch state ────────────────────────────────────────────────────── */
static struct doca_dev          *comch_dev;
static struct doca_comch_client *comch_client;
static struct doca_pe           *comch_pe;
static struct doca_comch_connection *comch_conn;  /* cached connection */
static volatile bool             comch_connected;

/* Counters */
static uint64_t g_msgs_received;
static uint64_t g_msgs_sent;
static uint64_t g_msgs_failed;

/* ── CLI options ────────────────────────────────────────────────────── */
static char g_pci_addr[32] = DEFAULT_PCI_ADDR;
static char g_server_name[64] = DEFAULT_SERVER_NAME;

struct host_agent_app_args {
    const char *config_path;
    const char *pci_addr_override;
    const char *server_name_override;
    bool config_path_explicit;
};

static void comch_destroy(void);

static void
progress_engine_once(void)
{
    if (comch_pe != NULL)
        doca_pe_progress(comch_pe);
}

static const char *
format_ipv4_nbo(struct in_addr addr, char *buf, size_t buf_len)
{
    if (inet_ntop(AF_INET, &addr, buf, buf_len) == NULL) {
        snprintf(buf, buf_len, "invalid");
    }

    return buf;
}

static const char *
format_ipv4_host_order(uint32_t addr_host_order, char *buf, size_t buf_len)
{
    struct in_addr addr = {
        .s_addr = htonl(addr_host_order),
    };

    return format_ipv4_nbo(addr, buf, buf_len);
}

static void
print_msg_summary(const hw_offload_msg_t *msg)
{
    char ue_ipv4_buf[INET_ADDRSTRLEN];
    char src_ip_buf[INET_ADDRSTRLEN];
    char dst_ip_buf[INET_ADDRSTRLEN];
    const char *src_ip = "-";
    const char *dst_ip = "-";

    if (msg->has_sdf) {
        src_ip = format_ipv4_host_order(msg->sdf_src_ip, src_ip_buf, sizeof(src_ip_buf));
        dst_ip = format_ipv4_host_order(msg->sdf_dst_ip, dst_ip_buf, sizeof(dst_ip_buf));
    }

    fprintf(stderr,
            "host_agent: pdr_id=%u teid=0x%x ue_ipv4=%s src_ip=%s dst_ip=%s\n",
            msg->pdr_id,
            msg->teid,
            format_ipv4_nbo(msg->ue_ipv4, ue_ipv4_buf, sizeof(ue_ipv4_buf)),
            src_ip,
            dst_ip);
}

static bool
pci_addr_match(const char *a, const char *b)
{
    size_t len_a, len_b;

    if (strcmp(a, b) == 0)
        return true;

    len_a = strlen(a);
    len_b = strlen(b);
    if (len_a > len_b)
        return strcmp(a + (len_a - len_b), b) == 0;
    if (len_b > len_a)
        return strcmp(b + (len_b - len_a), a) == 0;

    return false;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  DOCA Comch helpers
 * ═══════════════════════════════════════════════════════════════════════ */

/* Callback invoked when the Comch client context state changes.
 * Client uses doca_ctx_set_state_changed_cb, not a Comch-specific event. */
static void
comch_ctx_state_changed_cb(const union doca_data user_data,
                           struct doca_ctx *ctx,
                           enum doca_ctx_states prev_state,
                           enum doca_ctx_states next_state)
{
    (void)user_data;
    (void)ctx;
    (void)prev_state;

    if (next_state == DOCA_CTX_STATE_RUNNING) {
        DOCA_LOG_INFO("Comch client connected to DPU Agent");
        /* Cache the connection handle */
        doca_error_t result = doca_comch_client_get_connection(comch_client, &comch_conn);
        if (result == DOCA_SUCCESS) {
            comch_connected = true;
        } else {
            DOCA_LOG_WARN("Comch RUNNING but connection handle fetch failed: %s",
                          doca_error_get_descr(result));
        }
    } else if (next_state == DOCA_CTX_STATE_IDLE) {
        DOCA_LOG_WARN("Comch client disconnected or idle");
        comch_connected = false;
        comch_conn = NULL;
    }
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

/* Callback for Comch send task completion (task-based model) */
static void
comch_send_task_comp_cb(struct doca_comch_task_send *task,
                        union doca_data task_user_data,
                        union doca_data ctx_user_data)
{
    (void)task_user_data;
    (void)ctx_user_data;
    __atomic_fetch_add(&g_msgs_sent, 1, __ATOMIC_RELAXED);
    doca_task_free(doca_comch_task_send_as_task(task));
}

/* Callback for Comch send task error */
static void
comch_send_task_err_cb(struct doca_comch_task_send *task,
                       union doca_data task_user_data,
                       union doca_data ctx_user_data)
{
    (void)task_user_data;
    (void)ctx_user_data;
    DOCA_LOG_ERR("Comch send task failed");
    __atomic_fetch_add(&g_msgs_failed, 1, __ATOMIC_RELAXED);
    doca_task_free(doca_comch_task_send_as_task(task));
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
        if (pci_addr_match(addr_buf, pci_addr)) {
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
    struct doca_ctx *ctx;

    /* Open the BF3 PF device */
    result = open_doca_device_by_pci(g_pci_addr, &comch_dev);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Cannot open device %s: %s",
                     g_pci_addr, doca_error_get_descr(result));
        goto error;
    }

    /* Create progress engine */
    result = doca_pe_create(&comch_pe);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create PE: %s", doca_error_get_descr(result));
        goto error;
    }

    /* Create Comch client: (dev, server_name, &client) — no PE arg */
    result = doca_comch_client_create(comch_dev, g_server_name, &comch_client);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create Comch client: %s",
                     doca_error_get_descr(result));
        goto error;
    }

    ctx = doca_comch_client_as_ctx(comch_client);

    /* Connect PE to client context */
    result = doca_pe_connect_ctx(comch_pe, ctx);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to connect PE to client ctx: %s",
                     doca_error_get_descr(result));
        goto error;
    }

    /* Track connection state via generic ctx state change callback */
    result = doca_ctx_set_state_changed_cb(ctx, comch_ctx_state_changed_cb);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set state changed cb: %s",
                     doca_error_get_descr(result));
        goto error;
    }

    /* Configure task-based send (required before ctx start) */
    result = doca_comch_client_task_send_set_conf(comch_client,
                                                   comch_send_task_comp_cb,
                                                   comch_send_task_err_cb,
                                                   16);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set send task conf: %s",
                     doca_error_get_descr(result));
        goto error;
    }

    /* Register recv event callback */
    result = doca_comch_client_event_msg_recv_register(comch_client,
                                                        comch_recv_cb);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to register recv event callback: %s",
                     doca_error_get_descr(result));
        goto error;
    }

    /* Set max message size to accommodate hw_offload_msg_t */
    result = doca_comch_client_set_max_msg_size(comch_client,
                                                 sizeof(hw_offload_msg_t) + 64);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set max msg size: %s",
                     doca_error_get_descr(result));
        goto error;
    }

    /* Start the client context (initiates connection handshake) */
    result = doca_ctx_start(ctx);
    if (result != DOCA_SUCCESS && result != DOCA_ERROR_IN_PROGRESS) {
        DOCA_LOG_ERR("Failed to start Comch client: %s",
                     doca_error_get_descr(result));
        goto error;
    }

    /* Drive progress engine until connection is established */
    for (int i = 0; i < COMCH_CONNECT_RETRIES && !comch_connected; i++) {
        progress_engine_once();
        usleep(COMCH_CONNECT_POLL_US);
    }

    if (comch_connected)
        DOCA_LOG_INFO("Comch client connected — server=%s dev=%s",
                      g_server_name, g_pci_addr);
    else
        DOCA_LOG_WARN("Comch client not yet connected (will retry in background)");

    if (comch_connected) {
        fprintf(stderr,
                "host_agent: Comch connected (server=%s, pci=%s)\n",
                g_server_name, g_pci_addr);
    } else {
        fprintf(stderr,
                "host_agent: Comch not connected yet; continuing without offload connection\n");
    }

    return 0;

error:
    comch_destroy();
    return -1;
}

static void
comch_destroy(void)
{
    comch_connected = false;
    comch_conn = NULL;

    if (comch_client) {
        struct doca_ctx *ctx = doca_comch_client_as_ctx(comch_client);
        doca_error_t result = doca_ctx_stop(ctx);

        if (result == DOCA_ERROR_IN_PROGRESS) {
            enum doca_ctx_states state;

            for (int i = 0; i < COMCH_SHUTDOWN_RETRIES; i++) {
                result = doca_ctx_get_state(ctx, &state);
                if (result != DOCA_SUCCESS || state == DOCA_CTX_STATE_IDLE)
                    break;
                progress_engine_once();
                usleep(1000);
            }
        } else if (result != DOCA_SUCCESS && result != DOCA_ERROR_BAD_STATE) {
            DOCA_LOG_WARN("Failed to stop Comch client ctx cleanly: %s",
                          doca_error_get_descr(result));
        }

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
    print_msg_summary(msg);

    DOCA_LOG_INFO("msg_handler: op=%u dir=%s pdr=%u hw_rule=%u teid=0x%x",
                  msg->op,
                  msg->direction == HW_DIR_UPLINK ? "UL" : "DL",
                  msg->pdr_id, msg->hw_rule_id, msg->teid);

    /* Transmit over DOCA Comch to the DPU Agent via task-based send */
    if (comch_client && comch_connected && comch_conn) {
        doca_error_t result;
        struct doca_comch_task_send *task;

        /* Allocate and init a send task */
        result = doca_comch_client_task_send_alloc_init(comch_client,
                                                         comch_conn,
                                                         (const uint8_t *)msg,
                                                         sizeof(hw_offload_msg_t),
                                                         &task);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Send task alloc failed for hw_rule_id=%u: %s",
                         msg->hw_rule_id, doca_error_get_descr(result));
            __atomic_fetch_add(&g_msgs_failed, 1, __ATOMIC_RELAXED);
            rte_free(msg);
            return;
        }

        /* Submit the task — completion handled by comch_send_task_comp_cb */
        result = doca_task_submit(doca_comch_task_send_as_task(task));
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Send task submit failed for hw_rule_id=%u: %s",
                         msg->hw_rule_id, doca_error_get_descr(result));
            __atomic_fetch_add(&g_msgs_failed, 1, __ATOMIC_RELAXED);
            doca_task_free(doca_comch_task_send_as_task(task));
        }
    } else {
        fprintf(stderr,
                "host_agent: no Comch connection; rule hw_rule_id=%u stays local-only\n",
                msg->hw_rule_id);
        DOCA_LOG_WARN("Comch not connected — dropping hw_rule_id=%u",
                      msg->hw_rule_id);
        __atomic_fetch_add(&g_msgs_failed, 1, __ATOMIC_RELAXED);
    }

    /* Sender (UPF-C) allocated, receiver (us) frees — ONVM convention.
     * doca_comch_client_task_send_alloc_init() copies the payload into
     * an internal Comch buffer (verified for DOCA SDK v3.2.0), so it is
     * safe to free msg immediately.  If a future SDK version introduces
     * zero-copy sends, this free must be deferred to the send completion
     * callback (comch_send_task_comp_cb). */
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
    progress_engine_once();

    return 0;
}

/* ── CLI parsing ───────────────────────────────────────────────────── */
static void
usage(const char *progname) {
    printf("Usage:\n");
    printf("  %s [EAL args] -- [NF_LIB args] -- [HOST_AGENT args]\n", progname);
    printf("\nHost Agent args:\n");
    printf("  -f <PATH>       YAML config path    (default: %s)\n",
           DEFAULT_HOST_AGENT_CONFIG_PATH);
    printf("  -d <PCI_ADDR>   BF3 PF PCI address override (default: %s)\n",
           DEFAULT_PCI_ADDR);
    printf("  -s <NAME>       Comch server name override   (default: %s)\n",
           DEFAULT_SERVER_NAME);
}

static int
parse_app_args(int argc, char *argv[], struct host_agent_app_args *app_args,
               const char *progname) {
    int c;

    app_args->config_path = DEFAULT_HOST_AGENT_CONFIG_PATH;
    app_args->pci_addr_override = NULL;
    app_args->server_name_override = NULL;
    app_args->config_path_explicit = false;

    optind = 1;
    opterr = 0;

    while ((c = getopt(argc, argv, "f:d:s:h")) != -1) {
        switch (c) {
            case 'f':
                app_args->config_path = optarg;
                app_args->config_path_explicit = true;
                break;
            case 'd':
                app_args->pci_addr_override = optarg;
                break;
            case 's':
                app_args->server_name_override = optarg;
                break;
            case 'h':
                usage(progname);
                return 1;
            default:
                usage(progname);
                return -1;
        }
    }

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  main
 * ═══════════════════════════════════════════════════════════════════════ */
int
main(int argc, char *argv[]) {
    struct onvm_nf_local_ctx *nf_local_ctx;
    struct onvm_nf_function_table *nf_function_table;
    struct host_agent_app_args app_args;
    int arg_offset;
    int parse_rc;
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

    parse_rc = parse_app_args(argc, argv, &app_args, progname);
    if (parse_rc > 0) {
        onvm_nflib_stop(nf_local_ctx);
        return 0;
    }
    if (parse_rc < 0) {
        onvm_nflib_stop(nf_local_ctx);
        rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");
    }

    if (HostAgent_LoadAndParseConfig(app_args.config_path,
                                     g_pci_addr, sizeof(g_pci_addr),
                                     g_server_name, sizeof(g_server_name)) != 0) {
        if (app_args.config_path_explicit) {
            onvm_nflib_stop(nf_local_ctx);
            rte_exit(EXIT_FAILURE,
                     "Failed to load/parse Host Agent YAML config.\n");
        }
        fprintf(stderr,
                "[HOST_AGENT][CONFIG] using built-in defaults because the default config could not be loaded\n");
    } else {
        printf("Host Agent config loaded from %s\n", app_args.config_path);
    }

    if (app_args.pci_addr_override) {
        snprintf(g_pci_addr, sizeof(g_pci_addr), "%s",
                 app_args.pci_addr_override);
    }
    if (app_args.server_name_override) {
        snprintf(g_server_name, sizeof(g_server_name), "%s",
                 app_args.server_name_override);
    }

    /* Initialise DOCA Comch client to DPU */
    if (comch_init() < 0) {
        fprintf(stderr,
                "host_agent: Comch init failed; continuing without DPU offload\n");
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
