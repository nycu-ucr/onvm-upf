#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include "../../onvm/updk/updk/rule_pdr.h"

#define CLS_BACKEND_ID_PS   0
#define CLS_BACKEND_ID_TSS  1
#define CLS_BACKEND_ID_PTSS 2

#ifndef CLS_SELECTED_BACKEND_ID
#define CLS_SELECTED_BACKEND_ID CLS_BACKEND_ID_PS
#endif


typedef enum {
    CLS_BACKEND_PS      = CLS_BACKEND_ID_PS,
    CLS_BACKEND_TSS     = CLS_BACKEND_ID_TSS,
    CLS_BACKEND_PTSS    = CLS_BACKEND_ID_PTSS
} cls_backend_t;

/* Max number of PDI dimensions we feed into engines */
#define PDI_MAX_FLD 14

/*────────────────── Core data types ─────────────────────────────────────*/
typedef enum {
    SRC_IF_ACCESS  = 0,
    SRC_IF_CORE    = 1,
    SRC_IF_SGI_LAN = 2,
    SRC_IF_CP_FUNC = 3,
    SRC_IF_LI_FUNC = 4,
    SRC_IF_COUNT   = 5
} source_interface_t;

/* Packet Detection Information (subset we index on) */
typedef struct {
    /* mandatory key */
    struct in_addr ue_ip;  uint8_t ue_pref;
    /* 5-tuple + extras */
    struct in_addr src_ip; uint8_t src_pref;
    struct in_addr dst_ip; uint8_t dst_pref;
    uint16_t src_port, dst_port;
    uint8_t  proto, tos_tc;
    uint32_t spi, flow_label;
    uint8_t  qfi;
    /* outer GTP-U */
    uint32_t           teid;
    source_interface_t source_if;
    uint32_t           ni_hash;
} pdi_t;

/* Rule wrapper (one per PDR filter) */
typedef struct {
    uint16_t  pdr_id;
    uint32_t  precedence;
    pdi_t     pdi;
    uintptr_t descriptor;
    bool      is_uplink;
} pdr_t;

/* Flat packet view for classification */
typedef struct {
    uint32_t ue_ip, src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint8_t  proto,  tos_tc;
    uint32_t spi,    flow_label;
    uint32_t teid,   source_if, ni_hash;
    uint8_t  qfi;
    uint8_t  is_uplink;
} ps_packet_t;

/* Opaque classifier handle (one per immutable snapshot) */
typedef struct cls_handle_t cls_handle_t;

/*────────────────── Public C API (handle-based) ─────────────────────────*/
#ifdef __cplusplus
extern "C" {
#endif

/* CP side (build-time, UPF-C only) */
cls_handle_t *cls_create(cls_backend_t which);
void          cls_destroy(cls_handle_t *);

/* Insert/delete rules while building a snapshot (UPF-C only) */
uintptr_t cls_insert_rule(cls_handle_t *h, const pdr_t *r);
int       cls_delete_rule_by_descriptor(cls_handle_t *h, uintptr_t d);

/* DP side (read-only classify on an immutable snapshot, UPF-U) */
int cls_classify_packet(
        cls_handle_t       *h,            /* snapshot handle (immutable) */
        const ps_packet_t  *pkt,
        uint32_t           *precedence_out,
        uintptr_t          *descriptor_out);

/* Optional debug (CP only) */
void cls_print_all_rules(cls_handle_t *h);

#ifdef __cplusplus
}
#endif