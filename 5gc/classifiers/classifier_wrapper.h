#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include "../../onvm/updk/updk/rule_pdr.h"

/*────────────────── Classifier back-end list & compile-time pick ──────────*/
typedef enum {
    CLS_BACKEND_PS,      /* PartitionSort        */
    CLS_BACKEND_TSS,     /* Tuple-Space-Search   */
    CLS_BACKEND_PTSS     /* Parallel-TSS variant */
} cls_backend_t;

/* Change here or pass  -DCLS_SELECTED_BACKEND=CLS_BACKEND_TSS  etc. */
#ifndef CLS_SELECTED_BACKEND
#define CLS_SELECTED_BACKEND CLS_BACKEND_PS
#endif

/*────────────────── Constants ─────────────────────────────────────────────*/
#define PDI_MAX_FLD 13
#define ANY32 0xFFFFFFFFu
#define ANY16 0xFFFFu
#define ANY8  0xFFu

/*────────────────── Core data types ──────────────────────────────────────*/
typedef enum {
    SRC_IF_ACCESS  = 0,
    SRC_IF_CORE    = 1,
    SRC_IF_SGI_LAN = 2,
    SRC_IF_CP_FUNC = 3,
    SRC_IF_LI_FUNC = 4,
    SRC_IF_COUNT   = 5
} source_interface_t;

/* PDI inside a PDR --------------------------------------------------------*/
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

/* Rule wrapper -----------------------------------------------------------*/
typedef struct {
    uint16_t  pdr_id;
    uint32_t  precedence;
    pdi_t     pdi;
    uintptr_t descriptor;       /* back-pointer to original UPDK_PDR */
} pdr_t;

/* Flat packet view -------------------------------------------------------*/
typedef struct {
    uint32_t ue_ip, src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint8_t  proto, tos_tc;
    uint32_t spi, flow_label;
    uint32_t teid, source_if, ni_hash;
    uint8_t  qfi;
} ps_packet_t;

/* Opaque classifier handle ----------------------------------------------*/
typedef struct cls_handle_t cls_handle_t;

/*────────────────── Public API ───────────────────────────────────────────*/
#ifdef __cplusplus
extern "C" {
#endif

cls_handle_t *cls_create(cls_backend_t which);
void          cls_destroy(cls_handle_t *);

uintptr_t cls_insert_rule(cls_handle_t *, const pdr_t *);
int       cls_delete_rule_by_descriptor(cls_handle_t *, uintptr_t);

int cls_classify_packet(
        cls_handle_t       *,
        const ps_packet_t  *,
        uint32_t           *precedence_out,
        uintptr_t          *descriptor_out);

void cls_print_all_rules(cls_handle_t *);

#ifdef __cplusplus
}
#endif

/*────────────────── Singleton accessor (header-only) ─────────────────────*/
static inline cls_handle_t *cls_global(void)
{
    static cls_handle_t *h = NULL;
    if (!h)
        h = cls_create(CLS_SELECTED_BACKEND);
    return h;
}
