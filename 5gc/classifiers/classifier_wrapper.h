/*  classifier_wrapper.h  –  ONE header, nothing else required        */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>

#ifdef __cplusplus
extern "C" {
#endif


#define PDI_MAX_FLD  12        /* 0…11 dimensions in the Rule / Packet */

#define ANY32 0xFFFFFFFFu      /* wildcard sentinels */
#define ANY16 0xFFFFu
#define ANY8  0xFFu

struct UPDK_PDR; 

typedef struct UPDK_PDR UPDK_PDR;

extern cls_handle_t *g_classifier;

bool updk_pdr_to_cls_rule(const UPDK_PDR *in, pdr_t *out);

/* ========= PDI / PDR / Packet data-structures ==================== */
typedef enum {
    SRC_IF_ACCESS  = 0,
    SRC_IF_CORE    = 1,
    SRC_IF_SGI_LAN = 2,
    SRC_IF_CP_FUNC = 3,
    SRC_IF_LI_FUNC = 4
} source_interface_t;

typedef struct {
    /* --- mandatory key ------------------------------------------- */
    struct in_addr ue_ip;   uint8_t ue_pref;

    /* --- inner 5-tuple (+ extras) -------------------------------- */
    struct in_addr src_ip;  uint8_t src_pref;
    struct in_addr dst_ip;  uint8_t dst_pref;
    uint16_t       src_port;
    uint16_t       dst_port;
    uint8_t        proto;
    uint8_t        tos_tc;
    uint32_t       spi;
    uint32_t       flow_label;

    /* --- outer header keys --------------------------------------- */
    uint32_t           teid;
    source_interface_t source_if;
    uint32_t           ni_hash;
} pdi_t;

typedef struct {
    uint16_t  pdr_id;
    uint32_t  precedence;          
    pdi_t     pdi;
    uintptr_t descriptor;
} pdr_t;

typedef struct {
    uint32_t ue_ip;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
    uint8_t  tos_tc;
    uint32_t spi;
    uint32_t flow_label;
    uint32_t teid;
    uint32_t source_if;
    uint32_t ni_hash;
} ps_packet_t;


typedef enum {
    CLS_BACKEND_PS,    /* PartitionSort        */
    CLS_BACKEND_TSS,    /* Tuple Space Search   */
    CLS_BACKEND_PTSS
} cls_backend_t;

typedef struct cls_handle_t cls_handle_t;


cls_handle_t *cls_create (cls_backend_t which);
void          cls_destroy(cls_handle_t *);

uintptr_t cls_insert_rule(cls_handle_t *, const pdr_t *);
int       cls_delete_rule_by_descriptor(cls_handle_t *, uintptr_t);

int cls_classify_packet(
        cls_handle_t       *,
        const ps_packet_t  *,
        uint32_t           *precedence_out,
        uintptr_t          *descriptor_out);

void cls_print_all_rules(cls_handle_t *);   /* PS only – no-op for TSS */

#ifdef __cplusplus
}
#endif
