#pragma once
#include <stdint.h>

// Named memzone holding the authoritative classifier pointer + version
#define MZ_UPF_CLS_CTRL "UPF_CLS_CTRL_SLOT"

typedef struct upf_cls_ctrl_s {
    void    *active;     /* current immutable PartitionSort snapshot  */
    uint32_t version;    /* increasing publish counter                */
} upf_cls_ctrl_t;

/* Process-local pointer to the shared control slot (set by UpfClsCtrlInit) */
extern upf_cls_ctrl_t *g_upf_cls_ctrl;

/* Map/create the control slot (called once per process after onvm_nflib_init) */
int UpfClsCtrlInit(void);
