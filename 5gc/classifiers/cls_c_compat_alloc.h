#pragma once
#include <rte_malloc.h>
#ifndef CLS_ALIGN
#define CLS_ALIGN RTE_CACHE_LINE_SIZE
#endif

#define malloc(sz)        rte_malloc("cls", (sz), CLS_ALIGN)
#define calloc(n,sz)      rte_zmalloc("cls", ((size_t)(n))*(size_t)(sz), CLS_ALIGN)
#define realloc(p,sz)     rte_realloc((p), (sz), CLS_ALIGN)
#define free(p)           rte_free((p))
