#pragma once
#include "classifier_wrapper.h"          /* cls_create(), insert/delete …   */

// compile-time back-end selection
#if   defined(CLS_BACKEND_TSS)
constexpr cls_backend_t kBackend = CLS_BACKEND_TSS;
#elif defined(CLS_BACKEND_PTSS)
constexpr cls_backend_t kBackend = CLS_BACKEND_PTSS;
#else
constexpr cls_backend_t kBackend = CLS_BACKEND_PS;
#endif

// singleton handle ==== thread-safe
inline cls_handle_t *cls_global()
{
    static cls_handle_t *handle = cls_create(kBackend);   /* thread-safe C++11  */
    return handle;
}
