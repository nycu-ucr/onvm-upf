#include <new>
#include <cstddef>
#include <cstdint>
#include <rte_malloc.h>
#include <rte_memory.h>

static inline std::size_t round_up_align(std::size_t a) {
    // DPDK expects power-of-two, >= cacheline
    if (a < RTE_CACHE_LINE_SIZE) {
        a = RTE_CACHE_LINE_SIZE;
    }
    // round up to next power of two
    a--;
    a |= a >> 1;  a |= a >> 2;  a |= a >> 4;  a |= a >> 8;  a |= a >> 16;
#if SIZE_MAX > 0xFFFFFFFFu
    a |= a >> 32;
#endif
    a++;
    return a;
}

// --- base ---
void* operator new(std::size_t n) {
    if (void* p = rte_malloc("cls", n, RTE_CACHE_LINE_SIZE)) return p;
    throw std::bad_alloc();
}
void* operator new[](std::size_t n) {
    if (void* p = rte_malloc("cls", n, RTE_CACHE_LINE_SIZE)) return p;
    throw std::bad_alloc();
}
void  operator delete(void* p) noexcept       { if (p) rte_free(p); }
void  operator delete[](void* p) noexcept     { if (p) rte_free(p); }

// --- sized deletes (C++14/17) ---
void  operator delete(void* p, std::size_t) noexcept      { if (p) rte_free(p); }
void  operator delete[](void* p, std::size_t) noexcept    { if (p) rte_free(p); }

// --- aligned new/delete (C++17) ---
void* operator new(std::size_t n, std::align_val_t al) {
    std::size_t a = round_up_align(static_cast<std::size_t>(al));
    if (void* p = rte_malloc("cls", n, a)) return p;
    throw std::bad_alloc();
}
void* operator new[](std::size_t n, std::align_val_t al) {
    std::size_t a = round_up_align(static_cast<std::size_t>(al));
    if (void* p = rte_malloc("cls", n, a)) return p;
    throw std::bad_alloc();
}
void  operator delete(void* p, std::align_val_t) noexcept       { if (p) rte_free(p); }
void  operator delete[](void* p, std::align_val_t) noexcept     { if (p) rte_free(p); }
void  operator delete(void* p, std::size_t, std::align_val_t) noexcept   { if (p) rte_free(p); }
void  operator delete[](void* p, std::size_t, std::align_val_t) noexcept { if (p) rte_free(p); }
