
#pragma once
#include <cstdint>

struct MatchResult {
    int        priority;    // –1 ⇒ no match
    uintptr_t  descriptor;  //  0 ⇒ no match
    MatchResult(int p = -1, uintptr_t d = 0)
      : priority(p), descriptor(d) {}
};

// extern thread_local uintptr_t CURRENT_DESCRIPTOR;
