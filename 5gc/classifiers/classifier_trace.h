// classifier_trace.h
#pragma once

#include <cstdio>
#include <cstdint>
#include <vector>
#include <array>
#include <string>
#include <cstring>
#include <unistd.h>

// ---------------------- configuration ----------------------
#ifndef CLASSIFIER_DEBUG_PATH
#define CLASSIFIER_DEBUG_PATH 1  // set to 0 to disable all TRACE output
#endif

#define TRACE(fmt, ...) \
    do { \
        fprintf(stderr, "[FORCE-TRACE] " fmt "\n", ##__VA_ARGS__); \
        fflush(stderr); \
        const char *s = "[FORCE-TRACE] flushed\n"; \
        write(2, s, strlen(s)); \
    } while (0)

// ---------------------- field definitions ----------------------
// Mirror your to_cpp_pkt ordering here.
enum FieldIndex : int {
    FIELD_UE_IP     = 0,
    FIELD_SRC_IP    = 1,
    FIELD_DST_IP    = 2,
    FIELD_SRC_PORT  = 3,
    FIELD_DST_PORT  = 4,
    FIELD_PROTO     = 5,
    FIELD_TOS_TC    = 6,
    FIELD_SPI       = 7,
    FIELD_FLOW_LABEL= 8,
    FIELD_TEID      = 9,
    FIELD_SOURCE_IF = 10,
    FIELD_NI_HASH   = 11,
    FIELD_QFI       = 12,
    FIELD_IS_UPLINK = 13,
    FIELD_MAX       = 14
};

inline const char* FieldName(int f) {
    switch (f) {
    case FIELD_UE_IP: return "UE_IP";
    case FIELD_SRC_IP: return "SRC_IP";
    case FIELD_DST_IP: return "DST_IP";
    case FIELD_SRC_PORT: return "SRC_PORT";
    case FIELD_DST_PORT: return "DST_PORT";
    case FIELD_PROTO: return "PROTO";
    case FIELD_TOS_TC: return "TOS_TC";
    case FIELD_SPI: return "SPI";
    case FIELD_FLOW_LABEL: return "FLOW_LABEL";
    case FIELD_TEID: return "TEID";
    case FIELD_SOURCE_IF: return "SOURCE_IF";
    case FIELD_NI_HASH: return "NI_HASH";
    case FIELD_QFI: return "QFI";
    case FIELD_IS_UPLINK: return "IS_UPLINK";
    default: return "UNKNOWN";
    }
}

// ---------------------- trace collector (expanded) ----------------------
struct TraceStep {
    int level;
    int field;
    uint32_t pkt_val;
    uint32_t low;
    uint32_t high;
    bool match;
    std::string decision; // e.g., "LEFT", "RIGHT", "MATCH", "WILDCARD"
};

class TraceCollector {
public:
    std::vector<TraceStep> steps;

    void add(int level, int field, uint32_t pkt_val, uint32_t low, uint32_t high, bool match, const char* decision) {
        TraceStep s;
        s.level = level;
        s.field = field;
        s.pkt_val = pkt_val;
        s.low = low;
        s.high = high;
        s.match = match;
        s.decision = decision;
        steps.push_back(std::move(s));
    }

    void dump() const {
        fprintf(stderr, "===== CLASSIFIER TRACE DUMP (%zu steps) =====\n", steps.size());
        for (const auto& s : steps) {
            fprintf(stderr,
                "Level %2d Field %-12s pkt=0x%x rule=[0x%x,0x%x] %s (%s)\n",
                s.level,
                FieldName(s.field),
                s.pkt_val,
                s.low,
                s.high,
                s.match ? "IN" : "OUT",
                s.decision.c_str());
        }
        fprintf(stderr, "=============================================\n");
    }

    void clear() {
        steps.clear();
    }
};

// ---------------------- simple comparator ----------------------
// Assumes rule_intervals[i] corresponds to fieldOrder[i], and each interval is [low, high]
template <typename PacketType>
bool SimpleCompareRuleWithPacket(const std::vector<int>& fieldOrder,
                                 const std::vector<std::array<uint32_t,2>>& rule_intervals,
                                 const PacketType& pkt) {
    bool all_match = true;
    for (size_t level = 0; level < fieldOrder.size(); ++level) {
        int field = fieldOrder[level];
        uint32_t pkt_val = pkt[field];
        uint32_t low = rule_intervals[level][0];
        uint32_t high = rule_intervals[level][1];

        bool in_interval = (pkt_val >= low && pkt_val <= high) || (pkt_val == 0xFFFFFFFF);
        fprintf(stderr,
                "[SIMPLE-DEBUG] Field %-12s packet=0x%x rule=[0x%x,0x%x] %s\n",
                FieldName(field),
                pkt_val,
                low,
                high,
                in_interval ? "OK" : "<-- MISMATCH");

        if (!in_interval) {
            all_match = false;
            break; // stop at first failure
        }
    }
    fprintf(stderr, "[SIMPLE-DEBUG] Overall match: %s\n", all_match ? "YES" : "NO");
    return all_match;
}

// Helper to dump a packet in field order
template <typename PacketType>
void PrettyPrintPacket(const std::vector<int>& fieldOrder, const PacketType& pkt) {
    fprintf(stderr, "----- Packet dump -----\n");
    for (int f : fieldOrder) {
        fprintf(stderr, "  %s = 0x%x\n", FieldName(f), pkt[f]);
    }
    fprintf(stderr, "-----------------------\n");
}

// Helper to dump rule intervals
inline void PrettyPrintRule(const std::vector<int>& fieldOrder,
                            const std::vector<std::array<uint32_t,2>>& rule_intervals) {
    fprintf(stderr, "----- Rule dump -----\n");
    for (size_t i = 0; i < fieldOrder.size(); ++i) {
        int f = fieldOrder[i];
        uint32_t low = rule_intervals[i][0];
        uint32_t high = rule_intervals[i][1];
        fprintf(stderr, "  %s in [0x%x,0x%x]\n", FieldName(f), low, high);
    }
    fprintf(stderr, "---------------------\n");
}
