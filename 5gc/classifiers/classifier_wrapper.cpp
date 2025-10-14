#include <climits>
#include <cinttypes>
#include <cstdio>
#include <arpa/inet.h>

#include "classifier_wrapper.h"
#include "ElementaryClasses.h"

#include "PartitionSort/PartitionSort.h"
#include "TupleSpaceSearch/TupleSpaceSearch.h"


#if CLS_SELECTED_BACKEND_ID == CLS_BACKEND_ID_PS
struct cls_handle_t { PartitionSort *ps; };
#elif CLS_SELECTED_BACKEND_ID == CLS_BACKEND_ID_TSS
struct cls_handle_t { TupleSpaceSearch *tss; };
#else /* CLS_BACKEND_ID_TSS */
struct cls_handle_t { PriorityTupleSpaceSearch *ptss; };
#endif

/*────────────────── helpers ─────────────────────────────────────────────*/

static inline std::pair<uint32_t,uint32_t> ip_range(uint32_t ip, uint8_t len) {
    if (len == 0) return {0u, 0xFFFFFFFFu};
    uint32_t mask = (len == 32) ? 0xFFFFFFFFu : (0xFFFFFFFFu << (32 - len));
    uint32_t lo = ip & mask;
    return {lo, lo | ~mask};
}

static Rule to_cpp_rule(const pdr_t *in) {
    Rule R(PDI_MAX_FLD);

    // default: match-any on every dimension
    for (int d = 0; d < PDI_MAX_FLD; ++d) {
        R.range[d]         = {{ 0u, 0xFFFFFFFFu }};
        R.prefix_length[d] = 0; // /0 → wildcard
    }

    // UE IP
    if (in->pdi.ue_pref) {
        auto box = ip_range(in->pdi.ue_ip.s_addr, in->pdi.ue_pref);
        R.range[0]         = {{ box.first, box.second }};
        R.prefix_length[0] = in->pdi.ue_pref;
    }
    // SRC IP
    if (in->pdi.src_pref) {
        auto box = ip_range(in->pdi.src_ip.s_addr, in->pdi.src_pref);
        R.range[1]         = {{ box.first, box.second }};
        R.prefix_length[1] = in->pdi.src_pref;
    }
    // DST IP
    if (in->pdi.dst_pref) {
        auto box = ip_range(in->pdi.dst_ip.s_addr, in->pdi.dst_pref);
        R.range[2]         = {{ box.first, box.second }};
        R.prefix_length[2] = in->pdi.dst_pref;
    }
    // Ports / L4 / ToS / SPI
    if (in->pdi.src_port) { R.range[3] = {{ in->pdi.src_port, in->pdi.src_port }}; R.prefix_length[3] = 32; }
    if (in->pdi.dst_port) { R.range[4] = {{ in->pdi.dst_port, in->pdi.dst_port }}; R.prefix_length[4] = 32; }
    if (in->pdi.proto)    { R.range[5] = {{ in->pdi.proto,    in->pdi.proto    }}; R.prefix_length[5] = 32; }
    if (in->pdi.tos_tc)   { R.range[6] = {{ in->pdi.tos_tc,   in->pdi.tos_tc   }}; R.prefix_length[6] = 32; }
    if (in->pdi.spi)      { R.range[7] = {{ in->pdi.spi,      in->pdi.spi      }}; R.prefix_length[7] = 32; }

    // flow_label ignored for now (dimension 8)

    // TEID (required)
    R.range[9]          = {{ in->pdi.teid, in->pdi.teid }};
    R.prefix_length[9]  = 32;

    // source interface (access/core)
    R.range[10]         = {{ (uint32_t)in->pdi.source_if, (uint32_t)in->pdi.source_if }};
    R.prefix_length[10] = 32;

    // NI hash
    if (in->pdi.ni_hash) { R.range[11] = {{ in->pdi.ni_hash, in->pdi.ni_hash }}; R.prefix_length[11] = 32; }

    // QFI
    if (in->pdi.qfi)     { R.range[12] = {{ in->pdi.qfi, in->pdi.qfi }}; R.prefix_length[12] = 32; }

    // uplink flag
    uint32_t v = in->is_uplink ? 1u : 0u;
    R.range[13]         = {{ v, v }};
    R.prefix_length[13] = 32;

    // precedence: lower wins → invert so higher int priority is stronger
    R.priority   = INT32_MAX - (int)in->precedence;
    R.descriptor = in->descriptor;  // pointer/cookie to DP view (must be hugepage-resident)
    R.id         = in->pdr_id;

    return R;
}

static Packet to_cpp_pkt(const ps_packet_t *p) {
    Packet P(PDI_MAX_FLD);
    P[0]  = p->ue_ip;
    P[1]  = p->src_ip;
    P[2]  = p->dst_ip;
    P[3]  = p->src_port;
    P[4]  = p->dst_port;
    P[5]  = p->proto;
    P[6]  = p->tos_tc;
    P[7]  = p->spi;
    P[8]  = p->flow_label;
    P[9]  = p->teid;
    P[10] = p->source_if;
    P[11] = p->ni_hash;
    P[12] = p->qfi;
    P[13] = p->is_uplink;
    return P;
}

/*────────────────── C API (extern "C") ─────────────────────────────────*/

extern "C" {

/* Create a fresh, heap-allocated handle (one per snapshot).
 * NOTE: with the global new/delete shim linked into UPF-C,
 *       all allocations land in DPDK hugepages. */
cls_handle_t *cls_create(cls_backend_t /*backend_ignored_if_compiletime_selected*/) {
    try {
        auto *h = new cls_handle_t{};
    #if CLS_SELECTED_BACKEND_ID == CLS_BACKEND_ID_PS
        h->ps  = new PartitionSort();
    #elif CLS_SELECTED_BACKEND_ID == CLS_BACKEND_ID_TSS
        h->tss = new TupleSpaceSearch();
    #else
        h->ptss = new PriorityTupleSpaceSearch();
    #endif
        return h;
    } catch (const std::bad_alloc&) {
        return nullptr;
    }
}

void cls_destroy(cls_handle_t *h) {
    if (!h) return;
#if CLS_SELECTED_BACKEND_ID == CLS_BACKEND_ID_PS
    delete h->ps;
#elif CLS_SELECTED_BACKEND_ID == CLS_BACKEND_ID_TSS
    delete h->tss;
#else
    delete h->ptss;
#endif
    rte_free(h);
}

/* Insert one PDR (converted to a C++ Rule) into the snapshot being built. */
uintptr_t cls_insert_rule(cls_handle_t *h, const pdr_t *r) {
    if (!h || !r) return 0;
    Rule R = to_cpp_rule(r);
#if CLS_SELECTED_BACKEND_ID == CLS_BACKEND_ID_PS
    // PartitionSort returns its descriptor
    return h->ps->InsertRuleReturnDescriptor(R);
#elif CLS_SELECTED_BACKEND_ID == CLS_BACKEND_ID_TSS
    try {
        h->tss->InsertRule(R);
        return R.descriptor;
    } catch (const std::bad_alloc&) { return 0; }
#else
    try {
        h->ptss->InsertRule(R);
        return R.descriptor;
    } catch (const std::bad_alloc&) { 
        return 0; 
    }
#endif
}

/* Optional: delete by descriptor while building (if needed later) */
int cls_delete_rule_by_descriptor(cls_handle_t *h, uintptr_t d) {
    if (!h) return -1;
#if CLS_SELECTED_BACKEND_ID == CLS_BACKEND_ID_PS
    return h->ps->DeleteRuleByDescriptor(d) ? 0 : -1;
#elif CLS_SELECTED_BACKEND_ID == CLS_BACKEND_ID_TSS
    return h->tss->DeleteRuleByDescriptor(d) ? 0 : -1;
#else
    return h->ptss->DeleteRuleByDescriptor(d) ? 0 : -1;
#endif
}

/* Classify a packet against an immutable snapshot.
 * Returns: 1 on match, 0 on miss, -1 on error. */
int cls_classify_packet(
    cls_handle_t       *h,          /* kept non-const to match existing header */
    const ps_packet_t  *p,
    uint32_t           *prec_out,
    uintptr_t          *desc_out)
{
    if (!h || !p) return -1;

#if CLS_SELECTED_BACKEND_ID == CLS_BACKEND_ID_PS
    MatchResult m = h->ps->ClassifyAPacketMod(to_cpp_pkt(p));
#elif CLS_SELECTED_BACKEND_ID == CLS_BACKEND_ID_TSS
    MatchResult m = h->tss->ClassifyAPacketMod(to_cpp_pkt(p));
#else
    MatchResult m = h->ptss->ClassifyAPacketMod(to_cpp_pkt(p));
#endif

    if (m.priority < 0) return 0;  /* no match */

    if (prec_out) *prec_out = (uint32_t)(INT32_MAX - m.priority);
    if (desc_out) *desc_out = m.descriptor;
    return 1;
}

/* Debug helper: dump rules (backend-dependent). Safe to call in CP only. */
static void print_cidr(uint32_t host_ip, unsigned prefix) {
    struct in_addr addr; addr.s_addr = htonl(host_ip);
    char buf[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &addr, buf, sizeof(buf))) {
        snprintf(buf, sizeof(buf), "???.???.???.???");
    }
    printf("%s/%u", buf, prefix);
}

void cls_print_all_rules(cls_handle_t *h) {
#if CLS_SELECTED_BACKEND_ID == CLS_BACKEND_ID_PS
    if (h && h->ps) h->ps->PrintAllRules();
#elif CLS_SELECTED_BACKEND_ID == CLS_BACKEND_ID_TSS
    if (h && h->tss) {
        auto rules = h->tss->SerializeIntoRules();
        printf("=== TupleSpaceSearch: %zu rules ===\n", rules.size());
        for (size_t i = 0; i < rules.size(); ++i) {
            const auto &r = rules[i];
            uint32_t prec = (uint32_t)(INT32_MAX - r.priority);
            printf("Rule[%2zu] desc=0x%" PRIxPTR "  prec=%u  ", i, r.descriptor, prec);
            printf("UE=");  print_cidr(r.range[0][0], r.prefix_length[0]);  printf("  ");
            printf("SRC="); print_cidr(r.range[1][0], r.prefix_length[1]);  printf("  ");
            printf("DST="); print_cidr(r.range[2][0], r.prefix_length[2]);
            putchar('\n');
        }
        puts("=== end of rules ===");
    }
#else
    if (h && h->ptss) {
        auto rules = h->ptss->SerializeIntoRules();
        printf("=== PriorityTupleSpaceSearch: %zu rules ===\n", rules.size());
        for (size_t i = 0; i < rules.size(); ++i) {
            const auto &r = rules[i];
            uint32_t prec = (uint32_t)(INT32_MAX - r.priority);
            printf("Rule[%2zu] desc=0x%" PRIxPTR "  prec=%u  ", i, r.descriptor, prec);
            printf("UE=");  print_cidr(r.range[0][0], r.prefix_length[0]);  printf("  ");
            printf("SRC="); print_cidr(r.range[1][0], r.prefix_length[1]);  printf("  ");
            printf("DST="); print_cidr(r.range[2][0], r.prefix_length[2]);
            putchar('\n');
        }
        puts("=== end of rules ===");
    }
#endif
}

} /* extern "C" */
