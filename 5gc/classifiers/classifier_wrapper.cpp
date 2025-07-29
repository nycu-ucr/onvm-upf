#include <climits>
#include <cinttypes>

#include "classifier_wrapper.h"
#include "ElementaryClasses.h"
#include "PartitionSort/PartitionSort.h"
#include "TupleSpaceSearch/TupleSpaceSearch.h"
#include "../../onvm/updk/updk/rule_pdr.h"



struct cls_handle_t{
    cls_backend_t which;                  /* which engine is active  */
    PartitionSort            *ps  = nullptr;
    TupleSpaceSearch         *tss = nullptr;
    PriorityTupleSpaceSearch *ptss= nullptr;
};

static inline std::pair<uint32_t,uint32_t>
ip_range(uint32_t ip, uint8_t len) {
    uint32_t mask = len ? (len == 32 ? 0xFFFFFFFFu
                                     : 0xFFFFFFFFu << (32-len))
                        : 0;
    uint32_t low  = ip & mask;
    return {low, low | ~mask};
}

static Rule to_cpp_rule(const pdr_t *in)
{
    Rule R(PDI_MAX_FLD);

    /* UE / SRC / DST IPs ------------------------------------------------- */
    {
        auto box = ip_range(ntohl(in->pdi.ue_ip.s_addr), in->pdi.ue_pref);
        R.range[0] = {{ box.first, box.second }};
        R.prefix_length[0] = in->pdi.ue_pref;
    }
    {
        auto box = ip_range(ntohl(in->pdi.src_ip.s_addr), in->pdi.src_pref);
        R.range[1] = {{ box.first, box.second }};
        R.prefix_length[1] = in->pdi.src_pref;
    }
    {
        auto box = ip_range(ntohl(in->pdi.dst_ip.s_addr), in->pdi.dst_pref);
        R.range[2] = {{ box.first, box.second }};
        R.prefix_length[2] = in->pdi.dst_pref;
    }

    /* scalar equals  (src/dst port, proto, tos, spi, flow-label) --------- */
    const uint32_t scalars[6] = {
        in->pdi.src_port,  in->pdi.dst_port,
        in->pdi.proto,     in->pdi.tos_tc,
        in->pdi.spi,       in->pdi.flow_label
    };
    for (int d = 3; d <= 8; ++d) {
        R.range[d] = {{ scalars[d-3], scalars[d-3] }};
        R.prefix_length[d] = 32;
    }

    /* TEID / SourceIF / NI-hash ----------------------------------------- */
    R.range[9]  = {{ in->pdi.teid,      in->pdi.teid }};
    R.range[10] = {{ (uint8_t)in->pdi.source_if, (uint8_t)in->pdi.source_if }};
    R.range[11] = {{ in->pdi.ni_hash,   in->pdi.ni_hash }};
    R.range[12] = {{ in->pdi.qfi, in->pdi.qfi }};
    R.prefix_length[9]  = R.prefix_length[10] = R.prefix_length[11] = R.prefix_length[12] = 32;

    /* metadata ----------------------------------------------------------- */
    R.priority   = INT32_MAX - (int)in->precedence;   /* lower wins */
    R.descriptor = in->descriptor;
    R.id         = in->pdr_id;
    return R;
}

static Packet to_cpp_pkt(const ps_packet_t *p)
{
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
    P[12]  = p->qfi;
    return P;
}

/*------------------------------------------------------------------*/
/*  Opaque handle                                                   */
/*------------------------------------------------------------------*/
// struct cls_handle_t {
//     cls_backend_t which;
//     PartitionSort            *ps  = nullptr;
//     TupleSpaceSearch         *tss = nullptr;
//     PriorityTupleSpaceSearch *ptss= nullptr;
// };

/*------------------------------------------------------------------*/
/*  C API                                                           */
/*------------------------------------------------------------------*/
extern "C" {

// cls_handle_t *cls_create(cls_backend_t w)
// {
//     try {
//         auto *h = new cls_handle_t;
//         h->which = w;
//         if (w == CLS_BACKEND_PS)
//             h->ps  = new PartitionSort();
//         else
//             h->tss = new TupleSpaceSearch();
//         return h;
//     } catch (...) { return nullptr; }
// }

cls_handle_t* cls_create(cls_backend_t which)
{
    auto *h = new cls_handle_t{};
    h->which = which;
    try {
        if (which == CLS_BACKEND_PS) {
            h->ps  = new PartitionSort;
        }
        else if (which == CLS_BACKEND_TSS) {
            h->tss = new TupleSpaceSearch;
        }
        else {
            h->ptss = new PriorityTupleSpaceSearch;
        }
        return h;
    } catch (...) { 
        delete h; 
        return nullptr; 
    }
}


void cls_destroy(cls_handle_t *h)
{
    if (!h) return;
    delete h->ps;
    delete h->tss;
    delete h->ptss;
    delete h;
}

uintptr_t cls_insert_rule(cls_handle_t *h, const pdr_t *r)
{
    if (!h || !r) return 0;

    Rule R = to_cpp_rule(r);

    switch (h->which) {

    case CLS_BACKEND_PS:
        return h->ps->InsertRuleReturnDescriptor(R);

    case CLS_BACKEND_TSS:
        try {
            h->tss->InsertRule(R);
            return R.descriptor;
        } catch (const std::bad_alloc&) {
            return 0;
        }

    case CLS_BACKEND_PTSS:
        try {
            h->ptss->InsertRule(R);
            return R.descriptor;
        } catch (const std::bad_alloc&) {
            return 0;
        }

    default:
        return 0;
    }
}


int cls_delete_rule_by_descriptor(cls_handle_t *h, uintptr_t d)
{
    if (!h) return -1;

    if (h->which == CLS_BACKEND_PS)
        return h->ps->DeleteRuleByDescriptor(d) ? 0 : -1;
    if (h->which == CLS_BACKEND_TSS)
        return h->tss->DeleteRuleByDescriptor(d) ? 0 : -1;
    
    return h->ptss->DeleteRuleByDescriptor(d) ? 0 : -1;
}



int cls_classify_packet(
    cls_handle_t *h,
    const ps_packet_t *p,
    uint32_t *precedence_out,
    uintptr_t *descriptor_out
) {
    if (!h || !p) return -1;

    if (h->which == CLS_BACKEND_PS) {
        MatchResult m = h->ps->ClassifyAPacketMod(to_cpp_pkt(p));
        if (m.priority < 0) {
            return 0;
        }
        if (precedence_out) {
            *precedence_out  = (uint32_t)(INT32_MAX - m.priority);
        }
        if (descriptor_out) {
            *descriptor_out  = m.descriptor;
        }  
        return 1;

    } else if (h->which == CLS_BACKEND_TSS) {
        MatchResult m = h->tss->ClassifyAPacketMod(to_cpp_pkt(p));
        if (m.priority < 0) return 0;
        if (precedence_out) *precedence_out = (uint32_t)(INT32_MAX - m.priority);
        if (descriptor_out) *descriptor_out = m.descriptor;
        return 1;
    } else {
        MatchResult m = h->ptss->ClassifyAPacketMod(to_cpp_pkt(p));
        if (m.priority < 0) return 0;
        if (precedence_out) *precedence_out = (uint32_t)(INT32_MAX - m.priority);
        if (descriptor_out) *descriptor_out = m.descriptor;
        return 1;
    }
}

// void cls_print_all_rules(cls_handle_t *h)
// {
//     if (!h) return;

//     switch (h->which) {
//       case CLS_BACKEND_PS:
//         h->ps->PrintAllRules();
//         break;

//       case CLS_BACKEND_TSS: {
//         auto rules = h->tss->SerializeIntoRules();
//         printf("=== TupleSpaceSearch: %zu rules ===\n", rules.size());
//         for (size_t i = 0; i < rules.size(); ++i) {
//             printf("Rule[%2zu] desc=0x%" PRIxPTR "  prec=%u\n",
//                    i,
//                    rules[i].descriptor,
//                    (uint32_t)(INT32_MAX - rules[i].priority));
//         }
//         puts("=== end of rules ===");
//         break;
//       }

//       case CLS_BACKEND_PTSS: {
//         auto rules = h->ptss->SerializeIntoRules();
//         printf("=== PriorityTupleSearch: %zu rules ===\n", rules.size());
//         for (size_t i = 0; i < rules.size(); ++i) {
//             printf("Rule[%2zu] desc=0x%" PRIxPTR "  prec=%u\n",
//                    i,
//                    rules[i].descriptor,
//                    (uint32_t)(INT32_MAX - rules[i].priority));
//         }
//         puts("=== end of rules ===");
//         break;
//       }

//       default:
//         break;
//     }
// }


static void print_cidr(uint32_t host_ip, unsigned prefix) {
    struct in_addr addr;
    addr.s_addr = htonl(host_ip);
    char buf[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &addr, buf, sizeof(buf))) {
        snprintf(buf, sizeof(buf), "???.???.???.???");
    }
    printf("%s/%u", buf, prefix);
}


void cls_print_all_rules(cls_handle_t *h)
{
    if (!h) return;

    switch (h->which) {
      case CLS_BACKEND_PS:
        h->ps->PrintAllRules();
        break;

      case CLS_BACKEND_TSS: {
        auto rules = h->tss->SerializeIntoRules();
        printf("=== TupleSpaceSearch: %zu rules ===\n", rules.size());
        for (size_t i = 0; i < rules.size(); ++i) {
            const auto &r = rules[i];
            uint32_t prec = (uint32_t)(INT32_MAX - r.priority);
            printf("Rule[%2zu] desc=0x%" PRIxPTR "  prec=%u  ",
                   i, r.descriptor, prec);

            printf("UE=");   print_cidr(r.range[0][0], r.prefix_length[0]);   printf("  ");
            printf("SRC=");  print_cidr(r.range[1][0], r.prefix_length[1]);   printf("  ");
            printf("DST=");  print_cidr(r.range[2][0], r.prefix_length[2]);   
            putchar('\n');
        }
        puts("=== end of rules ===");
        break;
      }

      case CLS_BACKEND_PTSS: {
        auto rules = h->ptss->SerializeIntoRules();
        printf("=== PriorityTupleSearch: %zu rules ===\n", rules.size());
        for (size_t i = 0; i < rules.size(); ++i) {
            const auto &r = rules[i];
            uint32_t prec = (uint32_t)(INT32_MAX - r.priority);
            printf("Rule[%2zu] desc=0x%" PRIxPTR "  prec=%u  ",
                   i, r.descriptor, prec);

            printf("UE=");   print_cidr(r.range[0][0], r.prefix_length[0]);   printf("  ");
            printf("SRC=");  print_cidr(r.range[1][0], r.prefix_length[1]);   printf("  ");
            printf("DST=");  print_cidr(r.range[2][0], r.prefix_length[2]);   
            putchar('\n');
        }
        puts("=== end of rules ===");
        break;
      }

      default:
        break;
    }
}

}
