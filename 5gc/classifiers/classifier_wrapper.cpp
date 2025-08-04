#include <climits>
#include <cinttypes>
#include <cstdio>
#include <arpa/inet.h>

#include "classifier_wrapper.h"
#include "ElementaryClasses.h"

#include "PartitionSort/PartitionSort.h"
#include "TupleSpaceSearch/TupleSpaceSearch.h"

/*────────────────── Handle definition (compile-time variant) ─────────────*/
#if CLS_SELECTED_BACKEND == CLS_BACKEND_PS
struct cls_handle_t { PartitionSort *ps; };
#elif CLS_SELECTED_BACKEND == CLS_BACKEND_TSS
struct cls_handle_t { TupleSpaceSearch *tss; };
#else /* CLS_BACKEND_PTSS */
struct cls_handle_t { PriorityTupleSpaceSearch *ptss; };
#endif

/*────────────────── Construction ─────────────────────────────────────────*/
cls_handle_t *cls_create(cls_backend_t)
{
    static cls_handle_t h;
#if CLS_SELECTED_BACKEND == CLS_BACKEND_PS
    h.ps  = new PartitionSort();
#elif CLS_SELECTED_BACKEND == CLS_BACKEND_TSS
    h.tss = new TupleSpaceSearch();
#else
    h.ptss = new PriorityTupleSpaceSearch();
#endif
    return &h;
}

/*────────────────── Helpers ------------------------------------------------*/

static inline std::string ip4(uint32_t host_ip) {
    struct in_addr in { htonl(host_ip) };
    char buf[INET_ADDRSTRLEN];
    return inet_ntop(AF_INET, &in, buf, sizeof(buf)) ? buf : "<invalid>";
}


static inline std::pair<uint32_t,uint32_t> ip_range(uint32_t ip, uint8_t len) {
    uint32_t mask = len ? (len == 32
                           ? 0xFFFFFFFFu
                           : 0xFFFFFFFFu << (32 - len))
                        : 0;
    uint32_t lo = ip & mask;
    return {lo, lo | ~mask};
}

static Rule to_cpp_rule(const pdr_t *in)
{
    
    printf("=================6======================");

    char ue_buf[INET_ADDRSTRLEN];
    char src_buf[INET_ADDRSTRLEN];
    char dst_buf[INET_ADDRSTRLEN];

    struct in_addr tmp;

    /* UE-IP ------------------------------------------------------------ */
    tmp.s_addr = htonl(in->pdi.ue_ip.s_addr);       /* convert to network order */
    inet_ntop(AF_INET, &tmp, ue_buf, sizeof(ue_buf));

    /* SRC-IP ----------------------------------------------------------- */
    tmp.s_addr = htonl(in->pdi.src_ip.s_addr);
    inet_ntop(AF_INET, &tmp, src_buf, sizeof(src_buf));

    /* DST-IP ----------------------------------------------------------- */
    tmp.s_addr = htonl(in->pdi.dst_ip.s_addr);
    inet_ntop(AF_INET, &tmp, dst_buf, sizeof(dst_buf));

    printf(
    "DBG→to_cpp_rule in: pdr_id=%u  precedence=%u  descriptor=0x%lx\n"
    "             UE_IP=%s/%u  SRC_IP=%s/%u  DST_IP=%s/%u\n"
    "             sport=%u  dport=%u  proto=%u  tos=%u\n"
    "             spi=%u  flow_label=%u\n"
    "             teid=%u  source_if=%u  ni_hash=0x%08x  qfi=%u is_uplink=%d\n",
    in->pdr_id, in->precedence, (unsigned long)in->descriptor,
    ue_buf,  in->pdi.ue_pref,
    src_buf, in->pdi.src_pref,
    dst_buf, in->pdi.dst_pref,
    in->pdi.src_port, in->pdi.dst_port, in->pdi.proto, in->pdi.tos_tc,
    in->pdi.spi, in->pdi.flow_label,
    in->pdi.teid, in->pdi.source_if, in->pdi.ni_hash, in->pdi.qfi, in->is_uplink
    );
    

    
    Rule R(PDI_MAX_FLD);

    for (int d = 0; d < PDI_MAX_FLD; ++d) {
        R.range[d]         = {{ 0, 0xFFFFFFFFu }};  // UINT32_MAX
        R.prefix_length[d] = 0;  // /0 → match any
    }


    if (in->pdi.ue_pref) {
        auto box = ip_range(in->pdi.ue_ip.s_addr, in->pdi.ue_pref);
        R.range[0]         = {{ box.first, box.second }};
        R.prefix_length[0] = in->pdi.ue_pref;
    }

    if (in->pdi.src_pref) {
        auto box = ip_range(in->pdi.src_ip.s_addr, in->pdi.src_pref);
        R.range[1]         = {{ box.first, box.second }};
        R.prefix_length[1] = in->pdi.src_pref;
    }

    if (in->pdi.dst_pref) {
        auto box = ip_range(in->pdi.dst_ip.s_addr, in->pdi.dst_pref);
        R.range[2]         = {{ box.first, box.second }};
        R.prefix_length[2] = in->pdi.dst_pref;
    }

    if (in->pdi.src_port) {
        R.range[3]         = {{ in->pdi.src_port, in->pdi.src_port }};
        R.prefix_length[3] = 32;
    }

    if (in->pdi.dst_port) {
        R.range[4]         = {{ in->pdi.dst_port, in->pdi.dst_port }};
        R.prefix_length[4] = 32;
    }
    if (in->pdi.proto) {
        R.range[5]         = {{ in->pdi.proto, in->pdi.proto }};
        R.prefix_length[5] = 32;
    }
    if (in->pdi.tos_tc) {
        R.range[6]         = {{ in->pdi.tos_tc, in->pdi.tos_tc }};
        R.prefix_length[6] = 32;
    }
    if (in->pdi.spi) {
        R.range[7]         = {{ in->pdi.spi, in->pdi.spi }};
        R.prefix_length[7] = 32;
    }
    // ignoring flow label for now
    /* if (in->pdi.flow_label) {
        R.range[8]         = {{ in->pdi.flow_label, in->pdi.flow_label }};
        R.prefix_length[8] = 32;
    } */

    R.range[9]         = {{ in->pdi.teid, in->pdi.teid }};
    R.prefix_length[9] = 32;
    
    R.range[10]        = {{ in->pdi.source_if, in->pdi.source_if }};
    R.prefix_length[10]= 32;

    if (in->pdi.ni_hash) {
        R.range[11]        = {{ in->pdi.ni_hash, in->pdi.ni_hash }};
        R.prefix_length[11]= 32;
    }
    if (in->pdi.qfi) {
        R.range[12]        = {{ in->pdi.qfi, in->pdi.qfi }};
        R.prefix_length[12]= 32;
    }

    uint32_t v = in->is_uplink ? 1u : 0u;
    R.range[13]         = {{ v, v }};
    R.prefix_length[13] = 32;

    R.priority   = INT32_MAX - (int)in->precedence;   /* lower wins */
    R.descriptor = in->descriptor;
    R.id         = in->pdr_id;

    


    printf("DBG→built C++ Rule: dim=%d\n", R.dim);
    for (int d = 0; d < R.dim; ++d) {
        unsigned lo  = R.range[d][0];   // low end
        unsigned hi  = R.range[d][1];   // high end
        unsigned pfx = R.prefix_length[d];
        printf("   dim[%2d] = [%10u … %10u]  /%2u\n",
               d, lo, hi, pfx);
    }

    printf("=================8======================");
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
    P[13]  = p->is_uplink;
    return P;
}

/*────────────────── C API (extern \"C\") ─────────────────────────────────*/
extern "C" {

/* destroy ----------------------------------------------------------------*/
void cls_destroy(cls_handle_t *h)
{
    if (!h) return;
#if CLS_SELECTED_BACKEND == CLS_BACKEND_PS
    delete h->ps;
#elif CLS_SELECTED_BACKEND == CLS_BACKEND_TSS
    delete h->tss;
#else
    delete h->ptss;
#endif
}

uintptr_t cls_insert_rule(cls_handle_t *h, const pdr_t *r)
{
    if (!h || !r) return 0;
    Rule R = to_cpp_rule(r);
#if CLS_SELECTED_BACKEND == CLS_BACKEND_PS
    uintptr_t desc = h->ps->InsertRuleReturnDescriptor(R);
    printf("DBG=>cls_insert_rule: got descriptor=0x%lx for pdr_id=%u\n",
       (unsigned long)desc, r->pdr_id);
    cls_print_all_rules(h);
    return desc;
#elif CLS_SELECTED_BACKEND == CLS_BACKEND_TSS
    try { 
        h->tss->InsertRule(R);
    } catch (const std::bad_alloc&) { 
        return 0; 
    }
    return R.descriptor;
#else
    try {
        h->ptss->InsertRule(R);
    } catch (const std::bad_alloc&) {
        return 0; 
    }
    return R.descriptor;
#endif
}


int cls_delete_rule_by_descriptor(cls_handle_t *h, uintptr_t d)
{
    if (!h) return -1;
#if CLS_SELECTED_BACKEND == CLS_BACKEND_PS
    return h->ps->DeleteRuleByDescriptor(d) ? 0 : -1;
#elif CLS_SELECTED_BACKEND == CLS_BACKEND_TSS
    return h->tss->DeleteRuleByDescriptor(d) ? 0 : -1;
#else
    return h->ptss->DeleteRuleByDescriptor(d) ? 0 : -1;
#endif
}


int cls_classify_packet(
        cls_handle_t       *h,
        const ps_packet_t  *p,
        uint32_t           *prec_out,
        uintptr_t          *desc_out)
{
    if (!h || !p) return -1;
#if CLS_SELECTED_BACKEND == CLS_BACKEND_PS
    MatchResult m = h->ps->ClassifyAPacketMod(to_cpp_pkt(p));
#elif CLS_SELECTED_BACKEND == CLS_BACKEND_TSS
    MatchResult m = h->tss->ClassifyAPacketMod(to_cpp_pkt(p));
#else
    MatchResult m = h->ptss->ClassifyAPacketMod(to_cpp_pkt(p));
#endif
    if (m.priority < 0) return 0;          /* no match */

    if (prec_out) *prec_out  = (uint32_t)(INT32_MAX - m.priority);
    if (desc_out) *desc_out  = m.descriptor;
    return 1;
}



static void print_cidr(uint32_t host_ip, unsigned prefix) {
    struct in_addr addr;
    addr.s_addr = htonl(host_ip);
    char buf[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &addr, buf, sizeof(buf))) {
        snprintf(buf, sizeof(buf), "???.???.???.???");
    }
    printf("%s/%u", buf, prefix);
}


void cls_print_all_rules(cls_handle_t *h) {
    
#if CLS_SELECTED_BACKEND == CLS_BACKEND_PS
    if (h && h->ps)   h->ps->PrintAllRules();
#elif CLS_SELECTED_BACKEND == CLS_BACKEND_TSS
    if (h && h->tss) {
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
#else
    if (h && h->ptss) {
        auto rules = h->ptss->SerializeIntoRules();
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
#endif
}


} /* extern \"C\" */
