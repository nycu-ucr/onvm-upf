#include <ctype.h>
#include <string.h>
#include <cstdint>
#include <cstdlib>
#include <arpa/inet.h>
#include <iostream>
#include <iomanip>


#include "classifier_wrapper.h"
#include "upf_cls_adapter.h"
#include "upf_cls_backend.hpp" 


#define SRC_IF_ANY  ((source_interface_t)ANY8)


static int cls_debug_enabled = 1;


static inline std::string ip4(uint32_t host_ip) {
    struct in_addr in;
    in.s_addr = htonl(host_ip);               // convert back to network order
    char buf[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &in, buf, sizeof(buf)) == nullptr) {
        return std::string("<invalid>");
    }
    return std::string(buf);
}

// Dump a converted pdr_t rule if cls_debug_enabled==1
static void log_rule(const pdr_t &r) {
    if (!cls_debug_enabled) return;

    std::cerr
        << "ClassifierRule: id=" << r.pdr_id
        << " prec="   << r.precedence
        << " UE="     << ip4(r.pdi.ue_ip.s_addr) << "/" << (int)r.pdi.ue_pref
        << " SRC="    << ip4(r.pdi.src_ip.s_addr) << "/" << (int)r.pdi.src_pref
        << " DST="    << ip4(r.pdi.dst_ip.s_addr) << "/" << (int)r.pdi.dst_pref
        << " sport="  << r.pdi.src_port
        << " dport="  << r.pdi.dst_port
        << " proto="  << (int)r.pdi.proto
        << " tos="    << (int)r.pdi.tos_tc
        << " spi="    << r.pdi.spi
        << " flow="   << r.pdi.flow_label
        << " teid="   << r.pdi.teid
        << " srcIf="  << (int)r.pdi.source_if
        << " ni=0x"   << std::hex << std::setw(8) << std::setfill('0') << r.pdi.ni_hash << std::dec
        << " qfi="    << (int)r.pdi.qfi
        << " desc=0x" << std::hex << r.descriptor << std::dec
        << "\n";
}


static inline uint32_t fnv1a_hash(const char *s) {
    uint32_t h = 2166136261u;
    while (*s) {
        h ^= static_cast<uint8_t>(*s++);
        h *= 16777619u;
    }
    return h;
}


static inline void init_wildcard(pdr_t *r)
{
    memset(r, 0, sizeof(*r));
    r->pdi.src_port = ANY16;
    r->pdi.dst_port = ANY16;
    r->pdi.spi      = ANY32;
    r->pdi.flow_label = ANY32;
    r->pdi.teid     = ANY32;
    r->pdi.source_if= SRC_IF_ANY;
    r->pdi.ni_hash  = ANY32;
    r->pdi.qfi = ANY8;
}


// parse "X.Y.Z.W[/P]" → host-order IPv4 + prefix 
static inline uint32_t parse_ip_prefix(const char *s, uint8_t *prefix_out)
{
    char ipbuf[32];
    strncpy(ipbuf, s, sizeof(ipbuf) - 1);
    ipbuf[sizeof(ipbuf) - 1] = '\0';

    char *slash = strchr(ipbuf, '/');
    if (slash) {
        *slash = '\0';

        // only parse digit-prefixed values
        if (isdigit((unsigned char)slash[1])) {
            int pr = atoi(slash + 1);
            *prefix_out = (uint8_t)(pr > 32 ? 32 : pr);
        } else {
            *prefix_out = 32;  // malformed → default /32
        }
    } else {
        *prefix_out = 32;      // no “/” → default /32
    }

    struct in_addr addr;
    if (inet_aton(ipbuf, &addr) == 0) {
        *prefix_out = 0;       // invalid IP
        return 0;
    }

    return ntohl(addr.s_addr);
}


static inline source_interface_t map_src_if(uint8_t pfcp_if) {
    if (pfcp_if < SRC_IF_COUNT) {
        return static_cast<source_interface_t>(pfcp_if);
    }
    return SRC_IF_ACCESS;
}

pdr_t updk_pdr_to_cls_rule(const UPDK_PDR *in) {
    pdr_t out{};
    init_wildcard(&out);

    if (in->flags.pdrId) {
        out.pdr_id = in->pdrId;
    }
    if (in->flags.precedence) {
        out.precedence = in->precedence;
    }
    if (!in->flags.pdi)
        return out;

    const UPDK_PDI *p = &in->pdi;

    // Helper for IP + prefix
    auto load_ip = [&](
        bool ok, const struct in_addr &addr, uint8_t pref,
        struct in_addr &dst_ip, uint8_t &dst_pref
    ) {
        if (!ok) { 
            dst_pref = 0; 
            return; 
        }
        dst_ip.s_addr = ntohl(addr.s_addr);
        dst_pref = (pref ? pref : 32);
    };

    if (p->flags.ueIpAddress && p->ueIpAddress.flags.v4) {
        out.pdi.ue_ip.s_addr = ntohl(p->ueIpAddress.ipv4.s_addr);
        out.pdi.ue_pref  = 0;
    }

    // TEID
    if (p->flags.fTeid && p->fTeid.flags.v4)
        out.pdi.teid = ntohl(p->fTeid.teid);

    // SDF filter fields
    if (p->flags.sdfFilter) {

        const auto &f = p->sdfFilter;

        /* if (f.flags.proto) {
            out.pdi.proto = f.protocolId;
        }

        if (f.flags.srcPort) {
            out.pdi.src_port = ntohs(f.srcPort);
        }

        if (f.flags.dstPort) {
            out.pdi.dst_port = ntohs(f.dstPort);
        } */

        if (f.flags.ttc) {
            out.pdi.tos_tc = f.tosTrafficClass;
        }
        if (f.flags.spi) {
            out.pdi.spi = f.securityParameterIndex;
        }

        // Flow‐description parsing (pure C)
        if (f.flags.fd && f.flowDescription) {
            const char *desc = f.flowDescription;
            // from …
            if (const char *from = strstr(desc, "from ")) {
                from += 5;
                char buf[32]; size_t i = 0;
                while (from[i] && !isspace((unsigned char)from[i]) && i+1<sizeof(buf))
                    buf[i] = from[i], i++;
                buf[i] = 0;
                uint8_t pf = 0;
                out.pdi.src_ip.s_addr = parse_ip_prefix(buf, &pf);
                out.pdi.src_pref = pf ? pf : 32;
            }
            // to …
            if (const char *to = strstr(desc, "to ")) {
                to += 3;
                char buf2[32]; size_t j = 0;
                while (to[j] && !isspace((unsigned char)to[j]) && j+1<sizeof(buf2))
                    buf2[j] = to[j], j++;
                buf2[j] = 0;
                uint8_t pf2 = 0;
                out.pdi.dst_ip.s_addr = parse_ip_prefix(buf2, &pf2);
                out.pdi.dst_pref      = pf2 ? pf2 : 32;
            }
        }
    }

    // QFI
    if (p->flags.qfi)
        out.pdi.qfi = p->qfi;

    
    if (p->flags.networkInstance) {
        out.pdi.ni_hash = fnv1a_hash(p->networkInstance);
    }

    if (p->flags.sourceInterface) {
        out.pdi.source_if = map_src_if(p->sourceInterface);
    }

    log_rule(out);

    return out;
}




/*

// ---- SDF flowDescription → src/dst IP+prefix -------------------
if (p->flags.sdfFilter && p->sdfFilter.flowDescription) {
    const char *desc = p->sdfFilter.flowDescription;

    // ------- "from X.Y.Z.W[/P]" ----------------------------------
    const char *from = strstr(desc, "from");
    if (from) {
        from += 5;  // skip "from "
        char buf[32];
        size_t i = 0;
        while (from[i] && !isspace((unsigned char)from[i]) && i+1 < sizeof(buf))
            buf[i++] = from[i];
        buf[i] = '\0';

        uint32_t masked = charStr2MaskedIP(buf, &out.pdi.src_pref);
        out.pdi.src_ip.s_addr = masked;
    }

    //------- "to X.Y.Z.W[/P]" ------------------------------------
    const char *to = strstr(desc, "to");
    if (to) {
        to += 3;  // skip "to "
        char buf2[32];
        size_t j = 0;
        while (to[j] && !isspace((unsigned char)to[j]) && j+1 < sizeof(buf2))
            buf2[j++] = to[j];
        buf2[j] = '\0';

        uint32_t masked2 = charStr2MaskedIP(buf2, &out.pdi.dst_pref);
        out.pdi.dst_ip.s_addr = masked2;
    }
}



*/


extern "C" uintptr_t upf_cls_add_pdr(const UPDK_PDR *pdr)
{
    if (!pdr) return -1;
    pdr_t rule = updk_pdr_to_cls_rule(pdr);
    rule.descriptor = reinterpret_cast<uintptr_t>(pdr);

    return cls_insert_rule(cls_global(), &rule);
}

extern "C"
int upf_cls_del_pdr(const UPDK_PDR *pdr)
{
    if (!pdr) return -1;
    return cls_delete_rule_by_descriptor( cls_global(), reinterpret_cast<uintptr_t>(pdr));
}

extern "C"
const UPDK_PDR *upf_cls_lookup(const ps_packet_t *pkt)
{
    if (!pkt) return nullptr;

    uintptr_t desc = 0;
    /* cls_classify_packet returns 1 on hit */
    if (cls_classify_packet(cls_global(), pkt, nullptr, &desc) == 1)
        return reinterpret_cast<const UPDK_PDR *>(desc);

    return nullptr;
}
