/* C + C++ standard headers */
#include <ctype.h>
#include <string.h>
#include <cstdlib>
#include <cstdint>
#include <arpa/inet.h>
#include <iostream>
#include <iomanip>

/* Classifier front-end & public adapter interface */
#include "classifier_wrapper.h"
#include "upf_cls_adapter.h"

/* UPDK structures */
#include "../../onvm/updk/updk/rule_pdr.h"

/*──── Local helpers / state ─────────────────────────────────────────────*/
#define SRC_IF_ANY  ((source_interface_t)ANY8)
static int cls_debug_enabled = 1;

static inline std::string ip4(uint32_t host_ip) {
    struct in_addr in { htonl(host_ip) };
    char buf[INET_ADDRSTRLEN];
    return inet_ntop(AF_INET, &in, buf, sizeof(buf)) ? buf : "<invalid>";
}

/* Pretty-printer for converted PDR → rule */
static void log_rule(const pdr_t &r) {
    if (!cls_debug_enabled) return;
    std::cerr << "ClassifierRule: id=" << r.pdr_id
              << " prec=" << r.precedence
              << " UE="  << ip4(r.pdi.ue_ip.s_addr)  << "/" << (int)r.pdi.ue_pref
              << " SRC=" << ip4(r.pdi.src_ip.s_addr) << "/" << (int)r.pdi.src_pref
              << " DST=" << ip4(r.pdi.dst_ip.s_addr) << "/" << (int)r.pdi.dst_pref
              << " sport="  << r.pdi.src_port
              << " dport="  << r.pdi.dst_port
              << " proto="  << (int)r.pdi.proto
              << " tos="    << (int)r.pdi.tos_tc
              << " spi="    << r.pdi.spi
              << " flow="   << r.pdi.flow_label
              << " teid="   << r.pdi.teid
              << " srcIf="  << (int)r.pdi.source_if
              << " ni=0x"   << std::hex << std::setw(8) << std::setfill('0')
                             << r.pdi.ni_hash << std::dec
              << " qfi="    << (int)r.pdi.qfi
              << " desc=0x" << std::hex << r.descriptor << std::dec
              << '\n';
}

/* 32-bit FNV-1a hash for Network-Instance */
static inline uint32_t fnv1a_hash(const char *s) {
    uint32_t h = 2166136261u;
    while (*s) { h ^= (uint8_t)*s++; h *= 16777619u; }
    return h;
}

/* Initialise a rule with wildcards */
/* static inline void init_wildcard(pdr_t *r)
{
    memset(r, 0, sizeof(*r));
    r->pdi.src_port   = ANY16;
    r->pdi.dst_port   = ANY16;
    r->pdi.spi        = ANY32;
    r->pdi.flow_label = ANY32;
    r->pdi.teid       = ANY32;
    r->pdi.source_if  = SRC_IF_ANY;
    r->pdi.ni_hash    = ANY32;
    r->pdi.qfi        = ANY8;
} */

/* Parse “X.Y.Z.W[/P]” into host-order IPv4 + prefix */
static inline uint32_t parse_ip_prefix(const char *s, uint8_t *pref_out)
{
    char buf[32];
    strncpy(buf, s, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = 0;

    char *slash = strchr(buf, '/');
    if (slash) {
        *slash = 0;
        *pref_out = isdigit((unsigned)slash[1]) ? (uint8_t)atoi(slash + 1) : 32;
        if (*pref_out > 32) *pref_out = 32;
    } else {
        *pref_out = 32;
    }

    struct in_addr a;
    if (!inet_aton(buf, &a)) { *pref_out = 0; return 0; }
    return ntohl(a.s_addr);
}

static inline source_interface_t map_src_if(uint8_t pfcp_if)
{
    return pfcp_if < SRC_IF_COUNT ? (source_interface_t)pfcp_if
                                  : SRC_IF_ACCESS;
}

static pdr_t updk_pdr_to_cls_rule(const UPDK_PDR *in, bool is_uplink)
{
    pdr_t out{};
    // init_wildcard(&out);

    if (in->flags.pdrId) {
        out.pdr_id = in->pdrId;
    }
    if (in->flags.precedence) { 
        out.precedence = in->precedence;
    }
    if (!in->flags.pdi) {
        return out;
    }

    const UPDK_PDI &p = in->pdi;

    if (p.flags.ueIpAddress && p.ueIpAddress.flags.v4) {
         out.pdi.ue_ip.s_addr = ntohl(p.ueIpAddress.ipv4.s_addr);
         out.pdi.ue_pref      = 32;
     }

    if (p.flags.fTeid && p.fTeid.flags.v4) {
        out.pdi.teid = ntohl(p.fTeid.teid);
    }

    if (p.flags.qfi) {
        out.pdi.qfi = p.qfi;
    }
    if (p.flags.networkInstance) {
        out.pdi.ni_hash = fnv1a_hash(p.networkInstance);
    }
    if (p.flags.sourceInterface)  {
        out.pdi.source_if = map_src_if(p.sourceInterface);
    }


    // PDI -> SDF Filter -> Flow Description

    if (p.flags.sdfFilter) {
        
        const auto &f = p.sdfFilter;

        if (f.flags.ttc) {
            out.pdi.tos_tc = f.tosTrafficClass;
        }
        if (f.flags.spi) {
            out.pdi.spi = f.securityParameterIndex;
        }

        if (f.flags.fl) {
            out.pdi.flow_label = p.flowLabel;
        }  

        if (f.flags.fd && f.flowDescription) {
            const char *desc = f.flowDescription;
            char token[32];

            if (strstr(desc, "from any") && strstr(desc, "to assigned")) {
                if (is_uplink) {
                    // uplink: match UE→any
                    out.pdi.src_ip.s_addr = out.pdi.ue_ip.s_addr;
                    out.pdi.src_pref      = out.pdi.ue_pref;
                    out.pdi.dst_ip.s_addr = 0;
                    out.pdi.dst_pref      = 0;
                } else {
                    // downlink: match any→UE
                    out.pdi.src_ip.s_addr = 0;
                    out.pdi.src_pref      = 0;
                    out.pdi.dst_ip.s_addr = out.pdi.ue_ip.s_addr;
                    out.pdi.dst_pref      = out.pdi.ue_pref;
                }
            } else {
                if (const char *pos = strstr(desc, "from ")) {
                pos += 5;
                size_t i = 0;
                while (pos[i] && !isspace((unsigned char)pos[i]) && i + 1 < sizeof(token)) {
                    token[i] = pos[i];
                    ++i;
                }
                    
                token[i] = '\0';

                if (strcmp(token, "any") == 0) {
                    out.pdi.src_ip.s_addr = 0;
                    out.pdi.src_pref      = 0;          /* wildcard */
                } else if (strcmp(token, "assigned") == 0) {
                    if (out.pdi.ue_pref == 0 && out.pdi.ue_ip.s_addr == 0) {
                        std::cerr << "[upf_cls_adapter] ‘assigned’ used but UE IP missing – "
                                     "treating as wildcard\n";
                        out.pdi.src_ip.s_addr = 0;
                        out.pdi.src_pref      = 0;
                    } else {
                        out.pdi.src_ip.s_addr = out.pdi.ue_ip.s_addr;
                        out.pdi.src_pref      = out.pdi.ue_pref;
                    }
                } else {
                    uint8_t pf = 0;
                    out.pdi.src_ip.s_addr = parse_ip_prefix(token, &pf);
                    out.pdi.src_pref      = pf;
                }
            }

            /* ─── “to …” ───────────────────────────────────────────── */
            memset(token, 0, sizeof(token)); 
            
            if (const char *pos = strstr(desc, "to ")) {
                pos += 3;
                size_t j = 0;
                while (pos[j] && !isspace((unsigned char)pos[j]) && j + 1 < sizeof(token)) {
                    token[j] = pos[j];
                    ++j;
                }
                    
                token[j] = '\0';

                if (strcmp(token, "any") == 0) {
                    out.pdi.dst_ip.s_addr = 0;
                    out.pdi.dst_pref      = 0;
                } else if (strcmp(token, "assigned") == 0) {
                    if (out.pdi.ue_pref == 0 && out.pdi.ue_ip.s_addr == 0) {
                        std::cerr << "[upf_cls_adapter] ‘assigned’ used but UE IP missing – "
                                     "treating as wildcard\n";
                        out.pdi.dst_ip.s_addr = 0;
                        out.pdi.dst_pref      = 0;
                    } else {
                        out.pdi.dst_ip.s_addr = out.pdi.ue_ip.s_addr;
                        out.pdi.dst_pref      = out.pdi.ue_pref;
                    }
                } else {
                    uint8_t pf2 = 0;
                    out.pdi.dst_ip.s_addr = parse_ip_prefix(token, &pf2);
                    out.pdi.dst_pref      = pf2;
                }
            }
            }
            
        }
    }


    /* if (p.flags.srcPort) {
        out.pdi.src_port = p.srcPort;
    }
    if (p.flags.dstPort) {
        out.pdi.dst_port = p.dstPort;
    }      
    if (p.flags.proto) {
        out.pdi.proto = p.protocolId;
    }        
    if (p.flags.tos_tc) {
        out.pdi.tos_tc = p.tosTrafficClass;
    }       
    if (p.flags.spi) {
        out.pdi.spi = p.securityParameterIndex;
    }   */        
     

    log_rule(out);
    return out;
}



/*──────────────────────── C-callable API ───────────────────────────────*/
extern "C" {

/* insert */
uintptr_t upf_cls_add_pdr(const UPDK_PDR *pdr, bool is_uplink)
{
    if (!pdr) return 0;
    printf("=================1======================");
    pdr_t rule = updk_pdr_to_cls_rule(pdr, is_uplink);
    printf("=================2======================");
    rule.descriptor = reinterpret_cast<uintptr_t>(pdr);
    printf("=================3======================");
    return cls_insert_rule(cls_global(), &rule);
}

/* delete */
int upf_cls_del_pdr(const UPDK_PDR *pdr)
{
    if (!pdr) return -1;
    uintptr_t desc = reinterpret_cast<uintptr_t>(pdr);
    return cls_delete_rule_by_descriptor(cls_global(), desc);
}

/* lookup */
const UPDK_PDR *upf_cls_lookup(const ps_packet_t *pkt)
{
    uintptr_t desc = 0;
    if (cls_classify_packet(cls_global(), pkt, nullptr, &desc) == 1)
        return reinterpret_cast<const UPDK_PDR *>(desc);
    return nullptr;
}

} /* extern "C" */
