/* C/C++ headers */
#include <cstring>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <arpa/inet.h>
#include <iostream>
#include <iomanip>


/* Public adapter interface + wrapper types */
#include "upf_cls_adapter.h"
#include "classifier_wrapper.h"

#ifndef CLS_ADAPTER_DEBUG
#define CLS_ADAPTER_DEBUG 0
#endif

/*──────────────────── local helpers ────────────────────*/

static inline uint32_t fnv1a_hash(const char *s) {
    uint32_t h = 2166136261u;
    if (!s) return 0u;
    while (*s) { h ^= (uint8_t)*s++; h *= 16777619u; }
    return h;
}

/* Parse "A.B.C.D[/P]" → host-order IPv4 + prefix (0..32).
 * If no /P, defaults to /32 (exact). On parse error, returns 0 with pref=0. */
static inline uint32_t parse_ip_prefix(const char *s, uint8_t *pref_out) {
    if (!s || !*s) { *pref_out = 0; return 0; }
    char buf[32]; std::memset(buf, 0, sizeof(buf));
    std::strncpy(buf, s, sizeof(buf) - 1);

    char *slash = std::strchr(buf, '/');
    if (slash) {
        *slash = '\0';
        const char *p = slash + 1;
        *pref_out = (std::isdigit((unsigned char)*p)) ? (uint8_t)std::atoi(p) : 32;
        if (*pref_out > 32) *pref_out = 32;
    } else {
        *pref_out = 32;
    }

    struct in_addr a{};
    if (!inet_aton(buf, &a)) { *pref_out = 0; return 0; }
    /* store as host-order 32-bit (we convert as needed downstream) */
    return ntohl(a.s_addr);
}

/* Map PFCP sourceInterface to our enum; default ACCESS if unknown. */
static inline source_interface_t map_src_if(uint8_t pfcp_if) {
    return (pfcp_if < SRC_IF_COUNT) ? (source_interface_t)pfcp_if : SRC_IF_ACCESS;
}


static const char* ip_to_str(uint32_t host_ip, char buf[INET_ADDRSTRLEN]) {
    struct in_addr a; a.s_addr = htonl(host_ip);
    return inet_ntop(AF_INET, &a, buf, sizeof(buf)) ? buf : "<?>"; 
}

static inline std::string ip4(uint32_t host_ip) {
    struct in_addr in;
    in.s_addr = htonl(host_ip);          // we store host-order; inet_ntop expects network-order
    char buf[INET_ADDRSTRLEN] = {0};
    return inet_ntop(AF_INET, &in, buf, sizeof(buf)) ? std::string(buf) : std::string("<invalid>");
}

// Compact, readable single-line dump of pdr_t
static void log_rule(const pdr_t &r) {
    std::cerr << "ClassifierRule: "
              << "id="    << r.pdr_id
              << " prec=" << r.precedence
              << " UE="   << ip4(r.pdi.ue_ip.s_addr)  << "/" << int(r.pdi.ue_pref)
              << " SRC="  << ip4(r.pdi.src_ip.s_addr) << "/" << int(r.pdi.src_pref)
              << " DST="  << ip4(r.pdi.dst_ip.s_addr) << "/" << int(r.pdi.dst_pref)
              << " sport=" << r.pdi.src_port
              << " dport=" << r.pdi.dst_port
              << " proto=" << int(r.pdi.proto)
              << " tos="   << int(r.pdi.tos_tc)
              << " spi="   << r.pdi.spi
              << " flow="  << r.pdi.flow_label
              << " teid="  << r.pdi.teid
              << " srcIf=" << int(r.pdi.source_if)
              << " ni=0x"  << std::hex << std::setw(8) << std::setfill('0') << r.pdi.ni_hash
              << std::dec
              << " qfi="   << int(r.pdi.qfi)
              << " desc=0x"<< std::hex << std::setw(sizeof(uintptr_t)*2) << std::setfill('0')
              << static_cast<uintptr_t>(r.descriptor)
              << std::dec
              << '\n';
}

/*──────────────────── public C API ─────────────────────*/

extern "C" pdr_t updk_pdr_to_cls_rule(const UPDK_PDR *in, bool is_uplink)
{
#if CLS_ADAPTER_DEBUG
    std::printf("updk_pdr_to_cls_rule: is_uplink = %s\n", is_uplink ? "true" : "false");
#endif

    pdr_t out{};
    out.is_uplink = is_uplink;
    // descriptor is set by the builder (rebuild code), leave as 0

    if (!in) return out;

    if (in->flags.pdrId)      out.pdr_id     = in->pdrId;
    if (in->flags.precedence) out.precedence = in->precedence;
    if (!in->flags.pdi)       return out;

    const UPDK_PDI &p = in->pdi;

    if (p.flags.ueIpAddress && p.ueIpAddress.flags.v4) {
        out.pdi.ue_ip.s_addr = ntohl(p.ueIpAddress.ipv4.s_addr);
        out.pdi.ue_pref      = 32;
    }

    if (p.flags.fTeid && p.fTeid.flags.v4) {
        out.pdi.teid = p.fTeid.teid;
    }

    if (p.flags.qfi)               out.pdi.qfi = p.qfi;
    if (p.flags.networkInstance)   out.pdi.ni_hash = fnv1a_hash(p.networkInstance);

    // Your original behavior: ignore explicit SourceInterface and derive from is_uplink
    out.pdi.source_if = is_uplink ? SRC_IF_ACCESS : SRC_IF_CORE;

    if (p.flags.sdfFilter) {
        const auto &f = p.sdfFilter;

        if (f.flags.ttc) out.pdi.tos_tc = f.tosTrafficClass;
        if (f.flags.spi) out.pdi.spi    = f.securityParameterIndex;

        if (f.flags.fd && f.flowDescription) {
            const char *desc = f.flowDescription;
            char token[32];

            if (std::strstr(desc, "from any") && std::strstr(desc, "to assigned")) {
                if (is_uplink) {
                    // UL: UE → any
                    out.pdi.src_ip.s_addr = out.pdi.ue_ip.s_addr; out.pdi.src_pref = out.pdi.ue_pref;
                    out.pdi.dst_ip.s_addr = 0;                    out.pdi.dst_pref = 0;
                } else {
                    // DL: any → UE
                    out.pdi.src_ip.s_addr = 0;                    out.pdi.src_pref = 0;
                    out.pdi.dst_ip.s_addr = out.pdi.ue_ip.s_addr; out.pdi.dst_pref = out.pdi.ue_pref;
                }
#if CLS_ADAPTER_DEBUG
                std::printf("[CLS] FlowDescription hack: %s — src=%u dst=%u\n",
                            is_uplink ? "UL" : "DL",
                            out.pdi.src_ip.s_addr, out.pdi.dst_ip.s_addr);
#endif
            } else {
                // parse "from X"
                if (const char *pos = std::strstr(desc, "from ")) {
                    pos += 5;
                    size_t i = 0;
                    while (pos[i] && !std::isspace((unsigned char)pos[i]) && i + 1 < sizeof(token)) {
                        token[i++] = pos[i-0];
                    }
                    token[i] = '\0';

                    if      (std::strcmp(token, "any") == 0)      { out.pdi.src_ip.s_addr = 0; out.pdi.src_pref = 0; }
                    else if (std::strcmp(token, "assigned") == 0) {
                        if (out.pdi.ue_pref == 0 && out.pdi.ue_ip.s_addr == 0) {
#if CLS_ADAPTER_DEBUG
                            std::cerr << "[upf_cls_adapter] ‘assigned’ used but UE IP missing – wildcard\n";
#endif
                            out.pdi.src_ip.s_addr = 0; out.pdi.src_pref = 0;
                        } else {
                            out.pdi.src_ip.s_addr = out.pdi.ue_ip.s_addr; out.pdi.src_pref = out.pdi.ue_pref;
                        }
                    } else {
                        uint8_t pf = 0;
                        out.pdi.src_ip.s_addr = parse_ip_prefix(token, &pf);
                        out.pdi.src_pref      = pf;
                    }
                }

                // parse "to Y"
                std::memset(token, 0, sizeof(token));
                if (const char *pos = std::strstr(desc, "to ")) {
                    pos += 3;
                    size_t j = 0;
                    while (pos[j] && !std::isspace((unsigned char)pos[j]) && j + 1 < sizeof(token)) {
                        token[j++] = pos[j-0];
                    }
                    token[j] = '\0';

                    if      (std::strcmp(token, "any") == 0)      { out.pdi.dst_ip.s_addr = 0; out.pdi.dst_pref = 0; }
                    else if (std::strcmp(token, "assigned") == 0) {
                        if (out.pdi.ue_pref == 0 && out.pdi.ue_ip.s_addr == 0) {
#if CLS_ADAPTER_DEBUG
                            std::cerr << "[upf_cls_adapter] ‘assigned’ used but UE IP missing – wildcard\n";
#endif
                            out.pdi.dst_ip.s_addr = 0; out.pdi.dst_pref = 0;
                        } else {
                            out.pdi.dst_ip.s_addr = out.pdi.ue_ip.s_addr; out.pdi.dst_pref = out.pdi.ue_pref;
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

#if CLS_ADAPTER_DEBUG
    log_rule(out);
#endif

    return out;
}
