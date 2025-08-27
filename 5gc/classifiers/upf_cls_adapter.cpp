/* C/C++ headers */
#include <cstring>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <arpa/inet.h>


/* Public adapter interface + wrapper types */
#include "upf_cls_adapter.h"
#include "classifier_wrapper.h"

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

static void log_rule(const pdr_t* r, const char* tag /* e.g., "UL" or "DL" */) {
    if (!r) return;
    char ue[INET_ADDRSTRLEN], si[INET_ADDRSTRLEN], di[INET_ADDRSTRLEN];
    printf("[CLS][%s] PDR id=%u prec=%u is_ul=%u desc=0x%lx\n"
           "          UE=%s/%u  SRC=%s/%u  DST=%s/%u  L4:%u->%u proto=%u tos=%u\n"
           "          TEID=%u src_if=%u qfi=%u spi=%u ni_hash=0x%x\n",
           tag ? tag : "-", r->pdr_id, r->precedence, (unsigned)r->is_uplink,
           (unsigned long)r->descriptor,
           ip_to_str(r->pdi.ue_ip.s_addr, ue), r->pdi.ue_pref,
           ip_to_str(r->pdi.src_ip.s_addr, si), r->pdi.src_pref,
           ip_to_str(r->pdi.dst_ip.s_addr, di), r->pdi.dst_pref,
           (unsigned)r->pdi.src_port, (unsigned)r->pdi.dst_port,
           (unsigned)r->pdi.proto, (unsigned)r->pdi.tos_tc,
           r->pdi.teid, (unsigned)r->pdi.source_if, (unsigned)r->pdi.qfi,
           r->pdi.spi, r->pdi.ni_hash);
}

/*──────────────────── public C API ─────────────────────*/

extern "C" pdr_t updk_pdr_to_cls_rule(const UPDK_PDR *in, bool is_uplink) {
    pdr_t out{};
    out.is_uplink = is_uplink;
    out.descriptor = 0; /* builder sets if desired */

    if (!in) return out;

    if (in->flags.pdrId)       out.pdr_id    = in->pdrId;
    if (in->flags.precedence)  out.precedence= in->precedence;

    if (!in->flags.pdi) return out;
    const UPDK_PDI &p = in->pdi;

    /* UE IP (IPv4) */
    if (p.flags.ueIpAddress && p.ueIpAddress.flags.v4) {
        out.pdi.ue_ip.s_addr = ntohl(p.ueIpAddress.ipv4.s_addr); /* host-order */
        out.pdi.ue_pref      = 32;
    }

    /* TEID (host-order as carried) */
    if (p.flags.fTeid && p.fTeid.flags.v4)
        out.pdi.teid = p.fTeid.teid;

    /* QFI / Network Instance hash / Source Interface */
    if (p.flags.qfi)               out.pdi.qfi       = p.qfi;
    if (p.flags.networkInstance)   out.pdi.ni_hash   = fnv1a_hash(p.networkInstance);
    if (p.flags.sourceInterface)   out.pdi.source_if = map_src_if(p.sourceInterface);
    else                           out.pdi.source_if = is_uplink ? SRC_IF_ACCESS : SRC_IF_CORE;

    /* SDF Filter → optional fields */
    if (p.flags.sdfFilter) {
        const auto &f = p.sdfFilter;

        if (f.flags.ttc) out.pdi.tos_tc = f.tosTrafficClass;
        if (f.flags.spi) out.pdi.spi    = f.securityParameterIndex;
        /* IPv6 flow-label intentionally ignored here */

        /* Flow Description heuristics (simple "from X to Y" parsing) */
        if (f.flags.fd && f.flowDescription) {
            const char *desc = f.flowDescription;

            /* Quick path: "from any to assigned" / "from assigned to any" */
            bool has_from_any      = std::strstr(desc, "from any")      != nullptr;
            bool has_to_assigned   = std::strstr(desc, "to assigned")   != nullptr;
            bool has_from_assigned = std::strstr(desc, "from assigned") != nullptr;
            bool has_to_any        = std::strstr(desc, "to any")        != nullptr;

            if (out.pdi.ue_pref && (has_from_any && has_to_assigned)) {
                if (is_uplink) {
                    /* UL: UE→any */
                    out.pdi.src_ip.s_addr = out.pdi.ue_ip.s_addr; out.pdi.src_pref = out.pdi.ue_pref;
                    out.pdi.dst_ip.s_addr = 0;                    out.pdi.dst_pref = 0;
                } else {
                    /* DL: any→UE */
                    out.pdi.src_ip.s_addr = 0;                    out.pdi.src_pref = 0;
                    out.pdi.dst_ip.s_addr = out.pdi.ue_ip.s_addr; out.pdi.dst_pref = out.pdi.ue_pref;
                }
            } else if (out.pdi.ue_pref && (has_from_assigned && has_to_any)) {
                if (is_uplink) {
                    /* UL: UE→any */
                    out.pdi.src_ip.s_addr = out.pdi.ue_ip.s_addr; out.pdi.src_pref = out.pdi.ue_pref;
                    out.pdi.dst_ip.s_addr = 0;                    out.pdi.dst_pref = 0;
                } else {
                    /* DL: any→UE */
                    out.pdi.src_ip.s_addr = 0;                    out.pdi.src_pref = 0;
                    out.pdi.dst_ip.s_addr = out.pdi.ue_ip.s_addr; out.pdi.dst_pref = out.pdi.ue_pref;
                }
            } else {
                /* Generic "from X" */
                char tok[32] = {0};
                if (const char *pos = std::strstr(desc, "from ")) {
                    pos += 5;
                    size_t i = 0;
                    while (pos[i] && !std::isspace((unsigned char)pos[i]) && i + 1 < sizeof(tok)) {
                        tok[i++] = pos[i-0];
                    }
                    tok[i] = '\0';
                    if      (std::strcmp(tok, "any") == 0)      { out.pdi.src_ip.s_addr = 0; out.pdi.src_pref = 0; }
                    else if (std::strcmp(tok, "assigned") == 0) {
                        if (out.pdi.ue_pref) { out.pdi.src_ip.s_addr = out.pdi.ue_ip.s_addr; out.pdi.src_pref = out.pdi.ue_pref; }
                        else                 { out.pdi.src_ip.s_addr = 0;                     out.pdi.src_pref = 0; }
                    } else {
                        uint8_t pf = 0; out.pdi.src_ip.s_addr = parse_ip_prefix(tok, &pf); out.pdi.src_pref = pf;
                    }
                }
                /* Generic "to Y" */
                std::memset(tok, 0, sizeof(tok));
                if (const char *pos = std::strstr(desc, "to ")) {
                    pos += 3;
                    size_t j = 0;
                    while (pos[j] && !std::isspace((unsigned char)pos[j]) && j + 1 < sizeof(tok)) {
                        tok[j++] = pos[j-0];
                    }
                    tok[j] = '\0';
                    if      (std::strcmp(tok, "any") == 0)      { out.pdi.dst_ip.s_addr = 0; out.pdi.dst_pref = 0; }
                    else if (std::strcmp(tok, "assigned") == 0) {
                        if (out.pdi.ue_pref) { out.pdi.dst_ip.s_addr = out.pdi.ue_ip.s_addr; out.pdi.dst_pref = out.pdi.ue_pref; }
                        else                 { out.pdi.dst_ip.s_addr = 0;                     out.pdi.dst_pref = 0; }
                    } else {
                        uint8_t pf2 = 0; out.pdi.dst_ip.s_addr = parse_ip_prefix(tok, &pf2); out.pdi.dst_pref = pf2;
                    }
                }
            }
        }

        /* Ports/proto from SDF fields if present (your UPDK model may carry them separately).
           If not present, they remain wildcard (0 / prefix=0 in rule mapping). */
        if (f.flags.bidirectional) {
            /* If you support explicit ports/proto tokens, parse them here as needed. */
        }
    }

    return out;
}
