#include "upf_cls_adapter.h"
#include "upf_cls_adapter.hpp" 
#include "classifier_wrapper.h"

#include <arpa/inet.h>

/* ──────────────────────────────────────────────────────────────────── */
/* Helper: flag-aware UPDK_PDR → pdr_t                                */
/* ──────────────────────────────────────────────────────────────────── */
static pdr_t updk_pdr_to_cls_rule(const UPDK_PDR *in)
{
    pdr_t out{};
    init_wildcard(&out);                    /* pre-fill ANY32/16/8 everywhere */

    /* ---- meta ----------------------------------------------------- */
    if (in->flags.pdrId)      out.pdr_id     = in->pdrId;
    if (in->flags.precedence) out.precedence = in->precedence;

    /* ---- bail if no PDI ------------------------------------------ */
    if (!in->flags.pdi) return out;

    const UPDK_PDI *p = &in->pdi;

    /* ---- UE / SRC / DST IPs -------------------------------------- */
    auto load_ip = [&](bool ok, uint32_t ip, uint8_t pref,
                       uint32_t &dst_ip, uint8_t &dst_pref)
    {
        if (!ok) { dst_pref = 0; return; }      /* wildcard */
        dst_ip   = ntohl(ip);
        dst_pref = pref ? pref : 32;            /* 0 ⇒ /32 in free5gc    */
    };

    load_ip(p->flags.ueIpAddress  && p->ueIpAddress.flags.v4,
            p->ueIpAddress.ipv4.s_addr,  p->ueIpAddress.ipv4Prefix,
            out.pdi.ue_ip, out.pdi.ue_pref);

    load_ip(p->flags.srcIpAddress && p->srcIpAddress.flags.v4,
            p->srcIpAddress.ipv4.s_addr, p->srcIpAddress.ipv4Prefix,
            out.pdi.src_ip, out.pdi.src_pref);

    load_ip(p->flags.dstIpAddress && p->dstIpAddress.flags.v4,
            p->dstIpAddress.ipv4.s_addr, p->dstIpAddress.ipv4Prefix,
            out.pdi.dst_ip, out.pdi.dst_pref);

    /* ---- TEID ----------------------------------------------------- */
    if (p->flags.fTeid && p->fTeid.flags.v4)
        out.pdi.teid = ntohl(p->fTeid.teid);

    /* ---- SDF filter (ports, proto, tos, spi, fl) ------------------ */
    if (p->flags.sdfFilter) {
        const auto &f = p->sdfFilter;

        if (f.flags.proto)    out.pdi.proto      = f.protocolId;
        if (f.flags.srcPort)  out.pdi.src_port   = ntohs(f.srcPort);
        if (f.flags.dstPort)  out.pdi.dst_port   = ntohs(f.dstPort);
        if (f.flags.ttc)      out.pdi.tos_tc     = f.tosTrafficClass;
        if (f.flags.spi)      out.pdi.spi        = f.securityParameterIndex;
        if (f.flags.fl)       out.pdi.flow_label = f.flowLabel;
    }

    /* ---- QFI reuse into proto dim -------------------------------- */
    if (p->flags.qfi)
        out.pdi.proto = p->qfi;

    return out;
}


extern "C"
int upf_cls_add_pdr(const UPDK_PDR *pdr)
{
    if (!pdr) return -1;
    pdr_t rule = updk_pdr_to_cls_rule(pdr);
    rule.descriptor = reinterpret_cast<uintptr_t>(pdr);

    return cls_insert_rule_return_descriptor(
        cls_global(),
        &rule,
        rule.descriptor
    );
}

extern "C"
int upf_cls_del_pdr(const UPDK_PDR *pdr)
{
    if (!pdr) return -1;
    return cls_delete_rule_by_descriptor(
        cls_global(),
        reinterpret_cast<uintptr_t>(pdr)
    );
}
