#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "upf_context.h"
#include "utlt_debug.h"

static void fill_dl_far(UpfFAR *far, uint32_t far_id, const char *outer_ip, uint32_t teid) {
    memset(far, 0, sizeof(*far));

    far->flags.farId = 1;
    far->farId = far_id;
    far->flags.applyAction = 1;
    far->applyAction = UPDK_FAR_APPLY_ACTION_FORW;
    far->flags.forwardingParameters = 1;
    far->forwardingParameters.flags.destinationInterface = 1;
    far->forwardingParameters.destinationInterface = UPDK_INTERFACE_VALUE_ACCESS;
    far->forwardingParameters.flags.outerHeaderCreation = 1;
    far->forwardingParameters.outerHeaderCreation.description =
        UPDK_OUTER_HEADER_CREATION_DESCRIPTION_GTPU_UDP_IPV4;
    far->forwardingParameters.outerHeaderCreation.teid = teid;

    if (inet_pton(AF_INET, outer_ip,
                  &far->forwardingParameters.outerHeaderCreation.ipv4) != 1) {
        fprintf(stderr, "invalid IPv4 address: %s\n", outer_ip);
    }
}

static void print_path_entry(const char *prefix, const UpfDlPathEntry *entry) {
    char ipbuf[INET_ADDRSTRLEN];

    if (!entry) {
        printf("%s(null)\n", prefix);
        return;
    }

    printf("%sfar_id=%u outer_dst=%s teid=%u\n",
           prefix,
           entry->far_id,
           inet_ntop(AF_INET, &entry->outer_ip, ipbuf, sizeof(ipbuf)) ? ipbuf : "invalid",
           entry->teid);
}

static void print_effective_far(const char *label, const UpfFAR *far, bool copied) {
    char ipbuf[INET_ADDRSTRLEN];

    if (!far) {
        printf("%s(null)\n", label);
        return;
    }

    printf("%sfar_id=%u outer_dst=%s teid=%u copied=%s\n",
           label,
           far->farId,
           inet_ntop(AF_INET, &far->forwardingParameters.outerHeaderCreation.ipv4,
                     ipbuf, sizeof(ipbuf)) ? ipbuf : "invalid",
           far->forwardingParameters.outerHeaderCreation.teid,
           copied ? "yes" : "no");
}

int main(void) {
    UpfSession session;
    UpfFAR master_far;
    UpfFAR secondary_far;
    UpfFAR invalid_far;
    UpfFAR selected_far_copy;
    UpfFAR *effective_far;
    const UpfDlPathEntry *entry;

    memset(&session, 0, sizeof(session));
    session.index = 42;

    UTLT_SetLogLevel("info");
    UTLT_SetReportCaller(0);

    fill_dl_far(&master_far, 1001, "10.0.1.2", 1111);
    fill_dl_far(&secondary_far, 1002, "10.0.1.3", 2222);
    fill_dl_far(&invalid_far, 2001, "10.0.9.9", 9999);
    invalid_far.forwardingParameters.destinationInterface = UPDK_INTERFACE_VALUE_CORE;

    printf("SELFTEST: session=%d begin\n", session.index);
    printf("SELFTEST: master FAR candidate=%s\n",
           UpfFarIsDlAccessCandidate(&master_far) ? "yes" : "no");
    printf("SELFTEST: secondary FAR candidate=%s\n",
           UpfFarIsDlAccessCandidate(&secondary_far) ? "yes" : "no");
    printf("SELFTEST: invalid CORE FAR candidate=%s\n",
           UpfFarIsDlAccessCandidate(&invalid_far) ? "yes" : "no");

    if (UpfSessionUpsertDlPathFromFar(&session, &master_far) != STATUS_OK) {
        fprintf(stderr, "failed to upsert master FAR\n");
        return 1;
    }
    if (UpfSessionUpsertDlPathFromFar(&session, &secondary_far) != STATUS_OK) {
        fprintf(stderr, "failed to upsert secondary FAR\n");
        return 1;
    }
    if (session.dl_paths.count != 2) {
        fprintf(stderr, "unexpected dl_paths.count after inserts: %u\n", session.dl_paths.count);
        return 1;
    }

    printf("SELFTEST: after insert count=%u\n", session.dl_paths.count);
    for (uint8_t i = 0; i < session.dl_paths.count; i++) {
        char prefix[64];
        snprintf(prefix, sizeof(prefix), "SELFTEST: slot[%u] ", i);
        print_path_entry(prefix, &session.dl_paths.entries[i]);
    }

    entry = UpfSessionGetDlPathByHash(&session, 0u);
    print_path_entry("SELFTEST: hash=0 resolves to ", entry);
    if (!entry || entry->far_id != 1001 || entry->teid != 1111) {
        fprintf(stderr, "hash=0 did not resolve to master FAR\n");
        return 1;
    }

    memset(&selected_far_copy, 0, sizeof(selected_far_copy));
    effective_far = UpfSessionSelectDlFarByHash(&session, &master_far, 0u, &selected_far_copy);
    print_effective_far("SELFTEST: hash=0 effective ", effective_far,
                        effective_far == &selected_far_copy);
    if (effective_far != &master_far) {
        fprintf(stderr, "hash=0 should keep base FAR without copy\n");
        return 1;
    }

    effective_far = UpfSessionSelectDlFarByHash(&session, &master_far, 1u, &selected_far_copy);
    if (!effective_far) {
        fprintf(stderr, "failed to select effective FAR\n");
        return 1;
    }
    print_effective_far("SELFTEST: hash=1 effective ", effective_far,
                        effective_far == &selected_far_copy);
    if (effective_far != &selected_far_copy) {
        fprintf(stderr, "hash=1 should use far_copy override\n");
        return 1;
    }
    if (effective_far->forwardingParameters.outerHeaderCreation.teid != 2222) {
        fprintf(stderr, "unexpected selected TEID: %u\n",
                effective_far->forwardingParameters.outerHeaderCreation.teid);
        return 1;
    }
    if (effective_far->forwardingParameters.outerHeaderCreation.ipv4.s_addr !=
        secondary_far.forwardingParameters.outerHeaderCreation.ipv4.s_addr) {
        fprintf(stderr, "unexpected selected outer IP for secondary path\n");
        return 1;
    }

    entry = UpfSessionGetDlPathByHash(&session, 2u);
    print_path_entry("SELFTEST: hash=2 resolves to ", entry);
    if (!entry || entry->far_id != 1001) {
        fprintf(stderr, "hash=2 should wrap to slot 0 for 2-way ECMP\n");
        return 1;
    }

    if (UpfSessionUpsertDlPathFromFar(&session, &invalid_far) != STATUS_OK) {
        fprintf(stderr, "invalid FAR upsert should gracefully keep cache consistent\n");
        return 1;
    }
    printf("SELFTEST: after invalid CORE FAR count=%u\n", session.dl_paths.count);
    if (session.dl_paths.count != 2) {
        fprintf(stderr, "invalid FAR should not expand dl_paths\n");
        return 1;
    }

    if (UpfSessionRemoveDlPathByFarID(&session, secondary_far.farId) != STATUS_OK) {
        fprintf(stderr, "failed to remove secondary FAR\n");
        return 1;
    }
    printf("SELFTEST: after remove count=%u\n", session.dl_paths.count);
    if (session.dl_paths.count != 1) {
        fprintf(stderr, "unexpected dl_paths.count after remove: %u\n", session.dl_paths.count);
        return 1;
    }

    memset(&selected_far_copy, 0, sizeof(selected_far_copy));
    effective_far = UpfSessionSelectDlFarByHash(&session, &master_far, 1u, &selected_far_copy);
    print_effective_far("SELFTEST: post-remove effective ", effective_far,
                        effective_far == &selected_far_copy);
    if (effective_far != &master_far) {
        fprintf(stderr, "single-path fallback should return base FAR\n");
        return 1;
    }

    printf("SELFTEST: PASS\n");

    return 0;
}
