# DOCA-Accelerated UPF — Design & Implementation Guide

**Platform:** NVIDIA BlueField-3 DPU  
**SDK:** DOCA SDK v3.2.1 LTS (DOCA Flow `vnf,hws` mode)  
**Copyright:** 2025–2026 University of California, Riverside  
**License:** Apache-2.0  
**Branch:** `feature/doca-upf-offload`

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Design Principles](#2-design-principles)
3. [Source File Map](#3-source-file-map)
4. [Data Structures & Types](#4-data-structures--types)
5. [Initialization Sequence](#5-initialization-sequence)
6. [Configuration Files](#6-configuration-files)
7. [JSON Loader — "Mock SMF"](#7-json-loader--mock-smf)
8. [DOCA Flow Pipe Hierarchy](#8-doca-flow-pipe-hierarchy)
9. [HW Rule Installation](#9-hw-rule-installation)
10. [Shared Resources (Counters & Meters)](#10-shared-resources-counters--meters)
11. [SW Miss-Path](#11-sw-miss-path)
12. [Packet Flow — End to End](#12-packet-flow--end-to-end)
13. [QoS Enforcement](#13-qos-enforcement)
14. [Metadata Encoding](#14-metadata-encoding)
15. [MAC Address Strategy](#15-mac-address-strategy)
16. [Statistics & Monitoring](#16-statistics--monitoring)
17. [Build System](#17-build-system)
18. [CLI Usage](#18-cli-usage)
19. [Key Design Decisions & Rationale](#19-key-design-decisions--rationale)
20. [Dependencies](#20-dependencies)
21. [Glossary](#21-glossary)

---

## 1. Architecture Overview

The DOCA UPF is a **single-process** User Plane Function that merges the
UPF-C (control/session layer) and UPF-U (data plane) into one standalone
executable running on a BlueField-3 DPU. It does **not** depend on the
ONVM manager.

```
┌─────────────────────────────────────────────────────────┐
│                     DOCA UPF Process                    │
│                                                         │
│  ┌─────────────┐  ┌────────────────────────────────┐    │
│  │  JSON Loader │  │    UPDK Structs (HUGEPAGE)     │    │
│  │ ("Mock SMF") │→ │  UPDK_PDR[]  UPDK_FAR[]       │    │
│  │              │  │  UPDK_QER[]  UpfSession[]      │    │
│  └─────────────┘  └───────┬────────────────────────┘    │
│                           │                             │
│              ┌────────────┼────────────┐                │
│              ▼                         ▼                │
│  ┌──────────────────┐    ┌──────────────────────┐       │
│  │  DOCA Flow HW    │    │  PartitionSort +     │       │
│  │  Pipe Hierarchy  │    │  Hash Bypass         │       │
│  │  (fast path)     │    │  (SW classifier)     │       │
│  └────────┬─────────┘    └──────────┬───────────┘       │
│           │                         │                   │
│           │  matched packets        │  miss packets     │
│           │  never touch CPU        │  via RSS queues   │
│           │                         │                   │
│           ▼                         ▼                   │
│  ┌──────────────────┐    ┌──────────────────────┐       │
│  │  HW Encap/Decap  │    │  SW Miss-Path        │       │
│  │  HW Metering     │    │  (mirrors upf_u.c)   │       │
│  │  HW Counters     │    │  trTCM + token bucket│       │
│  └──────────────────┘    └──────────────────────┘       │
│                                                         │
│  ┌──────────────────┐    ┌──────────────────────┐       │
│  │  Port 0 (Access) │    │  Port 1 (Core)       │       │
│  │  N3 / gNB side   │    │  N6 / DN side        │       │
│  └──────────────────┘    └──────────────────────┘       │
└─────────────────────────────────────────────────────────┘
```

**Two-path model:**

| Path | When | How |
|------|------|-----|
| **HW fast-path** | PDR matches a FORW FAR rule installed in DOCA Flow | Packet classified, encap'd/decap'd, metered, counted entirely in HW — CPU never sees it |
| **SW miss-path** | No HW rule match (miss), or DROP/BUFF FAR | Packet steered via RSS to CPU queues 1..N−1; classified by PartitionSort + hash bypass; processed identically to `upf_u.c` |

---

## 2. Design Principles

| Principle | Detail |
|-----------|--------|
| **Reuse UPDK structs** | `UPDK_PDR`, `UPDK_FAR`, `UPDK_QER` from `onvm/updk/` — no custom rule types |
| **Reuse UpfSession** | `UpfSession` from `upf_context.h` — sessions, maps, pools |
| **Reuse PartitionSort** | `5gc/classifiers/` — same classifier used in `upf_u.c` + hash bypass from `pdr_hash_bypass.h` |
| **Reuse `parse_gtpu_once()`** | `gtp.h` parser for GTP-U header extraction |
| **Single process** | No shared memory, no seqlock, no ONVM messaging |
| **No FAR pipe** | FAR decision made at install time — only FORW PDRs go to HW |
| **No TTL decrement** | UPF is a tunnel endpoint, not an IP router |
| **JSON = "mock SMF"** | JSON loader produces identical data structures to PFCP path |
| **Mirror `upf_u.c`** | SW miss-path replicates `upf_u.c` packet handler line-by-line |

---

## 3. Source File Map

```
5gc/upf_doca/
├── upf_doca.h              # Main header: all types, enums, context struct, prototypes
├── upf_doca.c              # Entry point: main(), init sequence, worker loop, stats
├── upf_doca_json.c         # "Mock SMF": JSON/YAML → UPDK structs → sessions → classifier
├── upf_doca_pipeline.c     # DOCA Flow pipe creation + HW rule installation
├── upf_doca_sw_path.c      # SW miss-path (mirrors upf_u.c exactly)
├── meson.build             # Build configuration
├── config/
│   ├── sample_smf_rules.json   # Example PDR/FAR/QER rules
│   └── upf_doca.yaml           # Dataplane config (MACs, IPs, ports)
└── DOCA_UPF_DESIGN.md      # This document
```

### File Sizes & Responsibilities

| File | ~Lines | Purpose |
|------|--------|---------|
| `upf_doca.h` | 316 | Central header — types, limits, enums, entry callback status, `upf_doca_ctx_t`, function prototypes |
| `upf_doca.c` | 579 | `main()`, 15-step init, `port_init()`, `doca_flow_init_ports()` (correct DOCA API sequence), entry callback, `worker_loop()`, `upf_doca_print_stats()` |
| `upf_doca_json.c` | 770 | Parse JSON → UPDK PDR/FAR/QER, resolve cross-refs, create sessions, build classifier, parse YAML config |
| `upf_doca_pipeline.c` | 907 | All 13 DOCA Flow pipes (with l3/l4 type match fields), shared counter/meter init, HW rule installation with batch validation |
| `upf_doca_sw_path.c` | 712 | SW miss-path: classify, decap, encap, FAR action, L2 headers, trTCM + token bucket QoS |
| `meson.build` | 92 | Dependencies, includes, executable definition |

---

## 4. Data Structures & Types

### 4.1 Limits & Constants

```c
#define UPF_DOCA_MAX_PDR           512    // Max PDR rules (UL + DL)
#define UPF_DOCA_MAX_FAR           512    // Max FAR rules
#define UPF_DOCA_MAX_QER           256    // Max QER rules
#define UPF_DOCA_MAX_SESSION       256    // Max sessions (1 per UE)
#define UPF_DOCA_MAX_UE            256    // Max UE entries for AMBR policing
#define UPF_DOCA_NUM_PORTS         2      // Access + Core
#define UPF_DOCA_MAX_QUEUES        16     // Max RSS queues
#define UPF_DOCA_SW_BURST          32     // SW miss-path RX burst size
#define UPF_DOCA_GTP_PORT          2152   // GTP-U UDP port
#define UPF_DOCA_PSC_EXT_TYPE      0x85   // PDU Session Container extension type
#define UPF_DOCA_ENCAP_TTL         64     // Outer IP TTL for GTP encap
```

### 4.2 Pipe Type Enum

```c
enum upf_doca_pipe_type {
    /* RX Ingress domain */
    UPF_DOCA_PIPE_RX_ROOT,        // Root pipe → ULDL
    UPF_DOCA_PIPE_ULDL,           // Match UDP:2152 → UL; miss → DL
    UPF_DOCA_PIPE_8T_IPV4,        // UL: 8-tuple (TEID+QFI+inner 5-tuple)
    UPF_DOCA_PIPE_5T_IPV4,        // DL: 5-tuple (UE-IP + SDF)
    UPF_DOCA_PIPE_DECAP,          // UL: strip GTP-U, inject new ETH
    UPF_DOCA_PIPE_UL_TO_SW,       // RSS miss → CPU (uplink)
    UPF_DOCA_PIPE_DL_TO_SW,       // RSS miss → CPU (downlink)
    UPF_DOCA_PIPE_RX_DROP,        // Debug drop counter

    /* TX Egress domain */
    UPF_DOCA_PIPE_TX_ROOT,        // Egress root → metering chain
    UPF_DOCA_PIPE_SHARED_METER,   // Per-PDR QER MBR metering
    UPF_DOCA_PIPE_COLOR_MATCH,    // GREEN → continue; RED → drop
    UPF_DOCA_PIPE_ENCAP_COUNTER,  // GTP encap + per-PDR shared counter
    UPF_DOCA_PIPE_TX_DROP,        // Rate-limit drop counter
    UPF_DOCA_PIPE_NUM             // Total: 13 pipes
};
```

### 4.3 Encap Action Selector

```c
enum upf_doca_encap_action {
    UPF_DOCA_ENCAP_IPV4_4G = 0,   // GTP-U, no PSC (4G/non-QFI)
    UPF_DOCA_ENCAP_IPV4_5G,       // GTP-U + PSC with QFI (5G)
    UPF_DOCA_ENCAP_NONE,          // UL direction: no encap needed
    UPF_DOCA_ENCAP_NUM            // 3 action templates
};
```

### 4.4 Main Application Context (`upf_doca_ctx_t`)

The central context struct holds **all** state:

```
upf_doca_ctx_t
├── Configuration
│   ├── self_ip              (UPF N3 IP, network byte order)
│   ├── dn_mac[6]            (DN next-hop MAC, raw bytes from YAML)
│   ├── an_mac[6]            (gNB next-hop MAC, raw bytes from YAML)
│   ├── cn_ue_eth            (UPF access port own MAC — from rte_eth_macaddr_get)
│   ├── cn_dn_eth            (UPF core port own MAC — from rte_eth_macaddr_get)
│   ├── an_eth_addr          (gNB MAC as rte_ether_addr — copied from an_mac)
│   ├── dn_eth_addr          (DN MAC as rte_ether_addr — copied from dn_mac)
│   ├── access_port / core_port
│   └── num_queues, smf_json_path, yaml_config_path
│
├── UPDK Rules (hugepage-allocated via rte_calloc)
│   ├── pdrs[512]            (UPDK_PDR pointers, index = HW metadata value)
│   ├── fars[512]            (UPDK_FAR pointers)
│   ├── qers[256]            (UPDK_QER pointers)
│   └── num_pdrs, num_fars, num_qers
│
├── Sessions
│   ├── sessions[256]        (UpfSession pointers from upf_context.h)
│   └── num_sessions
│
├── Classifier (single-process — direct pointers, no seqlock)
│   ├── cls_active           (PartitionSort handle)
│   └── hash_active          (Hash bypass table)
│
├── DOCA Flow Handles
│   ├── ports[2]             (DOCA Flow port handles)
│   ├── pipes[2][13]         (Pipe handles per port per pipe_type)
│   ├── hw_entries[512]      (Per-PDR: rx_entry, encap_entry[2], meter_entry[2])
│   ├── shared_counter_ids[2][512]
│   ├── shared_meter_ids[2][512]
│   ├── num_static_entries[2]
│   └── entries_status        (upf_doca_entries_status: batch entry validation state)
│
├── SW Miss-Path State
│   ├── ue_table[256]        (Per-UE AMBR token buckets)
│   ├── ue_hash[256]         (UE-IP → ue_table index hash)
│   ├── sw_meters[]          (Per-flow trTCM meters)
│   ├── flow_table[]         (SDF→meter_idx mapping)
│   └── pdr_stats[512]       (Per-PDR SW stats)
│
└── Runtime
    └── force_quit, num_queues
```

### 4.5 Per-PDR HW Entry Tracking

```c
typedef struct {
    struct doca_flow_pipe_entry *rx_entry;       // 8T or 5T pipe entry
    struct doca_flow_pipe_entry *encap_entry[2]; // Encap entry per port
    struct doca_flow_pipe_entry *meter_entry[2]; // Meter entry per port
    bool installed;                               // true if FORW PDR in HW
} upf_doca_hw_entry_t;
```

### 4.6 Entry Callback Status (`upf_doca_entries_status`)

Used by the asynchronous entry-addition callback (`check_for_valid_entry`)
to track whether any HW entry installation failed during batched flush:

```c
typedef struct upf_doca_entries_status {
    bool failure;       // Set to true if any entry callback reports error
    int nb_processed;   // Number of entries processed by callbacks so far
} upf_doca_entries_status;
```

Lives in `ctx->entries_status`. Reset before each batch flush, then
checked after `doca_flow_entries_process()` returns to validate that
(a) no entry failed and (b) all expected entries were processed.
This pattern mirrors NVIDIA's `flow_common.c` reference implementation.

---

## 5. Initialization Sequence

`main()` in `upf_doca.c` runs a strict 15-step init:

```
Step  Function / Action                      File
─────────────────────────────────────────────────────────────
 1.   rte_eal_init()                         upf_doca.c
 2.   parse_args() → -j, -y, -q             upf_doca.c
 3.   signal(SIGINT/SIGTERM)                 upf_doca.c
 4.   upf_doca_yaml_load()                   upf_doca_json.c
        → dn_mac, an_mac, upf_ip (NBO), ports
 5.   upf_doca_json_load()                   upf_doca_json.c
        → Parse PDR/FAR/QER → rte_calloc UPDK structs
        → resolve_cross_refs (pdr→far, pdr→qer, pdr→qers[])
        → UpfSessionPoolInit, UeIpToUpfSessionMapInit, ...
        → create_sessions (UpfSession per UE)
        → build_classifier (PartitionSort + hash bypass)
 6.   rte_pktmbuf_pool_create()              upf_doca.c
 7.   port_init() × 2 ports                 upf_doca.c
        → RSS config, num_queues RX/TX queues each
      get_port_macs()
        → rte_eth_macaddr_get → cn_ue_eth, cn_dn_eth
        → Copy an_mac/dn_mac → an_eth_addr, dn_eth_addr
 8.   doca_flow_init_ports()                 upf_doca.c
        → DOCA Flow global init:
            set_pipe_queues(num_queues)
            set_mode_args("vnf,hws")
            set_resource_mode(DOCA_FLOW_RESOURCE_MODE_PORT)
            set_cb_entry_process(check_for_valid_entry)
            set_queue_depth(128)
            doca_flow_init()
        → Per-port (access + core):
            doca_dpdk_port_as_dev(port_id) → doca_dev handle
            set_port_id(port_id)
            set_dev(doca_dev)
            set_actions_mem_size(2048)
            set_nr_resources(COUNTER, MAX_PDR * 2)
            set_nr_resources(METER, MAX_PDR * 2)
            doca_flow_port_start()
        → doca_flow_port_pair(port0, port1)
 9.   upf_doca_pipeline_create()             upf_doca_pipeline.c
        → Create all 13 pipes per port (bottom-up)
10.   upf_doca_shared_counters_init()        upf_doca_pipeline.c
        → Allocate per-PDR shared counters on each port
11.   upf_doca_shared_meters_init()          upf_doca_pipeline.c
        → Allocate + configure per-PDR shared meters (MBR from QER)
12.   upf_doca_rules_install()               upf_doca_pipeline.c
        → Install FORW PDRs into 8T/5T + ENCAP_COUNTER + SHARED_METER
        → All entries added with DOCA_FLOW_WAIT_FOR_BATCH flag
        → Flush via doca_flow_entries_process() per port
        → Post-flush validation: check entries_status.failure == false
          and entries_status.nb_processed == total expected entries
        → Entry callback (check_for_valid_entry) logs failures
13.   upf_doca_sw_init()                     upf_doca_sw_path.c
        → Init flow tables, trTCM profiles, UE table
14.   rte_eal_remote_launch(worker_loop)     upf_doca.c
      + main core worker_loop()
        → sw_poll() + periodic stats
15.   Cleanup on SIGINT/SIGTERM              upf_doca.c
        → Print final stats
        → doca_flow_port_stop, doca_flow_destroy
        → rte_eth_dev_stop/close
        → rte_free(PDR/FAR/QER), cls_destroy, phb_destroy
        → rte_eal_cleanup
```

---

## 6. Configuration Files

### 6.1 YAML Config (`upf_doca.yaml`)

Dataplane settings parsed by `upf_doca_yaml_load()`:

```yaml
info:
  version: 1.0.0
  description: DOCA-Accelerated UPF dataplane configuration (BF3 DPU)

configuration:
  dataplane:
    dn_mac: "3c:fd:fe:b4:fe:21"    # DN next-hop MAC (core side)
    an_mac: "3c:fd:fe:b5:00:14"    # gNB next-hop MAC (access side)
    upf_ip: "192.168.1.2"          # UPF N3 interface IP

    ports:
      access: 0                     # DPDK port for N3 (UL ingress)
      core: 1                       # DPDK port for N6 (DL ingress)
```

**Key details:**
- `upf_ip` is converted to network byte order via `inet_pton()` and stored as
  `ctx->self_ip`. This is compared directly against `iph->dst_addr` (also NBO).
- `dn_mac`/`an_mac` are next-hop MACs (not this host's MACs). They are parsed
  from colon-separated hex strings into raw 6-byte arrays.
- `access`/`core` port indices must match EAL device order.

### 6.2 JSON Rules (`sample_smf_rules.json`)

PDR/FAR/QER rules parsed by `upf_doca_json_load()`. This file is the
**"mock SMF"** — it produces the same data structures that a real SMF would
produce via PFCP:

```json
{
    "createPdr": [
        {
            "pdrId": 1,
            "precedence": 100,
            "pdi": {
                "sourceInterface": { "type": 0 },
                "localFT": { "teidStart": 1, "ip": "192.168.1.2" },
                "qfi": 9,
                "userEquipment": { "ip": "10.60.0.1" },
                "sdf": [
                    { "description": "permit out ip from 10.60.0.1/32 to any" }
                ]
            },
            "outerHeaderRemoval": 0,
            "farId": 1,
            "qerIds": [1]
        },
        {
            "pdrId": 2,
            "precedence": 100,
            "pdi": {
                "sourceInterface": { "type": 1 },
                "userEquipment": { "ip": "10.60.0.1" },
                "sdf": [
                    { "description": "permit out ip from any to 10.60.0.1/32" }
                ]
            },
            "farId": 2,
            "qerIds": [1]
        }
    ],
    "createFar": [
        {
            "farId": 1,
            "applyAction": 2,
            "fp": {}
        },
        {
            "farId": 2,
            "applyAction": 2,
            "fp": {
                "outerHeader": { "teid": 1, "ip": "192.168.1.1" }
            }
        }
    ],
    "createQer": [
        {
            "qerId": 1,
            "qfi": 9,
            "maxBitRate": { "dlMBR": "1000000", "ulMBR": "1000000" },
            "guaranteedBitRate": { "dlGBR": "500000", "ulGBR": "500000" }
        }
    ]
}
```

**JSON Fields → UPDK Mapping:**

| JSON field | UPDK field | Notes |
|------------|-----------|-------|
| `sourceInterface.type` | `pdr->pdi.sourceInterface` | 0=ACCESS, 1=CORE |
| `localFT.teidStart` | `pdr->pdi.fTeid.teid` | GTP TEID |
| `localFT.ip` | `pdr->pdi.fTeid.ipv4` | F-TEID IP |
| `qfi` | `pdr->pdi.qfi` | QoS Flow Identifier |
| `userEquipment.ip` | `pdr->pdi.ueIpAddress.ipv4` | UE IP address |
| `sdf[].description` | `pdr->pdi.sdfFilter.flowDescription` | SDF filter string |
| `outerHeaderRemoval` | `pdr->outerHeaderRemoval` | 0=GTP_IP4 |
| `farId` | `pdr->farId` → resolved to `pdr->far` ptr | Cross-reference |
| `qerIds[]` | `pdr->qerId[]` → resolved to `pdr->qer`, `pdr->qers[]` | Cross-reference |
| `applyAction` | `far->applyAction` | 2=FORW bitmask |
| `fp.outerHeader.teid` | `far->forwardingParameters.outerHeaderCreation.teid` | DL encap TEID |
| `fp.outerHeader.ip` | `far->forwardingParameters.outerHeaderCreation.ipv4` | DL encap dst IP |
| `maxBitRate.dlMBR` | `qer->maximumBitrate.dl` | kbps |
| `guaranteedBitRate.dlGBR` | `qer->guaranteedBitrate.dl` | kbps |

---

## 7. JSON Loader — "Mock SMF"

**File:** `upf_doca_json.c`

The JSON loader is the **most important initialization file**. It replaces
the PFCP session-establishment path and produces identical data structures:

### 7.1 Parse Sequence (`upf_doca_json_load`)

```
upf_doca_json_load(ctx, json_path)
│
├── 1. Parse QERs:  for each "createQer" entry
│      → parse_one_qer() → rte_calloc("updk_qer") → UPDK_QER
│      → ctx->qers[i] = qer;  ctx->num_qers++
│
├── 2. Parse FARs:  for each "createFar" entry
│      → parse_one_far() → rte_calloc("updk_far") → UPDK_FAR
│      → ctx->fars[i] = far;  ctx->num_fars++
│
├── 3. Parse PDRs:  for each "createPdr" entry
│      → parse_one_pdr() → rte_calloc("updk_pdr") → UPDK_PDR
│      → parse_sdf_to_updk() → precompute has_fd, fd_target, meter_key
│      → ctx->pdrs[i] = pdr;  ctx->num_pdrs++
│
├── 4. Resolve cross-references:  resolve_cross_refs(ctx)
│      → For each PDR: find matching FAR by farId → pdr->far = far
│      → For each PDR: find QFI-bearing QER → pdr->qer = qer
│      → For each PDR: build pdr->qers[] array (all associated QERs)
│
├── 5. Init session pools/maps:
│      → UpfSessionPoolInit()
│      → UeIpToUpfSessionMapInit()
│      → TeidToUpfSessionMapInit()
│      → UpfPDRGlobalInit()
│
├── 6. Create sessions:  create_sessions(ctx)
│      → Group PDRs by UE-IP
│      → For each unique UE: UpfSessionAlloc(mock_seid++)
│      → Register PDR/FAR/QER to session
│      → UpfPDRGlobalAdd, InsertUEIPtoSessionMap, InsertTEIDtoSessionMap
│
└── 7. Build classifier:  build_classifier(ctx)
       → cls_create(CLS_BACKEND_PS) → PartitionSort classifier
       → phb_create() → hash bypass table
       → For each PDR: updk_pdr_to_cls_rule(&key)
         → cls_insert_rule(cls, key, precedence, descriptor=(uintptr_t)pdr)
         → phb_add_pdr(hash, pdr)
       → ctx->cls_active = cls
       → ctx->hash_active = hash
```

### 7.2 Key Functions

| Function | Purpose |
|----------|---------|
| `parse_one_pdr(json_obj)` | Allocates UPDK_PDR via `rte_calloc`, populates pdrId, precedence, farId, outerHeaderRemoval, qerIds, PDI fields (sourceInterface, fTeid, qfi, ueIpAddress, sdfFilter). Sets corresponding `flags.*` bits. |
| `parse_one_far(json_obj)` | Allocates UPDK_FAR, populates farId, applyAction, forwardingParameters.outerHeaderCreation (teid, ipv4, description=GTPU_UDP_IPV4). |
| `parse_one_qer(json_obj)` | Allocates UPDK_QER, populates qerId, qosFlowIdentifier, maximumBitrate (ul/dl), guaranteedBitrate (ul/dl). |
| `parse_sdf_to_updk(pdr, sdf_str)` | Parses SDF flow description string → `UPDK_SDFFilter` fields. Precomputes `pdr->has_fd`, `pdr->fd_target` (IP from SDF), `pdr->meter_key` (CRC32 hash of fd_target + port). Mirrors `UpfPdrPrecompileSdf()` from UPF-C. |
| `resolve_cross_refs(ctx)` | Links `pdr->far` pointer by matching farId. Sets `pdr->qer` to the QFI-bearing QER. Builds `pdr->qers[]` array with count for AMBR policing. |
| `create_sessions(ctx)` | Groups PDRs by UE-IP, allocates `UpfSession` per UE via `UpfSessionAlloc(mock_seid)`, registers rules to sessions, populates UE-IP → session and TEID → session maps. |
| `build_classifier(ctx)` | Creates PartitionSort classifier + hash bypass table. For each PDR: converts to `ps_packet_t` key, inserts into classifier with `descriptor = (uintptr_t)pdr`. |
| `upf_doca_yaml_load(ctx, path)` | Parses YAML config: `dn_mac`, `an_mac` (colon-hex → raw bytes), `upf_ip` (string → NBO via `inet_pton`), `access`/`core` port indices. |

### 7.3 SDF Precomputation

`parse_sdf_to_updk()` deserves special attention. It mirrors
`UpfPdrPrecompileSdf()` from `upf_context.c`:

```
Input:  "permit out ip from 10.60.0.1/32 to any"
Output:
  pdr->pdi.sdfFilter.flowDescription = "permit out ip from 10.60.0.1/32 to any"
  pdr->pdi.sdfFilter.flags.fd = 1
  pdr->has_fd = true
  pdr->fd_target = 0x0A3C0001  (10.60.0.1 in host byte order)
  pdr->meter_key = CRC32(fd_target + port_combo)
```

The `meter_key` is used by both HW metering and SW trTCM flow lookup
as the per-SDF-flow discriminator.

---

## 8. DOCA Flow Pipe Hierarchy

### 8.1 Complete Pipe Diagram

```
                        ┌──────────────────────────────────────────┐
                        │              RX INGRESS DOMAIN           │
                        │                                          │
                        │   RX_ROOT (root=true, catch-all)         │
                        │     │                                    │
                        │     ▼                                    │
                        │   ULDL (match: UDP dst_port == 2152)     │
                        │     │ hit                  │ miss        │
                        │     ▼                      ▼             │
                        │   8T_IPV4 (UL)           5T_IPV4 (DL)   │
                        │   ┌────────────┐         ┌──────────┐   │
                        │   │match:      │         │match:     │   │
                        │   │ TEID       │         │ dst_ip    │   │
                        │   │ QFI        │         │ src_ip    │   │
                        │   │ inner 5T   │         │ proto     │   │
                        │   │ (src/dst   │         │ src_port  │   │
                        │   │  IP, proto,│         │ dst_port  │   │
                        │   │  ports)    │         │           │   │
                        │   └─┬──────┬───┘         └─┬──────┬──┘   │
                        │     │hit   │miss           │hit   │miss  │
                        │     ▼      ▼               ▼      ▼      │
                        │   DECAP  UL_TO_SW     port_fwd DL_TO_SW  │
                        │     │    (RSS 1..N)  (access) (RSS 1..N) │
                        │     ▼                                    │
                        │   port_fwd(core)                         │
                        │                                          │
                        │   RX_DROP (miss fallback)                │
                        └──────────────────────────────────────────┘


                        ┌──────────────────────────────────────────┐
                        │              TX EGRESS DOMAIN             │
                        │                                          │
                        │   TX_ROOT (root=true, catch-all)         │
                        │     │                                    │
                        │     ▼                                    │
                        │   SHARED_METER                           │
                        │   (match: meta.pdr_idx, apply meter)     │
                        │     │                                    │
                        │     ▼                                    │
                        │   COLOR_MATCH                            │
                        │   (match: meter_color == GREEN)          │
                        │     │ GREEN              │ miss (RED)    │
                        │     ▼                    ▼               │
                        │   ENCAP_COUNTER        TX_DROP           │
                        │   (match: meta.pdr_idx)                  │
                        │   (action: encap + shared counter)       │
                        │     │                                    │
                        │     ▼                                    │
                        │   port_fwd (out)                         │
                        └──────────────────────────────────────────┘
```

### 8.2 Pipe Details

#### RX_ROOT
- **Root:** yes
- **Domain:** DEFAULT (ingress)
- **Match:** catch-all (empty)
- **Fwd:** → ULDL pipe
- **Miss:** → RX_DROP
- **Static entry:** 1 (immediate forward)

#### ULDL
- **Root:** no
- **Match:** `outer.l4_type_ext = UDP`, `outer.udp.dst_port = 2152`
- **Fwd (hit):** → 8T_IPV4 (uplink GTP-U packet)
- **Miss:** → 5T_IPV4 (downlink non-GTP packet)
- **Static entry:** 1 (match UDP:2152)

#### 8T_IPV4 (UL match)
- **Match fields:** `outer.l3_type = IP4` + `outer.ip4.src_ip` + `tun.gtp_teid` + `tun.gtp_ext_psc_qfi` + `inner.l3_type = IP4` + `inner.l4_type_ext = UDP` + `inner.ip4.src_ip` + `inner.ip4.dst_ip` + `inner.ip4.next_proto` + `inner.udp.src_port` + `inner.udp.dst_port`
- **Note:** `outer.l3_type`, `inner.l3_type`, and `inner.l4_type_ext` are required by DOCA Flow HWS to enable correct parser anchoring for GTP-U tunneled packets.
- **Action:** Set `meta.pkt_meta = pdr_index | META_DIR_UL`
- **Fwd (hit):** → DECAP pipe
- **Miss:** → UL_TO_SW (RSS to CPU)
- **Max entries:** 512

#### 5T_IPV4 (DL match)
- **Match fields:** `outer.l3_type = IP4` + `outer.l4_type_ext = UDP` + `outer.ip4.dst_ip` + `outer.ip4.src_ip` + `outer.ip4.next_proto` + `outer.udp.src_port` + `outer.udp.dst_port`
- **Note:** `outer.l3_type` and `outer.l4_type_ext` are required by DOCA Flow HWS for correct L3/L4 header parsing in hardware.
- **Action:** Set `meta.pkt_meta = pdr_index | META_DIR_DL`
- **Fwd (hit):** → `port_fwd(port_id ^ 1)` (direct to access port — encap on TX)
- **Miss:** → DL_TO_SW (RSS to CPU)
- **Max entries:** 512

#### DECAP
- **Match:** `parser_meta.inner_l3_type` (IPv4 or IPv6)
- **Action:** `decap_type = NON_SHARED`, strip GTP-U tunnel, inject new ETH:
  - `src_mac` = `cn_dn_eth` (UPF core port own MAC)
  - `dst_mac` = `dn_mac` (DN next-hop MAC)
  - `eth.type` = IPv4 or IPv6 based on inner L3
- **Fwd:** `port_fwd(port_id ^ 1)` → core port
- **Static entries:** 2 (one for IPv4 inner, one for IPv6 inner)

#### UL_TO_SW / DL_TO_SW
- **Match:** catch-all
- **Action:** Set `meta.pkt_meta = META_DIR_UL` or `META_DIR_DL`
- **Fwd:** RSS to queues `[1, 2, ..., N-1]` (queue 0 reserved for DOCA Flow)
- **RSS hash:**
  - UL: `inner_flags = RSS_IPV4_SRC` (hash on inner src IP)
  - DL: `outer_flags = RSS_IPV4_DST` (hash on outer dst IP = UE IP)
- **Static entry:** 1

#### ENCAP_COUNTER (TX egress)
- **Match:** `meta.pkt_meta` (masked by `META_PDR_MASK` = lower 16 bits)
- **Monitor:** Shared counter (per-PDR)
- **3 Action Templates:**
  - `IPV4_4G`: GTP-U encap, no PSC. `version_ihl=0x4500` (IPv4, 20-byte header), `src_mac=cn_ue_eth`, `dst_mac=an_mac`, `src_ip=self_ip`, `dst_ip=changeable`, `teid=changeable`
  - `IPV4_5G`: Same + PSC extension header with QFI (inherits `version_ihl` via struct copy)
  - `NONE`: No encap (UL direction — just count)
- **Note:** `version_ihl` in the encap template is essential — DOCA Flow uses it to identify the encapsulated packet as IPv4. Without it, the HW encap action may produce malformed outer IP headers.
- **Fwd:** `port_fwd(port_id)` — egress out the same port
- **Max entries:** 512

#### SHARED_METER (TX egress)
- **Match:** `meta.pkt_meta` (PDR index)
- **Monitor:** Shared meter (per-PDR, RFC 2697 single-rate)
- **Fwd:** → COLOR_MATCH pipe
- **Max entries:** 512

#### COLOR_MATCH (TX egress)
- **Match:** `parser_meta.meter_color == GREEN`
- **Fwd (GREEN):** → ENCAP_COUNTER pipe
- **Miss (RED/YELLOW):** → TX_DROP pipe
- **Static entry:** 1

### 8.3 Pipe Creation Order

Pipes are created **bottom-up** (leaf first) since `fwd_miss` and `fwd`
refer to already-created pipes:

```
Per port (access + core):
  RX domain:
    1. RX_DROP
    2. DECAP
    3. UL_TO_SW
    4. DL_TO_SW
    5. 8T_IPV4
    6. 5T_IPV4
    7. ULDL + static entry
    8. RX_ROOT + static entry

  TX domain:
    9.  TX_DROP
    10. ENCAP_COUNTER
    11. COLOR_MATCH + static entry
    12. SHARED_METER
    13. TX_ROOT + static entry
```

Function: `upf_doca_pipeline_create()` orchestrates all of the above.

---

## 9. HW Rule Installation

**Function:** `upf_doca_rules_install()` in `upf_doca_pipeline.c`

### 9.1 What Gets Installed

**Only FORW PDRs** are installed in HW. The logic:

```
for each PDR[i]:
    if (!pdr->far || !(far->applyAction & FORW)):
        skip  → falls to SW miss-path by design
    else:
        install in HW (both RX and TX pipes)
```

DROP, BUFF, and NOCP PDRs are **never** installed in HW. They are handled
entirely by the SW miss-path when their traffic arrives.

### 9.2 Per-PDR Installation

For each FORW PDR, three types of entries are installed:

```
1. RX Match Entry (1 entry on the RX port):
   ├── UL PDR → 8T_IPV4 pipe on access_port
   │     match: TEID + QFI + inner src_ip (from PDI fields)
   │     action: meta = i | META_DIR_UL
   └── DL PDR → 5T_IPV4 pipe on core_port
         match: outer dst_ip = UE IP (from PDI ueIpAddress)
         action: meta = i | META_DIR_DL

2. TX Encap+Counter Entries (2 entries — one per port):
   ├── UL: action_idx = ENCAP_NONE (just count)
   └── DL: action_idx = ENCAP_IPV4_4G or ENCAP_IPV4_5G
         encap params: teid = FAR.outerHeaderCreation.teid
                       dst_ip = FAR.outerHeaderCreation.ipv4
                       qfi = QER.qfi (if 5G)

3. TX Meter Entries (2 entries — one per port, if QER has MBR):
   └── match: meta = i
       monitor: shared_meter_id[port][i]
```

### 9.3 Batched Flush & Validation

All entries are added with `DOCA_FLOW_WAIT_FOR_BATCH` flag and a pointer
to `ctx->entries_status` as user context. After all entries for a port are
queued, they are flushed via `doca_flow_entries_process()`.

**Entry callback pattern** (mirrors NVIDIA `flow_common.c`):

```c
void check_for_valid_entry(struct doca_flow_pipe_entry *entry,
                           uint16_t pipe_queue,
                           enum doca_flow_entry_status status,
                           enum doca_flow_entry_op op,
                           void *user_ctx)
{
    upf_doca_entries_status *es = (upf_doca_entries_status *)user_ctx;
    if (entry == NULL || status != DOCA_FLOW_ENTRY_STATUS_SUCCESS)
        es->failure = true;
    es->nb_processed++;
}
```

**Post-flush validation:**

```
For each port:
  1. Reset ctx->entries_status = {false, 0}
  2. Add all entries with DOCA_FLOW_WAIT_FOR_BATCH + &ctx->entries_status
  3. doca_flow_entries_process(port, 0, timeout, num_static_entries[port])
  4. Check:
     - entries_status.failure == false  (no entry failed)
     - entries_status.nb_processed == total_expected  (all entries processed)
  5. If either check fails → UTLT_Error() + return -1
```

The `num_static_entries[]` counter **accumulates** across pipe creation
(static entries like RX_ROOT, ULDL, COLOR_MATCH, TX_ROOT) and rule
installation (dynamic PDR entries). It is **not** reset between phases,
ensuring the flush processes all pending entries.

---

## 10. Shared Resources (Counters & Meters)

### 10.1 Shared Counters

**Function:** `upf_doca_shared_counters_init()`

- Allocates one shared counter per PDR per port = `num_pdrs × 2` total.
- Used by the ENCAP_COUNTER pipe to count packets/bytes per PDR.
- Queried by `upf_doca_print_stats()` via `doca_flow_resource_query_entry()`
  (per-entry query — not the deprecated `doca_flow_resource_query`).

### 10.2 Shared Meters

**Function:** `upf_doca_shared_meters_init()`

- Allocates one shared meter per PDR per port.
- Meter algorithm: **RFC 2697** (single-rate three-color marker), color-blind.
- CIR/CBS derived from QER MBR:
  ```
  mbr_kbps = pdr->qer->maximumBitrate.{ul|dl}  (direction-dependent)
  cir = cbs = mbr_kbps × 1000 / 8   (convert kbps → bytes/sec)
  ```
- If no QER or no MBR: `cir = cbs = 1` (effectively unlimited).
- Used by the SHARED_METER pipe; packets colored RED are dropped by COLOR_MATCH.

---

## 11. SW Miss-Path

**File:** `upf_doca_sw_path.c`

The SW miss-path handles packets that didn't match any HW rule. It mirrors
the `upf_u.c` packet handler step-by-step.

### 11.1 When Packets Enter SW Path

- **UL miss:** UL_TO_SW pipe (8T_IPV4 miss) → RSS queues 1..N-1
- **DL miss:** DL_TO_SW pipe (5T_IPV4 miss) → RSS queues 1..N-1
- DROP/BUFF PDR traffic never has HW rules → always misses → SW path

### 11.2 Worker Loop

```c
upf_doca_sw_poll(ctx):
    for each port (0, 1):
        for each queue (1, 2, ..., num_queues-1):  // queue 0 = DOCA Flow reserved
            nb = rte_eth_rx_burst(port, queue, pkts, 32)
            for each pkt:
                sw_handle_one(ctx, pkt, port)
```

### 11.3 Per-Packet Handler (`sw_handle_one`)

```
sw_handle_one(ctx, pkt, rx_port):
│
├── Parse outer IP header
│
├── Direction detection:
│   ├── if iph->dst_addr == ctx->upf_ip → UPLINK
│   │     → parse_gtpu_once(pkt, &gtp_info)
│   │     → pdr = ClassifyUL(ctx, pkt, &gtp_info)
│   └── else → DOWNLINK
│         → pdr = ClassifyDL(ctx, pkt, iph->dst_addr)
│
├── if (!pdr) → DROP
│
├── DL: Populate UE table on first touch
│   → ue_idx = sw_ue_find(ue_ip)
│   → if miss: PopulateUeTable(ue_ip, pdr)
│
├── Strip Ethernet header (adj to L3)
│
├── Outer header removal (UL only):
│   └── if pdr->outerHeaderRemoval == GTP_IP4:
│       rte_pktmbuf_adj(pkt, gtp_info.outer_hdr_len)
│
├── FAR action:
│   → HandlePacketWithFar(pkt, ctx, far, qer, rx_port)
│   ├── FORW + outerHeaderCreation → Encap() (GTP-U encapsulation)
│   ├── FORW (no encap) → forward as-is
│   ├── DROP → free pkt
│   └── BUFF → drop (no CP path in standalone mode)
│
├── Attach L2 header:
│   → AttachL2Header(pkt, ctx, is_dl)
│   ├── DL: src=cn_ue_eth (access own MAC), dst=an_eth_addr (gNB)
│   └── UL: src=cn_dn_eth (core own MAC), dst=dn_eth_addr (DN)
│
├── DL QoS policing:
│   ├── Step 1: trTCM per-SDF flow
│   │   → ft_idx = sw_ft_search(pdr->meter_key)
│   │   → color = rte_meter_trtcm_color_blind_check()
│   │   → RED → DROP
│   │   → YELLOW → wait for qos_tb tokens (busy-wait)
│   │   → GREEN → continue
│   │
│   └── Step 2: Token bucket (non-QoS flows)
│       → wait for nqos_tb tokens (busy-wait)
│
└── TX:
    → rte_eth_tx_burst(tx_port=rx_port^1, queue=0, &pkt, 1)
```

### 11.4 Classifier Lookup Functions

#### `ClassifyUL(ctx, pkt, gtp_info)` — Uplink Classification

```
1. Parse inner IP header at offset: ETH + gtp_info->outer_hdr_len
2. Build ps_packet_t key:
     key.teid     = gtp_info->teid
     key.qfi      = gtp_info->qfi
     key.ue_ip    = inner4->src_addr (host order)
     key.src_ip   = same
     key.dst_ip   = inner4->dst_addr (host order)
     key.src_port = inner UDP src_port (host order)
     key.dst_port = inner UDP dst_port (host order)
     key.proto    = inner4->next_proto_id
     key.source_if = SRC_IF_ACCESS
     key.is_uplink = true

3. Try hash bypass: phb_classify_ul(hash_active, teid, &key)
   → O(1) lookup by TEID → returns UPDK_PDR* or NULL

4. Fallback to PartitionSort: cls_classify_packet(cls_active, &key, ...)
   → Multi-dimensional classification → returns descriptor = (uintptr_t)pdr
```

#### `ClassifyDL(ctx, pkt, ue_ip_be)` — Downlink Classification

```
1. Parse outer IP header
2. Build ps_packet_t key:
     key.src_ip   = outer4->src_addr (host order)
     key.dst_ip   = outer4->dst_addr (host order)
     key.proto    = outer4->next_proto_id
     key.ue_ip    = ue_ip_be → host order
     key.source_if = SRC_IF_CORE
     key.is_uplink = false
     + src_port/dst_port if UDP

3. Try hash bypass: phb_classify_dl(hash_active, ue_ip_host, &key)
   → O(1) lookup by UE IP → returns UPDK_PDR* or NULL

4. Fallback to PartitionSort: cls_classify_packet(cls_active, &key, ...)
```

### 11.5 GTP-U Encapsulation (`Encap`)

For DL FORW PDRs with `outerHeaderCreation.description == GTPU_UDP_IPV4`:

```
Before Encap:
  [Inner IP payload]

After Encap (no QFI / 4G):
  [IPv4 | UDP:2152 | GTPv1 | Inner IP payload]

After Encap (with QFI / 5G):
  [IPv4 | UDP:2152 | GTPv1+ExtHdr | PSC(QFI) | Inner IP payload]

Header values:
  outer.src_ip = ctx->upf_ip (self_ip, NBO)
  outer.dst_ip = far->outerHeaderCreation.ipv4 (gNB IP)
  outer.UDP = src:2152, dst:2152
  GTP.teid = far->outerHeaderCreation.teid
  PSC.qfi  = QERGetQFI(pdr->qer)
```

### 11.6 Important Local Data Structures

The SW path uses **file-local static arrays** (not `ctx->` fields) for type
safety with `int64_t` token bucket values:

| Static Array | Size | Purpose |
|-------------|------|---------|
| `sw_flows[256]` | `{subnet, flow_idx, in_use}` | SDF→meter_idx hash map |
| `sw_meters[256]` | `rte_meter_trtcm` | Per-flow trTCM meter instances |
| `sw_ue_table[256]` | `{ue_ip, ambr, gbr, qos_tb, nqos_tb}` | Per-UE AMBR token buckets |
| `sw_ue_hash[256]` | `{ue_ip, ue_idx, in_use}` | UE-IP → ue_table index hash |

---

## 12. Packet Flow — End to End

### 12.1 Uplink (UE → gNB → UPF → DN)

```
gNB sends:
  [ETH | IPv4(gNB→UPF) | UDP:2152 | GTPv1(TEID,QFI) | Inner-IPv4(UE→DN) | payload]

Arrives on Port 0 (access):
  RX_ROOT → ULDL (match UDP:2152 ✓) → 8T_IPV4

Case A: HW HIT (FORW PDR installed)
  8T_IPV4 matches TEID+QFI+inner → set meta = pdr_idx|DIR_UL
  → DECAP pipe:
    Strip GTP-U tunnel headers
    Inject new ETH: src=cn_dn_eth (UPF core MAC), dst=dn_mac (DN next-hop)
  → port_fwd to Port 1 (core)

  On Port 1 TX egress:
    TX_ROOT → SHARED_METER (meter by MBR)
    → COLOR_MATCH (GREEN? continue)
    → ENCAP_COUNTER: action_idx=ENCAP_NONE (UL, no re-encap), count packet
    → port_fwd (out Port 1)

  Result: [ETH(UPF_core→DN) | Inner-IPv4(UE→DN) | payload] → DN

Case B: SW MISS
  8T_IPV4 miss → UL_TO_SW (RSS to queue 1..N-1)
  → sw_handle_one():
    parse_gtpu_once() → extract TEID, QFI, outer_hdr_len
    ClassifyUL() → phb_classify_ul(TEID) or cls_classify_packet()
    Strip ETH, strip GTP-U (adj by outer_hdr_len)
    HandlePacketWithFar → FORW (no outerHeader) → no encap
    AttachL2Header: src=cn_dn_eth, dst=dn_eth_addr
    rte_eth_tx_burst(port 1)

  Result: [ETH(UPF_core→DN) | Inner-IPv4(UE→DN) | payload] → DN
```

### 12.2 Downlink (DN → UPF → gNB → UE)

```
DN sends:
  [ETH | IPv4(DN→UE_IP) | payload]

Arrives on Port 1 (core):
  RX_ROOT → ULDL (match UDP:2152 ✗ — not GTP-U) → miss → 5T_IPV4

Case A: HW HIT (FORW PDR installed)
  5T_IPV4 matches UE dst_ip → set meta = pdr_idx|DIR_DL
  → port_fwd to Port 0 (access)

  On Port 0 TX egress:
    TX_ROOT → SHARED_METER (meter by MBR)
    → COLOR_MATCH (GREEN? continue)
    → ENCAP_COUNTER:
      action_idx = ENCAP_IPV4_5G (if QFI > 0) or ENCAP_IPV4_4G
      Encap GTP-U:
        src_mac = cn_ue_eth (UPF access MAC)
        dst_mac = an_mac (gNB next-hop)
        src_ip  = self_ip (UPF N3 IP)
        dst_ip  = FAR.outerHeaderCreation.ipv4 (gNB IP)
        TEID    = FAR.outerHeaderCreation.teid
        QFI     = QER.qfi (5G only)
      Count packet with shared counter
    → port_fwd (out Port 0)

  Result: [ETH(UPF_access→gNB) | IPv4(UPF→gNB) | UDP:2152 | GTP(TEID,QFI) | IPv4(DN→UE) | payload]

Case B: SW MISS
  5T_IPV4 miss → DL_TO_SW (RSS to queue 1..N-1)
  → sw_handle_one():
    ClassifyDL(ue_ip_be) → phb_classify_dl(UE_IP) or cls_classify_packet()
    PopulateUeTable (first touch → AMBR/GBR from QER)
    Strip ETH
    HandlePacketWithFar → FORW + outerHeaderCreation
      → Encap(pkt, ctx, far, qer): prepend GTP-U + UDP + IP
    AttachL2Header: src=cn_ue_eth, dst=an_eth_addr
    DL QoS policing: trTCM per-SDF → token bucket per-UE
    rte_eth_tx_burst(port 0)
```

---

## 13. QoS Enforcement

QoS is enforced at **two levels**: HW (fast-path) and SW (miss-path).

### 13.1 HW QoS (DOCA Flow Shared Meters)

For every PDR with a QER that has `maximumBitrate`:

```
SHARED_METER pipe entry:
  match: meta.pkt_meta = pdr_index
  meter: RFC 2697 (single-rate, color-blind)
    CIR = CBS = MBR (kbps) × 1000 / 8  (bytes/sec)
    EBS = 0

COLOR_MATCH pipe:
  GREEN → continue to ENCAP_COUNTER
  RED   → TX_DROP (packet dropped in HW)
```

### 13.2 SW QoS (trTCM + Token Bucket)

The SW miss-path implements **DL-only** policing (mirrors `upf_u.c`):

**Layer 1: Per-SDF-flow trTCM** (`ConfigureQerFlows`)
- Key: `pdr->meter_key` (CRC32 of SDF target IP + port)
- PIR = QER MBR (kbps → bytes/sec)
- CIR = QER GBR (kbps → bytes/sec), or 0/1 if no GBR
- Profile stored in `sw_flow_profile` (DL + SDF) or `sw_profile` (others)
- Color output: GREEN=pass, YELLOW=wait, RED=drop

**Layer 2: Per-UE AMBR Token Bucket** (`PopulateUeTable` + `sw_ue_update_tokens`)
- For flows that aren't QoS-classified (no SDF match): uses `nqos_tb`
- For QoS flows getting YELLOW: waits on `qos_tb` tokens
- Token production rate = AMBR / 1000 × 125000 bytes per TSC cycle
- Busy-wait with `usleep(1)` until sufficient tokens

```
DL QoS Decision Flow:
  ┌───────────────────┐
  │  Has SDF filter?  │
  │  (pdr->has_fd)    │
  └────┬──────┬───────┘
       │yes   │no
       ▼      ▼
  ┌─────────┐  ┌───────────────┐
  │ trTCM   │  │ nQoS token    │
  │ per-SDF │  │ bucket wait   │
  └──┬──┬───┘  └───────────────┘
     │  │
     │  RED → DROP
     │  YELLOW → wait for qos_tb tokens
     │  GREEN → pass
     ▼
  TRANSMIT
```

---

## 14. Metadata Encoding

Packets matched by HW pipes carry a 32-bit `pkt_meta` value that encodes
both the PDR array index and the traffic direction:

```
  31        17  16        0
  ┌──────────┬──┬──────────┐
  │  unused  │DD│ pdr_index│
  └──────────┴──┴──────────┘

  DD = direction bits:
    0x1 << 16 = UL (0x00010000)
    0x2 << 16 = DL (0x00020000)

  pdr_index = lower 16 bits = index into ctx->pdrs[] array
```

**Encoding at RX:**
```c
meta = rte_cpu_to_be_32(pdr_index | UPF_DOCA_META_DIR_UL)  // UL
meta = rte_cpu_to_be_32(pdr_index | UPF_DOCA_META_DIR_DL)  // DL
```

**Decoding at TX (ENCAP_COUNTER pipe):**
```c
match.meta.pkt_meta = rte_cpu_to_be_32(pdr_index)
// mask = META_PDR_MASK = 0xFFFF (direction bits masked out)
```

This allows the TX egress pipes to identify which PDR a packet belongs to
and apply the correct encap action, counter, and meter.

---

## 15. MAC Address Strategy

Understanding which MAC goes where is critical:

### 15.1 Address Sources

| Variable | Source | Meaning |
|----------|--------|---------|
| `cn_ue_eth` | `rte_eth_macaddr_get(access_port)` | UPF access port **own** MAC |
| `cn_dn_eth` | `rte_eth_macaddr_get(core_port)` | UPF core port **own** MAC |
| `an_mac` / `an_eth_addr` | YAML config | gNB **next-hop** MAC |
| `dn_mac` / `dn_eth_addr` | YAML config | DN **next-hop** MAC |

### 15.2 Usage by Direction

| Operation | src_mac | dst_mac |
|-----------|---------|---------|
| **HW DECAP** (UL: strip GTP, toward DN) | `cn_dn_eth` (core own) | `dn_mac` (DN next-hop) |
| **HW ENCAP** (DL: add GTP, toward gNB) | `cn_ue_eth` (access own) | `an_mac` (gNB next-hop) |
| **SW AttachL2Header** (DL: toward gNB) | `cn_ue_eth` (access own) | `an_eth_addr` (gNB next-hop) |
| **SW AttachL2Header** (UL: toward DN) | `cn_dn_eth` (core own) | `dn_eth_addr` (DN next-hop) |

**Rule of thumb:** source MAC = the UPF port's own MAC on the **egress**
side. Destination MAC = the next-hop device's MAC on the **egress** side.

---

## 16. Statistics & Monitoring

### `upf_doca_print_stats()` (called every 5 seconds)

Prints three tables:

1. **Per-PDR table:**
   ```
   PDR_ID   Dir    RX_pkts      RX_bytes     HW_inst
   1        UL     0            0            YES
   2        DL     0            0            YES
   ```

2. **DPDK port stats:**
   ```
   Port 0: RX=1000 TX=950 missed=0 errors=0
   Port 1: RX=950 TX=1000 missed=0 errors=0
   ```

3. **HW shared counter queries:** For each installed PDR, queries
   `doca_flow_resource_query_entry()` on the encap entry to get HW
   packet/byte counts (per-entry query, not the deprecated system-level
   `doca_flow_resource_query`):
   ```
   HW Counter PDR[1] port[0]: pkts=500 bytes=32000
   ```

---

## 17. Build System

### Meson Configuration (`meson.build`)

**Executable:** `upf_doca`

**Source files:**
```
upf_doca.c, upf_doca_json.c, upf_doca_pipeline.c, upf_doca_sw_path.c
```

**External dependencies:**
| Dependency | Package | Purpose |
|------------|---------|---------|
| `libdpdk` | DPDK | EAL, mempool, ethdev, RSS, mbuf |
| `doca-flow` | DOCA SDK | Flow pipe creation, entry management |
| `doca-common` | DOCA SDK | Error handling, logging |
| `doca-dpdk-bridge` | DOCA SDK (optional) | DPDK↔DOCA integration |
| `json-c` | libjson-c | JSON parsing |
| `yaml` | libyaml | YAML parsing |

**Internal dependencies (from parent meson scope):**
| Dependency | Source | Purpose |
|------------|--------|---------|
| `libupf_dep` | `onvm/upf/` | `UpfSession`, `upf_context.h`, `gtp.h`, `pdr_hash_bypass.h` |
| `libutlt_dep` | `onvm/utlt/` | Debug, hash, pool utilities |
| `liblist_dep` | `onvm/list/` | Linked list (used by UpfSession) |
| `libupdk_dep` | `onvm/updk/` | UPDK rule structs (PDR/FAR/QER) |
| `liblogger_dep` | `onvm/logger/` | Logger headers |
| `classifier_dep` | `5gc/classifiers/` | PartitionSort + classifier_wrapper |

**Include paths:**
```
. (upf_doca/)
../../onvm/upf         → upf_context.h, gtp.h, pdr_hash_bypass.h
../../onvm/updk        → updk/rule_pdr.h, rule_far.h, rule_qer.h
../../onvm/utlt        → utlt_debug.h, utlt_pool.h
../../onvm/list        → list.h
../../onvm/logger      → logger headers
../classifiers         → classifier_wrapper.h, upf_cls_adapter.h
```

**Compiler flags:**
```
c_args: -D_GNU_SOURCE -std=gnu11
```

### Build Command
```bash
meson setup builddir
meson compile -C builddir
```

The `upf_doca` executable is installed to `bindir`.

---

## 18. CLI Usage

```
upf_doca <EAL_args> -- -j <smf_rules.json> -y <config.yaml> [-q <num_queues>]
```

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `-j` | Yes | — | Path to SMF PDR/FAR/QER JSON rule file |
| `-y` | Yes | — | Path to dataplane YAML config (MACs, IPs, ports) |
| `-q` | No | 2 | Number of RSS queues (queue 0 = DOCA Flow, 1..N-1 = SW miss-path) |

**Example:**
```bash
./upf_doca -l 0-3 -a 03:00.0 -a 03:00.1 -- \
    -j config/sample_smf_rules.json \
    -y config/upf_doca.yaml \
    -q 4
```

**EAL arguments:**
- `-l 0-3`: Use lcores 0–3 (lcore 0 = main + stats, 1–3 = workers)
- `-a 03:00.0 -a 03:00.1`: PCIe addresses of the two BF3 ports

---

## 19. Key Design Decisions & Rationale

### 19.1 No FAR Pipe

**Decision:** FAR action (FORW/DROP/BUFF) is evaluated at **install time**,
not at packet-match time.

**Rationale:** Only FORW PDRs need HW rules. DROP/BUFF PDRs never match in
HW, so packets naturally fall to the SW miss-path where FAR actions are
applied. This eliminates an entire pipe stage from the HW datapath, reducing
latency.

### 19.2 No TTL Decrement

**Decision:** The HW pipes do **not** decrement IP TTL.

**Rationale:** A UPF is a GTP tunnel endpoint, not an IP router. The inner
packet is encapsulated/decapsulated — the outer IP TTL is set to a fixed
value (64) on encap, and the inner IP TTL should remain unchanged.

### 19.3 JSON as "Mock SMF"

**Decision:** JSON file → identical UPDK structs that PFCP would produce.

**Rationale:** This allows standalone testing without a real 5GC control
plane. The JSON loader produces the **exact same** `UPDK_PDR`, `UPDK_FAR`,
`UPDK_QER` structs with the **exact same** flags, cross-references, and
session structures that the PFCP handler would create. When a real SMF is
available, only the loading path changes — all downstream code is unchanged.

### 19.4 Single Process (No ONVM)

**Decision:** Standalone executable, no ONVM manager dependency.

**Rationale:** On a BlueField DPU, the UPF runs alone. There's no need for
the ONVM multi-NF orchestration layer. This simplifies deployment,
eliminates shared-memory synchronization overhead, and allows direct
DOCA Flow calls without manager mediation.

### 19.5 SW Miss-Path Mirrors upf_u.c

**Decision:** The SW miss-path replicates `upf_u.c`'s packet handler flow
exactly: same classification order (hash bypass → PartitionSort), same
`ConfigureQerFlows`, same `HandlePacketWithFar`, same `Encap`, same
`AttachL2Header`, same trTCM + token bucket policing.

**Rationale:** Functional equivalence with the proven `upf_u.c` datapath.
Any packet that misses HW gets the exact same treatment it would get in the
non-DOCA UPF-U.

### 19.6 Queue 0 Reserved for DOCA Flow

**Decision:** RSS steers miss-path packets to queues 1..N-1 only.

**Rationale:** DOCA Flow in `vnf,hws` mode uses queue 0 internally for
hardware steering operations. SW packets on queue 0 could interfere.

---

## 20. Dependencies

### External
| Library | Version | Purpose |
|---------|---------|---------|
| DPDK | 22.11+ (BF3 SDK) | Packet I/O, memory management, RSS |
| DOCA SDK | 3.2.1 LTS | DOCA Flow (HW pipe offload) |
| json-c | 0.15+ | JSON parsing |
| libyaml | 0.2+ | YAML parsing |

### Internal (from this repo)
| Module | Path | Key Headers |
|--------|------|-------------|
| UPDK rules | `onvm/updk/updk/` | `rule_pdr.h`, `rule_far.h`, `rule_qer.h` |
| UPF context | `onvm/upf/` | `upf_context.h`, `gtp.h`, `pdr_hash_bypass.h` |
| Classifier | `5gc/classifiers/` | `classifier_wrapper.h`, `upf_cls_adapter.h` |
| Utilities | `onvm/utlt/` | `utlt_debug.h`, `utlt_pool.h`, `utlt_hash.h` |
| Linked list | `onvm/list/` | `list.h` |
| Logger | `onvm/logger/` | Logger macros |

---

## 21. Glossary

| Term | Meaning |
|------|---------|
| **PDR** | Packet Detection Rule — 3GPP rule matching packets by 5-tuple, TEID, QFI, etc. |
| **FAR** | Forwarding Action Rule — what to do with a matched packet (FORW, DROP, BUFF) |
| **QER** | QoS Enforcement Rule — MBR/GBR/AMBR rate limits per PDR |
| **TEID** | Tunnel Endpoint Identifier — GTP-U tunnel identifier |
| **QFI** | QoS Flow Identifier — 5G QoS discriminator (6 bits, 0–63) |
| **SDF** | Service Data Flow — fine-grained IP filter (source/dest IP + ports) |
| **PSC** | PDU Session Container — GTP-U extension header carrying QFI (type 0x85) |
| **PDI** | Packet Detection Information — the match criteria within a PDR |
| **UPDK** | User Plane Development Kit — the UPF's internal rule representation |
| **PHB** | PDR Hash Bypass — O(1) hash table for fast TEID/UE-IP → PDR lookup |
| **CLS** | Classifier — PartitionSort multi-dimensional packet classifier |
| **trTCM** | Two-Rate Three-Color Marker (RFC 2698) — metering algorithm |
| **NBO** | Network Byte Order — big-endian, as stored in packet headers |
| **HWS** | Hardware Steering — DOCA Flow mode where rules execute in HW |
| **VNF** | Virtual Network Function — DOCA Flow pipe type for inline processing |
| **RSS** | Receive Side Scaling — hash-based distribution of RX packets across queues |
| **AMBR** | Aggregate Maximum Bit Rate — per-UE maximum across all flows |
| **GBR** | Guaranteed Bit Rate — per-flow minimum guaranteed rate |
| **MBR** | Maximum Bit Rate — per-flow maximum rate |
| **BF3** | BlueField-3 — NVIDIA DPU with ConnectX-7 SmartNIC and Arm cores |

---

*Document generated for the `feature/doca-upf-offload` branch of onvm-upf.*
