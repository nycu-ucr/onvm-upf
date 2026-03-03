# onvm-upf → DOCA-Accelerated UPF on BF3 DPU — Planning Context

**Date**: February 26, 2026
**Base branch**: `optimize/fastpath-4-with-rte-hash` (commit `4b182aa`)
**Target branch**: TBD (create from base, e.g., `feature/doca-upf-offload`)
**Goal**: ICNP paper demonstrating that offloading PDR classification + GTP encap/decap to NVIDIA BlueField-3 DPU via DOCA Flow makes the UPF dataplane faster than the existing DPDK/OpenNetVM software implementation.

---

## 1. Motivation & Paper Thesis

Profiling of the current onvm-upf fastpath revealed that **PDR classification** and **GTP encapsulation/decapsulation** dominate the per-packet processing cost. The ICNP paper will show that offloading these two operations to BF3 hardware flow tables via DOCA Flow yields measurable throughput and latency improvements compared to the fully-software DPDK-based UPF.

---

## 2. Existing UPF Architecture (Summary)

### 2.1 Components

| Component | Location | Role |
|-----------|----------|------|
| ONVM Manager | `onvm/onvm_mgr/` | Shared-memory NF framework |
| UPF-C | `5gc/upf_c/` | PFCP/N4 control plane, PDR/FAR/QER management |
| UPF-U | `5gc/upf_u/upf_u.c` (1338 lines) | Per-packet dataplane NF |
| Classifier | `5gc/classifiers/` | PartitionSort multi-field classifier (C++ backend) |
| UPDK structs | `onvm/updk/updk/rule_pdr.h`, `rule_far.h`, `rule_qer.h` | PDR/FAR/QER data structures |
| GTP parser | `onvm/upf/gtp.h` | `parse_gtpu_once()` — single-pass GTP-U header parser |
| Hash bypass | `onvm/upf/pdr_hash_bypass.h` | O(1) TEID/UE-IP hash table in front of PartitionSort |
| CLS control | `onvm/upf/upf_cls_ctrl.h` | Seqlock-based classifier snapshot distribution |
| UPF context | `onvm/upf/upf_context.c/h` | Shared sessions, PDR global list, TEID/UE-IP maps |

### 2.2 Current UPF-U Packet Pipeline (`packet_handler` in `5gc/upf_u/upf_u.c`)

```
1. UpfClsMaybeFlipAndAck()          — classifier snapshot flip at burst boundary
2. Direction detection               — iph->dst_addr == SELF_IP → UL; else → DL
3. UL: parse_gtpu_once()            — extract TEID, QFI, outer_hdr_len
       GetPdrByTeid()               — hash bypass (phb_classify_ul) → PartitionSort fallback
4. DL: GetPdrByUeIpAddress()        — hash bypass (phb_classify_dl) → PartitionSort fallback
5. ConfigureQerFlows()              — lazy trTCM meter install on first miss
6. rte_pktmbuf_adj() strip ETH      — remove L2 header
7. Outer header removal (UL)         — rte_pktmbuf_adj(pkt, gtp_info.outer_hdr_len)
8. HandlePacketWithFar()             — FORW (with Encap()), DROP, BUFF, NOCP
9. AttachL2Header()                  — prepend new Ethernet header (MAC addresses from config)
10. DL QoS enforcement               — trTCM color check → per-UE token bucket (AMBR)
```

### 2.3 Key Data Structures

**UPDK_PDR** (`onvm/updk/updk/rule_pdr.h`):
- `pdrId`, `precedence`, `pdi` (sourceInterface, fTeid, ueIpAddress, sdfFilter, qfi)
- `outerHeaderRemoval`, `farId`, `far` (resolved pointer)
- `qer` (QFI-bearing QER selected by CP), `qers[2]`, `qer_count`
- `meter_key`, `fd_target`, `has_fd` (precomputed by UPF-C at CreatePDR time)
- `urrId[4]`, `qerId[2]`

**UPDK_FAR** (`onvm/updk/updk/rule_far.h`):
- `farId`, `applyAction` (DROP=1, FORW=2, BUFF=4, NOCP=8, DUPL=16)
- `forwardingParameters.outerHeaderCreation` (description, teid, ipv4/ipv6)
- `forwardingParameters.destinationInterface`

**UPDK_QER** (`onvm/updk/updk/rule_qer.h`):
- `qerId`, `gateStatus`, `maximumBitrate` {ul, dl}, `guaranteedBitrate` {ul, dl}
- `qosFlowIdentifier` (QFI), `reflectiveQos`

**Classifier key** (`ps_packet_t` in classifier):
- 14 dimensions: ue_ip, src_ip, dst_ip, src_port, dst_port, proto, tos_tc, spi, flow_label, teid, source_if, ni_hash, qfi, is_uplink

### 2.4 UPF-C PDR Lifecycle (`5gc/upf_c/n4_onvm_pfcp_handler.c`)

```
CreatePDR:
  _ConvertCreatePDRTlvToRule() → resolve QERs → UpfPdrSelectQfiQer()
  → UpfPdrPrecompileSdf() → UpfPDRGlobalAdd()
  → UpfClsRebuildAndPublish() → full rebuild of PartitionSort snapshot + hash bypass table
  → upf_cls_publish() seqlock → EVT_CLS_GC_REQ to UPF-U → flip at burst boundary → ACK-based GC
```

### 2.5 Current Config (`5gc/upf_u/config/upf_u.yaml`)

```yaml
configuration:
  dataplane:
    dn_mac: "3c:fd:fe:b4:fe:21"
    an_mac: "3c:fd:fe:b5:00:14"
    upf_ip: "192.168.1.2"
    ports:
      access: 0
      core: 1
```

### 2.6 QoS Model (Two-Tier, DL Only)

**Tier 1 — Per-flow trTCM** (`ConfigureQerFlows()` + `trtcmColorHandle()`):
- Keyed by `pdr->meter_key` (precomputed from SDF flowDescription + port)
- Uses QER's MBR as PIR, GBR as CIR
- `rte_meter_trtcm_color_blind_check()` → GREEN/YELLOW/RED → policer action
- Lazy install: first packet for a new meter_key triggers `ftAddEntry()` + `rte_meter_trtcm_config()`

**Tier 2 — Per-UE AMBR token bucket** (`ue_table[MAX_UE]`):
- Keyed by UE-IP via `ue_hash[]` (O(1) lookup)
- Split into qos_tb (GBR+share) and nqos_tb (remainder of AMBR)
- `updateTokenbyIndex()` refills tokens based on TSC cycles
- QoS flows: GREEN→deduct from qos_tb, YELLOW→wait+deduct, RED→drop
- Non-QoS flows: wait+deduct from nqos_tb
- AMBR/GBR/MBR derived from PDR's QERs via `GetQerByUEIpAddressFromPdr()`

---

## 3. DOCA Reference Application Analysis

### 3.1 Files (`doca-samples/applications/upf_accel/`)

| File | Lines | Purpose |
|------|-------|---------|
| `upf_accel.h` | ~370 | All structs: PDR, FAR, URR, QER, pipe enums, entry contexts |
| `upf_accel.c` | ~1915 | main(), init, smf_rules_add, shared meters/counters init |
| `upf_accel_pipeline.c` | ~2155 | All pipe creation: root, ULDL, 5T, 7T, 8T, decap, encap, meter, FAR, drops |
| `upf_accel_flow_processing.c` | ~2196 | Runtime: PDR lookup, dynamic entry add, aging, burst processing |
| `upf_accel_json_parser.c` | ~1325 | JSON parsing for SMF policy (PDR/FAR/URR/QER) |
| `upf_accel_packet_parser.c/h` | — | SW packet parser (ETH, IPv4, TCP/UDP, GTPv1-U with PSC) |
| `upf_accel_smf_default_init.c/h` | — | Hardcoded default rules for dry-run mode |
| `upf_accel_print_header.c/h` | — | Debug packet header printing |
| `upf_accel_params.json` | — | DPDK EAL flags, device PCI IDs, SMF file path |

### 3.2 DOCA Sample Init Flow

```
main()
  → doca_argp_init/start()          — parse CLI args
  → upf_accel_smf_parse()           — load PDR/FAR/URR/QER from JSON (or dry-run defaults)
  → init_upf_accel()
      → doca_flow_init("vnf,hws")   — VNF mode, HW steering
      → upf_accel_fp_data_init()    — per-core hash tables for connection tracking
      → init_doca_flow_ports()      — create 2 DOCA Flow ports
      → upf_accel_init_quota_counters()  — shared counters per PDR
      → upf_accel_shared_meters_init()   — shared meters from QER MBR
      → upf_accel_pipeline_create()      — create all pipes (RX + TX)
      → upf_accel_smf_rules_add()        — insert static entries (encap/meter pipes)
      → doca_flow_entries_process()      — finalize all static entries
  → run_upf_accel()
      → rte_eal_mp_remote_launch(fp_loop)  — worker cores
      → sigwait loop (SIGUSR1 → stats, SIGINT → quit)
```

### 3.3 DOCA Sample Pipe Hierarchy

**RX Domain (Ingress):**
```
RX_ROOT (TTL filter)
  └→ [VXLAN_DECAP] → ULDL_PIPE (match UDP:2152)
       ├─ hit → EXT_GTP (match PSC ext 0x85)
       │    ├─ hit → 8T_INNER_IP_TYPE → 8T_IPV4_PIPE (match: outer_src_ip + TEID + QFI + inner 5-tuple)
       │    │                                ├─ hit: set pkt_meta=pdr_id → DECAP → FAR → port_fwd
       │    │                                └─ miss → UL_TO_SW (RSS to CPU)
       │    └─ miss → 7T_INNER_IP_TYPE → 7T_IPV4_PIPE (no QFI, 4G)
       └─ miss → 5T_OUTER_IP_TYPE → 5T_IPV4_PIPE (DL: match outer 5-tuple)
                                         ├─ hit: set pkt_meta=pdr_id → FAR → port_fwd
                                         └─ miss → DL_TO_SW (RSS to CPU)
```

**TX Domain (Egress):**
```
TX_ROOT
  └→ SHARED_METER[0] → COLOR_MATCH[0] (green→next, red→drop)
       → SHARED_METER[1] → ... → COLOR_MATCH_NO_MORE
            → ENCAP_COUNTER_PIPE (match pkt_meta=pdr_id)
                 5 action templates:
                   - ENCAP_IPV4_4G (GTP-U, no PSC)
                   - ENCAP_IPV4_5G (GTP-U + PSC with QFI)
                   - ENCAP_IPV6_4G / ENCAP_IPV6_5G
                   - NONE (UL: no encap needed)
                 + shared counter per PDR
                 → [VXLAN_ENCAP] → port_fwd
```

### 3.4 Key Differences Between DOCA Sample and Our Design

| Aspect | DOCA Sample | Our DOCA UPF |
|--------|-------------|-------------|
| Classification | Reactive (SW first, offload after DPI threshold=2 pkts) | **Proactive** (all PDRs pre-installed in HW at startup) |
| Entry lifetime | Dynamic with HW aging (15s) + SW aging linked lists | **Static** (no aging; installed from JSON, persistent) |
| Connection tracking | Per-core `rte_hash` tables for flow state | **Not needed** (proactive model) |
| FAR actions | FORW only | **FORW, DROP, BUFF, NOCP** (BUFF/NOCP → SW miss-path) |
| QoS | Per-PDR shared meters only | Per-flow HW meters + **per-UE AMBR in SW** |
| Buffering | Not supported | **SW miss-path** (ported from current UPF-U) |
| Session report | Not supported | **SW miss-path** (logged, no ONVM IPC in standalone mode) |

### 3.5 What We Reuse From the DOCA Sample

- **DOCA Flow API patterns**: `doca_flow_pipe_cfg_create()`, `doca_flow_pipe_create()`, `doca_flow_pipe_add_entry()`, `doca_flow_entries_process()`
- **Pipe creation templates**: Match templates with `UINT32_MAX` wildcards, action templates for encap (5 variants) and decap
- **Shared meter configuration**: RFC 2697 srTCM, color-blind, byte-based, from QER MBR
- **Shared counter setup**: Per-PDR counters for throughput measurement
- **JSON parsing patterns**: Field extraction with `json-c` library (adapted to our field names)
- **Entry insertion patterns**: `upf_accel_pipe_8t_ipv4_accel()`, `upf_accel_pipe_5t_ipv4_accel()`, `upf_accel_pipe_encap_counter_insert()`

### 3.6 DOCA Sample JSON Config Format (for reference)

Top-level JSON: `{ "createPdr": [...], "createFar": [...], "createUrr": [...], "createQer": [...] }`

PDR fields: `pdrId`, `farId`, `urrIds[]`, `qerIds[]`, `pdi.sourceInterface.type` (0=UL, 2=DL), `pdi.localFT.teid_start/teid_end/ip`, `pdi.qfi`, `pdi.userEquipment.ip`, `pdi.sdf[].description` ("permit out ip/tcp/udp from IP port-range to IP port-range")

FAR fields: `farId`, `fp.outerHeader.teid`, `fp.outerHeader.ip`

QER fields: `qerId`, `qfi`, `maxBitRate.dlMBR/ulMBR`

---

## 4. Implementation Plan

### 4.1 Overview

Build a **single-instance standalone DOCA UPF** at `5gc/upf_doca/` that:
- Reads PDR/FAR/QER rules from a JSON config file (no PFCP, no ONVM, no UPF-C/UPF-U split)
- Programs BF3 HW flow pipes for PDR classification + GTP encap + GTP decap
- Provides a SW miss-path with all current UPF-U functionality (QoS, buffering, NOCP)
- Runs entirely on BF3 ARM cores in `vnf,hws` mode

### 4.2 Files to Create

| File | Purpose |
|------|---------|
| `5gc/upf_doca/upf_doca.c` | `main()`: DOCA init → JSON parse → pipeline create → rules install → launch workers → signal loop (SIGUSR1 for stats). Single binary. |
| `5gc/upf_doca/upf_doca.h` | Unified context struct: PDR/FAR/QER arrays, pipe handles, port handles, shared counter/meter IDs. Pipe enum. Entry contexts. |
| `5gc/upf_doca/upf_doca_json.c` | JSON parser using `json-c`. Reads our field names mapping to UPDK_PDR/FAR/QER semantics. |
| `5gc/upf_doca/upf_doca_pipeline.c` | Full pipe hierarchy creation (RX ingress + TX egress). |
| `5gc/upf_doca/upf_doca_sw_path.c` | SW miss-path handler: PDR linear scan, HandlePacketWithFar (FORW/DROP/BUFF/NOCP), SW Encap/Decap, per-UE AMBR token bucket. Ported from current `upf_u.c`. |
| `5gc/upf_doca/meson.build` | Build config. Links: `libdoca_flow`, `libdoca_common`, `libdoca_dpdk_bridge`, `libjson-c`, DPDK libs. |
| `5gc/upf_doca/config/upf_doca.yaml` | Runtime config: MAC addresses, UPF IP, port mapping (same fields as current `upf_u.yaml`). |
| `scripts/gen_upf_doca_config.py` | Python script to generate JSON configs with N UE sessions + matching TRex profiles. |

### 4.3 Pipe Hierarchy (Our Design)

**RX Domain (Ingress) — simplified for IPv4-only, 5G-only scope:**
```
RX_ROOT_PIPE
  └→ ULDL_PIPE (match outer.udp.dst_port == 2152)
       ├─ hit (UL) → 8T_IPV4_PIPE
       │    match: outer.ip4.src_ip + tun.gtp_teid + tun.gtp_ext_psc_qfi + inner 5-tuple
       │    action: set pkt_meta = pdr_id
       │    hit → DECAP_PIPE (strip GTP-U, inject new ETH header with configured MACs)
       │           → FAR_PIPE (TTL decrement, fwd to core port)
       │    miss → UL_TO_SW_PIPE (RSS to CPU cores for SW miss-path)
       │
       └─ miss (DL) → 5T_IPV4_PIPE
            match: outer.ip4.dst_ip (UE-IP) + outer.ip4.src_ip + proto + ports
            action: set pkt_meta = pdr_id
            hit → FAR_PIPE (TTL decrement, fwd to TX/egress path)
            miss → DL_TO_SW_PIPE (RSS to CPU cores for SW miss-path)
```

**TX Domain (Egress):**
```
TX_ROOT_PIPE
  └→ SHARED_METER chain (per-PDR QER MBR, RFC 2697 srTCM)
       → COLOR_MATCH (GREEN → continue, RED → RATE_DROP_PIPE)
            → ENCAP_COUNTER_PIPE
                 match: pkt_meta = pdr_id
                 5 action templates: IPv4_4G, IPv4_5G (with QFI/PSC), IPv6_4G, IPv6_5G, NONE
                 + shared counter per PDR (for throughput measurement)
                 → port_fwd (to opposite port)
```

### 4.4 Rule Installation (Proactive, Incremental)

For each PDR from JSON at startup:

1. **RX match pipe entry**: UL PDR → `doca_flow_pipe_add_entry()` on 8T_IPV4 pipe with match fields from PDI (TEID, QFI, inner 5-tuple). DL PDR → entry on 5T_IPV4 pipe with UE-IP + SDF fields. Action sets `pkt_meta = pdr_id`.

2. **TX encap/counter entry**: `match.meta.pkt_meta = pdr_id`, select action template based on FAR's outer header creation type + QFI presence. Set TEID and peer-IP per-entry. Attach shared counter.

3. **TX shared meter entry**: `match.meta.pkt_meta = pdr_id`, bind to shared meter resource configured with QER MBR.

4. **BUFF/NOCP PDRs are NOT installed in HW** — traffic for these PDRs reaches SW via RSS miss-path. The SW handler checks `far->applyAction` and performs buffering / session-report.

All entries batched with `DOCA_FLOW_WAIT_FOR_BATCH`, finalized with `doca_flow_entries_process()`.

### 4.5 SW Miss-Path (Full UPF-U Functionality)

Worker cores call `rte_eth_rx_burst()` from RSS queues (HW miss traffic). The SW handler:

1. Parse GTP-U header (reuse `parse_gtpu_once()` from `onvm/upf/gtp.h`)
2. PDR lookup via linear scan over the JSON-loaded PDR array (or optionally PartitionSort if we want to reuse the classifier)
3. `HandlePacketWithFar()`:
   - **FORW**: SW `Encap()` (GTP-U header prepend) + fwd. For UL: `rte_pktmbuf_adj()` to strip GTP-U.
   - **DROP**: Drop packet.
   - **BUFF**: Store in buffer array (ported from current `buffer[MAX_OF_BUFFER_PACKET_SIZE]`).
   - **NOCP**: Log session report event (no ONVM IPC in standalone mode; write to file/counter).
4. `AttachL2Header()` with configured MAC addresses.
5. Per-UE AMBR token bucket enforcement (DL only, ported from `ue_table[]` / `updateTokenbyIndex()`).
6. `rte_eth_tx_burst()` to send out.

### 4.6 QoS Offload Split

| QoS Tier | Current SW | DOCA UPF | Rationale |
|----------|-----------|----------|-----------|
| Per-flow trTCM (QER MBR/GBR) | `ConfigureQerFlows()` → `rte_meter_trtcm_color_blind_check()` | **HW shared meters** on TX egress path | DOCA shared meters support RFC 2697 srTCM, color-blind, byte-based. Maps QER MBR → CIR/CBS. Per-PDR granularity matches exactly. |
| Per-UE AMBR token bucket | `ue_table[]` → `updateTokenbyIndex()` → `usleep()` backpressure | **SW miss-path only** | No DOCA primitive for aggregate rate limiting across multiple PDRs belonging to the same UE. This is inherently a cross-PDR stateful policy. |

For the ICNP paper: per-flow MBR (which has per-packet cost in the fastpath) is offloaded. Per-UE AMBR (which is a DL-only aggregate policy with minimal fastpath cost compared to classification+encap/decap) stays in SW.

---

## 5. JSON Config Schema & Multi-UE Simulation

### 5.1 JSON Schema (Our Design)

```json
{
  "createPdr": [
    {
      "pdrId": 1,
      "precedence": 100,
      "farId": 101,
      "qerIds": [1],
      "outerHeaderRemoval": 0,
      "pdi": {
        "sourceInterface": { "type": "0" },
        "localFT": {
          "teid_start": 1000,
          "teid_end": 1000,
          "ip": { "v4": "192.168.1.2/32" }
        },
        "qfi": 9,
        "userEquipment": { "ip": { "v4": "10.60.0.1/32" } },
        "sdf": [{ "description": "permit out ip from any to assigned" }]
      }
    }
  ],
  "createFar": [
    {
      "farId": 101,
      "applyAction": 2,
      "fp": {
        "outerHeader": {
          "teid": 0,
          "ip": { "v4": "0.0.0.0" }
        }
      }
    },
    {
      "farId": 201,
      "applyAction": 2,
      "fp": {
        "outerHeader": {
          "teid": 2000,
          "ip": { "v4": "192.168.1.1" }
        }
      }
    }
  ],
  "createQer": [
    {
      "qerId": 1,
      "qfi": "9",
      "maxBitRate": { "dlMBR": "1000000", "ulMBR": "1000000" }
    }
  ]
}
```

Note: `applyAction` uses our UPDK constants: DROP=1, FORW=2, BUFF=4, NOCP=8.
UL FARs (no encap): `outerHeader.teid = 0`, `outerHeader.ip = "0.0.0.0"`.
DL FARs (with encap): `outerHeader.teid = <gNB TEID>`, `outerHeader.ip = <gNB N3 IP>`.

### 5.2 Multi-UE Simulation (100 UEs Example)

Each UE session = 2 PDRs (1 UL + 1 DL) + 2 FARs (1 UL + 1 DL) + 1 QER.

The Python generator (`scripts/gen_upf_doca_config.py`) produces:
- **UL PDR_i**: `pdrId=2*i`, `sourceInterface=ACCESS(0)`, `localFT.teid = base_teid + i`, `localFT.ip = "192.168.1.2/32"` (UPF N3), `userEquipment.ip = "10.60.0.<1+i>/32"`, `farId = 100+i`, `outerHeaderRemoval = 0` (GTP_IP4)
- **DL PDR_i**: `pdrId=2*i+1`, `sourceInterface=CORE(1)`, no localFT, `userEquipment.ip = "10.60.0.<1+i>/32"`, `sdf = "permit out ip from 10.60.0.<1+i>/32 to any"`, `farId = 200+i`
- **UL FAR_i**: `farId=100+i`, `applyAction=FORW(2)`, no outer header (UL → just forward inner IP)
- **DL FAR_i**: `farId=200+i`, `applyAction=FORW(2)`, `outerHeader.teid = 2000+i`, `outerHeader.ip = "192.168.1.1"` (gNB N3)
- **QER_i**: `qerId=i`, `qfi=9`, `dlMBR="1000000"`, `ulMBR="1000000"` (1 Gbps)

The first few UE sessions should use **real testbed IPs/TEIDs** (from actual SMF session establishment) so real traffic matches. Remaining sessions use synthetic sequential values.

### 5.3 Traffic Generation with TRex

TRex generates N simultaneous UE flows:

**UL traffic** (TRex → UPF access port):
- Outer: `src_ip=192.168.1.1` (gNB), `dst_ip=192.168.1.2` (UPF), `dst_port=2152`
- GTP-U: `TEID = 1000+i` (cycles via `field_engine` STLVmFlowVar)
- Inner: `src_ip=10.60.0.<1+i>` (UE), `dst_ip=8.8.8.8` (DN)
- Each TEID matches a different UL PDR → HW classifies → decaps → forwards to core port

**DL traffic** (TRex → UPF core port):
- Plain IP: `src_ip=8.8.8.8` (DN), `dst_ip=10.60.0.<1+i>` (UE-IP, cycles via field_engine)
- Each dst_ip matches a different DL PDR → HW classifies → encaps with correct TEID → forwards to access port back to TRex

TRex measures aggregate throughput (Mpps, Gbps), per-flow latency, and loss rate.

---

## 6. Measurement Plan for ICNP Paper

### 6.1 Metrics

| Metric | HW Path | SW Baseline |
|--------|---------|-------------|
| **Throughput** (Mpps, Gbps) | TRex external measurement (end-to-end) | TRex same setup, traffic through ONVM UPF-U |
| **Per-PDR counters** | `doca_flow_resource_query_entry()` → `total_pkts`/`total_bytes` | SW packet counters in `packet_handler` |
| **Rule install latency** | `rte_rdtsc()` around `pipe_add_entry()` + `entries_process()` batch | `rte_rdtsc()` around `UpfClsRebuildAndPublish()` |
| **Per-packet latency** | TRex latency streams (RTT) | TRex same setup |
| **Drop counters** | DOCA drop pipe entry counters | SW drop counter |

### 6.2 Scaling Experiments

Sweep PDR count: 10, 100, 1K, 10K UE sessions (= 20, 200, 2K, 20K PDRs).
Fixed traffic rate at line rate. Measure throughput and latency at each scale.
Both HW (DOCA UPF) and SW (ONVM UPF-U) baselines on same BF3 ARM cores.

### 6.3 Deployment

- **DOCA UPF**: Standalone binary on BF3 ARM cores, `vnf,hws` mode. Two ports (access + core) on BF3 ConnectX-7 NICs.
- **SW baseline**: ONVM manager + UPF-C + UPF-U on same BF3 ARM cores (or host CPU if needed). Same two ports.
- **Traffic**: TRex on separate host, connected to BF3 physical ports.

---

## 7. Testbed IP/MAC Reference

From current `upf_u.yaml` and codebase:
- **UPF N3 IP**: `192.168.1.2` (SELF_IP)
- **gNB N3 IP**: `192.168.1.1` (peer for GTP encap)
- **DN MAC**: `3c:fd:fe:b4:fe:21` (dn_mac)
- **AN MAC**: `3c:fd:fe:b5:00:14` (an_mac)
- **UE IP range**: `10.60.0.0/24` (assigned by SMF, typically sequential)
- **Access port**: 0
- **Core port**: 1

---

## 8. Feature Parity Checklist

| # | Feature | HW Offload | SW Miss-Path | Status |
|---|---------|-----------|-------------|--------|
| 1 | PDR classification (TEID-based UL) | ✅ 8T pipe | ✅ linear scan / PartitionSort | Planned |
| 2 | PDR classification (UE-IP-based DL) | ✅ 5T pipe | ✅ linear scan / PartitionSort | Planned |
| 3 | GTP-U decap (outer header removal, UL) | ✅ DECAP pipe | ✅ `rte_pktmbuf_adj()` | Planned |
| 4 | GTP-U encap (TEID + QFI/PSC, DL) | ✅ ENCAP pipe (5 templates) | ✅ `Encap()` | Planned |
| 5 | FAR FORW + port forward | ✅ FAR pipe (TTL dec) | ✅ `HandlePacketWithFar()` | Planned |
| 6 | FAR DROP | ✅ No HW entry → miss → SW drops | ✅ `meta->action = DROP` | Planned |
| 7 | Per-flow trTCM metering (QER MBR/GBR) | ✅ Shared meter chain | — | Planned |
| 8 | L2 header (MAC addresses) | ✅ DECAP pipe sets new ETH; ENCAP sets outer ETH | ✅ `AttachL2Header()` | Planned |
| 9 | Per-PDR packet/byte counters | ✅ DOCA shared counters | ✅ SW counters | Planned |
| 10 | FAR BUFF (buffering) | — | ✅ `buffer[]` array | Planned (SW only) |
| 11 | FAR NOCP (session report) | — | ✅ Log event | Planned (SW only) |
| 12 | Per-UE AMBR token bucket | — | ✅ `ue_table[]` + `updateTokenbyIndex()` | Planned (SW only) |
| 13 | Multiple UE simulation | ✅ JSON config + TRex multi-flow | — | Planned |

---

## 9. Key DOCA Flow API Patterns to Use

### Pipe creation:
```c
doca_flow_pipe_cfg_create(&cfg, port);
set_flow_pipe_cfg(cfg, name, DOCA_FLOW_PIPE_BASIC, is_root);
doca_flow_pipe_cfg_set_domain(cfg, DOCA_FLOW_PIPE_DOMAIN_DEFAULT);  // or EGRESS
doca_flow_pipe_cfg_set_nr_entries(cfg, max_entries);
doca_flow_pipe_cfg_set_match(cfg, &match, &match_mask);
doca_flow_pipe_cfg_set_actions(cfg, actions_arr, NULL, action_desc_arr, num_actions);
doca_flow_pipe_cfg_set_monitor(cfg, &mon);
doca_flow_pipe_create(cfg, &fwd_hit, &fwd_miss, &pipe);
doca_flow_pipe_cfg_destroy(cfg);
```

### Entry addition (proactive):
```c
doca_flow_pipe_add_entry(queue_id, pipe, &match, action_idx, &actions,
                         &monitor, &fwd, DOCA_FLOW_WAIT_FOR_BATCH,
                         user_ctx, &entry);
// After all entries:
doca_flow_entries_process(port, queue_id, timeout, max_entries);
```

### Shared meter config (from QER MBR):
```c
struct doca_flow_shared_resource_cfg cfg = {
    .meter_cfg = { .limit_type = DOCA_FLOW_METER_LIMIT_TYPE_BYTES,
                   .color_mode = DOCA_FLOW_METER_COLOR_MODE_BLIND,
                   .alg = DOCA_FLOW_METER_ALGORITHM_TYPE_RFC2697,
                   .rfc2697.ebs = 0 }};
cfg.meter_cfg.cir = cfg.meter_cfg.cbs = qer_mbr_kbps * 1000 / 8;  // kbps → bytes/s
doca_flow_port_shared_resource_get(port, DOCA_FLOW_SHARED_RESOURCE_METER, &meter_id);
doca_flow_port_shared_resource_set_cfg(port, DOCA_FLOW_SHARED_RESOURCE_METER, meter_id, &cfg);
```

### Counter query:
```c
struct doca_flow_resource_query stats;
doca_flow_resource_query_entry(entry, &stats);
// stats.counter.total_pkts, stats.counter.total_bytes
```

---

## 10. Open Items / Decisions Pending

1. **Real SMF PDRs**: User will provide actual PDR/FAR/QER values from their SMF for the "real" entries in the JSON config. These should be added to the first few entries of the generated JSON.

2. **TRex profile generation**: The Python script should also generate a matching TRex YAML profile that produces traffic hitting all configured PDRs. To be confirmed.

3. **IPv6 support**: Current plan is IPv4-only for ICNP. IPv6 requires the two-stage extension pipe chain (metadata-based correlation). Can be added later.

4. **VXLAN**: Not needed for ICNP. The DOCA sample supports it but we skip it.

5. **Live PFCP mode**: Not needed for ICNP. But the code should be structured so `upf_doca_install_pdr()` is a clean function callable from either JSON-init or a future PFCP handler.

6. **Branch name**: Create new branch from `optimize/fastpath-4-with-rte-hash` for the DOCA implementation.
