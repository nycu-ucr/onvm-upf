# Split-Agent DOCA Flow Offload — Technical Documentation

> **Branch:** `feature/doca-split-agent-offload`  
> **Target HW:** NVIDIA BlueField-3 DPU (ConnectX-7 SmartNIC)  
> **SDK:** DOCA Flow v3.2.0 (`switch,hws` mode)  
> **Scope:** 5G SA User Plane Function (UPF) data-plane offload via DOCA Flow

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Component Inventory](#2-component-inventory)
3. [End-to-End Packet Flow](#3-end-to-end-packet-flow)
4. [DOCA Flow Pipeline — The 13-Pipe Hierarchy](#4-doca-flow-pipeline--the-13-pipe-hierarchy)
5. [Port Creation and Device Binding](#5-port-creation-and-device-binding)
6. [ROOT Pipe — Traffic Steering](#6-root-pipe--traffic-steering)
7. [Priority-Bucketed Pipe Chaining (Precedence)](#7-priority-bucketed-pipe-chaining-precedence)
8. [Uplink Match Pipes — GTP Decap + SDF Matching](#8-uplink-match-pipes--gtp-decap--sdf-matching)
9. [Downlink Match Pipes — SDF Matching + pkt_meta Tagging](#9-downlink-match-pipes--sdf-matching--pkt_meta-tagging)
10. [Color-Gate Pipes — Meter Enforcement](#10-color-gate-pipes--meter-enforcement)
11. [DL_ENCAP Pipe — GTP Encapsulation with PSC](#11-dl_encap-pipe--gtp-encapsulation-with-psc)
12. [TO_HOST Pipe — Software Fallback](#12-to_host-pipe--software-fallback)
13. [trTCM Metering (RFC 2698)](#13-trtcm-metering-rfc-2698)
14. [Rule Installation — From PFCP to Silicon](#14-rule-installation--from-pfcp-to-silicon)
15. [SDF 5-Tuple Matching and Direction Reversal](#15-sdf-5-tuple-matching-and-direction-reversal)
16. [Per-Entry Match Masks (Wildcard Support)](#16-per-entry-match-masks-wildcard-support)
17. [hw_offload_msg — The Cross-Domain Message](#17-hw_offload_msg--the-cross-domain-message)
18. [Host Agent — ONVM-to-DPU Bridge](#18-host-agent--onvm-to-dpu-bridge)
19. [DPU Agent — Standalone DOCA Application](#19-dpu-agent--standalone-doca-application)
20. [UPF-C Hook — Building the Offload Message](#20-upf-c-hook--building-the-offload-message)
21. [Byte-Order Contracts](#21-byte-order-contracts)
22. [EAL Initialization and Devargs](#22-eal-initialization-and-devargs)
23. [Pipeline Teardown](#23-pipeline-teardown)
24. [Design Decisions and Alternatives Considered](#24-design-decisions-and-alternatives-considered)
25. [Current Limitations and Future Work](#25-current-limitations-and-future-work)

---

## 1. Architecture Overview

The Split-Agent design separates the 5G UPF control plane (PFCP handling, session management) from the data-plane offload (DOCA Flow programming on BlueField-3). Three cooperating components form a pipeline from PFCP signalling to silicon-programmed flow entries:

```
┌─────────────────────────── Host x86 ───────────────────────────┐
│                                                                 │
│  ┌──────────┐  ONVM ring   ┌──────────────┐  DOCA Comch (PCIe) │
│  │  UPF-C   │ ──────────▶  │  Host Agent   │ ──────────────────▶│
│  │ (NF #1)  │  hw_offload  │  (NF #3)      │                   │
│  └──────────┘  _msg_t      └──────────────┘                   │
│       ▲                                                         │
│       │ PFCP (N4)                                              │
│       ▼                                                         │
│  ┌──────────┐                                                  │
│  │   SMF    │                                                  │
│  └──────────┘                                                  │
└─────────────────────────────────────────────────────────────────┘
                              │ PCIe
                              ▼
┌─────────────────────── BlueField-3 DPU ────────────────────────┐
│                                                                 │
│  ┌──────────────┐                                              │
│  │  DPU Agent   │  dpu_pipeline_insert_rule()                  │
│  │ (ARM native) │ ──────▶  DOCA Flow switch,hws               │
│  └──────────────┘          13-pipe hierarchy                   │
│                                                                 │
│  Physical ports:  N3 (PF0) ←→ eSwitch ←→ N6 (PF1)            │
│                              ↕                                  │
│                         Host VF Rep                             │
└─────────────────────────────────────────────────────────────────┘
```

**Key principle:** The UPF-C software path remains fully functional. If HW offload fails or a packet doesn't match any offloaded rule, traffic falls through to the Host VF representor and is handled by the existing ONVM UPF software pipeline. The offload is an **acceleration overlay**, not a replacement.

---

## 2. Component Inventory

| File | Location | Role |
|------|----------|------|
| `dpu_pipeline.h` | `5gc/dpu_agent/` | Pipeline context struct, pipe handles, API declarations |
| `dpu_pipeline.c` | `5gc/dpu_agent/` | 13-pipe DOCA Flow hierarchy: build, insert, destroy (~1025 lines) |
| `dpu_agent.c` | `5gc/dpu_agent/` | Standalone DOCA app on BF3 ARM: doca_argp config, Comch server, main loop |
| `dpu_agent_config.h` | `5gc/dpu_agent/` | doca_argp config struct (`dpu_agent_cfg_t`) and registration API |
| `dpu_agent_config.c` | `5gc/dpu_agent/` | doca_argp callbacks + `register_dpu_agent_params()` |
| `dpu_agent_params.json` | `5gc/dpu_agent/config/` | DOCA Arg Parser JSON config (PCI addresses, MACs, IPs) |
| `host_agent.c` | `5gc/host_agent/` | ONVM NF #3: receives from UPF-C ring, sends via Comch client (~454 lines) |
| `hw_offload_msg.h` | `onvm/upf/` | Flat C struct for cross-domain message (PDR→FAR→QER→SDF, ~126 lines) |
| `upf_hw_offload.h` | `5gc/upf_c/` | Inline helper: builds `hw_offload_msg_t` from PFCP PDR and sends to Host Agent |

---

## 3. End-to-End Packet Flow

### 3.1 Uplink (N3 → N6): GTP-encapsulated from gNB to Data Network

```
gNB ──GTP-U──▶ N3 port
                  │
            ROOT pipe (CONTROL)
            match: port_id=N3, UDP dst=2152
                  │
            UL_MATCH[0] (highest prio bucket)
            match: TEID + QFI + inner 5-tuple
            action: GTP decap + L2 inject (UPF N6 MAC → DN GW MAC)
                    + pkt_meta = hw_rule_id + shared meter
                  │  miss → UL_MATCH[1] → ... → UL_MATCH[3] → TO_HOST
                  ▼
            UL_COLOR_GATE
            match: meter_color
            GREEN/YELLOW → fwd port N6
            RED → DROP
                  │
                  ▼
             N6 port ──▶ Data Network
```

### 3.2 Downlink (N6 → N3): Plain IPv4 from DN, encapsulated to GTP-U

```
DN ──IPv4──▶ N6 port
                │
          ROOT pipe (CONTROL)
          match: port_id=N6, L3=IPv4
                │
          DL_MATCH[0] (highest prio bucket)
          match: outer dst_ip=UE_IP + SDF 5-tuple (reversed)
          action: pkt_meta = hw_rule_id + shared meter
                │  miss → DL_MATCH[1] → ... → DL_MATCH[3] → TO_HOST
                ▼
          DL_COLOR_GATE
          match: meter_color
          GREEN/YELLOW → fwd port N3
          RED → DROP
                │
                ▼
          DL_ENCAP (EGRESS on N3)
          match: pkt_meta = hw_rule_id
          action: GTP-U encap (outer L2 + IPv4 + UDP + GTP + PSC)
                │
                ▼
           N3 port ──GTP-U──▶ gNB
```

### 3.3 Software Fallback

Any packet that misses all UL_MATCH or DL_MATCH buckets hits TO_HOST, which forwards to the Host VF representor. The ONVM manager delivers it to UPF-U for software-based PDR lookup, decap/encap, and forwarding — the original pre-offload path.

---

## 4. DOCA Flow Pipeline — The 13-Pipe Hierarchy

All pipes are created on the **switch manager port** (`doca_flow_port_switch_get`) in `switch,hws` mode, which operates in the BlueField eSwitch FDB domain.

| # | Pipe Name | Type | Domain | is_root | Count | Purpose |
|---|-----------|------|--------|---------|-------|---------|
| 1 | ROOT | CONTROL | DEFAULT | yes | 1 | Steer by port_id + protocol |
| 2–5 | UL_MATCH[0..3] | BASIC | DEFAULT | no | 4 | Uplink PDR matching (decap + meter) |
| 6–9 | DL_MATCH[0..3] | BASIC | DEFAULT | no | 4 | Downlink PDR matching (tag + meter) |
| 10 | UL_COLOR_GATE | BASIC | DEFAULT | no | 1 | Uplink meter enforcement |
| 11 | DL_COLOR_GATE | BASIC | DEFAULT | no | 1 | Downlink meter enforcement |
| 12 | DL_ENCAP | BASIC | EGRESS | yes | 1 | Downlink GTP encapsulation |
| 13 | TO_HOST | BASIC | DEFAULT | no | 1 | Software fallback catch-all |

**Build order** (reverse-dependency):
1. TO_HOST (no downstream deps)
2. UL_COLOR_GATE, DL_COLOR_GATE
3. UL_MATCH[3], UL_MATCH[2], UL_MATCH[1], UL_MATCH[0] (P3 built first so P2's `fwd_miss` can point to it)
4. DL_MATCH[3..0] (same pattern)
5. DL_ENCAP (egress root, separate domain)
6. ROOT (needs UL_MATCH[0] and DL_MATCH[0] for its control entries)

**Implementation:** `dpu_pipeline_init()` in `dpu_pipeline.c` (lines 715–782).

---

## 5. Port Creation and Device Binding

Three DOCA Flow ports are created, each bound to a physical DOCA device via `doca_flow_port_cfg_set_dev()`:

| Port | port_id | Device | Description |
|------|---------|--------|-------------|
| N3 | 0 | PF0 (`--n3-pci`) | Facing gNBs (uplink ingress, downlink egress) |
| N6 | 1 | PF1 (`--n6-pci`) | Facing Data Network (downlink ingress, uplink egress) |
| Host VF | 2 | VF (`--vf-pci`) | Software fallback path to host CPU |

The `create_port()` function (lines 108–144) handles:
1. `doca_flow_port_cfg_create()` — allocate port config
2. `doca_flow_port_cfg_set_port_id()` — logical port ID assignment
3. `doca_flow_port_cfg_set_dev()` — **required** HW context binding (every NVIDIA sample requires this)
4. `doca_flow_port_cfg_set_dev_rep()` — optional representor for Host VF
5. `doca_flow_port_cfg_set_nr_resources(METER, 4096)` — per-port meter pool
6. `doca_flow_port_start()` — activate the port

After creation, ports 0 and 1 are paired via `doca_flow_port_pair()`, and the switch manager port is obtained via `doca_flow_port_switch_get(ports[0])`.

---

## 6. ROOT Pipe — Traffic Steering

The ROOT pipe is a **CONTROL** type pipe (`DOCA_FLOW_PIPE_CONTROL`) with `is_root=true`, which means it is the first pipe a packet hits in the default (ingress) domain.

Control pipes support prioritized entries added via `doca_flow_pipe_control_add_entry()`. Two entries steer traffic:

| Priority | Match | Forward To |
|----------|-------|------------|
| 0 | `parser_meta.port_id == N3` AND `outer.udp.dst_port == 2152` | UL_MATCH[0] |
| 1 | `parser_meta.port_id == N6` AND `outer.l3_type == IPv4` | DL_MATCH[0] |
| miss | everything else | TO_HOST |

**Why `parser_meta.port_id`?** In `switch,hws` mode, all ports share the same eSwitch. Without port_id discrimination, GTP-U traffic from any port would enter the UL pipeline. The port_id ensures only N3-sourced GTP enters UL, and only N6-sourced IPv4 enters DL.

**Implementation:** `build_root_pipe()` in `dpu_pipeline.c` (lines 549–629).

---

## 7. Priority-Bucketed Pipe Chaining (Precedence)

3GPP TS 29.244 assigns each PDR a **precedence** value (lower = higher priority). When multiple PDRs match a packet, the one with the lowest precedence wins.

DOCA Flow's BASIC pipes don't have a native multi-priority ordering within a single pipe. The documented and **NVIDIA-recommended** approach is **pipe chaining**: multiple BASIC pipes connected via `fwd_miss`, where the first pipe to match wins.

### Bucket Mapping

```c
#define NUM_PRIO_BUCKETS    4
#define PRIO_BUCKET_RANGE   64

int bucket = precedence / PRIO_BUCKET_RANGE;
// bucket 0: precedence   0– 63  (highest priority)
// bucket 1: precedence  64–127
// bucket 2: precedence 128–191
// bucket 3: precedence 192–255  (lowest priority)
```

### Chain Topology

```
ROOT → UL_MATCH[0] ──miss──▶ UL_MATCH[1] ──miss──▶ UL_MATCH[2] ──miss──▶ UL_MATCH[3] ──miss──▶ TO_HOST
       (P0, prio 0–63)       (P1, 64–127)           (P2, 128–191)         (P3, 192–255)

ROOT → DL_MATCH[0] ──miss──▶ DL_MATCH[1] ──miss──▶ DL_MATCH[2] ──miss──▶ DL_MATCH[3] ──miss──▶ TO_HOST
```

### Build Order Matters

Pipes are built **P3 first, then P2, P1, P0**. This is because each pipe's `fwd_miss` must point to the next-lower-priority pipe, which must already exist. More importantly, in DOCA Flow, entries added later have higher insertion-order priority (they are checked first). Building P3 first and P0 last ensures that P0 entries — the highest 3GPP priority — are also the last added, giving them the highest DOCA insertion-order priority.

**Implementation:** `build_ul_match_pipes()` and `build_dl_match_pipes()` loops in `dpu_pipeline.c` (lines 269–377 and 385–465).

---

## 8. Uplink Match Pipes — GTP Decap + SDF Matching

Each `UL_MATCH[p]` pipe (4 instances, one per priority bucket) is a BASIC pipe matching:

### Pipe Template (set at creation time)

| Field | Template Value | Meaning |
|-------|---------------|---------|
| `tun.type` | `DOCA_FLOW_TUN_GTPU` | GTP-U tunnel |
| `tun.gtp_teid` | `UINT32_MAX` | CHANGEABLE per-entry |
| `tun.gtp_ext_psc_qfi` | `UINT8_MAX` | CHANGEABLE per-entry |
| `inner.l3_type` | `DOCA_FLOW_L3_TYPE_IP4` | Inner IPv4 |
| `inner.ip4.src_ip` | `UINT32_MAX` | UE IP (CHANGEABLE) |
| `inner.ip4.dst_ip` | `UINT32_MAX` | SDF remote IP (CHANGEABLE) |
| `inner.ip4.next_proto` | `UINT8_MAX` | SDF protocol (CHANGEABLE) |
| `inner.transport.src_port` | `UINT16_MAX` | SDF src port (CHANGEABLE) |
| `inner.transport.dst_port` | `UINT16_MAX` | SDF dst port (CHANGEABLE) |

> **Note:** The protocol-agnostic `transport` accessor (`struct doca_flow_header_l4_port`) is used for L4 port matching. In DOCA Flow's relaxed match mode, `tcp`, `udp`, and `transport` are union members sharing the same memory; `transport` avoids protocol-specific ambiguity.

> **Note (TEID-only matching):** The pipe matches `gtp_teid` but not the F-TEID IPv4 address (`fteid_ipv4`). In a single-BF3 5G SA deployment, all UL GTP-U traffic arriving on port N3 is already destined for this UPF's N3 IP — the F-TEID IP is implied by the physical port. The `fteid_ipv4` field is carried in `hw_offload_msg_t` for potential future use in multi-UPF or multi-DPU scenarios.

> **Note (QFI wildcard):** When `qfi=0` in the message, the per-entry mask for `gtp_ext_psc_qfi` is left at 0 (wildcard), matching any QFI value. This handles PDRs that do not specify a QFI in the PDI. When `qfi > 0`, the mask is `UINT8_MAX` (exact match).

### Actions (set at creation time, some CHANGEABLE)

| Action | Value | Description |
|--------|-------|-------------|
| `decap_type` | `NON_SHARED` | Inline GTP-U decap (removes outer L2+IP+UDP+GTP) |
| `decap_cfg.is_l2` | `false` | Not an L2 tunnel — it's GTP-over-UDP-over-IP |
| `decap_cfg.eth.src_mac` | UPF N6 MAC | Injected Ethernet src after decap |
| `decap_cfg.eth.dst_mac` | DN GW MAC | Injected Ethernet dst after decap |
| `decap_cfg.eth.type` | `0x0800` | IPv4 EtherType |
| `meta.pkt_meta` | `UINT32_MAX` | CHANGEABLE — set to `hw_rule_id` per-entry |

### Monitor

| Field | Value |
|-------|-------|
| `meter_type` | `DOCA_FLOW_RESOURCE_TYPE_SHARED` |
| `shared_meter.shared_meter_id` | Set per-entry (or skipped when no QER) |

### Forwarding

- **Hit:** → `UL_COLOR_GATE` (meter enforcement)
- **Miss:** → `UL_MATCH[p+1]` (next bucket) or `TO_HOST` (if p=3)

**Implementation:** `build_ul_match_pipes()` in `dpu_pipeline.c` (lines 269–377).

---

## 9. Downlink Match Pipes — SDF Matching + pkt_meta Tagging

Each `DL_MATCH[p]` pipe matches **outer** (pre-encap) fields because DL traffic arrives as plain IPv4 from N6:

### Pipe Template

| Field | Template Value | Meaning |
|-------|---------------|---------|
| `outer.l3_type` | `DOCA_FLOW_L3_TYPE_IP4` | Outer IPv4 |
| `outer.ip4.dst_ip` | `UINT32_MAX` | UE IP (CHANGEABLE) |
| `outer.ip4.src_ip` | `UINT32_MAX` | SDF remote IP (CHANGEABLE, reversed) |
| `outer.ip4.next_proto` | `UINT8_MAX` | SDF protocol (CHANGEABLE) |
| `outer.transport.src_port` | `UINT16_MAX` | SDF src port (CHANGEABLE, reversed) |
| `outer.transport.dst_port` | `UINT16_MAX` | SDF dst port (CHANGEABLE, reversed) |

### Actions

| Action | Value |
|--------|-------|
| `meta.pkt_meta` | `UINT32_MAX` (CHANGEABLE — set to `hw_rule_id`) |

The `pkt_meta` tag survives across the eSwitch and is matched by the DL_ENCAP pipe on egress to select the correct GTP tunnel parameters.

### Monitor + Forwarding

Same pattern as UL: shared meter → DL_COLOR_GATE → fwd port N3 (which triggers DL_ENCAP egress).

**Implementation:** `build_dl_match_pipes()` in `dpu_pipeline.c` (lines 385–465).

---

## 10. Color-Gate Pipes — Meter Enforcement

Two identical color-gate pipes (UL and DL) enforce the trTCM meter verdict:

```c
match.parser_meta.meter_color = UINT32_MAX;  // pipe-level: CHANGEABLE
```

Three static entries installed at pipe creation:

| Entry | meter_color | Forward |
|-------|------------|---------|
| GREEN | `DOCA_FLOW_METER_COLOR_GREEN` | → port N6 (UL) or N3 (DL) |
| YELLOW | `DOCA_FLOW_METER_COLOR_YELLOW` | → port N6 (UL) or N3 (DL) |
| miss (RED) | — | `fwd_miss = DROP` |

**Design:** GREEN and YELLOW packets are forwarded (they're within GBR or between GBR and MBR). RED packets exceeded the MBR and are dropped in hardware — no CPU involvement.

**Implementation:** `build_color_gate_pipe()` in `dpu_pipeline.c` (lines 196–262).

---

## 11. DL_ENCAP Pipe — GTP Encapsulation with PSC

The DL_ENCAP pipe runs in the **EGRESS domain** on the N3 port. It is a root pipe (`is_root=true`) in the egress domain, meaning every packet leaving N3 traverses it.

### Match

| Field | Template | Per-entry |
|-------|----------|-----------|
| `meta.pkt_meta` | `UINT32_MAX` | `htonl(hw_rule_id)` |

### Encapsulation Action

The pipe template defines the **full GTP-U encapsulation** with a PDU Session Container (PSC) extension:

| Layer | Field | Value |
|-------|-------|-------|
| Outer Ethernet | `src_mac` | UPF N3 MAC |
| | `dst_mac` | gNB MAC |
| | `type` | `0x0800` |
| Outer IPv4 | `src_ip` | UPF N3 IP (fixed) |
| | `dst_ip` | `UINT32_MAX` (CHANGEABLE — gNB F-TEID IP) |
| | `ttl` | 64 |
| Outer UDP | `dst_port` | 2152 (GTP-U) |
| GTP-U | `tun.type` | `DOCA_FLOW_TUN_GTPU` |
| | `gtp_teid` | `UINT32_MAX` (CHANGEABLE — DL TEID) |
| | `gtp_next_ext_hdr_type` | `0x85` (PSC extension) |
| | `gtp_ext_psc_qfi` | `UINT8_MAX` (CHANGEABLE — QFI) |

The **PSC extension** (`gtp_next_ext_hdr_type = 0x85`) is a 5G NR requirement — the gNB uses the QFI in the PSC to map the packet to the correct QoS flow on the radio interface.

### Per-Entry Values (set during rule insertion)

For each DL rule, a matching DL_ENCAP entry is inserted with:
- `pkt_meta = htonl(hw_rule_id)` — matches the tag set by DL_MATCH
- `outer.ip4.dst_ip = ohc_ipv4` — gNB's F-TEID IPv4 (from FAR)
- `tun.gtp_teid = htonl(ohc_teid)` — DL GTP TEID (from FAR)
- `tun.gtp_ext_psc_qfi = encap_qfi` — QFI for the PSC header (from QER)

### Forwarding

- **Hit:** → port N3 (egress — packet leaves the DPU)
- **Miss:** → DROP (untagged packets should never reach egress)

**Implementation:** `build_dl_encap_pipe()` in `dpu_pipeline.c` (lines 469–542).

---

## 12. TO_HOST Pipe — Software Fallback

A single BASIC pipe with one wildcard entry that forwards everything to the Host VF representor port:

```c
struct doca_flow_fwd fwd = {
    .type = DOCA_FLOW_FWD_PORT,
    .port_id = ctx->port_cfg.host_vf_port_id,  // port 2
};
```

This is the **catch-all** at the end of every priority chain:
- UL_MATCH[3].miss → TO_HOST
- DL_MATCH[3].miss → TO_HOST
- ROOT.miss → TO_HOST

Once a packet reaches the host, the ONVM manager delivers it to UPF-U, which performs software-based PDR lookup, decap/encap, and forwarding. This ensures **zero packet loss** — any traffic not (yet) programmed into hardware is handled by the existing software path.

**Implementation:** `build_to_host_pipe()` in `dpu_pipeline.c` (lines 152–193).

---

## 13. trTCM Metering (RFC 2698)

QoS enforcement uses **shared trTCM meters** (Two-Rate Three-Color Marker, RFC 2698) with color-blind mode:

### Rate Mapping

| trTCM Parameter | 3GPP Source | Formula |
|----------------|-------------|---------|
| CIR (Committed Information Rate) | GBR (Guaranteed Bit Rate) | `gbr_kbps × 1000 / 8` bytes/sec |
| CBS (Committed Burst Size) | — | `max(CIR/100, 4096)` bytes |
| PIR (Peak Information Rate) | MBR (Maximum Bit Rate) | `mbr_kbps × 1000 / 8` bytes/sec |
| PBS (Peak Burst Size) | — | `max(PIR/100, 4096)` bytes |

### Color Assignment

- **GREEN:** rate ≤ CIR (within guaranteed rate) → forward
- **YELLOW:** CIR < rate ≤ PIR (between GBR and MBR) → forward
- **RED:** rate > PIR (exceeds maximum) → drop

### No-QER Meter Skip

When both `gbr` and `mbr` are 0 (no QER associated with the PDR), `create_trtcm_meter()` returns `NO_METER_ID` (sentinel `UINT32_MAX`). The entry insertion code checks for this sentinel and **skips attaching a monitor** entirely — the entry passes directly to the color-gate, which will see an unmetered packet.

### Guard Rails

- `PIR >= CIR` enforced per RFC 2698 (`if (pir_bps < cir_bps) pir_bps = cir_bps`)
- If only GBR is 0 but MBR is set, CIR gets a floor of 1 Bps to avoid a degenerate 0-rate meter
- Minimum burst size of 4096 bytes to handle packet-level granularity

### Meter Lifecycle

```c
doca_flow_port_shared_resource_get(port, METER, &meter_id);  // allocate
doca_flow_port_shared_resource_set_cfg(port, METER, id, &cfg);  // configure
// ... entry uses monitor.shared_meter.shared_meter_id = meter_id
```

**Implementation:** `create_trtcm_meter()` in `dpu_pipeline.c` (lines 638–693).

---

## 14. Rule Installation — From PFCP to Silicon

The full journey of a PDR rule from PFCP Session Establishment to a hardware flow entry:

### Step 1: UPF-C receives PFCP Session Establishment/Modification

The SMF sends a PFCP message containing PDR + FAR + QER IEs. The UPF-C's PFCP handler resolves all cross-references (PDR→FAR, PDR→QER) and calls `upf_build_and_send_hw_offload()`.

### Step 2: Build `hw_offload_msg_t` (UPF-C)

`upf_hw_offload.h` extracts all offload-relevant fields:
- Direction from `sourceInterface` (ACCESS=UL, CORE/N6_LAN=DL)
- TEID, F-TEID from PDI (UL match)
- UE IP from PDI (DL match)
- QFI from PDI + QER
- SDF 5-tuple from `flowDescription` via `phb_parse_flow_description()`
- FAR apply-action, outer-header-creation (DL encap tunnel params)
- QER MBR/GBR rates

A globally unique `hw_rule_id` is assigned via atomic counter. This ID survives the entire pipeline and is used as `pkt_meta` for cross-pipe correlation (DL_MATCH → DL_ENCAP).

### Step 3: ONVM Ring (UPF-C → Host Agent)

```c
onvm_nflib_send_msg_to_nf(HOST_AGENT_SERVICE_ID, msg);
```

The message is `rte_calloc`'d from hugepages (visible to all DPDK secondaries) and delivered via the ONVM lockless inter-NF ring. Zero-copy, zero-lock.

### Step 4: Comch Transmission (Host Agent → DPU Agent)

The Host Agent's `msg_handler()` receives the `hw_offload_msg_t`, allocates a DOCA Comch send task, and submits it:

```c
doca_comch_client_task_send_alloc_init(client, conn, msg, sizeof(*msg), &task);
doca_task_submit(doca_comch_task_send_as_task(task));
```

The message crosses PCIe to the DPU ARM cores via DOCA Comch (Comm Channel). The Host Agent calls `rte_free(msg)` after submission (DOCA copies the payload internally).

### Step 5: DPU Agent receives, programs DOCA Flow

The DPU Agent's `comch_recv_cb()` deserialises the message and calls:

```c
dpu_pipeline_insert_rule(&g_pipeline, msg);
```

### Step 6: `dpu_pipeline_insert_rule()` — The Rule Materializer

This function (lines 795–975) performs:

1. **Bucket selection:** `precedence_to_bucket(msg->precedence)` → selects pipe index [0..3]
2. **Meter creation:** `create_trtcm_meter()` with UL or DL rates, or skip if no QER
3. **Match struct:** Populates TEID/QFI/inner-5-tuple (UL) or outer-5-tuple (DL)
4. **Per-entry match_mask:** Wildcards absent SDF fields (see §16)
5. **Actions:** Sets `pkt_meta = htonl(hw_rule_id)` (plus decap template for UL)
6. **Monitor:** Attaches shared meter if allocated
7. **Entry insertion:** `doca_flow_pipe_add_entry(queue=0, pipe, match, mask, actions, monitor, fwd=NULL, ...)`
8. **DL encap entry:** For DL rules with `ohc_desc == GTPU_UDP_IPV4`, a second entry is inserted into DL_ENCAP with the tunnel parameters
9. **Commit:** `doca_flow_entries_process(switch_port, 0, 0, 0)` — flushes entries to HW

---

## 15. SDF 5-Tuple Matching and Direction Reversal

### SDF Convention in 3GPP TS 29.244

The `flowDescription` in a PDI's SDF Filter is **always written in the UL direction** (from UE toward the network), regardless of whether the PDR is UL or DL. For example:

```
permit out ip from 10.0.0.0/8 to 192.168.1.1 80
```

This means: in the **UL direction**, source=UE subnet, destination=server:80.

### Uplink SDF Application (Direct)

For UL pipes, the SDF maps directly to **inner** headers (post-GTP-decap):

| SDF Field | Packet Field | Notes |
|-----------|-------------|-------|
| *(not used)* | `inner.ip4.src_ip` ← `ue_ipv4` | Always exact-matched to the UE's IP (see note below) |
| `sdf_dst_ip` | `inner.ip4.dst_ip` | Conditional; 0 = wildcard |
| `sdf_proto` | `inner.ip4.next_proto` | Conditional; 0 = wildcard |
| `sdf_src_port` | `inner.transport.src_port` | Conditional; 0 = wildcard |
| `sdf_dst_port` | `inner.transport.dst_port` | Conditional; 0 = wildcard |

> **Why `sdf_src_ip` is not applied separately:** Rules are installed per-session per-UE.
> In UL, the inner source IP is always the UE's own IP.  When SDF says `"from assigned"`,
> `sdf_src_ip` equals `ue_ipv4` — redundant. When SDF says `"from any"`, `sdf_src_ip == 0`,
> but the inner source is still the UE; matching on the exact `ue_ipv4` is more specific and
> correct.  For subnet SDFs like `"from 10.0.0.0/8"`, the UPF-C already knows the exact UE IP
> for this session, so exact-matching `ue_ipv4` is both correct and tighter than the subnet mask.
> The `sdf_src_ip` field is carried in the message for completeness and potential future use
> (e.g., multi-UE aggregation rules).

### Downlink SDF Application (Reversed)

For DL pipes, the packet direction is **opposite** to the SDF definition. The SDF's "source" becomes the packet's "destination" and vice versa. Additionally, DL matches on **outer** headers (pre-encap):

| SDF Field | DL Packet Field | Reason |
|-----------|----------------|--------|
| `sdf_dst_ip` | `outer.ip4.src_ip` | SDF dst = server, in DL the server is the source |
| UE IP | `outer.ip4.dst_ip` | UE is the destination in DL |
| `sdf_proto` | `outer.ip4.next_proto` | Protocol doesn't change direction |
| `sdf_dst_port` | `outer.transport.src_port` | SDF dst_port = server port, in DL it's src |
| `sdf_src_port` | `outer.transport.dst_port` | SDF src_port = UE port, in DL it's dst |

**Implementation:** `dpu_pipeline_insert_rule()` DL section in `dpu_pipeline.c` (lines 869–911).

---

## 16. Per-Entry Match Masks (Wildcard Support)

Not every PDR has a full SDF filter. Some are "catch-all" rules (e.g., match all traffic for a UE). DOCA Flow supports **per-entry match masks** — when a pipe template declares a field as CHANGEABLE (`UINT32_MAX` in both match and mask at creation time), each entry can set its own mask to selectively wildcard fields.

### Pipe Template (creation time)

```c
// match: all fields = UINT32_MAX (CHANGEABLE marker)
// mask:  all fields = UINT32_MAX (declares CHANGEABLE)
doca_flow_pipe_cfg_set_match(pipe_cfg, &match, &mask);
```

### Per-Entry Mask (insertion time)

```c
struct doca_flow_match match_mask = {};

// Always exact-match: TEID, UE IP
match_mask.tun.gtp_teid = UINT32_MAX;
match_mask.inner.ip4.src_ip = UINT32_MAX;

// QFI: exact-match if specified, wildcard if qfi=0
if (msg->qfi > 0)
    match_mask.tun.gtp_ext_psc_qfi = UINT8_MAX;
// else: stays 0 → wildcard (matches any QFI)

// SDF dst_ip: prefix mask or wildcard
if (msg->has_sdf && msg->sdf_dst_pref > 0)
    match_mask.inner.ip4.dst_ip = prefix_to_netmask(msg->sdf_dst_pref);
// else: stays 0 → wildcard (matches any dst_ip)

// SDF proto: exact or wildcard
if (msg->has_sdf && msg->sdf_proto > 0)
    match_mask.inner.ip4.next_proto = UINT8_MAX;

// SDF ports: exact or wildcard
if (msg->has_sdf && msg->sdf_src_port > 0)
    match_mask.inner.transport.src_port = UINT16_MAX;
if (msg->has_sdf && msg->sdf_dst_port > 0)
    match_mask.inner.transport.dst_port = UINT16_MAX;
```

### `prefix_to_netmask()` Helper

Converts a CIDR prefix length to a network-byte-order mask:

```c
prefix_to_netmask(24)  → 0xFFFFFF00 (in NBO: 0x00FFFFFF)
prefix_to_netmask(32)  → 0xFFFFFFFF (exact match)
prefix_to_netmask(0)   → 0x00000000 (wildcard)
```

This allows SDF filters like `10.0.0.0/8` to match any IP in the `10.x.x.x` range.

---

## 17. hw_offload_msg — The Cross-Domain Message

The `hw_offload_msg_t` struct is a **flat, packed C struct** that crosses three address spaces:

```
UPF-C (hugepage) → ONVM ring → Host Agent (hugepage) → DOCA Comch → DPU Agent (ARM heap)
```

### Size

~128 bytes — well within the 4 KiB DOCA Comch payload limit (verified by `_Static_assert`).

### Key Fields

| Field | Byte Order | Source |
|-------|-----------|--------|
| `magic` | HOST | `0x48574F46` ("HWOF") — sanity check at every boundary |
| `op` | — | `HW_OP_CREATE` (Phase 1 only) |
| `direction` | — | `HW_DIR_UPLINK` or `HW_DIR_DOWNLINK` |
| `hw_rule_id` | HOST | Atomic counter, globally unique, used as `pkt_meta` |
| `precedence` | HOST | 3GPP PDR precedence (lower = higher priority) |
| `teid` | HOST | GTP TEID (UL match) — `ntohl` already applied by UPDK |
| `ue_ipv4` | NBO | `struct in_addr` — raw copy from PFCP IE |
| `sdf_*` | HOST | Parsed from `flowDescription` by `phb_parse_flow_description()` |
| `ohc_teid` | HOST | FAR outer-header-creation TEID for DL encap |
| `ohc_ipv4` | NBO | FAR outer-header-creation gNB IP for DL encap |
| `mbr_ul/dl` | HOST | QER Maximum Bit Rate in kbps |
| `gbr_ul/dl` | HOST | QER Guaranteed Bit Rate in kbps |

### Byte-Order Contract

The DPU Agent is responsible for all HOST→NBO conversions at insertion time:
- `htonl(msg->teid)` for GTP TEID
- `htonl(msg->sdf_dst_ip)` for SDF IPs
- `htons(msg->sdf_src_port)` for SDF ports
- `htonl(msg->hw_rule_id)` for `pkt_meta`

Fields already in NBO (`ue_ipv4`, `ohc_ipv4`) are used as-is (`.s_addr`).

**Implementation:** `hw_offload_msg.h` in `onvm/upf/` (126 lines).

---

## 18. Host Agent — ONVM-to-DPU Bridge

The Host Agent (`5gc/host_agent/host_agent.c`) runs as **ONVM NF #3** (service ID `HOST_AGENT_SERVICE_ID = 3`). It is a DPDK secondary process with no data-plane packet processing — it only relays control messages.

### Lifecycle

1. `onvm_nflib_init()` — register as ONVM NF with `pkt_handler`, `msg_handler`, `user_actions`
2. `comch_init()` — open BF3 PF device, create DOCA Comch client, connect to DPU Agent's server
3. `onvm_nflib_run()` — enter main loop

### Message Relay (`msg_handler`)

```
UPF-C → (ONVM ring) → msg_handler() → comch_client_task_send → (PCIe) → DPU Agent
```

1. Validate `magic == HW_OFFLOAD_MAGIC`
2. Allocate Comch send task: `doca_comch_client_task_send_alloc_init()`
3. Submit: `doca_task_submit()`
4. Free hugepage message: `rte_free(msg)` (DOCA copies the buffer internally)

### Idle Callback (`callback_handler`)

```c
doca_pe_progress(comch_pe);  // drive Comch send completions + recv events
```

Called by ONVM's run loop when no packets are pending. Ensures Comch tasks complete.

### Comch Client Connection

Uses `doca_ctx_set_state_changed_cb()` to track connection state. When the context transitions to `DOCA_CTX_STATE_RUNNING`, the connection handle is cached. If the DPU Agent is not yet running, the Host Agent retries — Comch failure is **non-fatal** (messages are dropped, software path handles traffic).

---

## 19. DPU Agent — Standalone DOCA Application

The DPU Agent (`5gc/dpu_agent/dpu_agent.c`) runs natively on BlueField-3 ARM cores. It is the **primary owner** of the physical HW devices (no `--proc-type` flag needed).

### Lifecycle

1. **`doca_argp_init()`** — initialise DOCA Arg Parser with `&g_cfg` config struct
2. **`doca_argp_set_dpdk_program(dpdk_init_cb)`** — register EAL init callback
3. **`register_dpu_agent_params()`** — register 14 application-specific CLI/JSON params
4. **`doca_argp_start(argc, argv)`** — parse CLI + JSON (`-j`), invoke DPDK callback (`rte_eal_init`), invoke all parameter callbacks to populate `g_cfg`
5. **`finalize_config()`** — parse MAC/IP strings → binary, validate required fields
6. **Device opening:** `open_doca_device_by_pci()` for N3, N6, and VF
7. **Comch server:** `comch_server_init()` — opens host PF representor via `open_doca_device_rep_by_pci()`, then creates Comch server bound to that representor
8. **Pipeline:** `dpu_pipeline_init()` — builds the 13-pipe hierarchy
9. **Main loop:** `while (g_running) doca_pe_progress(g_comch_pe)`
10. **Shutdown:** `dpu_pipeline_destroy()`, `comch_server_destroy()`, `doca_dev_close()`, `rte_eal_cleanup()`, `doca_argp_destroy()`

### DOCA Arg Parser Configuration

Deployment-specific parameters are managed by **`doca_argp`** (DOCA Arg Parser), the native DOCA SDK configuration framework used by all NVIDIA DOCA sample applications. This eliminates external dependencies (no libyaml needed on the DPU).

Parameters can be provided via **CLI flags**, a **JSON config file** (`-j` / `--json`), or both (CLI overrides JSON). The JSON file follows the standard three-section DOCA layout (`config/dpu_agent_params.json`):

```json
{
    "doca_dpdk_flags": {
        "devices": [
            { "device": "pf", "id": "0000:03:00.0", "hws": true },
            { "device": "pf", "id": "0000:03:00.1", "hws": true }
        ],
        "core-list": "0-3",
        "flags": ""
    },
    "doca_general_flags": { "log-level": 60 },
    "doca_program_flags": {
        "comch-pci": "03:00.0",
        "rep-pci": "b5:00.0",
        "server-name": "dpu_agent",
        "n3-pci": "03:00.0",
        "n6-pci": "03:00.1",
        "upf-n3-ip": "192.168.1.1",
        "upf-n3-mac": "00:11:22:33:44:55",
        "gnb-mac": "00:11:22:33:44:66",
        "upf-n6-mac": "00:11:22:33:44:77",
        "dn-gw-mac": "00:11:22:33:44:88"
    }
}
```

**Key names** in `doca_program_flags` match the `--long-name` registered via `doca_argp_param_set_long_name()`. The `hws: true` flag in `doca_dpdk_flags` auto-generates HW-steering devargs (`dv_flow_en=2,fdb_def_rule_en=0,...`).

`dpu_agent_config.c` registers 14 parameters (11 STRING, 3 INT) using callback macros (`STRING_CB`, `INT_CB`) and helper functions (`reg_str`, `reg_int`). Two parameters are marked mandatory: `--rep-pci` and `--upf-n3-ip`.

### Comch Receive Path

```c
comch_recv_cb() → validate magic → switch(op) → dpu_pipeline_insert_rule()
```

### Device Management

Three `doca_dev` handles are opened — one per physical port. The VF device falls back to the N3 device if `vf_pci` is not specified. Devices are passed to `create_port()` which calls `doca_flow_port_cfg_set_dev()`.

Additionally, a `doca_dev_rep` is opened for the Comch server (`comch.rep_pci`). This representor identifies the host-side PF/VF on the BF3, allowing the DOCA Comch server to accept connections only from the designated host client. This is a **security requirement** per the DOCA Comch documentation: *"Only clients on the PF/VF/SF represented by the `doca_dev_rep` provided upon server creation can connect."*

### CLI Example

With JSON config (recommended — edit `config/dpu_agent_params.json` once per deployment):

```bash
./dpu_agent -j config/dpu_agent_params.json
```

With CLI overrides (useful for testing — overrides JSON values):

```bash
./dpu_agent -j config/dpu_agent_params.json \
  --rep-pci b5:00.1 \
  --upf-n3-ip 10.0.0.1
```

Pure CLI (no JSON file):

```bash
./dpu_agent \
  -a 03:00.0,dv_flow_en=2,fdb_def_rule_en=0,vport_match=1,repr_matching_en=0,dv_xmeta_en=4 \
  -a 03:00.1,dv_flow_en=2,fdb_def_rule_en=0,vport_match=1,repr_matching_en=0,dv_xmeta_en=4 \
  -- \
  --rep-pci b5:00.0 \
  --upf-n3-ip 192.168.1.1
```

> **`--rep-pci`** (required): The BF3-side representor PCI address of the host PF that runs the Host Agent. This is hardware-dependent and can be discovered on the DPU with `doca_caps` or by listing representors under `/sys/class/net/`. The DOCA Comch API requires this representor so the server knows which host-side PCIe function is allowed to connect.

---

## 20. UPF-C Hook — Building the Offload Message

`upf_hw_offload.h` (`5gc/upf_c/`) is an **inline-only header** included by the PFCP handler. It keeps UPF-C free of any DOCA headers — only DPDK + ONVM + UPDK types.

### Guard Conditions (what gets offloaded)

Only PDRs meeting **all** of these criteria are offloaded:
- FAR apply_action includes `FORW` (forwarding)
- UL: has a valid F-TEID with non-zero TEID
- DL: has a UE IP address (IPv4)
- Source interface is ACCESS (UL) or CORE/N6_LAN (DL)

DROP, BUFF, and NOCP actions are not offloaded in Phase 1.

### SDF Parsing

```c
phb_parse_flow_description(pdr->pdi.sdfFilter.flowDescription, &tmp);
```

The `phb_parse_flow_description()` function (from `pdr_hash_bypass.h`) parses IPFilterRule syntax (e.g., `permit out ip from 10.0.0.0/8 to 192.168.1.1 80`) into a `phb_candidate_t` struct with separate IP/prefix/port/proto fields.

### QER Selection and Extraction

A PDR can reference up to two QERs — one is a session-AMBR QER, the other is the per-flow QER that carries `qosFlowIdentifier` (and the MBR/GBR rates relevant to our meter). The UPF-C's `UpfPdrSelectQfiQer()` resolves the correct one into `pdr->qer` by scanning `pdr->qers[]` for the QFI-bearing entry, with fallback to `qers[0]`.

```c
/* Use pdr->qer — the QFI-resolved QER (same one used for encap_qfi) */
if (pdr->qer) {
    const UPDK_QER *qer = pdr->qer;
    msg->mbr_ul = qer->maximumBitrate.ul;  // kbps
    msg->mbr_dl = qer->maximumBitrate.dl;
    msg->gbr_ul = qer->guaranteedBitrate.ul;
    msg->gbr_dl = qer->guaranteedBitrate.dl;
}
```

Both the `encap_qfi` (for PSC extension) and the MBR/GBR bit-rates are extracted from the same resolved `pdr->qer`, ensuring consistency.

### Failure Path

If `onvm_nflib_send_msg_to_nf()` fails (Host Agent not running, ring full), the message is freed and a warning is logged. **The software path remains active** — the PDR is still installed in the SW lookup table. The offload is best-effort.

---

## 21. Byte-Order Contracts

| Value | In `hw_offload_msg_t` | Conversion at DPU Agent |
|-------|----------------------|-------------------------|
| `teid` | HOST (ntohl by UPDK) | `htonl(msg->teid)` |
| `ue_ipv4` | NBO (`struct in_addr`) | Used as-is: `msg->ue_ipv4.s_addr` |
| `sdf_src_ip`, `sdf_dst_ip` | HOST (phb parser) | `htonl(msg->sdf_dst_ip)` |
| `sdf_src_port`, `sdf_dst_port` | HOST | `htons(msg->sdf_src_port)` |
| `ohc_teid` | HOST (ntohl by UPDK) | `htonl(msg->ohc_teid)` |
| `ohc_ipv4` | NBO (`struct in_addr`) | Used as-is: `msg->ohc_ipv4.s_addr` |
| `hw_rule_id` (→ pkt_meta) | HOST | `htonl(msg->hw_rule_id)` |
| `mbr_*`, `gbr_*` | HOST (kbps) | Converted to bytes/sec for meter config |

**Rule:** DOCA Flow expects all IP/port fields in **Network Byte Order (NBO)**. The DPU Agent performs all conversions at insertion time.

---

## 22. EAL Initialization and Devargs

The DPU Agent calls `rte_eal_init()` to initialize DPDK, which is required by DOCA Flow for memory management and device probing. Critical devargs are passed via `-a` flags:

| Devarg | Value | Purpose |
|--------|-------|---------|
| `dv_flow_en` | `2` | Enable DOCA Flow HWS (Hardware Steering) mode |
| `fdb_def_rule_en` | `0` | Disable default FDB rule (we control all steering) |
| `vport_match` | `1` | Enable virtual port matching in eSwitch |
| `repr_matching_en` | `0` | Disable representor matching (we use port_id) |
| `dv_xmeta_en` | `4` | Extended metadata — enables pkt_meta survival across eSwitch |

`dv_xmeta_en=4` is **critical** — without it, the `pkt_meta` tag set by DL_MATCH would not survive the cross-domain transit to DL_ENCAP on the egress side.

> **Note (Relaxed Matching Mode):** In DOCA Flow v3.x, HWS mode (`dv_flow_en=2`, configured via `"switch,hws"` mode_args) uses **relaxed matching by default**. No explicit flag is needed. In relaxed mode, type selectors (`l3_type`, `l4_type_ext`, `tun.type`) in the `outer`, `inner`, and `tun` parts of `doca_flow_match` are used **only for the type cast of the underlying unions** — they do not enforce a hardware match on the specific protocol. It is the application's responsibility to ensure that packets arriving at a pipe have the expected header structure. Our pipeline achieves this via the ROOT control pipe, which steers packets by `port_id` and GTP-U protocol before they reach the match pipes.

---

## 23. Pipeline Teardown

`dpu_pipeline_destroy()` tears down resources in reverse creation order:

1. ROOT pipe (control entries + pipe)
2. DL_ENCAP pipe
3. DL_MATCH[0..3] pipes
4. UL_MATCH[0..3] pipes
5. DL_COLOR_GATE, UL_COLOR_GATE pipes
6. TO_HOST pipe
7. All ports (`doca_flow_port_stop()`)
8. `doca_flow_destroy()` — releases DOCA Flow globally

**Implementation:** `dpu_pipeline_destroy()` in `dpu_pipeline.c` (lines 984–1025).

---

## 24. Design Decisions and Alternatives Considered

### Why Pipe Chaining for Precedence (Not ACL/LPM/Control)?

| Alternative | Why Rejected |
|-------------|-------------|
| **ACL Pipe** | DOCA docs state ACL pipes support "only non-shared counters" — cannot attach shared meters for trTCM QoS |
| **LPM Pipe** | Cannot be root, only matches IP addresses (no L4 ports, protocol), no shared meter support |
| **Control Pipe** (for matching) | API supports actions+monitor, but no NVIDIA sample validates it for high-volume per-PDR matching with decap+meter. Control pipes are documented for root-level steering (exactly how we use ROOT). |
| **Single pipe, insertion order** | DOCA docs clarify insertion-order priority applies to overlapping entries across different pipes, not within the same pipe. Chaining is explicitly labeled "Recommended" in NVIDIA documentation. |

### Why `*.transport.*` for L4 Port Matching?

In DOCA Flow's relaxed match mode, `tcp`, `udp`, and `transport` are union members of `doca_flow_header_format` sharing the same memory. The `transport` member (type `doca_flow_header_l4_port`) provides a protocol-agnostic accessor for `src_port`/`dst_port`. We use it for all SDF port matching to avoid implying a TCP-only assumption. Protocol-specific accessors (`.udp.l4_port`) are reserved for cases where the protocol is known (e.g., GTP-U UDP port 2152 in the ROOT pipe and DL_ENCAP).

### Why pkt_meta for DL Cross-Pipe Correlation?

DL processing spans two domains (DEFAULT ingress → EGRESS):
- DL_MATCH (DEFAULT) tags the packet with `pkt_meta = hw_rule_id`
- DL_ENCAP (EGRESS) matches `pkt_meta` to select the right GTP tunnel

The `dv_xmeta_en=4` devarg ensures pkt_meta survives the domain crossing. This is the standard DOCA Flow pattern for egress encapsulation.

### Why 4 Priority Buckets?

4 buckets with a range of 64 each covers precedence values 0–255, which spans the entire 3GPP precedence range. Real deployments typically use a handful of distinct precedence values (e.g., 128 for default bearers, 255 for best-effort). 4 buckets provides sufficient granularity without creating too many pipes.

### Why No Batching?

Currently, `doca_flow_entries_process()` is called after each rule insertion (no `DOCA_FLOW_WAIT_FOR_BATCH` flag). This is correct for the initial Phase 1 where rules trickle in one at a time via PFCP. Batching is a performance optimization for bulk loading scenarios and can be added in Phase 2.

---

## 25. Current Limitations and Future Work

| Item | Status | Description |
|------|--------|-------------|
| **Rule deletion** (`HW_OP_DELETE`) | Phase 2 | Entry handles need to be stored in a lookup table by `hw_rule_id` |
| **Rule update** (`HW_OP_UPDATE`) | Phase 2 | May require delete+re-insert or `doca_flow_pipe_entry_update()` |
| **Batched insertion** | Optimization | Use `DOCA_FLOW_WAIT_FOR_BATCH` for bulk PDR loading |
| **VF representor probing** | Deployment | `host_vf_rep = NULL` — needs `doca_dev_rep` probing for host VF |
| **4G / no-PSC** | Scoped out | Only 5G SA with PSC extension is supported. 4G would require dual action templates |
| **IPv6** | Not implemented | Pipe templates only match IPv4 headers |
| **Multiple QERs per PDR** | Partial | The per-flow QER (with `qosFlowIdentifier`) is selected via `UpfPdrSelectQfiQer()`; session-AMBR QER is not applied as a second meter |
| **Comch buffer lifetime** | Likely safe | `rte_free()` after Comch submit — DOCA likely copies the buffer, but moving free to completion callback would be safest |
| **Counter statistics** | Not implemented | Shared counters could be attached alongside meters for reporting |
| **DROP/BUFF actions** | Not offloaded | Only FORWARD rules are offloaded; DROP/BUFF remain software-handled |
| **`fteid_ipv4` matching** | By design | UL matches TEID only; F-TEID IP is implied by the physical N3 port in single-BF3 deployments. Field is carried for future multi-UPF use |
| **`sdf_src_ip` in UL/DL** | By design | Not applied to match; `ue_ipv4` is used instead (exact, per-UE). See §15 for rationale |

---

## Appendix A: Commit History

| Hash | Message |
|------|---------|
| `30471dd` | feat: Split-Agent DOCA Flow offload for BF3 DPU (ICNP) |
| `64901a2` | fix: correct DOCA Flow/Comch API patterns against SDK samples |
| `ec76b9b` | fix: restore RFC 2698 (trTCM) metering |
| `7fabeea` | fix(dpu_pipeline): 4 DOCA Flow bugs found during docs re-review |
| `482e537` | fix(dpu_pipeline): 3 API bugs from DOCA SDK API reference docs |
| `90c7de7` | feat(dpu_pipeline): SDF matching, precedence buckets, port binding, encap PSC, no-QER meter skip |
| `d264d21` | fix(dpu_pipeline): add L4 port matching for full SDF 5-tuple enforcement |
| `06d2da3` | refactor(dpu_pipeline): use protocol-agnostic .transport accessor for SDF L4 ports |
| `13e6075` | fix(upf_hw_offload): use pdr->qer (QFI-resolved) for MBR/GBR instead of qers[0] |
| `556b1b8` | docs: update technical doc for QER selection fix and transport accessor |
| `b9d3932` | fix(dpu_pipeline): QFI wildcard mask; docs: sdf_src_ip, fteid_ipv4, relaxed mode |

---

## Appendix B: File Cross-Reference

```
onvm/upf/hw_offload_msg.h          ← Shared struct definition
onvm/utlt/upf_events.h             ← HOST_AGENT_SERVICE_ID = 3
onvm/upf/pdr_hash_bypass.h         ← phb_parse_flow_description(), SDF parser
5gc/upf_c/upf_hw_offload.h         ← UPF-C → hw_offload_msg builder + sender
5gc/host_agent/host_agent.c         ← ONVM NF #3, Comch client relay
5gc/dpu_agent/dpu_agent.c           ← BF3 ARM app, Comch server, main loop
5gc/dpu_agent/dpu_agent_config.h    ← doca_argp config struct + registration API
5gc/dpu_agent/dpu_agent_config.c    ← doca_argp callbacks + register_dpu_agent_params()
5gc/dpu_agent/config/dpu_agent_params.json ← DOCA Arg Parser JSON config (PCI, MAC, IP)
5gc/dpu_agent/dpu_pipeline.h        ← Pipeline context + API declarations
5gc/dpu_agent/dpu_pipeline.c        ← 13-pipe DOCA Flow hierarchy
```
