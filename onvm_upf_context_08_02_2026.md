# L²5GC+ `onvm-upf` — Comprehensive Context File (2026-02-08)

This document is a “context injection” for new conversations about the L²5GC+ `onvm-upf` codebase: architecture, control/data paths, memory model, classifier snapshots, QoS/buffering, configs, and operational assumptions.

It is written to be used as a single upfront prompt for future technical discussions and debugging.

---

## 0) One-sentence summary

`onvm-upf` is a **DPDK/OpenNetVM-based 5G UPF** split into **UPF-C (control plane, PFCP/N4)** and **UPF-U (user plane, dataplane)** with **DPDK multi-process shared-memory session state** and a **versioned seqlock classifier-snapshot distribution mechanism** (flip + ACK-based GC).

---

## 1) What changed since `onvm_upf_context_14_01_2026.md` (high level)

Recent fastpath changes on `optimize/fastpath-2`:
- **Unified GTP-U parse**: added `parse_gtpu_once()` + `gtp_parse_result_t` in `onvm/upf/gtp.h` so uplink extracts **TEID/QFI/header lengths once** and reuses them.
- **Uplink PDR lookup now consumes parsed GTP**: `GetPdrByTeid(pkt, &gtp_info)` uses the precomputed offsets; decap uses `gtp_info.outer_hdr_len` instead of recomputing.
- **PDR now carries multiple QER pointers**: `UPDK_PDR` extended with `qers[2]` and `qer_count` (`onvm/updk/updk/rule_pdr.h`) populated from UPF-C on Create/Update PDR.
- **UE QoS table population no longer scans session->pdr_list**: `GetQerByUEIpAddressFromPdr()` in `5gc/upf_u/upf_u.c` derives (AMBR/GBR/MBR-like) values from `pdr->qers[]`.
- **Key correctness insight**: `pdr->qer` is still set to `qers[0]` (legacy), but `qers[0]` may not contain bitrate IEs (`maximumBitrate/guaranteedBitrate`). Bitrate/QoS configuration can live in another slot (e.g. `qers[1]`).

Still pending / known “fastpath not yet clean” items:
- Session lookup is still done in the per-packet path mainly to call `ConfigureQerFlows()` (meter/flow-table configuration).
- SDF `flowDescription` string parsing still exists in dataplane (and may happen per packet for DL policing decisions).
- QER selection rules are not fully formalized (which QER is for encapsulation/QFI vs metering vs UE-table rates).

---

## 2) High-level architecture

### 2.1 Components
- **ONVM Manager** (`onvm/onvm_mgr`): DPDK primary process, owns ports/queues; schedules packets to NFs.
- **UPF-C (Control plane NF)** (`5gc/upf_c`):
  - PFCP/N4 procedures (Create/Update/Delete Session).
  - Owns rule/session objects (PDR/FAR/QER) and compiles classifier snapshots.
  - Publishes snapshots via a shared control-slot (memzone) and notifies UPF-U to flip.
  - Refreshes PDR → QER pointer associations (`pdr->qers[]`) when rules change.
- **UPF-U (User plane NF)** (`5gc/upf_u`):
  - Per-packet dataplane: parse → classify → FAR action → (optional) QoS/buffering → output.
  - Consumes published classifier snapshots and flips at burst boundaries.
- **Classifier subsystem** (`5gc/classifiers`):
  - Multiple backends (PS/TSS/PTSS) exposed through a C wrapper.
  - Snapshot handle is immutable; descriptor cookie is used to return match result.
- **Shared libs & state** (`onvm/*`):
  - `onvm/upf/*`: UPF shared context + shared tables + memzones (including classifier control slot).
  - `onvm/pfcp/*`: PFCP encoding/decoding.
  - `onvm/updk/*`: internal rule structures (UPDK_PDR/FAR/QER).
  - `onvm/utlt/*`: utilities + event IDs.

### 2.2 CP/DP split
- **UPF-C** is “authoritative” for rule/session state updates.
- **UPF-U** is “authoritative” for per-packet decisions and burst scheduling.
- Distribution is **shared memory + versioned pointer flip + ACK-based GC**, not RPC.

---

## 3) Repository layout (important paths)

- `5gc/`
  - `upf_c/` — UPF control-plane NF (PFCP/N4)
  - `upf_u/` — UPF user-plane NF (dataplane)
  - `classifiers/` — classifier engines + wrappers + UPF adapter
- `onvm/`
  - `onvm_mgr/` — ONVM manager
  - `onvm_nflib/` — ONVM NF library
  - `upf/` — shared UPF context, memzones, session tables, classifier control slot
  - `pfcp/`, `updk/`, `utlt/`, `list/`, `logger/`

Key configs:
- UPF-U: `5gc/upf_u/config/upf_u.yaml`
- UPF-C: `5gc/upf_c/config/upfcfg.yaml`

---

## 4) Build & environment assumptions

- DPDK submodule is pinned (repo history suggests DPDK v24.11.x); builds via Meson/Ninja.
- Typical entrypoint: `scripts/build.sh` (Meson setup + Ninja build).

---

## 5) Inter-NF signaling and shared memory

### 5.1 Service IDs and events
Central definition: `onvm/utlt/upf_events.h`

- **Service IDs**
  - `UPF_U_SERVICE_ID = 1`
  - `UPF_C_SERVICE_ID = 2`
- **Classifier flip protocol**
  - `EVT_CLS_GC_REQ` (UPF-C → UPF-U): “flip to new classifier version”
  - `EVT_CLS_GC_ACK` (UPF-U → UPF-C): “flip complete; safe to GC up to this version”

UPF-U sends events via:
- `UpfSendEvt1(dest_sid, type, arg0)` in `5gc/upf_u/upf_u.c`

### 5.2 Shared session state (DPDK multi-process)
Session objects are shared between UPF-C and UPF-U via DPDK multi-process hugepage memory.

Key file: `onvm/upf/upf.c`
- A shared pool `upf_session_table` stores `UpfSession` objects in a contiguous array (`data[]`).
- Maps (TEID→session index, UE-IP→session index) are shared `rte_hash` tables.
- Pointers to these shared structures are published via memzones (primary writes pointer; secondaries lookup):
  - `MZ_PFCP_SESSION_TABLE_INFO`
  - `MZ_TEID_TO_UPF_SESSION_MAP_INFO`
  - `MZ_UE_IP_TO_UPF_SESSION_MAP_INFO`

Who creates these:
- ONVM manager (primary) initializes shared tables in `onvm/onvm_mgr/onvm_init.c`.
- UPF-C and UPF-U (secondaries) call the same init routines; they attach via `rte_memzone_lookup()` and use the shared structures directly.

### 5.3 Shared classifier control-slot (memzone)
Header: `onvm/upf/upf_cls_ctrl.h`

- Memzone name: `MZ_UPF_CLS_CTRL = "UPF_CLS_CTRL_SLOT"`
- Structure: `upf_cls_ctrl_t { void *active; uint32_t version; }`
- Initialization: `UpfClsCtrlInit()` in `onvm/upf/upf_context.c` maps/reserves the control slot and sets a stable initial state:
  - `active = NULL`
  - `version = 0` (EVEN = stable)

### 5.4 Publish/flip protocol (seqlock + ACK GC)

#### (A) UPF-C: publish a fresh immutable snapshot
Key file: `5gc/upf_c/n4_onvm_pfcp_handler.c`

- `UpfClsRebuildAndPublish(out_version)` builds a new classifier snapshot and calls `upf_cls_publish(new_snap, &retired)`:
  - `version` becomes ODD during write (writer active)
  - `active` pointer is atomically swapped to the new snapshot
  - `version` becomes EVEN when stable (reader-safe)
- UPF-C then sends `EVT_CLS_GC_REQ(ver)` to UPF-U.

#### (B) UPF-U: flip at burst boundary + ACK
Key file: `5gc/upf_u/upf_u.c`

- UPF-U receives `EVT_CLS_GC_REQ` and sets `flip_pending=1`.
- At burst boundary it calls `UpfClsMaybeFlipAndAck()` which performs a seqlock read:
  1. read `version` until it is EVEN
  2. read `active` pointer
  3. re-read `version`; accept only if unchanged and EVEN
  4. commit locally to `g_cls_local.ptr` and clear `flip_pending`
  5. send `EVT_CLS_GC_ACK(ver)` back to UPF-C

#### (C) UPF-C: GC retired snapshots / PDR objects after ACK
- UPF-C frees/destroys retired snapshots only after it receives an ACK for a stable version.
- PDR objects can be deferred and freed after ACK (“grace period”) to avoid use-after-free when descriptors publish `UpfPDR*` cookies.

---

## 6) Classifier subsystem details (C API wrapping C++ engines)

Location: `5gc/classifiers/`

- Backends: PS/TSS/PTSS are exposed via `classifier_wrapper.h/.cpp`.
- Allocation shim: `cls_heap_dpdk_shim.cpp` routes aligned `new/delete` to `rte_malloc/rte_free` (DPDK hugepage heap).
- UPF adapter: `upf_cls_adapter.cpp` converts PDRs to rules; descriptor cookie is used to return match results to UPF-U.

Descriptor semantics (current design):
- During snapshot build, descriptor is set to a pointer cookie (typically `UpfPDR*`).
- In UPF-U, `UpfClassifyGetPdrPtr(key)` returns the PDR pointer cookie.

---

## 7) UPF-U dataplane behavior (fastpath)

Primary file: `5gc/upf_u/upf_u.c`

### 7.1 Direction detection
- Uplink: `iph->dst_addr == SELF_IP` (expects outer UDP dst port = 2152).
- Downlink: otherwise.

### 7.2 Uplink parsing (single-pass GTP-U)
Header: `onvm/upf/gtp.h`

- `parse_gtpu_once(pkt, &gtp_info)` extracts:
  - `teid` (host order)
  - `qfi` (0 if absent)
  - `gtp_hdr_len` and `outer_hdr_len` (used for decap and inner-header offset)
- Important constraint: parsing uses `rte_pktmbuf_mtod_offset()` with `rte_pktmbuf_data_len(pkt)` bounds checks; this assumes required bytes are in the first segment.

### 7.3 PDR lookup
- Uplink: `GetPdrByTeid(pkt, &gtp_info)`
  - uses `gtp_info.outer_hdr_len` to locate inner IPv4 header
  - builds classifier key with TEID + inner 5-tuple + `gtp_info.qfi` (if used by rules)
  - calls `UpfClassifyGetPdrPtr(&key)`
- Downlink: `GetPdrByUeIpAddress(pkt, ue_ip)`
  - builds classifier key using outer 5-tuple + `ue_ip` and calls `UpfClassifyGetPdrPtr(&key)`

### 7.4 Outer header removal (decap)
If `pdr->outerHeaderRemoval == OUTER_HEADER_REMOVAL_GTP_IP4`, the dataplane uses:
- `rte_pktmbuf_adj(pkt, gtp_info.outer_hdr_len)`

### 7.5 FAR application
Function: `HandlePacketWithFar(pkt, pdr->far, qer, meta)`

- Uses `pdr->far` for applyAction (DROP/FORW/BUFF/NOCP, etc.).
- If forwarding requires encapsulation, `Encap(pkt, far, qer)` is invoked.

### 7.6 QER usage and current ambiguity
`UPDK_PDR` currently contains both:
- `pdr->qer` (legacy single pointer; set to `qers[0]` by UPF-C)
- `pdr->qers[]` + `pdr->qer_count` (packed list; authoritative for “multiple QERs per PDR”)

Current behavior:
- Encapsulation/QFI path uses `pdr->qer` (slot 0).
- UE QoS table population uses `pdr->qers[]` (scans up to 2).

Known issue / key insight:
- `qers[0]` may *not* contain bitrate IEs (`maximumBitrate/guaranteedBitrate`); the MBR/GBR values can live in `qers[1]`.
- Therefore: any logic that needs bitrates must scan `pdr->qers[]` rather than trusting `pdr->qer`.

### 7.7 UE QoS table (DL) — PDR-local derivation
Function: `GetQerByUEIpAddressFromPdr(ue_ip, pdr, ip_str)`

- Replaces the old slow path that scanned `session->pdr_list`.
- Selection rule matches legacy behavior:
  - `AMBR` (implementation-defined) is derived as `max(QER.maximumBitrate.dl)` across associated QERs.
  - `GBR/MBR` are taken from a QER only when both flags are present.

### 7.8 QoS enforcement in packet_handler (DL OUT path)
Dataplane currently does both:
- **Policing** (trTCM meter → color → potential drop)
- **Shaping** (token-bucket “shape by waiting”: spin/sleep until enough tokens, then forward)

Note: SDF `flowDescription` parsing still occurs in fastpath to compute flow keys for metering and to decide “QoS vs non-QoS”.

---

## 8) UPF-C control plane behavior (PDR/QER pointer consistency)

Primary file: `5gc/upf_c/n4_onvm_pfcp_handler.c`

On CreatePDR / UpdatePDR:
- `pdr->qerId[]` is updated from PFCP TLVs.
- UPF-C resolves QER IDs to pointers and refreshes:
  - `pdr->qers[0..]`
  - `pdr->qer_count`
  - `pdr->qer = qers[0]` (legacy pointer for older dataplane call sites)

UpdatePDR QER association policy (current):
- `UpdatePDR` contains one QERID field, so multi-QER update semantics require a local policy.
- Current policy is “add if an empty slot exists; ignore if already present; warn+ignore if full”.

---

## 9) Operational invariants / “things that must match”

1. Service IDs: UPF-U=1, UPF-C=2.
2. Memzone names consistent across processes:
   - classifier control slot: `UPF_CLS_CTRL_SLOT`
   - session/map pointer slots: `MProc_pfcp_session_table_info`, `MProc_TeidToUpfSessionMap_info`, `MProc_UeIpToUpfSessionMap_info`
3. DPDK port numbering aligns with `5gc/upf_u/config/upf_u.yaml` and ONVM portmask.
4. Descriptor cookie type is consistent (pointer cookie vs id cookie).
5. Snapshot lifetime: UPF-C must not free snapshots/PDRs until ACK indicates dataplane flipped.

---

## 10) Debugging checklist (common failure modes)

- **“No snapshot yet” drops**: UPF-U hasn’t mapped `UPF_CLS_CTRL_SLOT` or UPF-C never published.
- **Rule updates not taking effect**: UPF-U not receiving `EVT_CLS_GC_REQ` or not flipping at burst boundary.
- **UAF after updates**: freeing PDRs/snapshots before ACK; multi-worker dataplane would require per-worker ACK/epoch.
- **Uplink PDR not found**: `parse_gtpu_once()` fails (extension parsing/length/segmentation) or inner offset wrong; old “scan ±4 bytes” fallback is removed.
- **DL UE table not populated**: `qers[0]` lacks `maximumBitrate`; ensure `pdr->qers[]` is populated and scanned.
- **QoS throughput collapse**: meter configuration still happens via session lookup; SDF string parsing + sleeps in shaping path add latency/jitter.

---

## 11) Quick “what to reference” map

- Shared control slot + init: `onvm/upf/upf_cls_ctrl.h`, `onvm/upf/upf_context.c`
- Snapshot publish/GC: `5gc/upf_c/n4_onvm_pfcp_handler.c`
- Flip + ACK: `5gc/upf_u/upf_u.c` (`UpfClsMaybeFlipAndAck`)
- Shared sessions/maps: `onvm/upf/upf.c` (memzones + rte_hash)
- Unified GTP parse: `onvm/upf/gtp.h` (`parse_gtpu_once`)
- Dataplane fastpath: `5gc/upf_u/upf_u.c`
- Classifier wrapper: `5gc/classifiers/classifier_wrapper.h/.cpp`
- Adapter: `5gc/classifiers/upf_cls_adapter.cpp`
- Events: `onvm/utlt/upf_events.h`

---

## 12) Notes / assumptions

- This context is intended to match the `optimize/fastpath-2` direction as of **2026-02-08**; details may diverge on other branches.
- Outstanding design decision: formalize “which QER is used for what” (encapsulation/QFI vs bitrates vs gate status) and move meter/key derivation out of per-packet fastpath when possible.

---
END OF CONTEXT

