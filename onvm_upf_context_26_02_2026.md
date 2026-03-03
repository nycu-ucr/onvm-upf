# L²5GC+ `onvm-upf` — Comprehensive Context File (2026-02-26)

This document is a “context injection” for new conversations about the L²5GC+ `onvm-upf` codebase: architecture, control/data paths, memory model, classifier snapshots, fastpath optimizations, QoS/metering, and operational assumptions.

It is written to be used as a single upfront prompt for future technical discussions and debugging.

This version is updated to match the **current code on the `optimize/fastpath-4-with-rte-hash` line** as of **2026-02-26**.

---

## 0) One-sentence summary

`onvm-upf` is a **DPDK/OpenNetVM-based 5G UPF** split into **UPF-C (control plane, PFCP/N4)** and **UPF-U (user plane, dataplane)** with **DPDK multi-process shared-memory session state**, an **immutable, versioned classifier-snapshot distribution mechanism** (seqlock publish → burst-boundary flip → ACK-based GC), and a **TEID/UE-IP hash-bypass fastpath** in front of the general classifier.

---

## 1) What changed since `onvm_upf_context_08_02_2026.md` (high level)

Newer fastpath/control-path work (post fastpath-2):

- **Per-packet session lookup removed from UPF-U fastpath**
  - The dataplane no longer needs to call `UpfSessionFindByUeIP/Teid` to derive QER/QoS state.
  - QoS plumbing is now derived directly from the **matched PDR** (resolved QER pointers, precomputed SDF integers).

- **Control-plane (UPF-C) now precomputes PDR-local QoS helpers**
  - `UpfPdrPrecompileSdf()` computes `pdr->meter_key / fd_target / has_fd` from `flowDescription` at Create/Update PDR time.
  - `UpfPdrSelectQfiQer()` selects and stores the **QFI-bearing QER** into `pdr->qer` (no longer “qers[0] by convention”).

- **Hash-bypass PDR classification added (TEID/UE-IP)**
  - UPF-C builds an immutable `phb_table_t` (“PDR hash bypass”) alongside the classifier snapshot and publishes it in the same control slot.
  - UPF-U tries hash bypass first, then falls back to PartitionSort (`cls_classify_packet`) on misses/poisoned buckets.

- **Classifier wrapper hot-path allocation removed**
  - `Packet` moved from a heap-backed `std::vector` to a fixed-size `std::array`, avoiding per-packet heap allocation in `to_cpp_pkt()`.

---

## 2) High-level architecture

### 2.1 Components
- **ONVM Manager** (`onvm/onvm_mgr`): DPDK primary process; owns ports/queues; schedules packets to NFs.
- **UPF-C (Control plane NF)** (`5gc/upf_c`):
  - PFCP/N4 procedures (Create/Update/Delete Session).
  - Owns rule objects (PDR/FAR/QER) and compiles classifier snapshots.
  - Builds and publishes:
    - an immutable **general classifier snapshot** (PS/TSS/PTSS backend via wrapper), and
    - an immutable **hash-bypass table** (`phb_table_t`) for TEID/UE-IP keyed PDR lookup.
- **UPF-U (User plane NF)** (`5gc/upf_u`):
  - Per-packet dataplane: parse → classify (hash-bypass → fallback classifier) → FAR action → (optional) QoS policing/shaping → output.
  - Consumes published snapshot pointers and flips at burst boundaries.
- **Classifier subsystem** (`5gc/classifiers`):
  - Backends PS/TSS/PTSS exposed through a C wrapper.
  - Snapshot handle is immutable; descriptor cookie returns the match (typically an `UpfPDR*`).
- **Shared libs & state** (`onvm/*`):
  - `onvm/upf/*`: shared UPF context, session tables, memzones, classifier control slot, hash-bypass table.
  - `onvm/pfcp/*`: PFCP encoding/decoding.
  - `onvm/updk/*`: internal rule structures (UPDK_PDR/FAR/QER).
  - `onvm/utlt/*`: utilities + event IDs.

### 2.2 CP/DP split
- **UPF-C** is authoritative for rule/session state updates.
- **UPF-U** is authoritative for per-packet decisions.
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
  - `upf/` — shared UPF context, memzones, session tables, classifier control slot, hash bypass
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
- Shared pool `upf_session_table` stores `UpfSession` objects in a contiguous array (`data[]`).
- Maps (TEID→session index, UE-IP→session index) are shared `rte_hash` tables.
- Pointers to these shared structures are published via memzones (primary writes pointer; secondaries lookup):
  - `MZ_PFCP_SESSION_TABLE_INFO`
  - `MZ_TEID_TO_UPF_SESSION_MAP_INFO`
  - `MZ_UE_IP_TO_UPF_SESSION_MAP_INFO`

Who creates these:
- ONVM manager (primary) initializes shared tables in `onvm/onvm_mgr/onvm_init.c`.
- UPF-C and UPF-U attach via `rte_memzone_lookup()` and use the shared structures directly.

### 5.3 Shared classifier control-slot (memzone)
Header: `onvm/upf/upf_cls_ctrl.h`

- Memzone name: `MZ_UPF_CLS_CTRL = "UPF_CLS_CTRL_SLOT"`
- Structure:
  - `upf_cls_ctrl_t {`
    - `void *active;`      (immutable classifier snapshot, `cls_handle_t*`)
    - `void *hash_bypass;` (immutable hash-bypass table, `phb_table_t*`)
    - `uint32_t version;`  (seqlock counter)
  - `}`
- Initialization: `UpfClsCtrlInit()` in `onvm/upf/upf_context.c` maps/reserves the control slot and initializes to a stable empty state:
  - `active = NULL`
  - `version = 0` (EVEN = stable)
  - `hash_bypass` is expected to be `NULL` until UPF-C publishes the first table

### 5.4 Publish/flip protocol (seqlock + ACK GC)

#### (A) UPF-C: publish a fresh immutable snapshot (+ hash bypass)
Key file: `5gc/upf_c/n4_onvm_pfcp_handler.c`

- `UpfClsRebuildAndPublish(out_version)`:
  1. Builds a new classifier snapshot (via `cls_create` + `cls_insert_rule`)
  2. Builds a new `phb_table_t` via `phb_create()` + `phb_add_pdr()` (`onvm/upf/pdr_hash_bypass.h`)
  3. Publishes both pointers with seqlock semantics via `upf_cls_publish(new_snap, new_hash, ...)`
  4. Sends `EVT_CLS_GC_REQ(ver)` to UPF-U

Seqlock semantics:
- `version` odd  ⇒ writer in progress
- `version` even ⇒ stable, reader-safe

#### (B) UPF-U: flip at burst boundary + ACK
Key file: `5gc/upf_u/upf_u.c`

- UPF-U receives `EVT_CLS_GC_REQ` and sets `flip_pending=1`.
- At burst boundary it calls `UpfClsMaybeFlipAndAck()` which performs a seqlock read:
  1. read `version` until it is EVEN
  2. read both pointers: `active` and `hash_bypass`
  3. re-read `version`; accept only if unchanged and EVEN
  4. commit locally to `g_cls_local.ptr` and `g_cls_local.hash` and clear `flip_pending`
  5. send `EVT_CLS_GC_ACK(ver)` back to UPF-C

#### (C) UPF-C: GC retired snapshots / hash tables / PDR objects after ACK
- UPF-C frees:
  - the retired classifier snapshot (`cls_destroy`) and
  - the retired `phb_table_t` (`phb_destroy`)
  only after receiving an ACK for the published version.
- PDR objects can be deferred and freed after ACK (“grace period”) to avoid use-after-free when descriptor cookies are raw pointers (`UpfPDR*`).

---

## 6) Classifier subsystem details (C API wrapping C++ engines)

Location: `5gc/classifiers/`

- Backends: PS/TSS/PTSS exposed via `classifier_wrapper.h/.cpp`.
- Allocation shim: `cls_heap_dpdk_shim.cpp` routes aligned `new/delete` to `rte_malloc/rte_free` (DPDK hugepage heap).
- `Packet` is now a fixed-size `std::array` (not `std::vector`), so per-packet `to_cpp_pkt()` avoids heap allocation.
- UPF adapter: `upf_cls_adapter.cpp` converts PDRs to rules; descriptor cookie is used to return match result to UPF-U.

Descriptor semantics:
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
- Parsing uses `rte_pktmbuf_mtod_offset()` with `rte_pktmbuf_data_len(pkt)` bounds checks; assumes required bytes are in the first segment.

### 7.3 PDR lookup (hash bypass → fallback classifier)
UPF-U does *two-stage* classification:

1) **Hash bypass** (O(1) expected):
   - UL: `phb_classify_ul(htbl, teid, &key)`
   - DL: `phb_classify_dl(htbl, ue_ip, &key)`
   - Returns a `UPDK_PDR*` on hit.
   - If the bucket is “poisoned” (overflowed) or missing, returns NULL.

2) **Fallback** (authoritative general classifier):
   - `UpfClassifyGetPdrPtr(&key)` → `cls_classify_packet()` on the published snapshot.

The hash bypass is defined in `onvm/upf/pdr_hash_bypass.h`:
- Two tables in one `phb_table_t`:
  - `teid_tbl[512]` for uplink (key = TEID)
  - `ueip_tbl[512]` for downlink (key = UE IPv4 host order)
- Each bucket stores up to `PHB_MAX_CANDIDATES=8` candidates (PDRs), sorted by precedence.
- **Overflow poisoning for correctness**: if a key has >8 PDRs, bucket sets `overflow=1` and lookup returns NULL, forcing fallback to the full classifier.
- Hash function is hardware CRC32: `rte_hash_crc_4byte(key, 0) & (n_buckets-1)` (power-of-two fast modulo).

### 7.4 FAR application
Function: `HandlePacketWithFar(pkt, pdr->far, pdr->qer, meta)`
- Uses FAR applyAction (DROP/FORW/BUFF/NOCP, etc.).
- If forwarding requires encapsulation, `Encap(pkt, far, qer)` is invoked.

### 7.5 QER usage (now formalized by UPF-C)
`UPDK_PDR` contains:
- `pdr->qers[2]` + `pdr->qer_count` (all QERs attached to this PDR)
- `pdr->qer` (selected by UPF-C as the **QFI-bearing, per-flow QER** via `UpfPdrSelectQfiQer()`)

Current behavior:
- Encapsulation/QFI stamping uses `pdr->qer`.
- UE QoS table population (DL shaping) scans `pdr->qers[]`.

### 7.6 QoS metering (no per-packet session lookup, no per-packet SDF string parsing)
Key points:
- UPF-C precomputes and stores:
  - `pdr->has_fd`, `pdr->fd_target`, `pdr->meter_key` (see §8).
- UPF-U uses those integer fields in the hot path; it does not parse `flowDescription` strings per packet.

In UPF-U:
- `ConfigureQerFlows(pdr, is_uplink)` is called after classification (UL and DL).
  - It uses `pdr->qer` (selected by CP) and `pdr->meter_key/has_fd` (precomputed by CP).
  - It lazily installs a new trTCM meter entry only on the first miss for that key (subsequent packets are a no-op).
- DL policing uses `ftSearch(pdr->meter_key)` to obtain the meter index and calls `rte_meter_trtcm_color_blind_check()`.

### 7.7 UE QoS table (DL) — PDR-local derivation
Function: `GetQerByUEIpAddressFromPdr(ue_ip, pdr, ip_str)`
- Replaces the old slow path that scanned `session->pdr_list`.
- Selection rule:
  - `AMBR` (implementation-defined) is derived as `max(QER.maximumBitrate.dl)` across `pdr->qers[]`.
  - `GBR/MBR` are taken from a QER only when both flags are present.

### 7.8 Buffering (current branch status)
- There is no per-session buffering in the current fastpath branch.
- UPF-U still contains a simple global `buffer[]` array used by FAR applyAction `BUFF` (not session-aware).
- `UPF_EVENT_SET_BUFFER` / `UPF_EVENT_CLEAR_AND_DRAIN` exist as event IDs, but are not wired into a per-session buffering pipeline in this branch.

---

## 8) UPF-C control plane behavior (PDR/QER consistency + precomputation)

Primary file: `5gc/upf_c/n4_onvm_pfcp_handler.c`

On CreatePDR / UpdatePDR:
- UPF-C resolves QER IDs to pointers and refreshes:
  - `pdr->qers[0..]`
  - `pdr->qer_count`
- UPF-C selects the QFI-bearing QER into `pdr->qer`:
  - `UpfPdrSelectQfiQer(pdr)` picks the first QER with `flags.qosFlowIdentifier`, else falls back to `qers[0]`.
- UPF-C precompiles the `flowDescription` for metering keys:
  - `UpfPdrPrecompileSdf(pdr, access_port, core_port, sgi_port)`
  - Produces:
    - `has_fd` = 1 if `from <IP/prefix>` is present (not `from any`)
    - `fd_target` = masked IPv4 network address (as parsed)
    - `meter_key` = `SourceInterfaceToPort(srcIf) + fd_target`

On publish:
- `UpfClsRebuildAndPublish()` rebuilds and publishes:
  - the general classifier snapshot, and
  - the hash bypass table (`phb_table_t`)
  using `upf_cls_publish()` with seqlock semantics.

---

## 9) Operational invariants / “things that must match”

1. Service IDs: UPF-U=1, UPF-C=2 (unless a split-UPF-U branch overrides this).
2. Memzone names consistent across processes:
   - classifier control slot: `UPF_CLS_CTRL_SLOT`
   - session/map pointer slots: `MProc_pfcp_session_table_info`, `MProc_TeidToUpfSessionMap_info`, `MProc_UeIpToUpfSessionMap_info`
3. **Port mapping consistency matters for metering keys**:
   - UPF-C uses `Self()->accessPort/corePort/sgiPort` when computing `meter_key`.
   - UPF-U uses `g_access_port/g_core_port/g_sgi_port` when interpreting SourceInterface and enforcing meters.
4. Descriptor cookie type is consistent (pointer cookie vs id cookie).
5. Snapshot lifetime: UPF-C must not free snapshots/PDRs/hash-bypass tables until ACK indicates dataplane flipped.

---

## 10) Debugging checklist (common failure modes)

- **“No snapshot yet” drops**: UPF-U hasn’t mapped `UPF_CLS_CTRL_SLOT` or UPF-C never published.
- **Rule updates not taking effect**: UPF-U not receiving `EVT_CLS_GC_REQ` or not flipping at burst boundary.
- **UAF after updates**: freeing PDRs/snapshots/hash-bypass table before ACK.
- **Hash bypass never hits**:
  - hash table pointer not published / not flipped (should be `NULL` until first publish),
  - keys not “hashable” (missing TEID for UL or UE IPv4 for DL),
  - bucket overflow poisoning triggered (key has >8 PDRs).
- **UE QoS table not populated**: ensure `pdr->qers[]` is populated and contains QERs with `maximumBitrate`.
- **QoS policing not applied**: check `pdr->has_fd` and `pdr->meter_key` are being set by UPF-C; note `UpfPdrPrecompileSdf()` currently only recognizes `from any` vs `from <IPv4/prefix>` patterns.

---

## 11) Quick “what to reference” map

- Shared control slot + init: `onvm/upf/upf_cls_ctrl.h`, `onvm/upf/upf_context.c`
- Snapshot publish/GC + hash bypass build: `5gc/upf_c/n4_onvm_pfcp_handler.c`
- Flip + ACK: `5gc/upf_u/upf_u.c` (`UpfClsMaybeFlipAndAck`)
- Hash bypass table definition: `onvm/upf/pdr_hash_bypass.h`
- Shared sessions/maps: `onvm/upf/upf.c`
- Unified GTP parse: `onvm/upf/gtp.h` (`parse_gtpu_once`)
- Dataplane fastpath: `5gc/upf_u/upf_u.c`
- Classifier wrapper: `5gc/classifiers/classifier_wrapper.h/.cpp`
- Adapter: `5gc/classifiers/upf_cls_adapter.cpp`
- Events: `onvm/utlt/upf_events.h`

---

## 12) Notes / assumptions

- This context matches the current fastpath direction as of **2026-02-26**; other branches (e.g., split ingress/egress buffering experiments) may diverge.
- Hash bypass is an acceleration structure; correctness is guaranteed by overflow poisoning + fallback to the authoritative classifier.

---
END OF CONTEXT
