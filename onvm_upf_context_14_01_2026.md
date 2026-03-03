# L²5GC+ `onvm-upf` — Comprehensive Context File (Copy/Paste Starter)

This document is a “context injection” for new conversations about the L²5GC+ `onvm-upf` codebase: architecture, control/data paths, memory model, classifier snapshots, QoS/buffering, configs, and operational assumptions. It is written to be used as a single upfront prompt for future technical discussions and debugging.

---

## 0) One-sentence summary

`onvm-upf` is a **DPDK/OpenNetVM-based 5G UPF** split into **UPF-C (control plane, PFCP/N4)** and **UPF-U (user plane, dataplane)** with **shared-memory session state** and a **versioned seqlock classifier-snapshot distribution mechanism**.

---

## 1) High-level architecture

### 1.1 Components
- **ONVM Manager** (`onvm/onvm_mgr`): primary process, owns DPDK ports/queues; schedules packets to NFs.
- **UPF-C (Control plane NF)** (`5gc/upf_c`):
  - Implements **PFCP/N4** message handling (Create/Update/Delete Session, etc.).
  - Maintains PDR/FAR/QER state and compiles classifier snapshots.
  - Publishes snapshots via a shared control-slot (memzone) and notifies UPF-U to flip.
- **UPF-U (User plane NF)** (`5gc/upf_u`):
  - Runs per-packet dataplane: classification → FAR action → optional QoS/buffering → forwarding.
  - Consumes published classifier snapshots and flips at burst boundaries.
- **Classifier subsystem** (`5gc/classifiers`):
  - Supports multiple backends (PartitionSort, TSS, Priority-TSS).
  - Exposes a C API wrapper around C++ classifier engines.
  - Allocates from DPDK hugepage heap via a `new/delete` alignment shim.
- **Shared libs & state** (`onvm/*`):
  - `onvm/upf/*`: UPF shared context, memzones, global lists.
  - `onvm/pfcp/*`: PFCP encoding/decoding/helpers.
  - `onvm/updk/*`: internal “UPDK” rule structures (PDR/FAR/QER representations).
  - `onvm/utlt/*`: utilities, types, and event IDs.

### 1.2 Data-plane/control-plane split
- **UPF-C** is “authoritative” for rules and session objects.
- **UPF-U** is “authoritative” for packet processing and burst scheduling decisions.
- Rule distribution is not “RPC”—it is **shared memory + versioned pointer flip + ACK-based GC**.

---

## 2) Repository layout (important paths)

Top-level:
- `5gc/`
  - `upf_c/` — UPF control-plane NF (PFCP/N4)
  - `upf_u/` — UPF user-plane NF (dataplane)
  - `classifiers/` — classifier engines + wrappers + UPF adapter
  - `dn_app/` — helper DN-side application (test support)
- `onvm/`
  - `onvm_mgr/` — ONVM manager
  - `onvm_nflib/` — ONVM NF library
  - `upf/` — shared UPF context, memzones, ctrl slots
  - `pfcp/`, `updk/`, `utlt/`, `list/`, `logger/`
- `scripts/` — build/run helpers

Key config files:
- UPF-U: `5gc/upf_u/config/upf_u.yaml`
- UPF-C: `5gc/upf_c/config/upfcfg.yaml` (+ example variants)

---

## 3) Build & environment assumptions

### 3.1 Tooling
- **DPDK 24.07.x** target.
- **Meson + Ninja** build system.
- Python venv used by scripts (`scripts/build.sh` activates `env/bin/activate`).
- Libyaml present (YAML configs).

### 3.2 Build entrypoint
- `scripts/build.sh` does:
  - `meson setup build`
  - `ninja -C build ...`
  - builds ONVM + NFs.

### 3.3 Run entrypoint
- ONVM manager: `scripts/start.sh` (wraps `onvm_mgr` launch, hugepage cleanup, stats options).
- NFs typically launched via per-component scripts (or directly via `build/...` binaries).

---

## 4) Service IDs and control events (inter-NF signaling)

Central definition: `onvm/utlt/upf_events.h`

- **Service IDs**
  - `UPF_U_SERVICE_ID = 1`
  - `UPF_C_SERVICE_ID = 2`
- **Event types**
  - `EVT_CLS_GC_REQ = 0x4201`  (UPF-C → UPF-U: “flip to new classifier version”)
  - `EVT_CLS_GC_ACK = 0x4202`  (UPF-U → UPF-C: “flip complete; safe to GC retired snapshot”)
  - `UPF_EVENT_SET_BUFFER = 0xA0` (buffering control path)
  - `UPF_EVENT_CLEAR_AND_DRAIN = 0xA1` (buffer drain control path)

UPF-U sends events via an internal helper:
- `UpfSendEvt1(dest_sid, type, arg0)` allocates an `Event` and sends via `onvm_nflib_send_msg_to_nf(...)`.

---

## 5) Shared memory model and “classifier snapshot” protocol

### 5.1 Shared control-slot memzone
Header: `onvm/upf/upf_cls_ctrl.h`

- Memzone name:
  - `MZ_UPF_CLS_CTRL = "UPF_CLS_CTRL_SLOT"`
- Structure:
  - `active: void*` — pointer to current immutable snapshot handle
  - `version: uint32_t` — publish counter (seqlock semantics)

Initialization:
- `UpfClsCtrlInit()` maps/reserves the memzone and initializes:
  - `active = NULL`
  - `version = 0` (EVEN = stable)

### 5.2 Publish/flip protocol (seqlock + ACK GC)

#### (A) UPF-C: rebuild and publish
Key file: `5gc/upf_c/n4_onvm_pfcp_handler.c`

- On PFCP session/rule change, UPF-C calls:
  - `UpfClsRebuildAndPublish(out_version)`
- Steps:
  1. `snap = cls_create(CLS_SELECTED_BACKEND_ID)`
  2. Iterate global `g_all_pdr_list` (shared list of `UpfPDR*`)
  3. For each `UpfPDR`, determine direction from PFCP `sourceInterface`
     - `ACCESS (0)` treated as uplink
     - `CORE   (1)` treated as downlink
  4. Convert PDR to classifier rule:
     - `pdr_t r = updk_pdr_to_cls_rule(up, is_uplink)`
  5. Store descriptor cookie:
     - `r.descriptor = (uintptr_t) up`  (publishes the actual pointer)
  6. Insert into snapshot:
     - `cls_insert_rule(snap, &r)`
  7. Publish with seqlock semantics:
     - version becomes ODD during write
     - atomically exchange `active`
     - version becomes EVEN when stable
  8. Save “retired snapshot” pointer + version for GC
  9. Notify UPF-U:
     - `UpfSendEvt1(UPF_U_SERVICE_ID, EVT_CLS_GC_REQ, ver)`

#### (B) UPF-U: flip at burst boundary + ACK
Key file: `5gc/upf_u/upf_u.c`

- UPF-U maintains a local view:
  - `g_cls_local.ptr`  (snapshot pointer)
  - `g_cls_local.ver`  (snapshot version)
  - `g_cls_local.flip_pending`
- When it receives `EVT_CLS_GC_REQ`, it sets `flip_pending=1`.
- At burst boundary it calls:
  - `UpfClsMaybeFlipAndAck()`
- Flip algorithm:
  1. Read `version` until it is EVEN (stable)
  2. Load `active` pointer
  3. Re-read `version` and require same EVEN value
  4. Commit local pointer/version
  5. Clear `flip_pending`
  6. ACK UPF-C with the stable version:
     - `UpfSendEvt1(UPF_C_SERVICE_ID, EVT_CLS_GC_ACK, ver)`

#### (C) UPF-C: free retired snapshot only after ACK
- UPF-C receives `EVT_CLS_GC_ACK(ver)` and calls:
  - `UpfClsOnAckFree(ver)`
- Behavior:
  - If `ver == g_cls_retired_version`, destroy snapshot:
    - `cls_destroy((cls_handle_t*)retired_ptr)`
  - Optionally clears `g_cls_retired_version`
  - Triggers deferred PDR frees:
    - `PdrFreeUpTo(ver)` (safe reclamation tied to version)

### 5.3 Why this design exists
- Avoids locks on DP fast path.
- Snapshot handles are immutable; UPF-U never sees partially-built rule tables.
- UPF-C can rebuild/replace entire classifier quickly and safely.
- ACK-based GC avoids use-after-free of classifier memory and PDR pointers.

---

## 6) Classifier subsystem details (C API wrapping C++ engines)

Location: `5gc/classifiers/`

### 6.1 Backends and selection
In `classifier_wrapper.h`:
- `CLS_BACKEND_ID_PS   = 0` (PartitionSort; default)
- `CLS_BACKEND_ID_TSS  = 1`
- `CLS_BACKEND_ID_PTSS = 2`
- Compile-time selection:
  - `CLS_SELECTED_BACKEND_ID` defaults to PS unless overridden.

### 6.2 DPDK hugepage heap allocation shim
File: `cls_heap_dpdk_shim.cpp`
- Overrides aligned `operator new/delete` to use:
  - `rte_malloc("cls", ...)` and `rte_free(...)`
- Ensures classifier snapshot objects live in DPDK-managed hugepage memory.

### 6.3 UPF adapter (PDR → classifier rule)
File: `upf_cls_adapter.cpp`
- Converts `UpfPDR` fields into a classifier `pdr_t` rule:
  - TEID/IP/ports/protocol matches
  - direction-specific matching logic (uplink vs downlink)
  - QFI handling (if present in PDR / extension header parsing)
- Includes pragmatic parsing for SDF “flow description” strings where used.

### 6.4 Descriptor semantics
- Classifier returns a descriptor cookie (`uintptr_t`) per match.
- In current implementation:
  - descriptor is set to `UpfPDR*` (pointer) during insert.
- UPF-U can use:
  - `UpfClassifyGetPdrPtr(key)` → returns `UPDK_PDR*` or `UpfPDR*` depending on how the cookie is interpreted.

---

## 7) UPF-U dataplane behavior (packet flow)

Primary file: `5gc/upf_u/upf_u.c`

### 7.1 Port roles and L2 identity
UPF-U uses YAML config (`5gc/upf_u/config/upf_u.yaml`) for:
- `dn_mac`, `an_mac`, `upf_ip`
- Port mapping:
  - `access: 1`
  - `core:   0`
(“SGi follows CORE” per config comments.)

### 7.2 Typical packet pipeline (conceptual)
1. Receive packet burst from ONVM/DPDK.
2. If `flip_pending`: perform `UpfClsMaybeFlipAndAck()` at burst boundary.
3. Parse packet into a classifier key (`ps_packet_t`-like).
4. Classify using immutable snapshot:
   - `cls_classify_packet(snapshot, key, &precedence, &descriptor)`
5. Obtain matched PDR (pointer cookie) and apply:
   - FAR action: forward/drop/encap/decap/buffer (as implemented)
   - QER/QoS enforcement
6. Emit packet to the appropriate output port via ONVM metadata.

### 7.3 GTP-U and QFI handling
- UPF-U includes logic to compute GTP header length and extract QFI (if extension header exists).
- The classifier key construction may include TEID, inner 5-tuple, and QFI depending on the selected rule model.

### 7.4 QoS
- Uses DPDK meter primitives:
  - `rte_meter_trtcm_profile` and `rte_meter_trtcm`
- Enforcement includes token bucket checks and (in some modes) deliberate throttling behavior.
- QoS behavior is a major performance lever (can introduce jitter/latency if implemented with waits/sleeps).

### 7.5 Buffering and drain control
- Buffering control is exposed through events:
  - `UPF_EVENT_SET_BUFFER`
  - `UPF_EVENT_CLEAR_AND_DRAIN`
- In your L²5GC+ project evolution, downlink buffering semantics were tightened to ensure **in-order delivery during drain**:
  - design choice: enqueue every downlink packet to an intermediate queue/ring first, and dequeue from there (avoids “live packets interleaving” with drained packets).

---

## 8) UPF-C control plane behavior (PFCP/N4 and rule lifecycle)

Primary files:
- `5gc/upf_c/upf.c` (main)
- `5gc/upf_c/n4_onvm_pfcp_path.c` (message/event ingress path)
- `5gc/upf_c/n4_onvm_pfcp_handler.c` (PFCP procedures → rule updates → classifier publish)

### 8.1 Config
`5gc/upf_c/config/upfcfg.yaml` contains:
- logging level
- PFCP local addresses
- GTP-U local address
- DNN list (CIDR, etc.)

### 8.2 Rule/session lifecycle
On PFCP session changes:
- Update internal rule objects (PDR/FAR/QER).
- Insert/update/delete PDRs in the global list `g_all_pdr_list`.
- Call `UpfClsRebuildAndPublish()` to create a fresh immutable snapshot.
- Notify UPF-U to flip via `EVT_CLS_GC_REQ`.
- On `EVT_CLS_GC_ACK`, reclaim retired snapshot + safely free deferred PDRs up to that version.

### 8.3 Memory safety strategy
- UPF-C avoids freeing rule objects that may still be referenced by a snapshot not yet retired.
- Deferred reclamation is tied to the same version used for snapshot GC.

---

## 9) Operational invariants / “things that must match” in deployments

1. **Service IDs** must be consistent:
   - UPF-U service id = 1
   - UPF-C service id = 2
2. **Memzone names** must match across all processes:
   - classifier control slot: `UPF_CLS_CTRL_SLOT`
3. **DPDK port numbering** must align with `upf_u.yaml` and ONVM portmask:
   - e.g., core=0, access=1
4. **MAC addresses** in UPF-U config must match your testbed topology (AN/DN neighbors).
5. **Snapshot lifetime**:
   - UPF-C must not destroy snapshots until UPF-U ACKs flip.
6. **Descriptor cookie type**:
   - If cookie is `UpfPDR*`, then UPF-U must treat it as such consistently (avoid mixing “pdrId cookie” vs “pointer cookie” builds).

---

## 10) Debugging checklist (common failure modes)

### 10.1 “UPF-U drops everything / no snapshot yet”
- Cause: UPF-C never published or UPF-U never mapped `UPF_CLS_CTRL_SLOT`.
- Check: `UpfClsCtrlInit()` called in both processes after ONVM init.

### 10.2 “Stale rules after PFCP update”
- Cause: UPF-U not receiving `EVT_CLS_GC_REQ` or not flipping at burst boundary.
- Check: event delivery path, `flip_pending` logic, service IDs.

### 10.3 “Crash / UAF after rule updates”
- Cause: freeing PDRs or snapshots before ACK.
- Check: `UpfClsOnAckFree(ver)` and deferred free boundary (`PdrFreeUpTo(ver)`).

### 10.4 “QoS causes unexpected throughput collapse”
- Cause: meter configuration, per-flow token bucket math, or sleeps/throttling.
- Check: QER profile construction and enforcement branch.

### 10.5 “Wrong port direction”
- Cause: mismatch between testbed wiring, DPDK port ids, and YAML `access/core` mapping.
- Check: `upf_u.yaml` + ONVM portmask + NIC binding order.

---

## 11) Quick “what to reference” map (for conversations)

- **Snapshot control slot + memzones**: `onvm/upf/upf_cls_ctrl.h`, `onvm/upf/upf_context.c`
- **Publish + rebuild**: `5gc/upf_c/n4_onvm_pfcp_handler.c` (`UpfClsRebuildAndPublish`, `upf_cls_publish`)
- **Flip + ACK**: `5gc/upf_u/upf_u.c` (`UpfClsMaybeFlipAndAck`, `UpfSendEvt1`)
- **Classifier wrapper API**: `5gc/classifiers/classifier_wrapper.h/.cpp`
- **DPDK heap shim for classifier**: `5gc/classifiers/cls_heap_dpdk_shim.cpp`
- **PDR → rule adapter**: `5gc/classifiers/upf_cls_adapter.cpp`
- **UPF-U config**: `5gc/upf_u/config/upf_u.yaml`
- **UPF-C config**: `5gc/upf_c/config/upfcfg.yaml`
- **Events**: `onvm/utlt/upf_events.h`

---

## 12) Current research direction tie-in (SmartNIC/DPU offload readiness)

The codebase is already structured in a DPU-friendly way because:
- CP/DP are separated (UPF-C vs UPF-U).
- Rules are materialized into an immutable snapshot and distributed via a tiny shared control surface.
- There is a natural “compile step” (PDR → classifier rule) that can be retargeted to:
  - hardware flow tables (DOCA Flow pipes/entries), or
  - hybrid host+NIC offload where UPF-U becomes the miss/exception path.

The main “hard parts” for offload (beyond classification) are:
- buffering semantics / in-order drain behavior,
- QoS enforcement model,
- state synchronization across host/DPU boundaries.

---

## 13) Minimal configuration snapshot (from repo defaults)

UPF-U (`5gc/upf_u/config/upf_u.yaml`):
- `upf_ip`: `192.168.1.2`
- `ports.access`: `1`
- `ports.core`: `0`
- `dn_mac`, `an_mac` set for the current lab topology.

UPF-C (`5gc/upf_c/config/upfcfg.yaml`):
- PFCP addr: `127.0.0.8`
- GTP-U addr: `10.100.200.3`
- DNN: `internet`, CIDR `10.60.0.0/24`

---

## 14) Notes / assumptions

- This context matches the repository snapshot as provided in `onvm-upf.zip` and may diverge from other branches/patches.
- Any changes to descriptor cookie type (pointer vs id) or to classifier backend selection should be reflected in this context file before reuse.

---
END OF CONTEXT
