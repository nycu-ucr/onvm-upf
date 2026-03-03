# UPF-U Ingress/Egress Split – Feature Notes

This document captures the design and implementation details for splitting the legacy run‑to‑completion UPF-U into separate **ingress** and **egress** NFs, plus the associated shared state, classifier, and L25GC integration changes. It is meant as an internal reference so you can quickly recall “what lives where” when revisiting this work later.

---

## 1. Requirements & Goals

### 1.1 High-level behaviour

- Replace the old single UPF-U NF with:
  - **Ingress NF** (producer):
    - Handles UL inline: classify + apply PDR/FAR/QER + transmit.
    - Handles DL by enqueuing mbufs into a per-session DL FIFO.
  - **Egress NF** (consumer):
    - Maintains a registry of session IDs.
    - Round-robins over sessions; for each live session, drains its DL FIFO to empty, applies DL PDR/FAR/QER/QoS, and transmits.
- No ready queue, no budgets; **round-robin + drain-to-empty** is the only scheduler.

### 1.2 Shared state & invariants

- Single source of truth for per-session state in shared hugepages:
  - `sess_id` (32-bit, process-agnostic ID).
  - `dl_ring*` (per-session DL `rte_ring*`, NULL until first DL).
  - `buffering` atomic: `0=live`, `1=paused`.
- Per-session DL FIFO is a DPDK `rte_ring` with **MP enqueue / SC dequeue**:
  - Producers: ingress (and potentially other producers later).
  - Consumer: egress (single worker).
- Elements in the ring are `struct rte_mbuf*` as‑is (no header stripping before enqueue).
- Strict invariants:
  - **Single owner for DL mbufs**: once enqueued, only egress dequeues and frees/transmits.
  - **Strict per-session order**: achieved by MP enqueue + SC dequeue + single consumer.
  - **Publish ordering**: `dl_ring` pointer must be visible before the first enqueue; readers use acquire semantics.
  - No data-plane ready queue, tick, or budget model: RR is the scheduler.

### 1.3 Control-plane contracts

- **REGISTER**:
  - Purpose: tell egress which sessions exist and should be visited in RR.
  - Content: `sess_id` (and conceptually UE-IP for observability).
  - Effect: egress adds `sess_id` to its RR registry.
- **FLAGS (SET_BUF / CLEAR_AND_DRAIN)**:
  - `buffering` flag lives in shared `UpfSession` and is truth.
  - `SET_BUF` (`buffering=1`):
    - Ingress continues to enqueue (or drops on full).
    - Egress, on `buffering=1`, skips this session during RR.
  - `CLEAR_AND_DRAIN` (`buffering=0`):
    - On next RR visit, egress drains ring to empty and moves on.
- **DELETE**:
  - CP sets `buffering=1`, stops new DL enqueue for that session.
  - Egress drains ring to empty, then CP safely removes the session/ring.
  - A delete event helps egress drop the session from its RR set.

---

## 2. Shared Session State (`onvm/upf`)

### 2.1 `UpfSession` extensions

**File:** `onvm/upf/upf_context.h`

- `typedef struct _UpfSession { ... } UpfSession;` now includes:
  - `uint32_t sess_id;`
    - 32-bit identifier derived from SEID (via `UpfSessionAlloc` in `onvm/upf/upf.c`).
  - `struct rte_ring *dl_ring;`
    - Pointer to per-session DL FIFO. NULL until first DL packet publishes/creates it.
  - `rte_atomic32_t buffering;`
    - Atomic flag: `0 = live`, `1 = paused`.

**File:** `onvm/upf/upf.c`

- `UpfSessionAlloc(const uint64_t seid)` now:
  - Sets `session->sess_id = (uint32_t)seid;`
  - Initialises `session->dl_ring = NULL;`
  - Initialises `session->buffering` to 0 via `rte_atomic32_init` + `rte_atomic32_set`.

### 2.2 Per-session DL ring helper

**Files:**
- `onvm/upf/upf_session_dl.h`
- `onvm/upf/upf_session_dl.c`
- `onvm/upf/meson.build` (added to `upf_sources`)

Key API:

- `struct rte_ring *UpfSessionEnsureDlRing(UpfSession *session);`
  - If `session->dl_ring` exists, returns it.
  - Otherwise:
    - Assembles ring name: `upf_dl_<sess_id>`.
    - `rte_ring_lookup(name)`; if not found, attempts `rte_ring_create(name, UPF_DL_RING_SIZE, ...)` with `RING_F_SC_DEQ`.
    - Publishes `session->dl_ring` with `__atomic_store` (release) and `rte_wmb()` to guarantee "pointer visible before enqueue".
- `UpfSessionIsBuffered`, `UpfSessionSetBuffering` helpers around the `buffering` atomic.

Purpose: centralise ring creation and publication semantics so both ingress and egress can safely share per-session DL rings via `UpfSession`.

---

## 3. Classifier Snapshot with Two Consumers

### 3.1 Events & service IDs

**File:** `onvm/utlt/upf_events.h`

- Service ID macros:
  - `UPF_INGRESS_SERVICE_ID` = 1 (also aliased as `UPF_U_SERVICE_ID`).
  - `UPF_EGRESS_SERVICE_ID` = 13.
  - `UPF_C_SERVICE_ID` = 2.
- Classifier consumers:
  - `UPF_CLS_CONS_INGRESS = 0`, `UPF_CLS_CONS_EGRESS = 1`, `UPF_CLS_CONS_MAX = 2`.
- Events:
  - `UPF_EVENT_SET_BUFFER`, `UPF_EVENT_CLEAR_AND_DRAIN`.
  - `UPF_EVENT_REGISTER_SESSION`, `UPF_EVENT_DELETE_SESSION`.
  - `EVT_CLS_GC_REQ` (publish / flip request from UPF-C to DP).
  - `EVT_CLS_GC_ACK` (ACK from ingress/egress back to UPF-C).

### 3.2 Publish and GC logic (UPF-C)

**Files:**
- `5gc/upf_c/n4_onvm_pfcp_handler.c`
- `5gc/upf_c/n4_onvm_pfcp_path.c`

Key structures:

- `static void *g_cls_retired_snapshot;`
- `static uint32_t g_cls_retired_version;`
- `static uint32_t g_cls_retired_ack_mask;`
- `static uint32_t g_cls_ack_need_mask;`

Flow:

1. **Publish** (`upf_cls_publish`):
   - Uses seqlock semantics:
     - Writes odd version to signal writer-in-progress.
     - Swaps `g_upf_cls_ctrl->active` pointer.
     - Writes even version to signal stable snapshot.
   - Captures `retired` snapshot (previous `active`).
   - If `retired`:
     - Stores to `g_cls_retired_snapshot`, `g_cls_retired_version`.
     - Clears `g_cls_retired_ack_mask`.
   - Sends `EVT_CLS_GC_REQ(ver)` to:
     - `UPF_INGRESS_SERVICE_ID` (ID 1).
     - `UPF_EGRESS_SERVICE_ID` (ID 13) if different.
   - Computes `g_cls_ack_need_mask` as the bitmask of consumers that must ACK (1 bit for ingress; optional second bit for egress).

2. **NF side flip** (`UpfClsMaybeFlipAndAck` in `5gc/upf_u/upf_u.c`):
   - Both ingress and egress have a local `g_cls_local` (pointer + version + pending flag).
   - When they observe `flip_pending`, they:
     - Read `g_upf_cls_ctrl->version` and `active` with seqlock semantics.
     - Commit `g_cls_local.ptr` and `g_cls_local.ver`.
     - Clear `flip_pending`.
     - Send `EVT_CLS_GC_ACK(version, consumer_id)` back to UPF-C.

3. **GC on ACK** (`UpfClsOnAckFree` in `n4_onvm_pfcp_handler.c`, called from `n4_onvm_pfcp_path.c:msg_handler`):
   - Receives `(ver, who)` for an ACK.
   - If `ver != g_cls_retired_version`, ignore.
   - Atomically sets bit corresponding to `who` in `g_cls_retired_ack_mask`.
   - If `g_cls_retired_ack_mask == g_cls_ack_need_mask`:
     - `to_free = g_cls_retired_snapshot; cls_destroy(to_free);`
     - Resets version and mask.
     - Calls `PdrFreeUpTo(ver)` to GC associated PDRs.

Motivation: we cannot free a retired classifier snapshot until **all consumers that were notified** have adopted the newer version, otherwise one of them could still be dereferencing freed memory.

---

## 4. Ingress/Egress NFs & Shared Fast-path (`5gc/upf_u`)

### 4.1 Shared fast-path library

**Files:**
- `5gc/upf_u/upf_u.c`
- `5gc/upf_u/upf_u_common.h`

`upf_u.c` now serves as a **common dataplane library**; its old monolithic `main` and `packet_handler` are preserved under `#if 0` for reference. Active responsibilities:

- Classifier front-end:
  - `upf_cls_local_t g_cls_local;`
  - `void UpfClsMaybeFlipAndAck(uint32_t consumer_id);`
  - `static inline const UPDK_PDR *UpfClassifyGetPdrPtr(const ps_packet_t *key);`
  - `GetPdrByTeid`, `GetPdrByUeIpAddress` (build key, call classifier wrapper).
- QoS / token bucket:
  - Token bucket structs for UE AMBR/GBR/MBR (`struct ue_tb ue_table[MAX_UE];`).
  - Flow table for QoS (hash on IP/prefix + interface).
  - Functions: `trtcmConfigFlowTables`, `trtcmColorHandle`, `trtcmPolicer`, `findIndexByUeIpAddress`, `updateTokenbyIndex`, `addEntrybyUeIp`, etc.
- FAR/QER and encapsulation:
  - `Encap` (GTP-U outer header creation, optional PDU session container).
  - `HandlePacketWithFar` (apply FAR apply-action: DROP/FORW/BUFF and optional NOCP).
  - `AttachL2Header` (maps DL vs UL to correct src/dst MACs).
- Utility:
  - IP string conversions, masked IP parsing, `SourceInterfaceToPort` for QoS flow keys.

`upf_u_common.h` exposes:

- `extern upf_cls_local_t g_cls_local;`
- Externs for MACs, `SELF_IP`, QoS arrays.
- Prototypes for all the helpers used by ingress/egress.

### 4.2 Ingress NF

**File:** `5gc/upf_u/upf_ingress.c`

Role: `NF_TAG="upf_ingress"`.

- `packet_handler`:
  - Reads IPv4 header; calls `UpfClsMaybeFlipAndAck(UPF_CLS_CONS_INGRESS)` once per burst.
  - UL path (dst IP == SELF_IP):
    - `GetPdrByTeid` (using TEID from outer GTP-U).
    - Performs outer header removal if configured.
    - Calls `HandlePacketWithFar` + `AttachL2Header(pkt, false)` to forward inline.
  - DL path (dst IP != SELF_IP):
    - `ue_ip = rte_be_to_cpu_32(iph->dst_addr);`
    - `pdr = GetPdrByUeIpAddress(pkt, ue_ip);`
    - `GetQerByUEIpAddress(ue_ip, ...)` to populate QoS state.
    - `session = UpfSessionFindByUeIP(ue_ip);`
    - `ring = UpfSessionEnsureDlRing(session);`
    - `rte_ring_mp_enqueue(ring, pkt);` → return `1` so ONVM treats it as buffered (no further TX or free in ingress).
- `msg_handler`:
  - Handles `EVT_CLS_GC_REQ` from UPF-C by updating `g_cls_local.pending_ver` and setting `flip_pending`.

### 4.3 Egress NF

**File:** `5gc/upf_u/upf_egress.c`

Role: `NF_TAG="upf_egress"`.

Key components:

- **Session registry**: `struct session_registry { uint32_t ids[MAX_SESS_REG]; uint32_t count; uint32_t cursor; };`
  - Maintained via REGISTER/DELETE events from UPF-C.
- **DL processing**: `process_downlink_pkt(pkt, meta)`:
  - Does DL classification via `GetPdrByUeIpAddress`.
  - Applies outer header removal.
  - Calls `HandlePacketWithFar` + `AttachL2Header(pkt, true)`.
  - Applies QoS (identical token-bucket + trTCM logic to old UPF-U).
- **Draining**: `drain_session(sess_id, nf_local_ctx, tx_buf, tx_count)`:
  - Finds `UpfSession` by `sess_id`.
  - Skips if `UpfSessionIsBuffered(session)` or `session->dl_ring == NULL`.
  - Uses `rte_ring_sc_dequeue_burst` to drain per-session ring to empty, calling `process_downlink_pkt` on each mbuf and batching TX to ONVM.
- **Message handler**:
  - `EVT_CLS_GC_REQ`: set `g_cls_local.pending_ver` and `flip_pending`.
  - `UPF_EVENT_REGISTER_SESSION(sess_id)`: add to registry.
  - `UPF_EVENT_DELETE_SESSION(sess_id)`: remove from registry.
  - `UPF_EVENT_SET_BUFFER` / `UPF_EVENT_CLEAR_AND_DRAIN`: set `buffering` flag for the corresponding `UpfSession`.
- **Tick** (`egress_tick` hooked as `user_actions`):
  - Calls `UpfClsMaybeFlipAndAck(UPF_CLS_CONS_EGRESS)`.
  - Visits each session in registry in RR order, calling `drain_session`.
  - Flushes remaining TX batches through ONVM.

---

## 5. PFCP and Event Plumbing (UPF-C)

**File:** `5gc/upf_c/n4_dispatcher.c`

- After `UpfSessionAddByMessage` creates a new session:
  - Sends `UPF_EVENT_REGISTER_SESSION(sess_id)` to:
    - `UPF_INGRESS_SERVICE_ID` (ID 1).
    - `UPF_EGRESS_SERVICE_ID` (ID 13) if different.
- This seeds egress’s RR registry with the newly created session IDs.

**File:** `5gc/upf_c/n4_onvm_pfcp_handler.c`

- In `UpfN4HandleSessionDeletionRequest`:
  - Before deleting the session, sends:
    - `UPF_EVENT_DELETE_SESSION(sess_id)` to ingress.
    - `UPF_EVENT_DELETE_SESSION(sess_id)` to egress.
- This allows egress to promptly remove sessions from its RR registry and stop polling them.

Future work (not implemented yet, but implied by design):

- Using `UPF_EVENT_SET_BUFFER` / `UPF_EVENT_CLEAR_AND_DRAIN` from UPF-C to drive the `buffering` flag over time, matching PFCP buffering semantics more closely.

---

## 6. Build & Launch Integration (onvm-upf)

### 6.1 Meson build

**File:** `5gc/upf_u/meson.build`

- Introduces a split of sources:
  - `sources_common = files('upf_u.c', 'upf_u_config.c')`
  - `ingress_sources = sources_common + files('upf_ingress.c')`
  - `egress_sources  = sources_common + files('upf_egress.c')`
- Builds two binaries:
  - `l25gc_upf_ingress`
  - `l25gc_upf_egress`
- Each linked with:
  - `onvm_dpdk_dep`, `onvm_nflib_dep`, `onvm_l25gc_dep`, `rt_dep`, `classifier_dep`, `upf_u_link_deps` (yaml).

### 6.2 ONVM NF launcher scripts (in onvm-upf repo)

**File:** `5gc/start_nf.sh`

- Extended to support:
  - `upf_u_ingress` → `build/app/l25gc_upf_ingress`
  - `upf_u_egress`  → `build/app/l25gc_upf_egress`
- Usage examples:
  - `./start_nf.sh upf_u_ingress 1 ...`
  - `./start_nf.sh upf_u_egress 14 ...`

**File:** `5gc/go.sh`

- For `NF_DIR=upf_u`:
  - `./go.sh ingress 1 ...` → calls `start_nf.sh upf_u_ingress 1 ...`
  - `./go.sh egress 14 ...` → calls `start_nf.sh upf_u_egress 14 ...`

These allow the split NFs to be launched in the same style as before, but with explicit roles.

---

## 7. L25GC-plus Integration Sketch (external consumer)

Although this work lives in the `onvm-upf` repo, the L25GC-plus tree (`L25GC-plus/scripts/run`) now uses a separate script:

**File (in L25GC-plus):** `scripts/run/run_upf_u_role.sh` (new)

- Role-based launcher:
  - `ROLE` ∈ {`ingress`, `egress`}.
  - `SERVICE-ID` is the next argument (1 for ingress, 14 for egress by default).
  - Remaining args are passed directly to the NF.
- Example calls from L25GC-plus root:
  - `./scripts/run/run_upf_u_role.sh ingress 1  ./NFs/onvm-upf/5gc/upf_u/config/upf_u.yaml`
  - `./scripts/run/run_upf_u_role.sh egress 14 ./NFs/onvm-upf/5gc/upf_u/config/upf_u.yaml`
- Each role uses:
  - `NFs/onvm-upf/build/5gc/l25gc_upf_ingress`
  - `NFs/onvm-upf/build/5gc/l25gc_upf_egress`

This preserves your previous pattern (“pass full config path from L25GC root”) while selecting the appropriate binary and service ID for each role.

---

## 8. Operational Notes & Order of Start

- ONVM manager must be running first (unchanged).
- Both ingress and egress should be running **before** PFCP sessions are established, so egress sees all `REGISTER` events and builds a complete RR registry.
- There is no strict dependency that UPF-C start before UPF-U; the crucial constraint is:
  - **Egress must be alive by the time sessions are created** if you want DL to drain without a separate “resync all sessions” mechanism.
- Typical start sequence in an integrated deployment:
  1. Start ONVM manager.
  2. Start UPF-C (service ID 2).
  3. Start UPF-U ingress (service ID 1).
  4. Start UPF-U egress (service ID 14).
  5. Start SMF/other CP NFs and let PFCP flows establish sessions.

---

## 9. Future Work / TODOs

- **Buffering semantics**:
  - Wire real `UPF_EVENT_SET_BUFFER` / `UPF_EVENT_CLEAR_AND_DRAIN` from UPF-C based on PFCP buffering state, rather than leaving them as telemetry-only.
- **Session resync for late egress**:
  - Add a mechanism for egress to discover existing `UpfSession` entries on startup (e.g., iterating the session pool) to populate its RR registry even if it started after CP created sessions.
- **Scaling egress workers**:
  - Current design uses a single egress worker (single consumer). For multiple egress cores, we’d need a well-defined sharding of `sess_id`s per worker.

---

This document should give you a quick “map” from conceptual design → code locations. When you revisit this feature, you can start from the appropriate section, then jump directly to the referenced files and symbols. 
