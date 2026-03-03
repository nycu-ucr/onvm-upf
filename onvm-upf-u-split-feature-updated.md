# UPF-U Ingress/Egress Split – Consolidated Feature Context (Pre Busy-Poll)

This document consolidates and updates the original context from:

- `onvm-upf-context_buffer.readme`
- `onvm-upf-upf-u-split-feature.md`

It describes the UPF-U split design (ingress/egress), how it is implemented in the `onvm-upf` codebase, and the behaviour of the original, non–busy-poll implementation. It ends with notes on the intermittent ~8 ms enqueue→dequeue delay observed, and how we confirmed it was in the DL buffering path.

---

## 1. High-Level Overview

- **Goal**: Split the legacy single UPF-U NF into:
  - **Ingress NF** (producer): handles UL inline; handles DL by enqueueing mbufs to per-session DL rings.
  - **Egress NF** (consumer): maintains a session registry and round-robins over per-session DL rings, draining DL traffic, applying PDR/FAR/QER/QoS, and transmitting.
- **Execution model**:
  - All components (UPF-C, UPF-U ingress, UPF-U egress, DN app, UE/RAN) run as ONVM NFs on the same manager.
  - Control-plane (UPF-C) manages PFCP, rules, and classifier snapshots.
  - Data-plane (ingress/egress) consumes classifier snapshots and shared session state from memzones.

---

## 2. Repository & Code Layout (Relevant Pieces)

- `5gc/upf_u_complete/` – original monolithic UPF-U NF (before split), with inline UL/DL processing.
- `5gc/upf_u/` – split UPF-U:
  - `upf_ingress.c` – ingress NF (UL inline; DL enqueue).
  - `upf_egress.c` – egress NF (RR scheduler and DL drain).
  - `upf_u.c` – common UPF-U helper logic, classifier helpers, QoS/token-bucket, FAR/QER application.
  - `upf_u_config.c` – YAML parser populating `SELF_IP`, DN/AN MACs, and port mapping (`g_access_port`, `g_core_port`, `g_sgi_port`).
- `onvm/upf/` – shared UPF state:
  - `upf_context.c/.h` – `UpfSession` pool, TEID and UE-IP maps, PDR/FAR/QER lists.
  - `upf_session_dl.{h,c}` – per-session DL ring creation and publish helpers.
- `5gc/upf_c/` – UPF-C control plane:
  - `n4_dispatcher.c` – receives N4 (PFCP) messages and generates UPF events.
  - `n4_onvm_pfcp_handler.c` – PFCP Session Establishment/Modification/Deletion; classifier rebuild/publish logic.
- ONVM core:
  - `onvm/onvm_mgr/onvm_init.c` – manager init; memzones, dynfields, ports.
  - `onvm/onvm_nflib/onvm_nflib.c` – NF initialization and main loop, callbacks (`pkt_handler`, `msg_handler`, `user_actions`).
  - `onvm/onvm_nflib/onvm_common.h` – shared types (`onvm_pkt_meta`, `struct onvm_configuration`, dynfield offsets, etc.).

---

## 3. Shared Session State and DL Rings

### 3.1 `UpfSession` extensions

Defined in `onvm/upf/upf_context.h`:

- `sess_id` (32-bit) – process-agnostic session identifier derived from PFCP SEID.
- `struct rte_ring *dl_ring` – per-session DL FIFO; NULL until first DL packet.
- `rte_atomic32_t buffering` – atomic flag: `0 = live`, `1 = paused`.

Allocation in `onvm/upf/upf.c`:

- `UpfSessionAlloc(seid)` sets:
  - `sess_id = (uint32_t)seid`
  - `dl_ring = NULL`
  - `buffering = 0` via `rte_atomic32_init` + `rte_atomic32_set`.

### 3.2 Per-session DL ring helper

`onvm/upf/upf_session_dl.{h,c}`:

- `struct rte_ring *UpfSessionEnsureDlRing(UpfSession *session);`
  - Looks up or creates ring named `upf_dl_<sess_id>`.
  - Uses `rte_ring_create(name, UPF_DL_RING_SIZE, rte_socket_id(), RING_F_SC_DEQ)`.
  - Publishes `session->dl_ring` with `__atomic_store_n(..., __ATOMIC_RELEASE)` and `rte_wmb()` to guarantee “pointer visible before enqueue”.
  - Consumers load with `__atomic_load_n(..., __ATOMIC_ACQUIRE)`.
- `UpfSessionIsBuffered` / `UpfSessionSetBuffering` wrap the `buffering` atomic.

### 3.3 Queueing invariants

- Elements are `struct rte_mbuf *` as-is (no header stripping before enqueue).
- Producers: ingress (and potentially others in future).
- Consumer: egress (single worker).
- Properties:
  - **Single owner** for DL mbufs: once enqueued, only egress dequeues and frees/transmits.
  - **Per-session order**: maintained by MP enqueue + SC dequeue + single consumer.

---

## 4. Classifier Snapshot and Consumers

- `onvm/upf/upf_cls_ctrl.h` defines a seqlock-based control structure in a memzone (`MZ_UPF_CLS_CTRL`):
  - `active` – pointer to current classifier snapshot.
  - `version` – seqlock version (even = stable, odd = writer in-progress).
- UPF-C publishes a new classifier with `upf_cls_publish` (in `5gc/upf_c/n4_onvm_pfcp_handler.c`):
  - Sets version odd, swaps `active`, sets version even.
  - Keeps retired snapshot until all consumers ACK.
  - Sends `EVT_CLS_GC_REQ` to ingress and egress NFs.
- Ingress and egress each maintain a local `upf_cls_local_t`:
  - `g_cls_local.ptr`, `g_cls_local.ver`, `flip_pending`.
  - Both call `UpfClsMaybeFlipAndAck(consumer_id)`:
    - Reads `version`/`active` via seqlock.
    - Updates `g_cls_local` and sends `EVT_CLS_GC_ACK` to UPF-C with version + consumer ID.

Consumer IDs (from `onvm/utlt/upf_events.h`):

- `UPF_CLS_CONS_INGRESS = 0`, `UPF_CLS_CONS_EGRESS = 1`.
- Service IDs (in this design):
  - Ingress: `UPF_INGRESS_SERVICE_ID` (e.g. service 1).
  - Egress: `UPF_EGRESS_SERVICE_ID` (e.g. service 13 or 14).
  - UPF-C: `UPF_C_SERVICE_ID` (e.g. service 2).

---

## 5. Control-Plane Events and Session Lifecycle

### 5.1 REGISTER and DELETE

`5gc/upf_c/n4_dispatcher.c`:

- On PFCP Session Establishment:
  - `session = UpfSessionAddByMessage(pfcpMessage);`
  - Sends `UPF_EVENT_REGISTER_SESSION(sess_id)` to:
    - Ingress (`UPF_INGRESS_SERVICE_ID`),
    - Egress (`UPF_EGRESS_SERVICE_ID`) if different.

`5gc/upf_c/n4_onvm_pfcp_handler.c`:

- On Session Deletion:
  - Sends `UPF_EVENT_DELETE_SESSION(sess_id)` to ingress and egress.
  - Then calls `UpfSessionRemove(session)` to free state.

### 5.2 Buffering events (design)

`onvm/utlt/upf_events.h`:

- `UPF_EVENT_SET_BUFFER` – set `buffering = 1` (paused).
- `UPF_EVENT_CLEAR_AND_DRAIN` – set `buffering = 0` (resume + drain).

Egress `msg_handler` (`5gc/upf_u/upf_egress.c`):

- On `UPF_EVENT_SET_BUFFER` / `UPF_EVENT_CLEAR_AND_DRAIN`:
  ```c
  UpfSession *s = UpfSessionFindBySeid(sess_id);
  if (s) UpfSessionSetBuffering(s, (e->type == UPF_EVENT_SET_BUFFER) ? 1 : 0);
  ```

In the original implementation, UPF-C **did not yet emit** these events based on PFCP buffering state (they were “future work”). So `buffering` is wired and respected in egress, but driven only by potential future control-plane logic.

---

## 6. Ingress NF – UL Inline, DL Enqueue

File: `5gc/upf_u/upf_ingress.c`

### 6.1 Main flow

- NF tag: `NF_TAG = "upf_ingress"`.
- Init:
  - `onvm_nflib_init_nf_local_ctx`, `onvm_nflib_init_nf_function_table`.
  - Registers:
    - `pkt_handler = packet_handler`.
    - `msg_handler = msg_handler`.
  - Calls `onvm_nflib_init(...)`.
  - Initializes CLS control (`UpfClsCtrlInit()`).
  - Learns NIC MACs for the CN-side ports using the configured port map:
    - `g_access_port` → `cn_ue_eth`.
    - `g_core_port` → `cn_dn_eth`.
  - Parses YAML config (`UpfU_LoadAndParseConfig("config/upf_u.yaml")`) populating `DnMac`, `AnMac`, `SELF_IP`, and `g_access_port`/`g_core_port`/`g_sgi_port`.

### 6.2 UL path (GTP-U → core)

Inside `packet_handler`:

- Classifies UL when `iph->dst_addr == SELF_IP`:
  - Extracts TEID via `get_teid_gtp_packet`.
  - Looks up UL PDR via `GetPdrByTeid`.
  - Strips outer headers as per `pdr->outerHeaderRemoval`.
  - Applies FAR/QER inline:
    - `HandlePacketWithFar(pkt, far, pdr->qer, meta)`.
    - `AttachL2Header(pkt, false)` for UL L2.
  - Returns `status` to ONVM; meta guides TX (to DN NF or NIC).

### 6.3 DL path (core → per-session DL ring)

Still in `packet_handler`:

- For non-SELF_IP destination (DL):
  - Uses `iph->dst_addr` as UE IP (host order via `rte_be_to_cpu_32`).
  - Lookup PDR via `GetPdrByUeIpAddress(pkt, ue_ip)`.
  - Calls `GetQerByUEIpAddress` for QoS bookkeeping.
  - Finds `UpfSession` by UE IP: `UpfSessionFindByUeIP(ue_ip)`.
  - Ensures `session->dl_ring` via `UpfSessionEnsureDlRing(session)`.
  - Enqueues packet:
    ```c
    int rc = rte_ring_mp_enqueue(ring, pkt);
    if (rc < 0) {
        meta->action = ONVM_NF_ACTION_DROP;
        UTLT_Warning("DL enqueue failed (sess_id=%u ring=%p rc=%d)", ...);
        return 0; // manager will free
    }
    return 1; // ownership transferred to egress
    ```
  - In the original (pre-logging) implementation, no timestamp was attached; the mbuf is simply enqueued and ownership moves to egress.

---

## 7. Egress NF – Session Registry and DL Drain

File: `5gc/upf_u/upf_egress.c`

### 7.1 Main components

- NF tag: `NF_TAG = "upf_egress"`.
- `struct session_registry`:
  - `ids[MAX_SESS_REG]`, `count`, `cursor`.
  - Maintains the set of active `sess_id`s for RR traversal.
- Helpers:
  - `registry_add(sess_id)` – append if not present.
  - `registry_remove(sess_id)` – remove by swapping with last; adjust `cursor`.
  - `registry_next_cursor()` – `(cursor + 1) % count`.

### 7.2 Message handling

`msg_handler`:

- `EVT_CLS_GC_REQ` → set `g_cls_local.pending_ver` and `flip_pending = 1`, log, free event.
- `UPF_EVENT_REGISTER_SESSION(sess_id)` → `registry_add(sess_id)`.
- `UPF_EVENT_DELETE_SESSION(sess_id)` → `registry_remove(sess_id)`.
- `UPF_EVENT_SET_BUFFER` / `UPF_EVENT_CLEAR_AND_DRAIN` → adjust `UpfSession.buffering`.

### 7.3 DL processing and QoS (original path)

`process_downlink_pkt`:

- Re-classifies DL packet by UE IP and 5-tuple using `GetPdrByUeIpAddress`.
- Strips outer headers as per `outerHeaderRemoval` (e.g., GTP-U for downlink plain IP).
- Applies FAR:
  - `HandlePacketWithFar(pkt, far, pdr->qer, meta)`.
  - `AttachL2Header(pkt, true)` for DL.
- QoS/token bucket:
  - Uses `ue_table[]` entries (from `upf_u.c`) and `updateTokenbyIndex` to maintain per-UE QoS and non-QoS token buckets.
  - Uses trTCM (`rte_meter_trtcm`) and `trtcmColorHandle`/`trtcmPolicer` for SDF-based QoS.
  - For non-QoS traffic, uses non-QoS bucket (`ue_nqos_tb_params`) with blocking loops:
    ```c
    while (ue_table[index].ue_nqos_tb_params.tb_tokens < cal_pktlen) {
        updateTokenbyIndex(index);
        usleep(1);
    }
    ```
  - These loops can introduce per-packet delay when tokens are depleted.

### 7.4 Round-robin drain

`drain_session(sess_id, nf_local_ctx, tx_buf, tx_count)`:

- Lookup `UpfSession` by `sess_id`.
  - If missing → remove from registry and return.
  - If `UpfSessionIsBuffered(session)` → skip.
- Load `session->dl_ring` with acquire semantics; if NULL, return.
- Repeatedly dequeue bursts:
  ```c
  struct rte_mbuf *burst[DL_DEQ_BURST];
  while ((nb = rte_ring_sc_dequeue_burst(ring, (void **)burst, DL_DEQ_BURST, NULL)) > 0) {
      for (i = 0; i < nb; i++) {
          pkt = burst[i];
          meta = onvm_get_pkt_meta(pkt, g_dynfield_offset);
          meta->action = DROP;
          if (process_downlink_pkt(pkt, meta)) tx_buf[(*tx_count)++] = pkt;
          if (*tx_count == PACKET_READ_SIZE) { onvm_pkt_process_tx_batch(...); *tx_count = 0; }
      }
  }
  ```

`egress_tick(nf_local_ctx)`:

- Calls `UpfClsMaybeFlipAndAck(UPF_CLS_CONS_EGRESS)`.
- If `g_registry.count == 0`, returns.
- Otherwise:
  - For each registered session (RR), calls `drain_session`.
  - After the RR cycle, if `tx_count > 0`, flushes TX via:
    - `onvm_pkt_process_tx_batch(nf->nf_tx_mgr, tx_buf, g_dynfield_offset, tx_count, nf)`
    - `onvm_pkt_flush_all_nfs(nf->nf_tx_mgr, nf)`.

### 7.5 NFLIB main loop (original, pre–busy-poll)

- `main` in `upf_egress.c`:
  - Sets up `nf_function_table`:
    - `pkt_handler = pkt_handler` (drops stray packets).
    - `msg_handler = msg_handler`.
    - `user_actions = egress_tick`.
  - Calls `onvm_nflib_run(nf_local_ctx)`, which spawns the standard nflib thread main loop:
    - Dequeues RX packets and calls `pkt_handler` (irrelevant here).
    - Flushes TX.
    - Dequeues NF messages and calls `msg_handler`.
    - Calls `user_actions` once per loop, i.e., `egress_tick`.
  - `keep_running` is controlled by signals and manager messages.

Thus, in the original design, the **timing of DL draining** is governed by how often nflib’s main loop calls `user_actions` (plus how long `egress_tick` spends per iteration).

---

## 8. Intermittent ~8 ms DL Enqueue→Dequeue Delay

### 8.1 Observation

During testing of the original (pre–busy-poll) split implementation, we observed occasional spikes in end-to-end ping latency. Wireshark/tcpdump and NF logging indicated that:

- DN received and replied to ICMP Echo Requests promptly.
- UPF-C and rule installation were not obviously slow.
- The spikes appeared as intermittent **8 ms-ish jitter** in an otherwise low-latency path.

### 8.2 Instrumentation in `feature/upf-split-with-logs`

To pinpoint where this delay lived, we added a DL enqueue→dequeue timestamp:

- Manager (`onvm_mgr`) registered a second mbuf dynfield `upf_dl_ts` and exposed its offset via `onvm_config->dl_ts_dynfield_offset`.
- NFs learned this offset as `onvm_dl_ts_offset` via `onvm_nflib_parse_config`.
- Ingress:
  - Immediately before `rte_ring_mp_enqueue(ring, pkt)`, we wrote:
    ```c
    uint64_t *ts = RTE_MBUF_DYNFIELD(pkt, onvm_dl_ts_offset, uint64_t *);
    if (ts) *ts = rte_get_tsc_cycles();
    ```
- Egress:
  - At the very top of `process_downlink_pkt`, we read and logged:
    ```c
    uint64_t *ts = RTE_MBUF_DYNFIELD(pkt, onvm_dl_ts_offset, uint64_t *);
    if (ts && *ts) {
        uint64_t diff = rte_get_tsc_cycles() - *ts;
        double us = (double)diff * 1e6 / rte_get_timer_hz();
        UTLT_Info("[DL] enqueue→dequeue latency: %.3f us", us);
        *ts = 0;
    }
    ```

This measured **only** the time between:

1. Ingress enqueue to per-session `dl_ring`, and
2. Egress starting to process that mbuf (before FAR/QoS).

### 8.3 What the logs showed (original implementation)

The logs on that branch showed:

- Most DL enqueue→dequeue latencies in the **1–3 µs** range.
- Intermittent spikes in the **2–8 ms** range (e.g., ~2000 µs, ~6000 µs, occasionally up to ~8000 µs).

Critically, we also saw that **some DL packets were not being drained every `egress_tick`**:

- When nflib’s main loop was under load (lots of NFs, shared resources, etc.), the `user_actions` callback (and thus `egress_tick`) could be delayed.
- During such periods, DL packets would be enqueued into their per-session `dl_ring` but not dequeued until a later iteration of the nflib loop.
- The measured enqueue→dequeue latency matched the gap between the enqueue and the next time `egress_tick` actually ran and visited that session in the registry.

### 8.4 Interpretation

From the logs and design:

- The occasional ~8 ms delay is **inside the data-plane buffering path between ingress and egress**, not in DN or the UE stack:
  - Ingress enqueue happens promptly after DL classification.
  - Egress only drains when:
    - nflib’s main loop calls `user_actions` and
    - `egress_tick` visits the session in the RR registry.
  - Any delay in those steps inflates the enqueue→dequeue latency.
- The DL ring itself is non-blocking; the delay is due to *when* the consumer (egress) executes, not the ring operations.
- QoS `usleep(1)` loops can add extra per-packet delay at the **end** of this period, but the instrumentation clearly showed that even without QoS being the root cause, there were windows where packets simply sat in the DL ring waiting for the next `egress_tick`.

In short:

- The original split implementation successfully introduced per-session DL buffering with strict FIFO order and a RR scheduler in egress.
- However, under realistic load, nflib’s scheduling of `user_actions` meant that some DL packets experienced multi-millisecond pauses between enqueue and dequeue, which we measured explicitly with the `upf_dl_ts` dynfield logging.

These observations motivated the later “busy-poll egress” experiment described separately in `onvm-upf-u-split-busy-poll.md`. 

