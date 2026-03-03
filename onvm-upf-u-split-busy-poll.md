# UPF-U Egress Busy-Poll Implementation – Behaviour and Findings

This document describes the “busy-poll egress” experiment for the split UPF-U, and what we learned from the additional logging. It assumes familiarity with the baseline split design described in `onvm-upf-u-split-feature-updated.md`.

---

## 1. Motivation

In the original split implementation:

- Egress’s DL draining logic (`egress_tick`) ran only when ONVM’s nflib main loop invoked `user_actions`.
- Under load, we observed intermittent multi-millisecond enqueue→dequeue delays for DL packets:
  - Most `enqueue→dequeue` latencies were ~1–3 µs.
  - Spikes of ~2 ms and ~6–8 ms appeared sporadically.
- These spikes matched the time between:
  - Ingress enqueueing a DL packet to the per-session `dl_ring`, and
  - The next time nflib’s main loop happened to call `egress_tick` and drain that ring.

Hypothesis: if we remove the nflib main loop from the scheduling path and put egress’s DL drain into a tight, dedicated loop, we can eliminate these enqueue→dequeue spikes.

---

## 2. Busy-Poll Egress Design

### 2.1 Key idea

- Keep the existing **ingress** implementation (UL inline, DL enqueue).
- Keep the existing **egress** logic (`session_registry`, `drain_session`, `process_downlink_pkt`, QoS, classifier flip).
- **Change only how egress is driven**:
  - Instead of relying on nflib’s `user_actions`, make egress run its own tight loop:
    ```c
    while (rte_atomic16_read(&nf_local_ctx->keep_running)) {
        onvm_nflib_dequeue_messages(nf_local_ctx);
        egress_tick(nf_local_ctx);
        rte_pause();
    }
    ```

This makes a single thread responsible for:

- Message handling (REGISTER/DELETE/CLS_GC_REQ, etc.).
- Calling `UpfClsMaybeFlipAndAck(UPF_CLS_CONS_EGRESS)`.
- Draining per-session DL rings and forwarding DL packets.

### 2.2 Implementation details

File: `5gc/upf_u/upf_egress.c` (busy-poll branch)

- Includes:
  - `onvm_nflib.h`
  - `onvm_threading.h`
  - `onvm_pkt_helper.h`
  - `utlt_debug.h`
- `nf_function_table`:
  - Only `msg_handler = msg_handler` is used; no `pkt_handler`, no `user_actions`.
  - `pkt_handler` still exists but is effectively unused (egress expects no RX traffic).
- NF initialization:
  - `nf_local_ctx = onvm_nflib_init_nf_local_ctx();`
  - `onvm_nflib_start_signal_handler(nf_local_ctx, NULL);`
  - `nf_function_table = onvm_nflib_init_nf_function_table();`
  - `nf_function_table->msg_handler = &msg_handler;`
  - `onvm_nflib_init(argc, argv, NF_TAG, nf_local_ctx, nf_function_table)`:
    - Parses NF args.
    - Starts NF (assigns `instance_id`, `service_id`, sets `nf_local_ctx->nf`).
    - Associates the function table with the NF.
  - YAML config is loaded (`UpfU_LoadAndParseConfig`), CLS control initialized (`UpfClsCtrlInit`), and MACs for CN-side ports learned using `g_access_port` and `g_core_port`.
- Instead of `onvm_nflib_run(nf_local_ctx)`, the NF now:
  ```c
  struct onvm_nf *nf = nf_local_ctx->nf;
  onvm_threading_core_affinitize(nf->thread_info.core);

  printf("Sending NF_READY message to manager...\n");
  if (onvm_nflib_nf_ready(nf) != 0) {
      rte_exit(EXIT_FAILURE, "Unable to message manager\n");
  }

  while (rte_atomic16_read(&nf_local_ctx->keep_running)) {
      onvm_nflib_dequeue_messages(nf_local_ctx);
      egress_tick(nf_local_ctx);
      rte_pause();
  }
  ```

### 2.3 Exposing message dequeue to NFs

Originally, `onvm_nflib_dequeue_messages` was `static inline` inside `onvm_nflib.c`. To safely reuse the existing message handling (and internal msg mempool) from our custom loop, we:

- Changed its declaration to a non-static function and added a prototype in `onvm_nflib.h`:
  ```c
  void onvm_nflib_dequeue_messages(struct onvm_nf_local_ctx *nf_local_ctx);
  ```
- Implementation still:
  - Checks `nf_local_ctx->nf->msg_q` via `rte_ring_count`.
  - If a message is available:
    - `rte_ring_dequeue`.
    - Calls `onvm_nflib_handle_msg(msg, nf_local_ctx)` (which dispatches to `msg_handler` for `MSG_FROM_NF`).
    - Returns the message to `nf_msg_pool` via `rte_mempool_put`.

This keeps NF code from touching `struct onvm_nf_msg` or the msg mempool directly.

---

## 3. Maintaining the DL Latency Logging

The busy-poll branch preserved the `upf_dl_ts` logging infrastructure from `feature/upf-split-with-logs`:

- Manager:
  - Registers `onvm_pkt_meta_dynfield` and `upf_dl_ts` in `onvm_mgr/onvm_init.c`.
  - Stores offsets in `onvm_config->dynfield_offset` and `onvm_config->dl_ts_dynfield_offset`.
- NFLIB:
  - `onvm_nflib_parse_config` sets `ONVM_NF_SHARE_CORES` and `onvm_dl_ts_offset` from `onvm_config`.
- Ingress:
  - Before enqueuing to `dl_ring`, stamps `upf_dl_ts`:
    ```c
    if (likely(onvm_dl_ts_offset >= 0)) {
        uint64_t *ts = RTE_MBUF_DYNFIELD(pkt, onvm_dl_ts_offset, uint64_t *);
        if (ts) *ts = rte_get_tsc_cycles();
    }
    ```
- Egress:
  - At the top of `process_downlink_pkt`, logs enqueue→dequeue latency:
    ```c
    if (likely(onvm_dl_ts_offset >= 0)) {
        uint64_t *ts = RTE_MBUF_DYNFIELD(pkt, onvm_dl_ts_offset, uint64_t *);
        if (ts && *ts) {
            uint64_t diff = rte_get_tsc_cycles() - *ts;
            double us = (double)diff * 1e6 / rte_get_timer_hz();
            UTLT_Info("[DL] enqueue→dequeue latency: %.3f us", us);
            *ts = 0;
        }
    }
    ```

This lets us compare enqueue→dequeue behaviour between the nflib-driven and busy-poll-driven egress implementations directly.

---

## 4. What the Busy-Poll Logs Showed

With the busy-poll loop, the logs showed:

- **Typical DL enqueue→dequeue latency**: ~1–2 µs.
  - This confirms that, under normal conditions, ingress→ring→egress is extremely fast.
- **Intermittent spikes in DL enqueue→dequeue**: ~2 ms and ~6 ms (e.g. ~2095 µs, ~6069–6127 µs), similar to what was observed before.
  - These spikes persisted even when the QoS `while (...) usleep(1)` loops were temporarily disabled, and also after restoring them.

Example pattern:

```text
[DL] enqueue→dequeue latency: 1.5 us
[DL] enqueue→dequeue latency: 1.7 us
[DL] enqueue→dequeue latency: 2095.8 us
[DL] enqueue→dequeue latency: 1.3 us
[DL] enqueue→dequeue latency: 1.7 us
[DL] enqueue→dequeue latency: 0.9 us
[DL] enqueue→dequeue latency: 6069.3 us
[DL] enqueue→dequeue latency: 6122.1 us
[DL] enqueue→dequeue latency: 1.4 us
...
```

At the same time:

- Egress logs showed `drain_session` consuming one packet per second per ping (as expected for 1 Hz pings), with `buffering=0` and `nb=1` per drain call.
- The busy-poll loop was clearly running continuously (no evidence of long sleep or blocking in the loop itself).

---

## 5. Key Findings

### 5.1 Busy-polling does **not** remove the enqueue→dequeue spikes

The experiment showed that:

- Moving egress from:
  - nflib-managed `user_actions` callback, to
  - a dedicated busy-poll loop (`while (keep_running) { dequeue_messages; egress_tick; rte_pause; }`)
  **did not materially change** the observed enqueue→dequeue distribution:
  - Microsecond-scale majority.
  - Occasional 2–6 ms spikes.
- This indicates that:
  - The original nflib loop was **not** the sole bottleneck responsible for the observed spikes.
  - Other factors (e.g., QoS token-bucket loops, per-packet work in `process_downlink_pkt`, cache/memory effects) can still produce several milliseconds of delay **after** the packet leaves the ring but before ONVM hands it to the NIC or next NF.

### 5.2 The DL ring itself is not the main problem

Both before and after busy-polling:

- DL enqueue→dequeue latencies rarely exceeded a few milliseconds; they did **not** match the multi-second ping RTTs observed at the UE.
- Under logging, we saw:
  - No large DL ring backlog for the ping flows (each ping led to `nb=1` DL dequeue).
  - Egress visiting the session on every iteration where a new DL packet was present.

This strongly suggests that:

- The per-session DL ring + RR scheduler is not introducing multi-second queuing delays.
- The multi-second ping “countdown” (e.g., 9 s → 8 s → ... → 1 s) observed elsewhere has to be attributed to:
  - Other sections of the dataplane (e.g., QoS or UL path), and/or
  - Host / UE-side behaviour (e.g., TUN handling, process scheduling), rather than the enqueue→dequeue gap measured in the DL ring.

### 5.3 DN sees ICMP quickly; UE still sees multi-second RTT

Additional observations:

- DN node tcpdump shows ICMP echo requests arriving and responses leaving promptly.
- Yet the UE’s `ping` tool sometimes sees multi-second RTTs with a “countdown” pattern.

When combined with the DL enqueue→dequeue logs:

- DN-side quick response implies UL (UE→UPF→DN) is not the primary source of multi-second delay.
- DL enqueue→dequeue is mostly microseconds to a few milliseconds.

Thus, the remaining RTT gap is likely:

- Downstream of egress (e.g., in the UE host stack or RAN/UE NF handling of tunnelled packets), or
- A combination of:
  - Minor but real enqueue→dequeue spikes (~2–6 ms),
  - Additional jitter in QoS and other processing stages, and
  - Non-UPF factors (e.g., scheduler, congestion, TUN latency) that the busy-poll loop cannot directly address.

---

## 6. Summary

- We implemented a single-thread, busy-poll egress loop that:
  - Takes over what nflib’s main loop used to do for this NF (message dequeue + DL drain).
  - Keeps per-session DL rings and QoS logic unchanged.
  - Preserves the DL enqueue→dequeue logging instrumentation.
- Measured behaviour:
  - DL enqueue→dequeue is almost always µs-level, with occasional ms-level spikes, **both before and after** busy-polling.
  - The busy-poll design did not eliminate the spikes or the multi-second ping RTTs observed at the UE.
- Conclusion:
  - The busy-poll egress implementation is a valid alternative scheduling strategy, but it does **not** solve the deeper latency issue.
  - The significant latency outliers must originate elsewhere (QoS/token-bucket, UL path, or outside UPF entirely), not purely from nflib’s `user_actions` timing or the DL ring’s enqueue/dequeue behaviour.

