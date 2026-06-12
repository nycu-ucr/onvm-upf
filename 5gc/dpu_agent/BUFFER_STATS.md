# DPU Buffer Stats Guide

This note explains the counters printed by `dpu_buffer_dump_stats()` in
[`dpu_buffer.c`](./dpu_buffer.c), and how to read them during a
`BUFF -> FORW` transition.

The buffer is DL-only. When a DL rule enters `BUFF`, matching packets are
redirected from hardware to the ARM-side buffer Rx loop and stored in a
per-flow `rte_ring`. During `FORW`, the flow goes through:

`ACTIVE -> DRAINING -> CLOSED`

The relevant code is in:

- [`dpu_buffer.h`](./dpu_buffer.h)
- [`dpu_buffer.c`](./dpu_buffer.c)

## State Machine

- `INACTIVE`
  Slot unused.
- `ACTIVE`
  Hardware still points to `TO_DPU_ARM_DL`. New packets are queued in the
  per-flow ring.
- `DRAINING`
  Used for `BUFF -> FORW`. The Rx lcore drains old ring contents first. While
  old packets remain, new arrivals are re-enqueued at the tail to preserve
  FIFO order. Once the ring is empty, new arrivals are sent directly on the
  pass-through path.
- `CLOSING`
  Used for `DROP`/`DELETE`, not normal `FORW`.
- `CLOSED`
  Drain/close completed. The flow stays visible in stats until the slot is
  reused, but it is no longer registered in `flow_id_map`.

## Current `BUFF -> FORW` Design

The current `FORW` path is orchestrated in
[`dpu_agent.c`](./dpu_agent.c), using the buffer-side helpers in
[`dpu_buffer.c`](./dpu_buffer.c) and the per-bucket DL override removal in
[`dpu_pipeline.c`](./dpu_pipeline.c).

The sequence is:

1. `update_dlencap_only()`
   Update the DL ENCAP entry and the software encap cache with the new
   gNB IP/TEID/QFI.
2. `begin_drain()`
   Transition `ACTIVE -> DRAINING` while hardware still points to
   `TO_DPU_ARM_DL`.
3. `wait_drain_done()`
   Wait for the Rx lcore to drain the buffered ring and observe at least one
   full Rx cycle with the ring empty.
4. `update_far(FORW)`
   Remove the matching `DL_*_BUFF_OVERRIDE` entry.
   This is the moment the hardware fast path reopens.
   The base `DL_*_MATCH` entry was never deleted; once the override is gone,
   new packets can fall through to the existing fast path immediately.
5. `rte_delay_us_block(50)`
   Fixed 50us grace period for packets already in flight toward the ARM Rx
   side.
6. `close_flow()`
   Transition `DRAINING -> CLOSED`, remove the flow from `flow_id_map`, and
   flush any residual packets that already made it into the ring.
7. `set_mode(FAST)`
   Update the pipeline record's logical mode.

Important clarifications:

- `FORW` does **not** wait on `enq_seq == deq_seq`.
  That quiesce check is used by the `DROP`/`DELETE` path, not by the normal
  `BUFF -> FORW` handoff.
- `wait_drain_done()` is the `FORW` fence.
  It proves the ring drained while the override was still active, not that no
  more old-path packets can arrive later from hardware.
- Hardware is reopened at step 4, not after `close_flow()`.

What this design guarantees:

- No DL base-entry delete+reinsert window during `BUFF -> FORW`.
  The base DL match entry stays installed throughout; only the override entry
  is removed.
- While the flow is still `DRAINING`, packets that are already committed to
  the old ARM path can still be handled by software pass-through.

What this design does **not** guarantee:

- The fixed 50us delay is not a hard retire barrier for the old ARM delivery
  path. It is a heuristic grace period.
- Packet ordering is not guaranteed during that grace period.
  After step 4, newer packets can already take the restored hardware fast
  path while older tail packets may still arrive on the ARM path and be
  software-transmitted.
- `residual=0` at `close_flow()` does not prove that no more old-tail packets
  exist.
  It only proves the ring was empty at close time.
  A packet that arrives after `close_flow()` removed the flow from
  `flow_id_map` is not counted as `residual`; it is dropped by the
  "no flow for rule_id" path instead.

## Global Line

Example:

```text
Buffer stats (global): in_flight=1312 draining=0 max_flows=400000 rx_port=3 tx_port=2 tx_q=2
```

Field meanings:

- `in_flight`
  Current total number of packets sitting in all per-flow rings.
  This is `ctx->global_count`.
  Despite the name, it does **not** mean "packets currently being processed by
  hardware" or "packets on the wire". It is closer to "currently queued in
  buffer memory".
- `draining`
  Number of flows currently in `DRAINING` state.
  This is `ctx->nr_draining`.
  It counts flows, not packets.
- `max_flows`
  Configured maximum number of buffer flow slots.
- `rx_port`
  DPDK Rx port ID polled by the buffer Rx loop. In this design this is the N6
  PF, fed by `TO_DPU_ARM_DL`.
- `tx_port`
  DPDK Tx port ID used by the software encap/drain path. In this design this
  is the N3 PF.
- `tx_q`
  Tx queue ID on `tx_port` used by the drain path.

## Per-Flow Line

Example:

```text
flow hw_rule_id=4 dir=DL state=ACTIVE ring=1312 drain_done=0 enq_seq=1312 deq_seq=1312 | enq=1312 drop=0 drained=0 passthrough=0 requeued=0
```

Field meanings:

- `hw_rule_id`
  The buffered flow.
- `dir`
  Direction. Buffering is expected to be `DL`.
- `state`
  One of `ACTIVE`, `DRAINING`, `CLOSING`, `CLOSED`.
- `ring`
  Current packet count in this flow's `rte_ring`.
  This is the best direct measure of "how much data is still queued for this
  flow right now".
- `drain_done`
  Drain completion flag.
  `0` means the Rx lcore has not yet declared the ring drained.
  `1` means the Rx lcore observed the ring empty in the `DRAINING` path.
- `enq_seq`
  Quiesce sequence number incremented **before** the Rx loop processes a packet
  for this flow in `ACTIVE`/`CLOSING`.
- `deq_seq`
  Quiesce sequence number incremented **after** the Rx loop finishes handling
  that packet, whether it was queued, dropped, or freed.
- `enq`
  Number of packets queued while the flow was in `ACTIVE`.
  This counts initial buffering.
- `drop`
  Number of packets dropped by the buffer path.
  Typical reasons are:
  - global buffer cap reached
  - per-flow ring enqueue failed
  - requeue during `DRAINING` failed
- `drained`
  Number of buffered packets successfully transmitted by the drain path after
  being dequeued from the ring.
  Important: this is a count of successful Tx/reinject from the ring, not just
  "number dequeued from the ring".
- `passthrough`
  Number of packets sent directly during `DRAINING` after the ring became
  empty.
  These packets were not stored in the ring.
- `requeued`
  Number of new arrivals during `DRAINING` that were appended to the ring tail
  because older packets were still pending.
  This preserves FIFO ordering.

## Slot Summary Line

Example:

```text
Buffer stats (slots): active=1 draining=0 closing=0 closed=0
```

This counts flow slots by state:

- `active`: number of flows in `ACTIVE`
- `draining`: number of flows in `DRAINING`
- `closing`: number of flows in `CLOSING`
- `closed`: number of flows in `CLOSED`

These are flow counts, not packet counts.

## Totals Line

Example:

```text
Buffer stats (totals): enq=1312 drop=0 drained=0 passthrough=0 requeued=0
```

This is the sum of the per-flow lifetime counters across all non-`INACTIVE`
slots currently present in the buffer table.

These totals are cumulative per slot lifetime, not instantaneous queue depth.

## The Most Important Non-Obvious Point

`enq_seq == deq_seq` does **not** mean the ring is empty.

It only means the Rx lcore is not currently mid-way through processing a packet
for that flow.

That is why this line is valid:

```text
state=ACTIVE ring=1312 drain_done=0 enq_seq=1312 deq_seq=1312
```

Interpretation:

- no packet is currently "half-processed" by the Rx lcore
- but 1312 packets are still sitting in the ring waiting for a future drain

## How to Read Your Example

### Before FORW

```text
Buffer stats (global): in_flight=1312 draining=0 ...
flow hw_rule_id=4 dir=DL state=ACTIVE ring=1312 drain_done=0 enq_seq=1312 deq_seq=1312 | enq=1312 drop=0 drained=0 passthrough=0 requeued=0
```

Meaning:

- one DL flow is actively buffering
- 1312 packets are currently queued in its ring
- no flow is draining yet
- all 1312 packets were normal `ACTIVE` enqueues
- none were drained yet
- no drops occurred

### Drain Starts

```text
begin_drain: hw_rule_id=4 ACTIVE → DRAINING (ring_count=2049)
```

Meaning:

- at the moment `begin_drain()` ran, the ring had grown to 2049 packets
- this is larger than the earlier 1312 because more packets arrived between
  the earlier stats dump and the later `FORW`

### Drain Completes

```text
wait_drain_done: hw_rule_id=4 drain complete (drained=2049 passthrough=0)
```

Meaning:

- the Rx lcore drained all 2049 queued packets from the ring and transmitted
  them
- no new packets arrived after the ring became empty, otherwise
  `passthrough` would be greater than zero

### Close

```text
close_flow: hw_rule_id=4 DRAINING → CLOSED (enq=2049 requeued=0 drop=0 drain=2049 passthrough=0 residual=0)
```

Meaning:

- the flow transitioned to `CLOSED`
- `enq=2049`: 2049 packets were buffered during the `ACTIVE` phase
- `requeued=0`: no new arrivals had to be appended during bounded draining
- `drop=0`: nothing was lost in the buffer path
- `drain=2049`: all buffered packets were successfully drained and transmitted
- `passthrough=0`: no direct-send packets happened after the ring emptied
- `residual=0`: the safety-net flush at close found nothing left in the ring

### Final Stats

```text
flow hw_rule_id=4 dir=DL state=CLOSED ring=0 drain_done=1 enq_seq=2049 deq_seq=2049 | enq=2049 drop=0 drained=2049 passthrough=0 requeued=0
Buffer stats (global): in_flight=0 draining=0 ...
```

Meaning:

- the ring is empty
- no flow is still draining
- the flow slot remains visible as `CLOSED` for observability
- the buffer path finished cleanly with zero loss

## Useful Sanity Checks

For a healthy `BUFF -> FORW` cycle, these are good signs:

- `ring` goes to `0`
- `in_flight` goes to `0`
- `draining` goes back to `0`
- `state` ends at `CLOSED`
- `drop=0`
- `residual=0`

Possible patterns to watch:

- `passthrough > 0`
  New packets arrived after the ring became empty but before hardware was fully
  switched back to the fast path. This is allowed.
- `requeued > 0`
  New packets arrived while old buffered packets were still being drained.
  Also allowed.
- `residual > 0`
  Close had to flush packets still left in the ring. This is a warning sign.
- `state=DRAINING` for too long
  Drain did not converge or `FORW` failed after drain.

## Relationship Between Counters

These relationships are usually useful:

- instantaneous queue depth:
  `in_flight ~= sum(ring over flows)`
- `drained + passthrough`
  total packets successfully sent during `DRAINING`
- `enq`
  packets that were buffered before the ring first became empty
- `requeued`
  packets that arrived during `DRAINING` while old packets still existed

Do not expect:

- `enq == drained + passthrough`

because:

- `passthrough` packets were never queued
- `requeued` is tracked separately from `enq`
- failed Tx is not counted in `drained`

## Short Glossary

- `in_flight`: packets currently queued in buffer memory
- `ring`: queued packets for one flow
- `drain_done`: Rx lcore has observed the ring empty
- `enq_seq/deq_seq`: quiesce bookkeeping, not ring occupancy
- `enq`: buffered while `ACTIVE`
- `drained`: queued packets successfully sent during drain
- `passthrough`: direct-send packets during `DRAINING`
- `requeued`: new arrivals appended during `DRAINING`
- `residual`: packets force-flushed during `close_flow`
