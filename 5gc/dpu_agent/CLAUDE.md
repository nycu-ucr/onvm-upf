# CLAUDE.md

Guidance for Claude Code when working in the **dpu_agent** subtree (`5gc/dpu_agent/`) only. This is a standalone DOCA application — it does NOT link `onvm_nflib`; don't assume the wider `onvm-upf` ONVM patterns apply here.

For deeper detail, see (this file is the entry point — these are the authoritative references):
- [DPU_ARM_BUFFERING_STRATEGY.md](../../DPU_ARM_BUFFERING_STRATEGY.md) — buffering + the BDP byte-budget allocator (full design).
- [BF3_DPU_OFFLOAD_TECHNICAL_DOC.md](../../BF3_DPU_OFFLOAD_TECHNICAL_DOC.md) — end-to-end split-agent offload (host_agent + dpu_agent, pipeline, message format, lifecycle).
- [docs/DPU_ARM_POLICING_AND_SHAPING.md](../../docs/DPU_ARM_POLICING_AND_SHAPING.md) — GBR token-bucket shaper.

## What this binary is

A DOCA application on the **BlueField-3 ARM cores**. It takes UPF rule offloads from a host process (`host_agent`, x86) over **DOCA Comch**, translates them into **DOCA Flow VNF-mode** pipes, and runs the data plane (UL decap, DL encap, ARP, buffering, shaping) on the BF3. Two PF ports: **N3** (p0, `03:00.0`, DOCA Flow port 0) toward gNB/UE, **N6** (p1, `03:00.1`, port 1) toward the DN.

- UL: `wire(N3) → N3_ROOT → UL_MATCH → UL_COLOR_GATE? → UL_DECAP → FWD_PORT(N6)`
- DL: `wire(N6) → N6_ROOT → DL_SDF_MATCH/DL_MATCH → DL_COLOR_GATE? → FWD_PIPE(DL_ENCAP@N3 EGRESS root) → FWD_PORT(N3)`

## Build and run

DOCA SDK is **BF3-only** — local edits compile-check at most.

```bash
# On BF3 ARM
meson setup build            # first time
ninja -C build
sudo ./build/dpu_agent -j config/dpu_agent_params.json
kill -SIGUSR1 <pid>          # dump pipeline + buffer + shaper + responder stats
kill -SIGINT  <pid>          # clean shutdown
```

`meson.build` lists the compiled `.c` files. `*_backed.c` / `*_stable.*` are **non-compiled historical variants** — don't edit them, don't trust them over the active files.

## DOCA Flow constraints (carry forward — these forced the current shape)

1. **Port IDs are constants, not config**: `DPU_PORT_ID_N3=0`, `DPU_PORT_ID_N6=1` ([dpu_pipeline.h](dpu_pipeline.h)). But **DPDK ethdev IDs are NOT probe-order** (BF3 auto-probes SF aux devices first) — resolve real PF IDs by PCI string via `find_dpdk_port_by_pci()` → `g_n3_dpdk_port` / `g_n6_dpdk_port`.
2. **GTP encap MUST live in EGRESS** on the egress port. DEFAULT-domain encap silently emits malformed packets. `DL_ENCAP` is the **egress_root on N3**; `UL_DECAP` stays DEFAULT (decap works there).
3. **An egress_root sees ALL Tx on its port.** `N3_EGRESS_PASSTHROUGH` (a FWD_PIPE catch-all — HWS rejects `fwd_miss = FWD_PORT`) is `DL_ENCAP`'s `fwd_miss` so non-DL Tx still escapes the wire.
4. **Cross-port + cross-domain `FWD_PIPE` is allowed only into an egress_root** (`DL_MATCH`@N6 → `DL_ENCAP`@N3).
5. **Tx-injected packets do NOT re-enter the ingress ROOT** in VNF mode. The buffer/shaper lcores therefore finalise the full wire-form packet in software (`dpu_gtp_codec`) and Tx on the **peer** port.
6. **`RTE_MBUF_DYNFLAG_TX_METADATA` is the same bit as the Rx metadata flag.** `dpu_gtp_codec` clears it before Tx, else mlx5 re-injects the old `pkt_meta` on N3 egress and `DL_ENCAP` double-encaps.
7. **mbuf Rx metadata is host byte order** (mlx5 converts BE→host). Lcores must NOT `ntohl()` the `rte_flow_dynf_metadata_get()` rule_id.
8. **Promiscuous on both PFs + `fdb_def_rule_en=0`** required (the host kernel owns the UPF IPs). Probe devargs: `dv_flow_en=2,fdb_def_rule_en=0,dv_xmeta_en=4`.
9. **HWS allows exactly ONE live `doca_flow_pipe_basic_update_entry()` per entry lifetime** (2nd → `DOCA_ERROR_IN_USE` rc=-16; `actions=NULL` → rc=-22). Root cause (researched 2026-06 against DPDK mlx5dr + DOCA 3.3 docs): an HWS "update" is internally a **re-create** gated on rule status CREATED (else EBUSY) and consumes fresh pipe space — never an in-place mutation; full background + references in DPU_ARM_BUFFERING_STRATEGY.md §11.9. Codebase contract: **first change may update, every later change is delete+add.** `update_dlencap_only` implements it — no-op on unchanged params, try `update_entry`, fall back to `reinsert_dl_encap_with_new_params()` (the remove+add window is traffic-free during BUFF→FORW because the override still detours the flow; only a FAST-mode handover pays the ~100µs gap). `reinsert_dl_match_with_new_fwd()` is the still-unwired twin for a repeated `update_qer`. BUFF/FORW use the **override pipe** and so do NOT consume the base entry's update slot. `remove_entry` right after an `update_entry` can transiently EBUSY → retry with `entries_process()` between attempts.
10. **`doca_flow_pipe_basic_add_entry` needs a FULLY-populated per-entry `doca_flow_actions`** — don't shrink it to only the CHANGEABLE fields (zeros come out on the wire). This is unlike the `upf_accel` `add_entry`+`action_idx` template pattern.
11. **`doca_flow_entries_process(port,0,0,0)` is one poll cycle, not a barrier.** Most SW state advances on enqueue, not confirmed completion — a known smell in entry-lifecycle code.

## Source layout

| File | Role |
|---|---|
| [dpu_agent.c](dpu_agent.c) | Main: EAL/DOCA init, device probe, per-port DPDK queues, Comch server, lcore launch, `comch_recv_cb` dispatch, signals. |
| [dpu_pipeline.c](dpu_pipeline.c)/[.h](dpu_pipeline.h) | All DOCA Flow pipe builders + per-rule CRUD (`insert_rule`, `delete_rule`, `update_far`, `update_qer`, `update_pdr`, `update_dlencap_only`). Largest file; architectural heart. |
| [dpu_buffer.c](dpu_buffer.c)/[.h](dpu_buffer.h) | Per-flow DL buffering for BUFF→FORW + the **BDP byte-budget allocator** (control tick: EWMA demand → max-min byte grants). |
| [dpu_gtp_codec.c](dpu_gtp_codec.c)/[.h](dpu_gtp_codec.h) | Shared SW GTP-U codec (`dpu_gtp_encap_dl`, `dpu_gtp_decap_ul`); clears TX_METADATA. |
| [dpu_shaper.c](dpu_shaper.c)/[.h](dpu_shaper.h) | GBR YELLOW token-bucket shaper. |
| [dpu_l2l3_responder.c](dpu_l2l3_responder.c)/[.h](dpu_l2l3_responder.h) | ARP responder + periodic GARP / unicast-reply. |
| [dpu_agent_config.c](dpu_agent_config.c)/[.h](dpu_agent_config.h) | `doca_argp` knob registration. |
| [hw_offload_msg.h](hw_offload_msg.h) | Comch host↔DPU wire format. **Changes here are an ABI break — coordinate with host_agent.** |
| [config/dpu_agent_params.json](config/dpu_agent_params.json) | Default runtime config (CLI args of the same name override). |

## Lcore layout

- **Main**: `doca_pe_progress` for Comch, applies rules.
- **Buffer**: `dpu_buffer_rx_loop` on N6 Rx q0..3; also runs the allocator control tick.
- **Shaper**: `shaper_loop` on N3 Rx 0..3 (UL YELLOW) + N6 Rx 4..7 (DL YELLOW).
- **Responder**: `l2l3_responder_loop` on N3 Rx 4 + N6 Rx 8; periodic ARP Tx.

Queue ranges / Tx queue IDs are in the top of [dpu_pipeline.h](dpu_pipeline.h).

## Current state

**Fast path (UL/DL)**: stable. UE↔DN works through the BF3 hardware pipeline.

**ARP**: asymmetric. N3 ARPs reach DOCA Flow and the responder replies. On N6 the firmware routes ARP to the host representor (`pf1hpf`), not BF3 ARM — worked around by periodic gratuitous-ARP + unicast-ARP-reply Tx every 1 s (peer L2/L3 from JSON; empty peer IP disables that side).

**BUFF mode**: DL only, via per-bucket per-family **override pipes** interleaved with the base DL classifier (`DL_SDF_BUFF_OVERRIDE_Px` / `DL_BUFF_OVERRIDE_Px`). `update_far(BUFF)` *adds* an override entry (match = `rec->cached_dl_match` verbatim, action `pkt_meta=htonl(rule_id)`, fwd → `TO_DPU_ARM_DL`); the base `DL_*_MATCH` entry is never touched. `update_far(FORW)` refreshes encap (`update_dlencap_only` — no-op if params unchanged; 2nd+ change auto-falls back to encap delete+add, see constraint 9) → `begin_drain` → `wait_drain_done` → *removes* the override → `set_mode(FAST)` → `begin_retire` (DRAINING→RETIRING) → (`wait_retire_done` → `close_flow`). The close is an **observed retire** (the Rx lcore declares old-path quiescence: K empty Rx epochs + tail-idle measured from RETIRING entry) that replaces the old fixed 50µs cutover delay. Drained and late in-flight packets are SW GTP-U+PSC encapped (`dpu_gtp_encap_dl`) and Tx'd on **N3 q2**. UL BUFF is rejected (`DOCA_ERROR_NOT_SUPPORTED`). Full protocol: [DPU_ARM_BUFFERING_STRATEGY.md](../../DPU_ARM_BUFFERING_STRATEGY.md).

**BDP byte-budget allocator** (replaces the old flat packet caps): the buffer admits per flow against a byte grant `A_i` and a global budget `M_op` (`m-op-bytes`, default 16 GiB; **unset/`0xFFFFFFFFFFFFFFFF` = OFF → legacy packet caps**). A control tick on the buffer lcore (every `tick-ms`) measures each ACTIVE flow's **offered load** (`enqueued + all-dropped` bytes — `A_i`-invariant), EWMAs it into a demand `U_i = rate × t-hold-ms`, and recomputes **max-min** grants under `M_op` (leaving DRAINING/CLOSING flows held as fixed reservations; a flow that enters **RETIRING** is removed from `nr_buffering` so the tick ignores it entirely — *RETIRING leaves the buffering set*: its ring is empty and it holds no grant). Cold-start seed = per-flow MBR→GBR→`default-seed-rate-kbps`, where **MBR/GBR ride the BUFF message** — `upf_send_hw_offload_update_far` (host) populates them from `pdr->qer`. `measure-demand=0` runs the static QoS-seed ablation. SIGUSR1 prints `bdp:` per-flow lines (`queued_bytes`, `A_i`, `U_i`, `ewma_rate_Bps`, `byte_drop`). The mbuf pool (`BUFFER_NB_MBUFS`, ~20 GiB) is the hard physical limit and must exceed `M_op`'s payload; per-flow ring (`DPU_BUFFER_PER_FLOW=8192`, ~16 MiB) caps a single flow regardless of `A_i`.

**Buffer slot lifecycle invariant** (BUFF→FORW→BUFF on the same `hw_rule_id`): `close_flow` / `quiesce_and_drain` must **NOT** `rte_hash_del_key` the flow binding — they only set `CLOSED`. The persistent `rte_ring` is reused on the next BUFF (CLOSED branch in `register_flow`); `register_flow` **refuses a still-RETIRING slot** (only CLOSED is reusable). Normal `close_flow` is now **RETIRING→CLOSED**, `retire_done`-gated, and decrements only `nr_retiring` (`begin_retire` already released `nr_draining`+`nr_buffering`). Bindings are **never** released at runtime — dropping one orphans the named ring and makes the next `rte_ring_create("buf_<id>")` fail (name still exists); the table is bounded by `max_hw_rules` distinct buffered rules. (The uncalled `unregister_flow` rollback API and the uncalled, Tx-queue-unsafe `drain_flow` were removed 2026-06 — `unregister_flow`'s `rte_hash_del_key` violated exactly this invariant.)

**GBR shaping**: **bounded buffered shaper** — YELLOW (GBR<rate<MBR) RSSes to ARM, where over-token packets are queued per-flow (cap `q_max = clamp(EIR*shape-max-delay-ms/1000, 16KiB, 16MiB)`) under a global `m-shape-bytes` budget (default 1 GiB; **`0` = legacy token-bucket pass/drop policer**) and drained at `EIR=MBR−GBR`. `M_shape` is logically separate from the buffer's `M_op` (same physical mbuf pool). A `shaper_loop` drain phase paces backlog via a `ready_ring` of slot indexes; a per-flow held-pkt preserves FIFO when tokens are short. EIR→0 and DL FAR→BUFF (`shaper_request_flush`, hooked in `HW_ACTION_BUFF`) flush the backlog. Per-slot rings (`shp_slot_<idx>`) persist; unregister → CLOSING (Rx drops new pkts), the **shaper lcore** frees mbufs then sets the slot INACTIVE. Like the buffer module, the shaper does **NOT** `rte_hash_del_key` in close paths (slot+key persist; `register` reuses the same slot once INACTIVE and **refuses** a non-INACTIVE slot to avoid racing the lcore's frees) — so the table is bounded by `max_hw_rules` distinct GBR flows. Not yet exercised on BF3. See [docs/DPU_ARM_POLICING_AND_SHAPING.md](../../docs/DPU_ARM_POLICING_AND_SHAPING.md).

## When you make changes

- **Pipe entry commits are per-port.** DL inserts touch N6 (`DL_MATCH`) and N3 (`DL_ENCAP`) — commit **N3 first, then N6** (else `DL_MATCH` briefly points at an empty `DL_ENCAP` → packets exit N3 un-encapped).
- **Don't rely on `parser_meta.outer_l3_type`** for ethertype (asymmetric across PFs on this firmware) — use `outer.eth.type`.
- **New JSON key** = four edits: the JSON, the `dpu_agent_cfg_t` struct, a `*_CB` + `reg_*` in [dpu_agent_config.c](dpu_agent_config.c), and (for IP/MAC) a `finalize_config()` parse block. 64-bit values (e.g. `m-op-bytes`) use the `UINT64_CB` string/`strtoull` path.
- **`hw_offload_msg.h` is a contract with host_agent** — any layout change needs the host rebuilt in lockstep. (Populating existing fields, like MBR/GBR on UPDATE_FAR, is not a layout change.)
- **Don't `rte_hash_del_key` in buffer close paths** — see the slot-lifecycle invariant.
- **Buffer slot lifecycle is decoupled from pipeline `current_mode`.** After FORW, `set_mode(FAST)` runs immediately (HW is FAST once the override is gone); the SW slot may still be **RETIRING** while pass-through draining the late DMA tail. Normal `close_flow` is RETIRING-only and `retire_done`-gated — *observed retire with bounded idle confidence, not deterministic*; force-closing a non-quiescent flow is a deferred API (`quiesce_and_drain` refuses RETIRING).
