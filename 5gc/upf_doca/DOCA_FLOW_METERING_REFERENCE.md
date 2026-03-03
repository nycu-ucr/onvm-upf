# DOCA Flow / BlueField Metering — Syntax & Capabilities (Reference)

This note distills what we need for UPF-style QoS from the DOCA metering excerpts you shared: **what a meter is**, **what it outputs**, **which algorithms exist**, **how to configure shared meters**, and **what the practical limits/units are**.

It is written to be *implementation-oriented*: if you’re wiring metering into a DOCA Flow pipeline (or comparing it to a SW `rte_meter_trtcm` path), this is the vocabulary and knob-set you have.

---

## 1) Mental model: a meter marks, your pipeline decides

A DOCA meter is a **token-bucket marker**:

- Every packet that hits a meter is assigned a **color**: `GREEN`, `YELLOW`, or `RED`.
- The meter itself does **not** “sleep” or “delay” packets. It only **marks**.
- What happens next is **up to your pipeline**:
  - match on the produced color in the next pipe/table, then
  - **forward**, **drop**, or **steer** (e.g., to a different queue/port/path).

Common policy patterns:

- **Strict policing:** `GREEN → FORW`, `{YELLOW,RED} → DROP`
- **2-tier policing:** `{GREEN,YELLOW} → FORW`, `RED → DROP`
- **Priority steering:** `GREEN → fast lane`, `YELLOW → best-effort lane`, `RED → drop`

In our current DOCA UPF pipeline, the “color match” stage forwards only `GREEN` and drops anything else (so `YELLOW` behaves like `RED` today).

---

## 2) Meter resource types: shared vs direct

### 2.1 Shared meter resource (DOCA Flow “shared resource meter”)

Key property:
- A **shared meter** can be referenced by **multiple pipe entries** (HW steering mode only, per the excerpt).

Operationally you:
1. **Acquire** a meter ID from a DOCA Flow port.
2. **Configure** its parameters (algorithm, units, rates/bursts).
3. **Bind** it to a pipe entry as a “shared meter” resource.
4. **Match on meter color** in a downstream pipe to decide the action.

This is exactly the “meter-color → color-match pipe” pattern you already use.

### 2.2 Direct meters (BlueField/DPL “direct meter” model)

The excerpt also describes **direct meters** in a table-centric model:

- A direct meter is **owned by a single table** (cannot be owned by multiple tables).
- The meter’s `meter()` method may only be called by the table that owns it (via a `direct_meter` binding).
- A direct meter is typically sized to match the table (table index → meter index).

If you’re staying strictly in DOCA Flow C pipelines, you mostly think in terms of **shared meters + color matching**. If you’re describing the underlying DPL/P4 model, “direct vs shared” becomes explicit.

---

## 3) Colors, units, and what gets counted

### 3.1 Color values

The excerpt defines a simple enum mapping:

- `RED`   = 0
- `YELLOW`= 1
- `GREEN` = 2

### 3.2 Metering units

Two unit systems are supported:

- **BYTES**: measured using the packet’s **IP length** (information rate), not the full L2 Ethernet frame.
- **PACKETS**: counts packets, with an internal convention of **128 bytes per packet** in this mode.

### 3.3 Measurement gotcha (important for experiments)

Meter parameters apply to the **information rate** (typically the inner IP layer), not “on-the-wire” Ethernet throughput.

So if you validate metering with a traffic generator / NIC counters at L2, you should expect a mismatch unless you:

- compute the **metered byte rate at the IP layer**, or
- subtract L2/L3/L4 overhead from your measurement before comparing to `CIR/PIR/EIR`.

---

## 4) Color-aware vs color-blind behavior (pre-colored packets)

The excerpt implies that a packet may enter the meter with an **initial color**:

- In a “color-aware” model, the meter can treat a `YELLOW` packet differently from a `GREEN` one on entry.
- In “color-blind” mode, you effectively treat everything as entering as `GREEN`.

The meter method signature shown (`meter(index, initial_color=GREEN)`) makes this explicit.

Practical note: if your pipeline never sets an initial color and uses “blind” mode, you are in the simplest (and most common) usage: **the meter alone determines the color from current token state**.

---

## 5) Supported marking algorithms (RFC 2697 / 2698 / 4115)

DOCA/BlueField metering supports three standard three-color marker algorithms:

### 5.1 RFC 2697 — Single-Rate Three-Color Marker (srTCM)

Parameters:
- `CIR` (Committed Information Rate)
- `CBS` (Committed Burst Size)
- `EBS` (Excess Burst Size)

Token bucket behavior (as described):
- A “committed” bucket (CBS) is refilled at `CIR`.
- Excess capability exists via `EBS`.
- Packet marking:
  - **GREEN**: within committed profile (fits in CBS)
  - **YELLOW**: exceeds committed burst but fits within excess burst
  - **RED**: exceeds both (out-of-profile)

Color-aware detail:
- If a packet arrives pre-colored `YELLOW`, it starts by consuming from the excess side (EBS).

### 5.2 RFC 2698 — Two-Rate Three-Color Marker (trTCM)

Parameters:
- `CIR`, `CBS`
- `PIR` (Peak Information Rate)
- `PBS` (Peak Burst Size)

Constraints:
- `PIR >= CIR` (explicitly stated in the excerpt)

Token bucket behavior (as described):
- CBS is refilled at `CIR`.
- A second bucket (PBS) is refilled at `PIR`.
- No “overflow” transfer from CBS to PBS (unlike srTCM’s CBS→EBS idea).
- Packet marking:
  - **RED**: exceeds the peak profile (beyond PIR/PBS)
  - Otherwise **GREEN** vs **YELLOW** depends on whether the packet exceeds `CIR` (committed) or not.

Color-aware detail:
- If a packet arrives pre-colored `YELLOW`, it starts consuming from the peak side (PBS).

### 5.3 RFC 4115 — trTCM variant without peak-rate dependency

The excerpt describes RFC 4115 as a two-bucket design where:

- There is a committed side (`CIR`/`CBS`), and
- an excess side (`EIR`/`EBS`) that also receives overflowed credentials from the committed side.

For exact marking rules, the excerpt points you to RFC 4115’s algorithm definition, but the key capability takeaway is:

- You can meter with **committed** and **excess** rates/bursts, producing the same `GREEN/YELLOW/RED` output.

---

## 6) Configuration “syntax”: what you actually set

### 6.1 DOCA Flow shared meter configuration (C API shape)

From the code patterns in `5gc/upf_doca/upf_doca_pipeline.c` and the DOCA sample `doca-samples/samples/doca_flow/flow_shared_meter/flow_shared_meter_sample.c`, the shared meter configuration conceptually looks like:

- Choose **limit type**: `BYTES` or `PACKETS`
- Choose **color mode**: `BLIND` (or an aware mode if used)
- Choose **algorithm**: RFC 2697 / 2698 / 4115
- Set the algorithm’s required **rate(s)** and **burst(s)**

Minimal example (srTCM, bytes, blind):

```c
struct doca_flow_shared_resource_cfg cfg = {
  .meter_cfg = {
    .limit_type = DOCA_FLOW_METER_LIMIT_TYPE_BYTES,
    .color_mode = DOCA_FLOW_METER_COLOR_MODE_BLIND,
    .alg        = DOCA_FLOW_METER_ALGORITHM_TYPE_RFC2697,
    .rfc2697.ebs = 0,
    .cir = <bytes_per_sec>,
    .cbs = <bytes>,
  }
};
doca_flow_port_shared_resource_get(port, DOCA_FLOW_SHARED_RESOURCE_METER, &meter_id);
doca_flow_port_shared_resource_set_cfg(port, DOCA_FLOW_SHARED_RESOURCE_METER, meter_id, &cfg);
```

Once configured, you bind the meter to an egress pipe entry (as a shared meter resource), then match on `parser_meta.meter_color` downstream.

### 6.2 Table-style “extern object” syntax (DPL/P4-like model)

The excerpt also describes meter objects as externs with constructors and a `meter()` method, e.g.:

- **Peak trTCM (RFC 2698)** shared meter object:
  - constructed with `size`, `units`, and optionally (`cir`,`cbs`,`pir`,`pbs`)
  - invoked as `meter(index, initial_color=GREEN)` returning `RED/YELLOW/GREEN`

- **srTCM (RFC 2697)** shared meter object:
  - constructed with (`cir`,`cbs`,`ebs`)

- **Direct** variants:
  - bound to a specific table (ownership restrictions)

If you’re explaining capabilities rather than writing the code, the key idea is:

> There exists a “meter array” abstraction indexed per-flow (or per-entry), and a per-packet `meter()` operation that returns one of three colors.

---

## 7) Limits & max values (from the excerpt)

### 7.1 Size

- The number of meter indices (`size`) must be:
  - a power of two, and
  - no greater than **16M**
- The system supports up to **16M total meters**.

### 7.2 Parameter maximums

When metering by **BYTES**, max values shown:

| Parameter | Max |
|---|---:|
| `cir` | 2,550,000,000,000 |
| `cbs` | 2,147,483,648 |
| `pir` | 5,100,000,000,000 |
| `pbs` | 4,294,967,296 |

When metering by **PACKETS**, max values shown:

| Parameter | Max |
|---|---:|
| `cir` | 1,992,187,500 |
| `cbs` | 16,777,216 |
| `pir` | 3,984,375,000 |
| `pbs` | 33,554,432 |

For srTCM specifically, the excerpt also lists `cbs` and `ebs` sharing the same max in each unit mode.

---

## 8) What DOCA metering gives you (capability summary)

From the excerpt, the metering feature set boils down to:

- **Per-flow metering** with three-color output (Green/Yellow/Red).
- **Algorithms:** RFC 2697 (srTCM), RFC 2698 (trTCM), RFC 4115.
- **Units:** bytes (IP-length “information rate”) or packets (128-byte packet unit).
- **Color-aware input:** ability to supply an initial color, enabling color-aware variants.
- **Integration hook:** meter result is matched downstream (color match) to implement policy.
- **Resource models:** shared meters reusable across entries; direct meters bound to a table (in the table/extern model).

If you map this to UPF/QER thinking:

- trTCM can represent the “**GBR vs MBR band**” (`CIR=GBR`, `PIR=MBR`) *as marking*.
- Your pipeline still decides what “yellow” means operationally (pass, downgrade, or drop).

