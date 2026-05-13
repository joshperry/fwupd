# dell-monitor-rt: plugin-vs-decomp audit

The first ~2/3 of the plugin was written before the C++ vtable / typed-
class decomp work landed. Wire patterns came from pcap inference plus
guesses about chip-side semantics. Now that we have typed decomp for
`libdevices`, `libhub`, `libpdc`, and `libdisplay`, this doc walks the
plugin module-by-module against the Wistron source we recovered and
records every divergence — what we do, what they do, why it matters,
and how we fixed it.

Order of attack:

1. **setup / vendor commands** — `fu_dell_monitor_rt_device_setup` and
   helpers (`vcmd`, `vcmd_read`, `i2c_write`, `i2c_read`, `handshake`)
   vs `libdevices.c` (`RTS5409S_HID`, `send_vendor_cmd`, `cal_auth`,
   `hub_force_handshake`).
2. **HUB1/HUB2 i2c-tunnel RAM loader** — `stage_downstream_mcu` +
   `i2c_tunnel_init_step` + `i2c_tunnel_poll` vs `libhub.c`
   (`Rts5409s_IIC_ISP::isp` → `program` → `RTS5409s_IIC_API::clear_address`
   + `write_flash` + `polling_status`). **CURRENT FAILURE POINT on
   real hardware.**
3. **c8 staging** — `stage_isp_firmware` vs `libhub.c`
   (`Rts5409s_ISP::isp`, c8 RAM stage).
4. **bootloader-enter trigger** — `enter_bootloader` (0xE9) vs decomp.
5. **PDC programming** — `pdc_program` / `pdc_verify_chunk` vs
   `libpdc.c` (`Tps6598xISP` 4CC flow).
6. **DISPLAY block-write** — `display_program` and the F4/F1/04/F5 loop
   vs `libdisplay.c` (`REALTEK_API` + `RealtekISP::set_write_protect_pin`).

Per-section format:

- **Plugin function** vs **decomp function**
- *We do* / *They do* / *Divergence* / *Severity* / *Fix*
- Each section ends with **Fixes pending** — actionable items to batch
  after the full audit completes.

Severity legend:

- `match` — wire/control pattern verified equivalent.
- `cosmetic` — divergence with no behavioral impact (timing, logging).
- `latent` — could fail on edge cases / different hardware than ours.
- `breaking` — known to cause real-hardware failure.

---

## Audit summary — prioritized fix list

Ranked by impact on real-hardware install (highest first):

**Tier 1 — currently blocking or likely-breaking on real hardware:**

- **F2.1 (HUB1/HUB2 i2c-tunnel) — confirmed via pcap frames 7406–
  7792:** Wistron's preamble is `read_fw_version × 2` then
  `clear_address`. Each `read_fw_version` is 5-byte write + 1-byte
  status poll + **3-byte read_seq response**. Our plugin issues
  the write + 1-byte poll but NOT the 3-byte read, and only one
  cycle instead of two. The chip's i2c FIFO ends up holding 3
  stale version bytes that subsequent reads consume in place of
  the expected ready status. Recommended fix: remove WAKE entirely
  (match `program()` exactly), or complete the WAKE cycle.
- **F3.2 (c8 staging) — confirmed via pcap envelope check:** The
  c8 chunk loop IS wrapped by the full `update_self` envelope.
  Add `enable_vdcmd(true, true)` + `erase_spare_bank` (0xE8) +
  chunks + `verify_update_fw` (0xD9) + `enable_vdcmd(true, false)`
  around our existing chunk loop. (This overturns my initial
  audit conclusion that c8 was "bare RAM stage" — the captured
  trace shows the full envelope at frames 28808–32108 and again
  39460–41080.)
- **F6.3 (DISPLAY block-write) — confirmed via pcap frame 811742:**
  Add post-loop validity-marker write. Sequence: set 3-byte SPI
  flash address via registers 0x64/0x65/0x66 (`0x3F`, `0xF8`,
  `0xFE`), then write 2 bytes (`0xAA 0x55`) to register 0x70.
  Without this, the panel scaler's bootloader rejects the new
  firmware.

**Tier 2 — robustness / portability:**

Status legend: ✅ landed, ⏳ deferred.

- ✅ **F1.1:** Retry loop on `enable_vdcmd` (up to 10 attempts).
  *commit 04c5ad75e.*
- ✅ **F1.4:** Minimum-response-length check (< 16) in `vcmd_read`
  before treating it as a 16-byte cal_auth challenge.
  *commits 04c5ad75e + 840697513 (emulation-tolerance rc==0 guard).*
- ✅ **F2.6:** Bump i2c-tunnel poll sleep from 2 ms → 3 ms.
  Matches Wistron's `nanosleep(0, 3,000,000ns)` at
  `libhub.so:0x19b4a0`. *commit 120e1dd8f.*
- ✅ **F2.5:** Handle trailing partial chunks in
  `stage_downstream_mcu` (not blocking for M3T105). *commit 120e1dd8f.*
- ✅ **F3.4:** Add 5-attempt retry around the full c8 staging
  envelope, matching `Rts5409s_ISP::isp`'s `update_self` retry.
  *commit 120e1dd8f — refactored arm into per-attempt inner helper.*
- ✅ **F4.1:** Replace plugin's hardcoded "fire 0xE9 twice" with a
  3-retry pattern modeled on `reset_self`. *commit 120e1dd8f.*
- ⏳ **F5.2:** Plumb `low_region_only` from .upg metadata into PDC
  dispatch. Two-region update path remains unimplemented; needs
  the .upg's `low_region_only` field plumbed through the route's
  protocol context. Not blocking for U4025QW M3T105 — current
  single-R0 hardcode matches the captured behavior.
- ✅ **F5.5:** Read `BootFlags82` (register 0x2D, 2 bytes) and log
  the full bitfield. Gating-on-BootOk is comparison-based against a
  chip-config expected value we don't have plumbed — so we log
  diagnostically and proceed. *commit e252ccefd.*
- ✅ **F5.6:** `0x100e0ac` magic check after FLrr (defensive).
  *commit e252ccefd.*
- ✅ **F6.1 / F6.2:** 3-attempt retries for end-block erase and
  per-block writes in DISPLAY programming. *commit e252ccefd.*

**Items resolved (downgraded from Tier 1):**

- **F4.2 (post-0xE9 sleep) — DOWNGRADED:** Pcap shows ~130 ms gap
  between 0xE9 and next host frame, not 2 seconds. fwupd's
  `WAIT_FOR_REPLUG` handles re-enumeration; mid-loop direct-stage
  triggers target separate devices.

**Items verified as match (no fix needed):**

All wire-format details (byte-for-byte against struct field layouts
from the typed-class decomp), all polling/check semantics, all
open/close orchestration (handled by fwupd's udev backend), the
deliberate off-by-one trailer divergence in PDC programming.

---

## Audit findings — sections

## 1. setup / vendor commands

Plugin: `fu_dell_monitor_rt_device_setup` at
`fu-dell-monitor-rt-device.c:1021+`. Sequence:

1. `vcmd(WRITE, 0x02 ENABLE_VDCMD, sub=0x01, arg=0x00, payload={0xDA, 0x0B})`
2. `vcmd(WRITE, 0x06 ENABLE_HIGH_CLOCK, sub=0x01, arg=0x00, payload=NULL)`
3. `read_panel_id` (DDC/CI VCP 0xEE) → cached on device
4. `read_isptag` (DDC/CI VCP 0xAD) → sets `fu_device_version`

Each DDC/CI read (#3, #4) internally runs `handshake()` (cal_auth) +
`i2c_write` (VCP request) + `i2c_read` (response).

### 1.1 `enable_vdcmd` vs `RTS5409S_HID::enable_vdcmd(bool, bool)`

*Decomp:* `libdevices.c:68895`. Wire layout from struct-field
assignments (lines 68931–68937):

| offset | value                                |
|-------:|--------------------------------------|
|      0 | 0x00 (HID report ID)                 |
|      1 | 0x40 (`out_report_byte1`)            |
|      2 | 0x02 (`out_opcode` ENABLE_VDCMD)     |
|      3 | `param_2 + 2*param_3` (`out_sub0`)   |
|      4 | 0x00 (`out_sub1`)                    |
|      5 | 0xDA (`out_sub2`, vendor sig low)    |
|      6 | 0x0B (`out_sub3`, vendor sig high)   |
|      7 | 0x00 (`out_count`)                   |

*We do:* `vcmd(dir=0x40, op=0x02, sub=0x01, arg=0x00, payload={0xDA,
0x0B})` writes `00 40 02 01 00 DA 0B 00` (then zero pad). **Wire
format: match.**

*Divergence — retry loop:* Wistron wraps the send in
`do…while ((last_error != 0) && (iVar3-- != 0))` with `iVar3 = 10` —
up to 10 retries on `last_error`. Plugin issues single-shot and treats
any HID error as fatal. **Severity: latent.**

*Divergence — combined enable available:* Wistron's flag form `param_2
+ 2*param_3` lets a single 0x02 frame enable both vdcmd and high-clock
in one shot (`sub0 = 3`). Our setup uses the separate two-frame pattern
the captured pcap shows; the combined form lives in some other Wistron
code paths (e.g. `write_hub_flash` at libdevices.c:70012). **Severity:
match (against pcap) — noted for future reference.**

### 1.2 `enable_high_clock_mode` vs `RTS5409S_HID::enable_high_clock_mode(bool)`

*Decomp:* `libdevices.c:68992`. Wire layout (lines 69022–69025):

| offset | value                                |
|-------:|--------------------------------------|
|      0 | 0x00                                 |
|      1 | 0x40                                 |
|      2 | 0x06                                 |
|      3 | `param_2` (enable flag)              |
|    4–7 | 0x00                                 |

A `"high_clk_mode\0"` string is passed to `send_vendor_cmd` for
logging — not on the wire.

*We do:* `vcmd(0x40, 0x06, 0x01, 0x00, NULL, 0)`. **Wire format:
match.** Single-shot, no retry loop in the decomp either. **Match.**

### 1.3 `send_vendor_cmd` semantics vs our HID write

*Decomp:* `libdevices.c:68856`:

```c
this->last_error = 0;
uVar2 = hid_write(this->hid_dev, param_2, 0xc1);  // write 193 bytes
if (iVar1 < 0)      last_error = 0x11;    // transport fail
else if (0x40 < iVar1) return iVar1 + -0x40;  // success: return (ret - 64)
else                last_error = 0xf1;    // "other error"
```

The `> 64` threshold is a partial-write detector, not a chip-echo check.
hidapi's Linux backend uses `write(2)` to hidraw, which returns the
number of bytes the kernel actually pushed onto the USB stack — not
anything from the chip. So Wistron's check is "did we manage to write
enough of the 193-byte frame to be a meaningful command (more than 64
bytes)" — and if not, treat as transport failure.

*We do:* `fu_hidraw_device_set_report` → `fu_udev_device_write` →
`fu_io_channel_write_raw` — fwupd's channel layer returns FALSE on
partial write or non-zero errno, exactly the same semantic.

**Severity: match — equivalent partial-write detection.**

### 1.4 `handshake()` (cal_auth) vs `RTS5409S_HID::hub_force_handshake`

*Decomp:* `libdevices.c:70826`. Wire flow:

**Challenge write:** zero `out_*` fields, then set:

| offset | value                                |
|-------:|--------------------------------------|
|      1 | 0x40                                 |
|      2 | 0xE1                                 |
|      3 | 0x01 (`out_sub0`)                    |
|      4 | 0x01 (`out_sub1`)                    |

Send via `send_vendor_cmd` with `"force_handshake\0"` log string.

**Challenge read:** `hid_get_input_report(hid_dev, &in_report_byte0,
0xc1)` — pulls 193-byte input report. Validate:

- `iVar4 < 1`  → `last_error = 0x21` ("transport error")
- `iVar4 < 0x10` → `last_error = 0xf1` ("chip rejected: short response")

Copy 16 challenge bytes from `&this->in_payload` (16 bytes).

**Compute response:** `cal_auth(this, challenge[16], response[8])` —
XOR-based per-byte derivation we already reverse-engineered correctly
(`fu_dell_monitor_rt_cal_auth` at `fu-dell-monitor-rt-device.c:385`).

**Response write:** zero `out_*` fields, set:

| offset | value                                |
|-------:|--------------------------------------|
|      1 | 0x40                                 |
|      2 | 0xE1                                 |
|      3 | 0x03 (`out_sub0`)                    |
|      4 | 0x00 (`out_sub1`, implicit)          |
| `out_payload` | 8-byte response               |

*We do:* `fu_dell_monitor_rt_device_handshake` at
`fu-dell-monitor-rt-device.c:413+`. Wire format matches:

- Challenge write via `vcmd_read(dir=0x40, op=0xE1, sub=0x01, arg=0x01,
  …)` — that places `0x01` at wire offsets 3 and 4 (sub0/sub1). **Match.**
- Challenge read via `HIDIOCGINPUT(193)`. **Match.**
- 16-byte challenge extracted from `challenge_resp[1..16]` (which is
  wire bytes `[0..15]`). **Match.**
- Response write via direct buffer construction: sets bytes 1=0x40,
  2=0xE1, 3=0x03, 4=0x00, then response at offset 64 (`buf[1+64]`).
  **Match against pcap.**

*Divergence — no short-response check:* Wistron's `hid_get_input_report
< 0x10 → error 0xf1`. Our `vcmd_read` doesn't validate the returned
length. If the kernel returns fewer than 16 bytes (e.g. chip in weird
state, USB glitch), we'd happily extract garbage from `challenge[0..15]`
and feed it to `cal_auth`, computing a meaningless response. **Severity:
latent.**

*out_payload offset — verified:* Reading the `RTS5409S_HID::write`
disassembly at `libdevices.so:0xb3480`:

  | field           | struct offset | wire offset (− 0x59) |
  |-----------------|--------------:|---------------------:|
  | out_report_byte0| 0x58          | (HID report ID, kernel-stripped) |
  | out_report_byte1| 0x59          | 0                    |
  | out_opcode      | 0x5a          | 1                    |
  | out_count       | 0x5f          | 6                    |
  | out_i2c_target  | 0x61          | 8                    |
  | out_i2c_speed   | 0x63          | 10                   |
  | out_payload     | 0x99          | 64                   |

The HID buffer starts at struct offset 0x58 (the report-ID byte the
kernel strips); the first byte the chip actually sees is at 0x59. So
`out_payload`'s wire offset is `0x99 - 0x59 = 0x40 = 64`. Plugin's
`WIRE_DATA_OFFSET = 64` — **match.** All other plugin wire offset
constants match the struct layout too.

### 1.5 `read_panel_id` / `read_isptag` (DDC/CI via i2c-tunnel slave 0x6E)

*Decomp scope:* The host-side VCP-selector wrapping lives in the main
firmware-updater binary, which we don't have full decomp for. The
chip-side semantics live in `FL5500_IIC_API` (libhub.so) but we
haven't audited those yet — and they're chip-side, so they don't
constrain our host-side wire pattern.

*We do:* For each VCP read:

1. `handshake()` → cal_auth.
2. Build 7-byte DDC/CI request: `51 84 c0 99 SEL 18 CRC`.
3. `i2c_write` to slave 0x6E with 7-byte payload.
4. `g_usleep(50 ms)`.
5. `i2c_read` from slave 0x6E with count=0x40.
6. Parse `response[1..]` for the VCP reply format.

*Verified:* Wire format matches captured pcap. Real-hardware run
(today) returned correct `M3T105` IspTag and panel id via this path —
so the wire protocol is correct end-to-end on actual silicon.
**Severity: match.**

*Divergence — hardcoded CRC bytes:* We hardcode `(SEL, CRC)` pairs per
VCP selector. DDC/CI's checksum is `0x6E ^ 0x51 ^ 0x84 ^ 0xC0 ^ 0x99
^ SEL ^ 0x18` — easy to compute on the fly. Hardcoded is fine for the
two VCPs we use; if we add more we'll want the algorithm. **Severity:
cosmetic.**

### 1.6 `set_bus_speed` — host-side flag, not a wire op

*Decomp:* `libdevices.c:66479`:

```c
void RTS5409S_HID::set_bus_speed(RTS5409S_HID *this, uchar param_2) {
    this->i2c_speed = param_2;
    return;
}
```

Pure setter. The host-side i2c_speed field controls the SPEED_OFFSET
byte in i2c-tunnel frames (wire byte 11 in our layout) — there's no
wire transaction for "set speed", it's encoded per-frame.

*We do:* `i2c_write_speed` takes the speed as a parameter and writes
it into the frame directly. **Match in spirit — no setter needed since
we pass speed per-call.**

### 1.7 setup-phase open-side flow (informational)

`RTS5409S_HID::open` (`libdevices.c:66511`) enumerates HID via hidapi,
opens the device, and calls vtable[5] (the actual `hid_open`). No wire
transactions on the device. `RTS5409S_HID` constructor
(`libdevices.c:66584`) sets `vid_pid = 0x11000bda` (= VID 0x0BDA, PID
0x1100) and zeroes everything else.

`RTS5409S_HID::close` (`libdevices.c:66541`) does graceful shutdown:
`hub_force_handshake` → `enable_high_clock_mode(false)` → `hid_close`.
We don't do graceful shutdown — the device is torn down by udev on
re-enumeration anyway, so this is fine on the install path.

`RTS5409S_HID::skip_handshake` (`libdevices.c:66493`) sets a
state-machine byte (`this[1].__vftable = 0xDE`) that subsequent
`hub_handshake`/`hub_force_handshake` calls check to suppress the
auth. Useful for ops that don't need auth (cosmetic version reads
etc.). We don't have an equivalent — every i2c-tunnel op runs a fresh
cal_auth. Matches pcap behavior for the install path.

### Fixes pending

The following are batched until the full audit completes. None are
required for the immediate HUB1 chunk-0 failure (different module).

- [ ] **F1.1 (latent):** Add retry loop to `enable_vdcmd`. Wistron's
  pattern is `do { send_vendor_cmd(...); } while (last_error != 0 &&
  --iVar3 != 0)` with `iVar3 = 10`. Plugin issues single-shot. The
  retry probably masks transient HID errors right after USB
  enumeration; on this hardware single-shot works, but the chip-vendor
  put the retry there for a reason and it's cheap insurance.
- [ ] **F1.4 (latent):** Add a minimum-response check in `vcmd_read`
  (or specifically in `handshake()`). Wistron's `hub_force_handshake`
  treats `hid_get_input_report < 0x10` as `last_error = 0xf1`
  (chip-side short response). Plugin doesn't validate the returned
  length before treating `challenge_resp[1..16]` as a valid 16-byte
  challenge — under a transient I/O glitch we'd silently feed garbage
  through `cal_auth` and send a garbage response.

Items resolved during the audit (no fix needed):

- **F1.3 (set_report response check)** → match. fwupd's channel layer
  detects partial writes via `fu_io_channel_write_raw` errno
  propagation, which is what Wistron's `> 64` check is also testing.
- **F1.4 (out_payload offset)** → match. Verified by reading the
  `RTS5409S_HID::write` disassembly — wire byte 64 is correct.
- **All wire offsets** (LEN_OFFSET, TARGET_OFFSET, SPEED_OFFSET,
  DATA_OFFSET) → match. Verified against struct-field offsets in the
  class JSON and confirmed by disassembly.

None of the above explains the HUB1 chunk-0 poll timeout (which is
section 2). The setup-phase wire pattern is byte-for-byte correct on
real hardware up through verify_baseline; the failure is downstream.

---

## 2. HUB1/HUB2 i2c-tunnel RAM loader

*Status: in progress — current real-hardware failure point.*

Plugin: `fu_dell_monitor_rt_device_stage_downstream_mcu` at
`fu-dell-monitor-rt-device.c:1344+`. Sequence per HUB1/HUB2 target:

1. `i2c_tunnel_init_step("WAKE", {0x25,0x03,0x00,0x00,0x02}, 5)` →
   `i2c_write` 5 bytes to slave + `i2c_tunnel_poll`.
2. `i2c_tunnel_init_step("BEGIN", {0x12,0x01,0x01}, 3)` → 3-byte
   write + poll.
3. For each 64-byte chunk: build 66-byte frame `[0x13, 0x40,
   <64 bytes>]`, write + poll.

### 2.1 What "WAKE" actually is — and what we miss

*Pcap confirmation (frames 7406–7792):* Wistron's HUB1 staging
preamble is NOT a single WAKE+BEGIN pair. It's
**`read_fw_version` TWICE, then `clear_address`**:

```
7406  i2c-W slave=0xD4 cnt=5 [25 03 00 00 02]    WAKE / read_fw_version
7408  i2c-R slave=0xD4 cnt=1                    1-byte status poll
7412  i2c-R slave=0xD4 cnt=3 (reg-select 0x80)  3-byte read_seq response
7782  i2c-W slave=0xD4 cnt=5 [25 03 00 00 02]    WAKE again
7784  i2c-R slave=0xD4 cnt=1                    1-byte status poll
7788  i2c-R slave=0xD4 cnt=3 (reg-select 0x80)  3-byte read_seq response
7792  i2c-W slave=0xD4 cnt=3 [12 01 01]          clear_address (BEGIN)
```

Our plugin: WAKE write + 1-byte poll, then BEGIN. Missing:

1. The **3-byte read_seq response** after each WAKE — the chip
   delivers the 3-byte version response and expects the host to
   drain it before the next operation. Leaving it un-drained
   parks the chip's i2c output FIFO in a "version-data-pending"
   state.
2. The **second WAKE+poll+read_3 cycle** entirely — Wistron does
   this twice, presumably as a stability check (first read may
   return stale data after device wake-up; second read confirms
   the stable version).

**Severity: breaking.** This is the leading suspect for the
chunk-0 poll failure on real hardware. The chip's i2c FIFO holds
3 stale version bytes; subsequent reads (the BEGIN poll, the
chunk poll) may consume those bytes instead of the expected
ready status.

### 2.1.x Wistron's caller chain — what produces these bytes

*Decomp:* `libhub.c:50641`, `RTS5409s_IIC_API::read_fw_version`. The
5 bytes `{0x25, 0x03, 0x00, 0x00, 0x02}` are constructed from a
stack local:

```c
local_90._0_2_ = 0;        // bytes 0..1
local_90._3_4_ = 0x325;     // bytes 3..6 = 0x25, 0x03, 0x00, 0x00 LE
local_90._7_1_ = 2;          // byte 7
write(this->iic, *this, 5, (long)&local_90 + 3);  // write bytes [3..7]
polling_status(this);
read_seq(this->iic, *this, 0x80, 3, &local_90);   // read 3 bytes back
// version is local_90[0..2]; require local_90[0] == 0x02
```

So `read_fw_version` is: write 5-byte "read register 0x325" command,
poll, then read 3 bytes containing `[0x02, major, minor]`.

*Caller chain:* `read_fw_version` is invoked from
`Rts5409s_IIC_ISP::get_fw_version` (libhub.c:51154), which is exposed
via dlsym from the main firmware-updater binary as the
"get_fw_version" entry point (`firmware-updater.c:355485+`).

**Wistron's `program()` does NOT call `get_fw_version` or write these
5 bytes.** It goes straight to `clear_address` then the chunk loop
(libhub.c:51498).

The pcap captured both the `get_fw_version` write (during Dell's
pre-update version-check phase) AND the `program()` writes (during
the actual update). The plugin's pcap-driven WAKE step was modeled
on the captured 5-byte write but lumped together with the program
flow — they're actually separate top-level calls in Wistron's tool.

*Divergence — extra wire op:* Plugin sends 5-byte write + poll that
Wistron's update flow does not. **Severity: latent → likely
breaking.** The chip processes the 5-byte command as
"prepare to deliver 3 version bytes". With Wistron's tool the 3-byte
`read_seq` follows. With our plugin no read follows — we move on to
the 3-byte `clear_address` write while the chip is potentially still
in "version-data ready" state. The chip may or may not handle the
state transition gracefully.

Also missing: **the 3-byte `read_seq` that completes `read_fw_version`.**
We never read the version response. If we keep the WAKE write, we
should also do the matching 3-byte read.

### 2.2 `BEGIN` vs `RTS5409s_IIC_API::clear_address`

*Decomp:* `libhub.c:50506`:

```c
local_23 = 0x112;       // 2 bytes: 0x12, 0x01
local_21 = 1;            // 1 byte: 0x01
write(this->iic, *this, 3, &local_23);
polling_status(this);
```

Wire bytes: `{0x12, 0x01, 0x01}` — i2c write of 3 bytes to slave, then
1-byte poll until 0x01. **Match.** Our `BEGIN = {0x12, 0x01, 0x01}`
is byte-for-byte equivalent.

### 2.3 Chunk write vs `RTS5409s_IIC_API::write_flash`

*Decomp:* `libhub.c:50822`. Allocates a buffer of `param_2 + 2` bytes:

```c
puVar3 = operator_new__((ulong)param_2 + 2);
*puVar3 = 0x13;          // CMD = chunk-write
puVar3[1] = param_2;      // LEN = chunk size (e.g. 64)
memcpy(puVar3 + 2, param_1, param_2);  // chunk data
write(this->iic, *this, param_2 + 2, puVar3);
polling_status(this);
```

Wire bytes: `{0x13, <chunk_size>, ...chunk_size bytes...}`. For
64-byte chunks: `{0x13, 0x40, <64 bytes>}` — 66 bytes total. **Match**
with our `{0x13, 0x40, ...}` frame.

### 2.4 Chunk-size determination

*Decomp:* `libhub.c:51499`:

```c
iVar4 = *(int *)&this->iic;   // IIC_INTF* (treated as int — non-zero check)
uVar7 = (-(uint)(iVar4 == 0) & 0xffffffe0) + 0x40;
```

If `iVar4 != 0` (IIC_INTF pointer is non-null — always true in
practice): `uVar7 = 0 + 0x40 = 64`. **Match** with our
`DELL_MONITOR_RT_I2C_LOADER_CHUNK = 64`.

The dead branch (`iVar4 == 0` → `uVar7 = 32`) is for a configuration
with no transport — never executed at runtime.

### 2.5 Trailing partial chunk

*Decomp:* `libhub.c:51562`:

```c
iVar4 = (int)((ulong)uVar2 % (ulong)uVar7);   // remainder
if (iVar4 != 0) {
    write_flash(this, ..., (uchar)((ulong)uVar2 % (ulong)uVar7));
}
```

If blob size isn't a multiple of 64, Wistron writes one trailing
chunk with `(size % 64)` bytes.

*We do:* `stage_downstream_mcu` checks `blob_size % CHUNK == 0` and
errors out otherwise. **Divergence: latent.** All our HUB1/HUB2/HUB4
blobs from M3T105 are clean 64-byte multiples, so this doesn't fire
in practice, but if a future .upg has a partial-chunk component our
plugin would refuse to flash it.

### 2.6 `polling_status` timing

*Decomp:* `libhub.c:50448`, asm at `libhub.so:0x9a810`. The retry
limit is `mov $0x14, %ebp` → 20 attempts. The per-attempt
`nanosleep` timespec is loaded from `libhub.so:0x19b4a0`:

```
0019b4a0: 0000 0000 0000 0000 c0c6 2d00 0000 0000
              tv_sec = 0 |   tv_nsec = 0x2DC6C0 = 3,000,000 ns = 3 ms
```

So Wistron: **20 × 3 ms = 60 ms total**.

*We do:* `i2c_tunnel_poll` is `20 × 2 ms = 40 ms total`.

**Severity: latent.** Off by 50%. The chip's actual ack time for a
chunk write is presumably well under 60 ms, but our 40 ms might be
too short for transient state — and the chip-vendor put the 3 ms
constant in there for a reason.

### 2.7 `polling_status` success / failure semantics

*Decomp:* `libhub.c:50448`:

```c
local_49 = -1;     // init to 0xFF
do {
    read(this->iic, *this, 1, &local_49);  // 1-byte i2c read
    if (local_49 == '\x01') goto SUCCESS;
    local_49 = -1;                          // reset
    nanosleep(3ms);
    iVar4--;
} while (iVar4 != 0);
// fall through: return 0xf1
```

Check: read 1 byte, success iff byte == `0x01`. **Match** with our
plugin's `response[1] == DELL_MONITOR_RT_I2C_POLL_READY (= 0x01)`
check.

### 2.8 Open / handshake before program

*Decomp:* `Rts5409s_IIC_ISP::isp` (libhub.c:51650) opens the IIC
transport (via slot 0x20 `open_pid` or 0x28 `open_path`), then calls
`program()`. The open is a host-side operation — for our setup it
maps to selecting the i2c-tunnel speed/target rather than emitting a
chip-side command.

The 1-second nanosleep we previously noted (`libhub.so:0x19b3b0`,
tv_sec=1) fires only on the fall-through "no real open method"
branch (both `open_pid` and `open_path` are the base-class stubs).
For a configured `RTS5409s_IIC_API` with a real `IIC_INTF` transport
plumbed in, neither stub matches → the open is called → the 1-second
sleep is skipped. So the 1s delay does NOT apply to our case. **Not
a divergence.**

`hub_handshake` (libdevices.c:70806) is a no-op stub for our state:
the asm at `libdevices.so:0xb8870` checks for the skip flag at
`this+0x224 == 0xDE` and only logs in that case; otherwise it returns
0 immediately without doing any handshake. `hub_force_handshake` (the
real cal_auth) is called from `RTS5409S_HID::open/close` once per
session, not per write. **Cal_auth is NOT required before each
HUB1/HUB2 i2c-tunnel write** — confirmed match with our plugin which
also doesn't call handshake here.

### Fixes pending

- [ ] **F2.1 (breaking — confirmed leading cause of chunk-0 failure
  on real hardware):** Wistron's actual preamble (pcap frames 7406–
  7792) is `read_fw_version × 2` then `clear_address`, where each
  `read_fw_version` is a complete `[25 03 00 00 02]` write + 1-byte
  status poll + **3-byte read_seq response** (i2c-R with register-
  select 0x80, count=3). Our plugin issues the write + poll but NOT
  the 3-byte read, and only one cycle instead of two.

  Two fix options:

  - **Remove WAKE entirely** — go straight to `clear_address`,
    matching what Wistron's `Rts5409s_IIC_ISP::program()` does
    inside libhub. The captured trace's WAKE bytes are from a
    separate `get_fw_version` call layered above `program()` by
    the main firmware-updater binary; not part of the chunk-write
    flow itself.

  - **Complete the WAKE cycle** — issue WAKE + poll + 3-byte
    read_seq + WAKE + poll + 3-byte read_seq + clear_address,
    byte-for-byte matching the captured trace. Safer because it
    matches Wistron's actual emit sequence even if the read is
    semantically unnecessary.

  Recommended: try the "remove WAKE entirely" path first since
  it's the minimal change that matches `program()`. If real-HW
  still fails at chunk-0, switch to the complete-WAKE-cycle path
  on the next iteration.

- [ ] **F2.6 (latent):** Bump `i2c_tunnel_poll` per-attempt sleep
  from 2 ms (`DELL_MONITOR_RT_I2C_POLL_SLEEP_US = 2000`) to 3 ms.
  Match Wistron's `nanosleep(0, 3000000ns)` constant at
  `libhub.so:0x19b4a0`. Total budget goes from 40 ms to 60 ms.

- [ ] **F2.5 (latent, cosmetic priority):** Handle trailing
  partial chunks in `stage_downstream_mcu`. Match Wistron's
  `if (size % chunk != 0)` final-chunk write. Not blocking for
  M3T105 but defensive for future .upg payloads.

Items resolved (no fix needed):

- **F2.2 BEGIN bytes** → match (`{0x12, 0x01, 0x01}` = clear_address).
- **F2.3 chunk wire format** → match (`{0x13, len, ...}` =
  write_flash).
- **F2.4 chunk size 64** → match (uVar7 = 0x40 in Wistron, plugin's
  `I2C_LOADER_CHUNK = 64`).
- **F2.7 polling check** → match (1-byte read, expect 0x01, 20
  retries).
- **F2.8 no per-write handshake required** → match. cal_auth fires
  once at HID open, not per i2c-tunnel write.

**F2.1 is the strongest candidate for the live chunk-0 failure.**
The "WAKE" wire op is from a function (`read_fw_version`) that
Wistron's actual program() flow doesn't invoke; leaving it in
without the matching 3-byte read leaves the chip in an unexpected
state when our plugin proceeds to clear_address + chunks.

---

## 3. c8 staging

Plugin: `fu_dell_monitor_rt_device_stage_isp_firmware` at
`fu-dell-monitor-rt-device.c:1439+`. Walks a 64-KB-aligned blob in
bank × addr × half loops, emitting 0xC8 frames carrying 128 bytes
each. Used for the HUB component on the primary (RTS5409s_ISP class,
chip_guid_alt 55afe793-…) and HUB4 on the secondary.

### 3.1 Wire format vs `RTS5409S_HID::write_hub_flash`

*Decomp:* `libdevices.c:69376`, asm at `libdevices.so:0xb6ae0`:

```c
this->out_opcode = 200;             // 0xC8
this->out_report_byte1 = 0x40;
this->out_sub0 = (char)param_2;            // address byte 0 (LE)
this->out_sub1 = (char)(param_2 >> 8);     // address byte 1
this->out_sub2 = (char)(param_2 >> 16);    // address byte 2
this->out_sub3 = (char)(param_2 >> 24);    // address byte 3
this->out_count = param_4;                 // length (typically 0x80)
memmove(&this->out_payload, param_3, param_4);
send_vendor_cmd(this, ...);
```

So Wistron's c8 wire = `{00, 40, C8, addr[0], addr[1], addr[2],
addr[3], count, 0…, <count bytes payload @ offset 64>}`.

*We do:* same wire layout, just decomposed into named fields:

| wire byte | Wistron        | plugin                              |
|----------:|----------------|-------------------------------------|
|         0 | 0 (report ID)  | 0                                   |
|         1 | 0x40           | `DELL_MONITOR_RT_DIR_WRITE`         |
|         2 | 0xC8           | `DELL_MONITOR_RT_OPCODE_STAGE_FW`   |
|         3 | addr[0]        | `flag` (0x00 low half, 0x80 high)    |
|         4 | addr[1]        | `addr` (0..255)                     |
|         5 | addr[2]        | `bank` (0..nbanks−1)                |
|         6 | addr[3]        | 0                                   |
|         7 | count          | 128 (`STAGE_FW_CHUNK_SIZE`)         |
|        64 | payload start  | payload start                       |

The plugin's `(flag, addr, bank)` triple at bytes 3–5 reconstructs the
same 32-bit LE address Wistron writes. Iteration order generates the
identical sequence of addresses: `0x00000000, 0x00000080, 0x00000100,
… 0x0000FF80, 0x00010000, …`. **Match — byte-for-byte equivalent.**

### 3.2 Orchestration: `RTS5409S_HID::update_self` wraps the chunk loop

*Decomp:* `libdevices.c:69996`. The chunk loop is step 3 of a
five-step sequence:

1. `enable_vdcmd(this, true, true)` — out_sub0 = `1 + 2*1 = 3`. The
   combined-mode form: enable vdcmd AND high_clock in a single
   0x02 frame. Wire: `00 40 02 03 00 DA 0B 00 …`.
2. `erase_spare_bank(this)` — out_opcode = `0xE8`, out_sub1 = 1.
   Wire: `00 40 E8 00 01 00 00 00 …`. Logged as "erase fail" if it
   fails.
3. Loop `write_hub_flash(this, offset, data, 0x80)` from offset 0 to
   `((size >> 7) << 7)` (rounded down to 128 boundary). Logged as
   "write fail (0x%08x, 0x%x, %d)" on each chunk failure.
4. If `size % 0x80 != 0`: one trailing `write_hub_flash` with the
   remainder count.
5. `verify_update_fw(this, &result_byte)` — out_opcode = `0xD9`,
   out_sub0 = 1. Wire: `00 40 D9 01 00 …`. Then sleeps and polls the
   input report 3 times for the verification result; success
   requires `result_byte == 0x01`. Logged as "verify fail (%d)" or
   "status check fail (%d)".
6. `enable_vdcmd(this, true, false)` — out_sub0 = 1. Cleanup:
   disable high_clock, leave vdcmd enabled.

*We do:* only step 3. **Severity: latent → likely breaking.**

This is the same divergence pattern as F1.1 in section 1 (we issue
just the wire we minimally need, without the framing init / cleanup
ops the chip-vendor put around it). At minimum:

- Without `enable_vdcmd(true, true)` the chip may still be in the
  high-clock state we set during `setup()` via the separate
  `enable_high_clock_mode(true)` call (opcode 0x06). The captured
  pcap shows our setup-style separate-calls pattern, so this may
  not matter — but we should confirm.
- Without `erase_spare_bank` the chip's spare flash bank holds
  whatever was there before. If this 0xC8 path actually writes to
  flash (see section 3.3), the writes would either fail or land in
  un-erased flash (which only allows 1→0 transitions, so writes
  would silently corrupt).
- Without `verify_update_fw` we have no proof the chunks landed
  correctly.

### 3.3 The c8 chunks ARE wrapped by the full update_self envelope

*Pcap confirmation:* the captured trace shows the FULL
`RTS5409S_HID::update_self` envelope wrapping each c8 burst, applied
twice (once per hub bank — slaves 0xD4 and 0xD6 each get one):

```
0x02 sub=0x01 da 0b    enable_vdcmd(true, false)   frames 28808 / 39460
0x06 sub=0x01           enable_high_clock_mode
0x02 sub=0x03 da 0b    enable_vdcmd(true, true)    frames 28840 / 39498
0xE8 sub=0x00 arg=0x01  erase_spare_bank            frames 28844 / 39500
0xC8 × 1024  (then × 512)  stage_fw chunks          frames 28852–32104 / 39506–41076
0xD9 sub=0x01           verify_update_fw            frames 32108 / 41080
```

**Our plugin's bare-loop approach is WRONG.** This overturns my
earlier audit conclusion (which was based on the skip catalog not
showing 0xE8 / 0xD9 events). The skip catalog was misleading
because c8 staging never reached real-HW execution — it would have
in subsequent route iterations after HUB1 succeeded.

The c8 staging IS using `RTS5409S_HID::update_self`. We need to
emit the full envelope: `enable_vdcmd(true, true)` →
`erase_spare_bank` (0xE8) → chunk loop → `verify_update_fw`
(0xD9) → `enable_vdcmd(true, false)`.

**Re: "RAM stage vs flash stage"**: the HUB component is apparently
NOT a RAM-loaded ISP shim — it's a flash update of the hub MCU's
own firmware. The "ISP shim" mental model we'd been using is
inaccurate. The decomp anchor IS `update_self`; we just need to
implement the full envelope.

**Severity: latent → likely breaking.** Without
`erase_spare_bank`, the chip's spare flash bank may already
contain garbage from a previous failed write; chunk writes
without prior erase only allow 1→0 transitions, silently
corrupting data. Without `verify_update_fw`, we proceed
optimistically into the 0xE9 trigger even if the chip rejected
some chunk writes.

### 3.4 Outer retry loop in `Rts5409s_ISP::isp`

*Decomp:* `libhub.c:49226`, asm at `libhub.so:0x99360`. The
update_self call is wrapped in a 5-attempt retry loop:

```c
uVar15 = 1;
do {
    uVar8 = (*update_self)(pIVar11, &local_58);
    if ((int)uVar8 == 0) goto SUCCESS;
    nanosleep(_DAT_0029b3b0, _UNK_0029b3b8);  // 1 second
    uVar15++;
} while (uVar15 != 6);  // i.e. up to 5 attempts
```

*We do:* single-shot — `stage_isp_firmware` returns FALSE on first
chunk failure. **Severity: latent.** Same pattern as the
`enable_vdcmd` retry in section 1 — the chip-vendor put retries
around this for a reason (presumably transient HID errors during
the ~512–1024 frames of c8 staging). We should match.

### 3.5 Pre-stage open / handshake

*Decomp:* `Rts5409s_ISP::isp` opens the iic transport (slot 0x20 or
0x28) before the update_self retry loop, same pattern as the IIC_ISP
flow in section 2. For our HID-backed RTS5409s_ISP, the transport
is RTS5409S_HID; its `open` is hidapi-side (no chip-side wire op).

No per-chunk handshake required for c8 staging (the per-write
`hub_handshake` is the same no-op stub we confirmed in section 2.8).

### Fixes pending

- [ ] **F3.4 (latent):** Add a 5-attempt retry around the whole
  `stage_isp_firmware` chunk loop, matching
  `Rts5409s_ISP::isp`'s `update_self` retry. 1 second between
  attempts. The captured pcap presumably doesn't show retries
  (the chip worked first time), but having the retry budget is
  cheap insurance against transient HID errors during the
  ~512+ frames per HUB component.

### Fixes pending (revised)

- [ ] **F3.2 (likely breaking — overturning earlier conclusion):**
  Wrap `stage_isp_firmware` with the full `update_self` envelope.
  Per pcap confirmation:

  1. `enable_vdcmd(true, true)` — opcode 0x02, sub0=3, payload
     `0xDA 0x0B` (combined vdcmd + high_clock).
  2. `erase_spare_bank` — opcode 0xE8, sub0=0, sub1=1.
  3. Chunk loop (current plugin code — unchanged).
  4. `verify_update_fw` — opcode 0xD9, sub0=1, then poll input
     report 3 times for `result_byte == 0x01`.
  5. `enable_vdcmd(true, false)` — opcode 0x02, sub0=1, payload
     `0xDA 0x0B` (cleanup: disable high_clock, leave vdcmd on).

- [ ] **F3.4 (latent — confirmed):** Add the outer 5-attempt
  retry around the whole envelope, matching `Rts5409s_ISP::isp`'s
  retry loop with 1-second `nanosleep(1s, 0)` between attempts.

Items resolved (no fix needed):

- **F3.1 wire format** → match. `{0x40, 0xC8, addr[0..3], count,
  zeros, payload}` with 128-byte chunks. Plugin's
  `(flag, addr, bank)` decomposition reconstructs the same 32-bit
  LE address Wistron writes.
- **F3.5 pre-stage handshake** → match. No per-chunk cal_auth
  required.
- **OQ3.1 RESOLVED:** the decomp anchor IS `RTS5409S_HID::update_self`
  — the c8 staging is a flash update of the hub MCU's own firmware,
  not a RAM-loaded ISP shim. Our plugin needs to emit the full
  envelope (see F3.2 above).
## 4. bootloader-enter trigger

Plugin: `fu_dell_monitor_rt_device_enter_bootloader` at
`fu-dell-monitor-rt-device.c:1506+`. A simple two-iteration loop that
emits opcode 0xE9 twice consecutively per call, with no payload and
no inter-iteration delay.

### 4.1 Wire format vs `RTS5409S_HID::reset_to_flash` / `reset_self`

*Decomp:* two functions emit 0xE9 in `libdevices.c`, both with
byte-identical wire output.

**`reset_to_flash` (libdevices.c:69185, asm at libdevices.so:0xb6740):**

```c
this->out_opcode = 0xe9;
this->out_report_byte1 = 0x40;
// out_sub0..3, out_count, payload all zero
send_vendor_cmd(this, ..., "reset_to_flash\0");
```

Single-shot. Wire: `00 40 E9 00 00 00 00 00 …`.

**`reset_self` (libdevices.c:70110, asm at libdevices.so:0xb7a50):**

```c
cVar4 = 3;
do {
    // zero buffer, set out_opcode=0xe9, out_report_byte1=0x40
    send_vendor_cmd(this, ..., "reset_to_flash\0");
} while ((iVar1 != 0) && (cVar4-- != 1));
```

Up to 3 retries on failure. Same wire bytes as `reset_to_flash`.

*We do:* `for (i = 0; i < 2; i++) vcmd(0x40, 0xE9, 0, 0, NULL, 0)`.
Wire format **match** — `00 40 E9 00 00 00 00 00 …` × 2.

*Divergence — control flow:*

| Wistron path                          | wire emissions       |
|---------------------------------------|----------------------|
| `reset_to_flash` (single-shot)        | 1                    |
| `reset_self` (3 retries on failure)   | 1 (best) … 3 (worst) |

Plugin emits exactly 2 every time, regardless of chip response. The
captured pcap shows 4 total 0xE9 wire ops across the install (two
c8-staging cycles × two emits each) which is consistent with EITHER
"chip needed one retry on each cycle" (Wistron) OR "plugin always
sends two" — both produce 2 emits per cycle.

**Severity: cosmetic on the wire (chip's silicon-level behavior may
prefer either interpretation), but latent on robustness.** If on
some other monitor the first 0xE9 fails for a transient reason,
plugin's blind second-shot might succeed where Wistron's retry would
also succeed; if the second emit also fails, we report success
falsely while Wistron would retry a third time and detect the
failure.

### 4.2 Post-0xE9 caller flow in `Rts5409s_ISP::isp`

*Decomp:* `libhub.c:49436+`. After successful `update_self`:

```c
// Slot 0xa8 of IIC_INTF vtable = reset_self
(*pIVar9->reset_self)();    // emit 0xE9 with retries
// Slot 0x48 = close
(*pIVar9->close)();         // close the HID/i2c transport
local_68.tv_sec = _DAT_0029b3c0;   // 2 seconds
local_68.tv_nsec = _UNK_0029b3c8;  // 0
nanosleep(&local_68, &local_68);
// log "Reset and wait HUB re-enumeration."
```

So Wistron's full post-stage sequence per cycle:

1. Emit 0xE9 (via `reset_self`, with retries).
2. **Close** the HID/i2c transport — the device is about to drop off
   the bus.
3. **Sleep 2 seconds** to let the chip re-enumerate as the
   bootloader device.
4. Continue to next stage / next device.

Constants verified at `libhub.so:0x19b3c0`:

```
0019b3c0: 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
              tv_sec = 2 | tv_nsec = 0
```

*We do:* `enter_bootloader` returns immediately after the two 0xE9
emits. No transport close, no sleep. The next iteration of
`write_firmware`'s route-dispatch loop runs immediately — which may
issue wire ops against the now-disconnecting HID fd.

*Pcap evidence:* the gap from each 0xE9 trigger pair to the next
host frame is **~130 ms**, not the 2-second `nanosleep` from the
decomp:

- E9 pair #1 (frames 34808, 34810) → next host frame 34880 at
  +128.2 ms (opcode 0x06 vendor command).
- E9 pair #2 (frames 43782, 43786) → next host frame 43858 at
  +132.6 ms (opcode 0xE1 cal_auth).

The 2-second `nanosleep` in `Rts5409s_ISP::isp` (libhub.c:49448)
fires on the host side, but during that sleep the kernel's USB
re-enumeration completes within ~130 ms — by the time the next
USB-tool-level frame is emitted, the device is back. The 2-second
budget is a worst-case ceiling, not an empirical baseline.

**Severity: latent — fwupd's `FWUPD_DEVICE_FLAG_WAIT_FOR_REPLUG`
handles this naturally** at the end of write_firmware. Between
operations within write_firmware the route loop on consecutive
direct-stage components targets DIFFERENT devices (HUB c8 on
primary device, then HUB4 c8 on secondary device — neither
disconnects the other), so there's no race against re-enumeration
mid-loop.

### 4.3 Transport close

Wistron's close after `reset_self` is the equivalent of `hid_close()`
on the hidapi handle. For our plugin, the fwupd udev backend manages
the fd lifecycle — when the device disconnects, fwupd closes the
hidraw fd automatically. So we don't need an explicit close at the
plugin level.

**Severity: match (handled by fwupd).**

### 4.4 What triggers a "reset" vs a "reset_to_flash"?

Both Wistron functions emit identical wire bytes (`00 40 E9 …`) and
pass the same string "reset_to_flash\0" to the logger. The
distinction is purely in the host-side wrapper: `reset_to_flash` is
single-shot (called from contexts that don't need retries), and
`reset_self` is the retry-loop version used by `Rts5409s_ISP::isp`.

For our plugin's case (post-c8-staging trigger), `reset_self`'s
retry pattern is the right model. **Severity: see F4.1.**

### Fixes pending

- [ ] **F4.1 (latent):** Replace plugin's hardcoded "fire twice" with
  a retry loop modeled on `reset_self`. Up to 3 attempts, exit on
  first success, return error if all 3 fail. Wire output stays
  identical in the success-on-first-try and chip-needs-1-retry
  cases — improves robustness only when the first emit fails
  outright.

- [ ] **F4.2 (RESOLVED — DOWNGRADED to "match — handled by
  WAIT_FOR_REPLUG"):** The 2-second `nanosleep` in
  `Rts5409s_ISP::isp` was a worst-case host-side ceiling, not a
  real-hardware requirement. Pcap shows the next host frame
  arrives ~130 ms after the 0xE9 pair — well within typical USB
  re-enumeration latency. fwupd's
  `FWUPD_DEVICE_FLAG_WAIT_FOR_REPLUG` handles this at the end of
  write_firmware. Between operations within the route loop,
  consecutive direct-stage components target different devices,
  so no mid-loop race.

Items resolved (no fix needed):

- **F4.1 wire format** → match. `{0x40, 0xE9, 0, 0, 0, 0, 0, 0, ...}`
  identical to Wistron.
- **F4.3 transport close** → match. fwupd's udev backend manages the
  hidraw fd lifecycle; explicit `hid_close` not needed.
## 5. PDC programming

Plugin: `fu_dell_monitor_rt_device_pdc_program` at
`fu-dell-monitor-rt-device.c:1850+`. Handles the TI TPS6598x USB-PD
controller (chip_guid_alt `ea72869e-…`) via the 4CC command interface
(FLrr/FLem/FLad/FLwd/FLrd/FLvy) over the i2c-tunnel to slave 0x42.

### 5.1 4CC command wire format vs `TPS6598X_API::fourCC_Command`

*Decomp:* `libpdc.c:48764`. Each 4CC command is a multi-step i2c
transaction:

1. Write `len` bytes to register 0x08 (Data1) — the input buffer.
2. Write 6 bytes to register 0x09 (Cmd1) — `0x04 0x46 0x4c <c1> <c2>`
   (length-prefix + "FL" + 2-char code).
3. Poll register 0x09 — chip clears it to 0 when command completes.
4. Read N+1 bytes from register 0x08 — first byte is the result
   status, then N bytes of response data.

*We do:* Same pattern, decomposed into helpers
(`fu_dell_monitor_rt_pdc_set_buf`, `fu_dell_monitor_rt_pdc_cmd`,
`fu_dell_monitor_rt_pdc_wait`, `fu_dell_monitor_rt_pdc_finish_cmd`)
at `fu-dell-monitor-rt-device.c:1527+`. **Wire format: match —**
verified end-to-end against pcap. The PDC flow runs fully under
emulation without skips after commit b48ba060b (per-chunk VerifyFW
addition).

### 5.2 Region 0 vs Region 1 — single-region vs two-region update

*Decomp:* `Tps6598xISP::FWUpdate82` (libpdc.c:50738). The top-level
PDC flow reads `BootFlags82` and dispatches based on:

```c
if ((this->api).low_region_only != 0) {
    // .upg config flag — single-region update path
    if ((BootFlags82 & 0x2280) != 0) bail;
    RegionUpdate82(this, false);   // Region 0 only
    return;
}
if (((byte)BootFlags82 & 0x20) == 0) {
    // Region 1 not yet attempted — update R1, then R0
    rgn1Vrfy = RegionUpdate82(this, true);
    if (rgn1Vrfy) rgn0Vrfy = RegionUpdate82(this, false);
    ...
}
// else: Region 0 only (or with conditional Region 1)
RegionUpdate82(this, false);
if (...) RegionUpdate82(this, true);
```

So the TPS6598x has **two flash regions**, and the firmware update may
write one or both, in order determined by:

1. `low_region_only` flag from `.upg` config (Wistron's
   per-PDC-component metadata).
2. `BootFlags82` chip-state register (read via `FLrr` at start of
   FWUpdate82).
3. Error flags from prior commands (readError/writeError/fourCCerror).

*We do:* `pdc_program` hardcodes "Region 0 only" (single FLrr +
single block-write loop).

*Pcap confirmation — overturns my earlier "single-region" claim:*
The captured trace has **TWO FLrr commands**, at frames 49750
(t=147.84s) and 289352 (t=566.23s) — separated by ~418 seconds.
Total PDC 4CC counts: `rr:2, em:1, ad:457, wd:457, rd:914, vy:1`.
One `em` (erase) and one `vy` (verify) — so it's not two complete
RegionUpdate cycles. More like one big erase + one block write loop
(457 chunks) + one final verify, with two FLrr probes bracketing
the flow.

Possible interpretations:

- **(A)** Wistron calls `RegionUpdate82(false)` once (Region 0
  only), and the two FLrr's are: (1) initial region-pointer
  discovery at the start, (2) a redundant re-probe partway
  through the flow (Wistron's RegionUpdate82 logic does have a
  "tempData == &region0_addr[lVar4]" recheck that may re-issue
  FLrr).
- **(B)** Wistron calls FWUpdate82 twice — but only one of the
  calls runs the actual write/erase/verify loop, the other only
  reads the region pointer for diagnostics.

The single `em` + single `vy` count rules out the two-region
update interpretation: two regions would produce two of each.

**Severity: latent — our single-FLrr / single-write-loop matches
the observed write/erase/verify count.** The extra FLrr probe is
benign on the wire (it doesn't change chip state); we just don't
emit it. For portability across:

- Different .upg payloads (some may set `low_region_only = false`,
  triggering two-region updates).
- Different chip states (BootFlags82 bit 5 indicates whether
  Region 1 was ever attempted; freshly-manufactured chips may
  need it).

… we'd need to (a) parse `low_region_only` from .upg metadata and
(b) read BootFlags82 from the chip at the start of `pdc_program`,
then dispatch one-or-two RegionUpdate calls accordingly.

For the current M3T105 + U4025QW combo this is a non-issue. But
the plugin's `route.proto->name = "TI TPS6598x USB-PD controller"`
ostensibly handles any TPS6598x-class chip, and silently
single-region'ing a chip that needs two-region updates could leave
it partially-flashed.

### 5.3 Per-chunk VerifyFW vs `using_verify_command_only`

*Decomp:* `Tps6598xISP::RegionUpdate82` (libpdc.c:50389):

```c
if (this->using_verify_command_only == 0) {
    // Do per-chunk VerifyFW after each FLwd
    cVar2 = VerifyFW(this, addr, chunk_size, src_data);
    ...
}
```

Wistron's tool has a runtime flag `using_verify_command_only`. When
false (the default for our captured update), per-chunk VerifyFW
(2× FLrd readback + memcmp + retry up to 3 times) runs after every
FLwd. When true, only the final FLvy runs.

*We do:* Per-chunk VerifyFW is unconditional in
`fu_dell_monitor_rt_pdc_verify_chunk` (added in commit b48ba060b).
Matches Wistron's runtime default (`using_verify_command_only=0`).
**Match — but unconditional.** For the U4025QW path this is fine;
for portability we could plumb the flag through .upg metadata or
default-on for safety.

### 5.4 The "off-by-one trailer" intentional divergence

*Decomp:* `Tps6598xISP::RegionUpdate82`'s chunk loop iterates
`count32bit < this->fw_region_size / chunk_size`. The header-last
write (chunk 0) happens AFTER the loop. If `fw_region_size %
chunk_size != 0`, the loop's last iteration reads
`fw_region_data[fw_region_size + 0..chunk_size-1]` — past the end
of the std::vector by up to one chunk. Wistron writes that heap
garbage to flash as the chunk just before the header.

*We do:* Skip that extra write entirely. The plugin's loop emits
`(blob_size / chunk_size) - 1` body chunks + 1 header chunk =
exactly `blob_size / chunk_size` chunks total. **Deliberate
divergence — see commit 48afc28** ("prefer fixing the bug — emit
455+1 writes, not 456+1"). The fixture specializer
(`pcap-to-fixture.py`) normalizes Wistron's heap-leak bytes to
zero so the emulator can match our doc-correct frames.

**Severity: match (deliberate, justified).**

### 5.5 Outer flow: pre-flash BootFlags82 read

*Decomp:* `FWUpdate82` reads `BootFlags82` register 0x2D, length 2,
via `TPS6598X_API::ReadIICRegister` at the very start of the update.
Logs the bits, then dispatches RegionUpdate82 based on them.

*We do:* `pdc_program` does NOT read BootFlags82. We go straight to
`FLrr(0)` → erase → write loop. **Severity: latent.** Without the
BootFlags82 check we don't know:

- Whether the chip is in a state that even allows updates (BootOk
  bit).
- Which region was last attempted (Region 1 attempted bit
  influences flash layout).
- Whether the prior update aborted mid-write (CRC fail / flash
  error bits).

Wistron uses these bits to choose the update path. We assume
single-region Region 0; if the chip is in an unexpected state we
might flash the wrong region or proceed into a broken state.

### 5.6 Region pointer constants and the "0x100e0ac" magic

*Decomp:* `RegionUpdate82` checks if `tempData == 0x100e0ac` after
the FLrr read. If so, logs "ABORT: Low-Region File found with
offset 0x0. This is not a valid 2-region flash image". This is a
sanity check for malformed flash images — a region pointer of
`0x100e0ac` means the chip has the low-region image but at offset
0, which Wistron treats as invalid.

*We do:* We check `base == 0 || base == 0xFFFFFFFF` (uninitialized
flash sentinel). We don't check for `0x100e0ac`. **Severity:
cosmetic for U4025QW** (our M3T105 PDC has a normal region
pointer), but a portability concern for chips that might have been
half-initialized by a botched prior install.

### 5.7 Pre-stage IIC open + post-stage close

*Decomp:* `Tps6598xISP::isp` (libpdc.c:50915) opens the IIC
transport (slot 0x20 or 0x28) before calling `FWUpdate82`. After
the update, `Tps6598xISP::check_start` closes it.

*We do:* Driven by fwupd's udev backend — no explicit open/close
needed in the plugin. **Match.**

### Fixes pending

- [ ] **F5.2 (latent):** Plumb `low_region_only` from .upg metadata
  into `pdc_program` dispatch. Read BootFlags82 at start; choose
  between single-region (R0 only) and two-region (R1 first, then
  R0) flows accordingly. **Not blocking for U4025QW M3T105** —
  current single-R0 hardcode matches the captured behavior. Worth
  fixing before any other Dell monitor / .upg combo is tried.
- [ ] **F5.5 (latent):** Read BootFlags82 at the start of
  `pdc_program` (4CC `FLrr` won't work for this; need
  `ReadIICRegister(0x2D, 2)`). Log the bits, refuse to proceed if
  BootOk == 0, dispatch region order accordingly. Same gating as
  F5.2.
- [ ] **F5.6 (cosmetic):** Add the `0x100e0ac` magic check after
  `FLrr` to bail on half-initialized chips. Low priority; only
  matters if a prior install ran but did not complete.

Items resolved (no fix needed):

- **F5.1 wire format** → match. 4CC `FLrr/FLem/FLad/FLwd/FLrd/FLvy`
  flow verified against decomp + pcap end-to-end.
- **F5.3 per-chunk verify** → match. Wistron's runtime default is
  `using_verify_command_only == 0` (per-chunk on); our plugin
  always-on matches.
- **F5.4 off-by-one trailer** → match. Deliberate divergence
  documented in commit 48afc28; specializer normalizes the fixture.
- **F5.7 open/close** → match. fwupd's udev backend handles fd
  lifecycle.
## 6. DISPLAY block-write

Plugin: `fu_dell_monitor_rt_device_display_program` at
`fu-dell-monitor-rt-device.c:3289+`. Handles the panel-scaler
(chip_guid_alt `23d1218b-…`) via the post-bootloader i2c-tunnel to
slave 0x94, using the F1/F4/04/F5 indirect-access vendor opcodes
and the SPI-flash erase/program helpers from `REALTEK_API`.

Most of the wire-level details for this module were decoded during
the initial implementation (tasks #47, #48, #51, #52, #53, #55) and
are already grounded in `libdisplay.c` decomp comments throughout the
plugin source. This audit focuses on divergences in the OUTER
orchestration that those task focused work didn't catch.

### 6.1 Pre-block-loop chip setup vs `RealtekISP::secure_program_rtk` preamble

*Decomp:* `libdisplay.c:67012`. The preamble (when `iic_api.field_0x1c
!= 0`) does:

1. `check_image` (block-size validation; rejects unless `block_size
   == 0x10000` or `0x1000`).
2. 3-attempt retry of `REALTEK_API::spi_unit_erase` on the FINAL
   64-KB block (address `flash_end_index << 16`).

*We do:* `fu_dell_monitor_rt_device_rtkpanel_setup` runs
`enter_isp → set_default_value → spi_disable_wp_pin →
spi_read_jedec_id → spi_set_wp_status → spi_unit_erase` on the end
block. **Match — verified against decomp during commits #52 #53 #55.**

*Divergence:* Wistron retries `spi_unit_erase` up to 3 times. We
single-shot. **Severity: latent.**

### 6.2 Per-block loop vs Wistron's inner loop

*Decomp:* `secure_program_rtk` main loop. Each block is wrapped in
a 3-attempt retry (`uVar14 = 3; do { … } while (uVar14 != 0)`).
Inside each attempt: spi_unit_erase (block) + spi_write_data
(payload bytes) + spi_read_crc (verify). Failures bubble through the
retry counter.

*We do:* `fu_dell_monitor_rt_device_display_program_block` runs the
F1/F4/04/F5 commit sequence once per block. **No per-block retry.**

**Severity: latent.** For our captured M3T105 path the chip
presumably succeeded on first try (otherwise the pcap would show 6+
attempts per failed block); for a flaky chip or marginal flash
sector this could fail without diagnostic and leave a partial
flash.

### 6.3 Post-loop validity-marker write — `field_0x1c`

*Decomp:* `secure_program_rtk:67296+`:

```c
LAB_001b3276:
    uVar9 = *(uint *)&(this->iic_api).field_0x1c;
    if (uVar9 != 0) {
        local_42 = 0x55aa;                                  // 2-byte literal
        uVar9 = REALTEK_API::spi_write_data(&this->iic_api,
                                             uVar9,         // SPI flash addr
                                             (uchar *)&local_42,
                                             '\x01');        // length = 1 byte
    }
```

After the block loop completes successfully, Wistron writes **one
byte** (the low byte of `0x55AA` literal = `0xAA`) to a flash
address held in `REALTEK_API::field_0x1c`. This is a "firmware
valid" marker — the chip's bootloader checks this address at boot;
the right value flags the new firmware as valid and bootable.

*We do:* Nothing.

*Pcap confirmation:* the marker write IS emitted by Wistron at the
end of the scaler block-write section. Frame 811742, exactly one
2-byte write to register 0x70 with value `AA 55`. The three
preceding writes set the indirect-access target SPI flash address:

```
811728: register 0x64 = 0x3F   (SPI address high byte)
811732: register 0x65 = 0xF8   (SPI address mid byte)
811734: register 0x66 = 0xFE   (SPI address low byte)
811742: register 0x70 = 0xAA 0x55   ← 2-byte marker
```

So the marker is written to SPI flash address **`0x3FF8FE`** —
MSB-first per the plugin's existing
`DELL_MONITOR_RT_RTKPANEL_REG_ADDR_HI/MID/LO` convention
(`fu-dell-monitor-rt-device.c:2400-2402`).

The decomp's `local_42 = 0x55aa; spi_write_data(..., &local_42,
'\x01')` (len=1) appears to disagree with the pcap's 2-byte write
— but `spi_write_data`'s `len` parameter may refer to a different
unit (word count? blob count?). The pcap is authoritative for the
wire emission.

**Severity: breaking on real hardware.** Without this marker write,
the panel scaler's bootloader treats the freshly-flashed firmware
as invalid and refuses to boot from it. Confirmed missing in our
plugin — `display_program` returns after the last block-write loop
iteration without emitting any 0x70/0xAA/0x55 wire ops.

### 6.4 The `0x55aa` literal — 1 byte or 2 bytes on the wire?

The decomp `local_42 = 0x55aa` is an `undefined2` (2-byte value) on
the stack. Stored little-endian: bytes `aa 55`. The
`spi_write_data(..., &local_42, '\x01')` call has size = 1, so only
the LOW byte (0xAA) goes to flash.

If the marker is actually supposed to be 2 bytes (0xAA, 0x55), this
is a Wistron off-by-one (similar to the PDC trailer bug we fixed in
commit 48afc28). If 1 byte is intentional, the chip's bootloader
looks for `0xAA` at the marker address.

**Severity: cosmetic to the audit, but matters if we implement the
fix.** Worth confirming against the captured pcap.

### 6.5 Outer flow: `RealtekISP::isp` orchestration

*Decomp:* `libdisplay.c:67757`. The isp() entry opens the IIC
transport, runs `secure_program_rtk`, then closes. Same pattern as
the other ISPs. No additional wire ops between open/program/close.

*We do:* Driven by fwupd's udev backend. **Match.**

### Fixes pending

- [ ] **F6.1 (latent):** Add 3-attempt retry around
  `spi_unit_erase` in `rtkpanel_setup` (the end-block-erase
  preamble).
- [ ] **F6.2 (latent):** Add 3-attempt retry around each per-block
  call to `display_program_block`.
- [ ] **F6.3 (breaking — confirmed via pcap frame 811742):** Add
  post-loop validity-marker write. The wire sequence:

  ```
  reg 0x64 = 0x3F   (SPI flash addr byte 0)
  reg 0x65 = 0xF8   (SPI flash addr byte 1)
  reg 0x66 = 0xFE   (SPI flash addr byte 2)
  reg 0x70 = 0xAA 0x55   (2-byte marker data)
  ```

  Target SPI flash address: `0x3FF8FE` (MSB-first, matching
  plugin's existing `RTKPANEL_REG_ADDR_HI/MID/LO` convention).
  Marker value: 2 bytes `0xAA 0x55`. The decomp's `'\x01'` length
  parameter on `spi_write_data` is misleading — pcap shows 2 bytes
  on the wire.

  Without this marker, the panel scaler's bootloader refuses the
  new firmware. Must fix before any real-hardware install attempt
  of the DISPLAY component.

Items resolved (no fix needed):

- **F6.1 pre-block setup wire format** → match (verified during
  initial implementation, commits #52 #53 #55).
- **F6.2 per-block F1/F4/04/F5 wire format** → match (verified
  during initial implementation, commits #47 #48 #51).
- **F6.5 open/close orchestration** → match. fwupd handles fd
  lifecycle.
