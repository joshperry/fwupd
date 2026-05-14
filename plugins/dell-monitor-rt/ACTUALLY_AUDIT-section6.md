# ACTUALLY_AUDIT — Section 6 (DISPLAY block-write)

The original Section 6 in `AUDIT.md` claimed "match (verified during
initial implementation)" for the wire format. That verdict was a code
review, not an audit — same failure mode as Sections 1.7 / 5.1 / 5.7
(all corrected on 2026-05-13). This file is a per-operation audit
under the discipline criteria committed to before starting:

1. One row per chip-observable operation in the decomp.
2. Every row cites a specific decomp line (or line range).
3. Every row cites our equivalent code line, or `-` if missing.
4. Every row gets ✓ (matches), ✗ (missing / wrong), or ⚠ (different
   but maybe-equivalent — needs evidence).
5. **Order matters.** Right ops in wrong order = ✗.
6. **Reads count as ops.** Every register read either checks the
   response bytes or has a written reason it doesn't. Read-and-discard
   = ✗.
7. **Sleeps count as ops.** Every nanosleep with its constant has a
   corresponding sleep with the same constant in our code, or it's ✗.
8. **Pcap evidence is on responses, not just request bytes.** "We
   send the same bytes" is half the story; "the chip sends the same
   response" is the other half.

If any row in this file is marked ✓ without a specific decomp + plugin
line cite, that's the same failure mode as the original audit. Reject
on review.

The current real-HW failure: DISPLAY block 0's 0x04 secure_control_gpio
commit STALLs with EPIPE (chip disconnects when we issue 0x04). Data
is byte-identical to recap (F1 chunks, erase). The cause is structural
— chip state or a missing secure-subsystem priming op. This audit
needs to find it.

---

## Decomp functions in scope

For DISPLAY (panel scaler, chip_guid_alt 23d1218b-…) the wire ops are
driven by these libdisplay.c functions:

| function                                | location          | role                                |
|-----------------------------------------|-------------------|-------------------------------------|
| `RealtekISP::isp`                       | libdisplay.c:67757 | top-level: open + check_image + program() loop |
| `RealtekISP::program`                   | libdisplay.c:66642 | non-secure path (4 KB sector loop)  |
| `RealtekISP::secure_program_rtk`        | libdisplay.c:67014 | secure path: end-block erase + per-block (erase + secure_program) + validity-marker |
| `RTS5409S_HID::secure_program`          | libdevices.c:70566 | per-block: F4 + F1×512 + 0x04 + F5 + status poll |
| `REALTEK_API::spi_unit_erase`           | libdisplay.c:63578 | per-block erase + secure_check_wp_pin call |
| `REALTEK_API::spi_write_data`           | libdisplay.c:63322 | the validity-marker write at end of secure_program_rtk |
| `RTS5409S_HID::secure_check_wp_pin`     | libdevices.c:68227 | rate-limited 0x04 GPIO emit (called by spi_unit_erase) |
| `RTS5409S_HID::erase_tmp_flash`         | libdevices.c:?    | F4 wire frame |
| `RTS5409S_HID::write_tmp_flash`         | libdevices.c:?    | F1 wire frame |
| `RTS5409S_HID::secure_control_gpio`     | libdevices.c:69058 | 0x04 wire frame (called from secure_program AND secure_check_wp_pin) |
| `RTS5409S_HID::verify_tmp_flash`        | libdevices.c:?    | F5 wire frame |
| `RTS5409S_HID::get_i2c_block_status`    | libdevices.c:?    | post-F5 status poll |

Our equivalent functions:

| plugin function                                           | location                                | role                          |
|-----------------------------------------------------------|-----------------------------------------|-------------------------------|
| `fu_dell_monitor_rt_device_display_program`               | fu-dell-monitor-rt-device.c:4165         | top-level                    |
| `fu_dell_monitor_rt_device_rtkpanel_setup`                | fu-dell-monitor-rt-device.c:3937         | preamble                     |
| `fu_dell_monitor_rt_device_display_program_block`         | fu-dell-monitor-rt-device.c:4026         | per-block: erase + F4 + F1×512 + 0x04 + F5 + F3 |
| `fu_dell_monitor_rt_device_rtkpanel_erase_and_verify_64k` | fu-dell-monitor-rt-device.c:3523         | per-block erase + CRC verify |
| `fu_dell_monitor_rt_device_rtkpanel_enter_isp`            | fu-dell-monitor-rt-device.c:3599         | enter ISP mode |
| `fu_dell_monitor_rt_device_rtkpanel_set_default_value`    | fu-dell-monitor-rt-device.c:3628         | 20-register chip init |
| `fu_dell_monitor_rt_device_rtkpanel_spi_disable_wp_pin`   | fu-dell-monitor-rt-device.c:3680         | WP pin disable |

---

## Audit walks (one per decomp function)

### 6.A `RealtekISP::secure_program_rtk` (libdisplay.c:67014)

Top-level driver of the DISPLAY phase. Below: every observable op the
function emits, in order, with our equivalent.

(STATUS: in progress — table to be filled.)

### 6.B `RTS5409S_HID::secure_program` (libdevices.c:70566)

Per-block driver. Called from `secure_program_rtk` via vtable
dispatch on the iic transport.

(STATUS: in progress — table to be filled.)

### 6.C `REALTEK_API::spi_unit_erase` (libdisplay.c:63578)

Per-block erase. Called from `secure_program_rtk` immediately before
`secure_program`. Notably calls `secure_check_wp_pin` which itself
emits the same 0x04 GPIO opcode that the per-block STALL is on.

(STATUS: in progress — table to be filled.)

### 6.D `RTS5409S_HID::secure_check_wp_pin` (libdevices.c:68227)

Rate-limited 0x04 GPIO emit. Active suspect for the failure: if our
spi_unit_erase doesn't call this, then Wistron emits 0x04 twice per
block (once via secure_check_wp_pin during erase, once via
secure_program after F1) and we only emit it once (in
display_program_block). The chip's secure subsystem might require the
first 0x04 to permit the second.

(STATUS: in progress — table to be filled.)
