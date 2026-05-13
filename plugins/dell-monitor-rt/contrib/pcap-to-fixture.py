#!/usr/bin/env python3
# pylint: disable=invalid-name,missing-docstring
#
# Copyright 2026 Joshua Perry <josh@6bit.com>
# Copyright 2026 Ada <ada@6bit.com>
#
# SPDX-License-Identifier: LGPL-2.1-or-later
"""
pcap-to-fixture.py — produce a fwupd emulation fixture for the
dell-monitor-rt plugin from a USB capture.

Pipeline:

    pcap (Wireshark/usbmon recording of Dell's updater)
        │
        ▼
    fwupd's contrib/pcap2emulation.py --gtype FuHidrawDevice
        │  generic conversion: USB ControlTransfer events
        │  → hidraw Write/Ioctl events, plus stereotyped
        │  GetBackendParent / ReadProp probe events for
        │  emulation-time setup.
        ▼
    THIS SCRIPT — dell-monitor-rt-specific specialization:
        - Adds the HID Report-ID prefix (0x00) the U4025QW
          requires on every hidraw write/read, since the
          chip's HID descriptor declares no report IDs.
        - Re-distributes events across setup / install /
          reload phases to match what the plugin's
          setup() / write_firmware() lifecycle actually
          runs, rather than the USB-re-enumeration-based
          phase boundaries pcap2emulation defaults to.
        - Identifies the bootloader-entry boundary
          (opcode 0xE9) and uses it to split
          pre-bootloader vendor-command init from the
          actual flash work.

Usage:

    pcap-to-fixture.py <pcap> <output.zip>

Pcap and output paths are passed through; vendor IDs
(0bda:1100, 0bda:1101) and other constants are hardcoded
because they're specific to the U4025QW (and other Dell
monitors using the same Wistron stack).
"""

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Tuple
from zipfile import ZipFile, ZIP_DEFLATED

# Realtek RTS5409S hub MCU on the Dell U4025QW exposes two HID interfaces:
#   - VID:PID 0bda:1100 — primary, runs the cal_auth + I²C tunnel + flash
#   - VID:PID 0bda:1101 — secondary; HUB4 c8 staging happens here, driven
#                          by the primary's plugin code via target redirect
DELL_MONITOR_RT_VID_PID = ["0bda:1100", "0bda:1101"]
PRIMARY_PID = 0x1100

# Bootloader-entry trigger — opcode 0xE9 sent twice on each firmware-mode
# HID interface immediately before the device drops the firmware-mode
# interface and re-enumerates as the bootloader interface. Used here as the
# phase boundary between "setup-style probes" and "install".
BOOTLOADER_ENTER_OPCODE = 0xE9

# HID Report-ID prefix byte — the U4025QW's HID descriptor declares no
# report IDs, so hidraw writes and reads carry a fixed leading 0x00 ahead
# of the 192-byte payload.
HIDRAW_REPORT_ID_PREFIX = 0x00

# i2c-tunnel write opcode (DIR=0x40, OP=0xC6). Outer frame layout (after
# the leading Report-ID byte we add elsewhere):
#   offset 0:  0x40             — direction (host → device)
#   offset 1:  0xC6             — i2c write
#   offset 6:  payload length   — bytes at offset 64.. that the chip reads
#   offset 8:  i2c slave addr
#   offset 64: payload bytes    — the on-wire I²C payload
I2C_TUNNEL_WRITE_DIR = 0x40
I2C_TUNNEL_WRITE_OP = 0xC6
I2C_TUNNEL_LEN_OFFSET = 6
I2C_TUNNEL_SLAVE_OFFSET = 8
I2C_TUNNEL_PAYLOAD_OFFSET = 64

# TPS6598x USB-PD controller (PDC) lives at i2c slave 0x42 behind the
# i2c-tunnel; per TI SLVUBH2B the host issues 4CC commands by writing
# `08 04 46 4c <c1> <c2>` to register 0x08 (Cmd1), with input data
# pre-staged via a write to register 0x09 (Data1) of the form
# `09 LL <data>`. Wistron's host code over-stages the input buffer for
# some 4CCs (heap-leak / over-spec length) — the chip ignores trailing
# bytes, but a doc-correct implementation only stages what the doc says
# the chip will read. We normalize the captured setbuf writes to the
# doc-spec lengths so the fixture matches a doc-correct plugin.
PDC_I2C_SLAVE = 0x42
PDC_REG_CMD1 = 0x08
PDC_REG_DATA1 = 0x09

# Doc-spec input lengths for the 4CCs the plugin actually issues, per
# TI SLVUBH2B section 6 (Flash 4CC commands). Commands whose input is
# variable-length (e.g. FLwd 1..64 bytes) are absent — the existing
# length is preserved as-is.
PDC_4CC_INPUT_LEN = {
    "rr": 1,  # 1 byte region number
    "em": 5,  # 4-byte LE address + 1-byte sector count
    "ad": 4,  # 4-byte LE address
    "rd": 4,  # 4-byte LE address (per captured trace)
    "vy": 4,  # 4-byte LE address
}


def _pcap2emulation_path() -> str:
    """Locate fwupd's pcap2emulation.py relative to this script.
    The repo layout is fwupd/{contrib,plugins/dell-monitor-rt/contrib}/.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    candidate = os.path.normpath(os.path.join(here, "..", "..", "..", "contrib", "pcap2emulation.py"))
    if not os.path.isfile(candidate):
        sys.stderr.write(f"could not find pcap2emulation.py at {candidate}\n")
        sys.exit(1)
    return candidate


def _run_pcap2emulation(pcap: str, work_dir: str) -> str:
    """Invoke contrib/pcap2emulation.py in --gtype FuHidrawDevice mode and
    return the path to the generated zip."""
    out_zip = os.path.join(work_dir, "intermediate.zip")
    cmd = [
        "python3",
        _pcap2emulation_path(),
        "--gtype",
        "FuHidrawDevice",
        pcap,
        out_zip,
    ] + DELL_MONITOR_RT_VID_PID
    sys.stderr.write("running: " + " ".join(cmd) + "\n")
    subprocess.run(cmd, check=True)
    return out_zip


def _read_phases(intermediate_zip: str) -> List[Tuple[str, Dict[str, Any]]]:
    """Read every JSON phase from the intermediate zip and any sibling
    `<zip>-N.json` files emitted as 'unused' overflow phases.
    Returns a list of (phase-name, phase-dict) pairs in pcap-frame order."""
    phases: List[Tuple[str, Dict[str, Any]]] = []
    with ZipFile(intermediate_zip, "r") as zf:
        for name in ("setup.json", "install.json", "reload.json"):
            if name in zf.namelist():
                phases.append((name, json.loads(zf.read(name))))
    # pcap2emulation puts excess phases as `<zip>-3.json` etc. next to
    # the zip. Sort by the trailing integer so they line up with the
    # pcap's actual re-enumeration order.
    base = intermediate_zip
    parent = os.path.dirname(base)
    prefix = os.path.basename(base) + "-"
    extras = []
    for fn in os.listdir(parent):
        if fn.startswith(prefix) and fn.endswith(".json"):
            try:
                idx = int(fn[len(prefix) : -len(".json")])
            except ValueError:
                continue
            extras.append((idx, fn))
    extras.sort()
    for idx, fn in extras:
        with open(os.path.join(parent, fn)) as f:
            phases.append((f"phase{idx}", json.load(f)))
    return phases


def _add_report_id_prefix(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Rewrite Write events and Ioctl events so each carries a leading
    0x00 Report-ID byte ahead of the captured wire payload.
    pcap2emulation.py emits the wire bytes verbatim because it can't tell
    from the pcap whether the device declares Report IDs; we know the
    U4025QW doesn't, so the hidraw I/O is `0x00 + payload`.

    For Ioctl events we also have to synthesize the input-buffer half of
    fwupd's event-id format. fu_ioctl_execute() builds the lookup key as
    `Ioctl:Request=0x..,Data=<base64-of-input>,Length=0x..` (see
    fu-ioctl.c:258-263), where the input buffer is whatever the plugin
    passed in. Our plugin zeroes the response buffer before HIDIOCGINPUT,
    so the input is 193 zero bytes — that's what we encode here. The
    captured response payload moves to the DataOut field that
    fu_device_event_copy_data reads back into the plugin's buffer."""
    rewritten: List[Dict[str, Any]] = []
    for ev in events:
        eid = ev.get("Id", "")
        if eid.startswith("Write:Data="):
            data_b64 = eid.split("Data=", 1)[1].split(",")[0]
            try:
                wire = base64.b64decode(data_b64) if data_b64 else b""
            except Exception:
                rewritten.append(ev)
                continue
            padded = bytes([HIDRAW_REPORT_ID_PREFIX]) + wire
            new_b64 = base64.b64encode(padded).decode("ascii")
            new_ev = dict(ev)
            new_ev["Id"] = f"Write:Data={new_b64},Length=0x{len(padded):x}"
            rewritten.append(new_ev)
        elif eid.startswith("Ioctl:Request="):
            # Captured response payload is in DataOut for events created
            # by the converter's existing code path, or in Data for
            # events that came through the new GET_REPORT pairing path.
            response_b64 = ev.get("DataOut") or ev.get("Data") or ""
            try:
                wire = base64.b64decode(response_b64) if response_b64 else b""
            except Exception:
                rewritten.append(ev)
                continue
            padded_response = bytes([HIDRAW_REPORT_ID_PREFIX]) + wire
            # Plugin's input buffer is zeroed (memset before HIDIOCGINPUT).
            zeroed_input = bytes(len(padded_response))
            zeroed_b64 = base64.b64encode(zeroed_input).decode("ascii")
            request_part = eid.split(",", 1)[0]  # "Ioctl:Request=0x..."
            new_ev = {
                "Id": f"{request_part},Data={zeroed_b64},Length=0x{len(padded_response):x}",
                "DataOut": base64.b64encode(padded_response).decode("ascii"),
            }
            rewritten.append(new_ev)
        else:
            rewritten.append(ev)
    return rewritten


def _decode_write_payload(event: Dict[str, Any]) -> bytes:
    """Return the raw HID write payload for a Write event, or empty bytes
    if the event isn't a Write or has no Data."""
    eid = event.get("Id", "")
    if not eid.startswith("Write:Data="):
        return b""
    b64 = eid.split("Data=", 1)[1].split(",")[0]
    try:
        return base64.b64decode(b64) if b64 else b""
    except Exception:
        return b""


def _i2c_tunnel_write_target(payload: bytes) -> int:
    """If `payload` is an i2c-tunnel write frame (0x40 0xC6 ...) return
    the target slave address; else -1.

    Note: This expects the post-Report-ID-prefix frame, where index 0 is
    the Report-ID byte and the i2c-tunnel header starts at index 1.
    Pre-prefix frames have the i2c-tunnel header at index 0; we handle
    both by sniffing for the 0x40/0xC6 pair at offsets 0 OR 1.
    """
    if len(payload) >= 9 and payload[0] == I2C_TUNNEL_WRITE_DIR and payload[1] == I2C_TUNNEL_WRITE_OP:
        return payload[I2C_TUNNEL_SLAVE_OFFSET]
    if (
        len(payload) >= 10
        and payload[0] == HIDRAW_REPORT_ID_PREFIX
        and payload[1] == I2C_TUNNEL_WRITE_DIR
        and payload[2] == I2C_TUNNEL_WRITE_OP
    ):
        return payload[1 + I2C_TUNNEL_SLAVE_OFFSET]
    return -1


def _i2c_tunnel_payload_view(payload: bytes) -> Tuple[int, bytes, int]:
    """Return (header_offset, inner_payload_bytes, len_field_offset) for
    an i2c-tunnel write frame. header_offset is 0 for pre-prefix frames
    or 1 for post-prefix frames. inner_payload is the bytes the chip
    actually receives (length = len_field)."""
    if len(payload) >= 9 and payload[0] == I2C_TUNNEL_WRITE_DIR and payload[1] == I2C_TUNNEL_WRITE_OP:
        h = 0
    elif (
        len(payload) >= 10
        and payload[0] == HIDRAW_REPORT_ID_PREFIX
        and payload[1] == I2C_TUNNEL_WRITE_DIR
        and payload[2] == I2C_TUNNEL_WRITE_OP
    ):
        h = 1
    else:
        return -1, b"", -1
    len_off = h + I2C_TUNNEL_LEN_OFFSET
    pay_off = h + I2C_TUNNEL_PAYLOAD_OFFSET
    if len(payload) <= len_off or len(payload) < pay_off:
        return -1, b"", -1
    n = payload[len_off]
    return h, bytes(payload[pay_off : pay_off + n]), len_off


def _next_pdc_4cc_after(events: List[Dict[str, Any]], start: int) -> str:
    """Look ahead from `start+1` for the next slave-0x42 4CC command write
    (`08 04 46 4c <c1> <c2>`). Return the 2-char command tail, or "" if
    we hit another setbuf or 50-event window first."""
    for j in range(start + 1, min(start + 50, len(events))):
        d = _decode_write_payload(events[j])
        if not d:
            continue
        if _i2c_tunnel_write_target(d) != PDC_I2C_SLAVE:
            continue
        _h, inner, _lo = _i2c_tunnel_payload_view(d)
        if len(inner) >= 6 and inner[0] == PDC_REG_CMD1 and inner[1] == 0x04 and inner[2] == 0x46 and inner[3] == 0x4C:
            return chr(inner[4]) + chr(inner[5])
        # Another setbuf before any 4CC — pairing is ambiguous.
        if len(inner) >= 2 and inner[0] == PDC_REG_DATA1:
            return ""
    return ""


def _rewrite_pdc_setbuf(payload: bytes, new_data: bytes) -> bytes:
    """Rebuild an i2c-tunnel-write HID frame with the inner PDC setbuf
    payload replaced by `09 LL new_data`. Outer LEN field at offset 6
    is updated; bytes between new payload end and old payload end are
    zeroed; total frame size is preserved."""
    h, _inner, len_off = _i2c_tunnel_payload_view(payload)
    if h < 0:
        return payload
    pay_off = h + I2C_TUNNEL_PAYLOAD_OFFSET
    out = bytearray(payload)
    new_inner = bytes([PDC_REG_DATA1, len(new_data)]) + new_data
    old_len = out[len_off]
    new_len = len(new_inner)
    out[len_off] = new_len
    # Clear the old payload region within the frame, then write the new
    # payload. This drops Wistron's heap-leak trailing bytes.
    for k in range(pay_off, pay_off + max(old_len, new_len)):
        if k < len(out):
            out[k] = 0
    out[pay_off : pay_off + new_len] = new_inner
    return bytes(out)


def _normalize_pdc_setbufs(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Walk events; for each TPS6598x setbuf write (slave 0x42, payload
    `09 LL <data>`), pair it with the next 4CC command on slave 0x42 and,
    if the doc spec for that command has a fixed input length shorter
    than what was captured, rewrite the captured setbuf to the doc-spec
    length (truncating Wistron's heap-leak trailing bytes).

    This is what makes a doc-correct plugin (sending 1-byte FLrr and
    5-byte FLem) match a fixture captured from Wistron's host code
    (which over-stages 4 and 8 bytes respectively)."""
    rewritten: List[Dict[str, Any]] = []
    rewrite_count = 0
    for i, ev in enumerate(events):
        d = _decode_write_payload(ev)
        if not d or _i2c_tunnel_write_target(d) != PDC_I2C_SLAVE:
            rewritten.append(ev)
            continue
        _h, inner, _lo = _i2c_tunnel_payload_view(d)
        # Only setbuf writes (register 0x09) need normalization.
        if not (len(inner) >= 2 and inner[0] == PDC_REG_DATA1):
            rewritten.append(ev)
            continue
        cmd = _next_pdc_4cc_after(events, i)
        canon_len = PDC_4CC_INPUT_LEN.get(cmd)
        captured_data_len = inner[1]
        if canon_len is None or captured_data_len <= canon_len:
            rewritten.append(ev)
            continue
        # Rewrite: keep the first `canon_len` bytes of the captured input.
        new_data = bytes(inner[2 : 2 + canon_len])
        new_payload = _rewrite_pdc_setbuf(d, new_data)
        new_b64 = base64.b64encode(new_payload).decode("ascii")
        new_ev = dict(ev)
        new_ev["Id"] = f"Write:Data={new_b64},Length=0x{len(new_payload):x}"
        rewritten.append(new_ev)
        rewrite_count += 1
    if rewrite_count:
        sys.stderr.write(
            f"  normalized {rewrite_count} PDC setbuf writes to doc-spec lengths\n"
        )
    return rewritten


def _is_c8_staging(event: Dict[str, Any]) -> bool:
    """A Write event whose payload starts 0x00 (Report-ID) + 0x40 (DIR_WRITE)
    + 0xC8 (STAGE_FW) — i.e. one of the 512 ISP-shim-staging frames the
    host emits before the bootloader-entry trigger."""
    eid = event.get("Id", "")
    if not eid.startswith("Write:Data="):
        return False
    data_b64 = eid.split("Data=", 1)[1].split(",")[0]
    try:
        decoded = base64.b64decode(data_b64) if data_b64 else b""
    except Exception:
        return False
    return (
        len(decoded) >= 3
        and decoded[0] == HIDRAW_REPORT_ID_PREFIX
        and decoded[1] == 0x40
        and decoded[2] == 0xC8
    )


def _is_bootloader_enter(event: Dict[str, Any]) -> bool:
    """A Write event whose payload starts 0x00 (Report-ID) + 0x40 (DIR_WRITE)
    + 0xE9 (BOOTLOADER_ENTER) — i.e. the trigger our plugin sends to
    transition the MCU into bootloader mode. We use this as the boundary
    between setup-time probes and install-time work."""
    eid = event.get("Id", "")
    if not eid.startswith("Write:Data="):
        return False
    data_b64 = eid.split("Data=", 1)[1].split(",")[0]
    try:
        decoded = base64.b64decode(data_b64) if data_b64 else b""
    except Exception:
        return False
    return (
        len(decoded) >= 3
        and decoded[0] == HIDRAW_REPORT_ID_PREFIX
        and decoded[1] == 0x40
        and decoded[2] == BOOTLOADER_ENTER_OPCODE
    )


def _split_at_bootloader_enter(
    events: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Partition a device's events into (setup, install) at the first
    bootloader-enter trigger. The trigger itself goes in install."""
    for i, ev in enumerate(events):
        if _is_bootloader_enter(ev):
            return events[:i], events[i:]
    # No trigger in this device's events — everything goes to install
    return [], events


def _flatten_devices(
    phases: List[Tuple[str, Dict[str, Any]]],
) -> List[Dict[str, Any]]:
    """Collapse all phases into one flat list of FuHidrawDevice entries,
    deduping by BackendId. Events from later phases for the same BackendId
    get appended in order. The original phase boundaries are USB
    re-enumeration points which don't align with our plugin's phases."""
    by_backend_id: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []
    for _name, phase in phases:
        for dev in phase.get("UsbDevices", []):
            bid = dev.get("BackendId", "")
            if bid not in by_backend_id:
                # First occurrence — keep the structural events at the head
                by_backend_id[bid] = {
                    k: v for k, v in dev.items() if k != "Events"
                }
                by_backend_id[bid]["Events"] = list(dev.get("Events", []))
                order.append(bid)
            else:
                # Subsequent occurrence — drop the structural probe events
                # at the head (already present from first occurrence) and
                # append only the wire events.
                merged = by_backend_id[bid]
                for ev in dev.get("Events", []):
                    eid = ev.get("Id", "")
                    if eid.startswith(
                        ("GetBackendParent:", "ReadProp:")
                    ):
                        continue
                    merged["Events"].append(ev)
    return [by_backend_id[bid] for bid in order]


def _is_first_install_marker(event: Dict[str, Any]) -> bool:
    """The first event that's clearly part of "install execution" rather
    than "info-display probes" — the first chunked HUB1 staging write
    (i2c-W slave=0xd4 count=66). Wistron's tool spends pcap phase 1's
    first ~320 events doing info reads (panel id, asset tag, model,
    firmware version, IspTag, hub status, PDC version) before this
    chunked write fires; that's the natural boundary between
    fwupd-setup-equivalent activity and fwupd-install-equivalent activity.

    Post-prefix layout (events here have already passed through
    _add_report_id_prefix): byte 0 is the leading 0x00 prefix, then
    direction at 1, opcode at 2, count at 7, slave at 9."""
    eid = event.get("Id", "")
    if not eid.startswith("Write:Data="):
        return False
    data_b64 = eid.split("Data=", 1)[1].split(",")[0]
    try:
        d = base64.b64decode(data_b64)
    except Exception:
        return False
    if len(d) < 12:
        return False
    return (
        d[0] == HIDRAW_REPORT_ID_PREFIX
        and d[1] == 0x40
        and d[2] == 0xC6
        and d[7] == 66
        and d[9] == 0xD4
    )


def _split_at_install_start(
    events: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Partition a device's events into (setup, install).

    Setup events: structural enumeration probes + the leading info-display
    wire activity that Wistron's tool runs before any chip programming.
    This covers what our plugin's setup() and pre-write_firmware lifecycle
    consume — version reads, panel id reads, hub/PDC status reads, etc.
    The events live in pcap phase 1 alongside install events, and we
    can't trivially distinguish them by event type alone.

    Install events: from the first chunked HUB1 staging write onward.
    That's the first event in the captured trace that's clearly part of
    install-execution rather than info-display.

    If no install marker is found (e.g., a child device that has no
    HUB1 activity), all events go to setup.
    """
    boundary = next(
        (i for i, ev in enumerate(events) if _is_first_install_marker(ev)),
        None,
    )
    if boundary is None:
        return list(events), []
    return events[:boundary], events[boundary:]


def _build_phase(devices: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {"FwupdVersion": "2.0.0", "UsbDevices": devices}


def specialize(intermediate_zip: str, output_zip: str) -> None:
    phases = _read_phases(intermediate_zip)

    # Step 1: collapse the pcap's re-enumeration-based phasing into one
    # big "everything Dell's binary did" stream per BackendId.
    flat_devices = _flatten_devices(phases)

    # Step 2: add Report-ID prefix to every Write/Ioctl event.
    for dev in flat_devices:
        dev["Events"] = _add_report_id_prefix(dev["Events"])

    # Step 2b: normalize TPS6598x set-buffer writes to doc-spec lengths.
    # Wistron's host code over-stages the input buffer for a few PDC
    # 4CC commands (FLrr stages 4 bytes when the doc says 1; FLem
    # stages 8 when the doc says 5) — the chip ignores the trailing
    # bytes, but a doc-correct host wouldn't have written them. We
    # rewrite the captured frames so the fixture matches what a
    # doc-correct plugin emits. Without this, the plugin would have
    # to copy Wistron's heap-leak bytes verbatim to satisfy the
    # emulator's strict Write matching, which would tie the plugin
    # to one specific buggy Wistron build.
    for dev in flat_devices:
        dev["Events"] = _normalize_pdc_setbufs(dev["Events"])

    # Step 3: split each device's flattened stream into setup vs install
    # events, respecting fwupd's per-device emulation-load reload semantics.
    #
    # Why a split, not a dump-to-both:
    #
    # fwupd's emulator appends a phase's events into the device's events
    # list when that phase is loaded — without clearing prior phases. So
    # if setup.json and install.json contain identical full-trace dumps
    # (the previous design here), the device's events list grows to ~2×
    # the trace size at install time. The matcher's cursor — which is per-
    # device but persists across phases — finds itself at position N (where
    # N is wherever setup() consumed up to), and any install-time read of
    # an event that lived early in the trace forces the matcher to scan
    # forward past the entire setup-phase copy of the events to reach the
    # install-phase copy. For our verify_baseline panel-id read this was
    # ~222k events bypassed silently — 99.9% of the recorded protocol.
    # That's not a small amount of "fixture noise"; it's the matcher
    # silently leapfrogging over almost the entire captured Wistron run.
    #
    # The split below puts each event in exactly one phase's events list,
    # so the matcher walks through one continuous stream that grows by
    # the install-phase events at install time, not by a duplicate copy
    # of everything. The plugin's emit order has to match the trace's
    # capture order monotonically, but that's the goal — the emulator
    # trace should converge on the pcap as we learn the protocol.
    #
    # Per-device split rules:
    #
    #   Primary device (PID 0x1100): structural enumeration events
    #     (GetBackendParent / ReadProp / ReadSysfs at the head of the
    #     event stream) go to setup.json — fwupd's setup() phase needs
    #     them to construct the device. All subsequent wire events
    #     (Write / Ioctl) go to install.json — they're consumed during
    #     write_firmware().
    #
    #   Child devices (PID 0x1101 in our case): all events go to
    #     setup.json. fwupd doesn't reload child-device event lists
    #     between phases — when the primary's write_firmware drives
    #     a child via target redirect, the matcher is still using
    #     events that were loaded at setup time. So child events have
    #     to be present at setup time to be available at install time.
    #     This is the original workaround the previous full-dump design
    #     was solving for; we preserve it here while fixing the primary
    #     side.
    setup_devs: List[Dict[str, Any]] = []
    install_devs: List[Dict[str, Any]] = []
    for dev in flat_devices:
        pid = dev.get("IdProduct", 0)
        if pid == PRIMARY_PID:
            setup_evs, install_evs = _split_at_install_start(dev["Events"])
            setup_dev = {k: v for k, v in dev.items() if k != "Events"}
            setup_dev["Events"] = setup_evs
            setup_devs.append(setup_dev)
            install_dev = {k: v for k, v in dev.items() if k != "Events"}
            install_dev["Events"] = install_evs
            install_devs.append(install_dev)
        else:
            # Child: full event stream in setup.json only.
            setup_dev = {k: v for k, v in dev.items() if k != "Events"}
            setup_dev["Events"] = list(dev.get("Events", []))
            setup_devs.append(setup_dev)

    setup_phase = _build_phase(setup_devs)
    install_phase = _build_phase(install_devs)
    # No reload events recovered from the wire trace yet — leave the phase
    # empty so the engine doesn't try to replay against it. The
    # post-flash version probe captured in the pcap's phase 7+ would slot
    # in here once we wire reload events into the plugin's reload path.
    reload_phase = _build_phase([])

    with ZipFile(output_zip, "w", compression=ZIP_DEFLATED) as out:
        out.writestr(
            "setup.json", json.dumps(setup_phase, indent=2, separators=(",", " : "))
        )
        out.writestr(
            "install.json",
            json.dumps(install_phase, indent=2, separators=(",", " : ")),
        )
        out.writestr(
            "reload.json", json.dumps(reload_phase, indent=2, separators=(",", " : "))
        )

    # Diagnostic summary
    for name, phase in [("setup", setup_phase), ("install", install_phase)]:
        for dev in phase["UsbDevices"]:
            n_writes = sum(
                1 for e in dev["Events"] if e.get("Id", "").startswith("Write:")
            )
            n_ioctls = sum(
                1 for e in dev["Events"] if e.get("Id", "").startswith("Ioctl:")
            )
            sys.stderr.write(
                f"  {name:<8} {dev['BackendId'][-50:]} writes={n_writes} ioctls={n_ioctls}\n"
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Convert a Dell U4025QW USB pcap into a fwupd emulation fixture."
    )
    parser.add_argument("pcap", help="Input pcap file (Wireshark/usbmon)")
    parser.add_argument("output", help="Output fixture .zip")
    args = parser.parse_args()

    pcap = os.path.abspath(os.path.expanduser(args.pcap))
    out = os.path.abspath(os.path.expanduser(args.output))

    with tempfile.TemporaryDirectory(prefix="dell-monitor-rt-fixture-") as work:
        intermediate = _run_pcap2emulation(pcap, work)
        specialize(intermediate, out)

    sys.stderr.write(f"wrote {out}\n")
