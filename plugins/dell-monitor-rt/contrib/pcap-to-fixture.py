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
#   - VID:PID 0bda:1101 — secondary; not currently driven by the plugin
DELL_MONITOR_RT_VID_PID = ["0bda:1100", "0bda:1101"]

# Bootloader-entry trigger — opcode 0xE9 sent twice on each firmware-mode
# HID interface immediately before the device drops the firmware-mode
# interface and re-enumerates as the bootloader interface. Used here as the
# phase boundary between "setup-style probes" and "install".
BOOTLOADER_ENTER_OPCODE = 0xE9

# HID Report-ID prefix byte — the U4025QW's HID descriptor declares no
# report IDs, so hidraw writes and reads carry a fixed leading 0x00 ahead
# of the 192-byte payload.
HIDRAW_REPORT_ID_PREFIX = 0x00


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

    # Step 3: split each device's events at the bootloader-enter boundary.
    # Pre-trigger events (enable_vdcmd, version probes, cal_auth cycles)
    # go in setup.json so the plugin's setup() can satisfy them. The
    # trigger and everything after it goes in install.json so the
    # plugin's write_firmware() can replay against them.
    setup_devs: List[Dict[str, Any]] = []
    install_devs: List[Dict[str, Any]] = []
    for dev in flat_devices:
        setup_events, install_events = _split_at_bootloader_enter(dev["Events"])
        # The structural probe events (GetBackendParent + ReadProp:HID_ID
        # + ReadProp:HID_NAME) need to be available in every phase that
        # might re-probe the device, not just the phase that first
        # enumerates it. After the bootloader-entry trigger the engine
        # auto-removes the device and waits for replug; when the new
        # device shows up it re-probes via GetBackendParent / HID_ID.
        # Without those events at the head of install.json's per-device
        # entry, that re-probe fails with "no event with ID
        # ReadProp:Key=HID_ID" and the install aborts.
        struct_events = [
            ev
            for ev in setup_events
            if ev.get("Id", "").startswith(("GetBackendParent:", "ReadProp:"))
        ]
        # The plugin's write_firmware does the ISP-shim staging (512 c8
        # writes) right before the bootloader-entry trigger. Those c8
        # events sit in the pre-trigger setup_events stream — but the
        # engine consumes install.json events during install phase, not
        # setup.json. Without copying the c8 staging across, the
        # plugin's first c8 write hits "no event with ID" when fwupd
        # looks up the event in install.json's empty pre-trigger area.
        # Pull just the c8 frames from the pre-trigger stream and
        # prepend them after the structural events in install.json.
        # Eventually staging should move into a detach() method that
        # runs in fwupd's DETACH phase, with its own detach.json — at
        # which point this duplication can go away.
        c8_staging = [
            ev
            for ev in setup_events
            if _is_c8_staging(ev)
        ]
        # setup.json carries the structural probes + pre-trigger events
        setup_dev = {k: v for k, v in dev.items() if k != "Events"}
        setup_dev["Events"] = setup_events
        setup_devs.append(setup_dev)
        # install.json: re-prepend the structural events so any post-
        # disconnect re-probe finds them, then the c8 staging frames so
        # write_firmware's pre-trigger stage can replay, then the post-
        # trigger wire events.
        install_dev = {k: v for k, v in dev.items() if k != "Events"}
        install_dev["Events"] = list(struct_events) + list(c8_staging) + install_events
        install_devs.append(install_dev)

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
