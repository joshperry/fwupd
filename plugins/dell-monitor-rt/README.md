---
title: Plugin: Dell Monitor (RealTek scaler / Wistron ISP)
---

## Introduction

This plugin updates firmware on Dell monitors built around a RealTek scaler
controller, accessed via Wistron's "in-system programming" (ISP) protocol
that tunnels I²C through HID Output Reports.

The reference monitor is the Dell U4025QW. The same protocol family applies
to a number of other Dell P/U-series monitors that ship with Dell Display &
Peripheral Manager support.

## Firmware Format

Dell distributes monitor firmware as proprietary `.upg` files (length-prefixed
record format with multiple component sections, ECDSA-signed). The plugin
parses the `.upg` and dispatches each component to the appropriate flash
sequence.

## GUID Generation

These devices use the standard USB DeviceInstanceId values, e.g.:

- `USB\VID_0BDA&PID_1100`
- `USB\VID_0BDA&PID_1101`

## Update Behavior

A typical M3T-series update writes ~1.1 MB across multiple components and
takes ≈18 minutes wall time. The protocol is HID-class control transfers
(SET_REPORT) carrying 192-byte vendor frames.

The device re-enumerates twice during the update (entering and exiting
bootloader mode); the plugin's `remove_delay` is set to 60 s to absorb
this.

## Vendor ID Security

The vendor ID is set to `USB:0x0BDA` (Realtek, the silicon vendor for the
upstream hub MCU exposing the firmware-update HID interfaces).

## External Interface Access

This plugin requires read/write access to the monitor's USB HID interfaces.

## Version Considerations

This plugin has been available since fwupd version `2.0.17` (in development).
