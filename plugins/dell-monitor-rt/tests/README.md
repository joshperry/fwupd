# dell-monitor-rt test fixtures

This directory holds the emulation fixtures used to drive the plugin
under `fwupdtool emulation-load` without touching real hardware.

## Files

| File | Committed? | Size | Purpose |
|------|-----------|------|---------|
| `u4025qw-setup.json` | yes | 2.5 KB | Setup-phase emulation fixture in the upstream `enumeration_data` style. Hooked into the meson `enumeration_data += files(…)` pattern (see `../meson.build`). Drives enumeration and the read-only setup probes. |
| `u4025qw-emulation.zip` | gitignored | 2.3 MB (~101 MB unzipped) | Full setup + install + reload emulation fixture for inner-loop dev of the install path. Way over upstream's per-fixture size norm (largest committed upstream fixture is 18 KB), so kept local. **Regenerated automatically by `dell-monitor-rt-emu`** from the source pcap via `contrib/pcap-to-fixture.py` — this file is no longer used directly; the live fixture lives at `build/_dell-monitor-rt-emu/u4025qw-emulation.zip`. |

## Critical: always regenerate the fixture before running

The committed `u4025qw-emulation.zip` is a **historical snapshot kept for
reference only**. The specializer (`contrib/pcap-to-fixture.py`) evolves
alongside the plugin (Report-ID prefix handling, phase split at `0xE9`,
structural-event propagation into `install.json` head, stable Created
timestamps to keep phase matching stable…). Each plugin change can
invalidate the cached fixture, so the dev-shell command always
regenerates from the pcap when the pcap or the specializer is newer
than the cached fixture under `build/_dell-monitor-rt-emu/`.

If you ever see `failed to probe: no event with ID ReadProp:Key=HID_ID:
no events loaded` from `emulation-load`, you're running against a stale
fixture (or the committed one). Re-run `dell-monitor-rt-emu` so the
specializer rebuilds the fixture from the pcap.

## Why one is committed and the other isn't

Surveying the 38 `*-setup.json` fixtures committed across upstream
plugins:

- All are setup-phase only
- Largest is 18 KB
- Install testing uses a different mechanism: `data/device-tests/`
  recipes that reference setup fixtures via `@enumeration_datadir@/…`
  and describe the **expected outcome** of an install — not a
  byte-replay of recorded install events

Our use case is unusual because we're doing protocol bring-up: we
genuinely want to byte-replay an install so we can verify each new
piece of write_firmware code emits the right frames. That requires
the install/reload events, which for this device run to ~101 MB
uncompressed. Committing that to fwupd's tree wouldn't fly upstream,
so the full fixture stays local; only the small setup fixture matches
the `enumeration_data` convention and gets committed.

## Generating `u4025qw-emulation.zip` locally

The fixture is built from a real-monitor USB capture by
`contrib/pcap2emulation.py` (FuHidrawDevice output mode added in
plugin task #27, merged with the canonical `emulation-tag` capture in
plugin task #28). The source pcap lives in the
`dell-u4025qw-fw` companion repo at:

```
captures/u4025qw-update-recap-20260502-185321.pcapng
```

To regenerate (exact invocation TBD — `pcap2emulation.py`'s CLI is
still being shaped):

```bash
python3 contrib/pcap2emulation.py \
  --output FuHidrawDevice \
  --merge-setup ../dell-u4025qw-fw/canonical-setup.zip \
  ../dell-u4025qw-fw/captures/u4025qw-update-recap-20260502-185321.pcapng \
  -o plugins/dell-monitor-rt/tests/u4025qw-emulation.zip
```

## Anatomy of the full zip

```
u4025qw-emulation.zip
├── setup.json         2.5  KB  — 8 hidraw device entries, no events
└── install.json       101  MB  — same 8 device entries with the full
                                   update event stream
```

Eight hidraw `BackendId`s appear because Dell's binary cycles the
device through pre-bootloader / bootloader / post-bootloader states,
and each USB re-enumeration creates a fresh hidraw node:

| BackendId tail | Role | Writes | Notes |
|---|---|---|---|
| `0bda:1101.0034/hidraw52` | secondary MCU, pre-handshake | 4 | enumeration probes |
| `0bda:1100.0036/hidraw54` | primary MCU, firmware mode | 6,479 | initial inventory + setup |
| `0bda:1101.003D/hidraw61` | secondary MCU, firmware mode | 1,034 | **2× `0xE9` at events 1036, 1037** — bootloader-entry trigger for the secondary |
| `0bda:1100.003F/hidraw63` | primary MCU, firmware mode | 532 | **2× `0xE9` at events 536, 537** — bootloader-entry trigger for the primary |
| `0bda:1101.0044/hidraw68` | secondary, post-trigger | 3 | settles |
| `0bda:1100.0047/hidraw71` | **primary, BOOTLOADER mode** | **114,807** | the actual block-write phase — this is where ~2 MB of `.upg` payload streams in |
| `0bda:1101.0051/hidraw81` | secondary, post-flash | 4 | re-enumerated after primary reboots |
| `0bda:1100.0053/hidraw83` | primary, post-flash | 122 | final version reads |

The `0xE9` opcode is the bootloader-entry trigger we recovered from
the recap pcap (only 4 occurrences in 880k frames, all immediately
preceding a firmware → bootloader re-enumeration). Both MCUs receive
it twice each; the chip requires the duplicate as a debounce gate.

## Caveats for replay

The `BackendId`s embed HID instance suffixes (`1100.0036`, `1100.003F`,
…) and hidraw node numbers (`hidraw54`, `hidraw63`, `hidraw71`) that
were assigned the day of capture. **They will not match a freshly-
plugged device's `BackendId` today** (today's primary is `1100.0111
/hidraw2`).

`fu-backend.c:446` looks up by exact `BackendId`, so `emulation-load`
treats the fixture entries as 8 brand-new synthetic devices, adds
them all with `FWUPD_DEVICE_FLAG_EMULATED` set, and leaves the live
`/dev/hidrawN` alone (un-tagged). Whether the plugin attaches to a
synthetic emulated device or to the live one then depends on how the
device list dedupes by `InstanceId`.

The plugin keeps a safety guard at the top of `write_firmware` that
refuses to run if `FWUPD_DEVICE_FLAG_EMULATED` isn't set on the
device it's been handed. A mismatch cannot send writes to real
hardware — the install will abort with `FWUPD_ERROR_NOT_SUPPORTED`.

## Running the emulator

The flake dev shell exposes a convenience command:

```bash
nix develop
dell-monitor-rt-emu        # builds cab if missing, runs emulation-load
```

That handles cab assembly from the in-tree `.upg` + a synthetic
metainfo and points fwupdtool at the local zip.
