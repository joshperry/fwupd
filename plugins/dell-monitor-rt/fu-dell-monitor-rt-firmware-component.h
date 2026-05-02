/*
 * Copyright 2026 Joshua Perry <josh@6bit.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#pragma once

#include <fwupdplugin.h>

#define FU_TYPE_DELL_MONITOR_RT_FIRMWARE_COMPONENT                                                 \
	(fu_dell_monitor_rt_firmware_component_get_type())
G_DECLARE_FINAL_TYPE(FuDellMonitorRtFirmwareComponent,
		     fu_dell_monitor_rt_firmware_component,
		     FU,
		     DELL_MONITOR_RT_FIRMWARE_COMPONENT,
		     FuFirmware)

/* Number of metadata fields per component, fixed by Dell's schema (a
 * hardcoded 18-call read in firmware-updater's FUN_001bfac0 — 1 key +
 * 17 fields). */
#define FU_DELL_MONITOR_RT_FIRMWARE_COMPONENT_FIELDS 17

/* Stable indices into the field array. Field meaning is positional
 * across all components; an unused slot for a given component is the
 * encrypted form of the literal string "0". */
typedef enum {
	FU_DELL_MONITOR_RT_FIRMWARE_FIELD_PRODUCT = 0,	      /* "U4025QW" */
	FU_DELL_MONITOR_RT_FIRMWARE_FIELD_VERSION = 1,	      /* "1.04", "M3T105" */
	FU_DELL_MONITOR_RT_FIRMWARE_FIELD_BUILD_DATE = 2,     /* "YYYY-MM-DD" */
	FU_DELL_MONITOR_RT_FIRMWARE_FIELD_CRC16 = 3,	      /* 4-char hex */
	FU_DELL_MONITOR_RT_FIRMWARE_FIELD_CHIP_GUID = 4,      /* primary chip-type GUID */
	FU_DELL_MONITOR_RT_FIRMWARE_FIELD_CHIP_GUID_ALT = 5,  /* secondary chip-type GUID */
	FU_DELL_MONITOR_RT_FIRMWARE_FIELD_USB_VID = 6,	      /* "0x0bda" */
	FU_DELL_MONITOR_RT_FIRMWARE_FIELD_USB_PID = 7,	      /* "0x1100" */
	FU_DELL_MONITOR_RT_FIRMWARE_FIELD_I2C_OR_INDEX = 8,   /* "0xD4", index, etc. */
	FU_DELL_MONITOR_RT_FIRMWARE_FIELD_PARAM9 = 9,
	FU_DELL_MONITOR_RT_FIRMWARE_FIELD_PARAM10 = 10,
	FU_DELL_MONITOR_RT_FIRMWARE_FIELD_PARAM11 = 11,
	FU_DELL_MONITOR_RT_FIRMWARE_FIELD_PARAM12 = 12,
	FU_DELL_MONITOR_RT_FIRMWARE_FIELD_PARAM13 = 13,
	FU_DELL_MONITOR_RT_FIRMWARE_FIELD_PARAM14 = 14,
	FU_DELL_MONITOR_RT_FIRMWARE_FIELD_FLASH_OFF_OR_SIZE = 15,
	FU_DELL_MONITOR_RT_FIRMWARE_FIELD_FLASH_SIZE_OR_END = 16,
} FuDellMonitorRtFirmwareField;

/* Construction (used by the container parser). */
FuDellMonitorRtFirmwareComponent *
fu_dell_monitor_rt_firmware_component_new(void);

/* Set the on-disk key for this component. May be either a plaintext
 * ASCII name (e.g. "HUB", "HUB1", "DISPLAY") or a Base64URL string
 * carrying an encrypted panel_id — the caller is responsible for
 * deciding which based on whether the bytes match a name in the
 * container's name_table. */
void
fu_dell_monitor_rt_firmware_component_set_key(FuDellMonitorRtFirmwareComponent *self,
					      GBytes *key);
GBytes *
fu_dell_monitor_rt_firmware_component_get_key(FuDellMonitorRtFirmwareComponent *self);

/* Mark this component as panel-bound (key is an encrypted panel_id
 * rather than a plaintext component name). */
void
fu_dell_monitor_rt_firmware_component_set_panel_bound(FuDellMonitorRtFirmwareComponent *self,
						      gboolean panel_bound);
gboolean
fu_dell_monitor_rt_firmware_component_get_panel_bound(FuDellMonitorRtFirmwareComponent *self);

/* Set/get one of the 17 raw (still-encrypted) metadata fields by index. */
void
fu_dell_monitor_rt_firmware_component_set_field(FuDellMonitorRtFirmwareComponent *self,
						FuDellMonitorRtFirmwareField idx,
						GBytes *value);
GBytes *
fu_dell_monitor_rt_firmware_component_get_field(FuDellMonitorRtFirmwareComponent *self,
						FuDellMonitorRtFirmwareField idx);
