/*
 * Copyright 2026 Joshua Perry <josh@6bit.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#pragma once

#include <fwupdplugin.h>

#define FU_TYPE_DELL_MONITOR_RT_FIRMWARE (fu_dell_monitor_rt_firmware_get_type())
G_DECLARE_FINAL_TYPE(FuDellMonitorRtFirmware,
		     fu_dell_monitor_rt_firmware,
		     FU,
		     DELL_MONITOR_RT_FIRMWARE,
		     FuFirmware)

/* Header accessors. The four header strings are stored on the parent
 * FuFirmware as id/version (fw_version) and via dedicated getters for
 * the Wistron-specific fields. */
const gchar *
fu_dell_monitor_rt_firmware_get_product(FuDellMonitorRtFirmware *self);
const gchar *
fu_dell_monitor_rt_firmware_get_fw_version(FuDellMonitorRtFirmware *self);

/* The two declared name lists. Each is a GPtrArray<gchar*>. */
GPtrArray *
fu_dell_monitor_rt_firmware_get_name_table(FuDellMonitorRtFirmware *self);
GPtrArray *
fu_dell_monitor_rt_firmware_get_panel_bound(FuDellMonitorRtFirmware *self);
