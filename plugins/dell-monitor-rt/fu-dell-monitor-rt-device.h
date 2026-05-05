/*
 * Copyright 2026 Joshua Perry <josh@6bit.com>
 * Copyright 2026 Ada <ada@6bit.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#pragma once

#include <fwupdplugin.h>

#define FU_TYPE_DELL_MONITOR_RT_DEVICE (fu_dell_monitor_rt_device_get_type())
G_DECLARE_FINAL_TYPE(FuDellMonitorRtDevice,
		     fu_dell_monitor_rt_device,
		     FU,
		     DELL_MONITOR_RT_DEVICE,
		     FuHidrawDevice)

/* Stage a 64 KB or 128 KB ISP shim into the device's RAM via opcode
 * 0xC8 (host-to-device firmware staging). Used cross-device by the
 * primary HID-A's write_firmware to stage HUB4 onto the secondary
 * HID-B child. Caller-visible so the plugin can drive it without
 * needing to subclass; size must be a multiple of 64 KB (256 frames
 * per 64 KB block). */
gboolean
fu_dell_monitor_rt_device_stage_isp_firmware(FuDellMonitorRtDevice *self,
					     GBytes *blob,
					     FuProgress *progress,
					     GError **error);

/* Send the 0xE9 bootloader-entry trigger pair. The chip drops its
 * firmware-mode hidraw interface immediately after acking the second
 * write, so no further IO can be performed on this fd after this
 * returns successfully. */
gboolean
fu_dell_monitor_rt_device_enter_bootloader(FuDellMonitorRtDevice *self,
					   GError **error);
