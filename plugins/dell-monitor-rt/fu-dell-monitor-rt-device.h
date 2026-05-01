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
