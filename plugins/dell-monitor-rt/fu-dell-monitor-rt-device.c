/*
 * Copyright 2026 Joshua Perry <josh@6bit.com>
 * Copyright 2026 Ada <ada@6bit.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "config.h"

#include "fu-dell-monitor-rt-device.h"

struct _FuDellMonitorRtDevice {
	FuHidDevice parent_instance;
};

G_DEFINE_TYPE(FuDellMonitorRtDevice, fu_dell_monitor_rt_device, FU_TYPE_HID_DEVICE)

static gboolean
fu_dell_monitor_rt_device_probe(FuDevice *device, GError **error)
{
	g_debug("dell-monitor-rt: probe %s", fu_device_get_name(device));
	return TRUE;
}

static gboolean
fu_dell_monitor_rt_device_setup(FuDevice *device, GError **error)
{
	g_debug("dell-monitor-rt: setup %s", fu_device_get_name(device));

	/* TODO: send opcode 0x10 (hid_fwGetVersion) and populate
	 * fu_device_set_version() with the M3T1xx string returned by
	 * the monitor. */
	fu_device_set_version(device, "0.0.0-skeleton");

	return TRUE;
}

static void
fu_dell_monitor_rt_device_init(FuDellMonitorRtDevice *self)
{
	fu_device_set_vendor(FU_DEVICE(self), "Dell");
	fu_device_add_protocol(FU_DEVICE(self), "com.dell.monitor.rt");
	fu_device_set_summary(FU_DEVICE(self),
			      "Dell monitor with RealTek scaler (Wistron ISP)");
	fu_device_add_flag(FU_DEVICE(self), FWUPD_DEVICE_FLAG_UPDATABLE);
	fu_device_set_remove_delay(FU_DEVICE(self), 60 * 1000); /* 60 s for re-enum */
}

static void
fu_dell_monitor_rt_device_class_init(FuDellMonitorRtDeviceClass *klass)
{
	FuDeviceClass *device_class = FU_DEVICE_CLASS(klass);
	device_class->probe = fu_dell_monitor_rt_device_probe;
	device_class->setup = fu_dell_monitor_rt_device_setup;
}
