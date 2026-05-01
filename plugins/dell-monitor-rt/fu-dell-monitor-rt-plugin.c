/*
 * Copyright 2026 Joshua Perry <josh@6bit.com>
 * Copyright 2026 Ada <ada@6bit.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "config.h"

#include "fu-dell-monitor-rt-device.h"
#include "fu-dell-monitor-rt-plugin.h"

struct _FuDellMonitorRtPlugin {
	FuPlugin parent_instance;
};

G_DEFINE_TYPE(FuDellMonitorRtPlugin, fu_dell_monitor_rt_plugin, FU_TYPE_PLUGIN)

static void
fu_dell_monitor_rt_plugin_init(FuDellMonitorRtPlugin *self)
{
}

static void
fu_dell_monitor_rt_plugin_constructed(GObject *obj)
{
	FuPlugin *plugin = FU_PLUGIN(obj);
	fu_plugin_add_udev_subsystem(plugin, "hidraw");
	fu_plugin_add_device_gtype(plugin, FU_TYPE_DELL_MONITOR_RT_DEVICE);

	/* chain up to parent */
	G_OBJECT_CLASS(fu_dell_monitor_rt_plugin_parent_class)->constructed(obj);
}

static void
fu_dell_monitor_rt_plugin_class_init(FuDellMonitorRtPluginClass *klass)
{
	FuPluginClass *plugin_class = FU_PLUGIN_CLASS(klass);
	plugin_class->constructed = fu_dell_monitor_rt_plugin_constructed;
}
