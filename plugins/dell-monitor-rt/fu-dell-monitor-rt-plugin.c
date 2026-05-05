/*
 * Copyright 2026 Joshua Perry <josh@6bit.com>
 * Copyright 2026 Ada <ada@6bit.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "config.h"

#include "fu-dell-monitor-rt-device.h"
#include "fu-dell-monitor-rt-firmware.h"
#include "fu-dell-monitor-rt-plugin.h"

struct _FuDellMonitorRtPlugin {
	FuPlugin parent_instance;
};

G_DEFINE_TYPE(FuDellMonitorRtPlugin, fu_dell_monitor_rt_plugin, FU_TYPE_PLUGIN)

/*
 * Pair the primary HID-A (DEV_1100) with the secondary HID-B (DEV_1101)
 * as parent/child so the primary's write_firmware can reach the
 * secondary's hidraw fd to stage HUB4. Each U4025QW exposes both
 * interfaces; the quirk matches both, but only the primary is
 * user-visible (the secondary is updatable-hidden).
 *
 * Pairing key is (vendor 0x0BDA, EMULATED-flag-state). Real-hardware
 * devices have distinct USB sysfs paths (the two chips sit on
 * different downstream ports of an internal hub) and so do their
 * synthetic counterparts (pcap2emulation gives each captured USB
 * device its own platform-id), which rules out pairing by shared
 * sysfs prefix. The flag part of the key keeps real and emulated
 * devices in separate buckets so a real primary doesn't accidentally
 * pair with a synthetic secondary when an emulation fixture is loaded
 * on top of live hardware.
 *
 * This assumes one monitor per (vendor, flag-state) bucket — which
 * is fine for the U4025QW today; if multi-monitor support is ever
 * needed, the pairing key would need a per-monitor discriminator.
 */
static void
fu_dell_monitor_rt_plugin_device_registered(FuPlugin *plugin, FuDevice *device)
{
	g_autofree gchar *cache_key = NULL;
	guint16 pid;
	guint16 partner_pid;
	gboolean emulated;
	FuDevice *partner;

	if (!FU_IS_DELL_MONITOR_RT_DEVICE(device))
		return;
	pid = fu_device_get_pid(device);
	if (pid != 0x1100 && pid != 0x1101)
		return;
	/* Skip if already paired — fu_device_add_child fires the added
	 * signal recursively, which would re-enter device_registered for
	 * the secondary in an infinite loop. */
	{
		GPtrArray *children = fu_device_get_children(device);
		g_autoptr(FuDevice) existing_parent = fu_device_get_parent(device, NULL);
		if (existing_parent != NULL ||
		    (children != NULL && children->len > 0)) {
			return;
		}
	}
	partner_pid = (pid == 0x1100) ? 0x1101 : 0x1100;
	emulated = fu_device_has_flag(device, FWUPD_DEVICE_FLAG_EMULATED);

	cache_key = g_strdup_printf("dell-monitor-rt:emul=%u:0x%04x",
				    emulated ? 1u : 0u,
				    partner_pid);
	partner = fu_plugin_cache_lookup(plugin, cache_key);
	if (partner != NULL) {
		FuDevice *primary = (pid == 0x1100) ? device : partner;
		FuDevice *secondary = (pid == 0x1100) ? partner : device;
		fu_device_add_child(primary, secondary);
		g_info("dell-monitor-rt: paired primary %s with secondary %s",
		       fu_device_get_id(primary),
		       fu_device_get_id(secondary));
		fu_plugin_cache_remove(plugin, cache_key);
	} else {
		g_autofree gchar *self_key =
		    g_strdup_printf("dell-monitor-rt:emul=%u:0x%04x",
				    emulated ? 1u : 0u,
				    pid);
		fu_plugin_cache_add(plugin, self_key, device);
		g_debug("dell-monitor-rt: cached %s under %s, awaiting partner",
			fu_device_get_id(device), self_key);
	}
}

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
	fu_plugin_add_firmware_gtype(plugin, FU_TYPE_DELL_MONITOR_RT_FIRMWARE);

	/* chain up to parent */
	G_OBJECT_CLASS(fu_dell_monitor_rt_plugin_parent_class)->constructed(obj);
}

static void
fu_dell_monitor_rt_plugin_class_init(FuDellMonitorRtPluginClass *klass)
{
	FuPluginClass *plugin_class = FU_PLUGIN_CLASS(klass);
	plugin_class->constructed = fu_dell_monitor_rt_plugin_constructed;
	plugin_class->device_registered = fu_dell_monitor_rt_plugin_device_registered;
}
