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
 * The pairing key is the shared USB device path: both BackendIds share
 * the same `/sys/devices/.../usb<N>/<path>/<path>:1.0/` prefix, so we
 * match by stripping the trailing HID instance directory and the
 * hidraw node, then comparing.
 *
 * Called once for each device at registration time. The first call
 * caches the device into the plugin's per-PID cache; the second call
 * sees the partner already cached and wires up the parent/child link.
 */
static gchar *
fu_dell_monitor_rt_plugin_usb_interface_path(FuDevice *device)
{
	const gchar *backend_id = fu_device_get_backend_id(device);
	g_autofree gchar *parent = NULL;
	const gchar *p;

	if (backend_id == NULL)
		return NULL;
	/* Strip the /hidraw/hidrawNN suffix → leaves the HID instance dir.
	 * Example:
	 *   /sys/.../usb3/3-1/3-1:1.0/0003:0BDA:1100.0036/hidraw/hidraw54
	 *   ↓ strip "/hidraw/hidraw54"
	 *   /sys/.../usb3/3-1/3-1:1.0/0003:0BDA:1100.0036
	 * Then strip the HID instance dir to get the USB interface path:
	 *   /sys/.../usb3/3-1/3-1:1.0
	 */
	parent = g_path_get_dirname(backend_id);
	p = strrchr(parent, '/');
	if (p == NULL)
		return NULL;
	parent = g_strndup(parent, p - parent);
	p = strrchr(parent, '/');
	if (p == NULL)
		return NULL;
	return g_strndup(parent, p - parent);
}

static void
fu_dell_monitor_rt_plugin_device_registered(FuPlugin *plugin, FuDevice *device)
{
	g_autofree gchar *iface_path = NULL;
	g_autofree gchar *cache_key = NULL;
	guint16 pid;
	guint16 partner_pid;
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
	g_debug("dell-monitor-rt: device_registered pid=0x%04x backend=%s",
		(unsigned)pid,
		fu_device_get_backend_id(device));

	iface_path = fu_dell_monitor_rt_plugin_usb_interface_path(device);
	if (iface_path == NULL) {
		g_debug("dell-monitor-rt: cannot derive USB interface path from BackendId %s",
			fu_device_get_backend_id(device));
		return;
	}

	cache_key = g_strdup_printf("dell-monitor-rt:%s:0x%04x", iface_path, partner_pid);
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
		    g_strdup_printf("dell-monitor-rt:%s:0x%04x", iface_path, pid);
		fu_plugin_cache_add(plugin, self_key, device);
		g_debug("dell-monitor-rt: cached %s under %s, awaiting partner",
			fu_device_get_id(device),
			self_key);
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
