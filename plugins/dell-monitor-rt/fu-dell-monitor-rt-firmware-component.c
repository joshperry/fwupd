/*
 * Copyright 2026 Joshua Perry <josh@6bit.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "config.h"

#include "fu-dell-monitor-rt-firmware-component.h"

struct _FuDellMonitorRtFirmwareComponent {
	FuFirmware parent_instance;
	GBytes *key;
	gboolean panel_bound;
	GBytes *fields[FU_DELL_MONITOR_RT_FIRMWARE_COMPONENT_FIELDS];
};

G_DEFINE_TYPE(FuDellMonitorRtFirmwareComponent,
	      fu_dell_monitor_rt_firmware_component,
	      FU_TYPE_FIRMWARE)

FuDellMonitorRtFirmwareComponent *
fu_dell_monitor_rt_firmware_component_new(void)
{
	return g_object_new(FU_TYPE_DELL_MONITOR_RT_FIRMWARE_COMPONENT, NULL);
}

void
fu_dell_monitor_rt_firmware_component_set_key(FuDellMonitorRtFirmwareComponent *self, GBytes *key)
{
	g_return_if_fail(FU_IS_DELL_MONITOR_RT_FIRMWARE_COMPONENT(self));
	if (self->key != NULL)
		g_bytes_unref(self->key);
	self->key = key != NULL ? g_bytes_ref(key) : NULL;
}

GBytes *
fu_dell_monitor_rt_firmware_component_get_key(FuDellMonitorRtFirmwareComponent *self)
{
	g_return_val_if_fail(FU_IS_DELL_MONITOR_RT_FIRMWARE_COMPONENT(self), NULL);
	return self->key;
}

void
fu_dell_monitor_rt_firmware_component_set_panel_bound(FuDellMonitorRtFirmwareComponent *self,
						      gboolean panel_bound)
{
	g_return_if_fail(FU_IS_DELL_MONITOR_RT_FIRMWARE_COMPONENT(self));
	self->panel_bound = panel_bound;
}

gboolean
fu_dell_monitor_rt_firmware_component_get_panel_bound(FuDellMonitorRtFirmwareComponent *self)
{
	g_return_val_if_fail(FU_IS_DELL_MONITOR_RT_FIRMWARE_COMPONENT(self), FALSE);
	return self->panel_bound;
}

void
fu_dell_monitor_rt_firmware_component_set_field(FuDellMonitorRtFirmwareComponent *self,
						FuDellMonitorRtFirmwareField idx,
						GBytes *value)
{
	g_return_if_fail(FU_IS_DELL_MONITOR_RT_FIRMWARE_COMPONENT(self));
	g_return_if_fail((guint)idx < FU_DELL_MONITOR_RT_FIRMWARE_COMPONENT_FIELDS);
	if (self->fields[idx] != NULL)
		g_bytes_unref(self->fields[idx]);
	self->fields[idx] = value != NULL ? g_bytes_ref(value) : NULL;
}

GBytes *
fu_dell_monitor_rt_firmware_component_get_field(FuDellMonitorRtFirmwareComponent *self,
						FuDellMonitorRtFirmwareField idx)
{
	g_return_val_if_fail(FU_IS_DELL_MONITOR_RT_FIRMWARE_COMPONENT(self), NULL);
	g_return_val_if_fail((guint)idx < FU_DELL_MONITOR_RT_FIRMWARE_COMPONENT_FIELDS, NULL);
	return self->fields[idx];
}

/* Export key + raw field sizes for `fwupdtool firmware-dump` introspection. */
static void
fu_dell_monitor_rt_firmware_component_export(FuFirmware *firmware,
					     FuFirmwareExportFlags flags,
					     XbBuilderNode *bn)
{
	FuDellMonitorRtFirmwareComponent *self = FU_DELL_MONITOR_RT_FIRMWARE_COMPONENT(firmware);
	if (self->key != NULL)
		fu_xmlb_builder_insert_kx(bn, "key_size", g_bytes_get_size(self->key));
	fu_xmlb_builder_insert_kb(bn, "panel_bound", self->panel_bound);
	for (guint i = 0; i < FU_DELL_MONITOR_RT_FIRMWARE_COMPONENT_FIELDS; i++) {
		if (self->fields[i] == NULL)
			continue;
		g_autofree gchar *attr = g_strdup_printf("field_%02u_size", i);
		fu_xmlb_builder_insert_kx(bn, attr, g_bytes_get_size(self->fields[i]));
	}
}

static void
fu_dell_monitor_rt_firmware_component_finalize(GObject *object)
{
	FuDellMonitorRtFirmwareComponent *self = FU_DELL_MONITOR_RT_FIRMWARE_COMPONENT(object);
	if (self->key != NULL)
		g_bytes_unref(self->key);
	for (guint i = 0; i < FU_DELL_MONITOR_RT_FIRMWARE_COMPONENT_FIELDS; i++) {
		if (self->fields[i] != NULL)
			g_bytes_unref(self->fields[i]);
	}
	G_OBJECT_CLASS(fu_dell_monitor_rt_firmware_component_parent_class)->finalize(object);
}

static void
fu_dell_monitor_rt_firmware_component_init(FuDellMonitorRtFirmwareComponent *self)
{
}

static void
fu_dell_monitor_rt_firmware_component_class_init(FuDellMonitorRtFirmwareComponentClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS(klass);
	FuFirmwareClass *firmware_class = FU_FIRMWARE_CLASS(klass);
	object_class->finalize = fu_dell_monitor_rt_firmware_component_finalize;
	firmware_class->export = fu_dell_monitor_rt_firmware_component_export;
}
