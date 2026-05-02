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
	gchar *panel_id; /* decrypted form of `key`, or NULL */
	gboolean panel_bound;
	GBytes *fields[FU_DELL_MONITOR_RT_FIRMWARE_COMPONENT_FIELDS];
	gchar *fields_str[FU_DELL_MONITOR_RT_FIRMWARE_COMPONENT_FIELDS];
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

void
fu_dell_monitor_rt_firmware_component_set_field_string(FuDellMonitorRtFirmwareComponent *self,
						       FuDellMonitorRtFirmwareField idx,
						       const gchar *value)
{
	g_return_if_fail(FU_IS_DELL_MONITOR_RT_FIRMWARE_COMPONENT(self));
	g_return_if_fail((guint)idx < FU_DELL_MONITOR_RT_FIRMWARE_COMPONENT_FIELDS);
	g_free(self->fields_str[idx]);
	self->fields_str[idx] = g_strdup(value);
}

const gchar *
fu_dell_monitor_rt_firmware_component_get_field_string(FuDellMonitorRtFirmwareComponent *self,
						       FuDellMonitorRtFirmwareField idx)
{
	g_return_val_if_fail(FU_IS_DELL_MONITOR_RT_FIRMWARE_COMPONENT(self), NULL);
	g_return_val_if_fail((guint)idx < FU_DELL_MONITOR_RT_FIRMWARE_COMPONENT_FIELDS, NULL);
	return self->fields_str[idx];
}

void
fu_dell_monitor_rt_firmware_component_set_panel_id(FuDellMonitorRtFirmwareComponent *self,
						   const gchar *panel_id)
{
	g_return_if_fail(FU_IS_DELL_MONITOR_RT_FIRMWARE_COMPONENT(self));
	g_free(self->panel_id);
	self->panel_id = g_strdup(panel_id);
}

const gchar *
fu_dell_monitor_rt_firmware_component_get_panel_id(FuDellMonitorRtFirmwareComponent *self)
{
	g_return_val_if_fail(FU_IS_DELL_MONITOR_RT_FIRMWARE_COMPONENT(self), NULL);
	return self->panel_id;
}

/* Field-name labels used in the `firmware-parse` XML dump. Order matches
 * FuDellMonitorRtFirmwareField. */
static const gchar *const fu_dell_monitor_rt_firmware_field_labels[] = {
    "product",	   "version",	   "build_date",	  "crc16",   "chip_guid",
    "chip_guid_alt", "usb_vid",	   "usb_pid",		  "i2c_or_index", "param09",
    "param10",	   "param11",	   "param12",		  "param13", "param14",
    "flash_off_or_size",
    "flash_size_or_end",
};

G_STATIC_ASSERT(G_N_ELEMENTS(fu_dell_monitor_rt_firmware_field_labels) ==
		FU_DELL_MONITOR_RT_FIRMWARE_COMPONENT_FIELDS);

static void
fu_dell_monitor_rt_firmware_component_export(FuFirmware *firmware,
					     FuFirmwareExportFlags flags,
					     XbBuilderNode *bn)
{
	FuDellMonitorRtFirmwareComponent *self = FU_DELL_MONITOR_RT_FIRMWARE_COMPONENT(firmware);
	if (self->key != NULL)
		fu_xmlb_builder_insert_kx(bn, "key_size", g_bytes_get_size(self->key));
	fu_xmlb_builder_insert_kb(bn, "panel_bound", self->panel_bound);
	if (self->panel_id != NULL)
		fu_xmlb_builder_insert_kv(bn, "panel_id", self->panel_id);
	for (guint i = 0; i < FU_DELL_MONITOR_RT_FIRMWARE_COMPONENT_FIELDS; i++) {
		if (self->fields_str[i] != NULL) {
			fu_xmlb_builder_insert_kv(bn,
						  fu_dell_monitor_rt_firmware_field_labels[i],
						  self->fields_str[i]);
		} else if (self->fields[i] != NULL) {
			g_autofree gchar *attr =
			    g_strdup_printf("%s_size", fu_dell_monitor_rt_firmware_field_labels[i]);
			fu_xmlb_builder_insert_kx(bn, attr, g_bytes_get_size(self->fields[i]));
		}
	}
}

static void
fu_dell_monitor_rt_firmware_component_finalize(GObject *object)
{
	FuDellMonitorRtFirmwareComponent *self = FU_DELL_MONITOR_RT_FIRMWARE_COMPONENT(object);
	if (self->key != NULL)
		g_bytes_unref(self->key);
	g_free(self->panel_id);
	for (guint i = 0; i < FU_DELL_MONITOR_RT_FIRMWARE_COMPONENT_FIELDS; i++) {
		if (self->fields[i] != NULL)
			g_bytes_unref(self->fields[i]);
		g_free(self->fields_str[i]);
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
