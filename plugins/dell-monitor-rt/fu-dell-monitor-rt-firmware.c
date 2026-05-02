/*
 * Copyright 2026 Joshua Perry <josh@6bit.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "config.h"

#include "fu-dell-monitor-rt-firmware-component.h"
#include "fu-dell-monitor-rt-firmware.h"

/*
 * .upg container format (reverse-engineered from Dell's `Firmware Updater`
 * binary, FUN_001bfac0 etc., verified against U4025QW M3T105 and U3224KB
 * M2T105 samples). Everything uses big-endian length-prefixed encoding.
 *
 *   string      = u32 BE length || `length` bytes
 *   string_list = u32 BE count  || count × string
 *
 *   HEADER:
 *     string      magic           = "UPG"
 *     string      format_version  = "1.0.5" or "1.0.6"
 *     string      product         (e.g. "U4025QW", "Dell U3224KB")
 *     string      fw_version      (e.g. "M3T105")
 *     string_list name_table      (declared component names)
 *     string_list panel_bound     (subset keyed by encrypted panel_id)
 *
 *   COMPONENTS:
 *     u32 N = name_table.size + panel_bound.size
 *     for each of N:
 *       string    key             plaintext name OR encrypted panel_id
 *       string×17 fields          metadata, each Wistron@<product>-encrypted
 *
 *   BINARY:
 *     u32 M = N
 *     for each of M:
 *       string    key             matches one component's key
 *       bytes     payload         ECIES-encrypted gzip+hex firmware
 *
 *   (Optional Thunderbolt trailer after the binary section — not parsed.)
 *
 * The plaintext metadata fields and ECIES blob decryption are intentionally
 * NOT performed here; both depend on per-product passphrases / static keys
 * that are wired up by the device-side code in follow-up commits. This
 * parser is responsible only for slicing the .upg into its structural
 * pieces and exposing them as FuDellMonitorRtFirmwareComponent children.
 */

/* Bound-checks against pathological / malicious inputs. The largest field
 * we expect anywhere is the WEBCAM payload in the U3224KB bundle at ~10 MB,
 * so 64 MB is comfortably above legitimate use. Header strings and
 * metadata fields are bounded much tighter. */
#define FU_DELL_MONITOR_RT_FIRMWARE_MAX_HEADER_STRING 256
#define FU_DELL_MONITOR_RT_FIRMWARE_MAX_NAME_LIST     64
#define FU_DELL_MONITOR_RT_FIRMWARE_MAX_COMPONENTS    64
#define FU_DELL_MONITOR_RT_FIRMWARE_MAX_FIELD_SIZE    1024
#define FU_DELL_MONITOR_RT_FIRMWARE_MAX_PAYLOAD_SIZE  (64 * 1024 * 1024)

struct _FuDellMonitorRtFirmware {
	FuFirmware parent_instance;
	gchar *product;
	gchar *fw_version;
	GPtrArray *name_table;	/* element-type: gchar* */
	GPtrArray *panel_bound; /* element-type: gchar* */
};

G_DEFINE_TYPE(FuDellMonitorRtFirmware, fu_dell_monitor_rt_firmware, FU_TYPE_FIRMWARE)

const gchar *
fu_dell_monitor_rt_firmware_get_product(FuDellMonitorRtFirmware *self)
{
	g_return_val_if_fail(FU_IS_DELL_MONITOR_RT_FIRMWARE(self), NULL);
	return self->product;
}

const gchar *
fu_dell_monitor_rt_firmware_get_fw_version(FuDellMonitorRtFirmware *self)
{
	g_return_val_if_fail(FU_IS_DELL_MONITOR_RT_FIRMWARE(self), NULL);
	return self->fw_version;
}

GPtrArray *
fu_dell_monitor_rt_firmware_get_name_table(FuDellMonitorRtFirmware *self)
{
	g_return_val_if_fail(FU_IS_DELL_MONITOR_RT_FIRMWARE(self), NULL);
	return self->name_table;
}

GPtrArray *
fu_dell_monitor_rt_firmware_get_panel_bound(FuDellMonitorRtFirmware *self)
{
	g_return_val_if_fail(FU_IS_DELL_MONITOR_RT_FIRMWARE(self), NULL);
	return self->panel_bound;
}

/* Read a u32 BE length, validate it against `max`, then read that many
 * bytes from the stream. */
static GBytes *
fu_dell_monitor_rt_firmware_read_lp_bytes(GInputStream *stream,
					  gsize *offset,
					  gsize max,
					  GError **error)
{
	guint32 len = 0;
	GBytes *out = NULL;

	if (!fu_input_stream_read_u32(stream, *offset, &len, G_BIG_ENDIAN, error))
		return NULL;
	*offset += sizeof(guint32);
	if (len > max) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_FILE,
			    "length-prefixed value %u exceeds bound %" G_GSIZE_FORMAT
			    " at offset 0x%" G_GSIZE_MODIFIER "x",
			    len,
			    max,
			    *offset - sizeof(guint32));
		return NULL;
	}
	out = fu_input_stream_read_bytes(stream, *offset, len, NULL, error);
	if (out == NULL)
		return NULL;
	*offset += len;
	return out;
}

/* Read a length-prefixed string and return it as a NUL-terminated gchar*.
 * The on-disk strings are not NUL-terminated, so we copy. */
static gchar *
fu_dell_monitor_rt_firmware_read_lp_string(GInputStream *stream,
					   gsize *offset,
					   gsize max,
					   GError **error)
{
	g_autoptr(GBytes) bytes = NULL;
	gsize sz = 0;
	const gchar *data;

	bytes = fu_dell_monitor_rt_firmware_read_lp_bytes(stream, offset, max, error);
	if (bytes == NULL)
		return NULL;
	data = g_bytes_get_data(bytes, &sz);
	return g_strndup(data, sz);
}

/* Read a string list (u32 count + count strings) into the supplied
 * GPtrArray (must be created with g_free as the element-free fn). */
static gboolean
fu_dell_monitor_rt_firmware_read_lp_string_list(GInputStream *stream,
						gsize *offset,
						GPtrArray *out,
						GError **error)
{
	guint32 n = 0;

	if (!fu_input_stream_read_u32(stream, *offset, &n, G_BIG_ENDIAN, error))
		return FALSE;
	*offset += sizeof(guint32);
	if (n > FU_DELL_MONITOR_RT_FIRMWARE_MAX_NAME_LIST) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_FILE,
			    "string list count %u exceeds bound %u at offset 0x%" G_GSIZE_MODIFIER
			    "x",
			    n,
			    (guint)FU_DELL_MONITOR_RT_FIRMWARE_MAX_NAME_LIST,
			    *offset - sizeof(guint32));
		return FALSE;
	}
	for (guint32 i = 0; i < n; i++) {
		gchar *s = fu_dell_monitor_rt_firmware_read_lp_string(
		    stream,
		    offset,
		    FU_DELL_MONITOR_RT_FIRMWARE_MAX_HEADER_STRING,
		    error);
		if (s == NULL)
			return FALSE;
		g_ptr_array_add(out, s);
	}
	return TRUE;
}

/* Decide whether `key` is a plaintext name from the container's name
 * table (vs. an encrypted Base64URL panel_id). Plaintext keys round-trip
 * back to a name that appears in name_table; encrypted ones don't. */
static gboolean
fu_dell_monitor_rt_firmware_key_is_plaintext_name(GBytes *key, GPtrArray *name_table)
{
	gsize sz = 0;
	const gchar *data = g_bytes_get_data(key, &sz);

	for (guint i = 0; i < name_table->len; i++) {
		const gchar *name = g_ptr_array_index(name_table, i);
		if (strlen(name) == sz && memcmp(name, data, sz) == 0)
			return TRUE;
	}
	return FALSE;
}

/* Lightweight pre-parse magic check used by the firmware-format detector. */
static gboolean
fu_dell_monitor_rt_firmware_validate(FuFirmware *firmware,
				     GInputStream *stream,
				     gsize offset,
				     GError **error)
{
	guint32 magic_len = 0;
	g_autofree gchar *magic = NULL;

	if (!fu_input_stream_read_u32(stream, offset, &magic_len, G_BIG_ENDIAN, error))
		return FALSE;
	if (magic_len != 3) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_FILE,
			    "expected magic length 3, got %u",
			    magic_len);
		return FALSE;
	}
	magic = fu_input_stream_read_string(stream, offset + sizeof(guint32), 3, error);
	if (magic == NULL)
		return FALSE;
	if (g_strcmp0(magic, "UPG") != 0) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_FILE,
			    "bad magic '%s', expected 'UPG'",
			    magic);
		return FALSE;
	}
	return TRUE;
}

static gboolean
fu_dell_monitor_rt_firmware_parse(FuFirmware *firmware,
				  GInputStream *stream,
				  FuFirmwareParseFlags flags,
				  GError **error)
{
	FuDellMonitorRtFirmware *self = FU_DELL_MONITOR_RT_FIRMWARE(firmware);
	gsize offset = 0;
	g_autofree gchar *magic = NULL;
	g_autofree gchar *fmt = NULL;
	guint32 component_count = 0;
	guint32 binary_count = 0;
	g_autoptr(GHashTable) components_by_key =
	    g_hash_table_new_full(g_bytes_hash, g_bytes_equal, (GDestroyNotify)g_bytes_unref, NULL);

	/* Header: 4 length-prefixed strings. */
	magic = fu_dell_monitor_rt_firmware_read_lp_string(
	    stream,
	    &offset,
	    FU_DELL_MONITOR_RT_FIRMWARE_MAX_HEADER_STRING,
	    error);
	if (magic == NULL)
		return FALSE;
	if (g_strcmp0(magic, "UPG") != 0) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_FILE,
			    "bad magic '%s', expected 'UPG'",
			    magic);
		return FALSE;
	}
	fmt = fu_dell_monitor_rt_firmware_read_lp_string(
	    stream,
	    &offset,
	    FU_DELL_MONITOR_RT_FIRMWARE_MAX_HEADER_STRING,
	    error);
	if (fmt == NULL)
		return FALSE;
	if (g_strcmp0(fmt, "1.0.5") != 0 && g_strcmp0(fmt, "1.0.6") != 0) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_FILE,
			    "unsupported .upg format version '%s' (want 1.0.5 or 1.0.6)",
			    fmt);
		return FALSE;
	}
	g_free(self->product);
	self->product = fu_dell_monitor_rt_firmware_read_lp_string(
	    stream,
	    &offset,
	    FU_DELL_MONITOR_RT_FIRMWARE_MAX_HEADER_STRING,
	    error);
	if (self->product == NULL)
		return FALSE;
	g_free(self->fw_version);
	self->fw_version = fu_dell_monitor_rt_firmware_read_lp_string(
	    stream,
	    &offset,
	    FU_DELL_MONITOR_RT_FIRMWARE_MAX_HEADER_STRING,
	    error);
	if (self->fw_version == NULL)
		return FALSE;

	/* Surface fw_version as the parent firmware's version string so
	 * `fwupdtool get-firmware <file>` shows it without extra plumbing. */
	fu_firmware_set_version(firmware, self->fw_version);

	/* Two string lists. */
	if (!fu_dell_monitor_rt_firmware_read_lp_string_list(stream,
							     &offset,
							     self->name_table,
							     error))
		return FALSE;
	if (!fu_dell_monitor_rt_firmware_read_lp_string_list(stream,
							     &offset,
							     self->panel_bound,
							     error))
		return FALSE;

	/* Components: u32 N + N × (key + 17 fields). */
	if (!fu_input_stream_read_u32(stream, offset, &component_count, G_BIG_ENDIAN, error))
		return FALSE;
	offset += sizeof(guint32);
	if (component_count > FU_DELL_MONITOR_RT_FIRMWARE_MAX_COMPONENTS) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_FILE,
			    "component count %u exceeds bound %u",
			    component_count,
			    (guint)FU_DELL_MONITOR_RT_FIRMWARE_MAX_COMPONENTS);
		return FALSE;
	}
	if (component_count != self->name_table->len + self->panel_bound->len) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_FILE,
			    "component count %u != name_table(%u) + panel_bound(%u)",
			    component_count,
			    self->name_table->len,
			    self->panel_bound->len);
		return FALSE;
	}
	for (guint32 i = 0; i < component_count; i++) {
		g_autoptr(FuDellMonitorRtFirmwareComponent) component =
		    fu_dell_monitor_rt_firmware_component_new();
		g_autoptr(GBytes) key = NULL;
		gboolean is_plaintext;

		key = fu_dell_monitor_rt_firmware_read_lp_bytes(
		    stream,
		    &offset,
		    FU_DELL_MONITOR_RT_FIRMWARE_MAX_FIELD_SIZE,
		    error);
		if (key == NULL)
			return FALSE;
		fu_dell_monitor_rt_firmware_component_set_key(component, key);
		is_plaintext =
		    fu_dell_monitor_rt_firmware_key_is_plaintext_name(key, self->name_table);
		fu_dell_monitor_rt_firmware_component_set_panel_bound(component, !is_plaintext);

		/* Set the FuFirmware id. For plaintext keys, the readable
		 * name. For panel-bound keys, a placeholder built from the
		 * component index since the key is opaque ciphertext until
		 * the device-side passphrase decrypts it. */
		if (is_plaintext) {
			gsize key_sz = 0;
			const gchar *key_data = g_bytes_get_data(key, &key_sz);
			g_autofree gchar *id = g_strndup(key_data, key_sz);
			fu_firmware_set_id(FU_FIRMWARE(component), id);
		} else {
			g_autofree gchar *id = g_strdup_printf("panel-bound-%u", i);
			fu_firmware_set_id(FU_FIRMWARE(component), id);
		}
		fu_firmware_set_idx(FU_FIRMWARE(component), i);

		/* 17 raw (still-encrypted) metadata fields. */
		for (guint j = 0; j < FU_DELL_MONITOR_RT_FIRMWARE_COMPONENT_FIELDS; j++) {
			g_autoptr(GBytes) field = NULL;
			field = fu_dell_monitor_rt_firmware_read_lp_bytes(
			    stream,
			    &offset,
			    FU_DELL_MONITOR_RT_FIRMWARE_MAX_FIELD_SIZE,
			    error);
			if (field == NULL)
				return FALSE;
			fu_dell_monitor_rt_firmware_component_set_field(component, j, field);
		}

		/* Index by raw key for the binary-section pairing pass. */
		g_hash_table_insert(components_by_key,
				    g_bytes_ref(key),
				    component); /* hash table holds borrowed ptr */
		if (!fu_firmware_add_image(firmware, FU_FIRMWARE(component), error))
			return FALSE;
	}

	/* Binary section: u32 M + M × (key + payload). */
	if (!fu_input_stream_read_u32(stream, offset, &binary_count, G_BIG_ENDIAN, error))
		return FALSE;
	offset += sizeof(guint32);
	if (binary_count != component_count) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_FILE,
			    "binary count %u != component count %u",
			    binary_count,
			    component_count);
		return FALSE;
	}
	for (guint32 i = 0; i < binary_count; i++) {
		g_autoptr(GBytes) key = NULL;
		g_autoptr(GBytes) payload = NULL;
		FuDellMonitorRtFirmwareComponent *component;

		key = fu_dell_monitor_rt_firmware_read_lp_bytes(
		    stream,
		    &offset,
		    FU_DELL_MONITOR_RT_FIRMWARE_MAX_FIELD_SIZE,
		    error);
		if (key == NULL)
			return FALSE;
		payload = fu_dell_monitor_rt_firmware_read_lp_bytes(
		    stream,
		    &offset,
		    FU_DELL_MONITOR_RT_FIRMWARE_MAX_PAYLOAD_SIZE,
		    error);
		if (payload == NULL)
			return FALSE;
		component = g_hash_table_lookup(components_by_key, key);
		if (component == NULL) {
			g_set_error(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_INVALID_FILE,
				    "binary entry %u has key with no matching component",
				    i);
			return FALSE;
		}
		fu_firmware_set_bytes(FU_FIRMWARE(component), payload);
	}

	/* The TBT trailer (if present) is intentionally not consumed. */
	return TRUE;
}

static gchar *
fu_dell_monitor_rt_firmware_join_ptr_array(GPtrArray *strings)
{
	g_autoptr(GString) joined = g_string_new(NULL);
	for (guint i = 0; i < strings->len; i++) {
		if (i > 0)
			g_string_append_c(joined, ',');
		g_string_append(joined, (const gchar *)g_ptr_array_index(strings, i));
	}
	return g_string_free(g_steal_pointer(&joined), FALSE);
}

static void
fu_dell_monitor_rt_firmware_export(FuFirmware *firmware,
				   FuFirmwareExportFlags flags,
				   XbBuilderNode *bn)
{
	FuDellMonitorRtFirmware *self = FU_DELL_MONITOR_RT_FIRMWARE(firmware);
	if (self->product != NULL)
		fu_xmlb_builder_insert_kv(bn, "product", self->product);
	if (self->fw_version != NULL)
		fu_xmlb_builder_insert_kv(bn, "fw_version", self->fw_version);
	if (self->name_table->len > 0) {
		g_autofree gchar *joined =
		    fu_dell_monitor_rt_firmware_join_ptr_array(self->name_table);
		fu_xmlb_builder_insert_kv(bn, "name_table", joined);
	}
	if (self->panel_bound->len > 0) {
		g_autofree gchar *joined =
		    fu_dell_monitor_rt_firmware_join_ptr_array(self->panel_bound);
		fu_xmlb_builder_insert_kv(bn, "panel_bound", joined);
	}
}

static void
fu_dell_monitor_rt_firmware_finalize(GObject *object)
{
	FuDellMonitorRtFirmware *self = FU_DELL_MONITOR_RT_FIRMWARE(object);
	g_free(self->product);
	g_free(self->fw_version);
	g_ptr_array_unref(self->name_table);
	g_ptr_array_unref(self->panel_bound);
	G_OBJECT_CLASS(fu_dell_monitor_rt_firmware_parent_class)->finalize(object);
}

static void
fu_dell_monitor_rt_firmware_init(FuDellMonitorRtFirmware *self)
{
	self->name_table = g_ptr_array_new_with_free_func(g_free);
	self->panel_bound = g_ptr_array_new_with_free_func(g_free);
}

static void
fu_dell_monitor_rt_firmware_class_init(FuDellMonitorRtFirmwareClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS(klass);
	FuFirmwareClass *firmware_class = FU_FIRMWARE_CLASS(klass);
	object_class->finalize = fu_dell_monitor_rt_firmware_finalize;
	firmware_class->validate = fu_dell_monitor_rt_firmware_validate;
	firmware_class->parse = fu_dell_monitor_rt_firmware_parse;
	firmware_class->export = fu_dell_monitor_rt_firmware_export;
}
