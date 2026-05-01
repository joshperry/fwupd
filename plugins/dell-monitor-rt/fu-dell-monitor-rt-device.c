/*
 * Copyright 2026 Joshua Perry <josh@6bit.com>
 * Copyright 2026 Ada <ada@6bit.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "config.h"

#include <sys/ioctl.h>
#include <linux/hidraw.h>

#include "fu-dell-monitor-rt-device.h"

/*
 * Wire format (verified against captured pcap of Dell's own updater
 * talking to the same monitor; see PLUGIN_NOTES §"Wire format"):
 *
 *   byte 0     direction      0x40 = WRITE   / 0xC0 = READ
 *   byte 1     opcode         (see DELL_MONITOR_RT_OPCODE_* below)
 *   byte 2     subcmd         (command-specific)
 *   byte 3     arg            (command-specific, often zero)
 *   bytes 4+   payload        (command-specific, including any "auth"
 *                              bytes such as enable_vdcmd's RealTek
 *                              vendor ID 0x0BDA, or response-format
 *                              hints, or firmware data for SRAM_WRITE)
 *
 * Sent as a HID Output Report (kernel HID stack issues the SET_REPORT
 * class control transfer) with a fixed 192-byte size.  When write(2)-ing
 * to /dev/hidrawN, byte 0 of the buffer is the Report ID — this device
 * declares no Report ID, so byte 0 is always 0x00 and the 192 actual
 * report bytes follow, giving a 193-byte transfer.
 */

#define DELL_MONITOR_RT_REPORT_SIZE  192
#define DELL_MONITOR_RT_BUF_SIZE     (1 + DELL_MONITOR_RT_REPORT_SIZE) /* report-ID prefix */

#define DELL_MONITOR_RT_DIR_WRITE    0x40
#define DELL_MONITOR_RT_DIR_READ     0xC0

#define DELL_MONITOR_RT_OPCODE_ENABLE_VDCMD          0x02
#define DELL_MONITOR_RT_OPCODE_ENABLE_HIGH_CLOCK     0x06
#define DELL_MONITOR_RT_OPCODE_GET_FW_VERSION        0x09

/* enable_vdcmd's "you may have noticed I'm a vendor command" auth bytes,
 * placed in the payload at offset 0 (= wire byte 4). Decoded from the
 * RealTek vendor ID 0x0BDA stored little-endian in libdevices.so's
 * RTS5409S_HID::enable_vdcmd disassembly. */
#define DELL_MONITOR_RT_VENDOR_SIG_LO 0xDA
#define DELL_MONITOR_RT_VENDOR_SIG_HI 0x0B

struct _FuDellMonitorRtDevice {
	FuHidrawDevice parent_instance;
};

G_DEFINE_TYPE(FuDellMonitorRtDevice, fu_dell_monitor_rt_device, FU_TYPE_HIDRAW_DEVICE)

/*
 * Build the standard 192-byte vendor frame and write it to the device's
 * hidraw fd. Goes through the kernel hid-generic driver, which is what
 * Dell's hidapi-based binary uses too.
 *
 * The first byte of the buffer is the HID Report ID (always 0 for this
 * device — its descriptor declares no report IDs); the kernel strips
 * that on the way out so the wire payload is the 192 bytes that follow.
 */
static gboolean
fu_dell_monitor_rt_device_vcmd(FuDellMonitorRtDevice *self,
			       guint8 dir,
			       guint8 opcode,
			       guint8 subcmd,
			       guint8 arg,
			       const guint8 *payload,
			       gsize payload_len,
			       GError **error)
{
	guint8 buf[DELL_MONITOR_RT_BUF_SIZE] = {0};
	const gsize payload_max = DELL_MONITOR_RT_REPORT_SIZE - 4;

	if (payload_len > payload_max) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_DATA,
			    "vcmd payload too large: %" G_GSIZE_FORMAT " > %u",
			    payload_len,
			    (guint)payload_max);
		return FALSE;
	}

	/* buf[0] = HID Report ID (stays zero) */
	buf[1] = dir;
	buf[2] = opcode;
	buf[3] = subcmd;
	buf[4] = arg;
	if (payload != NULL && payload_len > 0)
		memcpy(buf + 5, payload, payload_len);

	fu_dump_raw(G_LOG_DOMAIN, "vcmd write", buf, sizeof(buf));

	return fu_hidraw_device_set_report(FU_HIDRAW_DEVICE(self),
					   buf,
					   sizeof(buf),
					   FU_IO_CHANNEL_FLAG_USE_BLOCKING_IO,
					   error);
}

/*
 * Send a READ-direction vcmd and pull the response with GET_REPORT
 * (HID INPUT report). The response buffer is 193 bytes including the
 * leading Report ID byte.
 */
static gboolean
fu_dell_monitor_rt_device_vcmd_read(FuDellMonitorRtDevice *self,
				    guint8 opcode,
				    guint8 subcmd,
				    guint8 arg,
				    const guint8 *payload,
				    gsize payload_len,
				    guint8 *response,
				    gsize response_len,
				    GError **error)
{
	if (!fu_dell_monitor_rt_device_vcmd(self,
					    DELL_MONITOR_RT_DIR_READ,
					    opcode,
					    subcmd,
					    arg,
					    payload,
					    payload_len,
					    error))
		return FALSE;

	/* Pull the response via HIDIOCGINPUT (HID class GET_REPORT for the
	 * INPUT report type) — the same ioctl hidapi's hid_get_input_report
	 * issues on Linux, which Dell's binary uses. fwupd's own
	 * fu_hidraw_device_get_report is a misnomer: it reads from the
	 * INPUT interrupt endpoint, not via GET_REPORT, and times out for
	 * us because the device returns this response synchronously through
	 * the control pipe rather than pushing it on interrupt IN. */
	memset(response, 0, response_len);
	{
		g_autoptr(FuIoctl) ioctl =
		    fu_udev_device_ioctl_new(FU_UDEV_DEVICE(self));
		if (!fu_ioctl_execute(ioctl,
				      HIDIOCGINPUT(response_len), /* nocheck:blocked */
				      response,
				      response_len,
				      NULL,
				      5000, /* ms */
				      FU_IOCTL_FLAG_NONE,
				      error))
			return FALSE;
	}

	fu_dump_raw(G_LOG_DOMAIN, "vcmd read response", response, response_len);
	return TRUE;
}

/*
 * Read the upstream-hub MCU's firmware version. Mirrors
 * RTS5409S_HID::get_self_fw_version() in libdevices.so:
 *   - send  C0 09 00 00 00 00 20 …
 *   - read  193 bytes back
 *   - format response[0x12]<<bytes_we_dont_decode_yet> as the
 *     reported firmware version string
 *
 * For now we just stash the first 16 hex bytes of the response into the
 * version string so we can see what comes back and iterate from there.
 */
static gboolean
fu_dell_monitor_rt_device_read_version(FuDellMonitorRtDevice *self,
				       gchar **version_out,
				       GError **error)
{
	guint8 response[DELL_MONITOR_RT_BUF_SIZE] = {0};
	/* libdevices RTS5409S_HID::get_self_fw_version sets a 0x20 byte
	 * at wire offset 6 — purpose unknown but matched here. Bytes 4-5
	 * stay zero. */
	guint8 payload[3] = {0x00, 0x00, 0x20};

	if (!fu_dell_monitor_rt_device_vcmd_read(self,
						 DELL_MONITOR_RT_OPCODE_GET_FW_VERSION,
						 0x00,
						 0x00,
						 payload,
						 sizeof(payload),
						 response,
						 sizeof(response),
						 error))
		return FALSE;

	/* response[0] is the Report ID prefix (always 0); the wire payload
	 * starts at response[1]. PLUGIN_NOTES (Wire format §"version
	 * decoding") notes that the version major/minor are at object
	 * offsets 0x124/0x125 in Dell's binary, which maps to indices
	 * (0x124 - 0x119) = 0x0B and 0x0C of the response wire payload. */
	{
		guint8 minor = response[1 + 0x0B];
		guint8 major = response[1 + 0x0C];
		*version_out = g_strdup_printf("%u.%u", major, minor);
	}
	return TRUE;
}

static gboolean
fu_dell_monitor_rt_device_probe(FuDevice *device, GError **error)
{
	g_debug("dell-monitor-rt: probe %s", fu_device_get_name(device));
	return TRUE;
}

static gboolean
fu_dell_monitor_rt_device_setup(FuDevice *device, GError **error)
{
	FuDellMonitorRtDevice *self = FU_DELL_MONITOR_RT_DEVICE(device);
	g_autoptr(GError) error_local = NULL;
	g_autofree gchar *version = NULL;
	const guint8 vendor_sig[2] = {DELL_MONITOR_RT_VENDOR_SIG_LO,
				      DELL_MONITOR_RT_VENDOR_SIG_HI};

	/* Step 1: enable vendor-command mode (the auth bytes are the
	 * RealTek vendor ID 0x0BDA placed at wire bytes 4-5). */
	if (!fu_dell_monitor_rt_device_vcmd(self,
					    DELL_MONITOR_RT_DIR_WRITE,
					    DELL_MONITOR_RT_OPCODE_ENABLE_VDCMD,
					    0x01, /* "enable" */
					    0x00,
					    vendor_sig,
					    sizeof(vendor_sig),
					    &error_local)) {
		g_warning("dell-monitor-rt: enable_vdcmd failed: %s",
			  error_local->message);
		fu_device_set_version(device, "0.0.0-no-vdcmd");
		return TRUE;
	}

	/* Step 2: enable high-clock mode (Dell's binary's frame 7702 — the
	 * second thing it sends after enable_vdcmd). May not be strictly
	 * required for version-read but matches the captured init order. */
	g_clear_error(&error_local);
	if (!fu_dell_monitor_rt_device_vcmd(self,
					    DELL_MONITOR_RT_DIR_WRITE,
					    DELL_MONITOR_RT_OPCODE_ENABLE_HIGH_CLOCK,
					    0x01, /* "enable" */
					    0x00,
					    NULL,
					    0,
					    &error_local)) {
		g_warning("dell-monitor-rt: enable_high_clock failed: %s",
			  error_local->message);
		fu_device_set_version(device, "0.0.0-no-hiclk");
		return TRUE;
	}

	/* Step 3: ask for the hub MCU firmware version. */
	g_clear_error(&error_local);
	if (!fu_dell_monitor_rt_device_read_version(self, &version, &error_local)) {
		g_warning("dell-monitor-rt: get_self_fw_version failed: %s",
			  error_local->message);
		fu_device_set_version(device, "0.0.0-no-version");
		return TRUE;
	}

	g_debug("dell-monitor-rt: hub MCU firmware version = %s", version);
	fu_device_set_version(device, version);
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
	fu_device_add_flag(FU_DEVICE(self), FWUPD_DEVICE_FLAG_SIGNED_PAYLOAD);
	fu_device_set_remove_delay(FU_DEVICE(self), 60 * 1000); /* 60 s for re-enum */
	fu_udev_device_add_open_flag(FU_UDEV_DEVICE(self),
				     FU_IO_CHANNEL_OPEN_FLAG_READ);
	fu_udev_device_add_open_flag(FU_UDEV_DEVICE(self),
				     FU_IO_CHANNEL_OPEN_FLAG_WRITE);
}

static void
fu_dell_monitor_rt_device_class_init(FuDellMonitorRtDeviceClass *klass)
{
	FuDeviceClass *device_class = FU_DEVICE_CLASS(klass);
	device_class->probe = fu_dell_monitor_rt_device_probe;
	device_class->setup = fu_dell_monitor_rt_device_setup;
}
