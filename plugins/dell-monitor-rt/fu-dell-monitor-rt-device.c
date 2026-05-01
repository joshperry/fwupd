/*
 * Copyright 2026 Joshua Perry <josh@6bit.com>
 * Copyright 2026 Ada <ada@6bit.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "config.h"

#include "fu-dell-monitor-rt-device.h"

/*
 * Wire format (verified against captured pcap frame 7700 of Dell's own
 * updater talking to the same monitor):
 *
 *   byte 0     direction      0x40 = WRITE   / 0xC0 = READ
 *   byte 1     opcode         (see DELL_MONITOR_RT_OPCODE_* below)
 *   byte 2     subcmd / arg   (command-specific)
 *   byte 3     arg            (command-specific, often zero)
 *   bytes 4-5  vendor sig     0xDA 0x0B  (RealTek vendor ID 0x0BDA, LE)
 *                             — present on vendor-cmd-mode framings; some
 *                             other opcodes (e.g. SRAM write) put data here
 *   bytes 6-7  pad (zero)
 *   bytes 8+   payload        (firmware data for SRAM_WRITE; otherwise zero)
 *
 * Sent as a HID Output Report (kernel HID stack issues the SET_REPORT
 * class control transfer) with a fixed 192-byte size.  When write(2)-ing
 * to /dev/hidrawN, byte 0 of the buffer is the Report ID — this device
 * declares no Report ID, so byte 0 is always 0x00 and the 192 actual
 * report bytes follow, giving a 193-byte transfer.
 */

#define DELL_MONITOR_RT_REPORT_SIZE  192
#define DELL_MONITOR_RT_TIMEOUT_MS   5000

#define DELL_MONITOR_RT_DIR_WRITE    0x40
#define DELL_MONITOR_RT_DIR_READ     0xC0

#define DELL_MONITOR_RT_OPCODE_ENABLE_VDCMD          0x02
#define DELL_MONITOR_RT_OPCODE_ENABLE_HIGH_CLOCK     0x06

#define DELL_MONITOR_RT_VENDOR_SIG_LO 0xDA
#define DELL_MONITOR_RT_VENDOR_SIG_HI 0x0B

struct _FuDellMonitorRtDevice {
	FuHidrawDevice parent_instance;
};

G_DEFINE_TYPE(FuDellMonitorRtDevice, fu_dell_monitor_rt_device, FU_TYPE_HIDRAW_DEVICE)

/*
 * Build the standard 192-byte vendor frame and write it to the device's
 * hidraw fd.  Goes through the kernel's hid-generic driver, which is
 * what hidapi (and therefore Dell's official .deb updater) uses too.
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
	guint8 buf[1 + DELL_MONITOR_RT_REPORT_SIZE] = {0};

	if (payload_len > DELL_MONITOR_RT_REPORT_SIZE - 8) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_DATA,
			    "vcmd payload too large: %" G_GSIZE_FORMAT " > %u",
			    payload_len,
			    (guint)(DELL_MONITOR_RT_REPORT_SIZE - 8));
		return FALSE;
	}

	/* buf[0] is the Report ID prefix (always 0 — device declares none) */
	buf[1] = dir;
	buf[2] = opcode;
	buf[3] = subcmd;
	buf[4] = arg;
	buf[5] = DELL_MONITOR_RT_VENDOR_SIG_LO;
	buf[6] = DELL_MONITOR_RT_VENDOR_SIG_HI;
	/* buf[7] and buf[8] left zero */
	if (payload != NULL && payload_len > 0)
		memcpy(buf + 1 + 8, payload, payload_len);

	fu_dump_raw(G_LOG_DOMAIN, "vcmd write", buf, sizeof(buf));

	return fu_hidraw_device_set_report(FU_HIDRAW_DEVICE(self),
					   buf,
					   sizeof(buf),
					   FU_IO_CHANNEL_FLAG_NONE,
					   error);
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

	g_debug("dell-monitor-rt: setup %s", fu_device_get_name(device));

	/*
	 * Smoke test: send the enable_vdcmd (opcode 0x02) ping that the
	 * captured update sequence opens with.  See PLUGIN_NOTES §
	 * "Per-phase timeline" — Dell's binary issues this immediately on
	 * device open before doing anything else.
	 */
	if (!fu_dell_monitor_rt_device_vcmd(self,
					    DELL_MONITOR_RT_DIR_WRITE,
					    DELL_MONITOR_RT_OPCODE_ENABLE_VDCMD,
					    0x01, /* subcmd from pcap */
					    0x00,
					    NULL,
					    0,
					    &error_local)) {
		g_warning("dell-monitor-rt: enable_vdcmd ping failed: %s",
			  error_local->message);
		fu_device_set_version(device, "0.0.0-no-response");
		return TRUE; /* don't fail device setup; just record state */
	}

	fu_device_set_version(device, "0.0.0-vcmd-ack");
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

	/* Declare hidraw FD open mode so fu_udev_device_open() actually
	 * opens the descriptor in r/w; otherwise writes fail with EBADF. */
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
