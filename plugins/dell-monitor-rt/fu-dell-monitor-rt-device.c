/*
 * Copyright 2026 Joshua Perry <josh@6bit.com>
 * Copyright 2026 Ada <ada@6bit.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "config.h"

#include "fu-dell-monitor-rt-device.h"

/*
 * Wire format (decoded from the Wistron updater's libdevices.so source):
 *
 *   byte 0     direction      0x40 = WRITE   / 0xC0 = READ
 *   byte 1     opcode         (see DELL_MONITOR_RT_OPCODE_* below)
 *   byte 2     subcmd
 *   byte 3     arg
 *   bytes 4    pad (zero)
 *   bytes 5-6  vendor sig     0xDA 0x0B  (RealTek vendor ID 0x0BDA, LE)
 *   byte 7     pad (zero)
 *   bytes 8+   payload        (firmware data for SRAM_WRITE; otherwise zero)
 *
 * Sent as a HID Output Report (SET_REPORT class control transfer) with
 * a fixed 192-byte size.
 */

#define DELL_MONITOR_RT_REPORT_SIZE   192
#define DELL_MONITOR_RT_REPORT_ID     0x00
#define DELL_MONITOR_RT_TIMEOUT_MS    5000

#define DELL_MONITOR_RT_DIR_WRITE     0x40
#define DELL_MONITOR_RT_DIR_READ      0xC0

#define DELL_MONITOR_RT_OPCODE_ENABLE_VDCMD 0x02
#define DELL_MONITOR_RT_OPCODE_GET_VERSION  0x10  /* hypothesis — needs runtime confirm */

#define DELL_MONITOR_RT_VENDOR_SIG_LO 0xDA
#define DELL_MONITOR_RT_VENDOR_SIG_HI 0x0B

struct _FuDellMonitorRtDevice {
	FuHidDevice parent_instance;
};

G_DEFINE_TYPE(FuDellMonitorRtDevice, fu_dell_monitor_rt_device, FU_TYPE_HID_DEVICE)

/*
 * Build the standard 192-byte vendor frame and send it as a SET_REPORT.
 * Optionally pulls back the device's response via GET_REPORT.
 */
static gboolean
fu_dell_monitor_rt_device_vcmd(FuDellMonitorRtDevice *self,
			       guint8 dir,
			       guint8 opcode,
			       guint8 subcmd,
			       guint8 arg,
			       const guint8 *payload,
			       gsize payload_len,
			       guint8 *response,
			       GError **error)
{
	guint8 buf[DELL_MONITOR_RT_REPORT_SIZE] = {0};

	if (payload_len > DELL_MONITOR_RT_REPORT_SIZE - 8) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_DATA,
			    "vcmd payload too large: %" G_GSIZE_FORMAT " > %u",
			    payload_len,
			    (guint)(DELL_MONITOR_RT_REPORT_SIZE - 8));
		return FALSE;
	}

	buf[0] = dir;
	buf[1] = opcode;
	buf[2] = subcmd;
	buf[3] = arg;
	/* buf[4] left zero */
	buf[5] = DELL_MONITOR_RT_VENDOR_SIG_LO;
	buf[6] = DELL_MONITOR_RT_VENDOR_SIG_HI;
	/* buf[7] left zero */
	if (payload != NULL && payload_len > 0)
		memcpy(buf + 8, payload, payload_len);

	if (!fu_hid_device_set_report(FU_HID_DEVICE(self),
				      DELL_MONITOR_RT_REPORT_ID,
				      buf,
				      sizeof(buf),
				      DELL_MONITOR_RT_TIMEOUT_MS,
				      FU_HID_DEVICE_FLAG_NONE,
				      error))
		return FALSE;

	if (response != NULL) {
		guint8 in[DELL_MONITOR_RT_REPORT_SIZE] = {0};
		if (!fu_hid_device_get_report(FU_HID_DEVICE(self),
					      DELL_MONITOR_RT_REPORT_ID,
					      in,
					      sizeof(in),
					      DELL_MONITOR_RT_TIMEOUT_MS,
					      FU_HID_DEVICE_FLAG_NONE,
					      error))
			return FALSE;
		memcpy(response, in, DELL_MONITOR_RT_REPORT_SIZE);
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

	g_debug("dell-monitor-rt: setup %s", fu_device_get_name(device));

	/*
	 * Smoke test: send the enable_vdcmd (opcode 0x02) ping that the
	 * captured update sequence opens with. If the device acknowledges,
	 * we know the wire format and HID-class control transfer plumbing
	 * are working end-to-end.
	 *
	 * The captured frame at pcap timestamp 23.6 s was:
	 *   40 02 01 00 00 DA 0B 00 (rest zero) — direction WRITE,
	 *   opcode enable_vdcmd, subcmd 0x01.
	 */
	if (!fu_dell_monitor_rt_device_vcmd(self,
					    DELL_MONITOR_RT_DIR_WRITE,
					    DELL_MONITOR_RT_OPCODE_ENABLE_VDCMD,
					    0x01, /* subcmd from pcap */
					    0x00,
					    NULL,
					    0,
					    NULL,
					    &error_local)) {
		g_warning("dell-monitor-rt: enable_vdcmd ping failed: %s",
			  error_local->message);
		fu_device_set_version(device, "0.0.0-no-response");
		return TRUE; /* don't fail device setup; just record state */
	}

	/* TODO: send a real version-read opcode and parse the response.
	 * For now record that the ping succeeded so downstream tooling
	 * sees a distinct version string. */
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
}

static void
fu_dell_monitor_rt_device_class_init(FuDellMonitorRtDeviceClass *klass)
{
	FuDeviceClass *device_class = FU_DEVICE_CLASS(klass);
	device_class->probe = fu_dell_monitor_rt_device_probe;
	device_class->setup = fu_dell_monitor_rt_device_setup;
}
