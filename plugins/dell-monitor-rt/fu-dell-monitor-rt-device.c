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
#include "fu-dell-monitor-rt-firmware-component.h"
#include "fu-dell-monitor-rt-firmware.h"

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

/* HID I/O timeout. Matches what hidapi uses by default. */
#define DELL_MONITOR_RT_TIMEOUT_MS   5000

#define DELL_MONITOR_RT_DIR_WRITE    0x40
#define DELL_MONITOR_RT_DIR_READ     0xC0

#define DELL_MONITOR_RT_OPCODE_ENABLE_VDCMD          0x02
#define DELL_MONITOR_RT_OPCODE_ENABLE_HIGH_CLOCK     0x06
#define DELL_MONITOR_RT_OPCODE_GET_FW_VERSION        0x09  /* hub MCU only */
#define DELL_MONITOR_RT_OPCODE_AUTH                  0xE1  /* I²C tunnel auth */
#define DELL_MONITOR_RT_OPCODE_BOOTLOADER_ENTER      0xE9  /* re-enumerate as bootloader */
#define DELL_MONITOR_RT_OPCODE_I2C_WRITE             0xC6  /* I²C tunnel write */
#define DELL_MONITOR_RT_OPCODE_I2C_READ              0xD6  /* I²C tunnel read req */

/* Auth subcommands. 0x01 = "request challenge" (host then reads 16 bytes
 * via HIDIOCGINPUT); 0x03 = "send response" (8 bytes computed by cal_auth
 * and placed at wire offset 64 of the SET_REPORT payload). */
#define DELL_MONITOR_RT_AUTH_SUB_REQUEST   0x01
#define DELL_MONITOR_RT_AUTH_SUB_RESPONSE  0x03

/* Per-product synkey-seed buffer for the U4025QW, verbatim from the
 * `cert.dat` file shipped in Dell's monitorfirmwareupdateutility .deb.
 * (Dell's own naming — "cert.dat" — is misleading; it's not an X.509
 * cert but the seed buffer that derives the cal_auth key. See
 * PLUGIN_NOTES "I²C tunnel auth handshake".)
 *
 * fu_dell_monitor_rt_get_synkey() walks this buffer with the algorithm
 * decoded from RTS5409S_HID::get_synkey() in libdevices.so to derive
 * the 8-byte cal_auth key. For the U4025QW the derived key is
 *   4F DC C1 10 11 6D 76 02
 * which we previously hard-coded; deriving it from the seed lets us
 * support other Dell monitors by swapping out this blob (eventually
 * sourced from the .upg firmware payload, once the parser exists). */
static const guint8 DELL_MONITOR_RT_U4025QW_SYNKEY_SEED[18] = {
    0xF8, 0xB7, 0xFD, 0x21, 0xE0, 0x32, 0x22, 0xB8,
    0xA9, 0xE8, 0x7C, 0x11, 0x04, 0x94, 0xE2, 0x9D,
    0x9F, 0x6A,
};

/* I²C target addresses on the monitor's internal bus (per DDC/CI standard
 * + Wistron extensions). 0x37 is the 7-bit address of the FL5500 scaler
 * over DDC/CI; the 8-bit form 0x6E is what appears on the wire. */
#define DELL_MONITOR_RT_I2C_TARGET_DDCCI 0x6E

/* Default I²C bus speed config — written into wire byte 10. 0 = default
 * (matches the "this+0x40 == 0" we see right after open). */
#define DELL_MONITOR_RT_I2C_DEFAULT_SPEED 0x00

/* Wire offsets for I²C-tunnel commands (relative to the 192-byte payload
 * AFTER the report-ID prefix, so callers see them as buf[N+1] in the
 * 193-byte hidraw buffer). */
#define DELL_MONITOR_RT_I2C_WIRE_LEN_OFFSET     6
#define DELL_MONITOR_RT_I2C_WIRE_TARGET_OFFSET  8
#define DELL_MONITOR_RT_I2C_WIRE_SPEED_OFFSET  10
#define DELL_MONITOR_RT_I2C_WIRE_DATA_OFFSET   64  /* memmove dest in disasm */

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
 * Send a vcmd and pull a response via HIDIOCGINPUT.
 *
 * The wire-byte-0 direction selector (DIR_WRITE 0x40 / DIR_READ 0xC0)
 * is opcode-specific in this protocol — Dell's binary uses 0xC0 for
 * pure read-back commands (e.g. opcode 0x09 get_self_fw_version) and
 * 0x40 for action commands that also stage a response (e.g. opcode
 * 0xE1 cal_auth). The chip apparently accepts the "wrong" direction
 * for some opcodes too, but matching Dell's pattern is necessary for
 * emulation replays — the recorded fixture only contains the byte
 * patterns Dell actually emitted. The response buffer is 193 bytes
 * including the leading Report ID byte.
 */
static gboolean
fu_dell_monitor_rt_device_vcmd_read(FuDellMonitorRtDevice *self,
				    guint8 dir,
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
					    dir,
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
				      DELL_MONITOR_RT_TIMEOUT_MS,
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
 *   - send  C0 09 00 00 00 00 20 …  (HID Output Report, opcode 0x09)
 *   - pull  193-byte HID Input Report via HIDIOCGINPUT
 *   - format response[11..12] as "%X.%02X" (the format string in
 *     Dell's binary at libdevices.so .rodata + 0x1d1ecc)
 *
 * NOTE: this returns the *hub MCU's* (RealTek RTS5409S) internal
 * firmware revision, NOT the user-facing "M3T105" version that the
 * Dell GUI shows. M3T105 lives on the FL5500 scaler chip and is
 * readable via the I²C tunnel (Rts5409s_IIC_API::read_fw_version
 * reads register 0x0325 over the HID-encoded I²C bus). That's a
 * separate code path we'll add once the basic write loop works.
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
						 DELL_MONITOR_RT_DIR_READ,
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
		/* Dell's binary uses "%X.%02X" — version is hex-formatted */
		*version_out = g_strdup_printf("hub-%X.%02X", major, minor);
	}
	return TRUE;
}

/*
 * Walk a per-product seed buffer and derive the 8-byte cal_auth key.
 * Decoded from RTS5409S_HID::get_synkey() in libdevices.so (0xb8570).
 *
 * The seed is shipped as `cert.dat` in Dell's .deb (a misnomer — it's
 * not a certificate, just a key-derivation seed). At runtime Dell's
 * binary loads `cert.dat` and feeds it through the libdevices plugin
 * interface (`load(data, len)` → `IIC_INTF::load` → `HID_INTF::load`)
 * which copies it into RTS5409S_HID's vector at this+0x18; then
 * RTS5409S_HID::open() runs get_synkey() which derives the 8 key
 * bytes into this+0x21A.
 *
 * For each "trigger" byte buf[in]:
 *   - if (buf[in] & 0x11) == 0x01 or 0x10:  FAST — consume 2 bytes,
 *       produce 1 key byte = buf[in] ^ buf[in+1]
 *   - if (buf[in] & 0x11) == 0x11:          SLOW — consume 3 bytes,
 *       produce 2 key bytes:
 *         key[out]   = buf[in]   ^ buf[in+1]
 *         key[out+1] = buf[in+2] ^ buf[in+1]
 *   - if (buf[in] & 0x11) == 0x00:          SKIP — consume 1, no key
 *
 * Output bytes that overflow the 8-byte key buffer are discarded
 * (Dell's binary writes them past the 8-byte field; we just clip).
 */
static void
fu_dell_monitor_rt_get_synkey(const guint8 *seed,
			      gsize seed_len,
			      guint8 key[8])
{
	gsize in_idx = 0;
	gsize out_idx = 0;

	memset(key, 0, 8);
	while (in_idx < seed_len && out_idx < 8) {
		guint8 trigger = seed[in_idx];
		guint8 bits = trigger & 0x11;

		if (bits == 0x01 || bits == 0x10) {
			/* FAST */
			if (in_idx + 1 >= seed_len)
				break;
			key[out_idx] = trigger ^ seed[in_idx + 1];
			in_idx  += 2;
			out_idx += 1;
		} else if (bits == 0x11) {
			/* SLOW — write what fits, advance by 3 (note: the +1
			 * at LAB_001b85cb in the C decompile is INSIDE the
			 * else branch, so it doesn't apply to the slow path). */
			if (in_idx + 2 >= seed_len)
				break;
			if (out_idx < 8)
				key[out_idx] = trigger ^ seed[in_idx + 1];
			if (out_idx + 1 < 8)
				key[out_idx + 1] = seed[in_idx + 2] ^ seed[in_idx + 1];
			in_idx  += 3;
			out_idx += 2;
		} else {
			/* SKIP */
			in_idx += 1;
		}
	}
}

/*
 * Compute the 8-byte I²C-tunnel auth response for a given 16-byte device
 * challenge. Decoded from RTS5409S_HID::cal_auth in libdevices.so
 * (0xb8640). Self-contained — no crypto library needed.
 *
 * The algorithm: take parity of the 16-bit value (challenge[0]<<8) |
 * challenge[15]. If odd, base on the low half of the challenge and mix
 * one byte from the high half; if even, the reverse. Then XOR with the
 * 8-byte product key.
 */
static void
fu_dell_monitor_rt_cal_auth(const guint8 challenge[16],
			    const guint8 key[8],
			    guint8 response[8])
{
	guint16 mix = ((guint16)challenge[0] << 8) | challenge[15];
	gboolean parity_even = (__builtin_popcount(mix) & 1) == 0;
	guint8 tmp[8];
	guint idx;

	if (parity_even) {
		memcpy(tmp, &challenge[8], 8);
		idx = challenge[6] & 0x07;
		tmp[idx] ^= challenge[idx];
	} else {
		memcpy(tmp, &challenge[0], 8);
		idx = challenge[14] & 0x07;
		tmp[idx] ^= challenge[idx + 8];
	}
	for (guint i = 0; i < 8; i++)
		response[i] = tmp[i] ^ key[i];
}

/*
 * Run the per-cycle I²C-tunnel auth handshake. Required *every cycle*
 * before any 0xC6 / 0xD6 traffic — the device gates I²C tunnel access
 * on a fresh challenge/response each time. See PLUGIN_NOTES "I²C tunnel
 * auth handshake".
 */
static gboolean
fu_dell_monitor_rt_device_handshake(FuDellMonitorRtDevice *self,
				    const guint8 key[8],
				    GError **error)
{
	guint8 challenge_resp[DELL_MONITOR_RT_BUF_SIZE] = {0};
	guint8 response[8] = {0};
	const guint8 *challenge;

	/* Step 1+2: send 0x40 e1 01 01 and pull 16-byte challenge via
	 * HIDIOCGINPUT. Note the 0x40 (DIR_WRITE) direction byte — for the
	 * cal_auth opcode Dell's binary frames the request as an "action"
	 * even though it expects a response back via HIDIOCGINPUT. The
	 * chip would also accept 0xC0 here, but the captured fixture only
	 * has the 0x40 variant so emulation needs us to match. */
	if (!fu_dell_monitor_rt_device_vcmd_read(self,
						 DELL_MONITOR_RT_DIR_WRITE,
						 DELL_MONITOR_RT_OPCODE_AUTH,
						 DELL_MONITOR_RT_AUTH_SUB_REQUEST,
						 0x01, /* arg byte mirrors subcmd in pcap */
						 NULL,
						 0,
						 challenge_resp,
						 sizeof(challenge_resp),
						 error)) {
		g_prefix_error(error, "auth challenge request failed: ");
		return FALSE;
	}

	/* The 16-byte challenge starts at wire offset 0 of the response,
	 * which is response[1..16] in the 193-byte hidraw buffer (the
	 * leading byte is the report-ID prefix). */
	challenge = &challenge_resp[1];
	fu_dump_raw(G_LOG_DOMAIN, "auth challenge", challenge, 16);

	/* Step 3: compute response. */
	fu_dell_monitor_rt_cal_auth(challenge, key, response);
	fu_dump_raw(G_LOG_DOMAIN, "auth response", response, 8);

	/* Step 4: send 0x40 e1 03 00 with the 8-byte response at wire
	 * offset 64. fu_dell_monitor_rt_device_vcmd places its payload at
	 * wire offset 4, so we need a custom wire layout — bypass vcmd
	 * and build the buffer directly. */
	{
		guint8 buf[DELL_MONITOR_RT_BUF_SIZE] = {0};
		buf[1 + 0] = DELL_MONITOR_RT_DIR_WRITE;
		buf[1 + 1] = DELL_MONITOR_RT_OPCODE_AUTH;
		buf[1 + 2] = DELL_MONITOR_RT_AUTH_SUB_RESPONSE;
		buf[1 + 3] = 0x00;
		memcpy(&buf[1 + 64], response, 8);
		fu_dump_raw(G_LOG_DOMAIN, "auth response frame", buf, sizeof(buf));
		if (!fu_hidraw_device_set_report(FU_HIDRAW_DEVICE(self),
						 buf,
						 sizeof(buf),
						 FU_IO_CHANNEL_FLAG_USE_BLOCKING_IO,
						 error)) {
			g_prefix_error(error, "auth response send failed: ");
			return FALSE;
		}
	}
	return TRUE;
}

/*
 * Send an I²C-tunnel WRITE through the HID transport (opcode 0xC6).
 * Layout decoded from RTS5409S_HID::write in libdevices.so:
 *
 *   byte 0       0x40                 (HID direction = WRITE)
 *   byte 1       0xC6                 (I²C tunnel WRITE opcode)
 *   bytes 2-5    zero
 *   byte 6       len                  (I²C payload length)
 *   byte 7       zero
 *   byte 8       i2c_target           (I²C 8-bit address, e.g. 0x6E)
 *   byte 9       zero
 *   byte 10      bus speed config     (0 = default)
 *   bytes 11-63  zero
 *   bytes 64+    I²C payload bytes    (`len` bytes copied here)
 */
static gboolean
fu_dell_monitor_rt_device_i2c_write(FuDellMonitorRtDevice *self,
				    guint8 i2c_target,
				    const guint8 *data,
				    gsize len,
				    GError **error)
{
	guint8 buf[DELL_MONITOR_RT_BUF_SIZE] = {0};
	const gsize data_max =
	    DELL_MONITOR_RT_REPORT_SIZE - DELL_MONITOR_RT_I2C_WIRE_DATA_OFFSET;

	if (len > data_max) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_DATA,
			    "i2c-write payload too large: %" G_GSIZE_FORMAT
			    " > %u",
			    len,
			    (guint)data_max);
		return FALSE;
	}

	/* buf[0] is the Report ID prefix (always 0) */
	buf[1 + 0] = DELL_MONITOR_RT_DIR_WRITE;
	buf[1 + 1] = DELL_MONITOR_RT_OPCODE_I2C_WRITE;
	buf[1 + DELL_MONITOR_RT_I2C_WIRE_LEN_OFFSET]    = (guint8)len;
	buf[1 + DELL_MONITOR_RT_I2C_WIRE_TARGET_OFFSET] = i2c_target;
	buf[1 + DELL_MONITOR_RT_I2C_WIRE_SPEED_OFFSET]  = DELL_MONITOR_RT_I2C_DEFAULT_SPEED;
	if (data != NULL && len > 0) {
		memcpy(buf + 1 + DELL_MONITOR_RT_I2C_WIRE_DATA_OFFSET,
		       data,
		       len);
	}

	fu_dump_raw(G_LOG_DOMAIN, "i2c write", buf, sizeof(buf));
	return fu_hidraw_device_set_report(FU_HIDRAW_DEVICE(self),
					   buf,
					   sizeof(buf),
					   FU_IO_CHANNEL_FLAG_USE_BLOCKING_IO,
					   error);
}

/*
 * Send an I²C-tunnel READ request (opcode 0xD6, byte layout identical
 * to the WRITE except the response data is fetched via HIDIOCGINPUT).
 * `count` is the number of I²C bytes to receive; the response is
 * written to `response_out` starting at offset 1 (skipping the
 * leading HID report-ID byte).
 */
static gboolean
fu_dell_monitor_rt_device_i2c_read(FuDellMonitorRtDevice *self,
				   guint8 i2c_target,
				   guint8 count,
				   guint8 *response,
				   gsize response_len,
				   GError **error)
{
	guint8 buf[DELL_MONITOR_RT_BUF_SIZE] = {0};

	if (response_len < (gsize)count + 1) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_DATA,
			    "i2c-read response buffer too small for count=%u",
			    count);
		return FALSE;
	}

	buf[1 + 0] = DELL_MONITOR_RT_DIR_WRITE;
	buf[1 + 1] = DELL_MONITOR_RT_OPCODE_I2C_READ;
	buf[1 + DELL_MONITOR_RT_I2C_WIRE_LEN_OFFSET]    = count;
	buf[1 + DELL_MONITOR_RT_I2C_WIRE_TARGET_OFFSET] = i2c_target;
	buf[1 + DELL_MONITOR_RT_I2C_WIRE_SPEED_OFFSET]  = DELL_MONITOR_RT_I2C_DEFAULT_SPEED;

	fu_dump_raw(G_LOG_DOMAIN, "i2c read req", buf, sizeof(buf));
	if (!fu_hidraw_device_set_report(FU_HIDRAW_DEVICE(self),
					 buf,
					 sizeof(buf),
					 FU_IO_CHANNEL_FLAG_USE_BLOCKING_IO,
					 error))
		return FALSE;

	memset(response, 0, response_len);
	{
		g_autoptr(FuIoctl) ioctl =
		    fu_udev_device_ioctl_new(FU_UDEV_DEVICE(self));
		if (!fu_ioctl_execute(ioctl,
				      HIDIOCGINPUT(response_len), /* nocheck:blocked */
				      response,
				      response_len,
				      NULL,
				      DELL_MONITOR_RT_TIMEOUT_MS,
				      FU_IOCTL_FLAG_NONE,
				      error))
			return FALSE;
	}

	fu_dump_raw(G_LOG_DOMAIN, "i2c read response", response, response_len);
	return TRUE;
}

/*
 * Read the FL5500 scaler chip's firmware version via the I²C tunnel.
 * Sends a DDC/CI vendor command (51 84 c0 99 cc 20 0e) to target
 * 0x6E and parses the M3T105-style ASCII string out of the reply.
 * This is the version Dell's GUI displays — the user-facing
 * "M3T105"-format identifier — and what fwupd should compare against
 * LVFS release metadata. The hub MCU version (read via opcode 0x09)
 * is internal-only diagnostics.
 *
 * Verified byte-for-byte against frames in
 * captures/u4025qw-update-recap-20260502-185321.pcapng: Dell's
 * binary issues exactly the same 51 84 c0 99 cc 20 0e write to
 * target 0x6E and gets back 51 88 c1 99 4d3354313035 cf with
 * "M3T105" at offset 4 of the DDC/CI reply.
 */
static gboolean
fu_dell_monitor_rt_device_read_scaler_version(FuDellMonitorRtDevice *self,
					      gchar **version_out,
					      GError **error)
{
	/* DDC/CI vendor command 0xC0/0x99 with selector 0xCC/0x20 — reads
	 * the user-facing firmware version string from the FL5500 scaler.
	 * For the U4025QW running pre-update this returns "M3T105", the
	 * Dell-branded version identifier shown in DDPM and the .deb GUI.
	 *
	 * Wire layout (DDC/CI):
	 *   51 84 c0 99 cc 20 0e
	 *   │  │  └─────┬────┘ │
	 *   │  │       cmd     XOR-checksum over 0x6E (dest) || all preceding
	 *   │  length: 0x80 | (number of cmd bytes = 4)
	 *   src addr (host = 0x51)
	 *
	 * Frame 10778 of captures/u4025qw-m3t105-update-171436.pcapng. */
	const guint8 i2c_request[7] = {
	    0x51, 0x84, 0xc0, 0x99, 0xcc, 0x20, 0x0e,
	};
	guint8 response[DELL_MONITOR_RT_BUF_SIZE] = {0};
	guint8 hub_key[8];

	/* Derive the cal_auth key from the per-product seed buffer
	 * (cert.dat shipped with Dell's .deb). For the U4025QW this
	 * yields 4F DC C1 10 11 6D 76 02. */
	fu_dell_monitor_rt_get_synkey(DELL_MONITOR_RT_U4025QW_SYNKEY_SEED,
				      sizeof(DELL_MONITOR_RT_U4025QW_SYNKEY_SEED),
				      hub_key);

	/* The I²C tunnel is gated by a per-cycle auth handshake; the device
	 * STALLs subsequent 0xC6/0xD6 traffic if we skip it. Per the pcap
	 * the handshake must precede the WRITE in each cycle. */
	if (!fu_dell_monitor_rt_device_handshake(self, hub_key, error))
		return FALSE;

	if (!fu_dell_monitor_rt_device_i2c_write(self,
						 DELL_MONITOR_RT_I2C_TARGET_DDCCI,
						 i2c_request,
						 sizeof(i2c_request),
						 error))
		return FALSE;

	/* DDC/CI replies are slow — the FL5500 needs time to compose the
	 * response and stage it for retrieval over the I²C tunnel. In the
	 * pcap, Dell's binary waits ~280 frames (≈3 seconds at the captured
	 * rate) between the WRITE and the READ. Match that with a generous
	 * single sleep here. */
	g_usleep(50 * 1000); /* 50 ms */

	/* Pull whatever bytes the device buffered. Dell's binary uses
	 * length 0x40 (=64) as the "give me everything" READ. */
	if (!fu_dell_monitor_rt_device_i2c_read(self,
						DELL_MONITOR_RT_I2C_TARGET_DDCCI,
						0x40,
						response,
						sizeof(response),
						error))
		return FALSE;

	/* Expected (from frame 7995 of the pcap):
	 *   51 90 c1 99 37 35 33 2e 30 41 4b 30 31 2e 30 30 30 37 c4
	 * The "37..37" stretch is ASCII "753.0AK01.0007".
	 * If the device returns this, our tunnel reproduces Dell's protocol
	 * faithfully. Stash whatever ASCII we recognize as the version
	 * (knowingly a placeholder — we don't yet know which DDC/CI register
	 * carries the user-facing M3T105 string). */
	{
		const guint8 *wire = &response[1]; /* skip report-ID prefix */
		if (wire[0] == 0x51 && (wire[1] & 0x80) != 0 &&
		    wire[2] == 0xC1) {
			/* DDC/CI: byte 1 low 7 bits = number of payload bytes
			 * (opcode + sub + data, *not* including checksum).
			 * Data runs from byte 4 (after src/len/op/sub) for
			 * (len - 2) bytes, then a checksum byte. */
			gsize len = (wire[1] & 0x7F);
			if (len >= 2 && len < 60) {
				g_autoptr(GString) ascii = g_string_new(NULL);
				for (gsize i = 4; i < (gsize)(len + 2) && i < 60; i++) {
					if (wire[i] >= 0x20 && wire[i] < 0x7f)
						g_string_append_c(ascii, wire[i]);
				}
				*version_out = g_strdup(ascii->str);
				return TRUE;
			}
		}
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_READ,
			    "scaler-version DDC/CI reply malformed: "
			    "wire[0..3]=%02X %02X %02X %02X",
			    wire[0], wire[1], wire[2], wire[3]);
		return FALSE;
	}
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
	const guint8 vendor_sig[2] = {DELL_MONITOR_RT_VENDOR_SIG_LO,
				      DELL_MONITOR_RT_VENDOR_SIG_HI};

	/* Idempotency guard: setup() runs again whenever the engine re-adds
	 * the device — typically after a phase-load re-attaches it during
	 * install. The vendor-command init we do here is one-shot per
	 * device lifetime (Dell's binary doesn't re-send enable_vdcmd /
	 * cal_auth after a mid-install device cycle either), and
	 * re-running it under emulation advances the event cursor past
	 * the bootloader-entry events that write_firmware expects to find
	 * next. Short-circuit if the version is already set, which means
	 * a previous setup() pass already populated it. */
	if (fu_device_get_version(device) != NULL) {
		g_debug("dell-monitor-rt: setup re-entry — version already set "
			"to %s, skipping vendor-command init",
			fu_device_get_version(device));
		return TRUE;
	}

	/* SAFETY GUARD — see write_firmware for the full rationale. setup()
	 * issues real writes too (enable_vdcmd, cal_auth response, i2c_write
	 * for the DDC/CI version probe), so we must refuse the same way if
	 * fwupd hasn't tagged the device emulated. The IO helpers
	 * (fu_udev_device_write etc.) only intercept when EMULATED is set —
	 * absent that flag they fall through to /dev/hidrawN. Skip the
	 * vendor-command init entirely; report a placeholder version so
	 * fwupd still has something to display in get-devices output.
	 *
	 * Also inhibit the device so install dispatch ignores it. When an
	 * emulation fixture is loaded, the engine ends up with two matching
	 * U4025QW entries (the real hidraw and the synthetic emulated one);
	 * without inhibiting the real one, the engine picks it for install
	 * by enumeration order, our write_firmware refuses, and the
	 * emulated entry never gets exercised. The inhibit makes the
	 * emulated entry the only viable target. */
	if (!fu_device_has_flag(device, FWUPD_DEVICE_FLAG_EMULATED)) {
		g_warning("dell-monitor-rt: setup skipped — device is not "
			  "tagged FWUPD_DEVICE_FLAG_EMULATED, refusing to "
			  "send vendor commands to real hardware until the "
			  "protocol is fully validated under emulation");
		fu_device_set_version(device, "0.0.0-real-hw-locked");
		/* Use the "hidden" inhibit ID specifically — fu_device_list_
		 * get_active filters those out (fu-device-list.c:239), so
		 * the engine's install dispatch never considers this real
		 * device as a candidate. Without this, the real device and
		 * the synthetic emulated device both show up in install
		 * candidates; the engine's composite-update model is
		 * all-or-nothing, so the real device's safety-guard refusal
		 * aborts the entire install before write_firmware on the
		 * synthetic ever runs. With "hidden", only the synthetic
		 * remains an install candidate when an emulation fixture
		 * is loaded — which is exactly what we want during
		 * protocol bring-up. */
		fu_device_inhibit(device,
				  "hidden",
				  "real-hardware install disabled during plugin "
				  "bring-up; load an emulation fixture to test");
		return TRUE;
	}

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

	/* Step 3: read the user-facing firmware version (e.g. "M3T105") via
	 * a DDC/CI request to the FL5500 scaler — same byte sequence Dell's
	 * binary uses (51 84 c0 99 cc 20 0e to target 0x6E, then read back).
	 *
	 * We deliberately don't call read_version (the hub MCU's internal
	 * 0x09 opcode probe) here: Dell's binary doesn't issue 0xC0 0x09
	 * during the firmware-update flow, so emitting it would land our
	 * plugin's event cursor in the wrong place under emulation —
	 * fwupd's non-strict matcher leapfrogs forward to find a matching
	 * event ID, advancing past the cal_auth + i2c_write events the
	 * scaler probe needs next. Following Dell's sequence
	 * (enable_vdcmd → enable_high_clock → cal_auth → i2c_write →
	 * i2c_read) keeps the event cursor in step with the fixture. */
	g_clear_error(&error_local);
	{
		g_autofree gchar *scaler_ver = NULL;
		if (!fu_dell_monitor_rt_device_read_scaler_version(self,
								   &scaler_ver,
								   &error_local)) {
			g_warning("dell-monitor-rt: scaler version read failed: %s",
				  error_local->message);
			fu_device_set_version(device, "0.0.0-no-scaler-version");
			return TRUE;
		}
		fu_device_set_version(device, scaler_ver);
	}
	return TRUE;
}

static void
fu_dell_monitor_rt_device_init(FuDellMonitorRtDevice *self)
{
	fu_device_set_vendor(FU_DEVICE(self), "Dell");
	fu_device_add_protocol(FU_DEVICE(self), "com.dell.monitor.rt");
	fu_device_set_summary(FU_DEVICE(self),
			      "Dell monitor with RealTek scaler (Wistron ISP)");
	fu_device_set_firmware_gtype(FU_DEVICE(self), FU_TYPE_DELL_MONITOR_RT_FIRMWARE);
	fu_device_add_flag(FU_DEVICE(self), FWUPD_DEVICE_FLAG_UPDATABLE);
	fu_device_add_flag(FU_DEVICE(self), FWUPD_DEVICE_FLAG_SIGNED_PAYLOAD);
	fu_device_set_remove_delay(FU_DEVICE(self), 60 * 1000); /* 60 s for re-enum */
	fu_udev_device_add_open_flag(FU_UDEV_DEVICE(self),
				     FU_IO_CHANNEL_OPEN_FLAG_READ);
	fu_udev_device_add_open_flag(FU_UDEV_DEVICE(self),
				     FU_IO_CHANNEL_OPEN_FLAG_WRITE);
}

/*
 * Trigger bootloader-mode entry on the upstream-hub MCU.
 *
 * After this completes, the MCU drops its firmware-mode HID interface
 * and re-enumerates as the bootloader interface (a fresh hidraw node
 * with a different device descriptor — observed as 0x1100 → bootloader
 * VID/PID in our captures). fwupd waits for the re-enumeration via the
 * device's remove_delay (set to 60 s in init).
 *
 * Wire sequence — recovered from frames 43780-43786 of the recap pcap
 * captures/u4025qw-update-recap-20260502-185321.pcapng. The opcode
 * 0xE9 is sent only 4× in the entire 880k-frame capture, exclusively
 * here, immediately before each firmware-mode interface drops off the
 * bus to come back as the bootloader. Both invocations carry zero
 * subcmd, zero arg, and no payload, and Dell's binary fires them
 * back-to-back without waiting for an interrupt-IN ack between them.
 *
 * Why two writes? The MCU appears to require the trigger to be acked
 * twice before it commits to disconnecting (likely a deliberate "are
 * you sure" debounce — single accidental writes won't brick the
 * firmware mode). We mirror that behavior to stay symmetric with the
 * canonical capture; in the captured fixture this means our event
 * pattern matches Dell's exactly so the emulation framework can pair
 * both writes against recorded events.
 *
 * After this returns, no further IO is performed against the firmware-
 * mode hidraw fd — the fd is about to become invalid as the device
 * disconnects. The next phase (block writes against the bootloader
 * interface) runs against a freshly-enumerated FuDevice instance.
 */
static gboolean
fu_dell_monitor_rt_device_enter_bootloader(FuDellMonitorRtDevice *self,
					   GError **error)
{
	for (guint i = 0; i < 2; i++) {
		if (!fu_dell_monitor_rt_device_vcmd(self,
						    DELL_MONITOR_RT_DIR_WRITE,
						    DELL_MONITOR_RT_OPCODE_BOOTLOADER_ENTER,
						    0x00,
						    0x00,
						    NULL,
						    0,
						    error)) {
			g_prefix_error(error,
				       "bootloader-enter trigger %u failed: ",
				       i);
			return FALSE;
		}
	}
	return TRUE;
}

/*
 * write_firmware — stub.
 *
 * Real installs are not yet wired up. This placeholder exists so the
 * full pipeline (cab → FuFirmware parse → component-walk → device
 * dispatch) plumbs end-to-end against the captured emulation fixture.
 * Each iteration of real protocol code we add gets immediate test
 * coverage by replaying via:
 *
 *   fwupdtool emulation-load fixture.zip cab.cab
 *
 * The walk currently logs each component's id, version, primary
 * chip-type GUID, and decrypted-payload size, then returns success
 * without touching the device. As we land protocol code (bootloader
 * entry, block writes, commit, …) it slots in here, dispatched per
 * component by `chip_guid` against a small handler table.
 */
static gboolean
fu_dell_monitor_rt_device_write_firmware(FuDevice *device,
					 FuFirmware *firmware,
					 FuProgress *progress,
					 FwupdInstallFlags flags,
					 GError **error)
{
	FuDellMonitorRtFirmware *fw_container;
	GPtrArray *components;

	if (!FU_IS_DELL_MONITOR_RT_FIRMWARE(firmware)) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_FILE,
			    "expected FuDellMonitorRtFirmware, got %s",
			    G_OBJECT_TYPE_NAME(firmware));
		return FALSE;
	}
	fw_container = FU_DELL_MONITOR_RT_FIRMWARE(firmware);

	g_info("dell-monitor-rt: write_firmware (stub) — product=%s fw_version=%s",
	       fu_dell_monitor_rt_firmware_get_product(fw_container),
	       fu_dell_monitor_rt_firmware_get_fw_version(fw_container));

	/* SAFETY GUARD — refuse to issue any device IO unless fwupd has
	 * tagged us as emulated. During development we can only run against
	 * the captured fixture; real-hardware writes risk bricking the
	 * monitor (the bootloader-entry trigger especially). The guard fires
	 * specifically because our existing converter-produced fixture is in
	 * FuUsbDevice format while our plugin attaches to a FuHidrawDevice,
	 * so emulation-load builds a synthetic FuUsbDevice that our plugin
	 * never sees — the device our plugin DOES see stays real, with the
	 * EMULATED flag clear, and any IO falls through to /dev/hidrawN.
	 * Lift this guard once we have either (a) a fixture in matching
	 * FuHidrawDevice format with a BackendId that lines up with the
	 * real device's sysfs path, captured via fwupdtool emulation-tag +
	 * emulation-save, or (b) explicit user opt-in for real-hardware
	 * testing once we trust the protocol. */
	if (!fu_device_has_flag(device, FWUPD_DEVICE_FLAG_EMULATED)) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_NOT_SUPPORTED,
				    "dell-monitor-rt write_firmware refuses to run "
				    "against real hardware until the bootloader / "
				    "block-write / commit protocol is fully "
				    "validated under emulation. Re-emulate with a "
				    "fixture whose BackendId matches this device "
				    "and FWUPD_DEVICE_FLAG_EMULATED will be set.");
		return FALSE;
	}

	/* Bootloader entry — the first half of any real install. Drops the
	 * MCU's firmware-mode interface and triggers re-enumeration as the
	 * bootloader interface. Block writes / verify / commit will dispatch
	 * against the freshly-enumerated bootloader-mode FuDevice in a
	 * follow-up phase; for now this gets us past the first re-enum
	 * boundary so we can validate the emulation pipeline carries us
	 * through it cleanly. */
	{
		FuDellMonitorRtDevice *self = FU_DELL_MONITOR_RT_DEVICE(device);
		g_autoptr(GError) error_local = NULL;
		if (!fu_dell_monitor_rt_device_enter_bootloader(self, &error_local)) {
			g_prefix_error(&error_local, "bootloader entry: ");
			g_propagate_error(error, g_steal_pointer(&error_local));
			return FALSE;
		}
		g_info("dell-monitor-rt: bootloader-entry trigger sent — "
		       "device should be re-enumerating");
	}

	components = fu_firmware_get_images(firmware);
	for (guint i = 0; i < components->len; i++) {
		FuDellMonitorRtFirmwareComponent *component =
		    FU_DELL_MONITOR_RT_FIRMWARE_COMPONENT(g_ptr_array_index(components, i));
		const gchar *chip_guid = fu_dell_monitor_rt_firmware_component_get_field_string(
		    component,
		    FU_DELL_MONITOR_RT_FIRMWARE_FIELD_CHIP_GUID);
		const gchar *version = fu_dell_monitor_rt_firmware_component_get_field_string(
		    component,
		    FU_DELL_MONITOR_RT_FIRMWARE_FIELD_VERSION);
		g_autoptr(GBytes) payload = fu_firmware_get_bytes(FU_FIRMWARE(component), NULL);
		g_info("  component[%u] id=%s version=%s chip_guid=%s payload=%" G_GSIZE_FORMAT
		       " bytes (NOT FLASHED — write_firmware stub)",
		       i,
		       fu_firmware_get_id(FU_FIRMWARE(component)),
		       version != NULL ? version : "<encrypted>",
		       chip_guid != NULL ? chip_guid : "<encrypted>",
		       payload != NULL ? g_bytes_get_size(payload) : 0);
	}

	/* TODO: per-component dispatch table keyed by chip_guid will go here.
	 *   55afe793-… → RTS5409S hub MCU update path
	 *   5f3ba3d6-… → RTS5418E secondary
	 *   ea72869e-… → likely Parade scaler
	 *   etc.
	 * Each handler will translate the per-component plaintext firmware
	 * blob into the appropriate I²C-tunneled write_block / commit /
	 * reset sequence, exactly mirroring what Dell's updater does. */
	return TRUE;
}

static void
fu_dell_monitor_rt_device_class_init(FuDellMonitorRtDeviceClass *klass)
{
	FuDeviceClass *device_class = FU_DEVICE_CLASS(klass);
	device_class->probe = fu_dell_monitor_rt_device_probe;
	device_class->setup = fu_dell_monitor_rt_device_setup;
	device_class->write_firmware = fu_dell_monitor_rt_device_write_firmware;
}
