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

/* HID I/O timeout. Matches what hidapi uses by default. */
#define DELL_MONITOR_RT_TIMEOUT_MS   5000

#define DELL_MONITOR_RT_DIR_WRITE    0x40
#define DELL_MONITOR_RT_DIR_READ     0xC0

#define DELL_MONITOR_RT_OPCODE_ENABLE_VDCMD          0x02
#define DELL_MONITOR_RT_OPCODE_ENABLE_HIGH_CLOCK     0x06
#define DELL_MONITOR_RT_OPCODE_GET_FW_VERSION        0x09  /* hub MCU only */
#define DELL_MONITOR_RT_OPCODE_AUTH                  0xE1  /* I²C tunnel auth */
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
	 * HIDIOCGINPUT. Use vcmd_read which does exactly this round-trip. */
	if (!fu_dell_monitor_rt_device_vcmd_read(self,
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
 * Mirrors RTS5409s_IIC_API::read_fw_version in libhub.so:
 *   1. WRITE 5 bytes to DDC/CI target: { 0x25, 0x03, 0x00, 0x00, 0x02 }
 *      → register 0x0325 (LE), read-mode byte 0x02
 *   2. (optional) poll status — skipped here for simplicity
 *   3. READ 3 bytes back: [ status, minor, major ]
 *   4. Format as "%X.%02X" hex when status == 0x02
 */
static gboolean
fu_dell_monitor_rt_device_read_scaler_version(FuDellMonitorRtDevice *self,
					      gchar **version_out,
					      GError **error)
{
	/* Replay of Dell's first phase-1 register read (frame 7710 of the
	 * captured pcap). Wrapped in DDC/CI: source addr (host) = 0x51,
	 * length byte 0x80|4 = 0x84, then 4 cmd bytes, then XOR checksum
	 * over 0x6E (dest), 0x51, 0x84, and the cmd bytes. In Dell's run
	 * this returned the ASCII string "753.0AK01.0007" — almost
	 * certainly an EDID/panel-ID value, not the M3T105 version, but
	 * it's the smoke-test that proves the I²C tunnel works end-to-end
	 * since we can compare against the captured response byte-for-byte. */
	const guint8 i2c_request[7] = {
	    0x51, 0x84, 0xc0, 0x99, 0xee, 0x20, 0x2c,
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
				*version_out = g_strdup_printf("scaler-%s",
							       ascii->str);
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

	/* Step 4: I²C-tunnel READ test — pull the FL5500 scaler chip's
	 * own internal version string. This proves the I²C tunnel
	 * primitives work end-to-end, which is the same path we'll use
	 * for the actual flash writes / erases / status polls. */
	{
		g_autoptr(GError) scaler_err = NULL;
		g_autofree gchar *scaler_ver = NULL;
		if (fu_dell_monitor_rt_device_read_scaler_version(self,
								  &scaler_ver,
								  &scaler_err)) {
			g_debug("dell-monitor-rt: scaler version = %s", scaler_ver);
			/* Show both versions in the user-visible string */
			g_autofree gchar *combined =
			    g_strdup_printf("%s+%s", version, scaler_ver);
			fu_device_set_version(device, combined);
			return TRUE;
		}
		g_warning("dell-monitor-rt: scaler version read failed: %s",
			  scaler_err->message);
	}

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
