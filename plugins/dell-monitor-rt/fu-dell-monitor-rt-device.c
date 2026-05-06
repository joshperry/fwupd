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
#define DELL_MONITOR_RT_OPCODE_STAGE_FW              0xC8  /* load firmware chunk into RAM */
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

/* Per-frame i2c sub-command header for the downstream-MCU RAM loader.
 * Every 0xC6 frame in the HUB1/HUB2 stream begins with this prefix at
 * payload offset 0; the 64 bytes after are sequential firmware data. */
#define DELL_MONITOR_RT_I2C_LOADER_CMD     0x13
#define DELL_MONITOR_RT_I2C_LOADER_SUB     0x40
#define DELL_MONITOR_RT_I2C_LOADER_CHUNK   64
#define DELL_MONITOR_RT_I2C_LOADER_FRAME   (2 + DELL_MONITOR_RT_I2C_LOADER_CHUNK)

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
 * Read the user-facing package version (the "M3T105"-style string Dell
 * shows in its GUI) from the FL5500 scaler via DDC/CI tunnel.
 *
 * The chip exposes several VCP queries via the same 0xC0/0x99 vendor-
 * command pair, each selecting a different version field:
 *
 *   51 84 c0 99 cc 20 0e   → "753.0AK01.0007"   (scaler component ID)
 *   51 84 c0 99 ad 18 57   → "ISP#M3T105#"      (user-facing package ←)
 *   51 84 c0 99 ee 20 2c   → (other sub-version)
 *   51 84 c0 99 aa 14 5c   → (other sub-version)
 *   …
 *
 * We send the 0xAD selector — the response embeds the M3T105 between
 * '#' delimiters. After the post-update reload the same query returns
 * "CHK#M3T105#" instead of "ISP#M3T105#" (a different prefix marking
 * "the chip has confirmed the new firmware"); we strip either prefix
 * and surface the inner version unchanged.
 *
 * Verified against captures/u4025qw-update-recap-20260502-185321.pcapng:
 * Dell's binary issues this exact 51 84 c0 99 ad 18 57 frame and reads
 * back 51 99 c0 55 ad 23 49 53 50 23 4d 33 54 31 30 35 23 …
 * (ASCII "…ISP#M3T105#…").
 *
 * Note: the response opcode is 0xC0 here, not 0xC1 as for the 0xCC
 * selector — the existing parser's strict 0xC1 check would reject this
 * reply, so we accept both response opcodes.
 */
static gboolean
fu_dell_monitor_rt_device_read_scaler_version(FuDellMonitorRtDevice *self,
					      gchar **version_out,
					      GError **error)
{
	/* Wire layout (DDC/CI):
	 *   51 84 c0 99 ad 18 57
	 *   │  │  └─────┬────┘ │
	 *   │  │       cmd     XOR-checksum over 0x6E (dest) || all preceding
	 *   │  length: 0x80 | (number of cmd bytes = 4)
	 *   src addr (host = 0x51)
	 *
	 * Frame 188 of captures/u4025qw-update-recap-20260502-185321.pcapng. */
	const guint8 i2c_request[7] = {
	    0x51, 0x84, 0xc0, 0x99, 0xad, 0x18, 0x57,
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

	{
		const guint8 *wire = &response[1]; /* skip report-ID prefix */
		gsize len;
		g_autoptr(GString) ascii = NULL;
		const gchar *prefix;

		if (wire[0] != 0x51 || (wire[1] & 0x80) == 0 ||
		    (wire[2] != 0xC0 && wire[2] != 0xC1)) {
			g_set_error(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_READ,
				    "scaler-version DDC/CI reply malformed: "
				    "wire[0..3]=%02X %02X %02X %02X",
				    wire[0], wire[1], wire[2], wire[3]);
			return FALSE;
		}

		/* DDC/CI: byte 1 low 7 bits = number of payload bytes
		 * (opcode + sub + data, *not* including checksum). Data
		 * runs from byte 4 onward (after src/len/op/sub). */
		len = (wire[1] & 0x7F);
		if (len < 2 || len >= 60) {
			g_set_error(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_READ,
				    "scaler-version DDC/CI reply has bad length 0x%02x",
				    (unsigned)wire[1]);
			return FALSE;
		}

		/* Build a printable-ASCII view of the data area, including
		 * '#' delimiters. The response has a small fixed header
		 * (e.g. 55 ad 23) followed by '#'-delimited fields like
		 *   ISP#M3T105#
		 *   CHK#M3T105#   (post-update variant)
		 * We extract the version field by finding the prefix tag
		 * and taking everything up to the next '#'. */
		ascii = g_string_new(NULL);
		for (gsize i = 4; i < (gsize)(len + 2) && i < 60; i++) {
			if (wire[i] >= 0x20 && wire[i] < 0x7f)
				g_string_append_c(ascii, (gchar)wire[i]);
		}

		prefix = strstr(ascii->str, "ISP#");
		if (prefix == NULL)
			prefix = strstr(ascii->str, "CHK#");
		if (prefix != NULL) {
			const gchar *value = prefix + 4;
			const gchar *end = strchr(value, '#');
			if (end != NULL && end > value) {
				*version_out = g_strndup(value, end - value);
				return TRUE;
			}
		}

		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_READ,
			    "scaler-version reply did not contain ISP#…# or CHK#…# "
			    "version field; ascii=%s",
			    ascii->str);
		return FALSE;
	}
}

/*
 * Read the panel id from the FL5500 scaler via DDC/CI VCP 0xEE.
 *
 * Each panel SKU gets its own scaler firmware build, so the scaler's
 * firmware ID uniquely names the panel. The .upg's panel-binding
 * metadata uses this exact string as the key for panel-bound
 * components (DISPLAY in our test bundle): a component with
 * panel_bound: true and panel_id: 753.0AK01.0007 means "this entry
 * is the panel-specific firmware for monitors whose scaler reports
 * 753.0AK01.0007". A connected monitor whose scaler reports a
 * different string isn't supported by this .upg — flashing
 * panel-bound firmware to the wrong panel would brick it.
 *
 * Wire layout (DDC/CI):
 *   51 84 c0 99 ee 20 2c
 *   │  │  └─────┬────┘ │
 *   │  │       cmd     XOR-checksum over 0x6E (dest) || all preceding
 *   │  length: 0x80 | (number of cmd bytes = 4)
 *   src addr (host = 0x51)
 *
 * Reply (16 ASCII bytes between header and checksum, no '#'
 * delimiters):
 *   51 90 c1 99 37 35 33 2e 30 41 4b 30 31 2e 30 30 30 37 c4
 *                 7  5  3  .  0  A  K  0  1  .  0  0  0  7
 *
 * Verified against captures/u4025qw-update-recap-20260502-185321.pcapng.
 */
static gboolean
fu_dell_monitor_rt_device_read_panel_id(FuDellMonitorRtDevice *self,
					gchar **panel_id_out,
					GError **error)
{
	const guint8 i2c_request[7] = {
	    0x51, 0x84, 0xc0, 0x99, 0xee, 0x20, 0x2c,
	};
	guint8 response[DELL_MONITOR_RT_BUF_SIZE] = {0};
	guint8 hub_key[8];

	fu_dell_monitor_rt_get_synkey(DELL_MONITOR_RT_U4025QW_SYNKEY_SEED,
				      sizeof(DELL_MONITOR_RT_U4025QW_SYNKEY_SEED),
				      hub_key);
	if (!fu_dell_monitor_rt_device_handshake(self, hub_key, error))
		return FALSE;
	if (!fu_dell_monitor_rt_device_i2c_write(self,
						 DELL_MONITOR_RT_I2C_TARGET_DDCCI,
						 i2c_request,
						 sizeof(i2c_request),
						 error))
		return FALSE;
	g_usleep(50 * 1000);
	if (!fu_dell_monitor_rt_device_i2c_read(self,
						DELL_MONITOR_RT_I2C_TARGET_DDCCI,
						0x40,
						response,
						sizeof(response),
						error))
		return FALSE;

	{
		const guint8 *wire = &response[1]; /* skip report-ID prefix */
		gsize len;
		g_autoptr(GString) ascii = NULL;

		if (wire[0] != 0x51 || (wire[1] & 0x80) == 0 ||
		    (wire[2] != 0xC0 && wire[2] != 0xC1)) {
			g_set_error(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_READ,
				    "panel-id DDC/CI reply malformed: "
				    "wire[0..3]=%02X %02X %02X %02X",
				    wire[0], wire[1], wire[2], wire[3]);
			return FALSE;
		}
		len = (wire[1] & 0x7F);
		if (len < 2 || len >= 60) {
			g_set_error(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_READ,
				    "panel-id DDC/CI reply has bad length 0x%02x",
				    (unsigned)wire[1]);
			return FALSE;
		}

		/* Data area starts at byte 4 (after src/len/op/sub) and runs
		 * for (len - 2) bytes. The reply has no '#' delimiters — the
		 * panel id is the contiguous printable-ASCII run. */
		ascii = g_string_new(NULL);
		for (gsize i = 4; i < (gsize)(len + 2) && i < 60; i++) {
			if (wire[i] >= 0x20 && wire[i] < 0x7f)
				g_string_append_c(ascii, (gchar)wire[i]);
			else if (ascii->len > 0)
				break; /* end of ASCII run */
		}

		if (ascii->len == 0) {
			g_set_error_literal(error,
					    FWUPD_ERROR,
					    FWUPD_ERROR_READ,
					    "panel-id reply contained no printable ASCII");
			return FALSE;
		}
		*panel_id_out = g_strdup(ascii->str);
		return TRUE;
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

	/* Secondary HID-B (DEV_1101) shares the FuDellMonitorRtDevice GType
	 * with the primary HID-A (DEV_1100), but a different hidraw fd onto
	 * a different MCU. The captured trace shows the secondary doesn't
	 * receive enable_vdcmd / cal_auth / DDC version probe before its c8
	 * staging — Dell's binary just opens its hidraw and starts pushing
	 * 0xC8 frames. So setup() on the secondary is a no-op apart from
	 * stamping a placeholder version (the user-facing version belongs
	 * to the primary; the secondary is updatable-hidden in the quirk).
	 * The plugin's device_registered hook pairs them as parent/child so
	 * the primary's write_firmware can find this device and call
	 * fu_dell_monitor_rt_device_stage_isp_firmware against it. */
	if (fu_device_get_pid(device) == 0x1101) {
		fu_device_set_version(device, "secondary");
		return TRUE;
	}

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

	/* Step 3: read the user-facing package version (e.g. "M3T105") via
	 * a DDC/CI request to the FL5500 scaler. Dell's binary issues VCP
	 * selector 0xAD (51 84 c0 99 ad 18 57 to target 0x6E) which returns
	 * "ISP#M3T105#" — the same string Dell's UI shows. We previously
	 * read selector 0xCC which returns "753.0AK01.0007" (the scaler
	 * component's firmware ID, NOT the user-facing version), so the
	 * surfaced device version was misleading.
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
/*
 * Stage the ISP shim firmware into the upstream-hub MCU's RAM ahead of
 * the bootloader-entry trigger. After 0xE9 the chip jumps into this
 * staged code; without staging there's no flash-write code resident
 * and 0xE9 just causes a clean reset.
 *
 * Wire transport — recovered from the recap pcap and matched bytewise
 * against the decrypted .upg HUB component (see PLUGIN_NOTES "0x40 C8
 * — host-to-device firmware staging"). Each frame carries 128 bytes of
 * 8051 code with this layout:
 *
 *   wire offset 0  : 0x40 (DIR_WRITE)
 *   wire offset 1  : 0xC8 (STAGE_FW opcode)
 *   wire offset 2  : flag — 0x00 = lower half of 256-byte block,
 *                           0x80 = upper half
 *   wire offset 3  : addr — 256-byte block index, 0..255
 *   wire offset 4-5: zero
 *   wire offset 6  : 0x80 (payload length = 128 = sizeof high half)
 *   wire offset 7  : zero
 *   wire offset 8-63 : zero pad
 *   wire offset 64-191: 128 bytes of firmware data
 *
 * Iteration order matches Dell's binary: addr 0 lo half, addr 0 hi
 * half, addr 1 lo, addr 1 hi, ..., addr 255 hi half. 256 addresses ×
 * 2 halves = 512 SET_REPORTs to load a full 64 KB blob.
 *
 * The blob argument must be exactly 64 KB (= the size of the .upg's
 * HUB component for the U4025QW's primary RTS5409S hub MCU). Other
 * chips and other monitors will need different blobs sourced from
 * different .upg components.
 */
#define DELL_MONITOR_RT_STAGE_FW_BANK_SIZE   (64 * 1024)
#define DELL_MONITOR_RT_STAGE_FW_CHUNK_SIZE  128
#define DELL_MONITOR_RT_STAGE_FW_DATA_OFFSET 64    /* wire-byte offset of payload */
#define DELL_MONITOR_RT_STAGE_FW_BANK_OFFSET 4     /* wire-byte offset of bank/pass selector */

/*
 * Stream an ephemeral ISP shim into a downstream MCU's RAM via the i2c
 * tunnel (opcode 0xC6). Used for HUB1 → 0xD4 and HUB2 → 0xD6 — both
 * fire BEFORE bootloader entry, both go through HID-A. Each frame
 * carries `DELL_MONITOR_RT_I2C_LOADER_CMD/SUB` (0x13 0x40) followed by
 * `DELL_MONITOR_RT_I2C_LOADER_CHUNK` (64) bytes of sequential firmware
 * data. Verified bytewise against the captured pcap: HUB1.fw is the
 * concatenation of 2048 such 64-byte chunks, HUB2.fw is 1024 chunks.
 *
 * The single cal_auth handshake performed by our caller covers the
 * entire blob — Dell's binary doesn't refresh between chunks within a
 * single blob (only between blobs and around setup). The downstream
 * MCU acks each chunk via 0xD6 status read in the captured trace, but
 * we omit the polling reads here: the emulator leapfrogs past unmatched
 * read events, and on real hardware we expect the writes to be flow-
 * controlled by the HID transport itself (each SET_REPORT blocks until
 * the chip drains its buffer).
 */
static gboolean
fu_dell_monitor_rt_device_stage_downstream_mcu(FuDellMonitorRtDevice *self,
					       guint8 i2c_target,
					       GBytes *blob,
					       FuProgress *progress,
					       GError **error)
{
	const guint8 *blob_data;
	gsize blob_size;
	guint nchunks;

	blob_data = g_bytes_get_data(blob, &blob_size);
	if (blob_size == 0 ||
	    blob_size % DELL_MONITOR_RT_I2C_LOADER_CHUNK != 0) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_DATA,
			    "downstream-MCU blob size %" G_GSIZE_FORMAT
			    " not a multiple of %u",
			    blob_size,
			    DELL_MONITOR_RT_I2C_LOADER_CHUNK);
		return FALSE;
	}
	nchunks = (guint)(blob_size / DELL_MONITOR_RT_I2C_LOADER_CHUNK);

	if (progress != NULL)
		fu_progress_set_steps(progress, nchunks);

	for (guint i = 0; i < nchunks; i++) {
		guint8 frame[DELL_MONITOR_RT_I2C_LOADER_FRAME];

		frame[0] = DELL_MONITOR_RT_I2C_LOADER_CMD;
		frame[1] = DELL_MONITOR_RT_I2C_LOADER_SUB;
		memcpy(&frame[2],
		       blob_data + (i * DELL_MONITOR_RT_I2C_LOADER_CHUNK),
		       DELL_MONITOR_RT_I2C_LOADER_CHUNK);

		if (!fu_dell_monitor_rt_device_i2c_write(self,
							 i2c_target,
							 frame,
							 sizeof(frame),
							 error)) {
			g_prefix_error(error,
				       "downstream-MCU stage to 0x%02x failed at chunk %u/%u: ",
				       i2c_target,
				       i,
				       nchunks);
			return FALSE;
		}

		if (progress != NULL)
			fu_progress_step_done(progress);
	}
	return TRUE;
}

/*
 * Stage a 64-KB-aligned ISP shim blob into the device's RAM via the
 * 0xC8 STAGE_FW opcode. Walks the blob in 64 KB banks; each bank
 * iterates addr 0..255 × half 0/0x80, with the bank index placed at
 * wire offset 4 (verified against HID-B's HUB4 staging — pass-1 frames
 * carry bank=0, pass-2 frames carry bank=1, otherwise byte-identical
 * frame structure to HID-A's HUB staging).
 *
 * Sizes seen on the U4025QW:
 *   HUB  (HID-A primary)    64 KB →  1 bank ×  512 frames
 *   HUB4 (HID-B secondary) 128 KB →  2 banks × 512 frames = 1024 frames
 */
gboolean
fu_dell_monitor_rt_device_stage_isp_firmware(FuDellMonitorRtDevice *self,
					     GBytes *blob,
					     FuProgress *progress,
					     GError **error)
{
	const guint8 *blob_data;
	gsize blob_size;
	guint nbanks;

	g_return_val_if_fail(FU_IS_DELL_MONITOR_RT_DEVICE(self), FALSE);
	g_return_val_if_fail(blob != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	blob_data = g_bytes_get_data(blob, &blob_size);
	if (blob_size == 0 || blob_size % DELL_MONITOR_RT_STAGE_FW_BANK_SIZE != 0) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_DATA,
			    "ISP shim blob is %" G_GSIZE_FORMAT " bytes, must be a multiple of %u",
			    blob_size,
			    DELL_MONITOR_RT_STAGE_FW_BANK_SIZE);
		return FALSE;
	}
	nbanks = (guint)(blob_size / DELL_MONITOR_RT_STAGE_FW_BANK_SIZE);

	if (progress != NULL)
		fu_progress_set_steps(progress, nbanks * 256);

	for (guint bank = 0; bank < nbanks; bank++) {
		gsize bank_off = bank * DELL_MONITOR_RT_STAGE_FW_BANK_SIZE;
		for (guint addr = 0; addr < 256; addr++) {
			for (guint half = 0; half < 2; half++) {
				guint8 buf[DELL_MONITOR_RT_BUF_SIZE] = {0};
				gsize blob_off = bank_off + (addr * 256) + (half * 128);
				guint8 flag = (half == 0) ? 0x00 : 0x80;

				buf[1 + 0] = DELL_MONITOR_RT_DIR_WRITE;
				buf[1 + 1] = DELL_MONITOR_RT_OPCODE_STAGE_FW;
				buf[1 + 2] = flag;
				buf[1 + 3] = (guint8)addr;
				buf[1 + DELL_MONITOR_RT_STAGE_FW_BANK_OFFSET] = (guint8)bank;
				buf[1 + 6] = DELL_MONITOR_RT_STAGE_FW_CHUNK_SIZE;
				memcpy(&buf[1 + DELL_MONITOR_RT_STAGE_FW_DATA_OFFSET],
				       blob_data + blob_off,
				       DELL_MONITOR_RT_STAGE_FW_CHUNK_SIZE);

				if (!fu_hidraw_device_set_report(FU_HIDRAW_DEVICE(self),
								 buf,
								 sizeof(buf),
								 FU_IO_CHANNEL_FLAG_USE_BLOCKING_IO,
								 error)) {
					g_prefix_error(error,
						       "stage-fw failed at bank=%u addr=0x%02x half=0x%02x: ",
						       bank,
						       addr,
						       flag);
					return FALSE;
				}
			}
			if (progress != NULL)
				fu_progress_step_done(progress);
		}
	}
	return TRUE;
}

gboolean
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
 * Per-component pre-bootloader staging route. The .upg's metadata
 * tells us where each component's bytes go; we don't hardcode by id.
 *
 *   usb_pid       which USB-connected device the chip lives behind:
 *                  - 0x1100 = primary HID-A
 *                  - 0x1101 = secondary HID-B
 *
 *   i2c_or_index  what to do once we've picked the device:
 *                  - 0xD0..0xFF: 8-bit i2c slave address of a
 *                    downstream MCU sitting on the primary chip's
 *                    internal i2c bus, streamed via opcode 0xC6
 *                    (HUB1=0xD4, HUB2=0xD6 verified). Lower-but-still-
 *                    high values like PDC's 0x21 are *not* this kind
 *                    of i2c slave — they live on a different bus or
 *                    flow through a post-bootloader path we haven't
 *                    decoded, so we leave them unrouted.
 *                  - 0x01..0x0F: chip-internal slot index for direct
 *                    RAM staging via opcode 0xC8 (HUB=1, HUB4=2
 *                    verified).
 *                  - 0x00 or 0x10..0xCF: unrouted (post-bootloader
 *                    payload, scaler, etc. — those flow through a
 *                    different path that's not implemented yet).
 *
 *   target        For I2C_TUNNEL routes the i2c bus is on the primary,
 *                 so target is always the primary regardless of which
 *                 child the metadata's usb_pid points at. For
 *                 DIRECT_STAGE routes target is the device whose
 *                 fu_device_get_pid() matches usb_pid (self for the
 *                 primary, a paired child for the secondary).
 */
typedef enum {
	FU_DELL_MONITOR_RT_ROUTE_NONE,
	FU_DELL_MONITOR_RT_ROUTE_I2C_TUNNEL,
	FU_DELL_MONITOR_RT_ROUTE_DIRECT_STAGE,
} FuDellMonitorRtRouteKind;

/*
 * Per-chip-class protocol handler. Modeled after libhub.so's class
 * hierarchy (Rts5409s_ISP / Rts5418e_ISP / Rts5409s_IIC_ISP /
 * PS5512_ISP / Mchp58xx_72xx_ISP / FL5500_IIC_ISP / …) — each chip
 * family Dell talks to has its own set of pre-stage and stage
 * primitives. We mirror the dispatch with function pointers keyed by
 * the .upg's chip_guid_alt field, which encodes the *target* chip
 * class (vs chip_guid which encodes the *transport* chip).
 *
 *   arm_target  Called once per (target_device, this proto) before
 *               the first stage_blob lands on `target`. Issues any
 *               chip-mode prep — for the RTS540x family that's the
 *               enable_vdcmd sub=3 + 0xE8 sequence Dell does
 *               immediately before its first c8 frame on each chip;
 *               for the downstream-MCU class it's a no-op.
 *
 *   stage_blob  Stage one component's bytes onto the target. The
 *               route carries the i2c slave (for I2C_TUNNEL kinds)
 *               or the chip-internal slot index (DIRECT_STAGE).
 */
typedef struct _FuDellMonitorRtChipProto FuDellMonitorRtChipProto;
typedef struct _FuDellMonitorRtRoute FuDellMonitorRtRoute;

struct _FuDellMonitorRtChipProto {
	const gchar *name;
	const gchar *chip_guid_alt;
	gboolean (*arm_target)(FuDellMonitorRtDevice *target, GError **error);
	gboolean (*stage_blob)(FuDellMonitorRtDevice *target,
			       const FuDellMonitorRtRoute *route,
			       GBytes *blob,
			       GError **error);
};

struct _FuDellMonitorRtRoute {
	FuDellMonitorRtRouteKind kind;
	FuDellMonitorRtDevice *target;
	guint16 usb_pid;
	guint8 i2c_target;
	const gchar *chip_guid_alt;	   /* metadata, kept for diagnostics */
	const FuDellMonitorRtChipProto *proto; /* NULL if class is unhandled */
};

/* Downstream-MCU i2c slaves we've decoded sit at 0xD0+ on the primary's
 * internal i2c bus. Smaller values like PDC's 0x21 are some other kind
 * of routing tag we haven't decoded — treat them as unrouted rather
 * than mis-route into the i2c tunnel. */
#define DELL_MONITOR_RT_I2C_SLAVE_MIN  0xD0
/* Chip-internal slot indices for direct 0xC8 staging. We've verified
 * HUB=1, HUB4=2; 0 and 0x10..0xCF are something else. */
#define DELL_MONITOR_RT_DIRECT_INDEX_MIN 0x01
#define DELL_MONITOR_RT_DIRECT_INDEX_MAX 0x0F

/* ----- chip-protocol handlers --------------------------------------
 *
 * Each handler implements arm_target + stage_blob for one chip class.
 * Modeled after libhub.so's per-chip ISP classes (Rts5409s_ISP /
 * Rts5418e_ISP / Rts5409s_IIC_ISP / …) — they share a virtual
 * interface; we share a function-pointer struct.
 */

/*
 * RTS5409s/RTS5418E hub MCU class (chip_guid_alt 55afe793-…).
 *
 * arm_target sequence — observed exactly twice in the recap pcap, once
 * per chip, immediately before the first c8 frame on each:
 *
 *   40 02 03 00 …    enable_vdcmd sub=0x03  (mode-switch into c8-stage
 *                                             allowed mode; setup()
 *                                             only does sub=0x01)
 *   40 e8 00 01 …    0xE8 sub=0x00 arg=0x01 (arm c8-staging engine —
 *                                             undocumented opcode, no
 *                                             other occurrence in the
 *                                             880k-frame trace)
 *
 * Without this prep on real hardware the chip's c8 handler is likely
 * to either reject the staging frames or stage them somewhere we
 * don't expect. Under emulation the leapfrog matcher hides the
 * problem because the requested c8 frames just match later positions
 * in the captured stream — but the wire bytes are missing.
 */
static gboolean
fu_dell_monitor_rt_proto_rts540x_arm(FuDellMonitorRtDevice *target, GError **error)
{
	const guint8 vendor_sig[2] = {DELL_MONITOR_RT_VENDOR_SIG_LO,
				      DELL_MONITOR_RT_VENDOR_SIG_HI};
	/* enable_vdcmd carries the RealTek vendor ID in its payload — the
	 * chip uses it as a "you may have noticed I'm a vendor command"
	 * sanity check. sub=3 unlocks c8 staging mode (vs sub=1 which is
	 * basic vendor-cmd enable). */
	if (!fu_dell_monitor_rt_device_vcmd(target,
					    DELL_MONITOR_RT_DIR_WRITE,
					    DELL_MONITOR_RT_OPCODE_ENABLE_VDCMD,
					    0x03,
					    0x00,
					    vendor_sig,
					    sizeof(vendor_sig),
					    error)) {
		g_prefix_error(error, "rts540x arm enable_vdcmd sub=3: ");
		return FALSE;
	}
	/* 0xE8 sub=0 arg=1 — undocumented opcode that arms the c8-staging
	 * engine. Only two occurrences in the entire 880k-frame trace,
	 * one per chip, immediately before its first c8 frame. */
	if (!fu_dell_monitor_rt_device_vcmd(target,
					    DELL_MONITOR_RT_DIR_WRITE,
					    0xE8,
					    0x00,
					    0x01,
					    NULL,
					    0,
					    error)) {
		g_prefix_error(error, "rts540x arm 0xE8: ");
		return FALSE;
	}
	return TRUE;
}

static gboolean
fu_dell_monitor_rt_proto_rts540x_stage(FuDellMonitorRtDevice *target,
				       const FuDellMonitorRtRoute *route,
				       GBytes *blob,
				       GError **error)
{
	(void)route; /* DIRECT_STAGE — the route's i2c_target is unused */
	return fu_dell_monitor_rt_device_stage_isp_firmware(target, blob, NULL, error);
}

/*
 * Downstream-MCU class (chip_guid_alt 5f3ba3d6-…).
 *
 * The chip we're talking *to* is the primary (i2c bus is on it); the
 * actual MCU receiving these bytes isn't a USB device. arm_target is
 * a no-op because the primary is already in vendor-cmd mode from
 * setup(); the per-blob cal_auth happens in stage_blob since the auth
 * ticket is per-blob in Dell's binary too.
 *
 * Modeled after libhub.so::Rts5409s_IIC_ISP — same chip class as the
 * RTS540x but speaking the IIC variant of the ISP.
 */
static gboolean
fu_dell_monitor_rt_proto_dsmcu_arm(FuDellMonitorRtDevice *target, GError **error)
{
	(void)target;
	(void)error;
	return TRUE;
}

static gboolean
fu_dell_monitor_rt_proto_dsmcu_stage(FuDellMonitorRtDevice *target,
				     const FuDellMonitorRtRoute *route,
				     GBytes *blob,
				     GError **error)
{
	guint8 hub_key[8];

	fu_dell_monitor_rt_get_synkey(DELL_MONITOR_RT_U4025QW_SYNKEY_SEED,
				      sizeof(DELL_MONITOR_RT_U4025QW_SYNKEY_SEED),
				      hub_key);
	if (!fu_dell_monitor_rt_device_handshake(target, hub_key, error))
		return FALSE;
	return fu_dell_monitor_rt_device_stage_downstream_mcu(target,
							      route->i2c_target,
							      blob,
							      NULL,
							      error);
}

/*
 * Chip-protocol registry. Adding a new chip class for a future Dell
 * monitor (Parade scaler, Microchip dock controller, …) is a matter
 * of decoding its protocol from libhub.so's matching ISP class and
 * appending an entry here.
 */
static const FuDellMonitorRtChipProto FU_DELL_MONITOR_RT_CHIP_PROTOS[] = {
    {
	.name = "RTS5409s/RTS5418E hub MCU (c8 RAM stage)",
	.chip_guid_alt = "55afe793-98e8-470e-ad09-993be2b3b016",
	.arm_target = fu_dell_monitor_rt_proto_rts540x_arm,
	.stage_blob = fu_dell_monitor_rt_proto_rts540x_stage,
    },
    {
	.name = "Downstream MCU (i2c-tunnel RAM loader)",
	.chip_guid_alt = "5f3ba3d6-a0bd-4270-9938-814a45d5c824",
	.arm_target = fu_dell_monitor_rt_proto_dsmcu_arm,
	.stage_blob = fu_dell_monitor_rt_proto_dsmcu_stage,
    },
};

static const FuDellMonitorRtChipProto *
fu_dell_monitor_rt_proto_lookup(const gchar *chip_guid_alt)
{
	if (chip_guid_alt == NULL)
		return NULL;
	for (gsize i = 0; i < G_N_ELEMENTS(FU_DELL_MONITOR_RT_CHIP_PROTOS); i++) {
		if (g_strcmp0(FU_DELL_MONITOR_RT_CHIP_PROTOS[i].chip_guid_alt,
			      chip_guid_alt) == 0)
			return &FU_DELL_MONITOR_RT_CHIP_PROTOS[i];
	}
	return NULL;
}

static FuDellMonitorRtDevice *
fu_dell_monitor_rt_device_find_target_by_pid(FuDellMonitorRtDevice *self, guint16 pid)
{
	GPtrArray *children;
	if (fu_device_get_pid(FU_DEVICE(self)) == pid)
		return self;
	children = fu_device_get_children(FU_DEVICE(self));
	for (guint i = 0; children != NULL && i < children->len; i++) {
		FuDevice *child = g_ptr_array_index(children, i);
		if (FU_IS_DELL_MONITOR_RT_DEVICE(child) &&
		    fu_device_get_pid(child) == pid) {
			return FU_DELL_MONITOR_RT_DEVICE(child);
		}
	}
	return NULL;
}

static gboolean
fu_dell_monitor_rt_route_for_component(FuDellMonitorRtDevice *self,
				       FuDellMonitorRtFirmwareComponent *component,
				       FuDellMonitorRtRoute *route_out)
{
	const gchar *usb_pid_str;
	const gchar *i2c_str;
	const gchar *chip_guid_alt;
	guint64 usb_pid_val = 0;
	guint64 i2c_val = 0;

	memset(route_out, 0, sizeof(*route_out));
	usb_pid_str = fu_dell_monitor_rt_firmware_component_get_field_string(
	    component, FU_DELL_MONITOR_RT_FIRMWARE_FIELD_USB_PID);
	i2c_str = fu_dell_monitor_rt_firmware_component_get_field_string(
	    component, FU_DELL_MONITOR_RT_FIRMWARE_FIELD_I2C_OR_INDEX);
	chip_guid_alt = fu_dell_monitor_rt_firmware_component_get_field_string(
	    component, FU_DELL_MONITOR_RT_FIRMWARE_FIELD_CHIP_GUID_ALT);
	route_out->chip_guid_alt = chip_guid_alt;
	route_out->proto = fu_dell_monitor_rt_proto_lookup(chip_guid_alt);

	if (usb_pid_str == NULL || i2c_str == NULL)
		return FALSE;
	if (!fu_strtoull(usb_pid_str, &usb_pid_val, 0, 0xFFFF, FU_INTEGER_BASE_AUTO, NULL))
		return FALSE;
	if (!fu_strtoull(i2c_str, &i2c_val, 0, 0xFF, FU_INTEGER_BASE_AUTO, NULL))
		return FALSE;
	route_out->usb_pid = (guint16)usb_pid_val;

	if (i2c_val >= DELL_MONITOR_RT_I2C_SLAVE_MIN) {
		/* The i2c bus we'd tunnel onto belongs to the primary,
		 * regardless of which usb-pid the metadata names — the
		 * downstream MCU isn't on the bus as a USB device. */
		route_out->kind = FU_DELL_MONITOR_RT_ROUTE_I2C_TUNNEL;
		route_out->target = fu_dell_monitor_rt_device_find_target_by_pid(self, 0x1100);
		route_out->i2c_target = (guint8)i2c_val;
		return route_out->target != NULL;
	}

	if (i2c_val >= DELL_MONITOR_RT_DIRECT_INDEX_MIN &&
	    i2c_val <= DELL_MONITOR_RT_DIRECT_INDEX_MAX) {
		route_out->kind = FU_DELL_MONITOR_RT_ROUTE_DIRECT_STAGE;
		route_out->target =
		    fu_dell_monitor_rt_device_find_target_by_pid(self, route_out->usb_pid);
		return route_out->target != NULL;
	}

	/* Out-of-range value: post-bootloader payload, scaler, or some
	 * other routing tag we haven't decoded yet. Leave NONE. */
	return TRUE;
}

/*
 * Stage one component along its computed route. For i2c-tunnel routes
 * the caller is responsible for issuing a cal_auth handshake before
 * calling — we don't bundle that here because the auth ticket can
 * legitimately span multiple components and the caller has the
 * better view of when to refresh.
 */
/*
 * Stage one component along its computed route, dispatching via the
 * route's chip-protocol handler. The handler covers any chip-mode
 * prep + the per-blob wire sequence; the caller is responsible for
 * having already called `arm_target` once per (target, proto). A
 * NULL route->proto means we ran without pre-validation and is a
 * programming error — the validation pass at the top of write_firmware
 * is what should have failed first.
 */
static gboolean
fu_dell_monitor_rt_device_stage_along_route(const FuDellMonitorRtRoute *route,
					    GBytes *blob,
					    GError **error)
{
	if (route->proto == NULL) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_INTERNAL,
				    "stage_along_route called without a chip-protocol "
				    "handler — pre-validation should have rejected this");
		return FALSE;
	}
	return route->proto->stage_blob(route->target, route, blob, error);
}

/*
 * write_firmware — metadata-driven pre-bootloader staging.
 *
 * Walks every component in the .upg, classifies each by its
 * (usb_pid, i2c_or_index) metadata, and dispatches in three passes
 * matching the order Dell's binary uses:
 *
 *   1. i2c-tunnel components (e.g. HUB1 → 0xD4, HUB2 → 0xD6) staged
 *      on the primary's internal i2c bus, each preceded by a fresh
 *      cal_auth handshake.
 *   2. direct-stage components on each non-primary USB-connected
 *      device (e.g. HUB4 on the secondary), followed by that
 *      device's bootloader-entry trigger.
 *   3. direct-stage components on the primary (e.g. HUB), followed
 *      by the primary's bootloader-entry trigger.
 *
 * No component IDs are hardcoded — adding a new component to a future
 * .upg with appropriate usb_pid + i2c_or_index metadata routes
 * automatically. Components whose metadata classifies as NONE (post-
 * bootloader payloads, scalers, …) are left for a later phase.
 *
 * Status: pre-bootloader steps replay byte-for-byte against the
 * captured Dell-binary trace under emulation. Post-bootloader (the
 * 0x40 F1 block-write phase) is not yet implemented.
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

	g_info("dell-monitor-rt: write_firmware — product=%s fw_version=%s",
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

	/* Pre-validation — walk every component, classify, and bail
	 * BEFORE any IO if any routable component's chip class is
	 * unhandled. Components with route.kind == NONE (post-bootloader
	 * scaler payloads etc.) skip the check; we don't write to them
	 * anyway. The "fail hard before writes" property is the whole
	 * point of this pass. */
	{
		FuDellMonitorRtDevice *self = FU_DELL_MONITOR_RT_DEVICE(device);

		components = fu_firmware_get_images(firmware);
		for (guint i = 0; i < components->len; i++) {
			FuDellMonitorRtFirmwareComponent *component =
			    FU_DELL_MONITOR_RT_FIRMWARE_COMPONENT(
				g_ptr_array_index(components, i));
			FuDellMonitorRtRoute route = {0};

			if (!fu_dell_monitor_rt_route_for_component(self, component, &route))
				continue;
			if (route.kind == FU_DELL_MONITOR_RT_ROUTE_NONE)
				continue;
			if (route.proto != NULL)
				continue;
			g_set_error(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_NOT_SUPPORTED,
				    "dell-monitor-rt: refusing to install — component "
				    "'%s' has chip_guid_alt=%s which has no registered "
				    "protocol handler. We don't know how to safely talk "
				    "to that chip class. Add a handler to "
				    "FU_DELL_MONITOR_RT_CHIP_PROTOS[] or rebuild the "
				    ".upg without that component.",
				    fu_firmware_get_id(FU_FIRMWARE(component)),
				    route.chip_guid_alt != NULL ? route.chip_guid_alt
								: "<missing>");
			return FALSE;
		}
	}

	/* Track which (target, proto) pairs have been armed. Keys are
	 * "<device-id>|<proto-name>" strings. Hash table owns the keys. */
	{
		FuDellMonitorRtDevice *self = FU_DELL_MONITOR_RT_DEVICE(device);
		guint16 primary_pid = fu_device_get_pid(device);
		g_autoptr(GHashTable) armed =
		    g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
		g_autoptr(GHashTable) triggered =
		    g_hash_table_new(g_direct_hash, g_direct_equal);

		/* The three passes match Dell's observed order:
		 *
		 *   Pass 1 — every i2c-tunnel component. The proto's stage_blob
		 *            does its own per-blob cal_auth.
		 *   Pass 2 — every direct-stage component whose target is NOT
		 *            the primary, followed by that target's 0xE9. Dell
		 *            fires the secondary's 0xE9 before the primary's,
		 *            so we drain non-primary devices first.
		 *   Pass 3 — every direct-stage component whose target IS the
		 *            primary, then the primary's 0xE9. After this pass
		 *            the primary's firmware-mode hidraw fd becomes
		 *            invalid; the post-bootloader flash phase runs
		 *            against a freshly re-enumerated FuDevice and is
		 *            not yet implemented.
		 */
		for (guint pass = 0; pass < 3; pass++) {
			components = fu_firmware_get_images(firmware);
			for (guint i = 0; i < components->len; i++) {
				FuDellMonitorRtFirmwareComponent *component =
				    FU_DELL_MONITOR_RT_FIRMWARE_COMPONENT(
					g_ptr_array_index(components, i));
				FuDellMonitorRtRoute route = {0};
				g_autoptr(GBytes) blob = NULL;
				g_autoptr(GError) error_local = NULL;
				g_autofree gchar *arm_key = NULL;
				const gchar *id;

				if (!fu_dell_monitor_rt_route_for_component(self, component,
									    &route))
					continue;
				if (route.kind == FU_DELL_MONITOR_RT_ROUTE_NONE)
					continue;
				if (route.target == NULL) {
					g_warning("dell-monitor-rt: %s wants chip class %s on "
						  "pid 0x%04x but no such device is paired "
						  "(expected under single-device emulation; "
						  "would have failed pre-validation if "
						  "real-hardware-targeting)",
						  fu_firmware_get_id(FU_FIRMWARE(component)),
						  route.chip_guid_alt,
						  (unsigned)route.usb_pid);
					continue;
				}

				/* Pass-filter */
				if (pass == 0 &&
				    route.kind != FU_DELL_MONITOR_RT_ROUTE_I2C_TUNNEL)
					continue;
				if (pass == 1 &&
				    !(route.kind == FU_DELL_MONITOR_RT_ROUTE_DIRECT_STAGE &&
				      route.usb_pid != primary_pid))
					continue;
				if (pass == 2 &&
				    !(route.kind == FU_DELL_MONITOR_RT_ROUTE_DIRECT_STAGE &&
				      route.usb_pid == primary_pid))
					continue;

				blob = fu_firmware_get_bytes(FU_FIRMWARE(component),
							     &error_local);
				if (blob == NULL) {
					g_prefix_error(&error_local,
						       "fetching bytes for %s: ",
						       fu_firmware_get_id(FU_FIRMWARE(component)));
					g_propagate_error(error,
							  g_steal_pointer(&error_local));
					return FALSE;
				}

				/* Arm the (target, proto) pair once. */
				id = fu_device_get_id(FU_DEVICE(route.target));
				arm_key = g_strdup_printf("%s|%s",
							  id != NULL ? id : "(no-id)",
							  route.proto->name);
				if (!g_hash_table_contains(armed, arm_key)) {
					if (!route.proto->arm_target(route.target,
								     &error_local)) {
						g_prefix_error(&error_local,
							       "arming %s for %s: ",
							       id, route.proto->name);
						g_propagate_error(error,
								  g_steal_pointer(&error_local));
						return FALSE;
					}
					g_hash_table_add(armed, g_steal_pointer(&arm_key));
					g_info("dell-monitor-rt: armed %s with %s",
					       id, route.proto->name);
				}

				if (!fu_dell_monitor_rt_device_stage_along_route(&route,
										 blob,
										 &error_local)) {
					g_prefix_error(&error_local,
						       "%s via %s: ",
						       fu_firmware_get_id(FU_FIRMWARE(component)),
						       route.proto->name);
					g_propagate_error(error,
							  g_steal_pointer(&error_local));
					return FALSE;
				}
				if (route.kind == FU_DELL_MONITOR_RT_ROUTE_I2C_TUNNEL) {
					g_info("dell-monitor-rt: %s staged via i2c-tunnel to 0x%02x "
					       "(%" G_GSIZE_FORMAT " bytes)",
					       fu_firmware_get_id(FU_FIRMWARE(component)),
					       (unsigned)route.i2c_target,
					       g_bytes_get_size(blob));
				} else {
					g_info("dell-monitor-rt: %s staged on pid 0x%04x (%" G_GSIZE_FORMAT
					       " bytes)",
					       fu_firmware_get_id(FU_FIRMWARE(component)),
					       (unsigned)route.usb_pid,
					       g_bytes_get_size(blob));
				}

				/* For non-tunnel passes, fire 0xE9 once per target
				 * after that target's last component. We
				 * approximate "last component" by triggering on
				 * EVERY direct-stage component but tracking
				 * triggered-targets — first stage marks it
				 * triggered, subsequent stages skip the trigger.
				 * (The order is: stage, trigger, stage-on-other-
				 * device, trigger-on-other-device. Triggering
				 * after the first stage matches Dell's order
				 * since each device only has one direct-stage
				 * component on this product.) */
				if (route.kind == FU_DELL_MONITOR_RT_ROUTE_DIRECT_STAGE &&
				    !g_hash_table_contains(triggered, route.target)) {
					if (!fu_dell_monitor_rt_device_enter_bootloader(
						route.target, &error_local)) {
						g_prefix_error(&error_local,
							       "bootloader-entry on pid 0x%04x: ",
							       (unsigned)route.usb_pid);
						g_propagate_error(error,
								  g_steal_pointer(&error_local));
						return FALSE;
					}
					g_hash_table_add(triggered, route.target);
					g_info("dell-monitor-rt: bootloader-entry trigger sent "
					       "on pid 0x%04x",
					       (unsigned)route.usb_pid);
				}
			}
		}
	}

	/* Diagnostic walk — list every component and its computed route
	 * so it's obvious what would change with a different .upg. */
	components = fu_firmware_get_images(firmware);
	for (guint i = 0; i < components->len; i++) {
		FuDellMonitorRtFirmwareComponent *component =
		    FU_DELL_MONITOR_RT_FIRMWARE_COMPONENT(g_ptr_array_index(components, i));
		const gchar *version = fu_dell_monitor_rt_firmware_component_get_field_string(
		    component, FU_DELL_MONITOR_RT_FIRMWARE_FIELD_VERSION);
		FuDellMonitorRtRoute route = {0};
		g_autoptr(GBytes) payload = fu_firmware_get_bytes(FU_FIRMWARE(component), NULL);
		const gchar *route_str;

		fu_dell_monitor_rt_route_for_component(FU_DELL_MONITOR_RT_DEVICE(device),
						       component,
						       &route);
		switch (route.kind) {
		case FU_DELL_MONITOR_RT_ROUTE_I2C_TUNNEL:
			route_str = "i2c-tunnel via primary";
			break;
		case FU_DELL_MONITOR_RT_ROUTE_DIRECT_STAGE:
			route_str = "direct-stage on USB device";
			break;
		default:
			route_str = "post-bootloader (unrouted)";
			break;
		}
		g_info("  component[%u] id=%s version=%s pid=0x%04x i2c=0x%02x route=%s "
		       "payload=%" G_GSIZE_FORMAT " bytes",
		       i,
		       fu_firmware_get_id(FU_FIRMWARE(component)),
		       version != NULL ? version : "<encrypted>",
		       (unsigned)route.usb_pid,
		       (unsigned)route.i2c_target,
		       route_str,
		       payload != NULL ? g_bytes_get_size(payload) : 0);
	}
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
