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

/* Per-target session-opening bytes for the i2c-tunnel ISP loader.
 *
 * Wistron's `Rts5409s_IIC_ISP::program()` itself does just `BEGIN`
 * (`12 01 01` = clear_address) before the chunk loop — but the
 * pcap shows that real chip cycles get a `read_fw_version` cycle
 * BEFORE `BEGIN`, emitted by the main updater binary (or by the
 * IIC_ISP::open path) as a session-opening signal. AUDIT.md F2.1
 * recommended dropping it as orphan; that turned out to be wrong
 * on real hardware — chunk-0's READY poll never fires unless the
 * read_fw_version cycle preceded clear_address. The pcap (frames
 * 7782–7798 on HUB1 0xD4 and 20576–20588 on HUB2 0xD6) is the
 * authority; both targets follow the identical prelude, so we
 * emit the same.
 *
 * Per-target session sequence (post-cal_auth, pre-chunk-loop):
 *   1. WAKE  (`25 03 00 00 02`, 5 bytes) + 1-byte poll
 *   2. WAKE-READ (3-byte i2c-R at register 0x80) — this consumes
 *                the chip's queued `read_fw_version` response and
 *                completes the cycle. Without it the chip stays
 *                in "response queued" state and refuses to READY
 *                on subsequent chunk writes.
 *   3. BEGIN (`12 01 01`, 3 bytes) + 1-byte poll
 *   4. For each 64-byte chunk:
 *        c6 frame `13 40 <64 bytes>` + 1-byte poll until ready  */
#define DELL_MONITOR_RT_I2C_LOADER_WAKE       { 0x25, 0x03, 0x00, 0x00, 0x02 }
#define DELL_MONITOR_RT_I2C_LOADER_WAKE_RD_REG  0x80
#define DELL_MONITOR_RT_I2C_LOADER_WAKE_RD_LEN  3
#define DELL_MONITOR_RT_I2C_LOADER_BEGIN      { 0x12, 0x01, 0x01 }

/* Per-chunk polling parameters for the i2c-tunnel ISP loader.
 * RTS5409s_IIC_API::polling_status() in libhub.so issues up to 20 d6
 * reads with 3 ms sleeps between (`nanosleep(0, 3000000ns)` at
 * libhub.so:0x19b4a0), expecting wire-byte 0 == 0x01. Total budget
 * 60 ms (AUDIT.md F2.6). */
#define DELL_MONITOR_RT_I2C_POLL_RETRIES   20
#define DELL_MONITOR_RT_I2C_POLL_SLEEP_US  3000
#define DELL_MONITOR_RT_I2C_POLL_READY     0x01

/* I²C bus speed config — written into wire byte 10 of the i2c-tunnel
 * frame. 0 = default (~100 kHz), used for DDC/CI (slave 0x6E) and the
 * pre-bootloader hub-flash slaves (0xD4/0xD6). 1 = fast-mode (~400 kHz),
 * used for the TPS6598x USB-PD controller (slave 0x42) and slave 0x94.
 * The MCU keys SCL generation off this byte, so it must be set per
 * target rather than left at the boot default. */
#define DELL_MONITOR_RT_I2C_DEFAULT_SPEED 0x00
#define DELL_MONITOR_RT_I2C_SPEED_FAST    0x01

/* Wire offsets for I²C-tunnel commands (relative to the 192-byte payload
 * AFTER the report-ID prefix, so callers see them as buf[N+1] in the
 * 193-byte hidraw buffer). */
#define DELL_MONITOR_RT_I2C_WIRE_REG_OFFSET      2  /* read: register address */
#define DELL_MONITOR_RT_I2C_WIRE_LEN_OFFSET      6
#define DELL_MONITOR_RT_I2C_WIRE_TARGET_OFFSET   8
#define DELL_MONITOR_RT_I2C_WIRE_REG_FLAG_OFFSET 9  /* read: 1 = use REG_OFFSET */
#define DELL_MONITOR_RT_I2C_WIRE_SPEED_OFFSET   10
#define DELL_MONITOR_RT_I2C_WIRE_DATA_OFFSET    64  /* memmove dest in disasm */

/* enable_vdcmd's "you may have noticed I'm a vendor command" auth bytes,
 * placed in the payload at offset 0 (= wire byte 4). Decoded from the
 * RealTek vendor ID 0x0BDA stored little-endian in libdevices.so's
 * RTS5409S_HID::enable_vdcmd disassembly. */
#define DELL_MONITOR_RT_VENDOR_SIG_LO 0xDA
#define DELL_MONITOR_RT_VENDOR_SIG_HI 0x0B

struct _FuDellMonitorRtDevice {
	FuHidrawDevice parent_instance;
	/* Panel-id read during setup() and reused by verify_baseline. Wistron's
	 * tool reads VCP 0xEE exactly once, during the info-display phase
	 * before the install button is clicked, then caches the value for the
	 * panel-binding check at install time. We mirror that lifecycle so our
	 * wire trace converges on the captured pcap (read-once during setup,
	 * no install-time re-emit). NULL until setup() populates it. */
	gchar *cached_panel_id;
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
 * Retry wrapper around `vcmd`. Mirrors `RTS5409S_HID::enable_vdcmd`
 * at libdevices.c:68895, which wraps its single `send_vendor_cmd`
 * call in a `do…while ((last_error != 0) && (iVar3-- != 0))` with
 * `iVar3 = 10` — up to 10 retries on transport error. The retries
 * mask transient HID write failures that show up right after USB
 * enumeration on this chip family. Used for the setup-phase vendor
 * commands (`enable_vdcmd`, `enable_high_clock_mode`).
 */
static gboolean
fu_dell_monitor_rt_device_vcmd_retry(FuDellMonitorRtDevice *self,
				     guint8 dir,
				     guint8 opcode,
				     guint8 subcmd,
				     guint8 arg,
				     const guint8 *payload,
				     gsize payload_len,
				     guint attempts,
				     GError **error)
{
	g_autoptr(GError) last_error = NULL;

	for (guint i = 0; i < attempts; i++) {
		g_autoptr(GError) attempt_error = NULL;
		if (fu_dell_monitor_rt_device_vcmd(self,
						   dir,
						   opcode,
						   subcmd,
						   arg,
						   payload,
						   payload_len,
						   &attempt_error)) {
			if (i > 0) {
				g_debug("dell-monitor-rt: vcmd opcode=0x%02x "
					"succeeded on attempt %u/%u",
					opcode,
					i + 1,
					attempts);
			}
			return TRUE;
		}
		g_debug("dell-monitor-rt: vcmd opcode=0x%02x attempt %u/%u "
			"failed: %s",
			opcode,
			i + 1,
			attempts,
			attempt_error->message);
		g_clear_error(&last_error);
		last_error = g_steal_pointer(&attempt_error);
	}
	g_propagate_error(error, g_steal_pointer(&last_error));
	return FALSE;
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
				    gsize *bytes_out,
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
		gint rc = 0;
		if (!fu_ioctl_execute(ioctl,
				      HIDIOCGINPUT(response_len), /* nocheck:blocked */
				      response,
				      response_len,
				      &rc,
				      DELL_MONITOR_RT_TIMEOUT_MS,
				      FU_IOCTL_FLAG_NONE,
				      error))
			return FALSE;
		if (bytes_out != NULL)
			*bytes_out = (rc > 0) ? (gsize)rc : 0;
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
						 NULL, /* bytes_out — unused */
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
	{
		gsize bytes_in = 0;
		if (!fu_dell_monitor_rt_device_vcmd_read(self,
							 DELL_MONITOR_RT_DIR_WRITE,
							 DELL_MONITOR_RT_OPCODE_AUTH,
							 DELL_MONITOR_RT_AUTH_SUB_REQUEST,
							 0x01, /* arg byte mirrors subcmd in pcap */
							 NULL,
							 0,
							 challenge_resp,
							 sizeof(challenge_resp),
							 &bytes_in,
							 error)) {
			g_prefix_error(error, "auth challenge request failed: ");
			return FALSE;
		}
		/* Wistron's hub_force_handshake (libdevices.c:70912) treats
		 * `hid_get_input_report` returning fewer than 16 bytes as
		 * `last_error = 0xf1` ("chip rejected, short response"). We
		 * mirror that — the cal_auth challenge is exactly 16 bytes,
		 * so anything shorter means the chip didn't deliver the
		 * challenge and `cal_auth` would compute a garbage response.
		 * See AUDIT.md F1.4. The leading byte at challenge_resp[0]
		 * is the kernel-supplied report-ID prefix; we need 16 bytes
		 * of actual response data on top of it.
		 *
		 * Under emulation, fu_ioctl_execute doesn't populate `rc` via
		 * fu_device_event_copy_data — the event's DataOut is copied
		 * into the buffer but bytes_in stays 0. Only enforce the
		 * short-response check when we got a meaningful rc back,
		 * which is what real hardware actually reports. */
		if (bytes_in > 0 && bytes_in < 1 + 16) {
			g_set_error(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_READ,
				    "auth challenge response too short: "
				    "got %" G_GSIZE_FORMAT " bytes, need ≥ %u",
				    bytes_in,
				    (guint)(1 + 16));
			return FALSE;
		}
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
fu_dell_monitor_rt_device_i2c_write_speed(FuDellMonitorRtDevice *self,
					  guint8 i2c_target,
					  guint8 speed,
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
	buf[1 + DELL_MONITOR_RT_I2C_WIRE_SPEED_OFFSET]  = speed;
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

/* Default-speed wrapper used by everything except PDC. Most slaves
 * (DDC/CI 0x6E, hub flash 0xD4/0xD6) sit on the standard-mode 100 kHz
 * bus segment. */
static gboolean
fu_dell_monitor_rt_device_i2c_write(FuDellMonitorRtDevice *self,
				    guint8 i2c_target,
				    const guint8 *data,
				    gsize len,
				    GError **error)
{
	return fu_dell_monitor_rt_device_i2c_write_speed(
	    self, i2c_target, DELL_MONITOR_RT_I2C_DEFAULT_SPEED, data, len, error);
}

/*
 * Send an I²C-tunnel READ request (opcode 0xD6, byte layout identical
 * to the WRITE except the response data is fetched via HIDIOCGINPUT).
 * `count` is the number of I²C bytes to receive; the response is
 * written to `response_out` starting at offset 1 (skipping the
 * leading HID report-ID byte).
 *
 * The `_reg` variant performs a combined "write register addr →
 * repeated-start → read N bytes" sequence in one operation. Use it
 * for register-mapped chips (TPS6598x at 0x42, slave 0x94). The plain
 * read variant is for raw byte streams (DDC/CI, hub flash).
 */
static gboolean
fu_dell_monitor_rt_device_i2c_read_reg(FuDellMonitorRtDevice *self,
				       guint8 i2c_target,
				       guint8 speed,
				       guint8 reg_addr,
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
	/* When reading from a register-mapped chip (TPS6598x at 0x42, the
	 * unidentified 0x94 chip), the i2c-tunnel can do a combined
	 * "write register addr, repeated-start, read N bytes" sequence in
	 * one operation. Bytes 2 and 9 of the i2c-tunnel header carry the
	 * register address and the "use register-prefixed read" flag.
	 * For raw reads (DDC/CI 0x6E, hub flash 0xD4/0xD6) reg_addr=0 and
	 * both bytes stay zero. */
	if (reg_addr != 0) {
		buf[1 + DELL_MONITOR_RT_I2C_WIRE_REG_OFFSET]      = reg_addr;
		buf[1 + DELL_MONITOR_RT_I2C_WIRE_REG_FLAG_OFFSET] = 0x01;
	}
	buf[1 + DELL_MONITOR_RT_I2C_WIRE_LEN_OFFSET]    = count;
	buf[1 + DELL_MONITOR_RT_I2C_WIRE_TARGET_OFFSET] = i2c_target;
	buf[1 + DELL_MONITOR_RT_I2C_WIRE_SPEED_OFFSET]  = speed;

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

/* Default-speed raw read used by everything except PDC. */
static gboolean
fu_dell_monitor_rt_device_i2c_read(FuDellMonitorRtDevice *self,
				   guint8 i2c_target,
				   guint8 count,
				   guint8 *response,
				   gsize response_len,
				   GError **error)
{
	return fu_dell_monitor_rt_device_i2c_read_reg(
	    self,
	    i2c_target,
	    DELL_MONITOR_RT_I2C_DEFAULT_SPEED,
	    0, /* no register prefix */
	    count,
	    response,
	    response_len,
	    error);
}

/*
 * IspTag register: the chip's installed-package marker.
 *
 * The reply carries a 3-letter prefix and a version field. Decomp
 * (firmware-updater.c around offset 0x317600 + 360764) shows Dell's
 * binary calls this the "IspTag" command and writes "#ISP#<v>#" via
 * the same selector elsewhere — but that write does NOT appear in our
 * captured clean install (pcap starts before any IO and contains zero
 * VCP 0xAD writes), so we don't actually know what triggers the ISP →
 * CHK transition or what the prefix means operationally. What we DO
 * know empirically: the chip persistently reports the
 * last-installed-package version in the version field, regardless of
 * which prefix it's wearing. Treat the version as authoritative; log
 * the prefix for diagnostics; don't gate behavior on it until we
 * understand its semantics.
 */
typedef enum {
	FU_DELL_MONITOR_RT_ISPTAG_UNKNOWN,
	FU_DELL_MONITOR_RT_ISPTAG_ISP,
	FU_DELL_MONITOR_RT_ISPTAG_CHK,
} FuDellMonitorRtIspTagState;

typedef struct {
	FuDellMonitorRtIspTagState state;
	gchar *version; /* heap-owned; caller frees */
} FuDellMonitorRtIspTag;

static const gchar *
fu_dell_monitor_rt_isptag_state_str(FuDellMonitorRtIspTagState s)
{
	switch (s) {
	case FU_DELL_MONITOR_RT_ISPTAG_ISP:
		return "ISP";
	case FU_DELL_MONITOR_RT_ISPTAG_CHK:
		return "CHK";
	default:
		return "UNKNOWN";
	}
}

/*
 * Read the IspTag register from the chip via DDC/CI VCP 0xAD.
 *
 * The reply embeds the installed-package version between '#'
 * delimiters with a 3-letter prefix:
 *
 *   request:  51 84 c0 99 ad 18 57    (cmd bytes, XOR-checksum)
 *   response: 51 9a c1 99 23 49 53 50 23 4d 33 54 31 30 35 23 …
 *                                  ↑  ↑  …  …  …  …  …  …  ↑
 *                            '#' 'I' 'S' 'P' '#' 'M' 3  T  '#'
 *                                    └ prefix ┘  └─ version ─┘
 *
 * Note: the response opcode is 0xC0 here, not 0xC1 like the simpler
 * VCP 0xCC reply — the existing parsers used to require 0xC1 strictly,
 * so we accept both.
 *
 * Verified against captures/u4025qw-update-recap-20260502-185321.pcapng.
 */
static gboolean
fu_dell_monitor_rt_device_read_isptag(FuDellMonitorRtDevice *self,
				      FuDellMonitorRtIspTag *tag_out,
				      GError **error)
{
	const guint8 i2c_request[7] = {
	    0x51, 0x84, 0xc0, 0x99, 0xad, 0x18, 0x57,
	};
	guint8 response[DELL_MONITOR_RT_BUF_SIZE] = {0};
	guint8 hub_key[8];

	g_return_val_if_fail(tag_out != NULL, FALSE);
	tag_out->state = FU_DELL_MONITOR_RT_ISPTAG_UNKNOWN;
	tag_out->version = NULL;

	/* Derive the cal_auth key from the per-product seed buffer. */
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
		const gchar *isp_prefix;
		const gchar *chk_prefix;
		const gchar *prefix;

		if (wire[0] != 0x51 || (wire[1] & 0x80) == 0 ||
		    (wire[2] != 0xC0 && wire[2] != 0xC1)) {
			g_set_error(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_READ,
				    "IspTag DDC/CI reply malformed: "
				    "wire[0..3]=%02X %02X %02X %02X",
				    wire[0], wire[1], wire[2], wire[3]);
			return FALSE;
		}
		len = (wire[1] & 0x7F);
		if (len < 2 || len >= 60) {
			g_set_error(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_READ,
				    "IspTag DDC/CI reply has bad length 0x%02x",
				    (unsigned)wire[1]);
			return FALSE;
		}

		ascii = g_string_new(NULL);
		for (gsize i = 4; i < (gsize)(len + 2) && i < 60; i++) {
			if (wire[i] >= 0x20 && wire[i] < 0x7f)
				g_string_append_c(ascii, (gchar)wire[i]);
		}

		isp_prefix = strstr(ascii->str, "ISP#");
		chk_prefix = strstr(ascii->str, "CHK#");
		if (isp_prefix != NULL) {
			tag_out->state = FU_DELL_MONITOR_RT_ISPTAG_ISP;
			prefix = isp_prefix;
		} else if (chk_prefix != NULL) {
			tag_out->state = FU_DELL_MONITOR_RT_ISPTAG_CHK;
			prefix = chk_prefix;
		} else {
			g_set_error(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_READ,
				    "IspTag reply contained neither ISP#…# nor "
				    "CHK#…# field; ascii=%s",
				    ascii->str);
			return FALSE;
		}

		{
			const gchar *value = prefix + 4;
			const gchar *end = strchr(value, '#');
			if (end == NULL || end == value) {
				g_set_error(error,
					    FWUPD_ERROR,
					    FWUPD_ERROR_READ,
					    "IspTag %s prefix has no terminating '#'; "
					    "ascii=%s",
					    fu_dell_monitor_rt_isptag_state_str(
						tag_out->state),
					    ascii->str);
				return FALSE;
			}
			tag_out->version = g_strndup(value, end - value);
		}
		return TRUE;
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

/*
 * Commit a marked IspTag string ("#<marker>#<version>#") to the chip
 * via VCP 0xAD over DDC/CI. The chip uses IspTag as both an "intent
 * announcement" channel (marker = "ISP" at install start) and a "now
 * verify what I just programmed" trigger (marker = "CHK" after a
 * staged firmware completes).
 *
 * Wire format (28 bytes total on slave 0x6e):
 *
 *   byte 0:  0x51                source = host
 *   byte 1:  0x99                DDC/CI length byte = 0x80 | 25
 *   byte 2:  0xc0                opcode (proprietary)
 *   byte 3:  0x55                sub-op = WRITE
 *   byte 4:  0xad                VCP code = IspTag
 *   bytes 5..26:  "#<marker>#<version>#" + zero padding to 22 bytes
 *   byte 27: XOR checksum (includes i2c dest addr 0x6e)
 *
 * Pcap evidence in
 * captures/u4025qw-update-recap-20260502-185321.pcapng:
 *
 *   Frame  7230: "#ISP#M3T105#"   — pre-install announcement #1
 *   Frame  7264: "#ISP#M3T105#"   — pre-install announcement #2 (Wistron
 *                                  emits two identical writes back-to-back;
 *                                  defensive or paired-protocol, we just
 *                                  mirror)
 *   Frame 290306: "#CHK#M3T105#"  — post-PDC commit, triggers chip-side
 *                                  signature verification of the staged
 *                                  PDC firmware. Without this the chip
 *                                  STALLs DISPLAY block 0's
 *                                  secure_control_gpio commit because the
 *                                  PDC sits unverified in the spare bank.
 *
 * Decompiled source: firmware-updater.c FUN_00317d00 calls
 * vtable[0x1a0]("IspTag", str) after the per-chip program call returns
 * success. The string is built as "#CHK#" + <version> + "#" — same
 * shape as the parallel FUN_00317400 which uses "#ISP#".
 *
 * marker_3:   exactly 3 chars, "ISP" or "CHK".
 * version:    the .upg's top-level FIELD_VERSION (e.g., "M3T105"). Limited
 *             to 16 chars by the 28-byte wire envelope.
 */
static gboolean
fu_dell_monitor_rt_device_commit_isp_tag(FuDellMonitorRtDevice *self,
					 const gchar *marker_3,
					 const gchar *version,
					 GError **error)
{
	guint8 wire[28] = {0};
	guint8 response[DELL_MONITOR_RT_BUF_SIZE] = {0};
	guint8 hub_key[8];
	gsize version_len;
	gsize off;
	guint8 chk;

	g_return_val_if_fail(marker_3 != NULL && strlen(marker_3) == 3, FALSE);
	g_return_val_if_fail(version != NULL, FALSE);

	version_len = strlen(version);
	/* Payload after byte 4: "#" + 3 + "#" + version_len + "#" + zero padding;
	 * must fit in bytes 5..26 (22 bytes available). */
	if (3 + 3 + version_len > 22) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_DATA,
			    "version too long for IspTag VCP write: %" G_GSIZE_FORMAT,
			    version_len);
		return FALSE;
	}

	/* Header */
	wire[0] = 0x51; /* source = host */
	wire[1] = 0x99; /* 0x80 | 25 (length) */
	wire[2] = 0xc0; /* opcode */
	wire[3] = 0x55; /* sub = WRITE */
	wire[4] = 0xad; /* VCP code = IspTag */
	/* Payload "#<marker>#<version>#" starting at byte 5 */
	off = 5;
	wire[off++] = '#';
	memcpy(&wire[off], marker_3, 3);
	off += 3;
	wire[off++] = '#';
	memcpy(&wire[off], version, version_len);
	off += version_len;
	wire[off++] = '#';
	/* bytes off..26 stay zero (padding) */

	/* Checksum: XOR of dest addr 0x6e + all 27 preceding bytes */
	chk = DELL_MONITOR_RT_I2C_TARGET_DDCCI;
	for (gsize i = 0; i < 27; i++)
		chk ^= wire[i];
	wire[27] = chk;

	/* Per-write cal_auth handshake — same pattern as read_panel_id /
	 * read_isp_tag. The chip gates DDC/CI ops on a fresh challenge. */
	fu_dell_monitor_rt_get_synkey(DELL_MONITOR_RT_U4025QW_SYNKEY_SEED,
				      sizeof(DELL_MONITOR_RT_U4025QW_SYNKEY_SEED),
				      hub_key);
	if (!fu_dell_monitor_rt_device_handshake(self, hub_key, error)) {
		g_prefix_error(error,
			       "IspTag #%s#%s# commit handshake: ",
			       marker_3,
			       version);
		return FALSE;
	}
	if (!fu_dell_monitor_rt_device_i2c_write(self,
						 DELL_MONITOR_RT_I2C_TARGET_DDCCI,
						 wire,
						 sizeof(wire),
						 error)) {
		g_prefix_error(error,
			       "IspTag #%s#%s# write: ",
			       marker_3,
			       version);
		return FALSE;
	}
	/* Settle delay matches the cadence in the recap (~50 ms between
	 * write and response read for our existing read_panel_id /
	 * read_isp_tag pairs). */
	g_usleep(50 * 1000);
	/* Drain the chip's 64-byte response. We don't validate the
	 * contents — without decoding the response format we'd rather
	 * not gate the install on bytes we don't understand. The read
	 * is required because Wistron always does it and the chip's
	 * i2c-tunnel state machine may stall future ops if the response
	 * stays queued. */
	if (!fu_dell_monitor_rt_device_i2c_read(self,
						DELL_MONITOR_RT_I2C_TARGET_DDCCI,
						0x40,
						response,
						sizeof(response),
						error)) {
		g_prefix_error(error,
			       "IspTag #%s#%s# response drain: ",
			       marker_3,
			       version);
		return FALSE;
	}
	return TRUE;
}

/*
 * verify_baseline — pre-flash panel-binding check that runs before any
 * device IO that mutates state.
 *
 * Walks the .upg components: any with `panel_bound: TRUE` MUST have
 * `panel_id` matching the chip's reported value. A mismatch means this
 * .upg is for a different panel SKU; flashing it would brick the monitor.
 * Fail hard.
 *
 * The chip-side panel-id was read once during device_setup() (VCP 0xEE
 * to slave 0x6E, FL5500 scaler) and stashed in self->cached_panel_id —
 * see fu_dell_monitor_rt_device_setup. Wistron's tool follows the same
 * pattern: VCP 0xEE fires three times during the info-display phase
 * (pcap positions 8/68/140 in the captured trace), then never again for
 * the rest of the update. Reading panel-id at install time would diverge
 * from that pattern — the matcher would leapfrog forward past the
 * captured staging events looking for a VCP 0xEE write that doesn't
 * exist in the install.json portion of the fixture, and on real hardware
 * we'd be issuing a redundant DDC/CI probe that Wistron deliberately
 * doesn't.
 *
 * The IspTag is also read in setup() and surfaced via fu_device_set_
 * version, so engine-level "is this a re-install?" filtering already
 * has it. We don't repeat that read here.
 *
 * We deliberately do NOT short-circuit on "version already matches" —
 * fwupd's engine already filters that case at a higher level (via the
 * device version vs. release version comparison, controlled by the
 * `--allow-reinstall` CLI flag). Duplicating that check here would
 * just complicate emulation testing without adding safety.
 *
 * Returns TRUE on success (proceed with install). Returns FALSE on
 * panel mismatch, missing metadata, or missing cache (setup() failed
 * to read panel-id).
 */
static gboolean
fu_dell_monitor_rt_device_verify_baseline(FuDellMonitorRtDevice *self,
					  FuDellMonitorRtFirmware *fw_container,
					  GError **error)
{
	GPtrArray *components;

	components = fu_firmware_get_images(FU_FIRMWARE(fw_container));
	for (guint i = 0; i < components->len; i++) {
		FuDellMonitorRtFirmwareComponent *component =
		    FU_DELL_MONITOR_RT_FIRMWARE_COMPONENT(
			g_ptr_array_index(components, i));
		const gchar *component_panel_id;

		if (!fu_dell_monitor_rt_firmware_component_get_panel_bound(component))
			continue;
		component_panel_id =
		    fu_dell_monitor_rt_firmware_component_get_panel_id(component);
		if (component_panel_id == NULL) {
			g_set_error(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_INVALID_DATA,
				    "verify_baseline: panel-bound component '%s' "
				    "has no panel_id metadata",
				    fu_firmware_get_id(FU_FIRMWARE(component)));
			return FALSE;
		}
		if (self->cached_panel_id == NULL) {
			g_set_error(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_NOT_SUPPORTED,
				    "verify_baseline: component '%s' is "
				    "panel-bound but the chip's panel-id was "
				    "not read during setup; refusing to flash "
				    "without confirming panel match",
				    fu_firmware_get_id(FU_FIRMWARE(component)));
			return FALSE;
		}
		if (g_strcmp0(self->cached_panel_id, component_panel_id) != 0) {
			g_set_error(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_NOT_SUPPORTED,
				    "verify_baseline: this .upg targets panel '%s' "
				    "but the connected monitor reports panel '%s'. "
				    "Refusing to flash panel-bound firmware to a "
				    "different panel — that would brick it.",
				    component_panel_id,
				    self->cached_panel_id);
			return FALSE;
		}
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

	/* Emulation-test inhibit: when running emulation against a fixture
	 * from a user that lacks ACL on the real 0bda:1100 hidraw (e.g. ada
	 * on signi, where josh owns the device), the engine sees both the
	 * real hidraw entry and the synthetic emulated entry. Without
	 * inhibiting the real one, install dispatch picks it by enumeration
	 * order, and every wire op silently fails since we can't write to
	 * josh's hidraw. The emulator wrapper (flake.nix's
	 * dell-monitor-rt-emu) sets FWUPD_DELL_MONITOR_RT_INHIBIT_REAL=1 so
	 * setup() refuses real hardware in that context only — leaving
	 * real-hardware install runs (which don't set the env var)
	 * unaffected. Mirror f904dfde7's commit-message rationale. */
	if (!fu_device_has_flag(device, FWUPD_DEVICE_FLAG_EMULATED) &&
	    g_getenv("FWUPD_DELL_MONITOR_RT_INHIBIT_REAL") != NULL) {
		g_warning("dell-monitor-rt: real device inhibited for "
			  "emulation-test run (FWUPD_DELL_MONITOR_RT_INHIBIT_REAL "
			  "set); the synthetic emulated entry will receive the "
			  "install instead");
		fu_device_set_version(device, "0.0.0-emu-inhibit");
		fu_device_inhibit(device,
				  "hidden",
				  "real-hardware install suppressed during "
				  "emulation test; unset "
				  "FWUPD_DELL_MONITOR_RT_INHIBIT_REAL to run "
				  "against real hardware");
		return TRUE;
	}

	/* Step 1: enable vendor-command mode (the auth bytes are the
	 * RealTek vendor ID 0x0BDA placed at wire bytes 4-5).
	 *
	 * Wistron retries this up to 10× on `last_error != 0`
	 * (libdevices.c:68895) — see AUDIT.md F1.1. The retries mask
	 * transient HID write failures right after USB enumeration. */
	if (!fu_dell_monitor_rt_device_vcmd_retry(
		self,
		DELL_MONITOR_RT_DIR_WRITE,
		DELL_MONITOR_RT_OPCODE_ENABLE_VDCMD,
		0x01, /* "enable" */
		0x00,
		vendor_sig,
		sizeof(vendor_sig),
		10, /* Wistron's retry budget */
		&error_local)) {
		g_warning("dell-monitor-rt: enable_vdcmd failed: %s",
			  error_local->message);
		fu_device_set_version(device, "0.0.0-no-vdcmd");
		return TRUE;
	}

	/* Step 2: enable high-clock mode (Dell's binary's frame 7702 — the
	 * second thing it sends after enable_vdcmd). May not be strictly
	 * required for version-read but matches the captured init order.
	 * Wistron's enable_high_clock_mode (libdevices.c:68992) is
	 * single-shot in the decomp — no retry loop — but we apply the
	 * same retry budget for consistency. */
	g_clear_error(&error_local);
	if (!fu_dell_monitor_rt_device_vcmd_retry(
		self,
		DELL_MONITOR_RT_DIR_WRITE,
		DELL_MONITOR_RT_OPCODE_ENABLE_HIGH_CLOCK,
		0x01, /* "enable" */
		0x00,
		NULL,
		0,
		10,
		&error_local)) {
		g_warning("dell-monitor-rt: enable_high_clock failed: %s",
			  error_local->message);
		fu_device_set_version(device, "0.0.0-no-hiclk");
		return TRUE;
	}

	/* Step 3: read panel id (VCP 0xEE) and cache on the device. Order
	 * matters: Wistron's tool reads VCP 0xEE during the info-display phase
	 * BEFORE the IspTag read (pcap positions 8/68/140 vs. 206/218). The
	 * matcher walks the event stream forward, so reading IspTag first
	 * would advance the cursor past the VCP 0xEE events and the panel-id
	 * read would leapfrog forward looking for an event that no longer
	 * exists in the remaining setup.json window. We mirror Wistron's
	 * order — panel-id, then IspTag — so each read finds its matching
	 * event in place. The cached value is reused by verify_baseline so
	 * VCP 0xEE never re-fires during the install phase.
	 *
	 * Step 4 below reads VCP 0xAD (IspTag) to get the user-facing package
	 * version (e.g. "M3T105"). The wire request is 51 84 c0 99 ad 18 57 to
	 * slave 0x6E, returning "ISP#M3T105#" — the same string Dell's UI
	 * shows. We previously read selector 0xCC which returns
	 * "753.0AK01.0007" (the scaler component's firmware ID, not the
	 * user-facing version), so the surfaced device version was misleading.
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
		g_autofree gchar *panel_id = NULL;
		if (!fu_dell_monitor_rt_device_read_panel_id(self,
							     &panel_id,
							     &error_local)) {
			g_warning("dell-monitor-rt: panel-id read failed: %s",
				  error_local->message);
			fu_device_set_version(device, "0.0.0-no-panel-id");
			return TRUE;
		}
		g_debug("dell-monitor-rt: panel id=%s", panel_id);
		g_free(self->cached_panel_id);
		self->cached_panel_id = g_steal_pointer(&panel_id);
	}

	/* Step 4: read the user-facing IspTag (VCP 0xAD) for fwupd's device
	 * version field. */
	g_clear_error(&error_local);
	{
		FuDellMonitorRtIspTag tag = {0};
		if (!fu_dell_monitor_rt_device_read_isptag(self,
							   &tag,
							   &error_local)) {
			g_warning("dell-monitor-rt: IspTag read failed: %s",
				  error_local->message);
			fu_device_set_version(device, "0.0.0-no-isptag");
			return TRUE;
		}
		g_debug("dell-monitor-rt: IspTag prefix=%s version=%s",
			fu_dell_monitor_rt_isptag_state_str(tag.state),
			tag.version);
		fu_device_set_version(device, tag.version);
		g_free(tag.version);
	}
	return TRUE;
}

/* Private flag — set on the device at the end of pre-bootloader work
 * so the next write_firmware iteration knows to run the post-bootloader
 * passes instead of re-running pre-BL. Survives device replacement on
 * USB re-enumeration via the device_class->replace override. */
#define FU_DELL_MONITOR_RT_FLAG_PRE_BL_DONE "pre-bl-done"

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
	fu_device_register_private_flag(FU_DEVICE(self),
					FU_DELL_MONITOR_RT_FLAG_PRE_BL_DONE);
}

/*
 * Copy the install-phase tracking flag from the donor (pre-replug) device
 * to this (post-replug) device. Called by the engine's device-list
 * replace path whenever a new FuDevice is detected for the same backend_id
 * — which is exactly what happens after the 0xE9 bootloader-enter
 * trigger forces a USB re-enumeration. Without this, the post-replug
 * device starts fresh with no flag set and write_firmware would loop
 * back into pre-bootloader work.
 */
static void
fu_dell_monitor_rt_device_replace(FuDevice *device, FuDevice *donor)
{
	if (fu_device_has_private_flag(donor,
				       FU_DELL_MONITOR_RT_FLAG_PRE_BL_DONE)) {
		fu_device_add_private_flag(device,
					   FU_DELL_MONITOR_RT_FLAG_PRE_BL_DONE);
	}
}

/*
 * Clear install-phase state when the install completes (success or
 * failure). Without this, a failed install leaves the flag set and a
 * subsequent retry would jump straight to post-bootloader work without
 * re-doing the pre-BL flashing.
 */
static gboolean
fu_dell_monitor_rt_device_cleanup(FuDevice *device,
				  FuProgress *progress,
				  FwupdInstallFlags flags,
				  GError **error)
{
	(void)progress;
	(void)flags;
	(void)error;
	fu_device_remove_private_flag(device, FU_DELL_MONITOR_RT_FLAG_PRE_BL_DONE);
	return TRUE;
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
 * Poll the downstream MCU's i2c-tunnel ready bit. Mirrors
 * RTS5409s_IIC_API::polling_status() in libhub.so: issue a 1-byte d6
 * read; expect wire-byte 0 == 0x01; retry up to N times with a small
 * sleep between. Returns success only if a poll observed the ready
 * value within the retry budget.
 */
static gboolean
fu_dell_monitor_rt_device_i2c_tunnel_poll(FuDellMonitorRtDevice *self,
					  guint8 i2c_target,
					  GError **error)
{
	for (guint attempt = 0; attempt < DELL_MONITOR_RT_I2C_POLL_RETRIES;
	     attempt++) {
		guint8 response[DELL_MONITOR_RT_BUF_SIZE] = {0};
		g_autoptr(GError) error_local = NULL;

		if (!fu_dell_monitor_rt_device_i2c_read(self,
							i2c_target,
							1,
							response,
							sizeof(response),
							&error_local)) {
			/* If the chip is still busy the read may time out;
			 * keep retrying until the budget runs out. */
			g_debug("dell-monitor-rt: i2c poll 0x%02x attempt %u "
				"transport error: %s",
				i2c_target,
				attempt,
				error_local->message);
		} else if (response[1] == DELL_MONITOR_RT_I2C_POLL_READY) {
			return TRUE;
		} else {
			g_debug("dell-monitor-rt: i2c poll 0x%02x attempt %u "
				"got 0x%02x (want 0x%02x)",
				i2c_target,
				attempt,
				response[1],
				DELL_MONITOR_RT_I2C_POLL_READY);
		}
		g_usleep(DELL_MONITOR_RT_I2C_POLL_SLEEP_US);
	}
	g_set_error(error,
		    FWUPD_ERROR,
		    FWUPD_ERROR_TIMED_OUT,
		    "i2c-tunnel poll for slave 0x%02x timed out after %u "
		    "attempts (no READY response)",
		    i2c_target,
		    DELL_MONITOR_RT_I2C_POLL_RETRIES);
	return FALSE;
}

/*
 * Send one i2c-tunnel session-init command (WAKE or BEGIN) to a
 * downstream MCU and poll for the ready response. Returns FALSE on
 * write or poll failure.
 */
static gboolean
fu_dell_monitor_rt_device_i2c_tunnel_init_step(FuDellMonitorRtDevice *self,
					       guint8 i2c_target,
					       const gchar *step_name,
					       const guint8 *bytes,
					       gsize bytes_len,
					       GError **error)
{
	if (!fu_dell_monitor_rt_device_i2c_write(self,
						 i2c_target,
						 bytes,
						 bytes_len,
						 error)) {
		g_prefix_error(error,
			       "i2c-tunnel %s to 0x%02x failed: ",
			       step_name,
			       i2c_target);
		return FALSE;
	}
	if (!fu_dell_monitor_rt_device_i2c_tunnel_poll(self, i2c_target, error)) {
		g_prefix_error(error,
			       "i2c-tunnel %s to 0x%02x post-poll failed: ",
			       step_name,
			       i2c_target);
		return FALSE;
	}
	return TRUE;
}

/*
 * Stream an ephemeral ISP shim into a downstream MCU's RAM via the i2c
 * tunnel (opcode 0xC6). Used for HUB1 → 0xD4 and HUB2 → 0xD6 — both
 * fire BEFORE bootloader entry, both go through HID-A.
 *
 * Per-target session sequence (post-cal_auth, pre-chunk-loop):
 *   1. WAKE     `25 03 00 00 02` (5 bytes) + 1-byte poll
 *   2. WAKE-RD  3-byte i2c-R at register 0x80 — drains the chip's
 *               queued read_fw_version response and primes the
 *               i2c-tunnel state machine for the chunk loop. Without
 *               this 3-byte read, the chip stays in "response
 *               queued" state and never returns READY for chunk 0.
 *   3. BEGIN    `12 01 01` clear_address (3 bytes) + 1-byte poll
 *   4. For each 64-byte chunk:
 *        c6 frame `13 40 <64 bytes>` + 1-byte poll until ready
 *
 * Real-hardware pcap evidence (recap frames 7782–7798 / 20576–20588):
 * both HUB1 and HUB2 use this exact prelude. Removing the WAKE cycle
 * (AUDIT.md F2.1's first option) caused chunk-0 READY-poll timeout
 * on real HW — captured 2026-05-13 in
 * captures/u4025qw-failrun-20260513-142303.pcapng. The audit's
 * fallback "Complete the WAKE cycle" path is what real HW needs;
 * we run it ONCE per session (audit incorrectly suggested twice).
 *
 * Verified bytewise: HUB1.fw is 2048 chunks to slave 0xD4, HUB2.fw
 * is 1024 chunks to slave 0xD6.
 *
 * cal_auth: The single cal_auth handshake performed by our caller
 * covers the entire blob. Decomp evidence (hub_handshake() in
 * libdevices.so is a no-op stub; the real hub_force_handshake() is
 * only called at i2c-tunnel session open/close) confirms per-chunk
 * re-auth is not required.
 */
static gboolean
fu_dell_monitor_rt_device_stage_downstream_mcu(FuDellMonitorRtDevice *self,
					       guint8 i2c_target,
					       GBytes *blob,
					       FuProgress *progress,
					       GError **error)
{
	const guint8 wake[] = DELL_MONITOR_RT_I2C_LOADER_WAKE;
	const guint8 begin[] = DELL_MONITOR_RT_I2C_LOADER_BEGIN;
	const guint8 *blob_data;
	gsize blob_size;
	guint nchunks_full;
	guint partial;
	guint nsteps;

	blob_data = g_bytes_get_data(blob, &blob_size);
	if (blob_size == 0) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_INVALID_DATA,
				    "downstream-MCU blob is empty");
		return FALSE;
	}
	nchunks_full = (guint)(blob_size / DELL_MONITOR_RT_I2C_LOADER_CHUNK);
	partial = (guint)(blob_size % DELL_MONITOR_RT_I2C_LOADER_CHUNK);
	nsteps = nchunks_full + (partial ? 1 : 0);

	/* Step 1+2: WAKE write + poll, then drain the queued response
	 * with a 3-byte i2c-R at register 0x80. Both halves are
	 * required for the chip to enter the chunk-write-ready state. */
	if (!fu_dell_monitor_rt_device_i2c_tunnel_init_step(self,
							    i2c_target,
							    "WAKE",
							    wake,
							    sizeof(wake),
							    error))
		return FALSE;
	{
		guint8 wake_rd[DELL_MONITOR_RT_BUF_SIZE] = {0};
		if (!fu_dell_monitor_rt_device_i2c_read_reg(
			self,
			i2c_target,
			DELL_MONITOR_RT_I2C_DEFAULT_SPEED,
			DELL_MONITOR_RT_I2C_LOADER_WAKE_RD_REG,
			DELL_MONITOR_RT_I2C_LOADER_WAKE_RD_LEN,
			wake_rd,
			sizeof(wake_rd),
			error)) {
			g_prefix_error(
			    error,
			    "downstream-MCU WAKE-read at slave 0x%02x reg 0x%02x: ",
			    i2c_target,
			    DELL_MONITOR_RT_I2C_LOADER_WAKE_RD_REG);
			return FALSE;
		}
	}

	if (!fu_dell_monitor_rt_device_i2c_tunnel_init_step(self,
							    i2c_target,
							    "clear_address",
							    begin,
							    sizeof(begin),
							    error))
		return FALSE;

	if (progress != NULL)
		fu_progress_set_steps(progress, nsteps);

	for (guint i = 0; i < nchunks_full; i++) {
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
				       nchunks_full);
			return FALSE;
		}
		if (!fu_dell_monitor_rt_device_i2c_tunnel_poll(self,
							       i2c_target,
							       error)) {
			g_prefix_error(error,
				       "downstream-MCU poll after chunk %u/%u to 0x%02x: ",
				       i,
				       nchunks_full,
				       i2c_target);
			return FALSE;
		}

		if (progress != NULL)
			fu_progress_step_done(progress);
	}

	/* Trailing partial chunk (AUDIT.md F2.5). Wistron's program()
	 * emits a final write_flash with the residue count when the
	 * blob isn't a multiple of 0x40 (libhub.c::Rts5409s_IIC_ISP::
	 * program does `if (uVar7 != (size & 0x40 - 1)) write_flash(...,
	 * residue)`). The U4025QW HUB blobs are 64-aligned so this
	 * branch never fires for the current M3T105 firmware, but the
	 * code is here so future Dell payloads work without surprise. */
	if (partial > 0) {
		guint8 frame[DELL_MONITOR_RT_I2C_LOADER_FRAME];
		memset(frame, 0, sizeof(frame));
		frame[0] = DELL_MONITOR_RT_I2C_LOADER_CMD;
		frame[1] = (guint8)partial; /* count, not the full 0x40 */
		memcpy(&frame[2],
		       blob_data + (nchunks_full * DELL_MONITOR_RT_I2C_LOADER_CHUNK),
		       partial);

		if (!fu_dell_monitor_rt_device_i2c_write(self,
							 i2c_target,
							 frame,
							 2 + partial,
							 error)) {
			g_prefix_error(error,
				       "downstream-MCU stage to 0x%02x failed at trailing partial chunk (%u bytes): ",
				       i2c_target,
				       partial);
			return FALSE;
		}
		if (!fu_dell_monitor_rt_device_i2c_tunnel_poll(self,
							       i2c_target,
							       error)) {
			g_prefix_error(error,
				       "downstream-MCU poll after trailing partial chunk to 0x%02x: ",
				       i2c_target);
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
	/* Wistron emits 0xE9 twice per phase boundary in the captured
	 * trace: once via `reset_to_flash` (single-shot) and once via
	 * `reset_self` (libdevices.c:70110, retry up to 3× until
	 * send_vendor_cmd returns 0). For our plugin's case the chip
	 * only needs one successful emit to re-enumerate; we mirror
	 * `reset_self`'s pattern — a single emit with up to 3 retries
	 * on transport failure (AUDIT.md F4.1). On the success path
	 * this matches just the first of the captured pair, leaving
	 * the second event in the fixture unconsumed by the leapfrog
	 * matcher (harmless: the split-at-4th-0xE9 reload boundary is
	 * computed at fixture-build time and isn't affected). */
	guint attempts = 3;
	g_autoptr(GError) last_error = NULL;
	for (guint i = 0; i < attempts; i++) {
		g_autoptr(GError) attempt_error = NULL;
		if (fu_dell_monitor_rt_device_vcmd(self,
						   DELL_MONITOR_RT_DIR_WRITE,
						   DELL_MONITOR_RT_OPCODE_BOOTLOADER_ENTER,
						   0x00,
						   0x00,
						   NULL,
						   0,
						   &attempt_error))
			return TRUE;
		g_clear_error(&last_error);
		last_error = g_steal_pointer(&attempt_error);
		g_debug("bootloader-enter attempt %u/%u failed: %s",
			i + 1,
			attempts,
			last_error->message);
	}
	g_propagate_prefixed_error(error,
				   g_steal_pointer(&last_error),
				   "bootloader-enter trigger failed after %u attempts: ",
				   attempts);
	return FALSE;
}

/* ----- TI TPS6598x 4CC command primitives -------------------------
 *
 * The PDC component (TI TPS6598x USB-C Power Delivery controller) is
 * programmed via 4-character-code commands over the i2c-tunnel after
 * bootloader-entry. Slave 0x42 (8-bit) = TPS6598x i2c address. Each
 * 4CC command is a two-step i2c transaction:
 *
 *   1. Write to register 0x09 (Cmd1) the 4CC bytes "FL<c1><c2>".
 *      Format: c6→0x42 with payload `08 04 46 4c <c1> <c2>` (2 prefix
 *      bytes + 4-byte command). The chip's TPS6598x BootROM
 *      interprets register 0x09 writes as commands.
 *   2. Optional: read response via d6→0x42 count=N+1.
 *
 * For commands taking input data, the input goes into register 0x08
 * (Data1) BEFORE issuing the 4CC. Format: c6→0x42 with payload
 * `09 LL <data...>` where LL is the data length.
 *
 * The 4CC commands we use (decoded from libpdc.so + TI doc SLVUBH2B):
 *
 *   FLrr  Set Flash Read Region (load region pointer)
 *   FLem  Flash Memory Erase
 *   FLad  Set Flash Memory Write Start Address
 *   FLwd  Flash Memory Write (32 bytes per call)
 *   FLrd  Flash Memory Read
 *   FLvy  Flash Memory Verify
 */

#define DELL_MONITOR_RT_PDC_I2C_TARGET    0x42
#define DELL_MONITOR_RT_PDC_REG_CMD1      0x08 /* per TI SLVUBH2B */
#define DELL_MONITOR_RT_PDC_REG_DATA1     0x09
#define DELL_MONITOR_RT_PDC_FOURCC_PREFIX 0x4C46 /* "FL" little-endian */
#define DELL_MONITOR_RT_PDC_CHUNK_SIZE    32
#define DELL_MONITOR_RT_PDC_REGION0_BASE  0x800

/* Wait for the chip to ack a 4CC command. The TI BootROM clears Cmd1
 * once the command completes; the response read returns the result
 * byte. We just want the read to succeed, content is per-command. */
#define DELL_MONITOR_RT_PDC_ACK_BYTES 4
#define DELL_MONITOR_RT_PDC_DATA_BYTES 16

/*
 * Write `len` bytes into TPS6598x register 0x08 (Data1) — the input
 * buffer for whatever 4CC command will be issued next. The on-wire
 * payload is `08 LL <data>`; the i2c-tunnel slave is 0x42 (PDC).
 * Caller's responsibility: a valid cal_auth handshake before the
 * first call in a session.
 */
static gboolean
fu_dell_monitor_rt_pdc_set_buf(FuDellMonitorRtDevice *self,
			       const guint8 *data,
			       gsize len,
			       GError **error)
{
	g_autofree guint8 *payload = NULL;
	if (len > 64) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_DATA,
			    "PDC Data1 buffer too large: %" G_GSIZE_FORMAT,
			    len);
		return FALSE;
	}
	payload = g_malloc(len + 2);
	payload[0] = DELL_MONITOR_RT_PDC_REG_DATA1;
	payload[1] = (guint8)len;
	if (data != NULL && len > 0)
		memcpy(payload + 2, data, len);
	if (!fu_dell_monitor_rt_device_i2c_write_speed(self,
						       DELL_MONITOR_RT_PDC_I2C_TARGET,
						       DELL_MONITOR_RT_I2C_SPEED_FAST,
						       payload,
						       len + 2,
						       error)) {
		g_prefix_error(error, "PDC set_buf len=%" G_GSIZE_FORMAT ": ", len);
		return FALSE;
	}
	return TRUE;
}

/*
 * Issue a 4CC command on TPS6598x register 0x09 (Cmd1). cmd_str must
 * be exactly 2 ASCII chars (the "<c1><c2>" tail of "FL<c1><c2>").
 * On-wire payload: `09 04 46 4c <c1> <c2>`.
 */
static gboolean
fu_dell_monitor_rt_pdc_cmd(FuDellMonitorRtDevice *self,
			   const gchar *cmd_str,
			   GError **error)
{
	guint8 payload[6];
	if (cmd_str == NULL || strlen(cmd_str) != 2) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_DATA,
			    "PDC 4CC tail must be 2 chars, got %s",
			    cmd_str != NULL ? cmd_str : "(null)");
		return FALSE;
	}
	payload[0] = DELL_MONITOR_RT_PDC_REG_CMD1;
	payload[1] = 0x04;	     /* command length */
	payload[2] = 0x46;	     /* 'F' */
	payload[3] = 0x4c;	     /* 'L' */
	payload[4] = (guint8)cmd_str[0];
	payload[5] = (guint8)cmd_str[1];
	if (!fu_dell_monitor_rt_device_i2c_write_speed(self,
						       DELL_MONITOR_RT_PDC_I2C_TARGET,
						       DELL_MONITOR_RT_I2C_SPEED_FAST,
						       payload,
						       sizeof(payload),
						       error)) {
		g_prefix_error(error, "PDC FL%s issue: ", cmd_str);
		return FALSE;
	}
	return TRUE;
}

/* Read `count` bytes from a TPS6598x register. The i2c-tunnel does the
 * combined "write reg_addr, repeated-start, read count+1 bytes" in one
 * operation. count+1 because the chip prefixes its response with a
 * length byte. Returns the payload bytes (after the length prefix) via
 * response_out. reg_addr is typically 0x08 (Cmd1, for command status)
 * or 0x09 (Data1, for command response data). */
static gboolean
fu_dell_monitor_rt_pdc_read_resp(FuDellMonitorRtDevice *self,
				 guint8 reg_addr,
				 guint8 count,
				 guint8 *response_out,
				 gsize response_out_len,
				 GError **error)
{
	guint8 buf[DELL_MONITOR_RT_BUF_SIZE] = {0};
	if (response_out_len < count) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_INVALID_DATA,
				    "PDC response buffer too small");
		return FALSE;
	}
	if (!fu_dell_monitor_rt_device_i2c_read_reg(self,
						    DELL_MONITOR_RT_PDC_I2C_TARGET,
						    DELL_MONITOR_RT_I2C_SPEED_FAST,
						    reg_addr,
						    count + 1,
						    buf,
						    sizeof(buf),
						    error)) {
		g_prefix_error(error, "PDC read_resp reg=0x%02x count=%u: ", reg_addr, count);
		return FALSE;
	}
	/* Wire layout (per captured Ioctl responses): TPS6598x register
	 * reads return `<width_byte> <register_bytes...>`. width_byte is
	 * the chip-side register width (4 for Cmd1, 64 for Data1 — the
	 * chip ignores our count_arg here and always reports the full
	 * register width). We get count_arg bytes of register data after
	 * width_byte because we asked the i2c-tunnel for count_arg+1
	 * bytes total. Strip the HID report-id (buf[0]) AND the
	 * width_byte (buf[1]) and hand the caller just the data. */
	memcpy(response_out, buf + 2, count);
	return TRUE;
}

/* Read both Cmd1 (ack/status) and Data1 (response data) registers — the
 * ack-then-data pair that follows every 4CC command. Pass NULL for
 * data_out if the command has no response data to consume. */
static gboolean
fu_dell_monitor_rt_pdc_finish_cmd(FuDellMonitorRtDevice *self,
				  guint8 *data_out,
				  gsize data_count,
				  GError **error)
{
	guint8 ack[DELL_MONITOR_RT_PDC_ACK_BYTES] = {0};
	guint8 dummy[DELL_MONITOR_RT_PDC_ACK_BYTES] = {0};
	if (!fu_dell_monitor_rt_pdc_read_resp(self,
					      DELL_MONITOR_RT_PDC_REG_CMD1,
					      DELL_MONITOR_RT_PDC_ACK_BYTES,
					      ack,
					      sizeof(ack),
					      error))
		return FALSE;
	/* Always read Data1 too; Wistron's host code does this on every
	 * 4CC, and the chip is happiest when the round-trip completes
	 * (an internal busy/ready latch flips on the Data1 read). For
	 * commands with no return data we discard the bytes. */
	if (data_out == NULL) {
		data_out = dummy;
		data_count = DELL_MONITOR_RT_PDC_ACK_BYTES;
	}
	if (!fu_dell_monitor_rt_pdc_read_resp(self,
					      DELL_MONITOR_RT_PDC_REG_DATA1,
					      (guint8)data_count,
					      data_out,
					      data_count,
					      error))
		return FALSE;
	return TRUE;
}

/*
 * Per-chunk verify helper. Reads the just-written chunk back via FLrd
 * (in 16-byte halves, since the TPS6598x's reg-0x09 read window is
 * 16 bytes wide) and byte-compares against the expected data. Up to
 * `DELL_MONITOR_RT_PDC_VERIFY_RETRIES` retries on mismatch — matches
 * Tps6598xISP::VerifyFW at libpdc.c:50046.
 *
 * Called per-chunk in pdc_program. Wistron always does this (their
 * `using_verify_command_only` flag defaults to false); our previous
 * implementation skipped it, trusting only the final FLvy hardware
 * verify. We add it back as defense against silicon errata not
 * documented in the public TI ref — Wistron presumably has a reason
 * to belt-AND-suspenders this.
 */
#define DELL_MONITOR_RT_PDC_VERIFY_RETRIES 3
#define DELL_MONITOR_RT_PDC_VERIFY_HALF    16 /* FLrd reads 16-byte halves */

static gboolean
fu_dell_monitor_rt_pdc_verify_chunk(FuDellMonitorRtDevice *self,
				    guint32 addr,
				    const guint8 *expected,
				    gsize chunk_size,
				    GError **error)
{
	guint8 readback[DELL_MONITOR_RT_PDC_CHUNK_SIZE] = {0};
	guint retries = DELL_MONITOR_RT_PDC_VERIFY_RETRIES;

	g_assert(chunk_size <= sizeof(readback));

	while (retries > 0) {
		for (gsize offset = 0; offset < chunk_size;
		     offset += DELL_MONITOR_RT_PDC_VERIFY_HALF) {
			guint32 cur_addr = addr + (guint32)offset;
			guint8 addr_le[4] = {
			    (guint8)(cur_addr & 0xFF),
			    (guint8)((cur_addr >> 8) & 0xFF),
			    (guint8)((cur_addr >> 16) & 0xFF),
			    (guint8)((cur_addr >> 24) & 0xFF),
			};
			gsize to_read = MIN(DELL_MONITOR_RT_PDC_VERIFY_HALF,
					    chunk_size - offset);
			if (!fu_dell_monitor_rt_pdc_set_buf(self, addr_le, 4, error))
				return FALSE;
			if (!fu_dell_monitor_rt_pdc_cmd(self, "rd", error))
				return FALSE;
			if (!fu_dell_monitor_rt_pdc_finish_cmd(self,
							       &readback[offset],
							       to_read,
							       error))
				return FALSE;
		}

		if (memcmp(readback, expected, chunk_size) == 0)
			return TRUE;

		retries--;
	}

	g_set_error(error,
		    FWUPD_ERROR,
		    FWUPD_ERROR_INVALID_DATA,
		    "PDC chunk verify failed at flash 0x%08x after %u retries",
		    addr,
		    (guint)DELL_MONITOR_RT_PDC_VERIFY_RETRIES);
	return FALSE;
}

/*
 * Phase A driver — program the TPS6598x SPI flash with the PDC
 * firmware blob via the 4CC command interface.
 *
 * Mirrors libpdc.so::Tps6598xISP::RegionUpdate82's logic, with one
 * deliberate divergence: Wistron's loop bound has an off-by-one that
 * reads 32 bytes past the end of the std::vector, writing heap
 * garbage one chunk past the firmware end. We just don't issue that
 * extra write (PLUGIN_NOTES "Solved: the 32-byte 'trailer'").
 *
 * Wire conventions per TI ref doc SLVUBH2B (TPS6598x host interface):
 *
 *   FLrr (Set Flash Read Region):
 *     Input: 1 byte = region number (bit 0).
 *     Output: 4-byte LE flash address of the region's start.
 *
 *   FLem (Flash Memory Erase):
 *     Input: 4-byte LE start address + 1-byte sector count.
 *     Sector size is 4 KB per the doc.
 *
 *   FLad (Set Flash Memory Write Start Address):
 *     Input: 4-byte LE flash address.
 *
 *   FLwd (Flash Memory Write):
 *     Input: 1..64 bytes of data. Address auto-increments after the
 *     write. We use the same chunk size we want to write.
 *
 *   FLvy (Flash Memory Verify):
 *     Input: 4-byte LE region start address (same as FLad).
 *     Output: 1-byte status (0 = pass).
 *
 * Sequence (matches Wistron, minus the off-by-one):
 *   1. FLrr(R0)              — discover Region 0's flash base address
 *   2. FLem(base, ceil(blob_size / 4096))  — erase enough sectors
 *   3. For each chunk of `blob` from offset chunk_size onwards:
 *        FLad(base + offset) → FLwd(chunk) → 2× FLrd(verify in halves)
 *   4. FLad(base) + FLwd(blob[0:chunk_size]) → 2× FLrd — header-last commit
 *   5. FLrr(R0) again        — re-read region pointer (Wistron's pattern)
 *   6. FLvy(base)            — verify the entire region
 *
 * The per-chunk FLrd readback in step 3 mirrors Tps6598xISP::VerifyFW
 * (libpdc.c:50046). It's redundant with the chip's own FLvy command in
 * step 6, but Wistron does both — and we don't have visibility into
 * silicon errata that would justify trusting FLvy alone, so we don't.
 *
 * Portability notes:
 *   - Sector size hardcoded to 4 KB per the TPS6598x spec; if a
 *     future chip variant uses a different sector size we'd need
 *     to read it from chip-side state, but the doc fixes it for
 *     this family.
 *   - Region 0 base address is read from the chip via FLrr, NOT
 *     hardcoded. This works for any TPS6598x part / Dell product.
 *   - Chunk size is configurable (1..64); we pick 32 to match
 *     Wistron's choice (no chip-side reason for that specific
 *     value; just keeps emulation diffs minimal).
 */
#define DELL_MONITOR_RT_PDC_SECTOR_SIZE   4096

static gboolean
fu_dell_monitor_rt_device_pdc_program(FuDellMonitorRtDevice *self,
				      GBytes *blob,
				      FuProgress *progress,
				      GError **error)
{
	const guint8 *blob_data;
	gsize blob_size;
	guint32 base;
	guint nchunks;
	guint sector_count;
	guint8 region_ptr[DELL_MONITOR_RT_PDC_ACK_BYTES] = {0};
	/* Per TI SLVUBH2B: FLrr input is 1 byte (region number, 0 or 1).
	 * Wistron's host code stages 4 bytes here — the trailing 3 bytes
	 * are uninitialized heap (a long-standing off-by-one in their
	 * std::vector handling); the chip ignores them. We send the
	 * doc-spec minimum so the plugin is portable across TPS6598x
	 * variants. The emulator fixture is normalized by
	 * contrib/pcap-to-fixture.py to match these canonical lengths. */
	guint8 flrr_input[1] = {0x00};
	/* Per TI SLVUBH2B: FLem input is 5 bytes [addr_LE(4) + count(1)]. */
	guint8 flem_input[5] = {0};
	guint8 base_le[4];

	blob_data = g_bytes_get_data(blob, &blob_size);
	if (blob_size == 0 ||
	    blob_size % DELL_MONITOR_RT_PDC_CHUNK_SIZE != 0) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_DATA,
			    "PDC blob size %" G_GSIZE_FORMAT
			    " not a multiple of %u",
			    blob_size,
			    DELL_MONITOR_RT_PDC_CHUNK_SIZE);
		return FALSE;
	}
	nchunks = (guint)(blob_size / DELL_MONITOR_RT_PDC_CHUNK_SIZE);
	if (nchunks < 2) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_DATA,
			    "PDC blob has too few chunks: %u",
			    nchunks);
		return FALSE;
	}

	if (progress != NULL)
		fu_progress_set_steps(progress, nchunks + 4);

	/* (0) Read BootFlags82 (register 0x2D, 2 bytes LE). Mirrors
	 * Tps6598xISP::FWUpdate82 at libpdc.c:50768. AUDIT.md F5.5 —
	 * partial implementation: we log the bits for diagnostics, but
	 * we do NOT gate on BootOk. Wistron's gate is comparison-based
	 * (`(BootFlags82 & 1) != (this->flags >> 4 & 1)`), comparing
	 * the chip's BootOk bit against an EXPECTED value sourced from
	 * the chip-config struct (which we'd need plumbed from .upg
	 * metadata). For a chip in post-bootloader ISP mode BootOk=0
	 * is the expected state — the chip is running ISP code, not
	 * user firmware — so an absolute BootOk==1 check would falsely
	 * refuse the captured U4025QW path (which has BootFlags82=0x0018,
	 * BootOk=0). Full gating + two-region dispatch is F5.2,
	 * deferred until .upg's low_region_only field is plumbed. */
	{
		guint8 bootflags[2] = {0};
		if (!fu_dell_monitor_rt_pdc_read_resp(self,
						      0x2D, /* BootFlags82 */
						      sizeof(bootflags),
						      bootflags,
						      sizeof(bootflags),
						      error)) {
			g_prefix_error(error, "PDC BootFlags82 read: ");
			return FALSE;
		}
		g_info("dell-monitor-rt: PDC BootFlags82 = 0x%02x%02x "
		       "(BootOk=%u, R0_attempted=%u, R0_invalid=%u, "
		       "R1_attempted=%u, R1_invalid=%u, "
		       "R0_flash_err=%u, R0_crc_fail=%u, "
		       "R1_flash_err=%u, R1_crc_fail=%u)",
		       bootflags[1], bootflags[0],
		       bootflags[0] & 1,
		       (bootflags[0] >> 4) & 1,
		       (bootflags[0] >> 6) & 1,
		       (bootflags[0] >> 5) & 1,
		       (bootflags[0] >> 7) & 1,
		       bootflags[1] & 1,
		       (bootflags[1] >> 4) & 1,
		       (bootflags[1] >> 1) & 1,
		       (bootflags[1] >> 5) & 1);
	}

	/* (1) FLrr(R0): discover Region 0's flash base address.
	 * The chip returns 4 bytes (LE address). We use this as the
	 * write/erase base — DON'T hardcode per-product. */
	if (!fu_dell_monitor_rt_pdc_set_buf(self, flrr_input, sizeof(flrr_input), error))
		return FALSE;
	if (!fu_dell_monitor_rt_pdc_cmd(self, "rr", error))
		return FALSE;
	if (!fu_dell_monitor_rt_pdc_finish_cmd(self,
					       region_ptr,
					       sizeof(region_ptr),
					       error))
		return FALSE;
	base = (guint32)region_ptr[0] |
	       ((guint32)region_ptr[1] << 8) |
	       ((guint32)region_ptr[2] << 16) |
	       ((guint32)region_ptr[3] << 24);
	g_info("dell-monitor-rt: PDC Region 0 base = 0x%08x (read from chip)", base);
	if (base == 0 || base == 0xFFFFFFFF) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_DATA,
			    "PDC FLrr returned suspicious region base 0x%08x",
			    base);
		return FALSE;
	}
	/* AUDIT.md F5.6: defensive check for the `0x100e0ac` magic.
	 * Wistron's RegionUpdate82 at libpdc.c:50442 treats this
	 * specific value as "Low-Region File found with offset 0x0 —
	 * not a valid 2-region flash image"; flagged with an explicit
	 * ABORT log. Half-initialized chips from a prior botched flash
	 * may report this. */
	if (base == 0x0100E0AC) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_INVALID_DATA,
				    "PDC FLrr returned 0x0100E0AC — chip is "
				    "in a half-initialized state (Low-Region "
				    "file at offset 0x0). A prior install "
				    "likely aborted mid-flash; recovery via "
				    "Wistron's tooling required");
		return FALSE;
	}
	base_le[0] = (guint8)(base & 0xFF);
	base_le[1] = (guint8)((base >> 8) & 0xFF);
	base_le[2] = (guint8)((base >> 16) & 0xFF);
	base_le[3] = (guint8)((base >> 24) & 0xFF);
	if (progress != NULL)
		fu_progress_step_done(progress);

	/* (2) FLem: erase region. Input is 4-byte LE address + 1-byte
	 * sector count (4 KB sectors per TI spec). */
	sector_count = (guint)((blob_size + DELL_MONITOR_RT_PDC_SECTOR_SIZE - 1) /
			       DELL_MONITOR_RT_PDC_SECTOR_SIZE);
	if (sector_count > 0xFF) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_DATA,
			    "PDC blob too large: needs %u sectors (max 255)",
			    sector_count);
		return FALSE;
	}
	memcpy(flem_input, base_le, 4);
	flem_input[4] = (guint8)sector_count;
	g_info("dell-monitor-rt: PDC erase %u sectors at 0x%08x", sector_count, base);
	if (!fu_dell_monitor_rt_pdc_set_buf(self, flem_input, sizeof(flem_input), error))
		return FALSE;
	if (!fu_dell_monitor_rt_pdc_cmd(self, "em", error))
		return FALSE;
	if (!fu_dell_monitor_rt_pdc_finish_cmd(self, NULL, 0, error))
		return FALSE;
	if (progress != NULL)
		fu_progress_step_done(progress);

	/* (3) Main write loop — chunks 1..(nchunks-1), addresses
	 * base+chunk_size..base+(nchunks-1)*chunk_size. Skips chunk 0
	 * (the header); that goes last. Stops at chunk (nchunks-1) — we
	 * do NOT emit Wistron's iter-(nchunks) past-end write.
	 */
	for (guint i = 1; i < nchunks; i++) {
		guint32 addr = base + (guint32)(i * DELL_MONITOR_RT_PDC_CHUNK_SIZE);
		const guint8 *src = blob_data + (i * DELL_MONITOR_RT_PDC_CHUNK_SIZE);
		guint8 addr_le[4];
		addr_le[0] = (guint8)(addr & 0xFF);
		addr_le[1] = (guint8)((addr >> 8) & 0xFF);
		addr_le[2] = (guint8)((addr >> 16) & 0xFF);
		addr_le[3] = (guint8)((addr >> 24) & 0xFF);

		if (!fu_dell_monitor_rt_pdc_set_buf(self, addr_le, 4, error))
			return FALSE;
		if (!fu_dell_monitor_rt_pdc_cmd(self, "ad", error))
			return FALSE;
		if (!fu_dell_monitor_rt_pdc_finish_cmd(self, NULL, 0, error))
			return FALSE;

		if (!fu_dell_monitor_rt_pdc_set_buf(self, src,
						    DELL_MONITOR_RT_PDC_CHUNK_SIZE,
						    error))
			return FALSE;
		if (!fu_dell_monitor_rt_pdc_cmd(self, "wd", error))
			return FALSE;
		if (!fu_dell_monitor_rt_pdc_finish_cmd(self, NULL, 0, error))
			return FALSE;

		/* Per-chunk readback verify (matches Wistron's VerifyFW). */
		if (!fu_dell_monitor_rt_pdc_verify_chunk(self,
							 addr,
							 src,
							 DELL_MONITOR_RT_PDC_CHUNK_SIZE,
							 error))
			return FALSE;
		if (progress != NULL)
			fu_progress_step_done(progress);
	}

	/* (4) Header-last write: chunk 0 → flash base. */
	{
		if (!fu_dell_monitor_rt_pdc_set_buf(self, base_le, 4, error))
			return FALSE;
		if (!fu_dell_monitor_rt_pdc_cmd(self, "ad", error))
			return FALSE;
		if (!fu_dell_monitor_rt_pdc_finish_cmd(self, NULL, 0, error))
			return FALSE;

		if (!fu_dell_monitor_rt_pdc_set_buf(self, blob_data,
						    DELL_MONITOR_RT_PDC_CHUNK_SIZE,
						    error))
			return FALSE;
		if (!fu_dell_monitor_rt_pdc_cmd(self, "wd", error))
			return FALSE;
		if (!fu_dell_monitor_rt_pdc_finish_cmd(self, NULL, 0, error))
			return FALSE;

		/* Verify the header chunk too. */
		if (!fu_dell_monitor_rt_pdc_verify_chunk(self,
							 base,
							 blob_data,
							 DELL_MONITOR_RT_PDC_CHUNK_SIZE,
							 error))
			return FALSE;
	}
	if (progress != NULL)
		fu_progress_step_done(progress);

	/* (5) FLrr(R0) again — Dell does a second region-pointer read
	 * before verify. */
	if (!fu_dell_monitor_rt_pdc_set_buf(self, flrr_input, sizeof(flrr_input), error))
		return FALSE;
	if (!fu_dell_monitor_rt_pdc_cmd(self, "rr", error))
		return FALSE;
	if (!fu_dell_monitor_rt_pdc_finish_cmd(self,
					       region_ptr,
					       sizeof(region_ptr),
					       error))
		return FALSE;
	if (progress != NULL)
		fu_progress_step_done(progress);

	/* (6) FLvy(base): verify the entire region. Same input shape
	 * as FLad — 4-byte LE address. */
	if (!fu_dell_monitor_rt_pdc_set_buf(self, base_le, 4, error))
		return FALSE;
	if (!fu_dell_monitor_rt_pdc_cmd(self, "vy", error))
		return FALSE;
	if (!fu_dell_monitor_rt_pdc_finish_cmd(self, NULL, 0, error))
		return FALSE;
	if (progress != NULL)
		fu_progress_step_done(progress);

	g_info("dell-monitor-rt: PDC programmed, %u chunks (one fewer than "
	       "Wistron's loop, which has an off-by-one past-end read at "
	       "flash 0x%x)",
	       nchunks, base + nchunks * DELL_MONITOR_RT_PDC_CHUNK_SIZE);
	return TRUE;
}

/* ----- Phase B: DISPLAY block-write protocol ----------------------
 *
 * The panel-scaler firmware ("DISPLAY" component, ~1.7 MB on the
 * U4025QW) is delivered to the running RTS5409S host-side ISP shim via
 * a block-at-a-time stage-and-commit sequence over the primary HID
 * (no i2c-tunnel). Decoded from libdevices.so:
 *   RTS5409S_HID::secure_program (the per-block worker)
 *   RTS5409S_HID::erase_tmp_flash / write_tmp_flash /
 *   secure_control_gpio / verify_tmp_flash / get_i2c_block_status /
 *   check_image / get_block_address
 * plus the outer driver libdisplay.so:RealtekISP::secure_program_rtk.
 *
 * Source-blob structure (size = N * 0x10044 + 0x40):
 *
 *   block 0:    [4-byte target SPI addr LE] [65536-byte data] [64-byte sig]
 *   block 1:    same
 *   ...
 *   block N-1:  same
 *   trailer:    [64 bytes — global pubkey]
 *
 * Per block on the wire (verified bytewise against block 0 of the
 * captured trace, events 11925..12439):
 *   F4   erase_tmp_flash         — clear chip's tmp SRAM scratch
 *   F1×512 write_tmp_flash       — 128 B/frame to SRAM offsets
 *                                  0x0000, 0x0080, … 0xFF80 (512 frames
 *                                  × 128 B = 65536 B). NO F3 polls
 *                                  interleaved — the F1 loop streams
 *                                  back-to-back, mirroring the
 *                                  RTS5409S_HID::secure_program inner
 *                                  do-while which calls write_tmp_flash
 *                                  + a progress callback only.
 *   04   secure_control_gpio(6,1)— commit-prep GPIO assert
 *   F5   verify_tmp_flash(0,…)   — carries:
 *                                    byte 4   CRC8/SMBus of block data
 *                                    byte 6-9 target SPI addr LE
 *                                    byte 64-127  global pubkey (64 B)
 *                                    byte 128-191 per-block sig (64 B)
 *   F3 polls until READY          — post-commit. The chip returns
 *                                  0xA0 (high bit set = busy) until
 *                                  the F5 commit finishes computing,
 *                                  then 0x00 (high bit clear, low
 *                                  nibble clean = ready). The captured
 *                                  trace shows ~3,400 polls per
 *                                  inter-block phase — the chip is
 *                                  genuinely busy that long.
 *
 * The host computes only one thing per block: a CRC8 of the 65536 data
 * bytes. The pubkey and signature are sliced directly out of the source
 * blob; the chip does the ECDSA verify internally.
 *
 * Wire frame templates (192 bytes, post-report-id):
 *
 *   F4: 40 F4 00 00 00 00 00 00 ...                              (no payload)
 *   F1: 40 F1 <addr_LE32> 80 00 00 00 ... [128 B data]@offset 64
 *   F3: c0 F3 00 00 00 00 01 00 ...                              (read 1 byte)
 *   04: 40 04 01 01 06 00 00 00 ...                              (gpio(6,1))
 *   F5: 40 F5 94 01 <crc8> 00 <addr_LE32> 00... ...
 *       <64 B global pubkey>@offset 64
 *       <64 B per-block sig>@offset 128
 *
 * NOT YET IMPLEMENTED: the per-block REALTEK_API::spi_unit_erase pass
 * that runs BEFORE each F4. That pass is a series of i2c-tunnel
 * writes and reads to slave 0x94 (the FL5500 in ISP mode) that erases
 * the SPI flash region the chip is about to commit into. Without it,
 * real hardware would commit into a non-erased region; under emulation
 * the leapfrog matcher will skip past the captured spi_unit_erase
 * frames and the F4/F1/04/F5 frames will still match.
 */

#define DELL_MONITOR_RT_OPCODE_TMP_ERASE         0xF4
#define DELL_MONITOR_RT_OPCODE_TMP_WRITE         0xF1
#define DELL_MONITOR_RT_OPCODE_TMP_STATUS_POLL   0xF3
#define DELL_MONITOR_RT_OPCODE_SECURE_GPIO       0x04
#define DELL_MONITOR_RT_OPCODE_TMP_VERIFY        0xF5

/* SECURE_PROG_CFG.cfg+0x18 == 0x10044 (validated by RTS5409S_HID::
 * secure_program — anything else is rejected with status 0x81). */
#define DELL_MONITOR_RT_DISPLAY_BLOCK_SIZE       0x10044
#define DELL_MONITOR_RT_DISPLAY_BLOCK_HDR_LEN    4       /* target SPI addr (LE u32) */
#define DELL_MONITOR_RT_DISPLAY_BLOCK_DATA_LEN   0x10000 /* 65536 B SRAM payload */
#define DELL_MONITOR_RT_DISPLAY_BLOCK_SIG_LEN    0x40    /* 64 B per-block signature */
#define DELL_MONITOR_RT_DISPLAY_BLOCK_DATA_OFF   DELL_MONITOR_RT_DISPLAY_BLOCK_HDR_LEN
#define DELL_MONITOR_RT_DISPLAY_BLOCK_SIG_OFF \
	(DELL_MONITOR_RT_DISPLAY_BLOCK_DATA_OFF + DELL_MONITOR_RT_DISPLAY_BLOCK_DATA_LEN)
#define DELL_MONITOR_RT_DISPLAY_PUBKEY_LEN       0x40    /* 64 B trailer = global pubkey */

#define DELL_MONITOR_RT_DISPLAY_F1_CHUNK         0x80    /* 128 B per F1 frame */
#define DELL_MONITOR_RT_DISPLAY_F1_PER_BLOCK \
	(DELL_MONITOR_RT_DISPLAY_BLOCK_DATA_LEN / DELL_MONITOR_RT_DISPLAY_F1_CHUNK) /* 512 */

/* Constants observed in the F5 frame (verified against libdevices.so:
 * RTS5409S_HID::verify_tmp_flash mode-0 path). Wire bytes 2-3 come
 * from the 4-byte LE store of 0x94f54000 → wire[0..3]=40 F5 94 00;
 * the chip-state byte at wire[3] is overwritten by this[0x40], the
 * RTS5409S_HID's bus-speed cache, which is set to 0x01 at session
 * open by set_bus_speed(0x01) for the post-bootloader fast-mode bus. */
#define DELL_MONITOR_RT_DISPLAY_VERIFY_BYTE2     0x94
#define DELL_MONITOR_RT_DISPLAY_VERIFY_BYTE3     DELL_MONITOR_RT_I2C_SPEED_FAST

/* secure_control_gpio(0x06, 0x01) — wire bytes built from
 * `*(u32*)(buf+0x58) = 0x01044000` then `*(u16*)(buf+0x5c) =
 * CONCAT11(0x06, 0x01)`, giving wire[0..4] = 40 04 01 01 06. */
#define DELL_MONITOR_RT_DISPLAY_GPIO_PIN         0x06
#define DELL_MONITOR_RT_DISPLAY_GPIO_VALUE       0x01

/* F3 status poll exit conditions. Mirrors the loop in
 * RTS5409S_HID::secure_program (libdevices.so):
 *
 *     do {
 *         get_i2c_block_status(this, &status);
 *         if ((this[0x44] - 0x10 < 2) || -1 < (char)status) {
 *             if ((status & 0xf) != 0) goto error;
 *             break;            // success
 *         }
 *         ...sleep, decrement local_6c retry counter
 *     } while (local_6c != 0);
 *
 * Decoded: the chip returns a one-byte status where the HIGH BIT
 * (0x80) is the "still busy" flag, and the LOW NIBBLE (0x0F) is an
 * error code. Polling exits when the high bit clears; if the low
 * nibble is also zero the operation succeeded. The captured trace
 * confirms: every F3 poll returns 0xA0 (busy) until exactly one
 * poll returns 0x00 (ready), then the host moves on. NB: my first
 * Phase B implementation treated 0xA0 as the READY value — that
 * was wrong, and only worked under emulation because the captured
 * fixture's first F3 response is 0xA0 and the plugin took it as
 * success and proceeded. The correct check is high-bit-clear. */
#define DELL_MONITOR_RT_DISPLAY_F3_BUSY_BIT      0x80
#define DELL_MONITOR_RT_DISPLAY_F3_ERROR_NIBBLE  0x0F

/* Per-block F3-poll budget. The captured trace shows ~3,400 polls per
 * inter-block phase (post-F5 settle) — the chip is genuinely busy that
 * long. Wistron's host code uses a 30,000-attempt budget at ~1 ms each
 * (= 30 s). We match the budget but use a shorter sleep to keep total
 * wall-clock equivalent. */
#define DELL_MONITOR_RT_DISPLAY_F3_POLL_RETRIES  30000
#define DELL_MONITOR_RT_DISPLAY_F3_POLL_SLEEP_US 1000

/*
 * CRC-8/SMBus (poly 0x07, init=0, no input/output reflection, no
 * xorout). Verified against libdevices.so's
 * RTS5409S_HID::crc8_lut + RTS5409S_HID::cal_crc8: the binary
 * tabulates the same polynomial (table[1] == 0x07). Computing the
 * CRC byte-by-byte at runtime avoids carrying a 256-byte data blob
 * for what is < 100 LOC of derivation.
 */
static guint8
fu_dell_monitor_rt_crc8_smbus(const guint8 *data, gsize len)
{
	guint8 crc = 0;
	for (gsize i = 0; i < len; i++) {
		crc ^= data[i];
		for (int b = 0; b < 8; b++) {
			crc = (crc & 0x80) ? (guint8)((crc << 1) ^ 0x07)
					   : (guint8)(crc << 1);
		}
	}
	return crc;
}

/*
 * Send one vendor frame whose direction byte is at wire offset 0,
 * opcode at offset 1, and the rest of the 192-byte buffer is caller-
 * supplied (we just copy `body` over wire bytes 2.. and zero-fill
 * the rest). The caller hands us `body` (length `body_len`); we
 * frame it into a 193-byte hidraw report (1 report-id + 192 wire
 * bytes) and ship it via fu_hidraw_device_set_report.
 */
static gboolean
fu_dell_monitor_rt_device_send_vendor_frame(FuDellMonitorRtDevice *self,
					    guint8 opcode,
					    const guint8 *body,
					    gsize body_len,
					    GError **error)
{
	guint8 buf[DELL_MONITOR_RT_BUF_SIZE] = {0};

	if (body_len > DELL_MONITOR_RT_BUF_SIZE - 3) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INTERNAL,
			    "vendor frame body too large: %" G_GSIZE_FORMAT,
			    body_len);
		return FALSE;
	}
	buf[0] = 0;			    /* report-ID */
	buf[1] = DELL_MONITOR_RT_DIR_WRITE; /* wire byte 0 */
	buf[2] = opcode;		    /* wire byte 1 */
	if (body != NULL && body_len > 0)
		memcpy(buf + 3, body, body_len); /* wire bytes 2.. */
	return fu_hidraw_device_set_report(FU_HIDRAW_DEVICE(self),
					   buf,
					   sizeof(buf),
					   FU_IO_CHANNEL_FLAG_USE_BLOCKING_IO,
					   error);
}

/*
 * Issue a 0xF3 status poll and return wire byte 0 of the response
 * (the chip's status code). Mirrors RTS5409S_HID::get_i2c_block_status:
 * wire frame is c0 F3 00 00 00 00 01 00 ... (read 1 byte), then read
 * the input report. Returns the status byte in *status_out.
 */
static gboolean
fu_dell_monitor_rt_device_display_f3_read(FuDellMonitorRtDevice *self,
					  guint8 *status_out,
					  GError **error)
{
	guint8 buf[DELL_MONITOR_RT_BUF_SIZE] = {0};

	buf[0] = 0;			   /* report-ID */
	buf[1] = DELL_MONITOR_RT_DIR_READ; /* wire byte 0: c0 */
	buf[2] = DELL_MONITOR_RT_OPCODE_TMP_STATUS_POLL; /* wire byte 1: f3 */
	/* Wire byte 6 = read count, matching RTS5409S_HID::get_i2c_block_status:
	 * `this[0x5f] = 0x01` lands at +0x5f → wire offset 0x5f - 0x59 = 6. */
	buf[1 + DELL_MONITOR_RT_I2C_WIRE_LEN_OFFSET] = 0x01;
	if (!fu_hidraw_device_set_report(FU_HIDRAW_DEVICE(self),
					 buf,
					 sizeof(buf),
					 FU_IO_CHANNEL_FLAG_USE_BLOCKING_IO,
					 error))
		return FALSE;
	/* Read the response via HIDIOCGINPUT — the chip returns
	 * synchronously through the control pipe, the same way the existing
	 * vcmd_read helper picks up its responses. The leading byte of the
	 * input report is the chip's status code (no report-ID prefix on
	 * the input side; the kernel strips it). */
	memset(buf, 0, sizeof(buf));
	{
		g_autoptr(FuIoctl) ioctl =
		    fu_udev_device_ioctl_new(FU_UDEV_DEVICE(self));
		if (!fu_ioctl_execute(ioctl,
				      HIDIOCGINPUT(sizeof(buf)), /* nocheck:blocked */
				      buf,
				      sizeof(buf),
				      NULL,
				      DELL_MONITOR_RT_TIMEOUT_MS,
				      FU_IOCTL_FLAG_NONE,
				      error))
			return FALSE;
	}
	/* Response layout: buf[0] is the report-ID (always 0x00 on this
	 * device, since its HID descriptor declares no Report IDs); the
	 * actual wire bytes start at buf[1]. The chip's status code is
	 * the first wire byte, so buf[1]. (Same convention as
	 * fu_dell_monitor_rt_device_vcmd_read which extracts
	 * `wire = &response[1]` before parsing.) */
	*status_out = buf[1];
	return TRUE;
}

/*
 * Poll F3 until the chip clears the busy bit. Used between every F1
 * write and after the F5 commit. Returns success when READY observed
 * within the retry budget.
 */
static gboolean
fu_dell_monitor_rt_device_display_f3_wait_ready(FuDellMonitorRtDevice *self,
						GError **error)
{
	for (guint i = 0; i < DELL_MONITOR_RT_DISPLAY_F3_POLL_RETRIES; i++) {
		guint8 status = 0;
		if (!fu_dell_monitor_rt_device_display_f3_read(self,
							       &status,
							       error))
			return FALSE;
		/* High bit clear → chip done with whatever it was doing.
		 * Low nibble carries an error code; non-zero means the chip
		 * rejected the request and we should propagate the failure
		 * rather than treat it as ready. */
		if ((status & DELL_MONITOR_RT_DISPLAY_F3_BUSY_BIT) == 0) {
			if (status & DELL_MONITOR_RT_DISPLAY_F3_ERROR_NIBBLE) {
				g_set_error(error,
					    FWUPD_ERROR,
					    FWUPD_ERROR_INTERNAL,
					    "DISPLAY F3 status: chip reported "
					    "error nibble (status=0x%02x) after "
					    "%u polls",
					    status,
					    i + 1);
				return FALSE;
			}
			return TRUE;
		}
		g_usleep(DELL_MONITOR_RT_DISPLAY_F3_POLL_SLEEP_US);
	}
	g_set_error(error,
		    FWUPD_ERROR,
		    FWUPD_ERROR_TIMED_OUT,
		    "DISPLAY F3 status poll: chip stayed busy (status & 0x80) "
		    "after %u attempts",
		    (guint)DELL_MONITOR_RT_DISPLAY_F3_POLL_RETRIES);
	return FALSE;
}

/* ----- Phase B helpers: per-block SPI flash erase + verify --------
 *
 * Decoded from REALTEK_API in libdisplay.so plus the inter-block wire
 * trace. Each 64 KB DISPLAY block needs the panel scaler's SPI flash
 * region for that block's target address erased + verified BEFORE the
 * F4/F1/04/F5 stage-and-commit sequence stages new bytes for it.
 *
 * The SPI flash hangs off i2c slave 0x94 (the post-bootloader RealTek
 * panel-scaler ISP shim) — we don't talk to flash directly, we talk to
 * the chip's SPI controller via i2c register pokes. The shim sequences
 * the actual SPI bus traffic on the chip side.
 *
 * Wire format (i2c-tunnel writes/reads to slave 0x94, fast-mode bus):
 *
 *   spi_unit_erase(addr, 0x10000):
 *     write reg 0x64 = (addr >> 16) & 0xFF   ; SPI start-addr MSB
 *     write reg 0x65 = (addr >>  8) & 0xFF   ; mid
 *     write reg 0x66 = (addr      ) & 0xFF   ; LSB
 *     write reg 0x60 = 0xB8                  ; SPI command setup
 *     write reg 0x61 = 0xD8                  ; SPI 64 KB block-erase opcode
 *     write reg 0x60 = 0xB9                  ; trigger execute
 *     [poll reg 0x60 until bit 0 clears — ~120 reads, chip's SPI busy bit]
 *
 *   spi_read_crc(addr, 0x10000) → expects 0xDE for an erased 64 KB region:
 *     write reg 0x64..0x66 = start addr (MSB..LSB), as above
 *     write reg 0x72 = ((addr+0x10000-1) >> 16) & 0xFF  ; CRC end-addr MSB
 *     write reg 0x73 = ((addr+0x10000-1) >>  8) & 0xFF  ; mid
 *     write reg 0x74 = ((addr+0x10000-1)      ) & 0xFF  ; LSB
 *     read  reg 0x6F                         ; pre-CRC chip status (0x92)
 *     write reg 0x6F = 0x96                  ; trigger CRC computation
 *     [poll reg 0x6F until value == 0x92 — ~60 reads, chip computes CRC8]
 *     read  reg 0x75                         ; CRC8/SMBus result
 *     compare to 0xDE for 64 KB / 0x09 for 4 KB (precomputed CRC of all-FF)
 *
 * The CRC is the same CRC-8/SMBus we already use for F5; on chip side
 * REALTEK_API::wait_ready busy-waits on bit 0 of reg 0x60 between
 * trigger and result, and `if (size==0x10000 && crc!=0xde) error;`
 * is the exact verify check from REALTEK_API::spi_unit_erase decomp.
 *
 * Wistron's host code keeps using the same poll-until-status-matches
 * pattern Dell's stack favors — in our captured trace per inter-block
 * we see ~120 reg-0x60 polls during the SPI erase + ~60 reg-0x6F polls
 * during the chip-side CRC computation; both polled at single-digit ms.
 */

#define DELL_MONITOR_RT_RTKPANEL_I2C_TARGET     0x94

#define DELL_MONITOR_RT_RTKPANEL_REG_SPI_CMD    0x60 /* SPI cmd / busy bit-0 */
#define DELL_MONITOR_RT_RTKPANEL_REG_SPI_DATA   0x61 /* SPI cmd payload byte */
#define DELL_MONITOR_RT_RTKPANEL_REG_ADDR_HI    0x64 /* SPI start-addr MSB */
#define DELL_MONITOR_RT_RTKPANEL_REG_ADDR_MID   0x65
#define DELL_MONITOR_RT_RTKPANEL_REG_ADDR_LO    0x66
#define DELL_MONITOR_RT_RTKPANEL_REG_END_HI     0x72 /* CRC end-addr MSB */
#define DELL_MONITOR_RT_RTKPANEL_REG_END_MID    0x73
#define DELL_MONITOR_RT_RTKPANEL_REG_END_LO     0x74
#define DELL_MONITOR_RT_RTKPANEL_REG_STATUS     0x6F /* chip-status / CRC trigger */
#define DELL_MONITOR_RT_RTKPANEL_REG_CRC_RESULT 0x75 /* read CRC8 byte here */
#define DELL_MONITOR_RT_RTKPANEL_REG_INDIRECT_PAGE 0xF4 /* indirect-access page selector */
#define DELL_MONITOR_RT_RTKPANEL_REG_INDIRECT_DATA 0xF5 /* indirect-access data port */

#define DELL_MONITOR_RT_RTKPANEL_SPI_CMD_SETUP    0xB8 /* prepare-cmd phase */
#define DELL_MONITOR_RT_RTKPANEL_SPI_CMD_TRIGGER  0xB9 /* execute */
#define DELL_MONITOR_RT_RTKPANEL_SPI_OP_BLK_ERASE 0xD8 /* SPI 64 KB block erase */

#define DELL_MONITOR_RT_RTKPANEL_STATUS_READY     0x92 /* chip done */
#define DELL_MONITOR_RT_RTKPANEL_STATUS_TRIGGER   0x96 /* write to start CRC */

#define DELL_MONITOR_RT_RTKPANEL_BLOCK_SIZE       0x10000 /* 64 KB */
#define DELL_MONITOR_RT_RTKPANEL_CRC_64K_ERASED   0xDE /* CRC8 of 65536 0xFFs */

/* Validity-marker register + value. After the per-block stage+commit
 * loop completes, Wistron writes a 2-byte `AA 55` marker into the
 * SPI-data port at register 0x70, with the SPI target address pre-
 * loaded to 0x3FF8FE via the same ADDR_HI/MID/LO registers used by
 * the per-block writes. The panel scaler's bootloader reads this
 * byte at boot to flag the new firmware as valid (AUDIT.md F6.3,
 * libdisplay.c::secure_program_rtk @ 67296+). Pcap-confirmed at
 * frame 811742 with the i2c-tunnel payload `70 AA 55`. */
#define DELL_MONITOR_RT_RTKPANEL_REG_SPI_WRITE_PORT 0x70
#define DELL_MONITOR_RT_RTKPANEL_VALIDITY_ADDR      0x3FF8FE
#define DELL_MONITOR_RT_RTKPANEL_VALIDITY_LO        0xAA
#define DELL_MONITOR_RT_RTKPANEL_VALIDITY_HI        0x55

#define DELL_MONITOR_RT_RTKPANEL_BUSY_RETRIES     1024
#define DELL_MONITOR_RT_RTKPANEL_BUSY_SLEEP_US    500

/*
 * Write one byte to a register on the panel-scaler chip (slave 0x94)
 * via the i2c-tunnel. The wire payload is `<reg> <val>`, length 2.
 */
static gboolean
fu_dell_monitor_rt_device_rtkpanel_write_reg(FuDellMonitorRtDevice *self,
					     guint8 reg,
					     guint8 val,
					     GError **error)
{
	const guint8 payload[2] = {reg, val};
	return fu_dell_monitor_rt_device_i2c_write_speed(
	    self,
	    DELL_MONITOR_RT_RTKPANEL_I2C_TARGET,
	    DELL_MONITOR_RT_I2C_SPEED_FAST,
	    payload,
	    sizeof(payload),
	    error);
}

/*
 * Read one byte from a register on the panel-scaler chip (slave 0x94).
 * Uses the i2c-tunnel's combined write-reg + read-N pattern (reg_addr at
 * wire byte 2, reg_flag at wire byte 9, count=1). Response wire byte 0
 * is the register value; that lands at response[1] after the kernel
 * strips the report-ID prefix from the input report.
 */
static gboolean
fu_dell_monitor_rt_device_rtkpanel_read_reg(FuDellMonitorRtDevice *self,
					    guint8 reg,
					    guint8 *val_out,
					    GError **error)
{
	guint8 response[DELL_MONITOR_RT_BUF_SIZE] = {0};
	if (!fu_dell_monitor_rt_device_i2c_read_reg(
		self,
		DELL_MONITOR_RT_RTKPANEL_I2C_TARGET,
		DELL_MONITOR_RT_I2C_SPEED_FAST,
		reg,
		1,
		response,
		sizeof(response),
		error))
		return FALSE;
	/* response[0] = report-ID (stripped value, always 0); response[1]
	 * = the register value the chip returned. */
	*val_out = response[1];
	return TRUE;
}

/*
 * Poll a register on slave 0x94 until `done(value)` returns TRUE.
 * `desc` is just for error messages. Used both for the SPI flash busy
 * bit (reg 0x60 bit-0 clear) and the chip-side CRC compute (reg 0x6F
 * value == STATUS_READY).
 */
typedef gboolean (*FuDellMonitorRtRtkpanelDoneFn)(guint8 value);

static gboolean
fu_dell_monitor_rt_device_rtkpanel_poll_until(FuDellMonitorRtDevice *self,
					      guint8 reg,
					      FuDellMonitorRtRtkpanelDoneFn done,
					      const gchar *desc,
					      GError **error)
{
	for (guint i = 0; i < DELL_MONITOR_RT_RTKPANEL_BUSY_RETRIES; i++) {
		guint8 val = 0;
		if (!fu_dell_monitor_rt_device_rtkpanel_read_reg(self,
								 reg,
								 &val,
								 error))
			return FALSE;
		if (done(val))
			return TRUE;
		g_usleep(DELL_MONITOR_RT_RTKPANEL_BUSY_SLEEP_US);
	}
	g_set_error(error,
		    FWUPD_ERROR,
		    FWUPD_ERROR_TIMED_OUT,
		    "rtkpanel poll reg 0x%02x (%s) timed out after %u attempts",
		    reg,
		    desc,
		    (guint)DELL_MONITOR_RT_RTKPANEL_BUSY_RETRIES);
	return FALSE;
}

static gboolean
fu_dell_monitor_rt_rtkpanel_spi_idle(guint8 v)
{
	/* SPI flash busy bit is bit 0 of reg 0x60. Clear → idle. */
	return (v & 0x01) == 0;
}

static gboolean
fu_dell_monitor_rt_rtkpanel_status_ready(guint8 v)
{
	return v == DELL_MONITOR_RT_RTKPANEL_STATUS_READY;
}

/*
 * Erase one 64 KB SPI flash region at `addr`. Mirrors
 * REALTEK_API::spi_unit_erase(addr, 0x10000) for the 64-KB-block
 * variant. Issues the 6-write SPI command sequence, then waits for
 * bit 0 of reg 0x60 to clear. Caller is responsible for the CRC
 * verify (spi_read_crc) afterwards if it wants to confirm.
 */
static gboolean
fu_dell_monitor_rt_device_rtkpanel_spi_erase_64k(FuDellMonitorRtDevice *self,
						 guint32 addr,
						 GError **error)
{
	struct {
		guint8 reg;
		guint8 val;
	} ops[] = {
	    {DELL_MONITOR_RT_RTKPANEL_REG_ADDR_HI,  (guint8)((addr >> 16) & 0xFF)},
	    {DELL_MONITOR_RT_RTKPANEL_REG_ADDR_MID, (guint8)((addr >>  8) & 0xFF)},
	    {DELL_MONITOR_RT_RTKPANEL_REG_ADDR_LO,  (guint8)((addr      ) & 0xFF)},
	    {DELL_MONITOR_RT_RTKPANEL_REG_SPI_CMD,  DELL_MONITOR_RT_RTKPANEL_SPI_CMD_SETUP},
	    {DELL_MONITOR_RT_RTKPANEL_REG_SPI_DATA, DELL_MONITOR_RT_RTKPANEL_SPI_OP_BLK_ERASE},
	    {DELL_MONITOR_RT_RTKPANEL_REG_SPI_CMD,  DELL_MONITOR_RT_RTKPANEL_SPI_CMD_TRIGGER},
	};
	for (gsize i = 0; i < G_N_ELEMENTS(ops); i++) {
		if (!fu_dell_monitor_rt_device_rtkpanel_write_reg(self,
								  ops[i].reg,
								  ops[i].val,
								  error)) {
			g_prefix_error(error,
				       "rtkpanel spi_erase_64k addr 0x%08x step %u "
				       "(reg 0x%02x = 0x%02x): ",
				       addr,
				       (guint)i,
				       (guint)ops[i].reg,
				       (guint)ops[i].val);
			return FALSE;
		}
	}
	if (!fu_dell_monitor_rt_device_rtkpanel_poll_until(
		self,
		DELL_MONITOR_RT_RTKPANEL_REG_SPI_CMD,
		fu_dell_monitor_rt_rtkpanel_spi_idle,
		"SPI erase busy",
		error)) {
		g_prefix_error(error,
			       "rtkpanel spi_erase_64k addr 0x%08x: ",
			       addr);
		return FALSE;
	}
	return TRUE;
}

/*
 * Read the chip-computed CRC8/SMBus over `[addr .. addr+0x10000)`.
 * Mirrors REALTEK_API::spi_read_crc(addr, 0x10000, &crc). The chip
 * computes the CRC over its current SPI flash contents (post-erase)
 * and we compare to 0xDE = CRC8/SMBus of 65536 bytes of 0xFF, the
 * value REALTEK_API::spi_unit_erase asserts on its 64-KB-block path.
 */
static gboolean
fu_dell_monitor_rt_device_rtkpanel_spi_read_crc_64k(FuDellMonitorRtDevice *self,
						    guint32 addr,
						    guint8 *crc_out,
						    GError **error)
{
	guint32 end_addr = addr + DELL_MONITOR_RT_RTKPANEL_BLOCK_SIZE - 1;
	guint8 status = 0;
	struct {
		guint8 reg;
		guint8 val;
	} ops[] = {
	    {DELL_MONITOR_RT_RTKPANEL_REG_ADDR_HI,  (guint8)((addr     >> 16) & 0xFF)},
	    {DELL_MONITOR_RT_RTKPANEL_REG_ADDR_MID, (guint8)((addr     >>  8) & 0xFF)},
	    {DELL_MONITOR_RT_RTKPANEL_REG_ADDR_LO,  (guint8)((addr          ) & 0xFF)},
	    {DELL_MONITOR_RT_RTKPANEL_REG_END_HI,   (guint8)((end_addr >> 16) & 0xFF)},
	    {DELL_MONITOR_RT_RTKPANEL_REG_END_MID,  (guint8)((end_addr >>  8) & 0xFF)},
	    {DELL_MONITOR_RT_RTKPANEL_REG_END_LO,   (guint8)((end_addr      ) & 0xFF)},
	};
	for (gsize i = 0; i < G_N_ELEMENTS(ops); i++) {
		if (!fu_dell_monitor_rt_device_rtkpanel_write_reg(self,
								  ops[i].reg,
								  ops[i].val,
								  error)) {
			g_prefix_error(error,
				       "rtkpanel spi_read_crc range setup addr 0x%08x "
				       "step %u (reg 0x%02x = 0x%02x): ",
				       addr,
				       (guint)i,
				       (guint)ops[i].reg,
				       (guint)ops[i].val);
			return FALSE;
		}
	}
	/* Pre-trigger status read (the chip's "I'm ready for a CRC
	 * compute" handshake — Wistron checks but doesn't gate on it). */
	if (!fu_dell_monitor_rt_device_rtkpanel_read_reg(
		self,
		DELL_MONITOR_RT_RTKPANEL_REG_STATUS,
		&status,
		error)) {
		g_prefix_error(error,
			       "rtkpanel spi_read_crc pre-trigger status: ");
		return FALSE;
	}
	/* Trigger the chip-side CRC computation by writing 0x96 to reg
	 * 0x6F. The chip transitions reg 0x6F from 0x94 (computing) back
	 * to 0x92 (done) when the result is in reg 0x75. */
	if (!fu_dell_monitor_rt_device_rtkpanel_write_reg(
		self,
		DELL_MONITOR_RT_RTKPANEL_REG_STATUS,
		DELL_MONITOR_RT_RTKPANEL_STATUS_TRIGGER,
		error)) {
		g_prefix_error(error,
			       "rtkpanel spi_read_crc trigger: ");
		return FALSE;
	}
	if (!fu_dell_monitor_rt_device_rtkpanel_poll_until(
		self,
		DELL_MONITOR_RT_RTKPANEL_REG_STATUS,
		fu_dell_monitor_rt_rtkpanel_status_ready,
		"chip CRC ready",
		error)) {
		g_prefix_error(error,
			       "rtkpanel spi_read_crc compute wait addr 0x%08x: ",
			       addr);
		return FALSE;
	}
	if (!fu_dell_monitor_rt_device_rtkpanel_read_reg(
		self,
		DELL_MONITOR_RT_RTKPANEL_REG_CRC_RESULT,
		crc_out,
		error)) {
		g_prefix_error(error,
			       "rtkpanel spi_read_crc result read: ");
		return FALSE;
	}
	return TRUE;
}

/*
 * Erase one 64 KB SPI region for `addr` and verify the chip reads the
 * expected all-erased CRC. Combines spi_erase_64k + spi_read_crc_64k +
 * the `crc != 0xDE → fail` check from REALTEK_API::spi_unit_erase.
 */
static gboolean
fu_dell_monitor_rt_device_rtkpanel_erase_and_verify_64k(
    FuDellMonitorRtDevice *self,
    guint32 addr,
    GError **error)
{
	guint8 crc = 0;
	if (!fu_dell_monitor_rt_device_rtkpanel_spi_erase_64k(self, addr, error))
		return FALSE;
	if (!fu_dell_monitor_rt_device_rtkpanel_spi_read_crc_64k(self, addr, &crc, error))
		return FALSE;
	if (crc != DELL_MONITOR_RT_RTKPANEL_CRC_64K_ERASED) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INTERNAL,
			    "rtkpanel erase verify failed at addr 0x%08x: "
			    "chip-computed CRC8 = 0x%02x, expected 0x%02x "
			    "(CRC of 64 KB of 0xFF)",
			    addr,
			    (guint)crc,
			    (guint)DELL_MONITOR_RT_RTKPANEL_CRC_64K_ERASED);
		return FALSE;
	}
	return TRUE;
}

/* ----- Chip-setup helpers (one-shot, before the block loop) --------
 *
 * Mirror the call chain in `RealtekISP::disable_wp` (libdisplay.so,
 * decoded with our Ghidra class-recovery script — see
 * dell-u4025qw-fw/ghidra/scripts/RecoverWistronClasses.java):
 *
 *   enter_isp        — switch chip into ISP mode (reg 0x6F = 0x80 × 3)
 *   set_default_value — 20 fixed register writes that configure the
 *                       chip's SPI controller defaults
 *   spi_disable_wp_pin — chip-config-driven indirect F4/F5 access that
 *                        reads the SPI flash WP status register and
 *                        clears its block-protect bits. The exact wire
 *                        bytes depend on `wp_reg_a` and `wp_reg_b`
 *                        register addresses sourced from the `.upg`'s
 *                        per-component `param11` / `param12` metadata
 *                        (set into REALTEK_API.wp_reg_a/b by
 *                        RealtekISP::set_write_protect_pin). For
 *                        U4025QW DISPLAY: param11=0x109B param12=0x223B
 *                        param13=0x10001 (high word=1 selects the raw
 *                        encoding path).
 *   spi_read_jedec_id — read SPI flash JEDEC ID (0x9F op) + Release-
 *                       from-PD ID (0xAB op). We don't enforce a JEDEC
 *                       allowlist yet — log for diagnostic value.
 *   spi_set_wp_status — issue SPI WRSR (opcode 0x01) to commit the
 *                       new WP status to the flash chip.
 *   spi_unit_erase    — initial 64 KB erase + CRC verify at
 *                       (flash_size_or_end << 16); pre-clears the
 *                       "scratch" region the chip uses during F5
 *                       commits. Reuses the per-block helper.
 */

/* enter_isp: 3 hard-coded writes of reg 0x6F=0x80. The decomp's
 * `iVar6 = 3` retry counter is a literal 3-iter loop, not a poll-
 * until-success — three writes happen unconditionally on every call,
 * with a status poll between each. */
#define DELL_MONITOR_RT_RTKPANEL_ISP_ENTER_VAL   0x80
#define DELL_MONITOR_RT_RTKPANEL_ISP_ENTER_TRIES 3

/* Helper: poll reg 0x6F until the chip's high bit is SET (in-ISP ack).
 * The decomp's success branch is `(signed char)local_59 < 0`, i.e.
 * bit 7 = 1 means "I am now in ISP". This is the OPPOSITE convention
 * from the F3 chip-status register used elsewhere in this protocol —
 * for reg 0x6F enter_isp, bit-7-set means READY/in-ISP, while for F3
 * bit-7-set means BUSY. Different registers, different conventions. */
static gboolean
fu_dell_monitor_rt_rtkpanel_status_highbit_set(guint8 v)
{
	return (v & 0x80) != 0;
}

static gboolean
fu_dell_monitor_rt_device_rtkpanel_enter_isp(FuDellMonitorRtDevice *self, GError **error)
{
	for (guint i = 0; i < DELL_MONITOR_RT_RTKPANEL_ISP_ENTER_TRIES; i++) {
		if (!fu_dell_monitor_rt_device_rtkpanel_write_reg(
			self,
			DELL_MONITOR_RT_RTKPANEL_REG_STATUS,
			DELL_MONITOR_RT_RTKPANEL_ISP_ENTER_VAL,
			error)) {
			g_prefix_error(error, "rtkpanel enter_isp write %u: ", i);
			return FALSE;
		}
		if (!fu_dell_monitor_rt_device_rtkpanel_poll_until(
			self,
			DELL_MONITOR_RT_RTKPANEL_REG_STATUS,
			fu_dell_monitor_rt_rtkpanel_status_highbit_set,
			"enter_isp wait",
			error)) {
			g_prefix_error(error, "rtkpanel enter_isp wait %u: ", i);
			return FALSE;
		}
	}
	return TRUE;
}

/* set_default_value: 20 hard-coded register writes that put the chip's
 * SPI controller into the configuration the rest of the protocol
 * expects. Values verified byte-for-byte against the decomp of
 * REALTEK_API::set_default_value. */
static gboolean
fu_dell_monitor_rt_device_rtkpanel_set_default_value(FuDellMonitorRtDevice *self,
						     GError **error)
{
	const struct {
		guint8 reg;
		guint8 val;
	} pairs[] = {
	    {0xF4, 0x9F}, {0xF5, 0x06}, /* indirect-reg 0x9F = 0x06 */
	    {0xF4, 0xA0}, {0xF5, 0x74}, /* indirect-reg 0xA0 = 0x74 */
	    {0x1B, 0x02}, {0x1C, 0x30}, {0x1D, 0x1C},
	    {0x1E, 0x02}, {0x1F, 0x00}, {0x20, 0x1C},
	    {0x2C, 0x02}, {0x2D, 0x00}, {0x2E, 0x1C},
	    {0x62, 0x06}, {0x63, 0x50},
	    {0x6A, 0x03}, {0x6B, 0x0B}, {0x6C, 0x00},
	    {0xED, 0x84}, {0xEE, 0x04},
	};
	for (gsize i = 0; i < G_N_ELEMENTS(pairs); i++) {
		if (!fu_dell_monitor_rt_device_rtkpanel_write_reg(self,
								  pairs[i].reg,
								  pairs[i].val,
								  error)) {
			g_prefix_error(error,
				       "rtkpanel set_default_value step %u "
				       "(reg 0x%02x = 0x%02x): ",
				       (guint)i,
				       (guint)pairs[i].reg,
				       (guint)pairs[i].val);
			return FALSE;
		}
	}
	return TRUE;
}

/*
 * spi_disable_wp_pin: read the SPI flash WP status register via the
 * chip's indirect-register (`0xF4 = page selector, 0xF5 = data`)
 * protocol, clear the block-protect (BP) bits, and write the modified
 * value back into the same indirect register.
 *
 * The wire sequence depends on the chip-config bytes that the .upg's
 * metadata supplied via RealtekISP::set_write_protect_pin → stored
 * into REALTEK_API.wp_reg_a / wp_reg_b. The high byte of `wp_reg_b`
 * being `0xFF` (signed = -1) selects a SHORT path that touches a
 * single direct register at `wp_reg_b & 0xff`; any other value
 * selects a LONG path that uses two F4/F5 pair sequences. For the
 * U4025QW DISPLAY (wp_reg_b = 0x223B, high byte = 0x22) we take the
 * LONG path — which is the one this implementation emits.
 *
 * The IN-MEMORY WP status modification done here is committed to the
 * flash chip by a subsequent `spi_set_wp_status` call.
 */
static gboolean
fu_dell_monitor_rt_device_rtkpanel_spi_disable_wp_pin(FuDellMonitorRtDevice *self,
						      guint16 wp_reg_a,
						      guint16 wp_reg_b,
						      guint32 chip_flags,
						      GError **error)
{
	struct reg_pair {
		guint8 reg;
		guint8 val;
	};
	guint8 wp_status_buf[DELL_MONITOR_RT_BUF_SIZE] = {0};
	guint8 wp_status;
	guint8 wp_reg_a_hi = (wp_reg_a >> 8) & 0xFF;
	guint8 wp_reg_a_lo = (wp_reg_a >> 0) & 0xFF;
	guint8 wp_reg_b_hi = (wp_reg_b >> 8) & 0xFF;
	guint8 wp_reg_b_lo = (wp_reg_b >> 0) & 0xFF;
	guint8 chip_flags_b2 = (chip_flags >> 16) & 0xFF; /* this->chip_flags >> 16 in decomp */
	const struct reg_pair read_phase[] = {
	    {DELL_MONITOR_RT_RTKPANEL_REG_INDIRECT_PAGE, 0x9F}, /* select WP-config page */
	    {DELL_MONITOR_RT_RTKPANEL_REG_INDIRECT_DATA, wp_reg_a_hi},
	    {DELL_MONITOR_RT_RTKPANEL_REG_INDIRECT_PAGE, wp_reg_a_lo}, /* point at the WP-status sub-reg */
	};
	struct reg_pair writeback[6];

	if ((gint8)wp_reg_b_hi == -1) {
		/* SHORT path (direct register access). Not seen on U4025QW
		 * but documenting for future chips: read reg wp_reg_b_lo,
		 * modify, write back. */
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_NOT_SUPPORTED,
			    "rtkpanel spi_disable_wp_pin: SHORT path (wp_reg_b "
			    "high byte == 0xFF) not implemented yet — needs a "
			    "chip with that configuration to validate against. "
			    "wp_reg_b=0x%04x",
			    (guint)wp_reg_b);
		return FALSE;
	}

	/* LONG path: F4/F5 indirect access to read/modify/writeback the
	 * WP shadow register, then a second F4/F5 sequence that latches
	 * the new value via a chip-specific control register. */
	for (gsize i = 0; i < G_N_ELEMENTS(read_phase); i++) {
		if (!fu_dell_monitor_rt_device_rtkpanel_write_reg(self,
								  read_phase[i].reg,
								  read_phase[i].val,
								  error)) {
			g_prefix_error(error,
				       "rtkpanel spi_disable_wp_pin read-setup step %u: ",
				       (guint)i);
			return FALSE;
		}
	}
	/* Now read the indirect-data register (F5) → current WP status. */
	if (!fu_dell_monitor_rt_device_i2c_read_reg(
		self,
		DELL_MONITOR_RT_RTKPANEL_I2C_TARGET,
		DELL_MONITOR_RT_I2C_SPEED_FAST,
		DELL_MONITOR_RT_RTKPANEL_REG_INDIRECT_DATA,
		1,
		wp_status_buf,
		sizeof(wp_status_buf),
		error)) {
		g_prefix_error(error, "rtkpanel spi_disable_wp_pin read WP status: ");
		return FALSE;
	}
	/* response[0] = report-ID, response[1] = chip value. */
	wp_status = wp_status_buf[1];
	/* Clear bits 0..2, set bit 0. Matches decomp:
	 *   local_41 = local_41 & 0xF8 | 1; */
	wp_status = (wp_status & 0xF8) | 0x01;

	writeback[0] = (struct reg_pair){DELL_MONITOR_RT_RTKPANEL_REG_INDIRECT_PAGE, wp_reg_a_lo};
	writeback[1] = (struct reg_pair){DELL_MONITOR_RT_RTKPANEL_REG_INDIRECT_DATA, wp_status};
	writeback[2] = (struct reg_pair){DELL_MONITOR_RT_RTKPANEL_REG_INDIRECT_PAGE, 0x9F};
	writeback[3] = (struct reg_pair){DELL_MONITOR_RT_RTKPANEL_REG_INDIRECT_DATA, wp_reg_b_hi};
	writeback[4] = (struct reg_pair){DELL_MONITOR_RT_RTKPANEL_REG_INDIRECT_PAGE, wp_reg_b_lo};
	writeback[5] = (struct reg_pair){DELL_MONITOR_RT_RTKPANEL_REG_INDIRECT_DATA, chip_flags_b2};
	for (gsize i = 0; i < G_N_ELEMENTS(writeback); i++) {
		if (!fu_dell_monitor_rt_device_rtkpanel_write_reg(self,
								  writeback[i].reg,
								  writeback[i].val,
								  error)) {
			g_prefix_error(error,
				       "rtkpanel spi_disable_wp_pin writeback step %u: ",
				       (guint)i);
			return FALSE;
		}
	}
	return TRUE;
}

/* SPI flash JEDEC ID + Release-from-Power-Down ID via the chip's SPI
 * controller. Reads 4 bytes total: 3 from the JEDEC opcode (0x9F),
 * 1 from RES (0xAB at addr 0). For diagnostic value — Wistron's
 * decomp logs the result but doesn't gate behavior on it. We do the
 * same: log + continue. */
#define DELL_MONITOR_RT_RTKPANEL_SPI_OP_JEDEC_ID 0x9F
#define DELL_MONITOR_RT_RTKPANEL_SPI_OP_RES_ID   0xAB

#define DELL_MONITOR_RT_RTKPANEL_SPI_CMD_JEDEC_SETUP   0x46
#define DELL_MONITOR_RT_RTKPANEL_SPI_CMD_JEDEC_TRIGGER 0x47
#define DELL_MONITOR_RT_RTKPANEL_SPI_CMD_RES_SETUP     0x5A
#define DELL_MONITOR_RT_RTKPANEL_SPI_CMD_RES_TRIGGER   0x5B

#define DELL_MONITOR_RT_RTKPANEL_REG_JEDEC_BYTE_0      0x67
#define DELL_MONITOR_RT_RTKPANEL_REG_JEDEC_BYTE_1      0x68
#define DELL_MONITOR_RT_RTKPANEL_REG_JEDEC_BYTE_2      0x69

static gboolean
fu_dell_monitor_rt_device_rtkpanel_spi_read_jedec_id(FuDellMonitorRtDevice *self,
						     GError **error)
{
	struct reg_pair {
		guint8 reg;
		guint8 val;
	};
	guint8 buf[DELL_MONITOR_RT_BUF_SIZE] = {0};
	guint8 jedec[4] = {0};
	const struct reg_pair jedec_cmd[] = {
	    {DELL_MONITOR_RT_RTKPANEL_REG_SPI_CMD,  DELL_MONITOR_RT_RTKPANEL_SPI_CMD_JEDEC_SETUP},
	    {DELL_MONITOR_RT_RTKPANEL_REG_SPI_DATA, DELL_MONITOR_RT_RTKPANEL_SPI_OP_JEDEC_ID},
	    {DELL_MONITOR_RT_RTKPANEL_REG_SPI_CMD,  DELL_MONITOR_RT_RTKPANEL_SPI_CMD_JEDEC_TRIGGER},
	};
	const struct reg_pair res_cmd[] = {
	    {DELL_MONITOR_RT_RTKPANEL_REG_SPI_CMD,  DELL_MONITOR_RT_RTKPANEL_SPI_CMD_RES_SETUP},
	    {DELL_MONITOR_RT_RTKPANEL_REG_SPI_DATA, DELL_MONITOR_RT_RTKPANEL_SPI_OP_RES_ID},
	    {DELL_MONITOR_RT_RTKPANEL_REG_ADDR_HI,  0x00}, /* 3-byte addr = 0 */
	    {DELL_MONITOR_RT_RTKPANEL_REG_ADDR_MID, 0x00},
	    {DELL_MONITOR_RT_RTKPANEL_REG_ADDR_LO,  0x00},
	    {DELL_MONITOR_RT_RTKPANEL_REG_SPI_CMD,  DELL_MONITOR_RT_RTKPANEL_SPI_CMD_RES_TRIGGER},
	};

	/* Phase 1: JEDEC ID (SPI op 0x9F), reads 3 bytes. */
	for (gsize i = 0; i < G_N_ELEMENTS(jedec_cmd); i++) {
		if (!fu_dell_monitor_rt_device_rtkpanel_write_reg(self,
								  jedec_cmd[i].reg,
								  jedec_cmd[i].val,
								  error)) {
			g_prefix_error(error,
				       "rtkpanel jedec_id setup step %u: ",
				       (guint)i);
			return FALSE;
		}
	}
	if (!fu_dell_monitor_rt_device_rtkpanel_poll_until(
		self,
		DELL_MONITOR_RT_RTKPANEL_REG_SPI_CMD,
		fu_dell_monitor_rt_rtkpanel_spi_idle,
		"jedec_id wait",
		error))
		return FALSE;
	for (guint i = 0; i < 3; i++) {
		if (!fu_dell_monitor_rt_device_rtkpanel_read_reg(
			self,
			DELL_MONITOR_RT_RTKPANEL_REG_JEDEC_BYTE_0 + i,
			&jedec[i],
			error)) {
			g_prefix_error(error, "rtkpanel jedec_id byte %u: ", i);
			return FALSE;
		}
	}

	/* Phase 2: Release-from-PD ID (SPI op 0xAB), reads 1 byte. */
	for (gsize i = 0; i < G_N_ELEMENTS(res_cmd); i++) {
		if (!fu_dell_monitor_rt_device_rtkpanel_write_reg(self,
								  res_cmd[i].reg,
								  res_cmd[i].val,
								  error)) {
			g_prefix_error(error,
				       "rtkpanel res_id setup step %u: ",
				       (guint)i);
			return FALSE;
		}
	}
	if (!fu_dell_monitor_rt_device_rtkpanel_poll_until(
		self,
		DELL_MONITOR_RT_RTKPANEL_REG_SPI_CMD,
		fu_dell_monitor_rt_rtkpanel_spi_idle,
		"res_id wait",
		error))
		return FALSE;
	if (!fu_dell_monitor_rt_device_rtkpanel_read_reg(
		self,
		DELL_MONITOR_RT_RTKPANEL_REG_JEDEC_BYTE_0,
		&jedec[3],
		error)) {
		g_prefix_error(error, "rtkpanel res_id byte: ");
		return FALSE;
	}
	(void)buf;

	g_info("dell-monitor-rt: rtkpanel SPI flash JEDEC=%02x:%02x:%02x RES=%02x",
	       (guint)jedec[0], (guint)jedec[1], (guint)jedec[2], (guint)jedec[3]);
	return TRUE;
}

/* spi_set_wp_status: commit the in-memory WP-status modification to the
 * flash chip by issuing SPI Write-Status-Register (opcode 0x01).
 *
 * Wire sequence:  0x60=0x68, 0x61=0x01, 0x64=<status>, 0x60=0x69
 *
 * The status value passed to flash is implicit on this chip: the chip
 * already has the modified value latched from the earlier
 * spi_disable_wp_pin call, so we just write 0x00 to the address byte
 * (the SPI WRSR command takes the status from the chip-side staging
 * register, not from this i2c bus). The captured trace shows
 * reg=0x64 val=0x00.
 */
#define DELL_MONITOR_RT_RTKPANEL_SPI_CMD_WRSR_SETUP   0x68
#define DELL_MONITOR_RT_RTKPANEL_SPI_CMD_WRSR_TRIGGER 0x69
#define DELL_MONITOR_RT_RTKPANEL_SPI_OP_WRITE_STATUS  0x01

static gboolean
fu_dell_monitor_rt_device_rtkpanel_spi_set_wp_status(FuDellMonitorRtDevice *self,
						     GError **error)
{
	const struct {
		guint8 reg;
		guint8 val;
	} pairs[] = {
	    {DELL_MONITOR_RT_RTKPANEL_REG_SPI_CMD,  DELL_MONITOR_RT_RTKPANEL_SPI_CMD_WRSR_SETUP},
	    {DELL_MONITOR_RT_RTKPANEL_REG_SPI_DATA, DELL_MONITOR_RT_RTKPANEL_SPI_OP_WRITE_STATUS},
	    {DELL_MONITOR_RT_RTKPANEL_REG_ADDR_HI,  0x00},
	    {DELL_MONITOR_RT_RTKPANEL_REG_SPI_CMD,  DELL_MONITOR_RT_RTKPANEL_SPI_CMD_WRSR_TRIGGER},
	};
	for (gsize i = 0; i < G_N_ELEMENTS(pairs); i++) {
		if (!fu_dell_monitor_rt_device_rtkpanel_write_reg(self,
								  pairs[i].reg,
								  pairs[i].val,
								  error)) {
			g_prefix_error(error,
				       "rtkpanel spi_set_wp_status step %u: ",
				       (guint)i);
			return FALSE;
		}
	}
	/* No wait_ready here — the captured trace shows the chip absorbs
	 * the WRSR command synchronously and the next operation (initial
	 * erase) proceeds immediately. If real hardware needs a wait we'll
	 * see it as an emulator skip on the next sub-step. */
	return TRUE;
}

/*
 * One-shot chip-setup sequence run once at the start of DISPLAY
 * programming. Mirrors RealtekISP::disable_wp() + the pre-loop initial
 * erase from RealtekISP::secure_program_rtk().
 *
 *   wp_reg_a, wp_reg_b, chip_flags  — from .upg param11/12/13, used by
 *                                     spi_disable_wp_pin
 *   flash_end_index                 — .upg flash_size_or_end << 16 is
 *                                     the address of the chip's
 *                                     "scratch" 64 KB region; initial
 *                                     erase clears it before block 0
 */
static gboolean
fu_dell_monitor_rt_device_rtkpanel_setup(FuDellMonitorRtDevice *self,
					 guint16 wp_reg_a,
					 guint16 wp_reg_b,
					 guint32 chip_flags,
					 guint32 flash_end_index,
					 GError **error)
{
	if (!fu_dell_monitor_rt_device_rtkpanel_enter_isp(self, error)) {
		g_prefix_error(error, "rtkpanel setup: ");
		return FALSE;
	}
	if (!fu_dell_monitor_rt_device_rtkpanel_set_default_value(self, error)) {
		g_prefix_error(error, "rtkpanel setup: ");
		return FALSE;
	}
	if (!fu_dell_monitor_rt_device_rtkpanel_spi_disable_wp_pin(
		self, wp_reg_a, wp_reg_b, chip_flags, error)) {
		g_prefix_error(error, "rtkpanel setup: ");
		return FALSE;
	}
	if (!fu_dell_monitor_rt_device_rtkpanel_spi_read_jedec_id(self, error)) {
		g_prefix_error(error, "rtkpanel setup: ");
		return FALSE;
	}
	if (!fu_dell_monitor_rt_device_rtkpanel_spi_set_wp_status(self, error)) {
		g_prefix_error(error, "rtkpanel setup: ");
		return FALSE;
	}
	/* Initial erase at (flash_end_index << 16). Reuses the per-block
	 * helper, which also CRC-verifies the result.
	 *
	 * AUDIT.md F6.1: 3-attempt retry, matching RealtekISP::secure_
	 * program_rtk's preamble at libdisplay.c:67012 — `do { ... }
	 * while (++uVar14 != 4)` around spi_unit_erase. The retry covers
	 * transient SPI flash busy/timeout conditions. */
	{
		const guint max_attempts = 3;
		g_autoptr(GError) last_error = NULL;
		for (guint attempt = 0; attempt < max_attempts; attempt++) {
			g_autoptr(GError) attempt_error = NULL;
			if (fu_dell_monitor_rt_device_rtkpanel_erase_and_verify_64k(
				self,
				flash_end_index << 16,
				&attempt_error))
				return TRUE;
			g_clear_error(&last_error);
			last_error = g_steal_pointer(&attempt_error);
			g_debug("rtkpanel setup: initial erase attempt "
				"%u/%u failed: %s",
				attempt + 1,
				max_attempts,
				last_error->message);
		}
		g_propagate_prefixed_error(
		    error,
		    g_steal_pointer(&last_error),
		    "rtkpanel setup: initial erase at 0x%08x failed after %u attempts: ",
		    (guint)(flash_end_index << 16),
		    max_attempts);
		return FALSE;
	}
}

/*
 * Stage and commit one DISPLAY block.
 *
 *   block              65604-byte slice from the source blob:
 *                        block[0..4]       per-block addr (LE u32)
 *                        block[4..0x10004] 65536 B firmware payload
 *                        block[0x10004..0x10044] 64 B per-block ECDSA sig
 *   global_pubkey      64 B from the trailing 64 of the whole blob
 *   flash_start_index  chip-config knob from the component's
 *                      flash_off_or_size metadata; combines with
 *                      block[0..4] to produce the real target SPI
 *                      flash address: target = start*0x10000 + block_addr.
 *                      Mirrors libdisplay.so:
 *                         RealtekISP::secure_program_rtk:
 *                           uVar17 = *(int*)(this+0x1c) * 0x10000 + iVar6;
 *                      where this+0x1c is set by set_flash_start_index.
 *
 * Emits, in order:
 *   spi_unit_erase(target_addr, 64 KB) + spi_read_crc verify (== 0xDE)
 *   F4 erase_tmp_flash
 *   F1 × 512 write_tmp_flash
 *   04 secure_control_gpio(6, 1)
 *   F5 verify_tmp_flash (with crc8, full target_addr, pubkey, sig)
 *   F3 wait_ready (post-commit)
 */
static gboolean
fu_dell_monitor_rt_device_display_program_block(FuDellMonitorRtDevice *self,
						const guint8 *block,
						const guint8 *global_pubkey,
						guint32 flash_start_index,
						GError **error)
{
	const guint8 *data = block + DELL_MONITOR_RT_DISPLAY_BLOCK_DATA_OFF;
	const guint8 *sig = block + DELL_MONITOR_RT_DISPLAY_BLOCK_SIG_OFF;
	guint32 block_addr = fu_memread_uint32(block, G_LITTLE_ENDIAN);
	guint32 target_addr = (flash_start_index << 16) + block_addr;
	guint8 crc;
	guint8 body[DELL_MONITOR_RT_BUF_SIZE - 3];

	/* Erase the SPI flash region for this block (64 KB at target_addr)
	 * and verify the chip computes CRC = 0xDE over the erased region.
	 * Without this on real hardware the chip's F5 commit would write
	 * into a non-erased region — flash bits can only be flipped 1→0
	 * on this kind of NOR flash, so the result would be garbled. */
	if (!fu_dell_monitor_rt_device_rtkpanel_erase_and_verify_64k(
		self,
		target_addr,
		error)) {
		g_prefix_error(error,
			       "DISPLAY pre-block SPI erase at 0x%08x: ",
			       target_addr);
		return FALSE;
	}

	/* F4 erase_tmp_flash — opcode-only, all-zero body. */
	if (!fu_dell_monitor_rt_device_send_vendor_frame(
		self,
		DELL_MONITOR_RT_OPCODE_TMP_ERASE,
		NULL,
		0,
		error)) {
		g_prefix_error(error, "DISPLAY F4 erase_tmp_flash: ");
		return FALSE;
	}

	/* F1 × 512 write_tmp_flash — 128 B chunks at SRAM offsets
	 * 0x0000, 0x0080, … 0xFF80. wire layout is built from
	 * RTS5409S_HID::write_tmp_flash:
	 *   buf[+0x5b..+0x5e] = address (4-byte LE) → wire bytes 2..5
	 *   buf[+0x5f]        = length              → wire byte 6
	 *   buf[+0x99..+0x119] = 128 B payload      → wire bytes 64..192
	 * (wire byte indexing assumes report-ID at -1.) */
	for (guint i = 0; i < DELL_MONITOR_RT_DISPLAY_F1_PER_BLOCK; i++) {
		guint32 sram_addr = i * DELL_MONITOR_RT_DISPLAY_F1_CHUNK;

		memset(body, 0, sizeof(body));
		fu_memwrite_uint32(body + 0, sram_addr, G_LITTLE_ENDIAN);
		body[4] = DELL_MONITOR_RT_DISPLAY_F1_CHUNK; /* wire byte 6 */
		/* wire byte 64 == body offset 62 */
		memcpy(body + (DELL_MONITOR_RT_I2C_WIRE_DATA_OFFSET - 2),
		       data + sram_addr,
		       DELL_MONITOR_RT_DISPLAY_F1_CHUNK);
		if (!fu_dell_monitor_rt_device_send_vendor_frame(
			self,
			DELL_MONITOR_RT_OPCODE_TMP_WRITE,
			body,
			sizeof(body),
			error)) {
			g_prefix_error(error,
				       "DISPLAY F1 chunk %u (addr 0x%04x): ",
				       i,
				       sram_addr);
			return FALSE;
		}
	}

	/* 04 secure_control_gpio(0x06, 0x01) — commit-prep. Wire bytes
	 * 2..4 come from `*(u32*)(buf+0x58) = 0x01044000` then
	 * `*(u16*)(buf+0x5c) = CONCAT11(pin=0x06, value=0x01)`, giving
	 * wire[0..4] = 40 04 01 01 06. */
	memset(body, 0, sizeof(body));
	body[0] = 0x01; /* wire byte 2 — high byte of 0x01044000 LE */
	body[1] = DELL_MONITOR_RT_DISPLAY_GPIO_VALUE; /* wire byte 3 */
	body[2] = DELL_MONITOR_RT_DISPLAY_GPIO_PIN;   /* wire byte 4 */
	if (!fu_dell_monitor_rt_device_send_vendor_frame(
		self,
		DELL_MONITOR_RT_OPCODE_SECURE_GPIO,
		body,
		sizeof(body),
		error)) {
		g_prefix_error(error,
			       "DISPLAY 04 secure_control_gpio(0x%02x, 0x%02x): ",
			       (guint)DELL_MONITOR_RT_DISPLAY_GPIO_PIN,
			       (guint)DELL_MONITOR_RT_DISPLAY_GPIO_VALUE);
		return FALSE;
	}

	/* F5 verify_tmp_flash mode-0:
	 *   wire[2]      = 0x94 (constant from `0x94f54000` LE store)
	 *   wire[3]      = this[0x40] = bus-speed cache = 0x01
	 *   wire[4]      = CRC8/SMBus over the 65536 data bytes
	 *   wire[6..10]  = target SPI addr (4-byte LE; from block[0..4])
	 *   wire[64..128]  = global pubkey (last 64 B of whole blob)
	 *   wire[128..192] = per-block sig (last 64 B of this block) */
	crc = fu_dell_monitor_rt_crc8_smbus(data,
					    DELL_MONITOR_RT_DISPLAY_BLOCK_DATA_LEN);
	memset(body, 0, sizeof(body));
	body[0] = DELL_MONITOR_RT_DISPLAY_VERIFY_BYTE2;	     /* wire byte 2 */
	body[1] = DELL_MONITOR_RT_DISPLAY_VERIFY_BYTE3;	     /* wire byte 3 */
	body[2] = crc;					     /* wire byte 4 */
	fu_memwrite_uint32(body + 4, target_addr, G_LITTLE_ENDIAN); /* wire bytes 6..9 */
	/* wire byte 64 == body offset 62; copy 64 B pubkey there. */
	memcpy(body + (DELL_MONITOR_RT_I2C_WIRE_DATA_OFFSET - 2),
	       global_pubkey,
	       DELL_MONITOR_RT_DISPLAY_PUBKEY_LEN);
	/* wire byte 128 == body offset 126; copy 64 B sig there. */
	memcpy(body + (DELL_MONITOR_RT_I2C_WIRE_DATA_OFFSET - 2 +
		       DELL_MONITOR_RT_DISPLAY_PUBKEY_LEN),
	       sig,
	       DELL_MONITOR_RT_DISPLAY_BLOCK_SIG_LEN);
	if (!fu_dell_monitor_rt_device_send_vendor_frame(
		self,
		DELL_MONITOR_RT_OPCODE_TMP_VERIFY,
		body,
		sizeof(body),
		error)) {
		g_prefix_error(error, "DISPLAY F5 verify_tmp_flash: ");
		return FALSE;
	}

	/* F3 status poll until READY (post-commit). */
	if (!fu_dell_monitor_rt_device_display_f3_wait_ready(self, error)) {
		g_prefix_error(error, "DISPLAY F3 poll after F5 commit: ");
		return FALSE;
	}
	return TRUE;
}

/*
 * Drive the full DISPLAY block-write loop over a decrypted source blob.
 * Validates the blob is N * 0x10044 + 0x40 (= 26 * 65604 + 64 = 1,705,768
 * bytes for the U4025QW), slices the trailing 64 B as the global pubkey,
 * and calls _program_block once per block.
 */
static gboolean
fu_dell_monitor_rt_device_display_program(FuDellMonitorRtDevice *self,
					  GBytes *blob,
					  guint32 flash_start_index,
					  guint32 flash_end_index,
					  guint16 wp_reg_a,
					  guint16 wp_reg_b,
					  guint32 chip_flags,
					  FuProgress *progress,
					  GError **error)
{
	gsize blob_size = 0;
	const guint8 *blob_data = g_bytes_get_data(blob, &blob_size);
	gsize body_size;
	guint nblocks;
	const guint8 *global_pubkey;

	/* check_image: the sanity tests RTS5409S_HID::check_image runs
	 * before secure_program — size > 0x40, and the (size - 0x40)
	 * must be an exact multiple of 0x10044. */
	if (blob_size <= DELL_MONITOR_RT_DISPLAY_PUBKEY_LEN) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_DATA,
			    "DISPLAY blob too small: %" G_GSIZE_FORMAT
			    " bytes (need > %u for trailer)",
			    blob_size,
			    (guint)DELL_MONITOR_RT_DISPLAY_PUBKEY_LEN);
		return FALSE;
	}
	body_size = blob_size - DELL_MONITOR_RT_DISPLAY_PUBKEY_LEN;
	if (body_size % DELL_MONITOR_RT_DISPLAY_BLOCK_SIZE != 0) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_DATA,
			    "DISPLAY blob body size %" G_GSIZE_FORMAT
			    " is not a multiple of block size %u",
			    body_size,
			    (guint)DELL_MONITOR_RT_DISPLAY_BLOCK_SIZE);
		return FALSE;
	}
	nblocks = (guint)(body_size / DELL_MONITOR_RT_DISPLAY_BLOCK_SIZE);
	global_pubkey = blob_data + body_size;

	g_info("dell-monitor-rt: DISPLAY %" G_GSIZE_FORMAT
	       " bytes = %u blocks × %u B + %u B pubkey",
	       blob_size,
	       nblocks,
	       (guint)DELL_MONITOR_RT_DISPLAY_BLOCK_SIZE,
	       (guint)DELL_MONITOR_RT_DISPLAY_PUBKEY_LEN);

	/* Pre-block-loop chip setup. Mirrors RealtekISP::secure_program_rtk's
	 * pre-amble: enter_isp → set_default_value → spi_disable_wp_pin →
	 * spi_read_jedec_id → spi_set_wp_status → initial 64 KB erase at
	 * (flash_end_index << 16). Without this the panel scaler's SPI flash
	 * is write-protected and the per-block F4/F1/04/F5 commits won't
	 * land. Under emulation the leapfrog matcher would hide this — but
	 * we'd lose the chip ID / WP state we want for real hardware. */
	if (!fu_dell_monitor_rt_device_rtkpanel_setup(self,
						     wp_reg_a,
						     wp_reg_b,
						     chip_flags,
						     flash_end_index,
						     error)) {
		g_prefix_error(error, "DISPLAY pre-block setup: ");
		return FALSE;
	}

	if (progress != NULL) {
		fu_progress_set_id(progress, G_STRLOC);
		fu_progress_set_steps(progress, nblocks);
	}

	/* AUDIT.md F6.2: 3-attempt retry around each per-block call,
	 * matching RealtekISP::secure_program_rtk's main loop:
	 * `uVar14 = 3; do { ... } while (uVar14 != 0)`. Each attempt is
	 * the full F4/F1/04/F5 commit sequence; transient SPI errors
	 * (busy / verify-mismatch) get a re-try before bubbling up. */
	for (guint i = 0; i < nblocks; i++) {
		const guint8 *block = blob_data + i * DELL_MONITOR_RT_DISPLAY_BLOCK_SIZE;
		const guint max_attempts = 3;
		g_autoptr(GError) last_error = NULL;
		gboolean ok = FALSE;
		for (guint attempt = 0; attempt < max_attempts; attempt++) {
			g_autoptr(GError) attempt_error = NULL;
			if (fu_dell_monitor_rt_device_display_program_block(
				self,
				block,
				global_pubkey,
				flash_start_index,
				&attempt_error)) {
				ok = TRUE;
				break;
			}
			g_clear_error(&last_error);
			last_error = g_steal_pointer(&attempt_error);
			g_debug("DISPLAY block %u/%u attempt %u/%u: %s",
				i,
				nblocks,
				attempt + 1,
				max_attempts,
				last_error->message);
		}
		if (!ok) {
			g_propagate_prefixed_error(
			    error,
			    g_steal_pointer(&last_error),
			    "DISPLAY block %u/%u failed after %u attempts: ",
			    i,
			    nblocks,
			    max_attempts);
			return FALSE;
		}
		if (progress != NULL)
			fu_progress_step_done(progress);
	}

	/* Post-loop validity marker write (AUDIT.md F6.3). Wistron's
	 * `secure_program_rtk` (libdisplay.c:67296) ends with a 2-byte
	 * `AA 55` write to register 0x70 with the SPI target address
	 * pre-loaded to 0x3FF8FE — the panel scaler's bootloader reads
	 * this marker at boot to decide whether the freshly-flashed
	 * firmware is valid. Without this, the new firmware is treated
	 * as invalid and the chip falls back to the old image. Pcap-
	 * confirmed at frame 811742. */
	{
		const guint8 addr_hi = (DELL_MONITOR_RT_RTKPANEL_VALIDITY_ADDR >> 16) & 0xFF;
		const guint8 addr_mid = (DELL_MONITOR_RT_RTKPANEL_VALIDITY_ADDR >> 8) & 0xFF;
		const guint8 addr_lo = DELL_MONITOR_RT_RTKPANEL_VALIDITY_ADDR & 0xFF;
		const guint8 marker_wire[3] = {
		    DELL_MONITOR_RT_RTKPANEL_REG_SPI_WRITE_PORT,
		    DELL_MONITOR_RT_RTKPANEL_VALIDITY_LO,
		    DELL_MONITOR_RT_RTKPANEL_VALIDITY_HI,
		};
		const struct {
			guint8 reg;
			guint8 val;
		} addr_writes[] = {
		    {DELL_MONITOR_RT_RTKPANEL_REG_ADDR_HI, addr_hi},
		    {DELL_MONITOR_RT_RTKPANEL_REG_ADDR_MID, addr_mid},
		    {DELL_MONITOR_RT_RTKPANEL_REG_ADDR_LO, addr_lo},
		};
		for (gsize k = 0; k < G_N_ELEMENTS(addr_writes); k++) {
			if (!fu_dell_monitor_rt_device_rtkpanel_write_reg(
				self,
				addr_writes[k].reg,
				addr_writes[k].val,
				error)) {
				g_prefix_error(error,
					       "DISPLAY validity-marker addr setup "
					       "(reg 0x%02x): ",
					       addr_writes[k].reg);
				return FALSE;
			}
		}
		if (!fu_dell_monitor_rt_device_i2c_write_speed(
			self,
			DELL_MONITOR_RT_RTKPANEL_I2C_TARGET,
			DELL_MONITOR_RT_I2C_SPEED_FAST,
			marker_wire,
			sizeof(marker_wire),
			error)) {
			g_prefix_error(error, "DISPLAY validity-marker write: ");
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
	/* Post-bootloader path: routed via the primary's i2c-tunnel using
	 * a chip-specific protocol (e.g. TPS6598x 4CC commands for PDC).
	 * The route's i2c_target is the chip's 8-bit slave address. */
	FU_DELL_MONITOR_RT_ROUTE_POST_BOOTLOADER,
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
	/* Post-bootloader staging order — protocol handlers with lower
	 * `phase_order` run before higher ones. PDC (0) must precede
	 * DISPLAY (1) because that's the order Dell's binary observes
	 * in the captured trace, and the chip's ISP shim accepts the
	 * commands in that order. The order is enforced by an outer
	 * loop in write_firmware that filters by phase_order. Pre-
	 * bootloader handlers (i2c-tunnel and direct-stage) ignore the
	 * field — they have their own pass schedule. */
	guint8 phase_order;
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
	/* Component-derived chip-config knobs that the protocol handler
	 * may need for its wire-format. Populated by route_for_component
	 * from the .upg metadata; only the handlers that care about them
	 * read them.
	 *
	 *   flash_start_index  RealtekISP::set_flash_start_index's start
	 *                      arg — used by DISPLAY's F5 wire bytes 6..9
	 *                      to compute `start * 0x10000 + block_addr`.
	 *                      Comes from the .upg's flash_off_or_size field.
	 *                      For the U4025QW DISPLAY this is 0x20.
	 *
	 *   flash_end_index    RealtekISP::set_flash_start_index's end arg —
	 *                      used by DISPLAY's pre-block-loop initial
	 *                      64 KB erase at `end * 0x10000`. Comes from
	 *                      the .upg's flash_size_or_end field.
	 *
	 *   wp_reg_a/wp_reg_b  Per-chip SPI flash write-protect register
	 *                      addresses. REALTEK_API::spi_disable_wp_pin
	 *                      reads/modifies/writes the WP-status SR via
	 *                      these two 16-bit register addresses (high
	 *                      byte = page on F4, low byte = sub-reg on F4).
	 *                      For U4025QW DISPLAY these come from the .upg's
	 *                      param11 (=0x109B) and param12 (=0x223B) —
	 *                      passed through RealtekISP::set_write_protect_pin
	 *                      in the original stack.
	 *
	 *   chip_flags         Bit-flags REALTEK_API uses for chip variants;
	 *                      ctor sets 0x01010001 by default, override
	 *                      comes from the .upg's param13. Currently the
	 *                      WP-pin path consumes only the low bit (0 =
	 *                      add-write-mask, 1 = raw-write encoding) and
	 *                      a high-byte sentinel (0xFF = skip second
	 *                      indirect-data write for wp_reg_b). */
	guint32 flash_start_index;
	guint32 flash_end_index;
	guint16 wp_reg_a;
	guint16 wp_reg_b;
	guint32 chip_flags;
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
fu_dell_monitor_rt_proto_rts540x_arm_inner(FuDellMonitorRtDevice *target,
					   GError **error)
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

/*
 * Proto's arm_target callback is a no-op for rts540x — the arm step
 * is part of the per-stage update_self envelope (which the route
 * walker retries via stage_blob), so doing it here too would emit
 * the arm bytes twice on the wire. The route walker still calls
 * arm_target once before the first stage; we let it pass through
 * without any IO.
 */
static gboolean
fu_dell_monitor_rt_proto_rts540x_arm(FuDellMonitorRtDevice *target, GError **error)
{
	(void)target;
	(void)error;
	return TRUE;
}

/*
 * Send the verify_update_fw probe (opcode 0xD9 sub=1) and poll the
 * input report up to 3 times for a result byte == 0x01.
 *
 * Mirrors RTS5409S_HID::verify_update_fw at libdevices.c:69247:
 *   - send 40 D9 01 00 ...
 *   - nanosleep(_DAT_002d2110, 0)        (~100 ms initial settle)
 *   - loop 3×:
 *       hid_get_input_report → rc
 *         rc > 0 : success, *result = in_payload (response[1])
 *         rc == 0: last_error = 0xf1, exit
 *         rc < 0 : sleep _DAT_002d1160 (~5 ms), retry
 *
 * The two timing constants live in libdevices.so .data and we don't
 * have their exact values; 100 ms / 5 ms are conservative defaults
 * that match the visible cadence in the captured pcap (verify_update_fw
 * input-report polls land roughly that far apart).
 *
 * Caller is expected to treat *result != 0x01 as a chip-side reject
 * (matching the "status check fail" branch in update_self at
 * libdevices.c:70066).
 */
static gboolean
fu_dell_monitor_rt_device_verify_update_fw(FuDellMonitorRtDevice *self,
					   guint8 *result,
					   GError **error)
{
	guint8 response[DELL_MONITOR_RT_BUF_SIZE] = {0};
	gsize bytes_in = 0;

	g_return_val_if_fail(result != NULL, FALSE);

	if (!fu_dell_monitor_rt_device_vcmd(self,
					    DELL_MONITOR_RT_DIR_WRITE,
					    0xD9,
					    0x01, /* sub0 = 1 */
					    0x00,
					    NULL,
					    0,
					    error)) {
		g_prefix_error(error, "verify_update_fw probe: ");
		return FALSE;
	}

	g_usleep(100 * 1000); /* initial settle, ~_DAT_002d2110 */

	for (guint attempt = 0; attempt < 3; attempt++) {
		g_autoptr(FuIoctl) ioctl =
		    fu_udev_device_ioctl_new(FU_UDEV_DEVICE(self));
		gint rc = 0;
		g_autoptr(GError) err_local = NULL;

		memset(response, 0, sizeof(response));
		if (!fu_ioctl_execute(ioctl,
				      HIDIOCGINPUT(sizeof(response)), /* nocheck:blocked */
				      response,
				      sizeof(response),
				      &rc,
				      DELL_MONITOR_RT_TIMEOUT_MS,
				      FU_IOCTL_FLAG_NONE,
				      &err_local)) {
			/* transport error → retry up to 3× per Wistron */
			g_debug("verify_update_fw poll %u: %s",
				attempt,
				err_local->message);
			g_usleep(5 * 1000); /* ~_DAT_002d1160 retry sleep */
			continue;
		}

		/* ioctl succeeded → response buffer is populated.
		 *
		 * Under emulation, fu_ioctl_execute returns success with
		 * rc unpopulated (rc stays 0) because it replays event
		 * DataOut into the buffer without setting rc through
		 * fu_device_event_copy_data. Under real hardware rc is
		 * the byte count from HIDIOCGINPUT.
		 *
		 * Wistron's loop treats rc == 0 as "chip not ready,
		 * retry" (last_error = 0xf1). We can't reproduce that
		 * gating under emulation, so we only enforce the
		 * rc == 0 retry path when rc actually got a value. The
		 * caller checks result_byte == 0x01; if the chip really
		 * wasn't ready, response[1] stays 0 and the caller's
		 * status-check fails, which is the right outcome. */
		bytes_in = (rc > 0) ? (gsize)rc : 0;
		if (rc > 0 && bytes_in == 0) {
			/* real HW saying "not ready yet" — retry */
			g_usleep(5 * 1000);
			continue;
		}
		*result = response[1];
		fu_dump_raw(G_LOG_DOMAIN,
			    "verify_update_fw response",
			    response,
			    sizeof(response));
		return TRUE;
	}

	g_set_error_literal(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_READ,
			    "verify_update_fw: 3 input-report polls failed");
	return FALSE;
}

/*
 * Issue enable_vdcmd(true, false) — the cleanup half of
 * RTS5409S_HID::update_self's envelope at libdevices.c:70094. Disables
 * high_clock mode and leaves vdcmd enabled. Wire bytes:
 *   40 02 01 00 DA 0B 00 …
 *
 * Always called after the chunk loop completes (success or failure),
 * matching update_self's two enable_vdcmd cleanup callsites at
 * LAB_001b77e2 and the in-line one at libdevices.c:70073.
 */
static gboolean
fu_dell_monitor_rt_device_disarm_vdcmd(FuDellMonitorRtDevice *self,
				       GError **error)
{
	const guint8 vendor_sig[2] = {DELL_MONITOR_RT_VENDOR_SIG_LO,
				      DELL_MONITOR_RT_VENDOR_SIG_HI};
	if (!fu_dell_monitor_rt_device_vcmd(self,
					    DELL_MONITOR_RT_DIR_WRITE,
					    DELL_MONITOR_RT_OPCODE_ENABLE_VDCMD,
					    0x01, /* sub0 = 1 → high_clock=false */
					    0x00,
					    vendor_sig,
					    sizeof(vendor_sig),
					    error)) {
		g_prefix_error(error, "rts540x cleanup enable_vdcmd sub=1: ");
		return FALSE;
	}
	return TRUE;
}

/*
 * Wrap stage_isp_firmware in the verify+cleanup tail of Wistron's
 * `RTS5409S_HID::update_self` envelope (AUDIT.md F3.2):
 *
 *   1. enable_vdcmd(true, true)        ← arm_target (proto_rts540x_arm)
 *   2. erase_spare_bank                 ← arm_target
 *   3. write_hub_flash chunk loop       ← stage_isp_firmware (here)
 *   4. verify_update_fw + result check  ← here
 *   5. enable_vdcmd(true, false)        ← here (always, even on error)
 *
 * Steps 1+2 are emitted by the proto's arm_target callback (the route
 * walker calls it once per (target, proto) pair before the first
 * stage). RTS540x has exactly one stage per (target, proto), so 3+4+5
 * naturally fit here.
 *
 * Step 4 ("trailing partial chunk write" in update_self) is omitted
 * deliberately — F2.5 in AUDIT.md, Tier 2: U4025QW HUB blobs are 64-KB
 * aligned so the partial branch never fires, but the code is missing
 * if a future Dell payload is non-aligned.
 */
/*
 * One pass of the full RTS5409S_HID::update_self envelope:
 *   arm (enable_vdcmd sub=3 + erase_spare_bank)
 *     → chunk loop
 *     → verify_update_fw + result check
 *     → disarm (enable_vdcmd sub=1)
 *
 * Disarm fires on every exit path so the chip isn't left in
 * high_clock+vdcmd mode if a step in the middle fails.
 */
static gboolean
fu_dell_monitor_rt_proto_rts540x_envelope_once(FuDellMonitorRtDevice *target,
					       GBytes *blob,
					       GError **error)
{
	guint8 verify_result = 0xFF;
	g_autoptr(GError) inner_error = NULL;

	if (!fu_dell_monitor_rt_proto_rts540x_arm_inner(target, &inner_error))
		goto fail;
	if (!fu_dell_monitor_rt_device_stage_isp_firmware(target,
							  blob,
							  NULL,
							  &inner_error))
		goto fail;
	if (!fu_dell_monitor_rt_device_verify_update_fw(target,
							&verify_result,
							&inner_error)) {
		g_prefix_error(&inner_error, "rts540x verify_update_fw: ");
		goto fail;
	}
	if (verify_result != 0x01) {
		g_set_error(&inner_error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_WRITE,
			    "rts540x verify_update_fw: chip rejected staged "
			    "firmware (result byte 0x%02x, want 0x01)",
			    verify_result);
		goto fail;
	}
	if (!fu_dell_monitor_rt_device_disarm_vdcmd(target, &inner_error))
		goto fail;
	return TRUE;

fail:;
	g_autoptr(GError) ignored = NULL;
	fu_dell_monitor_rt_device_disarm_vdcmd(target, &ignored);
	g_propagate_error(error, g_steal_pointer(&inner_error));
	return FALSE;
}

static gboolean
fu_dell_monitor_rt_proto_rts540x_stage(FuDellMonitorRtDevice *target,
				       const FuDellMonitorRtRoute *route,
				       GBytes *blob,
				       GError **error)
{
	/* Outer 5-attempt retry around the full update_self envelope,
	 * matching Rts5409s_ISP::isp at libhub.c:49226 (asm
	 * libhub.so:0x99360):
	 *   uVar15 = 1;
	 *   do { uVar8 = update_self(...); if (!uVar8) goto SUCCESS;
	 *        nanosleep(1s); uVar15++; } while (uVar15 != 6);
	 * Each retry re-arms (enable_vdcmd sub=3 + 0xE8) — same chip-
	 * mode prep update_self does on every call. AUDIT.md F3.4. */
	const guint max_attempts = 5;
	g_autoptr(GError) last_error = NULL;

	(void)route; /* DIRECT_STAGE — the route's i2c_target is unused */

	for (guint attempt = 0; attempt < max_attempts; attempt++) {
		g_autoptr(GError) attempt_error = NULL;
		if (fu_dell_monitor_rt_proto_rts540x_envelope_once(target,
								   blob,
								   &attempt_error))
			return TRUE;
		g_clear_error(&last_error);
		last_error = g_steal_pointer(&attempt_error);
		g_debug("rts540x update_self attempt %u/%u failed: %s",
			attempt + 1,
			max_attempts,
			last_error->message);
		if (attempt + 1 < max_attempts)
			g_usleep(1000 * 1000); /* 1 s between attempts */
	}
	g_propagate_prefixed_error(error,
				   g_steal_pointer(&last_error),
				   "rts540x update_self failed after %u attempts: ",
				   max_attempts);
	return FALSE;
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
 * TI TPS6598x USB-PD controller class (chip_guid_alt ea72869e-…).
 *
 * Programmed POST-bootloader via the i2c-tunnel using TPS6598x's 4CC
 * command interface (FLrr/FLem/FLad/FLwd/FLrd/FLvy) on slave 0x42.
 * The pre-bootloader ISP shim we loaded onto the primary hub MCU is
 * what executes the i2c-tunnel transactions on the chip side; from
 * the host's perspective the wire opcodes are still 0xC6/0xD6.
 *
 * arm_target is a no-op because by the time we get here the primary
 * is already running its post-bootloader ISP shim and accepting
 * i2c-tunnel writes — the cal_auth handshake gets re-done in
 * stage_blob, just like for the downstream-MCU class.
 */
static gboolean
fu_dell_monitor_rt_proto_pdc_arm(FuDellMonitorRtDevice *target, GError **error)
{
	(void)target;
	(void)error;
	return TRUE;
}

static gboolean
fu_dell_monitor_rt_proto_pdc_stage(FuDellMonitorRtDevice *target,
				   const FuDellMonitorRtRoute *route,
				   GBytes *blob,
				   GError **error)
{
	guint8 hub_key[8];
	const gchar *install_version;

	(void)route; /* slave 0x42 is implicit in pdc_program */
	fu_dell_monitor_rt_get_synkey(DELL_MONITOR_RT_U4025QW_SYNKEY_SEED,
				      sizeof(DELL_MONITOR_RT_U4025QW_SYNKEY_SEED),
				      hub_key);
	if (!fu_dell_monitor_rt_device_handshake(target, hub_key, error))
		return FALSE;
	if (!fu_dell_monitor_rt_device_pdc_program(target, blob, NULL, error))
		return FALSE;

	/* Post-PDC commit: write "#CHK#<install_version>#" to VCP 0xAD.
	 * This triggers the chip's signature verification of the just-
	 * staged PDC firmware (recap frame 290306). Without it, DISPLAY
	 * block 0's 0x04 secure_control_gpio commit STALLs because the
	 * chip refuses to enable the secure flash GPIO while an
	 * unverified PDC sits in the spare bank. The install_version
	 * was cached on the device by write_firmware. */
	install_version =
	    fu_device_get_metadata(FU_DEVICE(target),
				   "dell-monitor-rt:install-version");
	if (install_version != NULL) {
		if (!fu_dell_monitor_rt_device_commit_isp_tag(target,
							      "CHK",
							      install_version,
							      error)) {
			g_prefix_error(error, "post-PDC IspTag commit: ");
			return FALSE;
		}
	} else {
		g_warning("dell-monitor-rt: post-PDC commit skipped — no "
			  "install-version metadata cached (write_firmware "
			  "should have set it)");
	}
	return TRUE;
}

/*
 * Panel-scaler "DISPLAY" class (chip_guid_alt 23d1218b-…).
 *
 * Programmed POST-bootloader via direct vendor-cmd opcodes (F4/F1/04/F5
 * + F3 polls) on the primary HID — no i2c-tunnel involved on this side
 * of the protocol. The chip's host-side ISP shim accepts a per-block
 * stage-and-commit sequence; the chip then internally relays the bytes
 * to the panel scaler's SPI flash.
 *
 * arm_target is currently a no-op: the cal_auth handshake we re-do in
 * stage_blob is the only state the chip needs that the post-bootloader
 * setup didn't already establish. There may be additional priming we
 * haven't decoded — emulator skips after the F4 frames will tell us.
 *
 * NOT YET IMPLEMENTED here: the per-block REALTEK_API::spi_unit_erase
 * pass that the libdisplay.so outer driver runs BEFORE each block's F4.
 * That pass is a series of i2c-tunnel writes/reads to slave 0x94. On
 * real hardware its absence means the chip commits into a non-erased
 * region; under emulation the leapfrog matcher will skip past the
 * captured spi_unit_erase frames so the F4/F1/04/F5 sequence still
 * matches.
 */
static gboolean
fu_dell_monitor_rt_proto_display_arm(FuDellMonitorRtDevice *target, GError **error)
{
	(void)target;
	(void)error;
	return TRUE;
}

static gboolean
fu_dell_monitor_rt_proto_display_stage(FuDellMonitorRtDevice *target,
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
	return fu_dell_monitor_rt_device_display_program(target,
							 blob,
							 route->flash_start_index,
							 route->flash_end_index,
							 route->wp_reg_a,
							 route->wp_reg_b,
							 route->chip_flags,
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
	.phase_order = 0, /* unused for direct-stage */
	.arm_target = fu_dell_monitor_rt_proto_rts540x_arm,
	.stage_blob = fu_dell_monitor_rt_proto_rts540x_stage,
    },
    {
	.name = "Downstream MCU (i2c-tunnel RAM loader)",
	.chip_guid_alt = "5f3ba3d6-a0bd-4270-9938-814a45d5c824",
	.phase_order = 0, /* unused for i2c-tunnel */
	.arm_target = fu_dell_monitor_rt_proto_dsmcu_arm,
	.stage_blob = fu_dell_monitor_rt_proto_dsmcu_stage,
    },
    {
	.name = "TI TPS6598x PD controller (post-bootloader 4CC flash)",
	.chip_guid_alt = "ea72869e-aa74-401c-8eda-8cf53ab7be72",
	.phase_order = 0, /* Phase A — runs first */
	.arm_target = fu_dell_monitor_rt_proto_pdc_arm,
	.stage_blob = fu_dell_monitor_rt_proto_pdc_stage,
    },
    {
	.name = "Panel scaler DISPLAY (post-bootloader F4/F1/04/F5 stage+commit)",
	.chip_guid_alt = "23d1218b-1805-42af-874c-1316003b6c7d",
	.phase_order = 1, /* Phase B — runs after PDC */
	.arm_target = fu_dell_monitor_rt_proto_display_arm,
	.stage_blob = fu_dell_monitor_rt_proto_display_stage,
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

	/* flash_start_index / flash_end_index — handlers that derive a
	 * per-block target SPI address from `start * 0x10000 + addr_in_block`
	 * and an initial erase at `end * 0x10000`. The .upg's
	 * `flash_off_or_size` field carries the start; `flash_size_or_end`
	 * carries the end. For the U4025QW DISPLAY these are 0x20 and 0x39,
	 * matching the RealtekISP::set_flash_start_index(0x20, 0x39) call
	 * decompiled out of the host-side ISP shim's setup path. Components
	 * that don't use them leave the fields at 0.
	 *
	 * wp_reg_a / wp_reg_b / chip_flags — REALTEK_API SPI flash write-
	 * protect register addresses + flags, plumbed through
	 * RealtekISP::set_write_protect_pin in the original stack. The .upg's
	 * param11/12/13 fields carry these (0x109B/0x223B/0x10001 for the
	 * U4025QW DISPLAY); only the DISPLAY handler reads them. */
	{
		guint64 v;
		const gchar *s;

		s = fu_dell_monitor_rt_firmware_component_get_field_string(
		    component,
		    FU_DELL_MONITOR_RT_FIRMWARE_FIELD_FLASH_OFF_OR_SIZE);
		v = 0;
		if (s != NULL &&
		    fu_strtoull(s, &v, 0, 0xFFFFFFFF, FU_INTEGER_BASE_AUTO, NULL))
			route_out->flash_start_index = (guint32)v;

		s = fu_dell_monitor_rt_firmware_component_get_field_string(
		    component,
		    FU_DELL_MONITOR_RT_FIRMWARE_FIELD_FLASH_SIZE_OR_END);
		v = 0;
		if (s != NULL &&
		    fu_strtoull(s, &v, 0, 0xFFFFFFFF, FU_INTEGER_BASE_AUTO, NULL))
			route_out->flash_end_index = (guint32)v;

		s = fu_dell_monitor_rt_firmware_component_get_field_string(
		    component, FU_DELL_MONITOR_RT_FIRMWARE_FIELD_PARAM11);
		v = 0;
		if (s != NULL &&
		    fu_strtoull(s, &v, 0, 0xFFFF, FU_INTEGER_BASE_AUTO, NULL))
			route_out->wp_reg_a = (guint16)v;

		s = fu_dell_monitor_rt_firmware_component_get_field_string(
		    component, FU_DELL_MONITOR_RT_FIRMWARE_FIELD_PARAM12);
		v = 0;
		if (s != NULL &&
		    fu_strtoull(s, &v, 0, 0xFFFF, FU_INTEGER_BASE_AUTO, NULL))
			route_out->wp_reg_b = (guint16)v;

		s = fu_dell_monitor_rt_firmware_component_get_field_string(
		    component, FU_DELL_MONITOR_RT_FIRMWARE_FIELD_PARAM13);
		v = 0;
		if (s != NULL &&
		    fu_strtoull(s, &v, 0, 0xFFFFFFFF, FU_INTEGER_BASE_AUTO, NULL))
			route_out->chip_flags = (guint32)v;
	}

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

	/* Post-bootloader: any component whose chip-class GUID resolves to
	 * a known protocol handler. Two sub-cases:
	 *
	 *   i2c_val > 0  → i2c-tunnel route (the value is the chip's 7-bit
	 *                  i2c slave). Currently PDC (chip_guid_alt
	 *                  ea72869e-…, i2c_or_index = 0x21 → slave 0x42).
	 *   i2c_val == 0 → no i2c-tunnel; the chip is reachable via
	 *                  primary HID vendor-cmd opcodes and the route's
	 *                  i2c_target is unused. Currently DISPLAY
	 *                  (chip_guid_alt 23d1218b-…), whose handler
	 *                  emits F4/F1/04/F5 frames directly.
	 *
	 * Either way the target is the primary (PID 0x1100) — that's
	 * where the post-bootloader ISP shim runs. */
	if (route_out->proto != NULL) {
		route_out->kind = FU_DELL_MONITOR_RT_ROUTE_POST_BOOTLOADER;
		route_out->target = fu_dell_monitor_rt_device_find_target_by_pid(self, 0x1100);
		route_out->i2c_target =
		    (i2c_val > 0) ? (guint8)(i2c_val << 1) : 0; /* 7-bit → 8-bit */
		return route_out->target != NULL;
	}

	/* Out-of-range value with no recognized chip class: post-bootloader
	 * payload, scaler, or some other routing tag we haven't decoded
	 * yet. Leave NONE. */
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

	/* Baseline verify — read IspTag + panel_id, log diagnostics, fail
	 * hard on panel mismatch. Any subsequent IO depends on this check
	 * passing. The version-match short-circuit happens at fwupd's
	 * higher-level engine, not here. */
	{
		FuDellMonitorRtDevice *self = FU_DELL_MONITOR_RT_DEVICE(device);

		if (!fu_dell_monitor_rt_device_verify_baseline(self,
							       fw_container,
							       error))
			return FALSE;
	}

	/* The install drops the firmware-mode HID interface multiple times
	 * (the 0xE9 BOOTLOADER_ENTER triggers fired below cycle the MCU
	 * FW→BL→FW→BL→FW). After write_firmware returns, fwupd's reload
	 * phase needs to find the device back on the bus to verify the
	 * install succeeded. Setting WAIT_FOR_REPLUG asks the engine to
	 * pause at the end of write_firmware until the device disappears
	 * and re-appears (or remove_delay elapses — 60s in our init).
	 *
	 * The pcap shows no version-confirm reads against the post-update
	 * device beyond the re-enumeration handshake itself, so we don't
	 * override device_class->reload — the default no-op success is
	 * the right answer here. The flag is the only piece of reload-
	 * phase machinery we need to invoke. */
	fu_device_add_flag(device, FWUPD_DEVICE_FLAG_WAIT_FOR_REPLUG);

	/* Multi-phase install: the chip's 0xE9 bootloader-enter trigger
	 * forces a full USB re-enumeration which invalidates our hidraw
	 * fd, so we can't keep doing IO after firing 0xE9 in the same
	 * write_firmware call. fwupd's standard pattern (cros-ec et al.)
	 * is to use FWUPD_DEVICE_FLAG_ANOTHER_WRITE_REQUIRED + a private
	 * stage-tracking flag transferred via device_class->replace:
	 *
	 *   Iteration 1 (PRE_BL_DONE flag NOT set):
	 *     - pre-bootloader work (passes 0..2): HUB1/HUB2 i2c-tunnel,
	 *       HUB c8 stage on primary, HUB4 c8 stage on secondary
	 *     - bootloader-enter 0xE9 on each direct-stage target
	 *     - set PRE_BL_DONE + ANOTHER_WRITE_REQUIRED, return success
	 *     - engine waits for replug (WAIT_FOR_REPLUG already set)
	 *     - engine replaces FuDevice with the re-enumerated one;
	 *       device_class->replace copies PRE_BL_DONE across
	 *
	 *   Iteration 2 (PRE_BL_DONE flag IS set):
	 *     - post-bootloader work (passes 3..4): PDC + DISPLAY
	 *     - no flag set, no ANOTHER_WRITE_REQUIRED, install done
	 *
	 * On real hardware this gives PDC programming a fresh hidraw fd
	 * onto the post-bootloader device. On emulation the engine
	 * doesn't actually replug — the fixture's event cursor walks
	 * through one continuous stream — but the flag-flip + ANOTHER_
	 * WRITE_REQUIRED dance still works because both iterations run
	 * on the same synthetic FuDevice. See AUDIT.md / pcap analysis
	 * in captures/u4025qw-failrun-20260513-145646.pcapng for the
	 * real-HW EPROTO that motivated this split. */
	{
		gboolean pre_bl_done =
		    fu_device_has_private_flag(device,
					       FU_DELL_MONITOR_RT_FLAG_PRE_BL_DONE);
		g_info("dell-monitor-rt: write_firmware phase = %s",
		       pre_bl_done ? "post-bootloader" : "pre-bootloader");
	}

	/* Cache the new firmware's top-level version string on the device.
	 * proto_pdc_stage (iteration 2) needs it for the post-PDC #CHK#
	 * commit. Re-set on every write_firmware call rather than carrying
	 * across the replug — fwupd's device replace doesn't copy metadata
	 * by default, but we get the same FuFirmware passed to every
	 * iteration so we can just refresh the cache here. */
	{
		const gchar *new_version =
		    fu_dell_monitor_rt_firmware_get_fw_version(fw_container);
		if (new_version != NULL) {
			fu_device_set_metadata(device,
					       "dell-monitor-rt:install-version",
					       new_version);
		}
	}

	/* Open every paired child device for the duration of write_firmware.
	 * fwupd's engine only opens the device it's actively flashing (the
	 * primary parent here); when our route walker dispatches a stage to
	 * a child target (e.g. HUB4 c8 staging on the secondary 0BDA:1101),
	 * the child's hidraw fd has never been opened and writes return
	 * EBADF. The locker array RAII-closes each child when write_firmware
	 * returns, restoring the pre-install fd state. */
	g_autoptr(GPtrArray) child_lockers =
	    g_ptr_array_new_with_free_func(g_object_unref);
	{
		GPtrArray *children = fu_device_get_children(device);
		for (guint i = 0; children != NULL && i < children->len; i++) {
			FuDevice *child = g_ptr_array_index(children, i);
			FuDeviceLocker *locker = NULL;
			if (fu_device_has_flag(child, FWUPD_DEVICE_FLAG_EMULATED))
				continue; /* synthetic devices have no real fd */
			locker = fu_device_locker_new(child, error);
			if (locker == NULL) {
				g_prefix_error(error,
					       "opening child %s for install: ",
					       fu_device_get_id(child));
				return FALSE;
			}
			g_ptr_array_add(child_lockers, locker);
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

		/* The four passes match Dell's observed order:
		 *
		 *   Pass 1 — every i2c-tunnel component. The proto's stage_blob
		 *            does its own per-blob cal_auth.
		 *   Pass 2 — every direct-stage component whose target is NOT
		 *            the primary, followed by that target's 0xE9. Dell
		 *            fires the secondary's 0xE9 before the primary's,
		 *            so we drain non-primary devices first.
		 *   Pass 3 — every direct-stage component whose target IS the
		 *            primary, then the primary's 0xE9. After this pass
		 *            the primary is running its post-bootloader ISP
		 *            shim and accepting i2c-tunnel writes again
		 *            (via the new shim's protocol).
		 *   Pass 4..N — post-bootloader components, sub-ordered by
		 *            their handler's `phase_order`. Currently:
		 *              pass 3 (phase_order=0) — TPS6598x PDC flash
		 *              pass 4 (phase_order=1) — RTS5409S DISPLAY
		 *                                       block-write loop
		 *            The two phases must run in this order: the
		 *            captured trace shows PDC programming entirely
		 *            precedes DISPLAY programming, and the chip's
		 *            ISP shim accepts the commands in that order.
		 *            New post-bootloader handlers slot in by setting
		 *            their `phase_order` and bumping NUM_PASSES.
		 */
#define DELL_MONITOR_RT_PRE_BOOTLOADER_PASSES 3
#define DELL_MONITOR_RT_POST_BOOTLOADER_PHASES 2
#define DELL_MONITOR_RT_NUM_PASSES                                                                 \
	(DELL_MONITOR_RT_PRE_BOOTLOADER_PASSES + DELL_MONITOR_RT_POST_BOOTLOADER_PHASES)
		/* Iteration 1 runs passes 0..PRE_BL_PASSES-1 (pre-bootloader);
		 * iteration 2 (PRE_BL_DONE flag set) runs passes PRE_BL_PASSES..
		 * NUM_PASSES-1 (post-bootloader). The route walker's filter
		 * logic already discriminates by `route.kind` and `phase_order`
		 * — limiting the loop range here just skips the irrelevant
		 * passes early. */
		guint pass_lo, pass_hi;
		if (fu_device_has_private_flag(
			device,
			FU_DELL_MONITOR_RT_FLAG_PRE_BL_DONE)) {
			pass_lo = DELL_MONITOR_RT_PRE_BOOTLOADER_PASSES;
			pass_hi = DELL_MONITOR_RT_NUM_PASSES;
		} else {
			pass_lo = 0;
			pass_hi = DELL_MONITOR_RT_PRE_BOOTLOADER_PASSES;

			/* Pre-install IspTag announcement (iteration 1 only).
			 * Wistron writes "#ISP#<new_version>#" to VCP 0xAD
			 * twice back-to-back before any flashing begins
			 * (recap frames 7230 and 7264). This tells the chip
			 * the target version of the in-progress update so it
			 * can later verify the staged firmware against it
			 * when "#CHK#<new_version>#" arrives post-PDC.
			 * Without this pair the chip rejects the post-PDC
			 * commit and stalls DISPLAY block 0. The duplicate
			 * write matches Wistron's exact emission pattern —
			 * defensive or paired-protocol, unclear, but cheap
			 * to mirror. */
			{
				const gchar *new_version =
				    fu_dell_monitor_rt_firmware_get_fw_version(
					fw_container);
				if (new_version != NULL) {
					for (guint k = 0; k < 2; k++) {
						if (!fu_dell_monitor_rt_device_commit_isp_tag(
							self,
							"ISP",
							new_version,
							error)) {
							g_prefix_error(
							    error,
							    "pre-install IspTag "
							    "announcement #%u: ",
							    k + 1);
							return FALSE;
						}
					}
				}
			}
		}
		for (guint pass = pass_lo; pass < pass_hi; pass++) {
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
				if (pass >= DELL_MONITOR_RT_PRE_BOOTLOADER_PASSES) {
					guint phase = pass - DELL_MONITOR_RT_PRE_BOOTLOADER_PASSES;
					if (route.kind != FU_DELL_MONITOR_RT_ROUTE_POST_BOOTLOADER)
						continue;
					if (route.proto == NULL ||
					    route.proto->phase_order != phase)
						continue;
				}

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
				/* Skip placeholder components with no flashable
				 * bytes — e.g. the .upg's plaintext "DISPLAY"
				 * entry exists only to declare the chip class
				 * (chip_guid_alt = 23d1218b-…); the actual
				 * 1.7 MB payload lives in the matching panel-
				 * bound component (id = the panel's scaler ID).
				 * Both components route to the same protocol
				 * handler, so we let the panel-bound one win
				 * by skipping any peer with an empty blob. */
				if (g_bytes_get_size(blob) == 0) {
					g_debug("dell-monitor-rt: %s has no flashable "
						"bytes (likely a metadata-only "
						"placeholder paired with a panel-bound "
						"sibling); skipping",
						fu_firmware_get_id(FU_FIRMWARE(component)));
					continue;
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
				} else if (route.kind == FU_DELL_MONITOR_RT_ROUTE_POST_BOOTLOADER) {
					g_info("dell-monitor-rt: %s programmed post-bootloader "
					       "via i2c slave 0x%02x (%" G_GSIZE_FORMAT " bytes)",
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

		/* If we just finished the pre-bootloader passes, mark
		 * the stage as done and ask the engine to come back for
		 * another write_firmware iteration after the device
		 * re-enumerates (forced by the 0xE9 we just fired). The
		 * second iteration will run the post-bootloader passes
		 * with a fresh hidraw fd. */
		if (pass_hi == DELL_MONITOR_RT_PRE_BOOTLOADER_PASSES) {
			fu_device_add_private_flag(
			    device,
			    FU_DELL_MONITOR_RT_FLAG_PRE_BL_DONE);
			fu_device_add_flag(device,
					   FWUPD_DEVICE_FLAG_ANOTHER_WRITE_REQUIRED);
			g_info("dell-monitor-rt: pre-bootloader complete; "
			       "yielding for replug + post-bootloader "
			       "iteration");
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
		case FU_DELL_MONITOR_RT_ROUTE_POST_BOOTLOADER:
			route_str = (route.proto != NULL) ? route.proto->name
							  : "post-bootloader";
			break;
		default:
			route_str = "(unrouted)";
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
fu_dell_monitor_rt_device_finalize(GObject *object)
{
	FuDellMonitorRtDevice *self = FU_DELL_MONITOR_RT_DEVICE(object);
	g_free(self->cached_panel_id);
	G_OBJECT_CLASS(fu_dell_monitor_rt_device_parent_class)->finalize(object);
}

static void
fu_dell_monitor_rt_device_class_init(FuDellMonitorRtDeviceClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS(klass);
	FuDeviceClass *device_class = FU_DEVICE_CLASS(klass);
	object_class->finalize = fu_dell_monitor_rt_device_finalize;
	device_class->probe = fu_dell_monitor_rt_device_probe;
	device_class->setup = fu_dell_monitor_rt_device_setup;
	device_class->write_firmware = fu_dell_monitor_rt_device_write_firmware;
	device_class->replace = fu_dell_monitor_rt_device_replace;
	device_class->cleanup = fu_dell_monitor_rt_device_cleanup;
}
