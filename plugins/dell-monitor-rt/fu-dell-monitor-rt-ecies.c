/*
 * Copyright 2026 Joshua Perry <josh@6bit.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "config.h"

#include <gio/gio.h>
#include <gmp.h>
#include <nettle/dsa.h>
#include <nettle/ecc-curve.h>
#include <nettle/ecc.h>
#include <nettle/ecdsa.h>
#include <nettle/sha3.h>

#include "fu-dell-monitor-rt-ecies.h"

/* secp521r1 constants. */
#define FU_DELL_MONITOR_RT_FIELD_BYTES	   66 /* 521 bits, padded */
#define FU_DELL_MONITOR_RT_POINT_BYTES	   (1 + 2 * FU_DELL_MONITOR_RT_FIELD_BYTES) /* SEC1 0x04||X||Y */
#define FU_DELL_MONITOR_RT_SHA3_512_DIGEST 64
#define FU_DELL_MONITOR_RT_SHA3_512_BLOCK  72

/* Each per-component plaintext we get out of ECIES ends in a 222-byte
 * authenticator: the raw r||s ECDSA signature followed by a DER
 * SubjectPublicKeyInfo carrying the (compressed) signing pubkey. */
#define FU_DELL_MONITOR_RT_TRAILER_LEN	  222
#define FU_DELL_MONITOR_RT_SIG_LEN	  (2 * FU_DELL_MONITOR_RT_FIELD_BYTES) /* r || s */
#define FU_DELL_MONITOR_RT_SPKI_LEN	  90  /* DER SubjectPublicKeyInfo */
#define FU_DELL_MONITOR_RT_COMPRESSED_LEN (1 + FU_DELL_MONITOR_RT_FIELD_BYTES) /* 02|03 || X */

/* secp521r1 b coefficient (from FIPS 186-4 / SEC2). The a coefficient
 * is just -3 mod p so we don't bother storing it. */
static const guint8 fu_dell_monitor_rt_secp521r1_b[FU_DELL_MONITOR_RT_FIELD_BYTES] = {
    0x00, 0x51, 0x95, 0x3e, 0xb9, 0x61, 0x8e, 0x1c, 0x9a, 0x1f, 0x92, 0x9a, 0x21, 0xa0,
    0xb6, 0x85, 0x40, 0xee, 0xa2, 0xda, 0x72, 0x5b, 0x99, 0xb3, 0x15, 0xf3, 0xb8, 0xb4,
    0x89, 0x91, 0x8e, 0xf1, 0x09, 0xe1, 0x56, 0x19, 0x39, 0x51, 0xec, 0x7e, 0x93, 0x7b,
    0x16, 0x52, 0xc0, 0xbd, 0x3b, 0xb1, 0xbf, 0x07, 0x35, 0x73, 0xdf, 0x88, 0x3d, 0x2c,
    0x34, 0xf1, 0xef, 0x45, 0x1f, 0xd4, 0x6b, 0x50, 0x3f, 0x00,
};

/* HMAC-SHA3-512 key length used by CryptoPP's HMAC<SHA3_512>::DEFAULT_KEYLENGTH.
 * The base class returns 16 (NOT the BLOCKSIZE of 72 nor the DIGESTSIZE of 64),
 * which is what `DL_EncryptionAlgorithm_Xor` reads when computing the KDF
 * output length. Verified empirically from CryptoPP 8.9. */
#define FU_DELL_MONITOR_RT_HMAC_KEY_BYTES 16

/*
 * Wistron's static secp521r1 ECIES private key, baked into every shipped
 * libhub.so we've examined (U4025QW M3T105 from Oct 2025, U3224KB M2T105
 * from Dec 2023; both have the byte-identical 98-byte PKCS#8 wrapper at
 * symbol _ZL13CK_PV_RawData). Cross-check via:
 *
 *   sha256(this_array)       = 0eede35b9795ae9464982485c118c82d4920e759
 *                              814018bf3528ff48892c7bd0   (PKCS#8 wrapper)
 *   sha256(scalar 66-bytes)  =                            (per below)
 *
 * If a future Dell/Wistron release rotates this, search for the fixed
 * 32-byte ASN.1 prefix
 *   30 60 02 01 00 30 10 06 07 2a 86 48 ce 3d 02 01
 *   06 05 2b 81 04 00 23 04 49 30 47 02 01 01 04 42
 * in the new libhub.so to find the replacement.
 */
static const guint8 fu_dell_monitor_rt_static_priv_scalar[FU_DELL_MONITOR_RT_FIELD_BYTES] = {
    0x01, 0x74, 0x26, 0xf1, 0x02, 0x5d, 0xd6, 0x6a, 0x3d, 0xf6, 0xa1, 0xe1, 0xda, 0x1d,
    0x9d, 0xd7, 0xae, 0xd4, 0xca, 0x61, 0x86, 0xf2, 0x6e, 0xee, 0x83, 0x30, 0x71, 0x7b,
    0x81, 0x85, 0x58, 0x55, 0x2f, 0xea, 0xe2, 0x3b, 0x18, 0xa7, 0x1d, 0x3e, 0xd9, 0x29,
    0x74, 0xa3, 0xec, 0x5d, 0x5b, 0x4f, 0xc4, 0xc8, 0xa0, 0x53, 0x63, 0xcd, 0x38, 0xb2,
    0x80, 0xb5, 0x66, 0xe5, 0xf0, 0xe3, 0xfc, 0xde, 0xce, 0x7a,
};

/* HMAC-SHA3-512 implemented manually on top of nettle's sha3_512_*.
 * nettle ships HMAC for SHA-1/2/256/384/512 as named functions but does
 * not include HMAC-SHA3-512 directly, so we wire it up from the spec
 * (RFC 2104, with SHA3-512's 72-byte block size and 64-byte digest). */
static void
fu_dell_monitor_rt_hmac_sha3_512(const guint8 *key,
				 gsize key_len,
				 const guint8 *msg,
				 gsize msg_len,
				 guint8 out[FU_DELL_MONITOR_RT_SHA3_512_DIGEST])
{
	guint8 padded_key[FU_DELL_MONITOR_RT_SHA3_512_BLOCK] = {0};
	guint8 inner_pad[FU_DELL_MONITOR_RT_SHA3_512_BLOCK];
	guint8 outer_pad[FU_DELL_MONITOR_RT_SHA3_512_BLOCK];
	guint8 inner_digest[FU_DELL_MONITOR_RT_SHA3_512_DIGEST];
	struct sha3_512_ctx ctx;

	/* If key longer than block size, K' = SHA3-512(K). Otherwise zero-pad. */
	if (key_len > FU_DELL_MONITOR_RT_SHA3_512_BLOCK) {
		sha3_512_init(&ctx);
		sha3_512_update(&ctx, key_len, key);
		sha3_512_digest(&ctx, FU_DELL_MONITOR_RT_SHA3_512_DIGEST, padded_key);
	} else {
		memcpy(padded_key, key, key_len);
	}

	for (guint i = 0; i < FU_DELL_MONITOR_RT_SHA3_512_BLOCK; i++) {
		inner_pad[i] = padded_key[i] ^ 0x36;
		outer_pad[i] = padded_key[i] ^ 0x5c;
	}

	sha3_512_init(&ctx);
	sha3_512_update(&ctx, sizeof(inner_pad), inner_pad);
	sha3_512_update(&ctx, msg_len, msg);
	sha3_512_digest(&ctx, FU_DELL_MONITOR_RT_SHA3_512_DIGEST, inner_digest);

	sha3_512_init(&ctx);
	sha3_512_update(&ctx, sizeof(outer_pad), outer_pad);
	sha3_512_update(&ctx, sizeof(inner_digest), inner_digest);
	sha3_512_digest(&ctx, FU_DELL_MONITOR_RT_SHA3_512_DIGEST, out);
}

/*
 * P1363 KDF2 with SHA3-512.
 *
 *   For i = 1, 2, ..., ceil(out_len / 64):
 *     block_i = SHA3-512(input || u32_BE(i))
 *   out = concat(block_1, block_2, ...)[:out_len]
 *
 * Counter starts at 1 (KDF2; KDF1 starts at 0).
 */
static void
fu_dell_monitor_rt_kdf2_sha3_512(const guint8 *input,
				 gsize input_len,
				 guint8 *out,
				 gsize out_len)
{
	guint8 block[FU_DELL_MONITOR_RT_SHA3_512_DIGEST];
	guint32 counter = 1;
	gsize off = 0;
	struct sha3_512_ctx ctx;

	while (off < out_len) {
		guint8 counter_be[4] = {(guint8)(counter >> 24),
					(guint8)(counter >> 16),
					(guint8)(counter >> 8),
					(guint8)(counter)};
		gsize chunk = out_len - off;
		if (chunk > FU_DELL_MONITOR_RT_SHA3_512_DIGEST)
			chunk = FU_DELL_MONITOR_RT_SHA3_512_DIGEST;
		sha3_512_init(&ctx);
		sha3_512_update(&ctx, input_len, input);
		sha3_512_update(&ctx, sizeof(counter_be), counter_be);
		sha3_512_digest(&ctx, FU_DELL_MONITOR_RT_SHA3_512_DIGEST, block);
		memcpy(out + off, block, chunk);
		off += chunk;
		counter++;
	}
}

static gboolean
fu_dell_monitor_rt_ecies_compute_shared(const guint8 *q_encoded,
					guint8 shared_x[FU_DELL_MONITOR_RT_FIELD_BYTES],
					GError **error)
{
	const struct ecc_curve *curve = nettle_get_secp_521r1();
	mpz_t x, y, d, rx, ry;
	struct ecc_point ephemeral, shared;
	struct ecc_scalar privkey;
	gboolean ret = FALSE;

	if (q_encoded[0] != 0x04) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_DATA,
			    "ephemeral pubkey leading byte 0x%02x: only SEC1 "
			    "uncompressed (0x04) is supported",
			    q_encoded[0]);
		return FALSE;
	}

	mpz_inits(x, y, d, rx, ry, NULL);
	ecc_point_init(&ephemeral, curve);
	ecc_point_init(&shared, curve);
	ecc_scalar_init(&privkey, curve);

	mpz_import(x, FU_DELL_MONITOR_RT_FIELD_BYTES, 1, 1, 0, 0, q_encoded + 1);
	mpz_import(y,
		   FU_DELL_MONITOR_RT_FIELD_BYTES,
		   1,
		   1,
		   0,
		   0,
		   q_encoded + 1 + FU_DELL_MONITOR_RT_FIELD_BYTES);
	mpz_import(d,
		   FU_DELL_MONITOR_RT_FIELD_BYTES,
		   1,
		   1,
		   0,
		   0,
		   fu_dell_monitor_rt_static_priv_scalar);

	/* Validate ephemeral point is on the curve. */
	if (!ecc_point_set(&ephemeral, x, y)) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_INVALID_DATA,
				    "ephemeral pubkey is not a valid secp521r1 point");
		goto out;
	}
	if (!ecc_scalar_set(&privkey, d)) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_INTERNAL,
				    "static private scalar out of range "
				    "(corrupt/wrong key)");
		goto out;
	}

	/* secp521r1 has cofactor h=1, so CryptoPP's
	 * IncompatibleCofactorMultiplication is a no-op for this curve;
	 * the shared point is just d * Q. */
	ecc_point_mul(&shared, &privkey, &ephemeral);
	ecc_point_get(&shared, rx, ry);

	/* Export X-coordinate as 66 bytes BE, zero-padded on the left. */
	memset(shared_x, 0, FU_DELL_MONITOR_RT_FIELD_BYTES);
	{
		size_t written = 0;
		guint8 *tmp = g_malloc(FU_DELL_MONITOR_RT_FIELD_BYTES);
		mpz_export(tmp, &written, 1, 1, 0, 0, rx);
		if (written > FU_DELL_MONITOR_RT_FIELD_BYTES) {
			g_free(tmp);
			g_set_error_literal(error,
					    FWUPD_ERROR,
					    FWUPD_ERROR_INTERNAL,
					    "shared x larger than field");
			goto out;
		}
		memcpy(shared_x + (FU_DELL_MONITOR_RT_FIELD_BYTES - written), tmp, written);
		g_free(tmp);
	}
	ret = TRUE;

out:
	mpz_clears(x, y, d, rx, ry, NULL);
	ecc_point_clear(&ephemeral);
	ecc_point_clear(&shared);
	ecc_scalar_clear(&privkey);
	return ret;
}

/* Decode a hex-encoded ASCII byte stream into binary. Skips no
 * whitespace — Dell's encoding is contiguous lowercase/uppercase hex. */
static GBytes *
fu_dell_monitor_rt_hex_decode(const guint8 *src, gsize src_len, GError **error)
{
	g_autoptr(GByteArray) out = g_byte_array_new();
	gsize i;

	if ((src_len & 1) != 0) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_DATA,
			    "hex stream length %" G_GSIZE_FORMAT " is odd",
			    src_len);
		return NULL;
	}
	for (i = 0; i < src_len; i += 2) {
		gint hi = g_ascii_xdigit_value(src[i]);
		gint lo = g_ascii_xdigit_value(src[i + 1]);
		guint8 byte;
		if (hi < 0 || lo < 0) {
			g_set_error(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_INVALID_DATA,
				    "non-hex byte at offset %" G_GSIZE_FORMAT,
				    i);
			return NULL;
		}
		byte = (guint8)((hi << 4) | lo);
		g_byte_array_append(out, &byte, 1);
	}
	return g_byte_array_free_to_bytes(g_steal_pointer(&out));
}

/* Run input through GZlibDecompressor (raw GZIP wrapper). */
static GBytes *
fu_dell_monitor_rt_gunzip(const guint8 *src, gsize src_len, GError **error)
{
	g_autoptr(GZlibDecompressor) decompressor =
	    g_zlib_decompressor_new(G_ZLIB_COMPRESSOR_FORMAT_GZIP);
	g_autoptr(GByteArray) out = g_byte_array_new();
	gsize in_off = 0;

	while (in_off < src_len) {
		guint8 buf[8192];
		gsize bytes_read = 0;
		gsize bytes_written = 0;
		GConverterResult res =
		    g_converter_convert(G_CONVERTER(decompressor),
					src + in_off,
					src_len - in_off,
					buf,
					sizeof(buf),
					(in_off + sizeof(buf) >= src_len)
					    ? G_CONVERTER_INPUT_AT_END
					    : G_CONVERTER_NO_FLAGS,
					&bytes_read,
					&bytes_written,
					error);
		if (res == G_CONVERTER_ERROR)
			return NULL;
		g_byte_array_append(out, buf, bytes_written);
		in_off += bytes_read;
		if (res == G_CONVERTER_FINISHED)
			break;
		if (bytes_read == 0 && bytes_written == 0) {
			g_set_error_literal(error,
					    FWUPD_ERROR,
					    FWUPD_ERROR_INVALID_DATA,
					    "gunzip stalled with no progress");
			return NULL;
		}
	}
	return g_byte_array_free_to_bytes(g_steal_pointer(&out));
}

/*
 * Decompress a SEC1-encoded compressed point (1 prefix byte + X) into
 * its (X, Y) coordinates on secp521r1.
 *
 * For p ≡ 3 (mod 4), which holds for the secp521r1 field modulus
 * p = 2^521 - 1, the modular square root is just (Y²)^((p+1)/4) mod p,
 * i.e. Y²^(2^519) mod p. We pick the Y whose parity matches the prefix
 * byte (0x02 → even Y, 0x03 → odd Y) and return p - Y otherwise.
 */
static gboolean
fu_dell_monitor_rt_secp521r1_decompress(const guint8 *compressed,
					mpz_t x_out,
					mpz_t y_out,
					GError **error)
{
	mpz_t p, b, y_squared, three_x, exponent;
	guint parity_wanted;
	gboolean ret = FALSE;

	if (compressed[0] != 0x02 && compressed[0] != 0x03) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_DATA,
			    "compressed point prefix 0x%02x not 0x02/0x03",
			    compressed[0]);
		return FALSE;
	}
	parity_wanted = compressed[0] - 0x02; /* 0 = even Y, 1 = odd Y */

	mpz_inits(p, b, y_squared, three_x, exponent, NULL);

	/* p = 2^521 - 1 */
	mpz_set_ui(p, 1);
	mpz_mul_2exp(p, p, 521);
	mpz_sub_ui(p, p, 1);

	mpz_import(x_out, FU_DELL_MONITOR_RT_FIELD_BYTES, 1, 1, 0, 0, compressed + 1);
	if (mpz_cmp(x_out, p) >= 0) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_INVALID_DATA,
				    "compressed point X >= p");
		goto out;
	}
	mpz_import(b,
		   FU_DELL_MONITOR_RT_FIELD_BYTES,
		   1,
		   1,
		   0,
		   0,
		   fu_dell_monitor_rt_secp521r1_b);

	/* Y² = X³ - 3X + b (mod p) */
	mpz_powm_ui(y_squared, x_out, 3, p);
	mpz_mul_ui(three_x, x_out, 3);
	mpz_sub(y_squared, y_squared, three_x);
	mpz_add(y_squared, y_squared, b);
	mpz_mod(y_squared, y_squared, p);

	/* Y = Y² ^ ((p+1)/4) mod p   ;   (p+1)/4 = 2^519 for this curve. */
	mpz_set_ui(exponent, 1);
	mpz_mul_2exp(exponent, exponent, 519);
	mpz_powm(y_out, y_squared, exponent, p);

	/* Validate the recovered Y is actually a square root (catches the
	 * "X has no Y on curve" case where the powm result is bogus). */
	{
		mpz_t check;
		mpz_init(check);
		mpz_powm_ui(check, y_out, 2, p);
		if (mpz_cmp(check, y_squared) != 0) {
			mpz_clear(check);
			g_set_error_literal(error,
					    FWUPD_ERROR,
					    FWUPD_ERROR_INVALID_DATA,
					    "compressed point X is not on the curve");
			goto out;
		}
		mpz_clear(check);
	}

	if (mpz_tstbit(y_out, 0) != parity_wanted)
		mpz_sub(y_out, p, y_out);
	ret = TRUE;

out:
	mpz_clears(p, b, y_squared, three_x, exponent, NULL);
	return ret;
}

/*
 * Parse the 90-byte DER-encoded SubjectPublicKeyInfo carrying the
 * trailer's signing pubkey. We don't reach for a full DER parser
 * because the structure is byte-for-byte fixed (verified against
 * captures/signing-pubkey.spki.der):
 *
 *   30 58                                    SEQUENCE (88)
 *     30 10                                  SEQUENCE (16) — AlgorithmIdentifier
 *       06 07 2a 86 48 ce 3d 02 01           OID 1.2.840.10045.2.1 (ecPublicKey)
 *       06 05 2b 81 04 00 23                 OID 1.3.132.0.35 (secp521r1)
 *     03 44                                  BIT STRING (68)
 *       00                                   0 unused bits
 *       02 || X                              compressed secp521r1 point
 *
 * If a future Dell/Wistron release switches to uncompressed encoding
 * (`04 || X || Y` inside the BIT STRING) we'd need to extend this.
 */
static const guint8 fu_dell_monitor_rt_spki_prefix[24] = {
    0x30, 0x58, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23, 0x03, 0x44, 0x00,
    /* compressed point follows: 0x02 or 0x03 then 66 X bytes */
};
G_STATIC_ASSERT(sizeof(fu_dell_monitor_rt_spki_prefix) - 1 +
		    FU_DELL_MONITOR_RT_COMPRESSED_LEN ==
		FU_DELL_MONITOR_RT_SPKI_LEN);

static gboolean
fu_dell_monitor_rt_parse_spki(const guint8 *spki,
			      mpz_t x_out,
			      mpz_t y_out,
			      GError **error)
{
	if (memcmp(spki,
		   fu_dell_monitor_rt_spki_prefix,
		   sizeof(fu_dell_monitor_rt_spki_prefix) - 1) != 0) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_INVALID_DATA,
				    "trailer SPKI prefix doesn't match the expected "
				    "fixed encoding");
		return FALSE;
	}
	return fu_dell_monitor_rt_secp521r1_decompress(
	    spki + (sizeof(fu_dell_monitor_rt_spki_prefix) - 1),
	    x_out,
	    y_out,
	    error);
}

/* Hex-encode `in` into `out` as `2*in_len` uppercase ASCII chars,
 * no separator. Caller owns out. */
static void
fu_dell_monitor_rt_hex_encode_upper(const guint8 *in, gsize in_len, gchar *out)
{
	static const gchar hexchars[] = "0123456789ABCDEF";
	for (gsize i = 0; i < in_len; i++) {
		out[i * 2 + 0] = hexchars[in[i] >> 4];
		out[i * 2 + 1] = hexchars[in[i] & 0x0f];
	}
}

/*
 * Verify the per-bundle ECDSA-secp521r1-with-SHA3_512 signature in the
 * trailer against the firmware bytes preceding it. Uses the trailer's
 * own embedded signing pubkey — see the trust-model note in the header
 * for why this is necessarily self-attestation rather than a real chain
 * of trust (no Dell/Wistron root key exists in the shipped binaries,
 * confirmed by exhaustive search across libhub.so, the main updater,
 * and the data files in both U4025QW and U3224KB bundles).
 *
 * Dell wraps the firmware in a layered hash before signing (verified
 * empirically against captures/load-vec-*.bin):
 *
 *   outer_message = uppercase_hex(SHA3-512(uppercase_hex(firmware_bytes)))
 *
 * The ECDSA<ECP, SHA3_512>::Verifier then hashes outer_message once more
 * with SHA3-512 internally before verifying, so the digest the signature
 * ultimately covers is:
 *
 *   final_digest = SHA3-512(outer_message)
 *
 * The double hex-then-hash dance is what `Certify::c` does in libhub.so
 * — it goes via Certify::h which is defined as:
 *
 *   Certify::h(input) = uppercase_hex(SHA3-512(input))
 *
 * applied to `uppercase_hex(firmware)`. We replicate it here verbatim.
 */
static gboolean
fu_dell_monitor_rt_verify_trailer(const guint8 *firmware,
				  gsize firmware_len,
				  const guint8 *trailer,
				  GError **error)
{
	const struct ecc_curve *curve = nettle_get_secp_521r1();
	struct ecc_point pub;
	struct dsa_signature sig;
	struct sha3_512_ctx hash_ctx;
	mpz_t x, y;
	guint8 inner_digest[FU_DELL_MONITOR_RT_SHA3_512_DIGEST];
	guint8 final_digest[FU_DELL_MONITOR_RT_SHA3_512_DIGEST];
	gchar outer_hex[FU_DELL_MONITOR_RT_SHA3_512_DIGEST * 2]; /* 128 chars */
	g_autofree gchar *firmware_hex = NULL;
	gboolean ok = FALSE;

	mpz_inits(x, y, NULL);
	ecc_point_init(&pub, curve);
	dsa_signature_init(&sig);

	/* Recover the signing point from the trailer's SPKI. */
	if (!fu_dell_monitor_rt_parse_spki(trailer + FU_DELL_MONITOR_RT_SIG_LEN,
					   x,
					   y,
					   error))
		goto out;
	if (!ecc_point_set(&pub, x, y)) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_INVALID_DATA,
				    "trailer signing pubkey is not a valid secp521r1 point");
		goto out;
	}

	/* Import r and s from the raw IEEE-1363 sig: 66+66 bytes BE. */
	mpz_import(sig.r, FU_DELL_MONITOR_RT_FIELD_BYTES, 1, 1, 0, 0, trailer);
	mpz_import(sig.s,
		   FU_DELL_MONITOR_RT_FIELD_BYTES,
		   1,
		   1,
		   0,
		   0,
		   trailer + FU_DELL_MONITOR_RT_FIELD_BYTES);

	/* uppercase_hex(firmware) */
	firmware_hex = g_malloc(firmware_len * 2);
	fu_dell_monitor_rt_hex_encode_upper(firmware, firmware_len, firmware_hex);

	/* SHA3-512(uppercase_hex(firmware)) → 64 bytes */
	sha3_512_init(&hash_ctx);
	sha3_512_update(&hash_ctx, firmware_len * 2, (const guint8 *)firmware_hex);
	sha3_512_digest(&hash_ctx, sizeof(inner_digest), inner_digest);

	/* uppercase_hex of those 64 bytes → 128-char ASCII */
	fu_dell_monitor_rt_hex_encode_upper(inner_digest,
					    sizeof(inner_digest),
					    outer_hex);

	/* SHA3-512 of the outer 128-char message — the digest ECDSA actually
	 * verifies against. */
	sha3_512_init(&hash_ctx);
	sha3_512_update(&hash_ctx, sizeof(outer_hex), (const guint8 *)outer_hex);
	sha3_512_digest(&hash_ctx, sizeof(final_digest), final_digest);

	if (!ecdsa_verify(&pub, sizeof(final_digest), final_digest, &sig)) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_AUTH_FAILED,
				    "trailer ECDSA signature did not verify against firmware");
		goto out;
	}
	ok = TRUE;

out:
	mpz_clears(x, y, NULL);
	ecc_point_clear(&pub);
	dsa_signature_clear(&sig);
	return ok;
}

GBytes *
fu_dell_monitor_rt_decrypt_payload(GBytes *ciphertext, GError **error)
{
	gsize ct_len = 0;
	const guint8 *ct;
	gsize encrypted_len;
	const guint8 *encrypted;
	const guint8 *received_mac;
	guint8 shared_x[FU_DELL_MONITOR_RT_FIELD_BYTES];
	guint8 expected_mac[FU_DELL_MONITOR_RT_SHA3_512_DIGEST];
	guint8 kdf_input[FU_DELL_MONITOR_RT_POINT_BYTES + FU_DELL_MONITOR_RT_FIELD_BYTES];
	g_autofree guint8 *derived_key = NULL;
	g_autofree guint8 *plaintext = NULL;
	g_autoptr(GBytes) gunzipped = NULL;

	g_return_val_if_fail(ciphertext != NULL, NULL);
	g_return_val_if_fail(error == NULL || *error == NULL, NULL);

	ct = g_bytes_get_data(ciphertext, &ct_len);
	if (ct_len <
	    FU_DELL_MONITOR_RT_POINT_BYTES + FU_DELL_MONITOR_RT_SHA3_512_DIGEST) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_DATA,
			    "ciphertext too short for ECIES envelope: %" G_GSIZE_FORMAT,
			    ct_len);
		return NULL;
	}
	encrypted = ct + FU_DELL_MONITOR_RT_POINT_BYTES;
	encrypted_len = ct_len - FU_DELL_MONITOR_RT_POINT_BYTES -
			FU_DELL_MONITOR_RT_SHA3_512_DIGEST;
	received_mac = encrypted + encrypted_len;

	/* (1) ECDH on secp521r1 → 66-byte X-coord shared secret. */
	if (!fu_dell_monitor_rt_ecies_compute_shared(ct, shared_x, error))
		return NULL;

	/* (2) KDF2-SHA3-512 input (DHAES_MODE): encoded ephemeral pubkey
	 * (the very 133 bytes from the ciphertext) followed by the
	 * shared secret X bytes. */
	memcpy(kdf_input, ct, FU_DELL_MONITOR_RT_POINT_BYTES);
	memcpy(kdf_input + FU_DELL_MONITOR_RT_POINT_BYTES,
	       shared_x,
	       FU_DELL_MONITOR_RT_FIELD_BYTES);

	/* (3) Derive K_mac(16) || K_xor(encrypted_len). */
	derived_key = g_malloc(FU_DELL_MONITOR_RT_HMAC_KEY_BYTES + encrypted_len);
	fu_dell_monitor_rt_kdf2_sha3_512(kdf_input,
					 sizeof(kdf_input),
					 derived_key,
					 FU_DELL_MONITOR_RT_HMAC_KEY_BYTES + encrypted_len);

	/* (4) Verify HMAC. CryptoPP's DL_EncryptionAlgorithm_Xor with
	 * DHAES_MODE=true and LABEL_OCTETS=false includes a trailing
	 * 8-byte big-endian zero (the bit-length of an empty label) in
	 * the MAC input. */
	{
		const guint8 label_octets[8] = {0};
		guint8 *mac_buf = g_malloc(encrypted_len + sizeof(label_octets));
		memcpy(mac_buf, encrypted, encrypted_len);
		memcpy(mac_buf + encrypted_len, label_octets, sizeof(label_octets));
		fu_dell_monitor_rt_hmac_sha3_512(derived_key,
						 FU_DELL_MONITOR_RT_HMAC_KEY_BYTES,
						 mac_buf,
						 encrypted_len + sizeof(label_octets),
						 expected_mac);
		g_free(mac_buf);
	}
	if (memcmp(expected_mac, received_mac, FU_DELL_MONITOR_RT_SHA3_512_DIGEST) != 0) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_AUTH_FAILED,
				    "ECIES MAC verification failed — payload tampered "
				    "or wrong private key");
		return NULL;
	}

	/* (5) XOR decrypt. */
	plaintext = g_malloc(encrypted_len);
	for (gsize i = 0; i < encrypted_len; i++)
		plaintext[i] =
		    encrypted[i] ^ derived_key[FU_DELL_MONITOR_RT_HMAC_KEY_BYTES + i];

	/* (6) Gunzip the XOR plaintext → ASCII hex stream → firmware||trailer. */
	gunzipped = fu_dell_monitor_rt_gunzip(plaintext, encrypted_len, error);
	if (gunzipped == NULL)
		return NULL;
	{
		gsize gz_len = 0;
		const guint8 *gz_data = g_bytes_get_data(gunzipped, &gz_len);
		g_autoptr(GBytes) firmware_with_trailer =
		    fu_dell_monitor_rt_hex_decode(gz_data, gz_len, error);
		gsize fwt_len = 0;
		const guint8 *fwt_data;
		if (firmware_with_trailer == NULL)
			return NULL;
		fwt_data = g_bytes_get_data(firmware_with_trailer, &fwt_len);
		if (fwt_len < FU_DELL_MONITOR_RT_TRAILER_LEN) {
			g_set_error(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_INVALID_DATA,
				    "decoded payload too short for trailer: %" G_GSIZE_FORMAT,
				    fwt_len);
			return NULL;
		}

		/* (7) Verify the trailer's ECDSA signature against the
		 * firmware bytes, then strip the trailer so consumers
		 * only see the firmware. */
		{
			gsize firmware_len = fwt_len - FU_DELL_MONITOR_RT_TRAILER_LEN;
			const guint8 *trailer = fwt_data + firmware_len;
			if (!fu_dell_monitor_rt_verify_trailer(fwt_data,
							       firmware_len,
							       trailer,
							       error))
				return NULL;
			return g_bytes_new(fwt_data, firmware_len);
		}
	}
}
