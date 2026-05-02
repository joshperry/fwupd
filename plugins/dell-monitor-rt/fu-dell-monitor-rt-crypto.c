/*
 * Copyright 2026 Joshua Perry <josh@6bit.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "config.h"

#include <gnutls/crypto.h>

#include "fu-dell-monitor-rt-crypto.h"

/* Algorithm constants — fixed by Dell's choice of CryptoPP template
 * parameters (DefaultParametersInfo). */
#define FU_DELL_MONITOR_RT_SALT_LEN	  8
#define FU_DELL_MONITOR_RT_BLOCK_LEN	  16 /* AES block */
#define FU_DELL_MONITOR_RT_AES_KEY_LEN	  16 /* AES-128 */
#define FU_DELL_MONITOR_RT_DIGEST_LEN	  32 /* SHA-256 */
#define FU_DELL_MONITOR_RT_MAC_KEY_LEN	  16 /* CryptoPP MAC::StaticGetValidKeyLength(16) */
#define FU_DELL_MONITOR_RT_KDF_ITERATIONS 2500

/* CryptoPP's `Mash` KDF (see default.cpp).
 *
 * Mash(in, inLen, out, outLen, iterations) computes:
 *
 *   bufSize = round_up(outLen, DIGESTSIZE)
 *   for i in 0, 32, 64, … up to outLen:
 *     outBuf[i:i+32] = SHA256(b[0..1] || in)        # b = i as u16-BE
 *   for k in 1..iterations:
 *     buf = outBuf
 *     for i in 0, 32, 64, … up to bufSize:
 *       outBuf[i:i+32] = SHA256(b[0..1] || buf)
 *
 *   return outBuf[:outLen]
 *
 * For our specific uses both outLen values (32 and 16) fit in one
 * SHA-256 block (DIGESTSIZE = 32), so bufSize = 32 and the inner loops
 * only execute once per outer iteration. That simplifies to:
 *
 *   block = SHA256(b"\x00\x00" || in)        # initial pass
 *   repeat (iterations - 1) times:
 *     block = SHA256(b"\x00\x00" || block)
 *
 *   return block[:outLen]
 */
static gboolean
fu_dell_monitor_rt_mash_one_block(const guint8 *in,
				  gsize in_len,
				  guint iterations,
				  guint8 out_block[FU_DELL_MONITOR_RT_DIGEST_LEN],
				  GError **error)
{
	const guint8 b_prefix[2] = {0x00, 0x00};
	guint8 buf[FU_DELL_MONITOR_RT_DIGEST_LEN];
	gnutls_hash_hd_t hash = NULL;
	int rc;

	if (iterations < 1) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_INVALID_DATA,
				    "Mash requires iterations >= 1");
		return FALSE;
	}

	/* initial pass: H(b || in) */
	rc = gnutls_hash_init(&hash, GNUTLS_DIG_SHA256);
	if (rc != GNUTLS_E_SUCCESS) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INTERNAL,
			    "gnutls_hash_init failed: %s",
			    gnutls_strerror(rc));
		return FALSE;
	}
	gnutls_hash(hash, b_prefix, sizeof(b_prefix));
	gnutls_hash(hash, in, in_len);
	gnutls_hash_output(hash, buf);

	/* (iterations - 1) more passes: H(b || buf) → buf */
	for (guint k = 1; k < iterations; k++) {
		gnutls_hash(hash, b_prefix, sizeof(b_prefix));
		gnutls_hash(hash, buf, sizeof(buf));
		gnutls_hash_output(hash, buf);
	}

	gnutls_hash_deinit(hash, NULL);
	memcpy(out_block, buf, FU_DELL_MONITOR_RT_DIGEST_LEN);
	return TRUE;
}

/* Decode a Base64URL-encoded GBytes payload into raw binary. GLib's
 * g_base64_decode handles the standard alphabet only, so we translate
 * Base64URL's `-_` into `+/` and pad to a multiple of 4 first. */
static GBytes *
fu_dell_monitor_rt_base64url_decode(GBytes *b64url, GError **error)
{
	gsize n_in = 0;
	const gchar *in = g_bytes_get_data(b64url, &n_in);
	gsize padded_len;
	gsize n_out = 0;
	g_autofree gchar *padded = NULL;
	g_autofree guint8 *raw = NULL;

	/* Round up to a multiple of 4 (with `=` padding). */
	padded_len = ((n_in + 3) / 4) * 4;
	padded = g_malloc0(padded_len + 1);
	for (gsize i = 0; i < n_in; i++) {
		gchar c = in[i];
		if (c == '-')
			c = '+';
		else if (c == '_')
			c = '/';
		padded[i] = c;
	}
	for (gsize i = n_in; i < padded_len; i++)
		padded[i] = '=';

	raw = g_base64_decode(padded, &n_out);
	if (raw == NULL || n_out == 0) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_INVALID_DATA,
				    "base64url decode produced no output");
		return NULL;
	}
	return g_bytes_new_take(g_steal_pointer(&raw), n_out);
}

/* AES-128-CBC decrypt the supplied buffer in place. Caller is responsible
 * for `cipherbuf` being a multiple of 16 bytes. */
static gboolean
fu_dell_monitor_rt_aes128_cbc_decrypt(const guint8 *key,
				      const guint8 *iv,
				      guint8 *cipherbuf,
				      gsize cipherbuf_len,
				      GError **error)
{
	gnutls_cipher_hd_t cipher = NULL;
	gnutls_datum_t key_datum = {(guint8 *)key, FU_DELL_MONITOR_RT_AES_KEY_LEN};
	gnutls_datum_t iv_datum = {(guint8 *)iv, FU_DELL_MONITOR_RT_BLOCK_LEN};
	int rc;

	if (cipherbuf_len % FU_DELL_MONITOR_RT_BLOCK_LEN != 0) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_DATA,
			    "AES-CBC ciphertext length %" G_GSIZE_FORMAT
			    " is not a multiple of 16",
			    cipherbuf_len);
		return FALSE;
	}
	rc = gnutls_cipher_init(&cipher, GNUTLS_CIPHER_AES_128_CBC, &key_datum, &iv_datum);
	if (rc != GNUTLS_E_SUCCESS) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INTERNAL,
			    "gnutls_cipher_init failed: %s",
			    gnutls_strerror(rc));
		return FALSE;
	}
	rc = gnutls_cipher_decrypt(cipher, cipherbuf, cipherbuf_len);
	gnutls_cipher_deinit(cipher);
	if (rc != GNUTLS_E_SUCCESS) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INTERNAL,
			    "gnutls_cipher_decrypt failed: %s",
			    gnutls_strerror(rc));
		return FALSE;
	}
	return TRUE;
}

GBytes *
fu_dell_monitor_rt_decrypt_metadata_field(const gchar *passphrase,
					  GBytes *ciphertext_b64url,
					  GError **error)
{
	gsize passphrase_len;
	gsize raw_len;
	const guint8 *raw;
	const guint8 *salt;
	guint8 *aes_block_region; /* keyCheck || plaintext || MAC, after AES-CBC decrypt */
	gsize aes_block_region_len;
	gsize plaintext_len;
	const guint8 *plaintext_start;
	const guint8 *mac_received;
	guint8 padding_byte;
	guint8 expected_keycheck[FU_DELL_MONITOR_RT_DIGEST_LEN];
	guint8 expected_mac[FU_DELL_MONITOR_RT_DIGEST_LEN];
	guint8 mash_buf[FU_DELL_MONITOR_RT_DIGEST_LEN];
	guint8 aes_key[FU_DELL_MONITOR_RT_AES_KEY_LEN];
	guint8 aes_iv[FU_DELL_MONITOR_RT_BLOCK_LEN];
	guint8 mac_key[FU_DELL_MONITOR_RT_MAC_KEY_LEN];
	gnutls_hash_hd_t hash = NULL;
	gnutls_hmac_hd_t hmac = NULL;
	g_autoptr(GBytes) raw_blob = NULL;
	g_autofree guint8 *kdf_input = NULL;
	g_autofree guint8 *aes_workbuf = NULL;
	int rc;

	g_return_val_if_fail(passphrase != NULL, NULL);
	g_return_val_if_fail(ciphertext_b64url != NULL, NULL);
	g_return_val_if_fail(error == NULL || *error == NULL, NULL);

	passphrase_len = strlen(passphrase);

	/* base64url-decode the on-disk ciphertext. */
	raw_blob = fu_dell_monitor_rt_base64url_decode(ciphertext_b64url, error);
	if (raw_blob == NULL)
		return NULL;
	raw = g_bytes_get_data(raw_blob, &raw_len);

	/* Layout: salt(8) || AES-CBC(keyCheck(16) || plaintext || MAC(32)),
	 * with PKCS#7 padding inside the AES region. So the minimum legal
	 * size is salt(8) + one AES block(16) = 24 bytes, but the keyCheck
	 * alone is 16 bytes plus a 32-byte MAC = 48 bytes pre-padding,
	 * which rounds to 64 bytes inside AES. Total minimum:
	 * 8 + 64 = 72 bytes. We require >= 56 (the bare minimum that keeps
	 * each region nonzero) and let downstream checks catch malformed
	 * payloads. */
	if (raw_len < FU_DELL_MONITOR_RT_SALT_LEN + 4 * FU_DELL_MONITOR_RT_BLOCK_LEN) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_DATA,
			    "ciphertext too short: %" G_GSIZE_FORMAT " bytes",
			    raw_len);
		return NULL;
	}
	if ((raw_len - FU_DELL_MONITOR_RT_SALT_LEN) % FU_DELL_MONITOR_RT_BLOCK_LEN != 0) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_DATA,
			    "AES region length %" G_GSIZE_FORMAT " is not a multiple of 16",
			    raw_len - FU_DELL_MONITOR_RT_SALT_LEN);
		return NULL;
	}
	salt = raw;
	aes_block_region_len = raw_len - FU_DELL_MONITOR_RT_SALT_LEN;
	aes_workbuf = g_memdup2(raw + FU_DELL_MONITOR_RT_SALT_LEN, aes_block_region_len);
	aes_block_region = aes_workbuf;

	/* Derive the AES key + IV: Mash<SHA256>(passphrase || salt, 32, 2500),
	 * split into key(16) || IV(16). */
	kdf_input = g_malloc(passphrase_len + FU_DELL_MONITOR_RT_SALT_LEN);
	memcpy(kdf_input, passphrase, passphrase_len);
	memcpy(kdf_input + passphrase_len, salt, FU_DELL_MONITOR_RT_SALT_LEN);
	if (!fu_dell_monitor_rt_mash_one_block(kdf_input,
					       passphrase_len + FU_DELL_MONITOR_RT_SALT_LEN,
					       FU_DELL_MONITOR_RT_KDF_ITERATIONS,
					       mash_buf,
					       error))
		return NULL;
	memcpy(aes_key, mash_buf, FU_DELL_MONITOR_RT_AES_KEY_LEN);
	memcpy(aes_iv,
	       mash_buf + FU_DELL_MONITOR_RT_AES_KEY_LEN,
	       FU_DELL_MONITOR_RT_BLOCK_LEN);

	/* Decrypt AES region in place. */
	if (!fu_dell_monitor_rt_aes128_cbc_decrypt(aes_key,
						   aes_iv,
						   aes_block_region,
						   aes_block_region_len,
						   error))
		return NULL;

	/* Strip PKCS#7 padding. */
	padding_byte = aes_block_region[aes_block_region_len - 1];
	if (padding_byte == 0 || padding_byte > FU_DELL_MONITOR_RT_BLOCK_LEN ||
	    padding_byte > aes_block_region_len) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_DATA,
			    "invalid PKCS#7 padding byte 0x%02x",
			    padding_byte);
		return NULL;
	}
	for (guint i = 1; i <= padding_byte; i++) {
		if (aes_block_region[aes_block_region_len - i] != padding_byte) {
			g_set_error_literal(error,
					    FWUPD_ERROR,
					    FWUPD_ERROR_AUTH_FAILED,
					    "PKCS#7 padding bytes mismatch — wrong passphrase?");
			return NULL;
		}
	}
	aes_block_region_len -= padding_byte;

	/* After unpadding the layout is: keyCheck(16) || plaintext(P) || MAC(32). */
	if (aes_block_region_len < FU_DELL_MONITOR_RT_BLOCK_LEN + FU_DELL_MONITOR_RT_DIGEST_LEN) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INVALID_DATA,
			    "decrypted region too short for keyCheck+MAC: %" G_GSIZE_FORMAT,
			    aes_block_region_len);
		return NULL;
	}
	plaintext_start = aes_block_region + FU_DELL_MONITOR_RT_BLOCK_LEN;
	plaintext_len = aes_block_region_len - FU_DELL_MONITOR_RT_BLOCK_LEN -
			FU_DELL_MONITOR_RT_DIGEST_LEN;
	mac_received = plaintext_start + plaintext_len;

	/* Verify keyCheck = SHA256(passphrase || salt)[:16]. */
	rc = gnutls_hash_init(&hash, GNUTLS_DIG_SHA256);
	if (rc != GNUTLS_E_SUCCESS) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INTERNAL,
			    "gnutls_hash_init failed: %s",
			    gnutls_strerror(rc));
		return NULL;
	}
	gnutls_hash(hash, passphrase, passphrase_len);
	gnutls_hash(hash, salt, FU_DELL_MONITOR_RT_SALT_LEN);
	gnutls_hash_deinit(hash, expected_keycheck);
	hash = NULL;
	if (memcmp(expected_keycheck, aes_block_region, FU_DELL_MONITOR_RT_BLOCK_LEN) != 0) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_AUTH_FAILED,
				    "keyCheck mismatch — wrong passphrase");
		return NULL;
	}

	/* Compute MAC_key = Mash<SHA256>(passphrase, 16, 1) which simplifies
	 * to SHA256("\x00\x00" || passphrase)[:16] (1 iteration, no mixing
	 * loop). */
	if (!fu_dell_monitor_rt_mash_one_block((const guint8 *)passphrase,
					       passphrase_len,
					       1,
					       mash_buf,
					       error))
		return NULL;
	memcpy(mac_key, mash_buf, FU_DELL_MONITOR_RT_MAC_KEY_LEN);

	/* Compute and verify HMAC-SHA256(MAC_key, plaintext). */
	rc = gnutls_hmac_init(&hmac,
			      GNUTLS_MAC_SHA256,
			      mac_key,
			      FU_DELL_MONITOR_RT_MAC_KEY_LEN);
	if (rc != GNUTLS_E_SUCCESS) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INTERNAL,
			    "gnutls_hmac_init failed: %s",
			    gnutls_strerror(rc));
		return NULL;
	}
	gnutls_hmac(hmac, plaintext_start, plaintext_len);
	gnutls_hmac_deinit(hmac, expected_mac);
	if (memcmp(expected_mac, mac_received, FU_DELL_MONITOR_RT_DIGEST_LEN) != 0) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_AUTH_FAILED,
				    "HMAC verification failed — ciphertext tampered or "
				    "wrong passphrase");
		return NULL;
	}

	/* Detach plaintext into its own GBytes (we own aes_workbuf). */
	{
		guint8 *out = g_memdup2(plaintext_start, plaintext_len);
		return g_bytes_new_take(out, plaintext_len);
	}
}

gchar *
fu_dell_monitor_rt_decrypt_metadata_field_as_string(const gchar *passphrase,
						    GBytes *ciphertext_b64url,
						    GError **error)
{
	g_autoptr(GBytes) plaintext = NULL;
	gsize plaintext_len = 0;
	const gchar *plaintext_data;

	plaintext = fu_dell_monitor_rt_decrypt_metadata_field(passphrase,
							      ciphertext_b64url,
							      error);
	if (plaintext == NULL)
		return NULL;
	plaintext_data = g_bytes_get_data(plaintext, &plaintext_len);
	if (!g_utf8_validate(plaintext_data, plaintext_len, NULL)) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_INVALID_DATA,
				    "decrypted metadata is not valid UTF-8");
		return NULL;
	}
	return g_strndup(plaintext_data, plaintext_len);
}
