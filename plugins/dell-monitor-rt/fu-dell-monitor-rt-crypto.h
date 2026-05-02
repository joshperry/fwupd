/*
 * Copyright 2026 Joshua Perry <josh@6bit.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#pragma once

#include <fwupdplugin.h>

/* Decrypt a Wistron@<MODEL>-encrypted Base64URL metadata field.
 *
 * `passphrase` is the literal C string the Dell updater uses, e.g.
 * "Wistron@U4025QW". `ciphertext_b64url` is the on-disk bytes of one
 * length-prefixed field from the .upg metadata section (Base64URL-encoded
 * ciphertext, NOT yet base64-decoded). `out_string_with_nul` controls
 * whether the returned plaintext is NUL-terminated (it always is from
 * Dell's encoder, but callers handling raw binary may want to drop it).
 *
 * Returns a freshly-allocated GBytes on success. The encryption matches
 * CryptoPP's `DataDecryptorWithMAC<Rijndael, SHA256, HMAC<SHA256>,
 * DataParametersInfo<16, 16, 32, 8, 2500>>`:
 *
 *   ciphertext_blob = base64url_decode(ciphertext_b64url)
 *                   = salt(8) || AES-CBC(keyCheck(16) || plaintext(P) || MAC(32))
 *
 *   AES_key || IV   = Mash<SHA256>(passphrase || salt, 32, 2500)
 *   MAC_key         = Mash<SHA256>(passphrase, 16, 1)   = SHA256("\x00\x00" || passphrase)[:16]
 *   keyCheck_check  = SHA256(passphrase || salt)[:16]
 *   MAC             = HMAC-SHA256(MAC_key, plaintext)
 *
 * `Mash` is CryptoPP's iterated-SHA256 KDF (see default.cpp). The function
 * performs all three integrity checks (keyCheck round-trip, AES padding,
 * MAC) before returning plaintext.
 */
GBytes *
fu_dell_monitor_rt_decrypt_metadata_field(const gchar *passphrase,
					  GBytes *ciphertext_b64url,
					  GError **error);

/* Convenience: decrypt and decode as a UTF-8 string (which is what every
 * field we have actually is). Returns NULL + error on integrity failure
 * OR on the result not being valid UTF-8. */
gchar *
fu_dell_monitor_rt_decrypt_metadata_field_as_string(const gchar *passphrase,
						    GBytes *ciphertext_b64url,
						    GError **error);
