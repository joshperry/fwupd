/*
 * Copyright 2026 Joshua Perry <josh@6bit.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#pragma once

#include <fwupdplugin.h>

/* Decrypt a Dell .upg binary firmware payload (ECIES + Gunzip + HexDecode).
 *
 * `ciphertext` is the on-disk bytes of one binary entry from the .upg
 * (the value paired with its component key). The pipeline is:
 *
 *   1. Read 1+66+66 SEC1-uncompressed ephemeral pubkey Q from ct[0..133)
 *   2. Compute shared secret X = x-coord(d * Q) on secp521r1, where d is
 *      the static private scalar Wistron embeds in every libhub.so.
 *   3. Derive 16+|encrypted| key bytes via P1363_KDF2-SHA3-512 over the
 *      input `Q_encoded || X_bytes` (DHAES_MODE).
 *   4. Verify HMAC-SHA3-512(K_mac, encrypted) against ct[end-64..end).
 *   5. plaintext = encrypted XOR K_xor.
 *   6. Gunzip plaintext, hex-decode the result.
 *
 * On success returns just the firmware bytes — the 222-byte signature
 * trailer (132-byte raw ECDSA-secp521r1-with-SHA3_512 signature followed
 * by a 90-byte DER SubjectPublicKeyInfo carrying the signing pubkey)
 * is verified internally and stripped before returning. Returns NULL
 * + GError on any integrity-check failure.
 *
 * NOTE on the trust model: the trailer signature is self-attestation
 * only. The signing pubkey ships *inside* the encrypted envelope, the
 * ECIES private key is shipped in every libhub.so so anyone can
 * decrypt-then-re-encrypt, and we've confirmed the per-bundle signing
 * pubkey varies bundle-to-bundle (different pubkey in U4025QW vs
 * U3224KB, distinct in both directions) AND no SPKI / pubkey / hash
 * of either pubkey appears anywhere in the shipped Firmware Updater,
 * libhub.so, libdevices.so, or any other plugin .so. Dell's own
 * Certify::c does no further key check after Certify::v returns —
 * it just copies the firmware out. So there's no Wistron/Dell root
 * key we can anchor to, and the trailer signature is useful only for
 * catching accidental corruption + post-decrypt tamper, not for
 * proving authorship.
 *
 * Real chain-of-trust for fwupd users comes from LVFS's cabinet
 * signature (the .cab carrying this .upg is GPG-signed by LVFS via
 * Jcat) and is verified by libfwupd before the plugin ever sees the
 * firmware bytes. That's the layer to rely on for authenticity.
 */
GBytes *
fu_dell_monitor_rt_decrypt_payload(GBytes *ciphertext, GError **error);
