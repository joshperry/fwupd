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
 * On success returns the final firmware blob plus a 222-byte signature
 * trailer (132-byte raw ECDSA-secp521r1-with-SHA3_512 signature followed
 * by a 90-byte SubjectPublicKeyInfo containing the signing pubkey).
 * Callers that want only the firmware bytes should slice off the
 * trailer themselves once we wire signature verification in. Returns
 * NULL + GError on any integrity-check failure.
 *
 * TODO: verify the trailing ECDSA-secp521r1-with-SHA3_512 signature
 *       against the firmware bytes using the trailer's embedded signing
 *       pubkey. Catches accidental corruption + post-decrypt tamper.
 *       (~80 lines: parse the 90-byte DER SubjectPublicKeyInfo, ECDSA
 *        verify with nettle's ecdsa_verify on the secp521r1 curve.)
 *
 * TODO: extract the *root* signing pubkey from libhub.so so we can verify
 *       the trailer pubkey itself, giving a real chain of trust rather
 *       than the in-envelope self-attestation we'd get from the TODO
 *       above alone. The root pubkey ships in `.rodata` next to
 *       CK_PV_RawData; spelunk for the corresponding SubjectPublicKeyInfo
 *       prefix (ASN.1 wrapper for compressed secp521r1 SPKI).
 */
GBytes *
fu_dell_monitor_rt_decrypt_payload(GBytes *ciphertext, GError **error);
