/**
 * Stealth transaction cryptography for Octra.
 *
 * All cryptographic operations use:
 *   - @noble/curves (Cure53-audited, pure TS): X25519 ECDH, ed25519→X25519 key conversion
 *   - @noble/hashes (Cure53-audited, pure TS): SHA-256
 *   - Web Crypto API (crypto.subtle): AES-256-GCM encrypt/decrypt
 *
 * Zero custom crypto implementations. Every operation is a library/API call.
 *
 * Protocol (matches webcli stealth.hpp):
 *   1. Convert recipient's ed25519 pubkey → X25519 pubkey
 *   2. Generate ephemeral X25519 keypair
 *   3. ECDH: shared = X25519(ephSk, recipientX25519Pub)
 *   4. tag = SHA-256(shared || "stealth_tag")[0..16]
 *   5. claim_secret = SHA-256(shared || "stealth_claim")
 *   6. claim_pub = SHA-256(claim_secret || recipientAddr)
 *   7. Envelope: AES-256-GCM(key=shared, plaintext=amount[8]||blinding[32], nonce=random[12])
 *      Wire format: nonce[12] || ciphertext[40] || tag[16] = 68 bytes
 */

import { x25519, ed25519 } from '@noble/curves/ed25519.js';
import { sha256 as nobleSha256 } from '@noble/hashes/sha256';

// --- Key Conversion ---

/** Convert ed25519 secret key (64 bytes: seed||pub) to X25519 secret key (32 bytes). */
export function edSkToX25519(edSk: Uint8Array): Uint8Array {
  return ed25519.utils.toMontgomerySecret(edSk.slice(0, 32));
}

/** Convert ed25519 public key (32 bytes) to X25519 public key (32 bytes). */
export function edPubToX25519(edPub: Uint8Array): Uint8Array {
  return ed25519.utils.toMontgomery(edPub);
}

// --- X25519 ECDH ---

/** Compute X25519 shared secret: result = X25519(sk, pk). */
export function x25519SharedSecret(sk: Uint8Array, pk: Uint8Array): Uint8Array {
  return x25519.scalarMult(sk, pk);
}

/** Compute X25519 public key from secret key: result = sk * basepoint. */
export function x25519ScalarMultBase(sk: Uint8Array): Uint8Array {
  return x25519.scalarMultBase(sk);
}

// --- Hashing ---

/** SHA-256 hash. */
export function sha256(data: Uint8Array): Uint8Array {
  return nobleSha256(data);
}

// --- Stealth Protocol Derivations ---

/** Derive stealth tag: SHA-256(shared || "OCTRA_STEALTH_TAG_V1")[0..16]. */
export function computeStealthTag(shared: Uint8Array): Uint8Array {
  const domain = new TextEncoder().encode('OCTRA_STEALTH_TAG_V1');
  const input = new Uint8Array(shared.length + domain.length);
  input.set(shared, 0);
  input.set(domain, shared.length);
  return sha256(input).slice(0, 16);
}

/** Derive claim secret: SHA-256(shared || "OCTRA_CLAIM_SECRET_V1"). */
export function computeClaimSecret(shared: Uint8Array): Uint8Array {
  const domain = new TextEncoder().encode('OCTRA_CLAIM_SECRET_V1');
  const input = new Uint8Array(shared.length + domain.length);
  input.set(shared, 0);
  input.set(domain, shared.length);
  return sha256(input);
}

/** Derive claim public key: SHA-256(claimSecret || recipientAddr || "OCTRA_CLAIM_BIND_V1"). */
export function computeClaimPub(claimSecret: Uint8Array, recipientAddr: string): Uint8Array {
  const addrBytes = new TextEncoder().encode(recipientAddr);
  const domain = new TextEncoder().encode('OCTRA_CLAIM_BIND_V1');
  const input = new Uint8Array(claimSecret.length + addrBytes.length + domain.length);
  input.set(claimSecret, 0);
  input.set(addrBytes, claimSecret.length);
  input.set(domain, claimSecret.length + addrBytes.length);
  return sha256(input);
}

// --- AES-256-GCM (via Web Crypto API) ---

/**
 * Encrypt stealth amount envelope.
 * Plaintext: amount (8 bytes LE) || blinding (32 bytes) = 40 bytes.
 * Output: nonce[12] || ciphertext[40] || authTag[16] = 68 bytes.
 */
export async function encryptStealthAmount(
  shared: Uint8Array,
  amount: bigint,
  blinding: Uint8Array,
  nonce?: Uint8Array,
): Promise<Uint8Array> {
  const iv = nonce ?? crypto.getRandomValues(new Uint8Array(12));

  // Build plaintext: amount (8 bytes LE) || blinding (32 bytes)
  const plaintext = new Uint8Array(40);
  const view = new DataView(plaintext.buffer);
  view.setUint32(0, Number(amount & 0xFFFFFFFFn), true);
  view.setUint32(4, Number((amount >> 32n) & 0xFFFFFFFFn), true);
  plaintext.set(blinding, 8);

  // Import shared secret as AES-256-GCM key
  const key = await crypto.subtle.importKey('raw', shared, { name: 'AES-GCM' }, false, ['encrypt']);

  // Encrypt (Web Crypto returns ciphertext || tag concatenated)
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
  const encBytes = new Uint8Array(encrypted); // 40 + 16 = 56 bytes

  // Wire format: nonce[12] || ciphertext+tag[56] = 68 bytes
  const result = new Uint8Array(68);
  result.set(iv, 0);
  result.set(encBytes, 12);
  return result;
}

/**
 * Decrypt stealth amount envelope.
 * Input: nonce[12] || ciphertext[40] || authTag[16] = 68 bytes.
 * Returns: { amount, blinding } or null on failure.
 */
export async function decryptStealthAmount(
  shared: Uint8Array,
  envelope: Uint8Array,
): Promise<{ amount: bigint; blinding: Uint8Array } | null> {
  if (envelope.length !== 68) return null;

  const iv = envelope.slice(0, 12);
  const ciphertextAndTag = envelope.slice(12); // 56 bytes

  const key = await crypto.subtle.importKey('raw', shared, { name: 'AES-GCM' }, false, ['decrypt']);

  try {
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertextAndTag);
    const plain = new Uint8Array(decrypted);
    if (plain.length !== 40) return null;

    const view = new DataView(plain.buffer);
    const lo = view.getUint32(0, true);
    const hi = view.getUint32(4, true);
    const amount = BigInt(lo) | (BigInt(hi) << 32n);
    const blinding = plain.slice(8);

    return { amount, blinding };
  } catch {
    return null; // Auth tag mismatch
  }
}

// --- High-level API ---

/**
 * Prepare a stealth send: ECDH key exchange, tag, claim_pub, encrypted envelope.
 *
 * @param recipientEdPub - Recipient's ed25519 public key (32 bytes)
 * @param ephSk - Ephemeral X25519 secret key (32 bytes, pre-clamped)
 * @param amount - Amount to send (raw units)
 * @param blinding - Random blinding factor (32 bytes)
 * @param recipientAddr - Recipient address string (for claim_pub derivation)
 */
export async function prepareStealthSend(
  recipientEdPub: Uint8Array,
  ephSk: Uint8Array,
  amount: bigint,
  blinding: Uint8Array,
  recipientAddr: string,
): Promise<{
  ephPk: Uint8Array;
  shared: Uint8Array;
  tag: Uint8Array;
  claimPub: Uint8Array;
  encAmount: string;
}> {
  // 1. Convert recipient ed25519 pub → X25519
  const recipientX25519 = edPubToX25519(recipientEdPub);

  // 2. Compute ephemeral public key
  const ephPk = x25519ScalarMultBase(ephSk);

  // 3. ECDH shared secret
  const shared = x25519SharedSecret(ephSk, recipientX25519);

  // 4. Stealth tag
  const tag = computeStealthTag(shared);

  // 5. Claim pub
  const claimSecret = computeClaimSecret(shared);
  const claimPub = computeClaimPub(claimSecret, recipientAddr);

  // 6. Encrypt amount envelope
  const encRaw = await encryptStealthAmount(shared, amount, blinding);
  const encAmount = uint8ToBase64(encRaw);

  return { ephPk, shared, tag, claimPub, encAmount };
}

/**
 * Check if a stealth output belongs to us.
 * Returns the shared secret if tag matches (for decryption), or null.
 *
 * @param edSk - Our ed25519 secret key (64 bytes: seed||pub)
 * @param ephPub - Ephemeral public key from the output (32 bytes)
 * @param expectedTag - Stealth tag from the output (16 bytes)
 */
export function checkStealthOutput(
  edSk: Uint8Array,
  ephPub: Uint8Array,
  expectedTag: Uint8Array,
): Uint8Array | null {
  // Convert our ed25519 sk → X25519 sk
  const x25519Sk = edSkToX25519(edSk);

  // ECDH with ephemeral pub
  const shared = x25519SharedSecret(x25519Sk, ephPub);

  // Compute what the tag should be
  const computedTag = computeStealthTag(shared);

  // Constant-time compare (16 bytes)
  if (!timingSafeEqual(computedTag, expectedTag)) return null;

  return shared;
}

// --- Utilities ---

/** Hex encode bytes. */
export function hexEncode(data: Uint8Array): string {
  return Array.from(data).map(b => b.toString(16).padStart(2, '0')).join('');
}

/** Hex decode string to bytes. */
export function hexDecode(hex: string): Uint8Array {
  const result = new Uint8Array(hex.length / 2);
  for (let i = 0; i < result.length; i++) {
    result[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return result;
}

/** Base64 encode. */
function uint8ToBase64(data: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < data.length; i++) binary += String.fromCharCode(data[i]);
  return btoa(binary);
}

/** Constant-time comparison for equal-length byte arrays. */
function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
