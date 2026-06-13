/**
 * Key Vault — isolated seed oracle for the Octra wallet.
 *
 * This module is the ONLY place the mnemonic/seed exists in memory.
 * It operates as an oracle with two capabilities:
 *   - sign(message): produce an ed25519 signature (value-securing)
 *   - derive: produce PVAC privacy keys or X25519 stealth keys (NOT value-securing)
 *
 * The raw ed25519 seed NEVER leaves this module.
 */

import { walletFromMnemonic, sign as ed25519Sign, toBase64, fromBase64 } from './crypto';
import { initPvac, isInitialized, getPubkey, getSeckey, getAesKat } from './pvac';
import { edSkToX25519 } from './crypto/stealth';
import { decryptMnemonic } from './storage';

// --- Internal state (never exported) ---
let mnemonic: string | null = null;
let hdIndex: number = 0;
let lockTimeout: ReturnType<typeof setTimeout> | null = null;
const AUTO_LOCK_MS = 15 * 60 * 1000;

// Cached derived values (cleared on lock)
let cachedAddress: string | null = null;
let cachedPublicKey: Uint8Array | null = null;
let cachedPvacSkB64: string | null = null;
let cachedPvacPkB64: string | null = null;

function clearCache() {
  cachedAddress = null;
  cachedPublicKey = null;
  cachedPvacSkB64 = null;
  cachedPvacPkB64 = null;
}

function resetLockTimer() {
  if (lockTimeout) clearTimeout(lockTimeout);
  lockTimeout = setTimeout(lock, AUTO_LOCK_MS);
}

/** Internal: derive wallet from mnemonic. Result is used transiently. */
function deriveWallet() {
  if (!mnemonic) throw new Error('Wallet locked');
  resetLockTimer();
  return walletFromMnemonic(mnemonic, hdIndex);
}

// --- Public API ---

export function isUnlocked(): boolean {
  return mnemonic !== null;
}

/**
 * Unlock the vault by decrypting the encrypted mnemonic in-place.
 * The plaintext mnemonic never leaves this module.
 */
export async function unlock(encryptedSeed: string, password: string, index: number = 0): Promise<void> {
  const m = await decryptMnemonic(encryptedSeed, password);
  mnemonic = m;
  hdIndex = index;
  clearCache();
  resetLockTimer();
  // Load PVAC keys from persistent storage (no WASM — keys were derived at import/generation)
  derivePvacKeys().catch(() => { /* non-fatal */ });
}

export function lock(): void {
  mnemonic = null;
  hdIndex = 0;
  clearCache();
  if (lockTimeout) { clearTimeout(lockTimeout); lockTimeout = null; }
}

export function setHdIndex(index: number): void {
  hdIndex = index;
  clearCache();
}

export function getHdIndex(): number {
  return hdIndex;
}

/** Get the wallet address (public, not secret). */
export function getAddress(): string {
  if (cachedAddress) return cachedAddress;
  const { address } = deriveWallet();
  cachedAddress = address;
  return address;
}

/** Derive the address for an arbitrary HD index without changing vault state. */
export function getAddressForIndex(index: number): string {
  if (!mnemonic) throw new Error('Wallet locked');
  return walletFromMnemonic(mnemonic, index).address;
}

/** Get the ed25519 public key (public, not secret). */
export function getPublicKey(): Uint8Array {
  if (cachedPublicKey) return new Uint8Array(cachedPublicKey);
  const { publicKey } = deriveWallet();
  cachedPublicKey = publicKey;
  return new Uint8Array(publicKey);
}

/** Sign a message with the ed25519 key. Returns signature bytes. */
export function sign(message: Uint8Array): Uint8Array {
  const { secretKey } = deriveWallet();
  return ed25519Sign(message, secretKey);
}

/**
 * Load PVAC keys from persistent storage (chrome.storage.local).
 * Returns null if keys have not been derived yet for this HD index.
 * NEVER triggers WASM — if keys are missing, wallet is considered not ready.
 */
export async function derivePvacKeys(): Promise<{ skB64: string; pkB64: string } | null> {
  // 1. In-memory cache (fastest)
  if (cachedPvacSkB64 && cachedPvacPkB64) {
    return { skB64: cachedPvacSkB64, pkB64: cachedPvacPkB64 };
  }

  // 2. Persistent local storage (survives everything — the permanent store)
  try {
    const key = `pvacKeys_${hdIndex}`;
    const stored = await chrome.storage.local.get(key);
    if (stored[key]?.skB64 && stored[key]?.pkB64) {
      cachedPvacSkB64 = stored[key].skB64;
      cachedPvacPkB64 = stored[key].pkB64;
      return { skB64: cachedPvacSkB64!, pkB64: cachedPvacPkB64! };
    }
  } catch { /* storage unavailable */ }

  // Keys not found — wallet not fully set up for this account
  return null;
}

/**
 * Load PVAC keys or throw if not available.
 * Use this in operations that require PVAC keys (decrypt, prove, etc.)
 */
export async function requirePvacKeys(): Promise<{ skB64: string; pkB64: string }> {
  const keys = await derivePvacKeys();
  if (!keys) throw new Error('PVAC keys not available — wallet import required');
  return keys;
}

/**
 * Derive PVAC keys via WASM and persist permanently to chrome.storage.local.
 * This should ONLY be called during wallet import/generation or new account creation.
 * Shows a loading state in the UI while running.
 */
export async function generateAndPersistPvacKeys(): Promise<{ skB64: string; pkB64: string }> {
  const { secretKey } = deriveWallet();
  // Always re-init with current account's seed (WASM may hold a different account's state)
  await initPvac(secretKey.slice(0, 32));
  cachedPvacSkB64 = toBase64(getSeckey());
  cachedPvacPkB64 = toBase64(getPubkey());
  const aesKatB64 = toBase64(getAesKat());

  // Persist permanently to local storage keyed by HD index
  try {
    const key = `pvacKeys_${hdIndex}`;
    await chrome.storage.local.set({
      [key]: { skB64: cachedPvacSkB64, pkB64: cachedPvacPkB64, aesKatB64 },
    });
  } catch { /* non-fatal but should not happen */ }

  return { skB64: cachedPvacSkB64, pkB64: cachedPvacPkB64 };
}

/** Get PVAC public key bytes (for on-chain registration). */
export async function getPvacPubkeyBytes(): Promise<Uint8Array> {
  const keys = await derivePvacKeys();
  if (!keys) throw new Error('PVAC keys not derived — wallet setup incomplete');
  return fromBase64(keys.pkB64);
}

/** Get AES KAT (needed for PVAC registration). */
export async function getPvacAesKat(): Promise<Uint8Array> {
  // Read from persisted storage (no WASM needed)
  try {
    const key = `pvacKeys_${hdIndex}`;
    const stored = await chrome.storage.local.get(key);
    if (stored[key]?.aesKatB64) {
      return fromBase64(stored[key].aesKatB64);
    }
  } catch { /* fall through */ }
  // Fallback: if WASM happens to be live (e.g. right after generation)
  if (isInitialized()) return getAesKat();
  throw new Error('PVAC AES KAT not available — re-derive keys');
}

/**
 * Derive X25519 secret key for stealth ECDH.
 * This is a stealth-detection key, not a value-securing key.
 */
export function deriveX25519Sk(): Uint8Array {
  const { secretKey } = deriveWallet();
  return edSkToX25519(secretKey);
}
