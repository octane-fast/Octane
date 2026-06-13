import { hmac } from '@noble/hashes/hmac';
import { sha512 } from '@noble/hashes/sha512';
import { sha256 } from '@noble/hashes/sha256';
import * as ed from '@noble/ed25519';
import { sha512 as sha512Hash } from '@noble/hashes/sha512';
import { generateMnemonic, mnemonicToSeedSync, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import type { Wallet } from './types';

// Configure noble/ed25519 to use sha512
ed.etc.sha512Sync = (...m: Uint8Array[]) => {
  const h = sha512Hash.create();
  for (const msg of m) h.update(msg);
  return h.digest();
};

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Encode(data: Uint8Array): string {
  let zeroes = 0;
  while (zeroes < data.length && data[zeroes] === 0) zeroes++;

  const buf = Array.from(data);
  const result: number[] = [];

  while (buf.length > 0) {
    let carry = 0;
    const next: number[] = [];
    for (let i = 0; i < buf.length; i++) {
      const val = carry * 256 + buf[i];
      const digit = Math.floor(val / 58);
      carry = val % 58;
      if (next.length > 0 || digit > 0) next.push(digit);
    }
    result.push(carry);
    buf.length = 0;
    buf.push(...next);
  }

  let str = '';
  for (let i = 0; i < zeroes; i++) str += '1';
  for (let i = result.length - 1; i >= 0; i--) str += BASE58_ALPHABET[result[i]];
  return str;
}

/**
 * Derive Octra HD seed from BIP39 master seed.
 * HD v2: HMAC-SHA512(key="Octra seed", data=masterSeed || index_le32), take first 32 bytes.
 * For index 0: HMAC-SHA512(key="Octra seed", data=masterSeed) directly.
 */
function deriveHdSeed(masterSeed: Uint8Array, index: number = 0): Uint8Array {
  const key = new TextEncoder().encode('Octra seed');
  if (index === 0) {
    const mac = hmac(sha512, key, masterSeed);
    return mac.slice(0, 32);
  }
  // index > 0: append index as little-endian u32
  const data = new Uint8Array(68);
  data.set(masterSeed, 0);
  data[64] = index & 0xff;
  data[65] = (index >> 8) & 0xff;
  data[66] = (index >> 16) & 0xff;
  data[67] = (index >> 24) & 0xff;
  const mac = hmac(sha512, key, data);
  return mac.slice(0, 32);
}

/**
 * Derive ed25519 keypair from 32-byte seed (NaCl-compatible).
 * Returns { publicKey (32), secretKey (64) }.
 */
function keypairFromSeed(seed: Uint8Array): { publicKey: Uint8Array; secretKey: Uint8Array } {
  const publicKey = ed.getPublicKey(seed);
  // ed25519 secret key = seed || publicKey (64 bytes, NaCl convention)
  const secretKey = new Uint8Array(64);
  secretKey.set(seed, 0);
  secretKey.set(publicKey, 32);
  return { publicKey, secretKey };
}

/**
 * Derive Octra address from public key: "oct" + base58(sha256(pubkey)) padded to 44 chars
 */
function deriveAddress(publicKey: Uint8Array): string {
  const hash = sha256(publicKey);
  let b58 = base58Encode(hash);
  while (b58.length < 44) b58 = '1' + b58;
  return 'oct' + b58;
}

/**
 * Create a new random 12-word mnemonic.
 */
export function createMnemonic(): string {
  return generateMnemonic(wordlist, 128);
}

/**
 * Validate a mnemonic phrase.
 */
export function isValidMnemonic(mnemonic: string): boolean {
  return validateMnemonic(mnemonic, wordlist);
}

/**
 * Derive a wallet from a mnemonic phrase at a given HD index.
 */
export function walletFromMnemonic(mnemonic: string, hdIndex: number = 0): Wallet {
  const masterSeed = mnemonicToSeedSync(mnemonic);
  const hdSeed = deriveHdSeed(masterSeed, hdIndex);
  const { publicKey, secretKey } = keypairFromSeed(hdSeed);
  const address = deriveAddress(publicKey);
  return { address, publicKey, secretKey };
}

/**
 * Sign a message with the wallet's secret key.
 */
export function sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
  const seed = secretKey.slice(0, 32);
  return ed.sign(message, seed);
}

/**
 * Encode bytes to base64.
 */
export function toBase64(data: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < data.length; i++) binary += String.fromCharCode(data[i]);
  return btoa(binary);
}

/**
 * Decode base64 to bytes.
 */
export function fromBase64(str: string): Uint8Array {
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
