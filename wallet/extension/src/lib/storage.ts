/**
 * Encrypted storage layer using chrome.storage.local.
 * Wallet secrets are encrypted with a user-provided password (AES-GCM).
 */

const STORAGE_KEY = 'octra_wallet_state';

interface Account {
  name: string;
  hdIndex: number;
  address: string;
}

interface StoredState {
  encryptedSeed: string; // base64 AES-GCM ciphertext of mnemonic
  accounts: Account[];
  activeIndex: number; // which account is active (index into accounts[])
}

async function deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

export async function encryptMnemonic(mnemonic: string, password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const enc = new TextEncoder();
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(mnemonic));
  // Format: salt(16) || iv(12) || ciphertext
  const combined = new Uint8Array(16 + 12 + ciphertext.byteLength);
  combined.set(salt, 0);
  combined.set(iv, 16);
  combined.set(new Uint8Array(ciphertext), 28);
  return btoa(String.fromCharCode(...combined));
}

export async function decryptMnemonic(encryptedB64: string, password: string): Promise<string> {
  const combined = Uint8Array.from(atob(encryptedB64), c => c.charCodeAt(0));
  const salt = combined.slice(0, 16);
  const iv = combined.slice(16, 28);
  const ciphertext = combined.slice(28);
  const key = await deriveKey(password, salt);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return new TextDecoder().decode(plaintext);
}

export async function saveWallet(state: StoredState): Promise<void> {
  await chrome.storage.local.set({ [STORAGE_KEY]: state });
}

export async function loadWallet(): Promise<StoredState | null> {
  const data = await chrome.storage.local.get(STORAGE_KEY);
  const raw = data[STORAGE_KEY];
  if (!raw) return null;
  return raw as StoredState;
}

export async function clearWallet(): Promise<void> {
  await chrome.storage.local.remove(STORAGE_KEY);
}

export async function hasWallet(): Promise<boolean> {
  const state = await loadWallet();
  return state !== null;
}

export type { StoredState, Account };
