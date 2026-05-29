// Service worker polyfill: Vite's dynamic import error handler references `window`
// which doesn't exist in service workers. Alias it to `self` (the SW global scope).
declare const self: typeof globalThis;
(globalThis as any).window = self;

import { toBase64, fromBase64 } from '../lib/crypto';
import { loadWallet, saveWallet } from '../lib/storage';
import type { StoredState } from '../lib/storage';
import * as rpc from '../lib/rpc';
import {
  isInitialized, initPvacFromKeys, encryptValue, decryptValue,
  pedersenCommit, makeZeroProofBound, makeRangeProof, ctSub, commitCt,
} from '../lib/pvac';
import {
  prepareStealthSend, checkStealthOutput, decryptStealthAmount, computeClaimSecret, hexEncode,
} from '../lib/stealth';
import { x25519SharedSecret } from '../lib/crypto/stealth';
import { sha256 } from '@noble/hashes/sha256';
import * as vault from '../lib/keyVault';

// Feature flags
const FEATURE_TOR = true;

// Tor proxy management (gated behind FEATURE_TOR)
const TOR_SOCKS_PORT = 9150;

async function enableTorProxy() {
  if (!FEATURE_TOR) return;
  const config = {
    mode: 'pac_script',
    pacScript: {
      data: `function FindProxyForURL(url, host) {
        if (host === "octra.network") {
          return "SOCKS5 127.0.0.1:${TOR_SOCKS_PORT}";
        }
        return "DIRECT";
      }`,
    },
  };
  await chrome.proxy.settings.set({ value: config, scope: 'regular' });
}

async function disableTorProxy() {
  if (!FEATURE_TOR) return;
  await chrome.proxy.settings.clear({ scope: 'regular' });
}

// Restore Tor state on service worker startup
if (FEATURE_TOR) {
  chrome.storage.local.get('torEnabled').then(({ torEnabled }) => {
    if (torEnabled) enableTorProxy();
  });
}

// Check for pending unshield jobs on SW startup (crypto may have finished while SW was dead)
chrome.storage.local.get(null).then((all) => {
  const keysToRemove: string[] = [];
  for (const key of Object.keys(all)) {
    if (!key.startsWith('job_')) continue;

    // Clean up terminal job states (done/error/cancelled) and their satellites
    if (!key.includes('_crypto') && !key.includes('_params') && !key.includes('_stealth') && !key.includes('_claim')) {
      const job = all[key];
      const jobId = key.replace('job_', '');
      if (job.status === 'done' || job.status === 'error' || job.status === 'cancelled') {
        keysToRemove.push(key, `job_${jobId}_crypto`, `job_${jobId}_params`, `job_${jobId}_stealth`, `job_${jobId}_stealth_params`, `job_${jobId}_claim`);
      } else if (job.status === 'crypto_done' || job.status === 'pending_unlock') {
        resumeUnshieldSubmission(jobId);
      } else if (job.status === 'running') {
        // SW may have died mid-submission; resume if crypto result exists
        if (all[`job_${jobId}_crypto`]) {
          resumeUnshieldSubmission(jobId);
        } else {
          // Stale running job with no crypto — mark as error
          keysToRemove.push(key, `job_${jobId}_params`);
        }
      }
    }
  }
  if (keysToRemove.length > 0) {
    // Filter to only keys that actually exist
    const existing = keysToRemove.filter(k => k in all);
    if (existing.length > 0) chrome.storage.local.remove(existing);
  }
});

/** Mark a job as done and schedule cleanup of all related keys after 30s */
function completeJob(storageKey: string, jobId: string, hash: string) {
  chrome.storage.local.set({ [storageKey]: { status: 'done', hash } });
  setTimeout(() => {
    chrome.storage.local.remove([
      storageKey, `job_${jobId}_crypto`, `job_${jobId}_params`,
      `job_${jobId}_stealth`, `job_${jobId}_stealth_params`, `job_${jobId}_claim`,
    ]);
  }, 30000);
}

// Private balance cache — skip decryption if the on-chain cipher hasn't changed
let cachedPrivateBalance: string | null = null;
let cachedCipherStr: string | null = null;

/**
 * Ensure the PVAC public key is registered on-chain for the current wallet.
 */
async function ensurePvacRegistered(): Promise<void> {
  const address = vault.getAddress();
  const existing = await rpc.getPvacPubkey(address);
  if (existing) return;

  const pvacPk = await vault.getPvacPubkeyBytes();
  const aesKat = await vault.getPvacAesKat();

  const pkHash = hexEncode(sha256(pvacPk));
  const msg = `register_pvac|${address}|${pkHash}`;
  const sig = vault.sign(new TextEncoder().encode(msg));

  await rpc.registerPvacPubkey(
    address,
    toBase64(pvacPk),
    toBase64(sig),
    toBase64(vault.getPublicKey()),
    hexEncode(aesKat),
  );
}

/**
 * Ensure the ed25519 public key is registered on-chain for the current wallet.
 */
async function ensurePublicKeyRegistered(): Promise<void> {
  const address = vault.getAddress();
  const existing = await rpc.getPublicKey(address);
  if (existing.public_key) return;

  const msg = `register_pubkey:${address}`;
  const sig = vault.sign(new TextEncoder().encode(msg));

  await rpc.registerPublicKey(address, toBase64(vault.getPublicKey()), toBase64(sig));
  console.log('[wallet] public key registered for', address);
}

// --- Unlock prompt for dApp requests ---
const unlockWaiters: Array<(unlocked: boolean) => void> = [];

function notifyUnlockWaiters() {
  while (unlockWaiters.length) unlockWaiters.pop()!(true);
}

async function ensureUnlocked(): Promise<boolean> {
  if (vault.isUnlocked()) return true;
  // Open popup so user can enter password
  const popupUrl = chrome.runtime.getURL('dist/src/popup/index.html?unlock=dapp');
  const win = await chrome.windows.create({
    url: popupUrl,
    type: 'popup',
    width: 380,
    height: 540,
    focused: true,
  });
  // Wait up to 2 minutes for unlock
  return new Promise<boolean>((resolve) => {
    const wrappedResolve = (unlocked: boolean) => {
      // Close the popup after unlock
      if (win?.id) chrome.windows.remove(win.id).catch(() => {});
      resolve(unlocked);
    };
    unlockWaiters.push(wrappedResolve);
    setTimeout(() => {
      const idx = unlockWaiters.indexOf(wrappedResolve);
      if (idx >= 0) {
        unlockWaiters.splice(idx, 1);
        if (win?.id) chrome.windows.remove(win.id).catch(() => {});
        resolve(false);
      }
    }, 120_000);
  });
}

// --- dApp approval popup infrastructure ---
interface PendingApprovalEntry {
  resolve: (approved: boolean) => void;
}
const pendingApprovals = new Map<string, PendingApprovalEntry>();

async function requestUserApproval(
  type: 'connect' | 'sign_message' | 'send_transaction' | 'call_contract' | 'pvac_decrypt' | 'pvac_prove',
  origin: string,
  data: Record<string, unknown>,
): Promise<boolean> {
  const id = crypto.randomUUID();
  const storageKey = `approval_${id}`;
  await chrome.storage.local.set({ [storageKey]: { id, type, origin, data } });

  const confirmUrl = chrome.runtime.getURL(`dist/src/popup/confirm.html?id=${id}`);
  chrome.windows.create({
    url: confirmUrl,
    type: 'popup',
    width: 400,
    height: 420,
    focused: true,
  });

  return new Promise<boolean>((resolve) => {
    pendingApprovals.set(id, { resolve });
    // Auto-reject after 2 minutes if no response
    setTimeout(() => {
      if (pendingApprovals.has(id)) {
        pendingApprovals.delete(id);
        chrome.storage.local.remove(storageKey);
        resolve(false);
      }
    }, 120_000);
  });
}

// Track approved origins to skip repeat confirmations for connect
const approvedOrigins = new Set<string>();

type MessageHandler = (
  message: Record<string, unknown>,
  sender: chrome.runtime.MessageSender,
  sendResponse: (response: unknown) => void,
) => boolean | void;

const handler: MessageHandler = (message, _sender, sendResponse) => {
  // Ignore messages targeted at other contexts
  if ((message as any).target && (message as any).target !== 'background') return;
  const { type, payload } = message as { type: string; payload: Record<string, unknown> };

  (async () => {
    try {
      switch (type) {
        case 'APPROVAL_RESPONSE': {
          const { id: approvalId, approved } = payload as { id: string; approved: boolean };
          const entry = pendingApprovals.get(approvalId);
          if (entry) {
            pendingApprovals.delete(approvalId);
            chrome.storage.local.remove(`approval_${approvalId}`);
            entry.resolve(approved);
          }
          sendResponse({ ok: true });
          break;
        }
        case 'UNLOCK': {
          const { encryptedSeed, password, hdIndex } = payload as { encryptedSeed: string; password: string; hdIndex?: number };
          await vault.unlock(encryptedSeed, password, hdIndex ?? 0);
          sendResponse({ success: true });
          // Notify any dApp requests waiting for unlock
          notifyUnlockWaiters();
          // Auto-register public key on-chain (fire-and-forget)
          ensurePublicKeyRegistered().catch(e => console.warn('[wallet] pubkey registration failed:', e.message));
          // Load PVAC keys from persistent storage and init offscreen
          vault.derivePvacKeys().then(async (keys) => {
            if (!keys) {
              // Skip expensive WASM derivation if account has no funds (can't register anyway)
              const bal = await rpc.getBalance(vault.getAddress()).catch(() => null);
              if (!bal || bal.raw === '0') {
                console.log('[pvac] skipping WASM derivation — account has no funds');
                return;
              }
              // Migration: wallet imported before persistent PVAC storage — derive once
              console.log('[pvac] keys not in local storage, running one-time WASM derivation');
              keys = await vault.generateAndPersistPvacKeys();
            }
            ensureOffscreen().then(() => {
              if (offscreenPort) {
                offscreenPort.postMessage({ action: 'init', pvacSkB64: keys!.skB64, pvacPkB64: keys!.pkB64, keyId: vault.getAddress() });
              }
            }).catch(() => {});
            // Register PVAC pubkey on-chain if not already
            ensurePvacRegistered().catch(e => console.warn('[pvac] registration failed:', e.message));
          }).catch((e) => { console.warn('[pvac] key load/derive failed:', e); });
          // Resume any pending_unlock jobs now that wallet is unlocked
          chrome.storage.local.get(null).then((all) => {
            for (const key of Object.keys(all)) {
              if (key.startsWith('job_') && !key.includes('_crypto') && !key.includes('_params')) {
                const job = all[key];
                if (job.status === 'pending_unlock') {
                  const jobId = key.replace('job_', '');
                  resumeUnshieldSubmission(jobId);
                }
              }
            }
          });
          break;
        }
        case 'LOCK': {
          vault.lock();
          cachedPrivateBalance = null;
          cachedCipherStr = null;
          sendResponse({ success: true });
          break;
        }
        case 'SET_TOR': {
          const { enabled } = payload as { enabled: boolean };
          if (enabled) {
            // Check if Tor proxy is reachable before enabling
            try {
              const ctrl = new AbortController();
              const timer = setTimeout(() => ctrl.abort(), 3000);
              try {
                await fetch(`http://127.0.0.1:${TOR_SOCKS_PORT}/`, {
                  method: 'GET',
                  signal: ctrl.signal,
                });
              } catch (e: any) {
                // AbortError means timeout = nothing listening
                if (e.name === 'AbortError') {
                  throw new Error('Tor proxy not reachable');
                }
                // Any other error (Failed to fetch, connection reset, etc.)
                // means the port IS open — SOCKS proxies reject HTTP requests
              }
              clearTimeout(timer);
              await enableTorProxy();
              sendResponse({ success: true });
            } catch {
              sendResponse({ error: 'Tor proxy not reachable at 127.0.0.1:' + TOR_SOCKS_PORT });
            }
          } else {
            await disableTorProxy();
            sendResponse({ success: true });
          }
          break;
        }
        case 'SET_RPC_URL': {
          const { url } = payload as { url: string };
          rpc.setRpcUrl(url);
          await chrome.storage.local.set({ rpcUrl: url });
          sendResponse({ success: true, rpcUrl: url });
          break;
        }
        case 'GET_RPC_URL': {
          sendResponse({ rpcUrl: rpc.getRpcUrl() });
          break;
        }
        case 'IS_UNLOCKED': {
          sendResponse({ unlocked: vault.isUnlocked() });
          break;
        }
        case 'SWITCH_ACCOUNT': {
          const { hdIndex } = payload as { hdIndex: number };
          vault.setHdIndex(hdIndex);
          cachedPrivateBalance = null;
          cachedCipherStr = null;
          sendResponse({ address: vault.getAddress() });
          ensurePublicKeyRegistered().catch(e => console.warn('[wallet] pubkey registration failed:', e.message));
          // Load PVAC keys for this account and init offscreen
          vault.derivePvacKeys().then(async (keys) => {
            if (!keys) {
              // Skip expensive WASM derivation if account has no funds
              const bal = await rpc.getBalance(vault.getAddress()).catch(() => null);
              if (!bal || bal.raw === '0') {
                console.log('[pvac] skipping WASM derivation — account has no funds');
                return;
              }
              keys = await vault.generateAndPersistPvacKeys();
            }
            ensureOffscreen().then(() => {
              if (offscreenPort) {
                offscreenPort.postMessage({ action: 'init', pvacSkB64: keys!.skB64, pvacPkB64: keys!.pkB64, keyId: vault.getAddress() });
              }
            }).catch(() => {});
            ensurePvacRegistered().catch(e => console.warn('[pvac] registration failed:', e.message));
          }).catch(() => {});
          break;
        }
        case 'GET_ACCOUNTS': {
          if (!vault.isUnlocked()) { sendResponse({ error: 'locked' }); break; }
          const state = await loadWallet();
          if (!state) { sendResponse({ error: 'no wallet' }); break; }
          const currentIdx = vault.getHdIndex();
          const accounts = state.accounts.map(acc => {
            vault.setHdIndex(acc.hdIndex);
            return { name: acc.name, hdIndex: acc.hdIndex, address: vault.getAddress() };
          });
          vault.setHdIndex(currentIdx);
          sendResponse({ accounts, activeHdIndex: currentIdx });
          break;
        }
        case 'ADD_ACCOUNT': {
          if (!vault.isUnlocked()) { sendResponse({ error: 'locked' }); break; }
          const { name, hdIndex } = payload as { name: string; hdIndex: number };
          const currentIdx2 = vault.getHdIndex();
          vault.setHdIndex(hdIndex);
          const newAddr = vault.getAddress();
          vault.setHdIndex(currentIdx2);
          sendResponse({ address: newAddr, name, hdIndex });
          break;
        }
        case 'GET_ADDRESS': {
          if (!vault.isUnlocked()) { sendResponse({ error: 'locked' }); break; }
          sendResponse({ address: vault.getAddress() });
          break;
        }
        case 'CHECK_STEALTH_READY': {
          if (!vault.isUnlocked()) { sendResponse({ ready: false, reason: 'locked' }); break; }
          try {
            const addr = vault.getAddress();
            const [pk, pvac, bal] = await Promise.all([
              rpc.getPublicKey(addr),
              rpc.getPvacPubkey(addr),
              rpc.getBalance(addr).catch(() => null),
            ]);
            if (pk.public_key && pvac) {
              sendResponse({ ready: true });
            } else if (!bal || bal.raw === '0') {
              sendResponse({ ready: false, reason: 'no_funds' });
            } else {
              sendResponse({ ready: false, reason: 'registering' });
            }
          } catch { sendResponse({ ready: false, reason: 'error' }); }
          break;
        }
        case 'DERIVE_PVAC_KEYS': {
          if (!vault.isUnlocked()) { sendResponse({ error: 'locked' }); break; }
          try {
            const keys = await vault.generateAndPersistPvacKeys();
            // Init offscreen with the newly derived keys
            ensureOffscreen().then(() => {
              if (offscreenPort) {
                offscreenPort.postMessage({ action: 'init', pvacSkB64: keys.skB64, pvacPkB64: keys.pkB64, keyId: vault.getAddress() });
              }
            }).catch(() => {});
            sendResponse({ success: true });
          } catch (e: any) {
            sendResponse({ error: e.message || 'PVAC derivation failed' });
          }
          break;
        }
        case 'GET_BALANCE': {
          if (!vault.isUnlocked()) { sendResponse({ error: 'locked' }); break; }
          const balance = await rpc.getBalance(vault.getAddress());
          sendResponse(balance);
          break;
        }
        case 'GET_TOKENS': {
          if (!vault.isUnlocked()) { sendResponse({ error: 'locked' }); break; }
          const tokens = await rpc.getTokensByAddress(vault.getAddress());
          sendResponse({ tokens });
          break;
        }
        case 'GET_ENCRYPTED_BALANCE': {
          if (!vault.isUnlocked()) { sendResponse({ error: 'locked' }); break; }
          const msg = new TextEncoder().encode(`octra_encryptedBalance|${vault.getAddress()}`);
          const ebSigRaw = vault.sign(msg);
          const result = await rpc.getEncryptedBalance(vault.getAddress(), toBase64(ebSigRaw), toBase64(vault.getPublicKey()));
          sendResponse({ encryptedBalance: result });
          break;
        }
        case 'GET_DECRYPTED_BALANCE': {
          if (!vault.isUnlocked()) { sendResponse({ error: 'locked' }); break; }
          try {
            const address = vault.getAddress();
            // Fetch encrypted balance from chain
            const ebMsg = new TextEncoder().encode(`octra_encryptedBalance|${address}`);
            const ebSig = vault.sign(ebMsg);
            const ebResult = await rpc.getEncryptedBalance(address, toBase64(ebSig), toBase64(vault.getPublicKey())) as Record<string, unknown>;
            const cipherStr = String(ebResult?.cipher ?? '');
            console.log('[pvac-decrypt] address=%s cipher_len=%d has_pvac=%s', address, cipherStr.length, ebResult?.has_pvac_pubkey);
            if (!cipherStr || cipherStr === '0') {
              console.log('[pvac-decrypt] no cipher, returning 0');
              cachedPrivateBalance = '0';
              cachedCipherStr = cipherStr;
              sendResponse({ balance: '0' }); break;
            }

            // If cipher hasn't changed, return cached decrypted value (skip expensive decrypt)
            if (cipherStr === cachedCipherStr && cachedPrivateBalance !== null) {
              console.log('[pvac-decrypt] cipher unchanged, returning cached=%s', cachedPrivateBalance);
              sendResponse({ balance: cachedPrivateBalance });
              break;
            }

            // Strip "hfhe_v1|" prefix
            const cipherB64 = cipherStr.startsWith('hfhe_v1|') ? cipherStr.slice(8) : cipherStr;
            console.log('[pvac-decrypt] cipher_b64_len=%d prefix=%s', cipherB64.length, cipherStr.slice(0, 8));

            // Try native prover first (uses cached PVAC keys — no raw seed exposed)
            let rawValue: bigint | null = null;
            const proverUp = await isProverAvailable();
            console.log('[pvac-decrypt] prover_available=%s', proverUp);
            if (proverUp) {
              try {
                const { skB64: pvacSkB64, pkB64: pvacPkB64 } = await vault.requirePvacKeys();
                const ctrl = new AbortController();
                const timer = setTimeout(() => ctrl.abort(), 3000);
                const res = await fetch(`${PROVER_URL}/decrypt`, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ pvac_sk_b64: pvacSkB64, pvac_pk_b64: pvacPkB64, cipher_b64: cipherB64 }),
                  signal: ctrl.signal,
                });
                clearTimeout(timer);
                const data = await res.json() as { value?: number; error?: string };
                console.log('[pvac-decrypt] native prover response: value=%s error=%s', data.value, data.error);
                if (data.value !== undefined) rawValue = BigInt(data.value);
              } catch (e) {
                console.warn('[pvac-decrypt] native prover failed:', (e as Error).message);
              }
            }

            // Try remote prover via relay (needs PVAC keys)
            if (rawValue === null) {
              const remoteConfig = await isRemoteProverConfigured();
              if (remoteConfig) {
                console.log('[pvac-decrypt] trying remote prover via relay');
                try {
                  const { skB64: pvacSkB64, pkB64: pvacPkB64 } = await vault.requirePvacKeys();
                  const result = await runRemoteProver('decrypt_bal', {
                    operation: 'decrypt',
                    pvac_sk_b64: pvacSkB64,
                    pvac_pk_b64: pvacPkB64,
                    cipher_b64: cipherB64,
                  }, remoteConfig);
                  if (result.value !== undefined) {
                    console.log('[pvac-decrypt] remote prover response: value=%s', result.value);
                    rawValue = BigInt(result.value);
                  }
                } catch (e) {
                  console.warn('[pvac-decrypt] remote prover failed:', (e as Error).message);
                }
              }
            }

            // Fallback: offscreen WASM worker (needs PVAC keys)
            if (rawValue === null) {
              console.log('[pvac-decrypt] falling back to WASM offscreen');
              try {
                const { skB64: pvacSkB64, pkB64: pvacPkB64 } = await vault.requirePvacKeys();
                await ensureOffscreen();
                const decResult = await chrome.runtime.sendMessage({ target: 'offscreen', action: 'decrypt', pvacSkB64, pvacPkB64, keyId: vault.getAddress(), cipherB64 }) as { value?: string; error?: string };
                console.log('[pvac-decrypt] WASM result: value=%s error=%s', decResult.value, decResult.error);
                if (decResult.error) { sendResponse({ error: decResult.error }); break; }
                rawValue = BigInt(decResult.value ?? '0');
              } catch (e) {
                console.warn('[pvac-decrypt] WASM fallback failed:', (e as Error).message);
                sendResponse({ error: 'Decryption failed — install Octane Accelerator for reliable decryption' });
                break;
              }
            }

            console.log('[pvac-decrypt] rawValue=%s (micro-units)', rawValue.toString());

            // Convert raw to human-readable (1 OCT = 1000000 raw)
            const whole = rawValue / 1000000n;
            const frac = rawValue % 1000000n;
            const balStr = frac === 0n ? `${whole}` : `${whole}.${String(frac).padStart(6, '0').replace(/0+$/, '')}`;
            console.log('[pvac-decrypt] final balance=%s', balStr);
            cachedPrivateBalance = balStr;
            cachedCipherStr = cipherStr;
            sendResponse({ balance: balStr });
          } catch (err) {
            console.error('[pvac-decrypt] error:', (err as Error).message);
            // If we have a cached value, return it on error instead of failing
            if (cachedPrivateBalance !== null) {
              sendResponse({ balance: cachedPrivateBalance });
            } else {
              sendResponse({ error: (err as Error).message });
            }
          }
          break;
        }
        case 'ENCRYPT_BALANCE': {
          if (!vault.isUnlocked()) { sendResponse({ error: 'locked' }); break; }
          const { amount } = payload as { amount: string };
          try {
            // Parse amount to raw units (1 OCT = 1000000 raw)
            let amountRaw: bigint;
            if (amount.includes('.')) {
              const [intPart, fracPart] = amount.split('.');
              const frac = (fracPart + '000000').slice(0, 6);
              amountRaw = BigInt(intPart) * 1000000n + BigInt(frac);
            } else {
              amountRaw = BigInt(amount) * 1000000n;
            }
            if (amountRaw <= 0n) { sendResponse({ error: 'invalid amount' }); break; }

            // Create job and respond immediately
            const jobId = crypto.randomUUID();
            const storageKey = `job_${jobId}`;
            await chrome.storage.local.set({ [storageKey]: { status: 'running', step: 'Registering PVAC key...' } });
            sendResponse({ jobId });

            // Ensure PVAC pubkey is registered on-chain
            try {
              await ensurePvacRegistered();
            } catch (regErr) {
              await chrome.storage.local.set({ [storageKey]: { status: 'error', error: (regErr as Error).message } });
              break;
            }

            // Try native prover first
            const proverAvailable = await isProverAvailable();
            if (proverAvailable) {
              await chrome.storage.local.set({ [storageKey]: { status: 'running', step: 'Proving ⚡ Desktop', prover: 'local' } });
              const seed = crypto.getRandomValues(new Uint8Array(32));
              const blinding = crypto.getRandomValues(new Uint8Array(32));
              let shieldResult: Record<string, string> | null = null;
              try {
                shieldResult = await runNativeProver(jobId, {
                  operation: 'shield',
                  secretKeyB64: 'vault', // placeholder — sanitizeProverPayload will replace with PVAC keys
                  amountRaw: String(amountRaw),
                  seedB64: toBase64(seed),
                  blindingB64: toBase64(blinding),
                });
              } catch {
                // Fall through to WASM
                await chrome.storage.local.set({ [storageKey]: { status: 'running', step: 'Prover unavailable, falling back...' } });
              }
              if (shieldResult) {
                const encData = JSON.stringify({
                  cipher: shieldResult.cipher,
                  amount_commitment: shieldResult.amount_commitment,
                  zero_proof: shieldResult.zero_proof,
                  blinding: shieldResult.blinding,
                });
                await chrome.storage.local.set({ [storageKey]: { status: 'running', step: 'Submitting transaction...' } });
                submitEncryptJob(jobId, amountRaw, encData);
                break;
              }
            }

            // Fallback: in-process WASM — must init WASM from stored keys
            const { skB64: fallbackSk, pkB64: fallbackPk } = await vault.requirePvacKeys();
            if (!isInitialized()) {
              await initPvacFromKeys(fromBase64(fallbackSk), fromBase64(fallbackPk));
            }

            const seed = crypto.getRandomValues(new Uint8Array(32));
            const blinding = crypto.getRandomValues(new Uint8Array(32));

            // FHE encrypt
            const cipherBytes = encryptValue(amountRaw, seed);
            const cipherStr2 = 'hfhe_v1|' + toBase64(cipherBytes);

            // Pedersen commitment
            const commitBytes = pedersenCommit(amountRaw, blinding);
            const commitB64 = toBase64(commitBytes);

            // Zero proof (bound)
            const zpBytes = makeZeroProofBound(cipherBytes, amountRaw, blinding);
            const zpStr = 'zkzp_v2|' + toBase64(zpBytes);

            // Build encrypted_data JSON
            const encData = JSON.stringify({
              cipher: cipherStr2,
              amount_commitment: commitB64,
              zero_proof: zpStr,
              blinding: toBase64(blinding),
            });

            await chrome.storage.local.set({ [storageKey]: { status: 'running', step: 'Submitting transaction...' } });
            submitEncryptJob(jobId, amountRaw, encData);
          } catch (err) {
            sendResponse({ error: (err as Error).message });
          }
          break;
        }
        case 'DECRYPT_BALANCE': {
          if (!vault.isUnlocked()) { sendResponse({ error: 'locked' }); break; }
          const { amount: decAmt } = payload as { amount: string };

          // Validate upfront, then kick off async job
          let decAmountRaw: bigint;
          try {
            if (decAmt.includes('.')) {
              const [intPart, fracPart] = decAmt.split('.');
              const frac = (fracPart + '000000').slice(0, 6);
              decAmountRaw = BigInt(intPart) * 1000000n + BigInt(frac);
            } else {
              decAmountRaw = BigInt(decAmt) * 1000000n;
            }
            if (decAmountRaw <= 0n) { sendResponse({ error: 'invalid amount' }); break; }
          } catch { sendResponse({ error: 'invalid amount' }); break; }

          // Generate job ID and respond immediately so popup can close
          const jobId = crypto.randomUUID();
          await chrome.storage.local.set({ [`job_${jobId}`]: { status: 'running', step: 'Registering PVAC key...', startedAt: Date.now() } });
          sendResponse({ jobId });

          // Ensure PVAC pubkey is registered on-chain
          try {
            await ensurePvacRegistered();
          } catch (err) {
            await chrome.storage.local.set({ [`job_${jobId}`]: { status: 'error', error: (err as Error).message } });
            break;
          }

          // Run the heavy computation in the background
          runUnshieldJob(jobId, decAmountRaw);
          break;
        }
        case 'GET_JOB_STATUS': {
          const { jobId } = payload as { jobId: string };
          const data = await chrome.storage.local.get(`job_${jobId}`);
          sendResponse(data[`job_${jobId}`] ?? { status: 'unknown' });
          break;
        }
        case 'CANCEL_UNSHIELD':
        case 'CANCEL_JOB': {
          const { jobId } = payload as { jobId: string };
          const storageKey = `job_${jobId}`;
          await chrome.storage.local.set({ [storageKey]: { status: 'cancelled' } });
          await chrome.storage.local.remove([`${storageKey}_crypto`, `${storageKey}_params`, `job_${jobId}_stealth`, `job_${jobId}_stealth_params`, 'activeUnshieldJob', 'activeUnshieldStart', 'activeShieldJob', 'activeShieldStart', 'activeStealthJob', 'activeStealthStart']);
          currentJobStorageKey = null;
          sendResponse({ success: true });
          break;
        }
        case 'SIGN_MESSAGE': {
          if (!vault.isUnlocked()) { sendResponse({ error: 'locked' }); break; }
          const msgBytes = new TextEncoder().encode(payload.message as string);
          const signature = vault.sign(msgBytes);
          sendResponse({ signature: toBase64(signature) });
          break;
        }
        case 'SEND_TRANSACTION': {
          if (!vault.isUnlocked()) { sendResponse({ error: 'locked' }); break; }
          const { to, amount, fee } = payload as { to: string; amount: string; fee?: string };
          const address = vault.getAddress();
          const balInfo = await rpc.getBalance(address);
          const nonce = balInfo.nonce + 1;
          // Convert human-readable amount to raw (1 OCT = 1000000 raw)
          let amountRaw: string;
          if (amount.includes('.')) {
            const [intPart, fracPart] = amount.split('.');
            const frac = (fracPart + '000000').slice(0, 6);
            amountRaw = String(BigInt(intPart) * BigInt(1000000) + BigInt(frac));
          } else {
            amountRaw = String(BigInt(amount) * BigInt(1000000));
          }
          const ou = fee ?? '10000';
          const timestamp = Math.floor(Date.now() / 1000);
          // Format timestamp as float string (e.g. "1779113687.0")
          const tsStr = Number.isInteger(timestamp) ? timestamp + '.0' : String(timestamp);
          // Build canonical JSON for signing
          const canonical = `{"from":"${address}","to_":"${to}","amount":"${amountRaw}","nonce":${nonce},"ou":"${ou}","timestamp":${tsStr},"op_type":"standard"}`;
          const txMsg = new TextEncoder().encode(canonical);
          const txSig = vault.sign(txMsg);
          const tx = {
            from: address,
            to_: to,
            amount: amountRaw,
            nonce,
            ou,
            timestamp,
            op_type: 'standard',
            signature: toBase64(txSig),
            public_key: toBase64(vault.getPublicKey()),
          };
          const result = await rpc.submitTransaction(tx);
          sendResponse(result);
          break;
        }
        case 'CONTRACT_CALL': {
          if (!vault.isUnlocked()) { sendResponse({ error: 'locked' }); break; }
          const { contract, method, params } = payload as { contract: string; method: string; params: unknown[] };
          const result = await rpc.contractCall(contract, method, params ?? [], vault.getAddress());
          sendResponse(result);
          break;
        }
        case 'SWAP_OCTUSD': {
          if (!vault.isUnlocked()) { sendResponse({ error: 'locked' }); break; }
          const { direction, amount } = payload as { direction: 'buy' | 'sell'; amount: string };
          try {
            const OCTUSD_ADDR = 'oct2hJMZbBdAAKTBXK61vs1TUx8oQNZVZyEpR4SXGFXgtvE';
            const balInfo = await rpc.getBalance(vault.getAddress());
            const nonce = balInfo.nonce + 1;
            const ou = '200000';
            const timestamp = Math.floor(Date.now() / 1000);
            const tsStr = timestamp + '.0';

            let amountRaw: string;
            let methodName: string;
            let message: string;

            if (direction === 'buy') {
              // mint: send OCT (payable), method has no params
              if (amount.includes('.')) {
                const [intPart, fracPart] = amount.split('.');
                const frac = (fracPart + '000000').slice(0, 6);
                amountRaw = String(BigInt(intPart) * 1000000n + BigInt(frac));
              } else {
                amountRaw = String(BigInt(amount) * 1000000n);
              }
              methodName = 'mint';
              message = '[]';
            } else {
              // redeem: no OCT sent, pass octUSD amount (raw) as param
              amountRaw = '0';
              let redeemRaw: string;
              if (amount.includes('.')) {
                const [intPart, fracPart] = amount.split('.');
                const frac = (fracPart + '000000').slice(0, 6);
                redeemRaw = String(BigInt(intPart) * 1000000n + BigInt(frac));
              } else {
                redeemRaw = String(BigInt(amount) * 1000000n);
              }
              methodName = 'redeem';
              message = JSON.stringify([Number(redeemRaw)]);
            }

            // Escape for canonical JSON
            const msgEscaped = message.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
            const swapAddr = vault.getAddress();
            const canonical = `{"from":"${swapAddr}","to_":"${OCTUSD_ADDR}","amount":"${amountRaw}","nonce":${nonce},"ou":"${ou}","timestamp":${tsStr},"op_type":"call","encrypted_data":"${methodName}","message":"${msgEscaped}"}`;
            const txMsg = new TextEncoder().encode(canonical);
            const txSig = vault.sign(txMsg);
            const tx = {
              from: swapAddr,
              to_: OCTUSD_ADDR,
              amount: amountRaw,
              nonce,
              ou,
              timestamp,
              op_type: 'call',
              encrypted_data: methodName,
              message,
              signature: toBase64(txSig),
              public_key: toBase64(vault.getPublicKey()),
            };
            const result = await rpc.submitTransaction(tx);
            sendResponse(result);
          } catch (err) {
            sendResponse({ error: (err as Error).message ?? 'swap failed' });
          }
          break;
        }
        case 'GET_ACTIVITY': {
          if (!vault.isUnlocked()) { sendResponse({ error: 'locked' }); break; }
          const history = await rpc.getAccountHistory(vault.getAddress(), 10);
          const txDetails = await Promise.all(
            history.recentTxs.map(async (t) => {
              try {
                const detail = await rpc.getTransaction(t.hash);
                return detail;
              } catch { return null; }
            })
          );
          sendResponse({ transactions: txDetails.filter(Boolean) });
          break;
        }
        case 'DAPP_REQUEST': {
          const { method: dappMethod, params: dappParams, origin: dappOrigin } =
            payload as { method: string; params: unknown[]; origin: string };

          switch (dappMethod) {
            case 'octra_requestAccounts':
            case 'requestAccounts': {
              let freshlyUnlocked = false;
              if (!vault.isUnlocked()) {
                const unlocked = await ensureUnlocked();
                if (!unlocked) { sendResponse({ error: 'Wallet is locked' }); break; }
                freshlyUnlocked = true;
              }
              // If user just unlocked, auto-approve since they showed intent
              // Otherwise show approval popup for first-time connections
              if (!approvedOrigins.has(dappOrigin)) {
                if (!freshlyUnlocked) {
                  const approved = await requestUserApproval('connect', dappOrigin, {});
                  if (!approved) { sendResponse({ error: 'User rejected connection' }); break; }
                }
                approvedOrigins.add(dappOrigin);
              }
              sendResponse([vault.getAddress()]);
              break;
            }
            case 'octra_getBalance':
            case 'octra_getEncryptedBalance':
            case 'getBalance':
            case 'get_balance': {
              if (!vault.isUnlocked()) {
                const unlocked = await ensureUnlocked();
                if (!unlocked) { sendResponse({ error: 'Wallet is locked' }); break; }
              }
              const balRes = await rpc.getBalance(vault.getAddress());
              sendResponse({
                public: parseFloat(balRes.formatted),
                private: 0,
                total: parseFloat(balRes.formatted),
                currency: 'OCT',
              });
              break;
            }
            case 'octra_getNetworkInfo':
            case 'octra_networkInfo':
            case 'getNetworkInfo':
            case 'get_network_info': {
              sendResponse({
                id: 'mainnet',
                name: 'Octra Mainnet',
                rpcUrl: 'https://octra.network/rpc',
                explorerUrl: 'https://octrascan.io',
                supportsPrivacy: true,
                isTestnet: false,
                color: '#6366f1',
              });
              break;
            }
            case 'octra_permissions':
            case 'permissions': {
              sendResponse(['read_balance', 'send_transactions', 'sign_messages']);
              break;
            }
            case 'octra_accounts':
            case 'accounts': {
              if (!vault.isUnlocked() || !approvedOrigins.has(dappOrigin)) {
                sendResponse([]);
              } else {
                sendResponse([vault.getAddress()]);
              }
              break;
            }
            case 'octra_getPublicKey':
            case 'getPublicKey': {
              if (!vault.isUnlocked()) {
                const unlocked = await ensureUnlocked();
                if (!unlocked) { sendResponse({ error: 'Wallet is locked' }); break; }
              }
              sendResponse(toBase64(vault.getPublicKey()));
              break;
            }
            case 'octra_signMessage':
            case 'signMessage':
            case 'sign_message': {
              if (!vault.isUnlocked()) {
                const unlocked = await ensureUnlocked();
                if (!unlocked) { sendResponse({ error: 'Wallet is locked' }); break; }
              }
              const rawParam = (dappParams as unknown[])[0];
              const message = typeof rawParam === 'string' ? rawParam : (rawParam as any)?.message;
              if (!message || typeof message !== 'string') {
                sendResponse({ error: 'Invalid message' });
                break;
              }
              const approved = await requestUserApproval('sign_message', dappOrigin, { message });
              if (!approved) { sendResponse({ error: 'User rejected signature request' }); break; }
              const msgBytes = new TextEncoder().encode(message);
              const sig = vault.sign(msgBytes);
              sendResponse(toBase64(sig));
              break;
            }
            case 'octra_sendTransaction':
            case 'sendTransaction':
            case 'send_transaction': {
              if (!vault.isUnlocked()) {
                const unlocked = await ensureUnlocked();
                if (!unlocked) { sendResponse({ error: 'Wallet is locked' }); break; }
              }
              const [txData] = dappParams as [{ to: string; amount: number; message?: string }];
              if (!txData?.to || txData.amount == null) {
                sendResponse({ error: 'Invalid transaction data' });
                break;
              }
              const txApproved = await requestUserApproval('send_transaction', dappOrigin, {
                to: txData.to,
                amount: txData.amount,
                message: txData.message,
              });
              if (!txApproved) { sendResponse({ error: 'User rejected transaction' }); break; }
              const amountRaw = String(Math.round(txData.amount * 1_000_000));
              const dappAddr = vault.getAddress();
              const balInfo = await rpc.getBalance(dappAddr);
              const nonce = balInfo.nonce + 1;
              const ts = Math.floor(Date.now() / 1000);
              const tsStr = ts + '.0';
              const canonical = `{"from":"${dappAddr}","to_":"${txData.to}","amount":"${amountRaw}","nonce":${nonce},"ou":"1000","timestamp":${tsStr},"op_type":"standard"}`;
              const txSig = vault.sign(new TextEncoder().encode(canonical));
              const txPayload = {
                from: dappAddr,
                to_: txData.to,
                amount: amountRaw,
                nonce,
                ou: '1000',
                timestamp: ts,
                op_type: 'standard',
                ...(txData.message ? { message: txData.message } : {}),
                signature: toBase64(txSig),
                public_key: toBase64(vault.getPublicKey()),
              };
              const submitRes = await rpc.submitTransaction(txPayload);
              sendResponse({ txHash: submitRes.hash, success: true });
              break;
            }
            case 'octra_callContract':
            case 'callContract':
            case 'call_contract': {
              if (!vault.isUnlocked()) {
                const unlocked = await ensureUnlocked();
                if (!unlocked) { sendResponse({ error: 'Wallet is locked' }); break; }
              }
              const [callData] = dappParams as [{ contract: string; method: string; params: unknown[]; amount?: string; ou?: string }];
              if (!callData?.contract || !callData?.method) {
                sendResponse({ error: 'Invalid contract call data' });
                break;
              }
              const callApproved = await requestUserApproval('call_contract', dappOrigin, {
                contract: callData.contract,
                method: callData.method,
                params: callData.params,
                amount: callData.amount,
              });
              if (!callApproved) { sendResponse({ error: 'User rejected contract call' }); break; }
              const amt = callData.amount || '0';
              const ou = callData.ou || '10000';
              const callAddr = vault.getAddress();
              const balInfo2 = await rpc.getBalance(callAddr);
              const nonce2 = balInfo2.nonce + 1;
              const ts2 = Math.floor(Date.now() / 1000);
              const tsStr2 = ts2 + '.0';
              const msgField = JSON.stringify(callData.params ?? []);
              const escMsg = msgField.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
              const canonical2 = `{"from":"${callAddr}","to_":"${callData.contract}","amount":"${amt}","nonce":${nonce2},"ou":"${ou}","timestamp":${tsStr2},"op_type":"call","encrypted_data":"${callData.method}","message":"${escMsg}"}`;
              const sig2 = vault.sign(new TextEncoder().encode(canonical2));
              const callPayload = {
                from: callAddr,
                to_: callData.contract,
                amount: amt,
                nonce: nonce2,
                ou,
                timestamp: ts2,
                op_type: 'call',
                encrypted_data: callData.method,
                message: msgField,
                signature: toBase64(sig2),
                public_key: toBase64(vault.getPublicKey()),
              };
              const callRes = await rpc.submitTransaction(callPayload);
              sendResponse({ txHash: callRes.hash, success: true });
              break;
            }
            case 'octra_contractCallView':
            case 'contractCallView':
            case 'contract_call_view':
            case 'octra_contract_call_view': {
              const [viewData] = dappParams as [{ contract: string; method: string; params: unknown[]; caller?: string }];
              if (!viewData?.contract || !viewData?.method) {
                sendResponse({ error: 'Invalid view call data' });
                break;
              }
              const caller = viewData.caller || (vault.isUnlocked() ? vault.getAddress() : '');
              const viewRes = await rpc.rpcCall('contract_call', [viewData.contract, viewData.method, viewData.params ?? [], caller]);
              sendResponse(viewRes);
              break;
            }
            default: {
              // --- PVAC / FHE proof methods for dApps ---
              // Helper: run a PVAC operation through desktop prover → relay → WASM fallback
              async function runPvacOp(
                operation: string,
                extra: Record<string, string>,
                wasmFallback: () => Promise<Record<string, unknown>>,
              ): Promise<Record<string, unknown>> {
                const { skB64, pkB64 } = await vault.requirePvacKeys();
                const payload: Record<string, string> = { operation, pvac_sk_b64: skB64, pvac_pk_b64: pkB64, ...extra };

                // 1) Try native desktop prover
                const proverUp = await isProverAvailable();
                if (proverUp) {
                  try {
                    const result = await runNativeProver(`dapp_${operation}_${Date.now()}`, payload);
                    return result;
                  } catch (e) {
                    console.warn(`[dapp-pvac] native prover failed for ${operation}:`, (e as Error).message);
                  }
                }

                // 2) Try remote prover via relay
                const remoteConfig = await isRemoteProverConfigured();
                if (remoteConfig) {
                  try {
                    const result = await runRemoteProver(`dapp_${operation}_${Date.now()}`, payload, remoteConfig);
                    return result;
                  } catch (e) {
                    console.warn(`[dapp-pvac] remote prover failed for ${operation}:`, (e as Error).message);
                  }
                }

                // 3) WASM fallback
                return wasmFallback();
              }

              if (dappMethod === 'octra_pvac_encrypt' || dappMethod === 'pvac_encrypt') {
                if (!vault.isUnlocked()) { sendResponse({ error: 'Wallet is locked' }); break; }
                const [encParams] = dappParams as [{ value: number }];
                if (encParams?.value == null) { sendResponse({ error: 'Missing value' }); break; }
                const encApproved = await requestUserApproval('pvac_prove', dappOrigin, { operation: 'Encrypt a value', detail: `Value: ${encParams.value}` });
                if (!encApproved) { sendResponse({ error: 'User rejected request' }); break; }
                try {
                  const seed = crypto.getRandomValues(new Uint8Array(32));
                  const seedB64 = toBase64(seed);
                  const result = await runPvacOp('encrypt', {
                    amountRaw: String(encParams.value),
                    seedB64,
                  }, async () => {
                    const { skB64, pkB64 } = await vault.requirePvacKeys();
                    const { initPvacFromKeys, encryptValue } = await import('../lib/pvac');
                    await initPvacFromKeys(fromBase64(skB64), fromBase64(pkB64));
                    const ct = encryptValue(BigInt(encParams.value), seed);
                    return { ciphertext: toBase64(ct) };
                  });
                  sendResponse({ ciphertext: result.ciphertext ?? result.cipher });
                } catch (e) { sendResponse({ error: (e as Error).message }); }
                break;
              }
              if (dappMethod === 'octra_pvac_decrypt' || dappMethod === 'pvac_decrypt') {
                if (!vault.isUnlocked()) { sendResponse({ error: 'Wallet is locked' }); break; }
                const [decParams] = dappParams as [{ ciphertext: string }];
                if (!decParams?.ciphertext) { sendResponse({ error: 'Missing ciphertext' }); break; }
                const approved = await requestUserApproval('pvac_decrypt', dappOrigin, { operation: 'Decrypt a private value' });
                if (!approved) { sendResponse({ error: 'User rejected decrypt request' }); break; }
                try {
                  const result = await runPvacOp('decrypt', {
                    cipher_b64: decParams.ciphertext,
                  }, async () => {
                    const { skB64, pkB64 } = await vault.requirePvacKeys();
                    const { initPvacFromKeys, decryptValue } = await import('../lib/pvac');
                    await initPvacFromKeys(fromBase64(skB64), fromBase64(pkB64));
                    const ct = fromBase64(decParams.ciphertext);
                    const value = decryptValue(ct);
                    return { value: Number(value) };
                  });
                  const val = result.value !== undefined ? Number(result.value) : undefined;
                  sendResponse({ value: val });
                } catch (e) { sendResponse({ error: (e as Error).message }); }
                break;
              }
              if (dappMethod === 'octra_pvac_rangeProof' || dappMethod === 'pvac_rangeProof') {
                if (!vault.isUnlocked()) { sendResponse({ error: 'Wallet is locked' }); break; }
                const [rpParams] = dappParams as [{ ciphertext: string; value: number }];
                if (!rpParams?.ciphertext || rpParams?.value == null) { sendResponse({ error: 'Missing ciphertext or value' }); break; }
                const rpApproved = await requestUserApproval('pvac_prove', dappOrigin, { operation: 'Generate range proof' });
                if (!rpApproved) { sendResponse({ error: 'User rejected request' }); break; }
                try {
                  const result = await runPvacOp('range_proof', {
                    cipher_b64: rpParams.ciphertext,
                    amountRaw: String(rpParams.value),
                  }, async () => {
                    const { skB64, pkB64 } = await vault.requirePvacKeys();
                    const { initPvacFromKeys, makeRangeProof } = await import('../lib/pvac');
                    await initPvacFromKeys(fromBase64(skB64), fromBase64(pkB64));
                    const ct = fromBase64(rpParams.ciphertext);
                    const proof = makeRangeProof(ct, BigInt(rpParams.value));
                    return { proof: toBase64(proof) };
                  });
                  sendResponse({ proof: result.proof });
                } catch (e) { sendResponse({ error: (e as Error).message }); }
                break;
              }
              if (dappMethod === 'octra_pvac_commit' || dappMethod === 'pvac_commit') {
                if (!vault.isUnlocked()) { sendResponse({ error: 'Wallet is locked' }); break; }
                const [cmParams] = dappParams as [{ value: number; blinding?: string }];
                if (cmParams?.value == null) { sendResponse({ error: 'Missing value' }); break; }
                const cmApproved = await requestUserApproval('pvac_prove', dappOrigin, { operation: 'Create Pedersen commitment', detail: `Value: ${cmParams.value}` });
                if (!cmApproved) { sendResponse({ error: 'User rejected request' }); break; }
                try {
                  const blinding = cmParams.blinding ? fromBase64(cmParams.blinding) : crypto.getRandomValues(new Uint8Array(32));
                  const blindingB64 = toBase64(blinding);
                  const result = await runPvacOp('commit', {
                    amountRaw: String(cmParams.value),
                    blindingB64,
                  }, async () => {
                    const { skB64, pkB64 } = await vault.requirePvacKeys();
                    const { initPvacFromKeys, pedersenCommit } = await import('../lib/pvac');
                    await initPvacFromKeys(fromBase64(skB64), fromBase64(pkB64));
                    const commitment = pedersenCommit(BigInt(cmParams.value), blinding);
                    return { commitment: toBase64(commitment), blinding: blindingB64 };
                  });
                  sendResponse({ commitment: result.commitment, blinding: result.blinding ?? blindingB64 });
                } catch (e) { sendResponse({ error: (e as Error).message }); }
                break;
              }
              if (dappMethod === 'octra_pvac_zeroProof' || dappMethod === 'pvac_zeroProof') {
                if (!vault.isUnlocked()) { sendResponse({ error: 'Wallet is locked' }); break; }
                const [zpParams] = dappParams as [{ ciphertext: string; value: number; blinding: string }];
                if (!zpParams?.ciphertext || zpParams?.value == null || !zpParams?.blinding) { sendResponse({ error: 'Missing params' }); break; }
                const zpApproved = await requestUserApproval('pvac_prove', dappOrigin, { operation: 'Generate zero-knowledge proof' });
                if (!zpApproved) { sendResponse({ error: 'User rejected request' }); break; }
                try {
                  const result = await runPvacOp('zero_proof', {
                    cipher_b64: zpParams.ciphertext,
                    amountRaw: String(zpParams.value),
                    blindingB64: zpParams.blinding,
                  }, async () => {
                    const { skB64, pkB64 } = await vault.requirePvacKeys();
                    const { initPvacFromKeys, makeZeroProofBound } = await import('../lib/pvac');
                    await initPvacFromKeys(fromBase64(skB64), fromBase64(pkB64));
                    const ct = fromBase64(zpParams.ciphertext);
                    const blindingBytes = fromBase64(zpParams.blinding);
                    const proof = makeZeroProofBound(ct, BigInt(zpParams.value), blindingBytes);
                    return { proof: toBase64(proof) };
                  });
                  sendResponse({ proof: result.proof });
                } catch (e) { sendResponse({ error: (e as Error).message }); }
                break;
              }
              if (dappMethod === 'octra_pvac_getPubkey' || dappMethod === 'pvac_getPubkey') {
                if (!vault.isUnlocked()) { sendResponse({ error: 'Wallet is locked' }); break; }
                try {
                  const { pkB64 } = await vault.requirePvacKeys();
                  sendResponse({ pubkey: pkB64 });
                } catch (e) { sendResponse({ error: (e as Error).message }); }
                break;
              }

              // Fall through to RPC passthrough for node-level methods
              const RPC_PASSLIST = [
                'octra_balance', 'octra_tokensByAddress', 'octra_account',
                'octra_transaction', 'octra_recommendedFee', 'node_status',
                'contract_call',
              ];
              if (RPC_PASSLIST.includes(dappMethod)) {
                const result = await rpc.rpcCall(dappMethod, dappParams ?? []);
                sendResponse(result);
              } else {
                sendResponse({ error: `Unsupported method: ${dappMethod}` });
              }
            }
          }
          break;
        }
        case 'RPC_PASSTHROUGH': {
          const RPC_ALLOWLIST = [
            'octra_balance', 'octra_tokensByAddress', 'octra_account',
            'octra_transaction', 'octra_recommendedFee', 'node_status',
            'contract_call',
          ];
          const { method, params } = payload as { method: string; params: unknown[] };
          if (!RPC_ALLOWLIST.includes(method)) {
            sendResponse({ error: `RPC method not allowed: ${method}` });
            break;
          }
          const result = await rpc.rpcCall(method, params ?? []);
          sendResponse(result);
          break;
        }
        case 'STEALTH_SEND': {
          if (!vault.isUnlocked()) { sendResponse({ error: 'locked' }); break; }
          const { to, amount } = payload as { to: string; amount: string };
          try {
            // Parse amount
            let amountRaw: bigint;
            if (amount.includes('.')) {
              const [intPart, fracPart] = amount.split('.');
              const frac = (fracPart + '000000').slice(0, 6);
              amountRaw = BigInt(intPart) * 1000000n + BigInt(frac);
            } else {
              amountRaw = BigInt(amount) * 1000000n;
            }
            if (amountRaw <= 0n) { sendResponse({ error: 'invalid amount' }); break; }

            // Check recipient has PVAC pubkey registered (required to receive stealth)
            const recipientPvac = await rpc.getPvacPubkey(to);
            if (!recipientPvac) {
              sendResponse({ error: 'recipient_no_pvac' });
              break;
            }

            // Create job and respond immediately
            const jobId = crypto.randomUUID();
            const storageKey = `job_${jobId}`;
            await chrome.storage.local.set({ [storageKey]: { status: 'running', step: 'Registering PVAC key...' } });
            sendResponse({ jobId });

            // Ensure PVAC pubkey is registered on-chain
            try {
              await ensurePvacRegistered();
            } catch (regErr) {
              await chrome.storage.local.set({ [storageKey]: { status: 'error', error: (regErr as Error).message } });
              break;
            }

            // Run stealth send in background
            runStealthSendJob(jobId, to, amountRaw);
          } catch (err) {
            sendResponse({ error: (err as Error).message });
          }
          break;
        }
        case 'STEALTH_SCAN': {
          if (!vault.isUnlocked()) { sendResponse({ error: 'locked' }); break; }
          try {
            const x25519Sk = vault.deriveX25519Sk();
            const { outputs } = await rpc.getStealthOutputs(0);
            const mine: Array<Record<string, unknown>> = [];
            for (const out of outputs) {
              if (Number(out.claimed ?? 0) !== 0) continue;
              try {
                const ephB64 = String(out.eph_pub ?? '');
                const ephRaw = fromBase64(ephB64);
                if (ephRaw.length !== 32) continue;
                const tagHex = String(out.stealth_tag ?? '');
                const expectedTag = new Uint8Array(16);
                for (let i = 0; i < 16; i++)
                  expectedTag[i] = parseInt(tagHex.slice(i*2, i*2+2), 16);

                const shared = await checkStealthOutput(x25519Sk, ephRaw, expectedTag);
                if (!shared) continue;

                // It's ours
                mine.push({
                  id: out.id,
                  epoch: out.epoch_id ?? 0,
                  sender: out.sender_addr ?? '',
                  tx_hash: out.tx_hash ?? '',
                  eph_pub: ephB64,
                  enc_amount: out.enc_amount ?? '',
                });
              } catch { continue; }
            }
            sendResponse({ outputs: mine });
          } catch (err) {
            sendResponse({ error: (err as Error).message });
          }
          break;
        }
        case 'STEALTH_CLAIM': {
          if (!vault.isUnlocked()) { sendResponse({ error: 'locked' }); break; }
          const { id, eph_pub, enc_amount } = payload as { id: string; eph_pub: string; enc_amount: string };
          try {
            // Re-derive shared secret from ephemeral pubkey
            const ephRaw = fromBase64(eph_pub);
            const x25519Sk = vault.deriveX25519Sk();
            const sharedSecret = x25519SharedSecret(x25519Sk, ephRaw);

            // Decrypt envelope to get amount + blinding
            const envelope = fromBase64(enc_amount);
            const decResult = await decryptStealthAmount(sharedSecret, envelope);
            if (!decResult) { sendResponse({ error: 'Failed to decrypt stealth envelope' }); break; }

            // Derive claim_secret
            const claimSecret = computeClaimSecret(sharedSecret);

            // Create job and respond immediately
            const jobId = crypto.randomUUID();
            const storageKey = `job_${jobId}`;
            await chrome.storage.local.set({ [storageKey]: { status: 'running', step: 'Registering PVAC key...' } });
            sendResponse({ jobId, amount: String(decResult.amount) });

            // Ensure PVAC pubkey is registered on-chain
            try {
              await ensurePvacRegistered();
            } catch (regErr) {
              await chrome.storage.local.set({ [storageKey]: { status: 'error', error: (regErr as Error).message } });
              break;
            }

            // Run claim job
            runStealthClaimJob(jobId, id, claimSecret, decResult.amount, decResult.blinding);
          } catch (err) {
            sendResponse({ error: (err as Error).message });
          }
          break;
        }
        case 'IMPORT_PAIRING': {
          // Parse .pair file content and store pairing config
          const { fileContent } = payload as { fileContent: string };
          const lines = fileContent.split('\n');
          const config: Record<string, string> = {};
          for (const line of lines) {
            if (line.startsWith('#') || !line.includes('=')) continue;
            const [k, ...v] = line.split('=');
            config[k.trim()] = v.join('=').trim();
          }
          if (!config.relay || !config.room || !config.key) {
            sendResponse({ error: 'Invalid pairing file' });
            break;
          }
          await chrome.storage.local.set({ pairingConfig: { relay: config.relay, room: config.room, key: config.key } });
          sendResponse({ ok: true });
          break;
        }
        case 'REMOVE_PAIRING': {
          await chrome.storage.local.remove('pairingConfig');
          sendResponse({ ok: true });
          break;
        }
        case 'GET_PROVER_STATUS': {
          const local = await isProverAvailable();
          const remoteConfig = await isRemoteProverConfigured();
          const { proverMode } = await chrome.storage.local.get('proverMode');
          // Auto-detect mode if not explicitly set
          const mode = proverMode ?? (local ? 'local' : remoteConfig ? 'remote' : 'browser');
          sendResponse({
            local,
            remote: !!remoteConfig,
            mode,
            relayUrl: remoteConfig?.relay ?? null,
          });
          break;
        }
        case 'SET_PROVER_MODE': {
          const { mode } = payload as { mode: string };
          await chrome.storage.local.set({ proverMode: mode });
          // Invalidate prover cache so next balance refresh respects new mode
          proverAvailableCache = null;
          sendResponse({ ok: true });
          break;
        }
        default:
          sendResponse({ error: `unknown message type: ${type}` });
      }
    } catch (err) {
      sendResponse({ error: (err as Error).message || 'operation failed' });
    }
  })();
  return true; // async response
};

chrome.runtime.onMessage.addListener(handler);

// --- Offscreen document management ---
let offscreenCreated = false;

async function ensureOffscreen() {
  if (offscreenCreated) return;
  try {
    // Check if already exists
    if ((chrome.runtime as any).getContexts) {
      const contexts = await (chrome.runtime as any).getContexts({ contextTypes: ['OFFSCREEN_DOCUMENT'] });
      if (contexts && contexts.length > 0) { offscreenCreated = true; return; }
    }
  } catch { /* getContexts not available, try creating */ }

  try {
    await chrome.offscreen.createDocument({
      url: 'offscreen.html',
      reasons: [chrome.offscreen.Reason.WORKERS as any],
      justification: 'PVAC WASM computation for shielded transactions',
    });
  } catch (e: any) {
    // "Only a single offscreen document may be created" = already exists, that's fine
    if (!e.message?.includes('single offscreen')) throw e;
  }
  offscreenCreated = true;
  // Wait for the offscreen to connect its port
  await new Promise<void>((resolve) => {
    if (offscreenPort) { resolve(); return; }
    const check = setInterval(() => {
      if (offscreenPort) { clearInterval(check); resolve(); }
    }, 100);
    // Safety timeout
    setTimeout(() => { clearInterval(check); resolve(); }, 3000);
  });
}

// Listen for port connections from offscreen document
let offscreenPort: chrome.runtime.Port | null = null;

chrome.runtime.onConnect.addListener((port) => {
  if (port.name === 'offscreen') {
    offscreenPort = port;
    port.onMessage.addListener(async (msg) => {
      if (msg.type === 'jobStatus' && msg.jobId) {
        await chrome.storage.local.set({ [`job_${msg.jobId}`]: { status: 'running', step: msg.step } });
      } else if (msg.type === 'cryptoResult' && msg.jobId) {
        await chrome.storage.local.set({ [`job_${msg.jobId}_crypto`]: msg.data });
        await chrome.storage.local.set({ [`job_${msg.jobId}`]: { status: 'crypto_done', step: 'Submitting transaction...' } });
        resumeUnshieldSubmission(msg.jobId);
      } else if (msg.type === 'jobError' && msg.jobId) {
        await chrome.storage.local.set({ [`job_${msg.jobId}`]: { status: 'error', error: msg.error } });
      }
    });
    port.onDisconnect.addListener(() => { offscreenPort = null; });
  }
});

// Handle cryptoComplete via sendMessage (fallback when port disconnected during computation)
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.target === 'background' && msg.action === 'cryptoComplete' && msg.jobId) {
    chrome.storage.local.set({ [`job_${msg.jobId}_crypto`]: msg.data }).then(() =>
      chrome.storage.local.set({ [`job_${msg.jobId}`]: { status: 'crypto_done', step: 'Submitting transaction...' } })
    ).then(() => resumeUnshieldSubmission(msg.jobId));
    sendResponse({ ok: true });
  }
  if (msg.target === 'background' && msg.action === 'cryptoError' && msg.jobId) {
    chrome.storage.local.set({ [`job_${msg.jobId}`]: { status: 'error', error: msg.error } });
    sendResponse({ ok: true });
  }
});

let currentJobStorageKey: string | null = null;

// --- Native Desktop Prover ---
const PROVER_URL = 'http://127.0.0.1:19876';
const PROVER_WS_URL = 'ws://127.0.0.1:19876/prove';

// Remote prover pairing config (stored in chrome.storage.local as 'pairingConfig')
interface PairingConfig {
  relay: string;   // e.g. "wss://relay.octane.fast"
  room: string;    // room ID
  key: string;     // base64 X25519 public key of accelerator
}

// Cache prover availability to avoid 2s timeout on every balance refresh
let proverAvailableCache: boolean | null = null;
let proverCacheExpiry = 0;
const PROVER_CACHE_TTL_OK = 10_000;   // 10s when available
const PROVER_CACHE_TTL_FAIL = 30_000; // 30s cooldown on failure

async function isProverAvailable(): Promise<boolean> {
  const now = Date.now();
  if (proverAvailableCache !== null && now < proverCacheExpiry) {
    return proverAvailableCache;
  }
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 2000);
    const res = await fetch(`${PROVER_URL}/health`, { signal: ctrl.signal });
    clearTimeout(timer);
    const data = await res.json();
    const available = data.status === 'ready';
    proverAvailableCache = available;
    proverCacheExpiry = now + (available ? PROVER_CACHE_TTL_OK : PROVER_CACHE_TTL_FAIL);
    return available;
  } catch {
    proverAvailableCache = false;
    proverCacheExpiry = now + PROVER_CACHE_TTL_FAIL;
    return false;
  }
}

async function isRemoteProverConfigured(): Promise<PairingConfig | null> {
  const { pairingConfig } = await chrome.storage.local.get('pairingConfig');
  return pairingConfig ?? null;
}

// Connect to the remote prover through the relay
function runRemoteProver(jobId: string, payload: Record<string, string>, config: PairingConfig): Promise<Record<string, string>> {
  return new Promise((resolve, reject) => {
    const storageKey = `job_${jobId}`;
    const wsUrl = `${config.relay}/room/${config.room}?role=client`;
    const ws = new WebSocket(wsUrl);
    let settled = false;
    let peerConnected = false;

    ws.onopen = () => {
      // Wait for peer_connected before sending payload
    };

    ws.onmessage = async (ev) => {
      try {
        const msg = JSON.parse(ev.data as string);

        // Relay control messages
        if (msg.type === 'peer_connected') {
          peerConnected = true;
          // Sanitize payload to remove ed25519 seed before sending to remote prover
          const safe = await sanitizeProverPayload(payload);
          ws.send(JSON.stringify({ ...safe, jobId }));
          return;
        }
        if (msg.type === 'peer_disconnected') {
          if (!settled) {
            settled = true;
            ws.close();
            reject(new Error('Remote prover disconnected'));
          }
          return;
        }

        // Prover messages (forwarded from accelerator)
        if (msg.type === 'status') {
          chrome.storage.local.set({ [storageKey]: { status: 'running', step: msg.step } });
        } else if (msg.type === 'result' && msg.data) {
          settled = true;
          ws.close();
          resolve(msg.data);
        } else if (msg.type === 'error') {
          settled = true;
          ws.close();
          reject(new Error(msg.error ?? 'Remote prover error'));
        }
      } catch (e) {
        settled = true;
        ws.close();
        reject(e);
      }
    };

    ws.onerror = () => {
      if (!settled) {
        settled = true;
        reject(new Error('Relay connection failed'));
      }
    };

    ws.onclose = () => {
      if (!settled) {
        settled = true;
        reject(new Error('Relay disconnected'));
      }
    };

    // Timeout: if no peer_connected after 15s, give up
    setTimeout(() => {
      if (!peerConnected && !settled) {
        settled = true;
        ws.close();
        reject(new Error('Remote prover not reachable (timeout)'));
      }
    }, 15000);
  });
}

/**
 * Ensure prover payload has PVAC keys for initialization.
 * Uses cached PVAC keys (NOT the raw signing seed).
 */
async function sanitizeProverPayload(payload: Record<string, string>): Promise<Record<string, string>> {
  if (payload.pvac_sk_b64 && payload.pvac_pk_b64) return payload;
  if (!vault.isUnlocked()) throw new Error('Wallet locked');
  const { skB64, pkB64 } = await vault.requirePvacKeys();
  const sanitized = { ...payload, pvac_sk_b64: skB64, pvac_pk_b64: pkB64 };
  delete sanitized.secretKeyB64;
  return sanitized;
}

function runNativeProver(jobId: string, payload: Record<string, string>): Promise<Record<string, string>> {
  return new Promise((resolve, reject) => {
    const storageKey = `job_${jobId}`;
    const ws = new WebSocket(PROVER_WS_URL);
    let settled = false;

    // Keep service worker alive during long proving operations (Chrome MV3 kills after ~30s idle)
    const keepAlive = setInterval(() => {
      chrome.storage.local.get(storageKey);
    }, 5000);

    const cleanup = () => { clearInterval(keepAlive); };

    ws.onopen = async () => {
      const safe = await sanitizeProverPayload(payload);
      ws.send(JSON.stringify({ ...safe, jobId }));
    };

    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data as string);
        if (msg.type === 'status') {
          chrome.storage.local.set({ [storageKey]: { status: 'running', step: msg.step } });
        } else if (msg.type === 'result' && msg.data) {
          settled = true;
          cleanup();
          ws.close();
          resolve(msg.data);
        } else if (msg.type === 'error') {
          settled = true;
          cleanup();
          ws.close();
          reject(new Error(msg.error ?? 'Prover error'));
        }
      } catch (e) {
        settled = true;
        cleanup();
        ws.close();
        reject(e);
      }
    };

    ws.onerror = () => {
      if (!settled) {
        settled = true;
        cleanup();
        reject(new Error('Prover connection failed'));
      }
    };

    ws.onclose = () => {
      if (!settled) {
        settled = true;
        cleanup();
        reject(new Error('Prover disconnected'));
      }
    };
  });
}

// --- Async unshield job (delegated to offscreen document) ---
async function runUnshieldJob(jobId: string, decAmountRaw: bigint) {
  const storageKey = `job_${jobId}`;
  currentJobStorageKey = storageKey;
  const update = (fields: Record<string, unknown>) =>
    chrome.storage.local.set({ [storageKey]: { status: 'running', ...fields } });

  try {
    if (!vault.isUnlocked()) throw new Error('locked');
    const address = vault.getAddress();

    // Fetch current encrypted balance
    await update({ step: 'Fetching encrypted balance...' });
    const ebMsg = new TextEncoder().encode(`octra_encryptedBalance|${address}`);
    const ebSig = vault.sign(ebMsg);
    const ebResult = await rpc.getEncryptedBalance(address, toBase64(ebSig), toBase64(vault.getPublicKey())) as Record<string, unknown>;
    const currentCipherStr = String(ebResult?.cipher ?? '');
    if (!currentCipherStr || currentCipherStr === '0') throw new Error('No encrypted balance');

    const currentCipherB64 = currentCipherStr.startsWith('hfhe_v1|') ? currentCipherStr.slice(8) : currentCipherStr;

    // Store job params so we can resume after SW wakes
    await chrome.storage.local.set({ [`job_${jobId}_params`]: {
      decAmountRaw: String(decAmountRaw),
      address,
    }});

    const seed = crypto.getRandomValues(new Uint8Array(32));
    const blinding = crypto.getRandomValues(new Uint8Array(32));

    const basePayload = {
      operation: 'unshield',
      currentCipherB64,
      decAmountRaw: String(decAmountRaw),
      amountRaw: String(decAmountRaw),
      seedB64: toBase64(seed),
      blindingB64: toBase64(blinding),
    };

    // Try native desktop prover first (much faster, uses cached PVAC keys)
    const proverAvailable = await isProverAvailable();
    if (proverAvailable) {
      await update({ step: 'Using native prover...' });
      let nativeResult: Record<string, string> | null = null;
      try {
        const { skB64: pvacSk, pkB64: pvacPk } = await vault.requirePvacKeys();
        const nativePayload = { ...basePayload, pvac_sk_b64: pvacSk, pvac_pk_b64: pvacPk };
        nativeResult = await runNativeProver(jobId, nativePayload);
      } catch (proverErr) {
        console.warn('[octane] native prover failed:', (proverErr as Error).message);
        await update({ step: 'Local prover unavailable, trying remote...' });
      }
      if (nativeResult) {
        console.log('[octane] native prover result keys:', Object.keys(nativeResult));
        await update({ step: 'Submitting transaction...' });
        await submitUnshieldDirect(jobId, storageKey, nativeResult, decAmountRaw);
        return;
      }
    }

    // For remote/WASM paths, derive PVAC keys (need WASM or session cache)
    const { skB64: pvacSkB64, pkB64: pvacPkB64 } = await vault.requirePvacKeys();
    const proverPayload = { ...basePayload, pvac_sk_b64: pvacSkB64, pvac_pk_b64: pvacPkB64, pvacSkB64, pvacPkB64 };

    // Try remote prover via relay (if pairing configured and local unavailable)
    if (!proverAvailable) {
      const remoteConfig = await isRemoteProverConfigured();
      if (remoteConfig) {
        await update({ step: 'Proving ☁️ Remote', prover: 'remote' });
        try {
          const result = await runRemoteProver(jobId, proverPayload, remoteConfig);
          console.log('[octane] remote prover result keys:', Object.keys(result));
          // Submit directly from memory — same as native path
          await update({ step: 'Submitting transaction...' });
          await submitUnshieldDirect(jobId, storageKey, result, decAmountRaw);
          return;
        } catch (remoteErr) {
          await update({ step: 'Remote prover unavailable, falling back to in-browser...' });
        }
      }
    }

    // Fallback: Spin up offscreen document for heavy crypto (WASM)
    await update({ step: 'Proving 🌐 In-Browser', prover: 'wasm' });
    await ensureOffscreen();

    if (!offscreenPort) throw new Error('Offscreen port not connected');

    offscreenPort.postMessage({
      action: 'computeUnshield',
      jobId,
      ...proverPayload,
      keyId: address,
    });

    // Service worker can now die — offscreen + worker will continue independently
  } catch (err) {
    await chrome.storage.local.set({ [storageKey]: { status: 'error', error: (err as Error).message } });
    currentJobStorageKey = null;
  }
}

// --- Async encrypt job submission with indefinite retry ---
async function submitEncryptJob(
  jobId: string,
  amountRaw: bigint,
  encData: string,
  attempt = 0,
) {
  const storageKey = `job_${jobId}`;
  try {
    if (!vault.isUnlocked()) throw new Error('locked');
    const address = vault.getAddress();

    // Check if cancelled
    const currentJob = await chrome.storage.local.get(storageKey);
    if (currentJob[storageKey]?.status === 'cancelled') return;

    // Recover attempt count from storage if starting fresh (service worker restart)
    if (attempt === 0 && currentJob[storageKey]?.attempt) {
      attempt = currentJob[storageKey].attempt;
    }

    await chrome.storage.local.set({ [storageKey]: { status: 'running', step: `Submitting transaction...${attempt > 0 ? ` (retry ${attempt})` : ''}`, attempt } });

    const balInfo = await rpc.getBalance(address);
    const nonce = balInfo.nonce + 1;
    const feeInfo = await rpc.getRecommendedFee('encrypt');
    const ou = feeInfo.recommended;
    const timestamp = Math.floor(Date.now() / 1000);
    const tsStr = timestamp + '.0';

    const encDataEscaped = encData.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    const canonical = `{"from":"${address}","to_":"${address}","amount":"${amountRaw}","nonce":${nonce},"ou":"${ou}","timestamp":${tsStr},"op_type":"encrypt","encrypted_data":"${encDataEscaped}"}`;
    const txMsg = new TextEncoder().encode(canonical);
    const txSig = vault.sign(txMsg);

    const tx = {
      from: address,
      to_: address,
      amount: String(amountRaw),
      nonce,
      ou,
      timestamp,
      op_type: 'encrypt',
      encrypted_data: encData,
      signature: toBase64(txSig),
      public_key: toBase64(vault.getPublicKey()),
    };
    const result = await rpc.submitTransaction(tx);
    completeJob(storageKey, jobId, result.hash);
  } catch (err) {
    // Retry indefinitely on any error — user can cancel
    const nextAttempt = attempt + 1;
    const errMsg = (err as Error).message ?? 'unknown error';
    await chrome.storage.local.set({ [storageKey]: { status: 'running', step: `Submitting transaction... (retry ${nextAttempt} — ${errMsg})`, attempt: nextAttempt } });
    setTimeout(() => submitEncryptJob(jobId, amountRaw, encData, nextAttempt), SUBMIT_RETRY_DELAY);
  }
}

// --- Stealth Send Job ---
async function runStealthSendJob(jobId: string, to: string, amountRaw: bigint, attempt = 0) {
  const storageKey = `job_${jobId}`;
  const update = (fields: Record<string, unknown>) =>
    chrome.storage.local.set({ [storageKey]: { status: 'running', ...fields } });

  try {
    // Check if cancelled
    const currentJob = await chrome.storage.local.get(storageKey);
    if (currentJob[storageKey]?.status === 'cancelled') return;

    // Recover attempt count from storage if starting fresh (service worker restart)
    if (attempt === 0 && currentJob[storageKey]?.attempt) {
      attempt = currentJob[storageKey].attempt;
    }

    if (!vault.isUnlocked()) throw new Error('locked');
    const address = vault.getAddress();

    // [1] Get recipient's public key (retries indefinitely on network errors)
    await update({ step: `Fetching recipient public key...${attempt > 0 ? ` (retry ${attempt})` : ''}`, attempt });
    const recipientPkResult = await rpc.getPublicKey(to);
    if (!recipientPkResult.public_key) throw new Error('Recipient has no public key registered — they must make at least one transaction first');
    const theirSigningPk = fromBase64(recipientPkResult.public_key);
    if (theirSigningPk.length !== 32) throw new Error('Invalid recipient public key');

    // [2] ECDH key exchange + stealth envelope (all via WASM)
    await update({ step: 'Key exchange...' });
    const ephSk = crypto.getRandomValues(new Uint8Array(32));
    ephSk[0] &= 248;
    ephSk[31] &= 127;
    ephSk[31] |= 64;
    const blinding = crypto.getRandomValues(new Uint8Array(32));

    const stealth = await prepareStealthSend(theirSigningPk, ephSk, amountRaw, blinding, to);

    // [3] Check encrypted balance
    await update({ step: 'Checking encrypted balance...' });
    const ebMsg = new TextEncoder().encode(`octra_encryptedBalance|${address}`);
    const ebSig = vault.sign(ebMsg);
    const ebResult = await rpc.getEncryptedBalance(address, toBase64(ebSig), toBase64(vault.getPublicKey())) as Record<string, unknown>;
    const currentCipherStr = String(ebResult?.cipher ?? '');
    if (!currentCipherStr || currentCipherStr === '0') throw new Error('No encrypted balance available');
    const currentCipherB64 = currentCipherStr.startsWith('hfhe_v1|') ? currentCipherStr.slice(8) : currentCipherStr;

    // [4] Try native prover first
    const proverAvailable = await isProverAvailable();
    if (proverAvailable) {
      await update({ step: 'Proving ⚡ Desktop', prover: 'local' });
      const seed = crypto.getRandomValues(new Uint8Array(32));
      try {
        const result = await runNativeProver(jobId, {
          operation: 'stealth',
          currentCipherB64,
          amountRaw: String(amountRaw),
          seedB64: toBase64(seed),
          blindingB64: toBase64(blinding),
        });

        // Build stealth_data JSON
        const stealthData = JSON.stringify({
          version: 5,
          delta_cipher: result.cipher,
          commitment: result.commitment ?? result.amount_commitment,
          range_proof_delta: result.range_proof_delta,
          range_proof_balance: result.range_proof_balance,
          eph_pub: toBase64(stealth.ephPk),
          stealth_tag: hexEncode(stealth.tag),
          enc_amount: stealth.encAmount,
          claim_pub: hexEncode(stealth.claimPub),
          amount_commitment: result.amount_commitment,
          send_zero_proof: result.zero_proof ?? result.send_zero_proof,
        });

        await update({ step: 'Submitting transaction...' });
        await submitStealthTx(jobId, stealthData, 0);
        return;
      } catch {
        await update({ step: 'Local prover unavailable, trying remote...' });
      }
    }

    // [4b] Try remote prover
    if (!proverAvailable) {
      const remoteConfig = await isRemoteProverConfigured();
      if (remoteConfig) {
        await update({ step: 'Proving ☁️ Remote', prover: 'remote' });
        const seed = crypto.getRandomValues(new Uint8Array(32));
        try {
          const result = await runRemoteProver(jobId, {
            operation: 'stealth',
            currentCipherB64,
            amountRaw: String(amountRaw),
            seedB64: toBase64(seed),
            blindingB64: toBase64(blinding),
          }, remoteConfig);

          const stealthData = JSON.stringify({
            version: 5,
            delta_cipher: result.cipher,
            commitment: result.commitment ?? result.amount_commitment,
            range_proof_delta: result.range_proof_delta,
            range_proof_balance: result.range_proof_balance,
            eph_pub: toBase64(stealth.ephPk),
            stealth_tag: hexEncode(stealth.tag),
            enc_amount: stealth.encAmount,
            claim_pub: hexEncode(stealth.claimPub),
            amount_commitment: result.amount_commitment,
            send_zero_proof: result.zero_proof ?? result.send_zero_proof,
          });

          await update({ step: 'Submitting transaction...' });
          await submitStealthTx(jobId, stealthData, 0);
          return;
        } catch {
          await update({ step: 'Remote prover unavailable, falling back to in-browser...' });
        }
      }
    }

    // [5] WASM fallback
    if (!isInitialized()) {
      await update({ step: 'Proving 🌐 In-Browser', prover: 'wasm' });
      await vault.requirePvacKeys(); // ensures PVAC keys available
    }

    // Encrypt delta
    await update({ step: 'Encrypting amount...' });
    const seed = crypto.getRandomValues(new Uint8Array(32));
    const ctDelta = encryptValue(amountRaw, seed);
    const deltaCipherStr = 'hfhe_v1|' + toBase64(ctDelta);

    // Pedersen commitment + zero proof
    await update({ step: 'Generating commitment & zero proof...' });
    const amtCommit = pedersenCommit(amountRaw, blinding);
    const amtCommitB64 = toBase64(amtCommit);
    const sendZkp = makeZeroProofBound(ctDelta, amountRaw, blinding);
    const sendZpStr = 'zkzp_v2|' + toBase64(sendZkp);

    // ct_sub: new balance = current - delta
    await update({ step: 'Computing new balance...' });
    const currentCipher = fromBase64(currentCipherB64);
    const ebDecrypted = decryptValue(currentCipher);
    if (ebDecrypted < amountRaw) throw new Error(`Insufficient encrypted balance: have ${ebDecrypted}, need ${amountRaw}`);
    const newBalCipher = ctSub(currentCipher, ctDelta);
    const newBalValue = ebDecrypted - amountRaw;

    // Range proof for delta
    await update({ step: 'Range proof (delta)...' });
    const rpDelta = makeRangeProof(ctDelta, amountRaw);
    const rpDeltaStr = 'rp_v1|' + toBase64(rpDelta);

    // Range proof for remaining balance
    await update({ step: 'Range proof (balance)...' });
    const rpBal = makeRangeProof(newBalCipher, newBalValue);
    const rpBalStr = 'rp_v1|' + toBase64(rpBal);

    // Ciphertext commitment (hash of pk + ct_delta, used by node for verification)
    const ctCommitment = commitCt(ctDelta);

    // Build stealth_data
    const stealthData = JSON.stringify({
      version: 5,
      delta_cipher: deltaCipherStr,
      commitment: toBase64(ctCommitment),
      range_proof_delta: rpDeltaStr,
      range_proof_balance: rpBalStr,
      eph_pub: toBase64(stealth.ephPk),
      stealth_tag: hexEncode(stealth.tag),
      enc_amount: stealth.encAmount,
      claim_pub: hexEncode(stealth.claimPub),
      amount_commitment: amtCommitB64,
      send_zero_proof: sendZpStr,
    });

    await update({ step: 'Submitting transaction...' });
    await submitStealthTx(jobId, stealthData, 0);
  } catch (err) {
    const msg = (err as Error).message ?? '';
    // Definitive errors — don't retry
    const isFatal = msg.includes('no public key registered') ||
                    msg.includes('Invalid recipient public key') ||
                    msg.includes('invalid amount') ||
                    msg.includes('Insufficient encrypted balance');
    if (isFatal) {
      await chrome.storage.local.set({ [storageKey]: { status: 'error', error: msg } });
    } else {
      // Network / transient error — retry indefinitely (user can cancel)
      const nextAttempt = attempt + 1;
      await chrome.storage.local.set({ [storageKey]: { status: 'running', step: `Error: ${msg}. Retrying... (attempt ${nextAttempt})`, attempt: nextAttempt } });
      // Store params for potential service-worker restart
      await chrome.storage.local.set({ [`job_${jobId}_stealth_params`]: { to, amountRaw: String(amountRaw) } });
      setTimeout(() => runStealthSendJob(jobId, to, amountRaw, nextAttempt), SUBMIT_RETRY_DELAY);
    }
  }
}

async function submitStealthTx(
  jobId: string,
  stealthData: string,
  attempt: number,
) {
  const storageKey = `job_${jobId}`;
  try {
    if (!vault.isUnlocked()) throw new Error('locked');
    const address = vault.getAddress();

    const currentJob = await chrome.storage.local.get(storageKey);
    if (currentJob[storageKey]?.status === 'cancelled') return;
    if (attempt === 0 && currentJob[storageKey]?.attempt) {
      attempt = currentJob[storageKey].attempt;
    }

    await chrome.storage.local.set({ [storageKey]: { status: 'running', step: `Submitting transaction...${attempt > 0 ? ` (retry ${attempt})` : ''}`, attempt } });

    const balInfo = await rpc.getBalance(address);
    const nonce = balInfo.nonce + 1;
    const feeInfo = await rpc.getRecommendedFee('stealth');
    const ou = feeInfo.recommended;
    const timestamp = Math.floor(Date.now() / 1000);
    const tsStr = timestamp + '.0';

    const encDataEscaped = stealthData.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    const canonical = `{"from":"${address}","to_":"stealth","amount":"0","nonce":${nonce},"ou":"${ou}","timestamp":${tsStr},"op_type":"stealth","encrypted_data":"${encDataEscaped}"}`;
    const txMsg = new TextEncoder().encode(canonical);
    const txSig = vault.sign(txMsg);

    const tx = {
      from: address,
      to_: 'stealth',
      amount: '0',
      nonce,
      ou,
      timestamp,
      op_type: 'stealth',
      encrypted_data: stealthData,
      signature: toBase64(txSig),
      public_key: toBase64(vault.getPublicKey()),
    };
    const result = await rpc.submitTransaction(tx);
    completeJob(storageKey, jobId, result.hash);
  } catch (err) {
    const nextAttempt = attempt + 1;
    await chrome.storage.local.set({ [storageKey]: { status: 'running', step: `Submitting transaction... (retry ${nextAttempt})`, attempt: nextAttempt } });
    // Store stealthData for potential resume
    await chrome.storage.local.set({ [`job_${jobId}_stealth`]: stealthData });
    setTimeout(() => submitStealthTx(jobId, stealthData, nextAttempt), SUBMIT_RETRY_DELAY);
  }
}

// --- Stealth Claim Job ---
async function runStealthClaimJob(
  jobId: string,
  outputId: string,
  claimSecret: Uint8Array,
  amount: bigint,
  blinding: Uint8Array,
) {
  const storageKey = `job_${jobId}`;
  const update = (fields: Record<string, unknown>) => chrome.storage.local.set({ [storageKey]: { status: 'running', ...fields } });

  try {
    if (!vault.isUnlocked()) throw new Error('locked');

    const amountRaw = amount;

    // Try native prover first
    const proverAvailable = await isProverAvailable();
    if (proverAvailable) {
      await update({ step: 'Proving ⚡ Desktop', prover: 'local' });
      const seed = crypto.getRandomValues(new Uint8Array(32));
      try {
        const result = await runNativeProver(jobId, {
          operation: 'claim',
          amountRaw: String(amountRaw),
          seedB64: toBase64(seed),
          blindingB64: toBase64(blinding),
        });

        // Build claim_data JSON
        const claimData = JSON.stringify({
          version: 5,
          output_id: Number(outputId),
          claim_cipher: result.cipher,
          commitment: result.commitment ?? result.amount_commitment,
          claim_secret: hexEncode(claimSecret),
          zero_proof: result.zero_proof,
        });

        await update({ step: 'Submitting transaction...' });
        await submitClaimTx(jobId, claimData, 0);
        return;
      } catch {
        await update({ step: 'Local prover unavailable, trying remote...' });
      }
    }

    // Try remote prover
    if (!proverAvailable) {
      const remoteConfig = await isRemoteProverConfigured();
      if (remoteConfig) {
        await update({ step: 'Proving ☁️ Remote', prover: 'remote' });
        const seed = crypto.getRandomValues(new Uint8Array(32));
        try {
          const result = await runRemoteProver(jobId, {
            operation: 'claim',
            amountRaw: String(amountRaw),
            seedB64: toBase64(seed),
            blindingB64: toBase64(blinding),
          }, remoteConfig);

          const claimData = JSON.stringify({
            version: 5,
            output_id: Number(outputId),
            claim_cipher: result.cipher,
            commitment: result.commitment ?? result.amount_commitment,
            claim_secret: hexEncode(claimSecret),
            zero_proof: result.zero_proof,
          });

          await update({ step: 'Submitting transaction...' });
          await submitClaimTx(jobId, claimData, 0);
          return;
        } catch {
          await update({ step: 'Remote prover unavailable, falling back to in-browser...' });
        }
      }
    }

    // WASM fallback
    if (!isInitialized()) {
      await update({ step: 'Proving 🌐 In-Browser', prover: 'wasm' });
      await vault.requirePvacKeys(); // ensures PVAC keys available
    }

    // Encrypt claim amount
    await update({ step: 'Encrypting claim amount...' });
    const seed = crypto.getRandomValues(new Uint8Array(32));
    const ctClaim = encryptValue(amountRaw, seed);
    const claimCipherStr = 'hfhe_v1|' + toBase64(ctClaim);

    // Ciphertext commitment
    await update({ step: 'Computing commitment...' });
    const ctCommitment = commitCt(ctClaim);
    const commitmentB64 = toBase64(ctCommitment);

    // Zero proof
    await update({ step: 'Generating zero proof...' });
    const zpBytes = makeZeroProofBound(ctClaim, amountRaw, blinding);
    const zpStr = 'zkzp_v2|' + toBase64(zpBytes);

    // Build claim_data JSON
    const claimData = JSON.stringify({
      version: 5,
      output_id: Number(outputId),
      claim_cipher: claimCipherStr,
      commitment: commitmentB64,
      claim_secret: hexEncode(claimSecret),
      zero_proof: zpStr,
    });

    await update({ step: 'Submitting transaction...' });
    await submitClaimTx(jobId, claimData, 0);
  } catch (err) {
    await chrome.storage.local.set({ [storageKey]: { status: 'error', error: (err as Error).message } });
  }
}

async function submitClaimTx(
  jobId: string,
  claimData: string,
  attempt: number,
) {
  const storageKey = `job_${jobId}`;
  try {
    if (!vault.isUnlocked()) throw new Error('locked');
    const address = vault.getAddress();

    const currentJob = await chrome.storage.local.get(storageKey);
    if (currentJob[storageKey]?.status === 'cancelled') return;
    if (attempt === 0 && currentJob[storageKey]?.attempt) {
      attempt = currentJob[storageKey].attempt;
    }

    await chrome.storage.local.set({ [storageKey]: { status: 'running', step: `Submitting transaction...${attempt > 0 ? ` (retry ${attempt})` : ''}`, attempt } });

    const balInfo = await rpc.getBalance(address);
    const nonce = balInfo.nonce + 1;
    const feeInfo = await rpc.getRecommendedFee('claim');
    const ou = feeInfo.recommended;
    const timestamp = Math.floor(Date.now() / 1000);
    const tsStr = timestamp + '.0';

    const encDataEscaped = claimData.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    const canonical = `{"from":"${address}","to_":"${address}","amount":"0","nonce":${nonce},"ou":"${ou}","timestamp":${tsStr},"op_type":"claim","encrypted_data":"${encDataEscaped}"}`;
    const txMsg = new TextEncoder().encode(canonical);
    const txSig = vault.sign(txMsg);

    const tx = {
      from: address,
      to_: address,
      amount: '0',
      nonce,
      ou,
      timestamp,
      op_type: 'claim',
      encrypted_data: claimData,
      signature: toBase64(txSig),
      public_key: toBase64(vault.getPublicKey()),
    };
    const result = await rpc.submitTransaction(tx);
    completeJob(storageKey, jobId, result.hash);
  } catch (err) {
    const msg = (err as Error).message ?? 'unknown error';
    const isFatal = msg.includes('already claimed') ||
                    msg.includes('output not found') ||
                    msg.includes('bad_commitment') ||
                    msg.includes('invalid signature') ||
                    msg.includes('bad_claim_secret');
    if (isFatal) {
      await chrome.storage.local.set({ [storageKey]: { status: 'error', error: msg } });
    } else {
      const nextAttempt = attempt + 1;
      await chrome.storage.local.set({ [storageKey]: { status: 'running', step: `Submitting... (retry ${nextAttempt} — ${msg})`, attempt: nextAttempt } });
      await chrome.storage.local.set({ [`job_${jobId}_claim`]: claimData });
      setTimeout(() => submitClaimTx(jobId, claimData, nextAttempt), SUBMIT_RETRY_DELAY);
    }
  }
}

// Resume transaction submission after offscreen writes crypto result to storage
const SUBMIT_RETRY_DELAY = 5000; // steady 5s between retries

/** Submit unshield tx directly from in-memory crypto result (no storage roundtrip). */
async function submitUnshieldDirect(
  jobId: string,
  storageKey: string,
  cryptoResult: Record<string, string>,
  decAmountRaw: bigint,
) {
  try {
    const encData = JSON.stringify({
      cipher: cryptoResult.cipher,
      amount_commitment: cryptoResult.amount_commitment,
      zero_proof: cryptoResult.zero_proof,
      blinding: cryptoResult.blinding,
      range_proof_balance: cryptoResult.range_proof_balance,
      ...(cryptoResult.range_proof_delta ? { range_proof_delta: cryptoResult.range_proof_delta } : {}),
      ...(cryptoResult.commitment ? { commitment: cryptoResult.commitment } : {}),
    });

    const balInfo = await rpc.getBalance(vault.getAddress());
    const nonce = balInfo.nonce + 1;
    const feeInfo = await rpc.getRecommendedFee('decrypt');
    const ou = feeInfo.recommended;
    const timestamp = Math.floor(Date.now() / 1000);
    const tsStr = timestamp + '.0';

    const encDataEscaped = encData.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    const canonical = `{"from":"${vault.getAddress()}","to_":"${vault.getAddress()}","amount":"${decAmountRaw}","nonce":${nonce},"ou":"${ou}","timestamp":${tsStr},"op_type":"decrypt","encrypted_data":"${encDataEscaped}"}`;
    const txMsg = new TextEncoder().encode(canonical);
    const txSig = vault.sign(txMsg);

    const tx = {
      from: vault.getAddress(),
      to_: vault.getAddress(),
      amount: String(decAmountRaw),
      nonce,
      ou,
      timestamp,
      op_type: 'decrypt',
      encrypted_data: encData,
      signature: toBase64(txSig),
      public_key: toBase64(vault.getPublicKey()),
    };
    console.log('[octane] submitting unshield tx, encData length:', encData.length);
    const result = await rpc.submitTransaction(tx);
    console.log('[octane] submit response:', JSON.stringify(result));
    completeJob(storageKey, jobId, result.hash);
  } catch (err) {
    console.error('[octane] direct submit failed:', (err as Error).message);
    await chrome.storage.local.set({ [storageKey]: { status: 'error', error: (err as Error).message } });
  }
}

async function resumeUnshieldSubmission(jobId: string, attempt = 0) {
  const storageKey = `job_${jobId}`;
  currentJobStorageKey = storageKey;
  try {
    // Check if job was cancelled
    const currentJob = await chrome.storage.local.get(storageKey);
    if (currentJob[storageKey]?.status === 'cancelled') {
      currentJobStorageKey = null;
      return;
    }

    // Recover attempt count from storage if starting fresh (service worker restart)
    if (attempt === 0 && currentJob[storageKey]?.attempt) {
      attempt = currentJob[storageKey].attempt;
    }

    const w = vault.isUnlocked() ? { address: vault.getAddress() } : null;
    // If wallet is locked, try to get params from storage and wait for unlock
    if (!w) {
      await chrome.storage.local.set({ [storageKey]: { status: 'pending_unlock', step: 'Unlock wallet to complete unshield' } });
      return;
    }

    const { [`job_${jobId}_crypto`]: cryptoResult, [`job_${jobId}_params`]: params } =
      await chrome.storage.local.get([`job_${jobId}_crypto`, `job_${jobId}_params`]);

    if (!cryptoResult) {
      await chrome.storage.local.set({ [storageKey]: { status: 'error', error: 'Crypto result not found' } });
      return;
    }
    if (cryptoResult.error) {
      await chrome.storage.local.set({ [storageKey]: { status: 'error', error: cryptoResult.error } });
      return;
    }

    const decAmountRaw = cryptoResult.decAmountRaw ?? params?.decAmountRaw ?? '0';
    console.log('[octane] resumeUnshieldSubmission cryptoResult keys:', Object.keys(cryptoResult));
    console.log('[octane] cryptoResult sample:', JSON.stringify(cryptoResult).slice(0, 300));

    // Validate crypto result has required fields
    if (!cryptoResult.cipher || !cryptoResult.amount_commitment || !cryptoResult.zero_proof) {
      console.error('[octane] cryptoResult missing required fields, aborting job', jobId);
      await chrome.storage.local.set({ [storageKey]: { status: 'error', error: 'Corrupted crypto result — please retry' } });
      await chrome.storage.local.remove([`job_${jobId}_crypto`, `job_${jobId}_params`]);
      currentJobStorageKey = null;
      return;
    }

    // Build and submit transaction
    await chrome.storage.local.set({ [storageKey]: { status: 'running', step: `Submitting transaction...${attempt > 0 ? ` (retry ${attempt})` : ''}` } });
    const encData = JSON.stringify({
      cipher: cryptoResult.cipher,
      amount_commitment: cryptoResult.amount_commitment,
      zero_proof: cryptoResult.zero_proof,
      blinding: cryptoResult.blinding,
      range_proof_balance: cryptoResult.range_proof_balance,
      ...(cryptoResult.range_proof_delta ? { range_proof_delta: cryptoResult.range_proof_delta } : {}),
      ...(cryptoResult.commitment ? { commitment: cryptoResult.commitment } : {}),
    });
    console.log('[octane] encData length:', encData.length, 'preview:', encData.slice(0, 200));

    const balInfo = await rpc.getBalance(vault.getAddress());
    const nonce = balInfo.nonce + 1;
    const feeInfo = await rpc.getRecommendedFee('decrypt');
    const ou = feeInfo.recommended;
    const timestamp = Math.floor(Date.now() / 1000);
    const tsStr = timestamp + '.0';

    const encDataEscaped = encData.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    const canonical = `{"from":"${vault.getAddress()}","to_":"${vault.getAddress()}","amount":"${decAmountRaw}","nonce":${nonce},"ou":"${ou}","timestamp":${tsStr},"op_type":"decrypt","encrypted_data":"${encDataEscaped}"}`;
    const txMsg = new TextEncoder().encode(canonical);
    const txSig = vault.sign(txMsg);

    const tx = {
      from: vault.getAddress(),
      to_: vault.getAddress(),
      amount: String(decAmountRaw),
      nonce,
      ou,
      timestamp,
      op_type: 'decrypt',
      encrypted_data: encData,
      signature: toBase64(txSig),
      public_key: toBase64(vault.getPublicKey()),
    };
    console.log('[octane] submitting tx:', JSON.stringify({ ...tx, encrypted_data: `[${encData.length} chars]` }));
    const result = await rpc.submitTransaction(tx);
    console.log('[octane] submit response:', JSON.stringify(result));
    completeJob(storageKey, jobId, result.hash);
  } catch (err) {
    const msg = (err as Error).message ?? '';
    console.error('[octane] submit error:', msg, err);
    // Retry indefinitely on any error — user can cancel
    const nextAttempt = attempt + 1;
    await chrome.storage.local.set({ [storageKey]: { status: 'running', step: `Submitting transaction... (retry ${nextAttempt})`, attempt: nextAttempt } });
    setTimeout(() => resumeUnshieldSubmission(jobId, nextAttempt), SUBMIT_RETRY_DELAY);
    return;
  } finally {
    currentJobStorageKey = null;
  }
}
