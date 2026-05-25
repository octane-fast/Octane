// Service worker polyfill: Vite's dynamic import error handler references `window`
// which doesn't exist in service workers. Alias it to `self` (the SW global scope).
declare const self: typeof globalThis;
(globalThis as any).window = self;

import { sign, toBase64, fromBase64, walletFromMnemonic } from '../lib/crypto';
import { decryptMnemonic, loadWallet, saveWallet } from '../lib/storage';
import type { StoredState } from '../lib/storage';
import * as rpc from '../lib/rpc';
import {
  initPvac, isInitialized, encryptValue, decryptValue,
  pedersenCommit, makeZeroProofBound, makeRangeProof, ctSub, getPubkey, getAesKat, commitCt,
} from '../lib/pvac';
import {
  prepareStealthSend, checkStealthOutput, decryptStealthAmount, computeClaimSecret, hexEncode,
} from '../lib/stealth';
import { edSkToX25519, x25519SharedSecret } from '../lib/crypto/stealth';
import { sha256 } from '@noble/hashes/sha256';

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
  for (const key of Object.keys(all)) {
    if (key.startsWith('job_') && !key.includes('_crypto') && !key.includes('_params')) {
      const job = all[key];
      if (job.status === 'crypto_done' || job.status === 'pending_unlock') {
        const jobId = key.replace('job_', '');
        resumeUnshieldSubmission(jobId);
      } else if (job.status === 'running') {
        // SW may have died mid-submission; resume if crypto result exists
        const jobId = key.replace('job_', '');
        if (all[`job_${jobId}_crypto`]) {
          resumeUnshieldSubmission(jobId);
        }
      }
    }
  }
});

// In-memory unlocked state
let unlockedMnemonic: string | null = null;
let activeHdIndex: number = 0;
let lockTimeout: ReturnType<typeof setTimeout> | null = null;
const AUTO_LOCK_MS = 15 * 60 * 1000; // 15 minutes

function resetLockTimer() {
  if (lockTimeout) clearTimeout(lockTimeout);
  lockTimeout = setTimeout(() => {
    unlockedMnemonic = null;
    activeHdIndex = 0;
  }, AUTO_LOCK_MS);
}

function getWallet() {
  if (!unlockedMnemonic) return null;
  resetLockTimer();
  return walletFromMnemonic(unlockedMnemonic, activeHdIndex);
}

/**
 * Ensure the PVAC public key is registered on-chain for the given wallet.
 * Mirrors webcli's ensure_pvac_registered().
 */
async function ensurePvacRegistered(
  address: string,
  secretKey: Uint8Array,
  publicKey: Uint8Array,
): Promise<void> {
  const existing = await rpc.getPvacPubkey(address);
  if (existing) return; // already registered

  // Initialize PVAC if needed
  if (!isInitialized()) {
    const ok = await initPvac(secretKey.slice(0, 32));
    if (!ok) throw new Error('PVAC init failed');
  }

  // Get PVAC public key and AES KAT
  const pvacPk = getPubkey();
  const aesKat = getAesKat();

  // Sign: "register_pvac|" + address + "|" + sha256hex(pvac_pk_bytes)
  const pkHash = hexEncode(sha256(pvacPk));
  const msg = `register_pvac|${address}|${pkHash}`;
  const msgBytes = new TextEncoder().encode(msg);
  const sig = sign(msgBytes, secretKey);

  await rpc.registerPvacPubkey(
    address,
    toBase64(pvacPk),
    toBase64(sig),
    toBase64(publicKey),
    hexEncode(aesKat),
  );
}

/**
 * Ensure the ed25519 public key is registered on-chain for the given wallet.
 * Required for others to stealth-send to this address.
 */
async function ensurePublicKeyRegistered(
  address: string,
  secretKey: Uint8Array,
  publicKey: Uint8Array,
): Promise<void> {
  const existing = await rpc.getPublicKey(address);
  if (existing.public_key) return; // already registered

  // Sign: "register_pubkey:" + address
  const msg = `register_pubkey:${address}`;
  const msgBytes = new TextEncoder().encode(msg);
  const sig = sign(msgBytes, secretKey);

  await rpc.registerPublicKey(address, toBase64(publicKey), toBase64(sig));
}

// --- Unlock prompt for dApp requests ---
const unlockWaiters: Array<(unlocked: boolean) => void> = [];

function notifyUnlockWaiters() {
  while (unlockWaiters.length) unlockWaiters.pop()!(true);
}

async function ensureUnlocked(): Promise<boolean> {
  if (unlockedMnemonic) return true;
  // Open popup so user can enter password
  const popupUrl = chrome.runtime.getURL('dist/src/popup/index.html?unlock=dapp');
  chrome.windows.create({
    url: popupUrl,
    type: 'popup',
    width: 380,
    height: 540,
    focused: true,
  });
  // Wait up to 2 minutes for unlock
  return new Promise<boolean>((resolve) => {
    unlockWaiters.push(resolve);
    setTimeout(() => {
      const idx = unlockWaiters.indexOf(resolve);
      if (idx >= 0) {
        unlockWaiters.splice(idx, 1);
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
  type: 'connect' | 'sign_message' | 'send_transaction' | 'call_contract',
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
          unlockedMnemonic = await decryptMnemonic(encryptedSeed, password);
          activeHdIndex = hdIndex ?? 0;
          resetLockTimer();
          sendResponse({ success: true });
          // Notify any dApp requests waiting for unlock
          notifyUnlockWaiters();
          // Auto-register public key on-chain (fire-and-forget)
          {
            const w = getWallet();
            if (w) {
              ensurePublicKeyRegistered(w.address, w.secretKey, w.publicKey).catch(() => {});
              // Eagerly start offscreen + warm up PVAC WASM so decrypt is instant
              ensureOffscreen().then(() => {
                if (offscreenPort) {
                  offscreenPort.postMessage({ action: 'warmup', secretKeyB64: toBase64(w.secretKey.slice(0, 32)) });
                }
              }).catch(() => {});
            }
          }
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
          unlockedMnemonic = null;
          activeHdIndex = 0;
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
        case 'IS_UNLOCKED': {
          sendResponse({ unlocked: unlockedMnemonic !== null });
          break;
        }
        case 'SWITCH_ACCOUNT': {
          const { hdIndex } = payload as { hdIndex: number };
          activeHdIndex = hdIndex;
          const w = getWallet();
          sendResponse({ address: w?.address ?? '' });
          // Auto-register public key on-chain (fire-and-forget)
          if (w) ensurePublicKeyRegistered(w.address, w.secretKey, w.publicKey).catch(() => {});
          break;
        }
        case 'GET_ACCOUNTS': {
          if (!unlockedMnemonic) { sendResponse({ error: 'locked' }); break; }
          const state = await loadWallet();
          if (!state) { sendResponse({ error: 'no wallet' }); break; }
          const accounts = state.accounts.map(acc => {
            const derived = walletFromMnemonic(unlockedMnemonic!, acc.hdIndex);
            return { name: acc.name, hdIndex: acc.hdIndex, address: derived.address };
          });
          sendResponse({ accounts, activeHdIndex });
          break;
        }
        case 'ADD_ACCOUNT': {
          if (!unlockedMnemonic) { sendResponse({ error: 'locked' }); break; }
          const { name, hdIndex } = payload as { name: string; hdIndex: number };
          const newWallet = walletFromMnemonic(unlockedMnemonic, hdIndex);
          sendResponse({ address: newWallet.address, name, hdIndex });
          break;
        }
        case 'GET_ADDRESS': {
          const w = getWallet();
          if (!w) { sendResponse({ error: 'locked' }); break; }
          sendResponse({ address: w.address });
          break;
        }
        case 'GET_BALANCE': {
          const w = getWallet();
          if (!w) { sendResponse({ error: 'locked' }); break; }
          const balance = await rpc.getBalance(w.address);
          sendResponse(balance);
          break;
        }
        case 'GET_TOKENS': {
          const w = getWallet();
          if (!w) { sendResponse({ error: 'locked' }); break; }
          const tokens = await rpc.getTokensByAddress(w.address);
          sendResponse({ tokens });
          break;
        }
        case 'GET_ENCRYPTED_BALANCE': {
          const w = getWallet();
          if (!w) { sendResponse({ error: 'locked' }); break; }
          const msg = new TextEncoder().encode(`octra_encryptedBalance|${w.address}`);
          const sig = sign(msg, w.secretKey);
          const result = await rpc.getEncryptedBalance(w.address, toBase64(sig), toBase64(w.publicKey));
          sendResponse({ encryptedBalance: result });
          break;
        }
        case 'GET_DECRYPTED_BALANCE': {
          const w = getWallet();
          if (!w) { sendResponse({ error: 'locked' }); break; }
          try {
            // Fetch encrypted balance from chain
            const ebMsg = new TextEncoder().encode(`octra_encryptedBalance|${w.address}`);
            const ebSig = sign(ebMsg, w.secretKey);
            const ebResult = await rpc.getEncryptedBalance(w.address, toBase64(ebSig), toBase64(w.publicKey)) as Record<string, unknown>;
            const cipherStr = String(ebResult?.cipher ?? '');
            if (!cipherStr || cipherStr === '0') {
              sendResponse({ balance: '0' }); break;
            }
            // Strip "hfhe_v1|" prefix
            const cipherB64 = cipherStr.startsWith('hfhe_v1|') ? cipherStr.slice(8) : cipherStr;
            const secretKeyB64 = toBase64(w.secretKey.slice(0, 32));

            // Try native prover first (fast, already initialized)
            let rawValue: bigint | null = null;
            if (await isProverAvailable()) {
              try {
                const ctrl = new AbortController();
                const timer = setTimeout(() => ctrl.abort(), 3000);
                const res = await fetch(`${PROVER_URL}/decrypt`, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ secret_key_b64: secretKeyB64, cipher_b64: cipherB64 }),
                  signal: ctrl.signal,
                });
                clearTimeout(timer);
                const data = await res.json() as { value?: number; error?: string };
                if (data.value !== undefined) rawValue = BigInt(data.value);
              } catch { /* fall through to offscreen */ }
            }

            // Fallback: offscreen WASM worker
            if (rawValue === null) {
              await ensureOffscreen();
              const decResult = await chrome.runtime.sendMessage({ target: 'offscreen', action: 'decrypt', secretKeyB64, cipherB64 }) as { value?: string; error?: string };
              if (decResult.error) { sendResponse({ error: decResult.error }); break; }
              rawValue = BigInt(decResult.value ?? '0');
            }

            // Convert raw to human-readable (1 OCT = 1000000 raw)
            const whole = rawValue / 1000000n;
            const frac = rawValue % 1000000n;
            const balStr = frac === 0n ? `${whole}` : `${whole}.${String(frac).padStart(6, '0').replace(/0+$/, '')}`;
            sendResponse({ balance: balStr });
          } catch (err) {
            sendResponse({ error: (err as Error).message });
          }
          break;
        }
        case 'ENCRYPT_BALANCE': {
          const w = getWallet();
          if (!w) { sendResponse({ error: 'locked' }); break; }
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
              await ensurePvacRegistered(w.address, w.secretKey, w.publicKey);
            } catch (regErr) {
              await chrome.storage.local.set({ [storageKey]: { status: 'error', error: (regErr as Error).message } });
              break;
            }

            // Try native prover first
            const proverAvailable = await isProverAvailable();
            if (proverAvailable) {
              await chrome.storage.local.set({ [storageKey]: { status: 'running', step: 'Using native prover...' } });
              const seed = crypto.getRandomValues(new Uint8Array(32));
              const blinding = crypto.getRandomValues(new Uint8Array(32));
              try {
                const result = await runNativeProver(jobId, {
                  operation: 'shield',
                  secretKeyB64: toBase64(w.secretKey.slice(0, 32)),
                  amountRaw: String(amountRaw),
                  seedB64: toBase64(seed),
                  blindingB64: toBase64(blinding),
                });
                // Build encData from native result
                const encData = JSON.stringify({
                  cipher: result.cipher,
                  amount_commitment: result.amount_commitment,
                  zero_proof: result.zero_proof,
                  blinding: result.blinding,
                });
                await chrome.storage.local.set({ [storageKey]: { status: 'running', step: 'Submitting transaction...' } });
                submitEncryptJob(jobId, w.address, w.secretKey, w.publicKey, amountRaw, encData);
                break;
              } catch {
                // Fall through to WASM
                await chrome.storage.local.set({ [storageKey]: { status: 'running', step: 'Prover unavailable, falling back...' } });
              }
            }

            // Fallback: in-process WASM
            if (!isInitialized()) {
              const ok = await initPvac(w.secretKey.slice(0, 32));
              if (!ok) {
                await chrome.storage.local.set({ [storageKey]: { status: 'error', error: 'PVAC init failed' } });
                break;
              }
            }

            const seed = crypto.getRandomValues(new Uint8Array(32));
            const blinding = crypto.getRandomValues(new Uint8Array(32));

            // FHE encrypt
            const cipherBytes = encryptValue(amountRaw, seed);
            const cipherStr = 'hfhe_v1|' + toBase64(cipherBytes);

            // Pedersen commitment
            const commitBytes = pedersenCommit(amountRaw, blinding);
            const commitB64 = toBase64(commitBytes);

            // Zero proof (bound)
            const zpBytes = makeZeroProofBound(cipherBytes, amountRaw, blinding);
            const zpStr = 'zkzp_v2|' + toBase64(zpBytes);

            // Build encrypted_data JSON
            const encData = JSON.stringify({
              cipher: cipherStr,
              amount_commitment: commitB64,
              zero_proof: zpStr,
              blinding: toBase64(blinding),
            });

            await chrome.storage.local.set({ [storageKey]: { status: 'running', step: 'Submitting transaction...' } });
            submitEncryptJob(jobId, w.address, w.secretKey, w.publicKey, amountRaw, encData);
          } catch (err) {
            sendResponse({ error: (err as Error).message });
          }
          break;
        }
        case 'DECRYPT_BALANCE': {
          const w = getWallet();
          if (!w) { sendResponse({ error: 'locked' }); break; }
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
            await ensurePvacRegistered(w.address, w.secretKey, w.publicKey);
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
          const w = getWallet();
          if (!w) { sendResponse({ error: 'locked' }); break; }
          const msgBytes = new TextEncoder().encode(payload.message as string);
          const signature = sign(msgBytes, w.secretKey);
          sendResponse({ signature: toBase64(signature) });
          break;
        }
        case 'SEND_TRANSACTION': {
          const w = getWallet();
          if (!w) { sendResponse({ error: 'locked' }); break; }
          const { to, amount, fee } = payload as { to: string; amount: string; fee?: string };
          const balInfo = await rpc.getBalance(w.address);
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
          const canonical = `{"from":"${w.address}","to_":"${to}","amount":"${amountRaw}","nonce":${nonce},"ou":"${ou}","timestamp":${tsStr},"op_type":"standard"}`;
          const txMsg = new TextEncoder().encode(canonical);
          const txSig = sign(txMsg, w.secretKey);
          const tx = {
            from: w.address,
            to_: to,
            amount: amountRaw,
            nonce,
            ou,
            timestamp,
            op_type: 'standard',
            signature: toBase64(txSig),
            public_key: toBase64(w.publicKey),
          };
          const result = await rpc.submitTransaction(tx);
          sendResponse(result);
          break;
        }
        case 'CONTRACT_CALL': {
          const w = getWallet();
          if (!w) { sendResponse({ error: 'locked' }); break; }
          const { contract, method, params } = payload as { contract: string; method: string; params: unknown[] };
          const result = await rpc.contractCall(contract, method, params ?? [], w.address);
          sendResponse(result);
          break;
        }
        case 'SWAP_OCTUSD': {
          const w = getWallet();
          if (!w) { sendResponse({ error: 'locked' }); break; }
          const { direction, amount } = payload as { direction: 'buy' | 'sell'; amount: string };
          try {
            const OCTUSD_ADDR = 'oct2hJMZbBdAAKTBXK61vs1TUx8oQNZVZyEpR4SXGFXgtvE';
            const balInfo = await rpc.getBalance(w.address);
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
            const canonical = `{"from":"${w.address}","to_":"${OCTUSD_ADDR}","amount":"${amountRaw}","nonce":${nonce},"ou":"${ou}","timestamp":${tsStr},"op_type":"call","encrypted_data":"${methodName}","message":"${msgEscaped}"}`;
            const txMsg = new TextEncoder().encode(canonical);
            const txSig = sign(txMsg, w.secretKey);
            const tx = {
              from: w.address,
              to_: OCTUSD_ADDR,
              amount: amountRaw,
              nonce,
              ou,
              timestamp,
              op_type: 'call',
              encrypted_data: methodName,
              message,
              signature: toBase64(txSig),
              public_key: toBase64(w.publicKey),
            };
            const result = await rpc.submitTransaction(tx);
            sendResponse(result);
          } catch (err) {
            sendResponse({ error: (err as Error).message ?? 'swap failed' });
          }
          break;
        }
        case 'GET_ACTIVITY': {
          const w = getWallet();
          if (!w) { sendResponse({ error: 'locked' }); break; }
          const history = await rpc.getAccountHistory(w.address, 10);
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
              if (!getWallet()) {
                const unlocked = await ensureUnlocked();
                if (!unlocked) { sendResponse({ error: 'Wallet is locked' }); break; }
                freshlyUnlocked = true;
              }
              const w = getWallet()!;
              // If user just unlocked, auto-approve since they showed intent
              // Otherwise show approval popup for first-time connections
              if (!approvedOrigins.has(dappOrigin)) {
                if (!freshlyUnlocked) {
                  const approved = await requestUserApproval('connect', dappOrigin, {});
                  if (!approved) { sendResponse({ error: 'User rejected connection' }); break; }
                }
                approvedOrigins.add(dappOrigin);
              }
              sendResponse([w.address]);
              break;
            }
            case 'octra_getBalance':
            case 'octra_getEncryptedBalance':
            case 'getBalance':
            case 'get_balance': {
              if (!getWallet()) {
                const unlocked = await ensureUnlocked();
                if (!unlocked) { sendResponse({ error: 'Wallet is locked' }); break; }
              }
              const w = getWallet()!;
              const balRes = await rpc.getBalance(w.address);
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
              // Non-interactive version: return address if origin already approved
              const w = getWallet();
              if (!w || !approvedOrigins.has(dappOrigin)) {
                sendResponse([]);
              } else {
                sendResponse([w.address]);
              }
              break;
            }
            case 'octra_signMessage':
            case 'signMessage':
            case 'sign_message': {
              if (!getWallet()) {
                const unlocked = await ensureUnlocked();
                if (!unlocked) { sendResponse({ error: 'Wallet is locked' }); break; }
              }
              const w = getWallet()!;
              const rawParam = (dappParams as unknown[])[0];
              const message = typeof rawParam === 'string' ? rawParam : (rawParam as any)?.message;
              if (!message || typeof message !== 'string') {
                sendResponse({ error: 'Invalid message' });
                break;
              }
              const approved = await requestUserApproval('sign_message', dappOrigin, { message });
              if (!approved) { sendResponse({ error: 'User rejected signature request' }); break; }
              const msgBytes = new TextEncoder().encode(message);
              const sig = sign(msgBytes, w.secretKey);
              sendResponse(toBase64(sig));
              break;
            }
            case 'octra_sendTransaction':
            case 'sendTransaction':
            case 'send_transaction': {
              if (!getWallet()) {
                const unlocked = await ensureUnlocked();
                if (!unlocked) { sendResponse({ error: 'Wallet is locked' }); break; }
              }
              const w = getWallet()!;
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
              const balInfo = await rpc.getBalance(w.address);
              const nonce = balInfo.nonce + 1;
              const ts = Math.floor(Date.now() / 1000);
              const tsStr = ts + '.0';
              const canonical = `{"from":"${w.address}","to_":"${txData.to}","amount":"${amountRaw}","nonce":${nonce},"ou":"1000","timestamp":${tsStr},"op_type":"standard"}`;
              const txSig = sign(new TextEncoder().encode(canonical), w.secretKey);
              const txPayload = {
                from: w.address,
                to_: txData.to,
                amount: amountRaw,
                nonce,
                ou: '1000',
                timestamp: ts,
                op_type: 'standard',
                ...(txData.message ? { message: txData.message } : {}),
                signature: toBase64(txSig),
                public_key: toBase64(w.publicKey),
              };
              const submitRes = await rpc.submitTransaction(txPayload);
              sendResponse({ txHash: submitRes.hash, success: true });
              break;
            }
            case 'octra_callContract':
            case 'callContract':
            case 'call_contract': {
              if (!getWallet()) {
                const unlocked = await ensureUnlocked();
                if (!unlocked) { sendResponse({ error: 'Wallet is locked' }); break; }
              }
              const w = getWallet()!;
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
              const balInfo2 = await rpc.getBalance(w.address);
              const nonce2 = balInfo2.nonce + 1;
              const ts2 = Math.floor(Date.now() / 1000);
              const tsStr2 = ts2 + '.0';
              const msgField = JSON.stringify(callData.params ?? []);
              const escMsg = msgField.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
              const canonical2 = `{"from":"${w.address}","to_":"${callData.contract}","amount":"${amt}","nonce":${nonce2},"ou":"${ou}","timestamp":${tsStr2},"op_type":"call","encrypted_data":"${callData.method}","message":"${escMsg}"}`;
              const sig2 = sign(new TextEncoder().encode(canonical2), w.secretKey);
              const callPayload = {
                from: w.address,
                to_: callData.contract,
                amount: amt,
                nonce: nonce2,
                ou,
                timestamp: ts2,
                op_type: 'call',
                encrypted_data: callData.method,
                message: msgField,
                signature: toBase64(sig2),
                public_key: toBase64(w.publicKey),
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
              const w2 = getWallet();
              const caller = viewData.caller || w2?.address || '';
              const viewRes = await rpc.rpcCall('contract_call', [viewData.contract, viewData.method, viewData.params ?? [], caller]);
              sendResponse(viewRes);
              break;
            }
            default: {
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
          const w = getWallet();
          if (!w) { sendResponse({ error: 'locked' }); break; }
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

            // Create job and respond immediately
            const jobId = crypto.randomUUID();
            const storageKey = `job_${jobId}`;
            await chrome.storage.local.set({ [storageKey]: { status: 'running', step: 'Registering PVAC key...' } });
            sendResponse({ jobId });

            // Ensure PVAC pubkey is registered on-chain
            try {
              await ensurePvacRegistered(w.address, w.secretKey, w.publicKey);
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
          const w = getWallet();
          if (!w) { sendResponse({ error: 'locked' }); break; }
          try {
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

                const shared = await checkStealthOutput(w.secretKey, ephRaw, expectedTag);
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
          const w = getWallet();
          if (!w) { sendResponse({ error: 'locked' }); break; }
          const { id, eph_pub, enc_amount } = payload as { id: string; eph_pub: string; enc_amount: string };
          try {
            // Re-derive shared secret from ephemeral pubkey
            const ephRaw = fromBase64(eph_pub);
            const x25519Sk = edSkToX25519(w.secretKey);
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
              await ensurePvacRegistered(w.address, w.secretKey, w.publicKey);
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
          sendResponse({
            local,
            remote: !!remoteConfig,
            relayUrl: remoteConfig?.relay ?? null,
          });
          break;
        }
        default:
          sendResponse({ error: `unknown message type: ${type}` });
      }
    } catch (err) {
      sendResponse({ error: (err as Error).message });
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

async function isProverAvailable(): Promise<boolean> {
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 2000);
    const res = await fetch(`${PROVER_URL}/health`, { signal: ctrl.signal });
    clearTimeout(timer);
    const data = await res.json();
    return data.status === 'ready';
  } catch {
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

    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data as string);

        // Relay control messages
        if (msg.type === 'peer_connected') {
          peerConnected = true;
          // Now send the prove request through relay to accelerator
          ws.send(JSON.stringify({ ...payload, jobId }));
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

function runNativeProver(jobId: string, payload: Record<string, string>): Promise<Record<string, string>> {
  return new Promise((resolve, reject) => {
    const storageKey = `job_${jobId}`;
    const ws = new WebSocket(PROVER_WS_URL);
    let settled = false;

    ws.onopen = () => {
      ws.send(JSON.stringify({ ...payload, jobId }));
    };

    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data as string);
        if (msg.type === 'status') {
          chrome.storage.local.set({ [storageKey]: { status: 'running', step: msg.step } });
        } else if (msg.type === 'result' && msg.data) {
          settled = true;
          ws.close();
          resolve(msg.data);
        } else if (msg.type === 'error') {
          settled = true;
          ws.close();
          reject(new Error(msg.error ?? 'Prover error'));
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
        reject(new Error('Prover connection failed'));
      }
    };

    ws.onclose = () => {
      if (!settled) {
        settled = true;
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
    const w = getWallet();
    if (!w) throw new Error('locked');

    // Fetch current encrypted balance
    await update({ step: 'Fetching encrypted balance...' });
    const ebMsg = new TextEncoder().encode(`octra_encryptedBalance|${w.address}`);
    const ebSig = sign(ebMsg, w.secretKey);
    const ebResult = await rpc.getEncryptedBalance(w.address, toBase64(ebSig), toBase64(w.publicKey)) as Record<string, unknown>;
    const currentCipherStr = String(ebResult?.cipher ?? '');
    if (!currentCipherStr || currentCipherStr === '0') throw new Error('No encrypted balance');

    const currentCipherB64 = currentCipherStr.startsWith('hfhe_v1|') ? currentCipherStr.slice(8) : currentCipherStr;

    // Store job params so we can resume after SW wakes
    await chrome.storage.local.set({ [`job_${jobId}_params`]: {
      decAmountRaw: String(decAmountRaw),
      address: w.address,
    }});

    const seed = crypto.getRandomValues(new Uint8Array(32));
    const blinding = crypto.getRandomValues(new Uint8Array(32));

    const proverPayload = {
      operation: 'unshield',
      currentCipherB64,
      decAmountRaw: String(decAmountRaw),
      amountRaw: String(decAmountRaw),
      seedB64: toBase64(seed),
      blindingB64: toBase64(blinding),
      secretKeyB64: toBase64(w.secretKey.slice(0, 32)),
    };

    // Try native desktop prover first (much faster)
    const proverAvailable = await isProverAvailable();
    if (proverAvailable) {
      await update({ step: 'Using native prover...' });
      try {
        const result = await runNativeProver(jobId, proverPayload);
        console.log('[octane] native prover result:', JSON.stringify(result).slice(0, 500));
        // Store result and proceed to submission (include decAmountRaw for resilience)
        await chrome.storage.local.set({ [`job_${jobId}_crypto`]: { ...result, decAmountRaw: String(decAmountRaw) } });
        await chrome.storage.local.set({ [storageKey]: { status: 'crypto_done', step: 'Submitting transaction...' } });
        resumeUnshieldSubmission(jobId);
        return;
      } catch (proverErr) {
        // Fall back to remote prover or WASM
        await update({ step: 'Local prover unavailable, trying remote...' });
      }
    }

    // Try remote prover via relay (if pairing configured and local unavailable)
    if (!proverAvailable) {
      const remoteConfig = await isRemoteProverConfigured();
      if (remoteConfig) {
        await update({ step: 'Connecting to remote prover...' });
        try {
          const result = await runRemoteProver(jobId, proverPayload, remoteConfig);
          console.log('[octane] remote prover result:', JSON.stringify(result).slice(0, 500));
          await chrome.storage.local.set({ [`job_${jobId}_crypto`]: { ...result, decAmountRaw: String(decAmountRaw) } });
          await chrome.storage.local.set({ [storageKey]: { status: 'crypto_done', step: 'Submitting transaction...' } });
          resumeUnshieldSubmission(jobId);
          return;
        } catch (remoteErr) {
          await update({ step: 'Remote prover unavailable, falling back to in-browser...' });
        }
      }
    }

    // Fallback: Spin up offscreen document for heavy crypto (WASM)
    await update({ step: 'Starting computation engine...' });
    await ensureOffscreen();

    if (!offscreenPort) throw new Error('Offscreen port not connected');

    offscreenPort.postMessage({
      action: 'computeUnshield',
      jobId,
      ...proverPayload,
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
  address: string,
  secretKey: Uint8Array,
  publicKey: Uint8Array,
  amountRaw: bigint,
  encData: string,
  attempt = 0,
) {
  const storageKey = `job_${jobId}`;
  try {
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
    const txSig = sign(txMsg, secretKey);

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
      public_key: toBase64(publicKey),
    };
    const result = await rpc.submitTransaction(tx);
    await chrome.storage.local.set({ [storageKey]: { status: 'done', hash: result.hash } });
  } catch (err) {
    // Retry indefinitely on any error — user can cancel
    const nextAttempt = attempt + 1;
    const errMsg = (err as Error).message ?? 'unknown error';
    await chrome.storage.local.set({ [storageKey]: { status: 'running', step: `Submitting transaction... (retry ${nextAttempt} — ${errMsg})`, attempt: nextAttempt } });
    setTimeout(() => submitEncryptJob(jobId, address, secretKey, publicKey, amountRaw, encData, nextAttempt), SUBMIT_RETRY_DELAY);
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

    const w = getWallet();
    if (!w) throw new Error('locked');

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
    const ebMsg = new TextEncoder().encode(`octra_encryptedBalance|${w.address}`);
    const ebSig = sign(ebMsg, w.secretKey);
    const ebResult = await rpc.getEncryptedBalance(w.address, toBase64(ebSig), toBase64(w.publicKey)) as Record<string, unknown>;
    const currentCipherStr = String(ebResult?.cipher ?? '');
    if (!currentCipherStr || currentCipherStr === '0') throw new Error('No encrypted balance available');
    const currentCipherB64 = currentCipherStr.startsWith('hfhe_v1|') ? currentCipherStr.slice(8) : currentCipherStr;

    // [4] Try native prover first
    const proverAvailable = await isProverAvailable();
    if (proverAvailable) {
      await update({ step: 'Using native prover...' });
      const seed = crypto.getRandomValues(new Uint8Array(32));
      try {
        const result = await runNativeProver(jobId, {
          operation: 'stealth',
          secretKeyB64: toBase64(w.secretKey.slice(0, 32)),
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
        await submitStealthTx(jobId, w, stealthData, 0);
        return;
      } catch {
        await update({ step: 'Local prover unavailable, trying remote...' });
      }
    }

    // [4b] Try remote prover
    if (!proverAvailable) {
      const remoteConfig = await isRemoteProverConfigured();
      if (remoteConfig) {
        await update({ step: 'Connecting to remote prover...' });
        const seed = crypto.getRandomValues(new Uint8Array(32));
        try {
          const result = await runRemoteProver(jobId, {
            operation: 'stealth',
            secretKeyB64: toBase64(w.secretKey.slice(0, 32)),
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
          await submitStealthTx(jobId, w, stealthData, 0);
          return;
        } catch {
          await update({ step: 'Remote prover unavailable, falling back to in-browser...' });
        }
      }
    }

    // [5] WASM fallback
    if (!isInitialized()) {
      await update({ step: 'Initializing PVAC...' });
      const ok = await initPvac(w.secretKey.slice(0, 32));
      if (!ok) throw new Error('PVAC init failed');
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
    await submitStealthTx(jobId, w, stealthData, 0);
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
  w: { address: string; secretKey: Uint8Array; publicKey: Uint8Array },
  stealthData: string,
  attempt: number,
) {
  const storageKey = `job_${jobId}`;
  try {
    const currentJob = await chrome.storage.local.get(storageKey);
    if (currentJob[storageKey]?.status === 'cancelled') return;
    if (attempt === 0 && currentJob[storageKey]?.attempt) {
      attempt = currentJob[storageKey].attempt;
    }

    await chrome.storage.local.set({ [storageKey]: { status: 'running', step: `Submitting transaction...${attempt > 0 ? ` (retry ${attempt})` : ''}`, attempt } });

    const balInfo = await rpc.getBalance(w.address);
    const nonce = balInfo.nonce + 1;
    const feeInfo = await rpc.getRecommendedFee('stealth');
    const ou = feeInfo.recommended;
    const timestamp = Math.floor(Date.now() / 1000);
    const tsStr = timestamp + '.0';

    const encDataEscaped = stealthData.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    const canonical = `{"from":"${w.address}","to_":"stealth","amount":"0","nonce":${nonce},"ou":"${ou}","timestamp":${tsStr},"op_type":"stealth","encrypted_data":"${encDataEscaped}"}`;
    const txMsg = new TextEncoder().encode(canonical);
    const txSig = sign(txMsg, w.secretKey);

    const tx = {
      from: w.address,
      to_: 'stealth',
      amount: '0',
      nonce,
      ou,
      timestamp,
      op_type: 'stealth',
      encrypted_data: stealthData,
      signature: toBase64(txSig),
      public_key: toBase64(w.publicKey),
    };
    const result = await rpc.submitTransaction(tx);
    await chrome.storage.local.set({ [storageKey]: { status: 'done', hash: result.hash } });
  } catch (err) {
    const nextAttempt = attempt + 1;
    await chrome.storage.local.set({ [storageKey]: { status: 'running', step: `Submitting transaction... (retry ${nextAttempt})`, attempt: nextAttempt } });
    // Store stealthData for potential resume
    await chrome.storage.local.set({ [`job_${jobId}_stealth`]: stealthData });
    setTimeout(() => submitStealthTx(jobId, w, stealthData, nextAttempt), SUBMIT_RETRY_DELAY);
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
    const w = getWallet();
    if (!w) throw new Error('locked');

    const amountRaw = amount;

    // Try native prover first
    const proverAvailable = await isProverAvailable();
    if (proverAvailable) {
      await update({ step: 'Using native prover...' });
      const seed = crypto.getRandomValues(new Uint8Array(32));
      try {
        const result = await runNativeProver(jobId, {
          operation: 'claim',
          secretKeyB64: toBase64(w.secretKey.slice(0, 32)),
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
        await submitClaimTx(jobId, w, claimData, 0);
        return;
      } catch {
        await update({ step: 'Local prover unavailable, trying remote...' });
      }
    }

    // Try remote prover
    if (!proverAvailable) {
      const remoteConfig = await isRemoteProverConfigured();
      if (remoteConfig) {
        await update({ step: 'Connecting to remote prover...' });
        const seed = crypto.getRandomValues(new Uint8Array(32));
        try {
          const result = await runRemoteProver(jobId, {
            operation: 'claim',
            secretKeyB64: toBase64(w.secretKey.slice(0, 32)),
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
          await submitClaimTx(jobId, w, claimData, 0);
          return;
        } catch {
          await update({ step: 'Remote prover unavailable, falling back to in-browser...' });
        }
      }
    }

    // WASM fallback
    if (!isInitialized()) {
      await update({ step: 'Initializing PVAC...' });
      const ok = await initPvac(w.secretKey.slice(0, 32));
      if (!ok) throw new Error('PVAC init failed');
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
    await submitClaimTx(jobId, w, claimData, 0);
  } catch (err) {
    await chrome.storage.local.set({ [storageKey]: { status: 'error', error: (err as Error).message } });
  }
}

async function submitClaimTx(
  jobId: string,
  w: { address: string; secretKey: Uint8Array; publicKey: Uint8Array },
  claimData: string,
  attempt: number,
) {
  const storageKey = `job_${jobId}`;
  try {
    const currentJob = await chrome.storage.local.get(storageKey);
    if (currentJob[storageKey]?.status === 'cancelled') return;
    if (attempt === 0 && currentJob[storageKey]?.attempt) {
      attempt = currentJob[storageKey].attempt;
    }

    await chrome.storage.local.set({ [storageKey]: { status: 'running', step: `Submitting transaction...${attempt > 0 ? ` (retry ${attempt})` : ''}`, attempt } });

    const balInfo = await rpc.getBalance(w.address);
    const nonce = balInfo.nonce + 1;
    const feeInfo = await rpc.getRecommendedFee('claim');
    const ou = feeInfo.recommended;
    const timestamp = Math.floor(Date.now() / 1000);
    const tsStr = timestamp + '.0';

    const encDataEscaped = claimData.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    const canonical = `{"from":"${w.address}","to_":"${w.address}","amount":"0","nonce":${nonce},"ou":"${ou}","timestamp":${tsStr},"op_type":"claim","encrypted_data":"${encDataEscaped}"}`;
    const txMsg = new TextEncoder().encode(canonical);
    const txSig = sign(txMsg, w.secretKey);

    const tx = {
      from: w.address,
      to_: w.address,
      amount: '0',
      nonce,
      ou,
      timestamp,
      op_type: 'claim',
      encrypted_data: claimData,
      signature: toBase64(txSig),
      public_key: toBase64(w.publicKey),
    };
    const result = await rpc.submitTransaction(tx);
    await chrome.storage.local.set({ [storageKey]: { status: 'done', hash: result.hash } });
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
      setTimeout(() => submitClaimTx(jobId, w, claimData, nextAttempt), SUBMIT_RETRY_DELAY);
    }
  }
}

// Resume transaction submission after offscreen writes crypto result to storage
const SUBMIT_RETRY_DELAY = 5000; // steady 5s between retries

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

    const w = getWallet();
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

    const balInfo = await rpc.getBalance(w.address);
    const nonce = balInfo.nonce + 1;
    const feeInfo = await rpc.getRecommendedFee('decrypt');
    const ou = feeInfo.recommended;
    const timestamp = Math.floor(Date.now() / 1000);
    const tsStr = timestamp + '.0';

    const encDataEscaped = encData.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    const canonical = `{"from":"${w.address}","to_":"${w.address}","amount":"${decAmountRaw}","nonce":${nonce},"ou":"${ou}","timestamp":${tsStr},"op_type":"decrypt","encrypted_data":"${encDataEscaped}"}`;
    const txMsg = new TextEncoder().encode(canonical);
    const txSig = sign(txMsg, w.secretKey);

    const tx = {
      from: w.address,
      to_: w.address,
      amount: String(decAmountRaw),
      nonce,
      ou,
      timestamp,
      op_type: 'decrypt',
      encrypted_data: encData,
      signature: toBase64(txSig),
      public_key: toBase64(w.publicKey),
    };
    console.log('[octane] submitting tx:', JSON.stringify({ ...tx, encrypted_data: `[${encData.length} chars]` }));
    const result = await rpc.submitTransaction(tx);
    console.log('[octane] submit response:', JSON.stringify(result));
    await chrome.storage.local.set({ [storageKey]: { status: 'done', hash: result.hash } });

    // Clean up intermediate storage
    await chrome.storage.local.remove([`job_${jobId}_crypto`, `job_${jobId}_params`]);
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
