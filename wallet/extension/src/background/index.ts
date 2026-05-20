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
  pedersenCommit, makeZeroProofBound, makeRangeProof, ctSub, getPubkey, getAesKat,
} from '../lib/pvac';

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
        case 'UNLOCK': {
          const { encryptedSeed, password, hdIndex } = payload as { encryptedSeed: string; password: string; hdIndex?: number };
          unlockedMnemonic = await decryptMnemonic(encryptedSeed, password);
          activeHdIndex = hdIndex ?? 0;
          resetLockTimer();
          sendResponse({ success: true });
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
            // Init PVAC if needed
            if (!isInitialized()) {
              const ok = await initPvac(w.secretKey.slice(0, 32));
              if (!ok) { sendResponse({ error: 'PVAC init failed' }); break; }
            }
            // Fetch encrypted balance
            const ebMsg = new TextEncoder().encode(`octra_encryptedBalance|${w.address}`);
            const ebSig = sign(ebMsg, w.secretKey);
            const ebResult = await rpc.getEncryptedBalance(w.address, toBase64(ebSig), toBase64(w.publicKey)) as Record<string, unknown>;
            const cipherStr = String(ebResult?.cipher ?? '');
            if (!cipherStr || cipherStr === '0') {
              sendResponse({ balance: '0' }); break;
            }
            // Decode cipher (strip "hfhe_v1|" prefix)
            const cipherB64 = cipherStr.startsWith('hfhe_v1|') ? cipherStr.slice(8) : cipherStr;
            const cipherBytes = fromBase64(cipherB64);
            const rawValue = decryptValue(cipherBytes);
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

            // Init PVAC if needed
            if (!isInitialized()) {
              const ok = await initPvac(w.secretKey.slice(0, 32));
              if (!ok) { sendResponse({ error: 'PVAC init failed' }); break; }
            }

            // Generate random seed & blinding
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

            // Build transaction
            const balInfo = await rpc.getBalance(w.address);
            const nonce = balInfo.nonce + 1;
            const feeInfo = await rpc.getRecommendedFee('encrypt');
            const ou = feeInfo.recommended;
            const timestamp = Math.floor(Date.now() / 1000);
            const tsStr = timestamp + '.0';

            // Canonical JSON for signing (encrypted_data must be JSON-escaped)
            const encDataEscaped = encData.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
            const canonical = `{"from":"${w.address}","to_":"${w.address}","amount":"${amountRaw}","nonce":${nonce},"ou":"${ou}","timestamp":${tsStr},"op_type":"encrypt","encrypted_data":"${encDataEscaped}"}`;
            const txMsg = new TextEncoder().encode(canonical);
            const txSig = sign(txMsg, w.secretKey);

            const tx = {
              from: w.address,
              to_: w.address,
              amount: String(amountRaw),
              nonce,
              ou,
              timestamp,
              op_type: 'encrypt',
              encrypted_data: encData,
              signature: toBase64(txSig),
              public_key: toBase64(w.publicKey),
            };
            const result = await rpc.submitTransaction(tx);
            sendResponse(result);
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
          await chrome.storage.local.set({ [`job_${jobId}`]: { status: 'running', step: 'Starting...', startedAt: Date.now() } });
          sendResponse({ jobId });

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
        case 'CANCEL_UNSHIELD': {
          const { jobId } = payload as { jobId: string };
          const storageKey = `job_${jobId}`;
          await chrome.storage.local.set({ [storageKey]: { status: 'cancelled' } });
          await chrome.storage.local.remove([`${storageKey}_crypto`, `${storageKey}_params`, 'activeUnshieldJob', 'activeUnshieldStart']);
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

    // Spin up offscreen document for heavy crypto
    await update({ step: 'Starting computation engine...' });
    await ensureOffscreen();

    // Store job params so we can resume after SW wakes
    await chrome.storage.local.set({ [`job_${jobId}_params`]: {
      decAmountRaw: String(decAmountRaw),
      address: w.address,
    }});

    // Send computation to offscreen via persistent port
    const seed = crypto.getRandomValues(new Uint8Array(32));
    const blinding = crypto.getRandomValues(new Uint8Array(32));

    if (!offscreenPort) throw new Error('Offscreen port not connected');

    offscreenPort.postMessage({
      action: 'computeUnshield',
      jobId,
      currentCipherB64,
      decAmountRaw: String(decAmountRaw),
      seedB64: toBase64(seed),
      blindingB64: toBase64(blinding),
      secretKeyB64: toBase64(w.secretKey.slice(0, 32)),
    });

    // Service worker can now die — offscreen + worker will continue independently
  } catch (err) {
    await chrome.storage.local.set({ [storageKey]: { status: 'error', error: (err as Error).message } });
    currentJobStorageKey = null;
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

    const decAmountRaw = params?.decAmountRaw ?? '0';

    // Build and submit transaction
    await chrome.storage.local.set({ [storageKey]: { status: 'running', step: `Submitting transaction...${attempt > 0 ? ` (retry ${attempt})` : ''}` } });
    const encData = JSON.stringify({
      cipher: cryptoResult.cipher,
      amount_commitment: cryptoResult.amount_commitment,
      zero_proof: cryptoResult.zero_proof,
      blinding: cryptoResult.blinding,
      range_proof_balance: cryptoResult.range_proof_balance,
    });

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
    const result = await rpc.submitTransaction(tx);
    await chrome.storage.local.set({ [storageKey]: { status: 'done', hash: result.hash } });

    // Clean up intermediate storage
    await chrome.storage.local.remove([`job_${jobId}_crypto`, `job_${jobId}_params`]);
  } catch (err) {
    const msg = (err as Error).message ?? '';
    const isTransient = msg.includes('Failed to fetch') || msg.includes('NetworkError') || msg.includes('timeout') || msg.includes('ECONNREFUSED');

    if (isTransient) {
      await chrome.storage.local.set({ [storageKey]: { status: 'running', step: `Network error, retrying... (attempt ${attempt + 1})` } });
      setTimeout(() => resumeUnshieldSubmission(jobId, attempt + 1), SUBMIT_RETRY_DELAY);
      return;
    }

    await chrome.storage.local.set({ [storageKey]: { status: 'error', error: msg } });
  } finally {
    currentJobStorageKey = null;
  }
}
