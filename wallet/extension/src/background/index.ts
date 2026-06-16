// Service worker polyfill: Vite's dynamic import error handler references `window`
// which doesn't exist in service workers. Alias it to `self` (the SW global scope).
declare const self: typeof globalThis;
(globalThis as any).window = self;

import { toBase64, fromBase64 } from '../lib/crypto';
import { loadWallet } from '../lib/storage';
import * as rpc from '../lib/rpc';
import {
  initPvacFromKeys, encryptValue, decryptValue,
  pedersenCommit, makeZeroProofBound, makeRangeProof,
  ctAdd, ctSub, ctMul, ctAddConst, ctSubConst,
} from '../lib/pvac';
import {
  checkStealthOutput, decryptStealthAmount, computeClaimSecret, hexEncode,
} from '../lib/stealth';
import { x25519SharedSecret } from '../lib/crypto/stealth';
import { sha256 } from '@noble/hashes/sha2';
import * as vault from '../lib/keyVault';
import {
  FEATURE_TOR, TOR_SOCKS_PORT,
  SK_TOR_ENABLED, SK_APPROVAL_PREFIX,
  POPUP_UNLOCK_PATH, POPUP_CONFIRM_PATH,
  POPUP_UNLOCK_WIDTH, POPUP_UNLOCK_HEIGHT,
  POPUP_CONFIRM_WIDTH, POPUP_CONFIRM_HEIGHT,
  APPROVAL_TIMEOUT_MS,
  APPROVAL_CONNECT, APPROVAL_SIGN_MESSAGE, APPROVAL_SEND_TX,
  APPROVAL_CALL_CONTRACT, APPROVAL_PVAC_DECRYPT, APPROVAL_PVAC_PROVE, APPROVAL_ZKTLS_PROVE,
  MSG_APPROVAL_RESPONSE, MSG_UNLOCK, MSG_LOCK, MSG_SET_TOR,
  MSG_SET_RPC_URL, MSG_GET_RPC_URL, MSG_IS_UNLOCKED,
  MSG_SWITCH_ACCOUNT, MSG_GET_ACCOUNTS, MSG_ADD_ACCOUNT, MSG_GET_ADDRESS,
  MSG_CHECK_STEALTH_READY, MSG_DERIVE_PVAC_KEYS,
  MSG_GET_BALANCE, MSG_GET_TOKENS, MSG_GET_ENCRYPTED_BALANCE,
  MSG_GET_DECRYPTED_BALANCE, MSG_ENCRYPT_BALANCE, MSG_DECRYPT_BALANCE,
  MSG_GET_JOB_STATUS, MSG_CANCEL_UNSHIELD, MSG_CANCEL_JOB,
  MSG_SIGN_MESSAGE, MSG_SEND_TRANSACTION, MSG_CONTRACT_CALL, MSG_GET_ACTIVITY, MSG_DAPP_REQUEST,
  MSG_RPC_PASSTHROUGH, MSG_STEALTH_SEND, MSG_STEALTH_SCAN,
  MSG_STEALTH_CLAIM, MSG_IMPORT_PAIRING, MSG_REMOVE_PAIRING,
  MSG_GET_PROVER_STATUS, MSG_SET_PROVER_MODE,
  MSG_FETCH_CIRCLE_ASSET, MSG_GET_NFT_CONTENT,
  MSG_GET_ZKTLS_CLAIMS,
  SK_ZKTLS_PROOF_PREFIX, SK_ACTIVE_ZKTLS_JOB, SK_ACTIVE_ZKTLS_START,
  ACTION_INIT, ACTION_DECRYPT,
  ERR_LOCKED,
  SIG_ENCRYPTED_BALANCE,
  ERR_WALLET_LOCKED,
  ERR_USER_REJECTED_CONNECTION,
  getNetworkInfo,
  ERR_INVALID_AMOUNT,
  ERR_USER_REJECTED_SIGNATURE,
  ERR_USER_REJECTED_TX,
  ERR_INVALID_CALLDATA,
  ERR_USER_REJECTED_CONTRACT,
  ERR_MISSING_VALUE,
  ERR_USER_REJECTED_REQUEST,
  ERR_MISSING_CIPHERTEXT,
  SK_STEALTH_LAST_EPOCH,
  SK_STEALTH_PENDING,
  SK_STEALTH_CLAIMED,
  STEALTH_DATA_VERSION,
} from '../lib/constants';
import { type ApprovalType } from '../lib/types';
import { enableTorProxy, disableTorProxy, isTorReachable } from '../lib/tor';
import { runJobCleanup, cleanupOrphanedApprovals } from '../lib/cleanup';
import { completeJob, resumePendingUnlockJobs, setJob, getJob, removeJob } from '../lib/jobStore';
import {
  PROVER_URL, isProverAvailable, isRemoteProverConfigured,
  invalidateProverCache, setKeyProvider, route as routeProof,
} from '../lib/proofRouter';
import { getCachedProof, setCachedProof, getAllCachedProofs } from '../lib/zktlsCache';
import { parseAmountRaw, formatAmountHuman } from '../lib/units';
import { buildSignedTx, buildCanonical } from '../lib/txBuilder';
import { getDefaultFee, getOperationFee } from '../lib/fees';
import { runJob } from '../lib/jobRunner';
import { shieldJob, unshieldJob, stealthSendJob, stealthClaimJob } from './jobs';

// Inject key provider for prover payload sanitization
setKeyProvider(() => vault.requirePvacKeys());

// Mutex for stealth scan/claim to prevent concurrent read-modify-write on pending list
let stealthLock: Promise<void> = Promise.resolve();
function withStealthLock<T>(fn: () => Promise<T>): Promise<T> {
  const prev = stealthLock;
  let resolve: () => void;
  stealthLock = new Promise(r => { resolve = r; });
  return prev.then(fn).finally(() => resolve!());
}

// Restore Tor state on service worker startup
if (FEATURE_TOR) {
  chrome.storage.local.get(SK_TOR_ENABLED).then(({ torEnabled }) => {
    if (torEnabled) enableTorProxy();
  });
}

// Clean up stale jobs on service worker startup
runJobCleanup();

// Purge orphaned approval entries left by previous SW lifetimes
cleanupOrphanedApprovals();

// Private balance cache — skip decryption if the on-chain cipher hasn't changed
let cachedPrivateBalance: string | null = null;
let cachedCipherStr: string | null = null;

/**
 * Ensure the PVAC public key is registered on-chain for the current wallet.
 * Unlocks: shield, unshield, stealth send/claim, and receiving stealth payments.
 * The node uses this key to verify ciphertexts and proofs.
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
 * Unlocks: receiving stealth payments (senders need this for ECDH key exchange).
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
  const popupUrl = chrome.runtime.getURL(POPUP_UNLOCK_PATH);
  const win = await chrome.windows.create({
    url: popupUrl,
    type: 'popup',
    width: POPUP_UNLOCK_WIDTH,
    height: POPUP_UNLOCK_HEIGHT,
    focused: true,
  });
  // Wait for unlock or timeout
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
    }, APPROVAL_TIMEOUT_MS);
  });
}

// --- dApp approval popup infrastructure ---
interface PendingApprovalEntry {
  resolve: (approved: boolean) => void;
}
const pendingApprovals = new Map<string, PendingApprovalEntry>();

async function requestUserApproval(
  type: ApprovalType,
  origin: string,
  data: Record<string, unknown>,
): Promise<boolean> {
  const id = crypto.randomUUID();
  const storageKey = `${SK_APPROVAL_PREFIX}${id}`;
  await chrome.storage.local.set({ [storageKey]: { id, type, origin, data } });

  const confirmUrl = chrome.runtime.getURL(`${POPUP_CONFIRM_PATH}?id=${id}`);
  chrome.windows.create({
    url: confirmUrl,
    type: 'popup',
    width: POPUP_CONFIRM_WIDTH,
    height: POPUP_CONFIRM_HEIGHT,
    focused: true,
  });

  return new Promise<boolean>((resolve) => {
    pendingApprovals.set(id, { resolve });
    // Auto-reject if no response
    setTimeout(() => {
      if (pendingApprovals.has(id)) {
        pendingApprovals.delete(id);
        chrome.storage.local.remove(storageKey);
        resolve(false);
      }
    }, APPROVAL_TIMEOUT_MS);
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
        case MSG_APPROVAL_RESPONSE: {
          const { id: approvalId, approved } = payload as { id: string; approved: boolean };
          const entry = pendingApprovals.get(approvalId);
          if (entry) {
            pendingApprovals.delete(approvalId);
            chrome.storage.local.remove(`${SK_APPROVAL_PREFIX}${approvalId}`);
            entry.resolve(approved);
          }
          sendResponse({ ok: true });
          break;
        }
        case MSG_UNLOCK: {
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
              // No persisted keys yet — skip if account has no funds (can't register anyway)
              const bal = await rpc.getBalance(vault.getAddress()).catch(() => null);
              if (!bal || bal.raw === '0') {
                console.log('[pvac] skipping WASM derivation — account has no funds');
                return;
              }
              // Lazy init: derive PVAC keys on first unlock with funds
              console.log('[pvac] keys not in local storage, running WASM derivation');
              keys = await vault.generateAndPersistPvacKeys();
            }
            // Only spin up offscreen WASM if no external prover is available
            if (!await isProverAvailable() && !await isRemoteProverConfigured()) {
              ensureOffscreen().then(() => {
                if (offscreenPort) {
                  offscreenPort.postMessage({ action: ACTION_INIT, pvacSkB64: keys!.skB64, pvacPkB64: keys!.pkB64, keyId: vault.getAddress() });
                }
              }).catch(() => {});
            }
            // Register PVAC pubkey on-chain if not already
            ensurePvacRegistered().catch(e => console.warn('[pvac] registration failed:', e.message));
          }).catch((e) => { console.warn('[pvac] key load/derive failed:', e); });
          // Resume any pending_unlock jobs now that wallet is unlocked
          resumePendingUnlockJobs();
          break;
        }
        case MSG_LOCK: {
          vault.lock();
          cachedPrivateBalance = null;
          cachedCipherStr = null;
          sendResponse({ success: true });
          break;
        }
        case MSG_SET_TOR: {
          const { enabled } = payload as { enabled: boolean };
          if (enabled) {
            const reachable = await isTorReachable();
            if (!reachable) {
              sendResponse({ error: 'Tor proxy not reachable at 127.0.0.1:' + TOR_SOCKS_PORT });
              break;
            }
            await enableTorProxy();
            sendResponse({ success: true });
          } else {
            await disableTorProxy();
            sendResponse({ success: true });
          }
          break;
        }
        case MSG_SET_RPC_URL: {
          const { url } = payload as { url: string };
          rpc.setRpcUrl(url);
          await chrome.storage.local.set({ rpcUrl: url });
          // Clear private balance cache — chain data differs between networks
          cachedPrivateBalance = null;
          cachedCipherStr = null;
          sendResponse({ success: true, rpcUrl: url });
          break;
        }
        case MSG_GET_RPC_URL: {
          sendResponse({ rpcUrl: rpc.getRpcUrl() });
          break;
        }
        case MSG_IS_UNLOCKED: {
          sendResponse({ unlocked: vault.isUnlocked() });
          break;
        }
        case MSG_SWITCH_ACCOUNT: {
          const { hdIndex } = payload as { hdIndex: number };
          vault.setHdIndex(hdIndex);
          cachedPrivateBalance = null;
          cachedCipherStr = null;
          sendResponse({ address: vault.getAddress() });
          ensurePublicKeyRegistered().catch(e => console.warn('[wallet] pubkey registration failed:', e.message));
          // Load PVAC keys for this account and init offscreen
          vault.derivePvacKeys().then(async (keys) => {
            if (!keys) {
              // No persisted keys yet — skip if account has no funds (can't register anyway)
              const bal = await rpc.getBalance(vault.getAddress()).catch(() => null);
              if (!bal || bal.raw === '0') {
                console.log('[pvac] skipping WASM derivation — account has no funds');
                return;
              }
              // Lazy init: derive PVAC keys on first switch to a funded account
              keys = await vault.generateAndPersistPvacKeys();
            }
            // Only spin up offscreen WASM if no external prover is available
            if (!await isProverAvailable() && !await isRemoteProverConfigured()) {
              ensureOffscreen().then(() => {
                if (offscreenPort) {
                  offscreenPort.postMessage({ action: ACTION_INIT, pvacSkB64: keys!.skB64, pvacPkB64: keys!.pkB64, keyId: vault.getAddress() });
                }
              }).catch(() => {});
            }
            ensurePvacRegistered().catch(e => console.warn('[pvac] registration failed:', e.message));
          }).catch(() => {});
          break;
        }
        case MSG_GET_ACCOUNTS: {
          if (!vault.isUnlocked()) { sendResponse({ error: 'locked' }); break; }
          const state = await loadWallet();
          if (!state) { sendResponse({ error: 'no wallet' }); break; }
          const accounts = state.accounts.map(acc => ({
            name: acc.name, hdIndex: acc.hdIndex, address: vault.getAddressForIndex(acc.hdIndex),
          }));
          sendResponse({ accounts, activeHdIndex: vault.getHdIndex() });
          break;
        }
        case MSG_ADD_ACCOUNT: {
          if (!vault.isUnlocked()) { sendResponse({ error: 'locked' }); break; }
          const { name, hdIndex } = payload as { name: string; hdIndex: number };
          const newAddr = vault.getAddressForIndex(hdIndex);
          sendResponse({ address: newAddr, name, hdIndex });
          break;
        }
        case MSG_GET_ADDRESS: {
          if (!vault.isUnlocked()) { sendResponse({ error: ERR_LOCKED }); break; }
          sendResponse({ address: vault.getAddress() });
          break;
        }
        case MSG_CHECK_STEALTH_READY: {
          if (!vault.isUnlocked()) { sendResponse({ ready: false, reason: ERR_LOCKED }); break; }
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
        case MSG_DERIVE_PVAC_KEYS: {
          if (!vault.isUnlocked()) { sendResponse({ error: ERR_LOCKED }); break; }
          try {
            const keys = await vault.generateAndPersistPvacKeys();
            // Only spin up offscreen WASM if no external prover is available
            if (!await isProverAvailable() && !await isRemoteProverConfigured()) {
              ensureOffscreen().then(() => {
                if (offscreenPort) {
                  offscreenPort.postMessage({ action: ACTION_INIT, pvacSkB64: keys.skB64, pvacPkB64: keys.pkB64, keyId: vault.getAddress() });
                }
              }).catch(() => {});
            }
            sendResponse({ success: true });
          } catch (e: any) {
            sendResponse({ error: e.message || 'PVAC derivation failed' });
          }
          break;
        }
        case MSG_GET_BALANCE: {
          if (!vault.isUnlocked()) { sendResponse({ error: ERR_LOCKED }); break; }
          const balance = await rpc.getBalance(vault.getAddress());
          sendResponse(balance);
          break;
        }
        case MSG_GET_TOKENS: {
          if (!vault.isUnlocked()) { sendResponse({ error: ERR_LOCKED }); break; }
          const tokens = await rpc.getTokensByAddress(vault.getAddress());
          sendResponse({ tokens });
          break;
        }
        case MSG_GET_ENCRYPTED_BALANCE: {
          if (!vault.isUnlocked()) { sendResponse({ error: ERR_LOCKED }); break; }
          const msg = new TextEncoder().encode(`${SIG_ENCRYPTED_BALANCE}|${vault.getAddress()}`);
          const ebSigRaw = vault.sign(msg);
          const result = await rpc.getEncryptedBalance(vault.getAddress(), toBase64(ebSigRaw), toBase64(vault.getPublicKey()));
          sendResponse({ encryptedBalance: result });
          break;
        }
        case MSG_GET_DECRYPTED_BALANCE: {
          if (!vault.isUnlocked()) { sendResponse({ error: 'locked' }); break; }
          try {
            const address = vault.getAddress();
            // Fetch encrypted balance from chain
            const ebMsg = new TextEncoder().encode(`${SIG_ENCRYPTED_BALANCE}|${address}`);
            const ebSig = vault.sign(ebMsg);
            const ebResult = await rpc.getEncryptedBalance(address, toBase64(ebSig), toBase64(vault.getPublicKey())) as Record<string, unknown>;
            const cipherStr = String(ebResult?.cipher ?? '');
            if (!cipherStr || cipherStr === '0') {
              cachedPrivateBalance = '0';
              cachedCipherStr = cipherStr;
              sendResponse({ balance: '0' }); break;
            }

            // If cipher hasn't changed, return cached decrypted value (skip expensive decrypt)
            if (cipherStr === cachedCipherStr && cachedPrivateBalance !== null) {
              sendResponse({ balance: cachedPrivateBalance });
              break;
            }

            console.log('[pvac-decrypt] decrypting balance, cipher_len=%d', cipherStr.length);

            // Strip "hfhe_v1|" prefix
            const cipherB64 = cipherStr.startsWith('hfhe_v1|') ? cipherStr.slice(8) : cipherStr;

            // Route decrypt through prover cascade
            const { skB64: pvacSkB64, pkB64: pvacPkB64 } = await vault.requirePvacKeys();
            const decPayload = { operation: 'decrypt', pvac_sk_b64: pvacSkB64, pvac_pk_b64: pvacPkB64, cipher_b64: cipherB64 };
            const t0 = Date.now();
            const decResult = (await routeProof({
              operation: 'decrypt',
              payload: decPayload,
              native: async () => {
                const ctrl = new AbortController();
                const timer = setTimeout(() => ctrl.abort(), 3000);
                try {
                  const res = await fetch(`${PROVER_URL}/decrypt`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(decPayload),
                    signal: ctrl.signal,
                  });
                  clearTimeout(timer);
                  const data = await res.json() as { value?: number; error?: string };
                  if (data.value !== undefined) return { value: data.value };
                  return null;
                } catch (fetchErr) {
                  clearTimeout(timer);
                  throw fetchErr;
                }
              },
              wasm: async () => {
                console.log('[pvac-decrypt] wasm fallback');
                await ensureOffscreen();
                const r = await chrome.runtime.sendMessage({ target: 'offscreen', action: ACTION_DECRYPT, pvacSkB64, pvacPkB64, keyId: vault.getAddress(), cipherB64 }) as { value?: string; error?: string };
                if (r.error) throw new Error(r.error);
                return { value: r.value ?? '0' };
              },
            }))!;
            const rawValue = BigInt(decResult.value as string | number);
            console.log('[pvac-decrypt] decrypted=%d prover=%s elapsed=%dms', rawValue, decResult.prover ?? '?', Date.now() - t0);

            const balStr = formatAmountHuman(rawValue);
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
        case MSG_ENCRYPT_BALANCE: {
          if (!vault.isUnlocked()) { sendResponse({ error: 'locked' }); break; }
          const { amount } = payload as { amount: string };
          try {
            const amountRaw = parseAmountRaw(amount);
            if (amountRaw <= 0n) { sendResponse({ error: 'invalid amount' }); break; }

            // Create job and respond immediately
            const jobId = crypto.randomUUID();
            await setJob(jobId, { status: 'running', step: 'Ensuring PVAC key registered...' });
            sendResponse({ jobId });

            // Ensure PVAC pubkey is registered on-chain
            try {
              await ensurePvacRegistered();
            } catch (regErr) {
              await setJob(jobId, { status: 'error', error: (regErr as Error).message });
              break;
            }

            runJob(shieldJob(jobId, amountRaw));
          } catch (err) {
            sendResponse({ error: (err as Error).message });
          }
          break;
        }
        case MSG_DECRYPT_BALANCE: {
          if (!vault.isUnlocked()) { sendResponse({ error: 'locked' }); break; }
          const { amount: decAmt } = payload as { amount: string };

          // Validate upfront, then kick off async job
          let decAmountRaw: bigint;
          try {
            decAmountRaw = parseAmountRaw(decAmt);
            if (decAmountRaw <= 0n) { sendResponse({ error: 'invalid amount' }); break; }
          } catch { sendResponse({ error: 'invalid amount' }); break; }

          // Generate job ID and respond immediately so popup can close
          const jobId = crypto.randomUUID();
          await setJob(jobId, { status: 'running', step: 'Ensuring PVAC key registered...', startedAt: Date.now() });
          sendResponse({ jobId });

          // Ensure PVAC pubkey is registered on-chain
          try {
            await ensurePvacRegistered();
          } catch (err) {
            await setJob(jobId, { status: 'error', error: (err as Error).message });
            break;
          }

          // Run the heavy computation in the background
          runJob(unshieldJob(jobId, decAmountRaw));
          break;
        }
        case MSG_GET_JOB_STATUS: {
          const { jobId } = payload as { jobId: string };
          const data = await getJob(jobId);
          sendResponse(data ?? { status: 'unknown' });
          break;
        }
        case MSG_CANCEL_UNSHIELD:
        case MSG_CANCEL_JOB: {
          const { jobId } = payload as { jobId: string };
          await setJob(jobId, { status: 'cancelled' });
          await removeJob(jobId);
          await chrome.storage.local.remove(['activeUnshieldJob', 'activeUnshieldStart', 'activeShieldJob', 'activeShieldStart', 'activeStealthJob', 'activeStealthStart', 'activeClaimJob', 'activeClaimStart']);
          currentJobStorageKey = null;
          sendResponse({ success: true });
          break;
        }
        case MSG_SIGN_MESSAGE: {
          if (!vault.isUnlocked()) { sendResponse({ error: 'locked' }); break; }
          const msgBytes = new TextEncoder().encode(payload.message as string);
          const signature = vault.sign(msgBytes);
          sendResponse({ signature: toBase64(signature) });
          break;
        }
        case MSG_SEND_TRANSACTION: {
          if (!vault.isUnlocked()) { sendResponse({ error: 'locked' }); break; }
          const { to, amount, fee } = payload as { to: string; amount: string; fee?: string };
          const address = vault.getAddress();
          const balInfo = await rpc.getBalance(address);
          const nonce = balInfo.nonce + 1;
          const amountRaw = String(parseAmountRaw(amount));
          const defaultFee = await getDefaultFee();
          const tx = buildSignedTx({ from: address, to, amount: amountRaw, nonce, ou: fee ?? defaultFee, opType: 'standard' });
          const result = await rpc.submitTransaction(tx);
          sendResponse(result);
          break;
        }
        case MSG_CONTRACT_CALL: {
          if (!vault.isUnlocked()) { sendResponse({ error: 'locked' }); break; }
          const { contract, method, params } = payload as { contract: string; method: string; params: unknown[] };
          const result = await rpc.contractCall(contract, method, params ?? [], vault.getAddress());
          sendResponse(result);
          break;
        }
        case MSG_GET_ACTIVITY: {
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
        case MSG_DAPP_REQUEST: {
          const { method: dappMethod, params: dappParams, origin: dappOrigin } =
            payload as { method: string; params: unknown[]; origin: string };

          switch (dappMethod) {
            case 'octra_requestAccounts':
            case 'requestAccounts': {
              let freshlyUnlocked = false;
              if (!vault.isUnlocked()) {
                const unlocked = await ensureUnlocked();
                if (!unlocked) { sendResponse({ error: ERR_WALLET_LOCKED }); break; }
                freshlyUnlocked = true;
              }
              // If user just unlocked, auto-approve since they showed intent
              // Otherwise show approval popup for first-time connections
              if (!approvedOrigins.has(dappOrigin)) {
                if (!freshlyUnlocked) {
                  const approved = await requestUserApproval(APPROVAL_CONNECT, dappOrigin, {});
                  if (!approved) { sendResponse({ error: ERR_USER_REJECTED_CONNECTION }); break; }
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
                if (!unlocked) { sendResponse({ error: ERR_WALLET_LOCKED }); break; }
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
              sendResponse(getNetworkInfo(rpc.getRpcUrl()));
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
                if (!unlocked) { sendResponse({ error: ERR_WALLET_LOCKED }); break; }
              }
              sendResponse(toBase64(vault.getPublicKey()));
              break;
            }
            case 'octra_signMessage':
            case 'signMessage':
            case 'sign_message': {
              if (!vault.isUnlocked()) {
                const unlocked = await ensureUnlocked();
                if (!unlocked) { sendResponse({ error: ERR_WALLET_LOCKED }); break; }
              }
              const rawParam = (dappParams as unknown[])[0];
              const message = typeof rawParam === 'string' ? rawParam : (rawParam as any)?.message;
              if (!message || typeof message !== 'string') {
                sendResponse({ error: 'Invalid message' });
                break;
              }
              const approved = await requestUserApproval(APPROVAL_SIGN_MESSAGE, dappOrigin, { message });
              if (!approved) { sendResponse({ error: ERR_USER_REJECTED_SIGNATURE }); break; }
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
                if (!unlocked) { sendResponse({ error: ERR_WALLET_LOCKED }); break; }
              }
              const [txData] = dappParams as [{ to: string; amount: number; message?: string }];
              if (!txData?.to || txData.amount == null) {
                sendResponse({ error: ERR_INVALID_AMOUNT });
                break;
              }
              const txApproved = await requestUserApproval(APPROVAL_SEND_TX, dappOrigin, {
                to: txData.to,
                amount: txData.amount,
                message: txData.message,
              });
              if (!txApproved) { sendResponse({ error: ERR_USER_REJECTED_TX }); break; }
              const amountRaw = String(Math.round(txData.amount * 1_000_000));
              const dappAddr = vault.getAddress();
              const balInfo = await rpc.getBalance(dappAddr);
              const nonce = balInfo.nonce + 1;
              const defaultFee = await getDefaultFee();
              const txPayload = buildSignedTx({
                from: dappAddr, to: txData.to, amount: amountRaw, nonce,
                ou: defaultFee, opType: 'standard',
                ...(txData.message ? { message: txData.message } : {}),
              });
              const submitRes = await rpc.submitTransaction(txPayload);
              sendResponse({ txHash: submitRes.hash, success: true });
              break;
            }
            case 'octra_callContract':
            case 'callContract':
            case 'call_contract': {
              if (!vault.isUnlocked()) {
                const unlocked = await ensureUnlocked();
                if (!unlocked) { sendResponse({ error: ERR_WALLET_LOCKED }); break; }
              }
              const [callData] = dappParams as [{ contract?: string; address?: string; method: string; params: unknown[]; amount?: string; ou?: string; caller?: string }];
              const contractAddr = callData.contract || callData.address;
              if (!contractAddr || !callData?.method) {
                sendResponse({ error: ERR_INVALID_CALLDATA });
                break;
              }
              // Read-only calls (no amount) go through view path — no approval needed
              if (!callData.amount || callData.amount === '0') {
                const caller = callData.caller || vault.getAddress();
                const viewRes = await rpc.rpcCall('contract_call', [contractAddr, callData.method, callData.params ?? [], caller]);
                sendResponse(viewRes);
                break;
              }
              // State-changing calls need approval
              const callApproved = await requestUserApproval(APPROVAL_CALL_CONTRACT, dappOrigin, {
                contract: contractAddr,
                method: callData.method,
                params: callData.params,
                amount: callData.amount,
              });
              if (!callApproved) { sendResponse({ error: ERR_USER_REJECTED_CONTRACT }); break; }
              const callAddr = vault.getAddress();
              const balInfo2 = await rpc.getBalance(callAddr);
              const nonce2 = balInfo2.nonce + 1;
              const msgField = JSON.stringify(callData.params ?? []);
              const defaultFee = await getDefaultFee();
              const callPayload = buildSignedTx({
                from: callAddr, to: contractAddr, amount: callData.amount, nonce: nonce2,
                ou: callData.ou || defaultFee, opType: 'call',
                encryptedData: callData.method, message: msgField,
              });
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
            case 'octra_signTransaction':
            case 'signTransaction':
            case 'sign_transaction': {
              console.log('[wallet] octra_signTransaction raw payload:', JSON.stringify(dappParams));
              if (!vault.isUnlocked()) {
                const unlocked = await ensureUnlocked();
                if (!unlocked) { sendResponse({ error: ERR_WALLET_LOCKED }); break; }
              }
              const [signTxData] = dappParams as [{
                from: string; to_: string; amount: string; nonce: number;
                ou: string; timestamp?: number; op_type: string;
                encrypted_data?: string; message?: string;
                dapp_metadata?: { title?: string; description?: string };
              }];
              if (!signTxData?.from || !signTxData?.to_) {
                sendResponse({ error: 'Invalid transaction data' });
                break;
              }
              const signTxApproved = await requestUserApproval(APPROVAL_SEND_TX, dappOrigin, {
                to: signTxData.to_,
                amount: signTxData.amount,
                message: signTxData.message || signTxData.encrypted_data,
                description: signTxData.dapp_metadata?.description,
              });
              if (!signTxApproved) { sendResponse({ error: ERR_USER_REJECTED_TX }); break; }
              try {
                // Use the dapp's from address (not the vault's) so the signature matches
                const from = signTxData.from || vault.getAddress();
                // Floor timestamp — node canonical format uses integer + ".0" suffix
                const ts = Math.floor(signTxData.timestamp ?? Date.now() / 1000);
                const canonical = buildCanonical({
                  from,
                  to: signTxData.to_,
                  amount: signTxData.amount ?? '0',
                  nonce: signTxData.nonce ?? 1,
                  ou: signTxData.ou ?? '1000',
                  opType: signTxData.op_type ?? 'call',
                  ...(signTxData.encrypted_data !== undefined ? { encryptedData: signTxData.encrypted_data } : {}),
                  ...(signTxData.message !== undefined ? { message: signTxData.message } : {}),
                }, ts);
                console.log('[wallet] octra_signTransaction canonical:', canonical);
                const sig = vault.sign(new TextEncoder().encode(canonical));
                sendResponse({
                  from,
                  to_: signTxData.to_,
                  amount: signTxData.amount ?? '0',
                  nonce: signTxData.nonce ?? 1,
                  ou: signTxData.ou ?? '1000',
                  timestamp: ts,
                  op_type: signTxData.op_type ?? 'call',
                  ...(signTxData.encrypted_data !== undefined ? { encrypted_data: signTxData.encrypted_data } : {}),
                  ...(signTxData.message !== undefined ? { message: signTxData.message } : {}),
                  signature: toBase64(sig),
                  public_key: toBase64(vault.getPublicKey()),
                });
              } catch (e) { sendResponse({ error: (e as Error).message }); }
              break;
            }
            default: {
              // --- PVAC / FHE proof methods for dApps ---
              // Helper: run a PVAC operation through the prover cascade
              async function runPvacOp(
                operation: string,
                extra: Record<string, string>,
                wasmFallback: () => Promise<Record<string, unknown>>,
              ): Promise<Record<string, unknown>> {
                const { skB64, pkB64 } = await vault.requirePvacKeys();
                const payload: Record<string, string> = { operation, pvac_sk_b64: skB64, pvac_pk_b64: pkB64, ...extra };
                // wasm provided → always returns non-null
                return (await routeProof({ operation, payload, wasm: wasmFallback }))!;
              }

              // Encrypt a value and produce a bound zero proof
              if (dappMethod === 'octra_pvac_encryptProve' || dappMethod === 'pvac_encryptProve') {
                if (!vault.isUnlocked()) { sendResponse({ error: ERR_WALLET_LOCKED }); break; }
                const [epParams] = dappParams as [{ value: number; rangeProof?: boolean }];
                if (epParams?.value == null) { sendResponse({ error: ERR_MISSING_VALUE }); break; }
                const epApproved = await requestUserApproval(APPROVAL_PVAC_PROVE, dappOrigin, { operation: 'Encrypt & prove a value', detail: `Value: ${epParams.value}` });
                if (!epApproved) { sendResponse({ error: ERR_USER_REJECTED_REQUEST }); break; }
                try {
                  const val = BigInt(epParams.value);
                  const blinding = crypto.getRandomValues(new Uint8Array(32));
                  // Route through shield operation — encrypts + Pedersen commitment + bound zero proof
                  const result = await runPvacOp('shield', {
                    amountRaw: String(epParams.value),
                    seedB64: toBase64(crypto.getRandomValues(new Uint8Array(32))),
                    blindingB64: toBase64(blinding),
                  }, async () => {
                    const { skB64, pkB64 } = await vault.requirePvacKeys();
                    await initPvacFromKeys(fromBase64(skB64), fromBase64(pkB64));
                    const seed = crypto.getRandomValues(new Uint8Array(32));
                    const ct = encryptValue(val, seed);
                    const commitment = pedersenCommit(val, blinding);
                    const zp = makeZeroProofBound(ct, val, blinding);
                    return {
                      cipher: toBase64(ct),
                      amount_commitment: toBase64(commitment),
                      zero_proof: toBase64(zp),
                      blinding: toBase64(blinding),
                    };
                  });
                  const response: Record<string, unknown> = {
                    ciphertext: result.cipher,
                    amount_commitment: result.amount_commitment,
                    zero_proof: result.zero_proof,
                    blinding: result.blinding,
                  };
                  // Optionally generate range proof in the same call
                  if (epParams.rangeProof) {
                    const rpResult = await runPvacOp('range_proof', {
                      cipher_b64: result.cipher,
                      amountRaw: String(epParams.value),
                    }, async () => {
                      const { skB64, pkB64 } = await vault.requirePvacKeys();
                      await initPvacFromKeys(fromBase64(skB64), fromBase64(pkB64));
                      const ct = fromBase64((result.cipher ?? '').startsWith('hfhe_v1|') ? (result.cipher as string).slice(8) : result.cipher as string);
                      const proof = makeRangeProof(ct, val);
                      return { proof: toBase64(proof) };
                    });
                    response.range_proof = rpResult.proof;
                  }
                  sendResponse(response);
                } catch (e) { sendResponse({ error: (e as Error).message }); }
                break;
              }
              if (dappMethod === 'octra_pvac_encrypt' || dappMethod === 'pvac_encrypt') {
                if (!vault.isUnlocked()) { sendResponse({ error: ERR_WALLET_LOCKED }); break; }
                const [encParams] = dappParams as [{ value: number }];
                if (encParams?.value == null) { sendResponse({ error: ERR_MISSING_VALUE }); break; }
                const encApproved = await requestUserApproval(APPROVAL_PVAC_PROVE, dappOrigin, { operation: 'Encrypt a value', detail: `Value: ${encParams.value}` });
                if (!encApproved) { sendResponse({ error: ERR_USER_REJECTED_REQUEST }); break; }
                try {
                  const seed = crypto.getRandomValues(new Uint8Array(32));
                  const seedB64 = toBase64(seed);
                  const result = await runPvacOp('encrypt', {
                    amountRaw: String(encParams.value),
                    seedB64,
                  }, async () => {
                    const { skB64, pkB64 } = await vault.requirePvacKeys();
                    await initPvacFromKeys(fromBase64(skB64), fromBase64(pkB64));
                    const ct = encryptValue(BigInt(encParams.value), seed);
                    return { ciphertext: toBase64(ct) };
                  });
                  sendResponse({ ciphertext: result.ciphertext ?? result.cipher });
                } catch (e) { sendResponse({ error: (e as Error).message }); }
                break;
              }
              if (dappMethod === 'octra_pvac_decrypt' || dappMethod === 'pvac_decrypt') {
                if (!vault.isUnlocked()) { sendResponse({ error: ERR_WALLET_LOCKED }); break; }
                const [decParams] = dappParams as [{ ciphertext: string }];
                if (!decParams?.ciphertext) { sendResponse({ error: ERR_MISSING_CIPHERTEXT }); break; }
                const approved = await requestUserApproval(APPROVAL_PVAC_DECRYPT, dappOrigin, { operation: 'Decrypt a private value' });
                if (!approved) { sendResponse({ error: ERR_USER_REJECTED_REQUEST }); break; }
                try {
                  const result = await runPvacOp('decrypt', {
                    cipher_b64: decParams.ciphertext,
                  }, async () => {
                    const { skB64, pkB64 } = await vault.requirePvacKeys();
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
                const rpApproved = await requestUserApproval(APPROVAL_PVAC_PROVE, dappOrigin, { operation: 'Generate range proof' });
                if (!rpApproved) { sendResponse({ error: 'User rejected request' }); break; }
                try {
                  const result = await runPvacOp('range_proof', {
                    cipher_b64: rpParams.ciphertext,
                    amountRaw: String(rpParams.value),
                  }, async () => {
                    const { skB64, pkB64 } = await vault.requirePvacKeys();
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
                const cmApproved = await requestUserApproval(APPROVAL_PVAC_PROVE, dappOrigin, { operation: 'Create Pedersen commitment', detail: `Value: ${cmParams.value}` });
                if (!cmApproved) { sendResponse({ error: 'User rejected request' }); break; }
                try {
                  const blinding = cmParams.blinding ? fromBase64(cmParams.blinding) : crypto.getRandomValues(new Uint8Array(32));
                  const blindingB64 = toBase64(blinding);
                  const result = await runPvacOp('commit', {
                    amountRaw: String(cmParams.value),
                    blindingB64,
                  }, async () => {
                    const { skB64, pkB64 } = await vault.requirePvacKeys();
                    await initPvacFromKeys(fromBase64(skB64), fromBase64(pkB64));
                    const commitment = pedersenCommit(BigInt(cmParams.value), blinding);
                    return { commitment: toBase64(commitment), blinding: blindingB64 };
                  });
                  sendResponse({ commitment: result.commitment, blinding: result.blinding ?? blindingB64 });
                } catch (e) { sendResponse({ error: (e as Error).message }); }
                break;
              }
              // Homomorphic add: add two ciphertexts
              if (dappMethod === 'octra_pvac_ctAdd' || dappMethod === 'pvac_ctAdd') {
                if (!vault.isUnlocked()) { sendResponse({ error: ERR_WALLET_LOCKED }); break; }
                const [addParams] = dappParams as [{ a: string; b: string }];
                if (!addParams?.a || !addParams?.b) { sendResponse({ error: 'Missing ciphertext a or b' }); break; }
                try {
                  const { skB64, pkB64 } = await vault.requirePvacKeys();
                  await initPvacFromKeys(fromBase64(skB64), fromBase64(pkB64));
                  const result = ctAdd(fromBase64(addParams.a), fromBase64(addParams.b));
                  sendResponse({ ciphertext: toBase64(result) });
                } catch (e) { sendResponse({ error: (e as Error).message }); }
                break;
              }
              // Homomorphic multiply: multiply two ciphertexts
              if (dappMethod === 'octra_pvac_ctMul' || dappMethod === 'pvac_ctMul') {
                if (!vault.isUnlocked()) { sendResponse({ error: ERR_WALLET_LOCKED }); break; }
                const [mulParams] = dappParams as [{ a: string; b: string }];
                if (!mulParams?.a || !mulParams?.b) { sendResponse({ error: 'Missing ciphertext a or b' }); break; }
                try {
                  const { skB64, pkB64 } = await vault.requirePvacKeys();
                  await initPvacFromKeys(fromBase64(skB64), fromBase64(pkB64));
                  const seed = crypto.getRandomValues(new Uint8Array(32));
                  const result = ctMul(fromBase64(mulParams.a), fromBase64(mulParams.b), seed);
                  sendResponse({ ciphertext: toBase64(result) });
                } catch (e) { sendResponse({ error: (e as Error).message }); }
                break;
              }
              // Homomorphic subtract: subtract two ciphertexts
              if (dappMethod === 'octra_pvac_ctSub' || dappMethod === 'pvac_ctSub') {
                if (!vault.isUnlocked()) { sendResponse({ error: ERR_WALLET_LOCKED }); break; }
                const [subParams] = dappParams as [{ a: string; b: string }];
                if (!subParams?.a || !subParams?.b) { sendResponse({ error: 'Missing ciphertext a or b' }); break; }
                try {
                  const { skB64, pkB64 } = await vault.requirePvacKeys();
                  await initPvacFromKeys(fromBase64(skB64), fromBase64(pkB64));
                  const result = ctSub(fromBase64(subParams.a), fromBase64(subParams.b));
                  sendResponse({ ciphertext: toBase64(result) });
                } catch (e) { sendResponse({ error: (e as Error).message }); }
                break;
              }
              // Add constant: add a plaintext constant to a ciphertext
              if (dappMethod === 'octra_pvac_ctAddConst' || dappMethod === 'pvac_ctAddConst') {
                if (!vault.isUnlocked()) { sendResponse({ error: ERR_WALLET_LOCKED }); break; }
                const [acParams] = dappParams as [{ ciphertext: string; value: number }];
                if (!acParams?.ciphertext || acParams?.value == null) { sendResponse({ error: 'Missing ciphertext or value' }); break; }
                try {
                  const { skB64, pkB64 } = await vault.requirePvacKeys();
                  await initPvacFromKeys(fromBase64(skB64), fromBase64(pkB64));
                  const result = ctAddConst(fromBase64(acParams.ciphertext), BigInt(acParams.value));
                  sendResponse({ ciphertext: toBase64(result) });
                } catch (e) { sendResponse({ error: (e as Error).message }); }
                break;
              }
              // Subtract constant: subtract a plaintext constant from a ciphertext
              if (dappMethod === 'octra_pvac_ctSubConst' || dappMethod === 'pvac_ctSubConst') {
                if (!vault.isUnlocked()) { sendResponse({ error: ERR_WALLET_LOCKED }); break; }
                const [scParams] = dappParams as [{ ciphertext: string; value: number }];
                if (!scParams?.ciphertext || scParams?.value == null) { sendResponse({ error: 'Missing ciphertext or value' }); break; }
                try {
                  const { skB64, pkB64 } = await vault.requirePvacKeys();
                  await initPvacFromKeys(fromBase64(skB64), fromBase64(pkB64));
                  const result = ctSubConst(fromBase64(scParams.ciphertext), BigInt(scParams.value));
                  sendResponse({ ciphertext: toBase64(result) });
                } catch (e) { sendResponse({ error: (e as Error).message }); }
                break;
              }
              // Stealth transfer: encrypt amount + subtract from balance + range proofs (single approval)
              if (dappMethod === 'octra_pvac_stealthTransfer' || dappMethod === 'pvac_stealthTransfer') {
                if (!vault.isUnlocked()) { sendResponse({ error: ERR_WALLET_LOCKED }); break; }
                const [stParams] = dappParams as [{ balance: string; amount: number; balanceValue: number }];
                if (!stParams?.balance || stParams?.amount == null || stParams?.balanceValue == null) {
                  sendResponse({ error: 'Missing balance, amount, or balanceValue' }); break;
                }
                const stAmt = BigInt(stParams.amount);
                const stNewValue = BigInt(stParams.balanceValue) - stAmt;
                if (stNewValue < 0n) { sendResponse({ error: `Insufficient balance: have ${stParams.balanceValue}, need ${stParams.amount}` }); break; }
                const stApproved = await requestUserApproval(APPROVAL_PVAC_PROVE, dappOrigin, {
                  operation: 'Stealth transfer',
                  detail: `Send ${stParams.amount} (new balance: ${stNewValue})`,
                });
                if (!stApproved) { sendResponse({ error: ERR_USER_REJECTED_REQUEST }); break; }
                try {
                  const { skB64, pkB64 } = await vault.requirePvacKeys();
                  await initPvacFromKeys(fromBase64(skB64), fromBase64(pkB64));
                  const stripPrefix = (s: string) => s.startsWith('hfhe_v1|') ? s.slice(8) : s;

                  // 1. Encrypt delta + zero proof (routed through accelerator)
                  const deltaResult = await runPvacOp('shield', {
                    amountRaw: String(stParams.amount),
                    seedB64: toBase64(crypto.getRandomValues(new Uint8Array(32))),
                    blindingB64: toBase64(crypto.getRandomValues(new Uint8Array(32))),
                  }, async () => {
                    const deltaSeed = crypto.getRandomValues(new Uint8Array(32));
                    const deltaCt = encryptValue(stAmt, deltaSeed);
                    const deltaBlinding = crypto.getRandomValues(new Uint8Array(32));
                    const deltaCommitment = pedersenCommit(stAmt, deltaBlinding);
                    const deltaZp = makeZeroProofBound(deltaCt, stAmt, deltaBlinding);
                    return {
                      cipher: toBase64(deltaCt),
                      amount_commitment: toBase64(deltaCommitment),
                      zero_proof: toBase64(deltaZp),
                      blinding: toBase64(deltaBlinding),
                    };
                  });
                  const deltaCt = fromBase64(stripPrefix(deltaResult.cipher));

                  // 2. Subtract from balance (fast WASM arithmetic)
                  const newBalCt = ctSub(fromBase64(stripPrefix(stParams.balance)), deltaCt);

                  // 3. Range proofs (routed through accelerator)
                  const rpDeltaResult = await runPvacOp('range_proof', {
                    cipher_b64: deltaResult.cipher,
                    amountRaw: String(stParams.amount),
                  }, async () => {
                    const rpDelta = makeRangeProof(deltaCt, stAmt);
                    return { proof: toBase64(rpDelta) };
                  });

                  const rpBalResult = await runPvacOp('range_proof', {
                    cipher_b64: stripPrefix(toBase64(newBalCt)).startsWith('hfhe_v1|') ? stripPrefix(toBase64(newBalCt)) : toBase64(newBalCt),
                    amountRaw: String(Number(stNewValue)),
                  }, async () => {
                    const rpBal = makeRangeProof(newBalCt, stNewValue);
                    return { proof: toBase64(rpBal) };
                  });

                  sendResponse({
                    ciphertext: deltaResult.cipher,
                    amount_commitment: deltaResult.amount_commitment,
                    zero_proof: deltaResult.zero_proof,
                    blinding: deltaResult.blinding,
                    new_balance: toBase64(newBalCt),
                    range_proof_delta: rpDeltaResult.proof,
                    range_proof_balance: rpBalResult.proof,
                    new_balance_value: Number(stNewValue),
                  });
                } catch (e) { sendResponse({ error: (e as Error).message }); }
                break;
              }

              if (dappMethod === 'octra_pvac_zeroProof' || dappMethod === 'pvac_zeroProof') {
                if (!vault.isUnlocked()) { sendResponse({ error: 'Wallet is locked' }); break; }
                const [zpParams] = dappParams as [{ ciphertext: string; value: number; blinding: string }];
                if (!zpParams?.ciphertext || zpParams?.value == null || !zpParams?.blinding) { sendResponse({ error: 'Missing params' }); break; }
                const zpApproved = await requestUserApproval(APPROVAL_PVAC_PROVE, dappOrigin, { operation: 'Generate zero-knowledge proof' });
                if (!zpApproved) { sendResponse({ error: 'User rejected request' }); break; }
                try {
                  const result = await runPvacOp('zero_proof', {
                    cipher_b64: zpParams.ciphertext,
                    amountRaw: String(zpParams.value),
                    blindingB64: zpParams.blinding,
                  }, async () => {
                    const { skB64, pkB64 } = await vault.requirePvacKeys();
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

              // Filter proof records to only the requested indices
              function filterProofRecords(result: Record<string, unknown>, indices?: number[]): Record<string, unknown> {
                if (!indices || indices.length === 0) return result;
                const records = result.records as Array<Record<string, unknown>> | undefined;
                if (!records) return result;
                const indexSet = new Set(indices);
                return { ...result, records: records.filter((_, i) => indexSet.has(i)) };
              }

              // ── zkTLS Proof (Jolt) ──────────────────────────────────
              // Records a TLS session with the given URL, proves the decryption
              // using the Jolt zkVM (via Octane Accelerator), and returns the
              // plaintext application data.
              if (dappMethod === 'octra_requestZktlsProofJolt' || dappMethod === 'requestZktlsProofJolt') {
                if (!vault.isUnlocked()) {
                  const unlocked = await ensureUnlocked();
                  if (!unlocked) { sendResponse({ error: ERR_WALLET_LOCKED }); break; }
                }
                const [zktlsParams] = dappParams as [{ url: string; headers?: Record<string, string>; id?: string; regenerate?: boolean; records?: number[] }];
                if (!zktlsParams?.url) { sendResponse({ error: 'Missing url parameter' }); break; }

                // Check cache if an ID was provided and regenerate is not set
                const proofId = zktlsParams.id;
                if (proofId && !zktlsParams.regenerate) {
                  try {
                    const entry = await getCachedProof(proofId);
                    if (entry) {
                      const ageSec = Math.floor((Date.now() - entry.timestamp) / 1000);
                      console.log('[zktls] returning cached proof for id=%s (age=%ds)', proofId, ageSec);
                      const cachedResult = { ...(entry.result as Record<string, unknown>), _cached: true, _cacheAge: ageSec };
                      sendResponse(filterProofRecords(cachedResult, zktlsParams.records));
                      break;
                    }
                  } catch (e) { console.warn('[zktls] IDB read error:', (e as Error).message); }
                }

                // Fail-fast: check prover availability before showing approval dialog
                const nativeReady = await isProverAvailable();
                const remoteReady = await isRemoteProverConfigured();
                if (!nativeReady && !remoteReady) {
                  sendResponse({ error: 'No prover available. Start the Octane Accelerator or configure a remote prover.' });
                  break;
                }

                const zktlsApproved = await requestUserApproval(
                  APPROVAL_ZKTLS_PROVE,
                  dappOrigin,
                  {
                    operation: 'Prove TLS session (Jolt zkVM)',
                    detail: `URL: ${zktlsParams.url}`,
                    proofId: proofId ?? null,
                  }
                );
                if (!zktlsApproved) { sendResponse({ error: ERR_USER_REJECTED_REQUEST }); break; }

                // Track as in-progress in activity tab
                const zktlsJobId = `zktls_${Date.now()}`;
                await chrome.storage.local.set({ [SK_ACTIVE_ZKTLS_JOB]: zktlsJobId, [SK_ACTIVE_ZKTLS_START]: Date.now() });

                try {
                  const result = await routeProof({
                    operation: 'jolt_zktls_prove',
                    payload: {
                      operation: 'jolt_zktls_prove',
                      url: zktlsParams.url,
                      headers: JSON.stringify(zktlsParams.headers ?? {}),
                      ...(zktlsParams.records && zktlsParams.records.length > 0 ? { records: zktlsParams.records } : {}),
                    },
                    onStatus: (step) => {
                      console.log('[zktls] %s', step);
                      // Update job status so activity tab shows current step
                      setJob(zktlsJobId, { status: 'running', step });
                    },
                  });
                  if (!result) {
                    sendResponse({ error: 'No prover available. Start the Octane Accelerator or configure a remote prover.' });
                  } else {
                    // Cache the result in IndexedDB if an ID was provided
                    if (proofId) {
                      try {
                        await setCachedProof({
                          id: proofId,
                          result,
                          timestamp: Date.now(),
                          url: zktlsParams.url,
                          headers: zktlsParams.headers ?? {},
                          origin: dappOrigin,
                        });
                        console.log('[zktls] cached proof in IDB for id=%s', proofId);
                      } catch (e) { console.warn('[zktls] IDB write error:', (e as Error).message); }
                    }
                    sendResponse(filterProofRecords(result, zktlsParams.records));
                  }
                } catch (e) { sendResponse({ error: (e as Error).message }); }
                finally {
                  await removeJob(zktlsJobId);
                  await chrome.storage.local.remove([SK_ACTIVE_ZKTLS_JOB, SK_ACTIVE_ZKTLS_START]);
                }
                break;
              }

              // Generic RPC wrapper methods used by dApps
              if (dappMethod === 'octra_request' || dappMethod === 'request') {
                const [innerReq] = dappParams as [{ method: string; params: unknown[] }];
                if (innerReq?.method) {
                  const result = await rpc.rpcCall(innerReq.method, innerReq.params ?? []);
                  sendResponse(result);
                } else {
                  sendResponse({ error: 'Invalid octra_request: missing method' });
                }
                break;
              }
              if (dappMethod === 'octra_jsonRpc' || dappMethod === 'jsonRpc') {
                const [jsonRpcReq] = dappParams as [{ jsonrpc?: string; id?: number; method: string; params: unknown[] }];
                if (jsonRpcReq?.method) {
                  const result = await rpc.rpcCall(jsonRpcReq.method, jsonRpcReq.params ?? []);
                  sendResponse({ jsonrpc: '2.0', id: jsonRpcReq.id ?? 1, result });
                } else {
                  sendResponse({ jsonrpc: '2.0', id: 1, error: { code: -32600, message: 'Invalid Request' } });
                }
                break;
              }
              if (dappMethod === 'octra_rpc' || dappMethod === 'rpc') {
                const [rpcMethod, ...rpcParams] = dappParams as [string, ...unknown[]];
                if (rpcMethod) {
                  const result = await rpc.rpcCall(rpcMethod, rpcParams);
                  sendResponse(result);
                } else {
                  sendResponse({ error: 'Invalid octra_rpc: missing method' });
                }
                break;
              }

              // Fall through to RPC passthrough for node-level methods
              const RPC_PASSLIST = [
                'octra_balance', 'octra_tokensByAddress', 'octra_account',
                'octra_transaction', 'octra_recommendedFee', 'node_status',
                'contract_call', 'octra_submit',
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
        case MSG_RPC_PASSTHROUGH: {
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
        case MSG_STEALTH_SEND: {
          if (!vault.isUnlocked()) { sendResponse({ error: 'locked' }); break; }
          const { to, amount } = payload as { to: string; amount: string };
          try {
            const amountRaw = parseAmountRaw(amount);
            if (amountRaw <= 0n) { sendResponse({ error: 'invalid amount' }); break; }

            // Check recipient has PVAC pubkey registered (required to receive stealth)
            const recipientPvac = await rpc.getPvacPubkey(to);
            if (!recipientPvac) {
              sendResponse({ error: 'recipient_no_pvac' });
              break;
            }

            // Create job and respond immediately
            const jobId = crypto.randomUUID();
            await setJob(jobId, { status: 'running', step: 'Ensuring PVAC key registered...' });
            sendResponse({ jobId });

            // Ensure PVAC pubkey is registered on-chain
            try {
              await ensurePvacRegistered();
            } catch (regErr) {
              await setJob(jobId, { status: 'error', error: (regErr as Error).message });
              break;
            }

            // Run stealth send in background
            runJob(stealthSendJob(jobId, to, amountRaw));
          } catch (err) {
            sendResponse({ error: (err as Error).message });
          }
          break;
        }
        case MSG_STEALTH_SCAN: {
          if (!vault.isUnlocked()) { sendResponse({ error: ERR_LOCKED }); break; }
          withStealthLock(async () => {
            const addr = vault.getAddress();
            const epochKey = SK_STEALTH_LAST_EPOCH + addr;
            const pendingKey = SK_STEALTH_PENDING + addr;

            // Load last scanned epoch
            const stored = await chrome.storage.local.get([epochKey, pendingKey]);
            const lastEpoch = (stored[epochKey] as number) ?? 0;
            const existingPending = (stored[pendingKey] as Array<Record<string, unknown>>) ?? [];

            const x25519Sk = vault.deriveX25519Sk();
            const { outputs } = await rpc.getStealthOutputs(lastEpoch);
            const newFound: Array<Record<string, unknown>> = [];
            // Only advance epoch for outputs we definitively handled (matched ours or confirmed claimed).
            // Skip-outputs (bad tag, bad eph, errors) stay behind so they get re-scanned.
            let maxHandledEpoch = lastEpoch;

            let skippedClaimed = 0;
            let skippedBadTag = 0;
            let skippedBadEph = 0;
            let matched = 0;

            for (const out of outputs) {
              const epoch = Number(out.epoch_id ?? 0);

              if (Number(out.claimed ?? 0) !== 0) {
                skippedClaimed++;
                if (epoch > maxHandledEpoch) maxHandledEpoch = epoch;
                continue;
              }
              try {
                const ephB64 = String(out.eph_pub ?? '');
                const ephRaw = fromBase64(ephB64);
                if (ephRaw.length !== 32) { skippedBadEph++; continue; }
                const tagHex = String(out.stealth_tag ?? '');
                const expectedTag = new Uint8Array(16);
                for (let i = 0; i < 16; i++)
                  expectedTag[i] = parseInt(tagHex.slice(i*2, i*2+2), 16);

                const shared = await checkStealthOutput(x25519Sk, ephRaw, expectedTag);
                if (!shared) { skippedBadTag++; continue; }

                matched++;
                if (epoch > maxHandledEpoch) maxHandledEpoch = epoch;
                newFound.push({
                  id: out.id,
                  epoch,
                  sender: out.sender_addr ?? '',
                  tx_hash: out.tx_hash ?? '',
                  eph_pub: ephB64,
                  enc_amount: out.enc_amount ?? '',
                });
              } catch (e) { console.warn('[stealth-scan] error processing output %s: %s', out.id, (e as Error).message); continue; }
            }

            // Merge new discoveries with existing pending (dedup by id)
            const existingIds = new Set(existingPending.map(o => o.id));
            const merged = [...existingPending, ...newFound.filter(o => !existingIds.has(o.id))];

            // Only advance epoch for outputs we handled (matched ours or confirmed claimed).
            const nextEpoch = maxHandledEpoch > lastEpoch ? maxHandledEpoch + 1 : lastEpoch;
            if (matched > 0 || nextEpoch !== lastEpoch) {
              console.log('[stealth-scan] scan=%d matched=%d claimed=%d badTag=%d pending=%d epoch=%d→%d', outputs.length, matched, skippedClaimed, skippedBadTag, merged.length, lastEpoch, nextEpoch);
            }
            await chrome.storage.local.set({
              [epochKey]: nextEpoch,
              [pendingKey]: merged,
            });

            return merged;
          }).then(merged => {
            sendResponse({ outputs: merged });
          }).catch(err => {
            console.error('[stealth-scan] fatal error: %s', (err as Error).message);
            sendResponse({ error: (err as Error).message });
          });
          break;
        }
        case MSG_STEALTH_CLAIM: {
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
            await setJob(jobId, { status: 'running', step: 'Ensuring PVAC key registered...' });
            sendResponse({ jobId, amount: String(decResult.amount) });

            // Remove claimed output from pending list (serialized to avoid races)
            const claimAddr = vault.getAddress();
            withStealthLock(async () => {
              const pendingKey = SK_STEALTH_PENDING + claimAddr;
              const { [pendingKey]: pending } = await chrome.storage.local.get(pendingKey);
              if (Array.isArray(pending)) {
                const filtered = pending.filter((o: Record<string, unknown>) => o.id !== id);
                await chrome.storage.local.set({ [pendingKey]: filtered });
              }
            });

            // Ensure PVAC pubkey is registered on-chain
            try {
              await ensurePvacRegistered();
            } catch (regErr) {
              await setJob(jobId, { status: 'error', error: (regErr as Error).message });
              break;
            }

            // Run claim job
            runJob(stealthClaimJob(jobId, id, claimSecret, decResult.amount, decResult.blinding));
          } catch (err) {
            sendResponse({ error: (err as Error).message });
          }
          break;
        }
        case MSG_IMPORT_PAIRING: {
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
        case MSG_REMOVE_PAIRING: {
          await chrome.storage.local.remove('pairingConfig');
          sendResponse({ ok: true });
          break;
        }
        case MSG_GET_PROVER_STATUS: {
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
        case MSG_SET_PROVER_MODE: {
          const { mode } = payload as { mode: string };
          await chrome.storage.local.set({ proverMode: mode });
          // Invalidate prover cache so next balance refresh respects new mode
          invalidateProverCache();
          sendResponse({ ok: true });
          break;
        }
        case MSG_FETCH_CIRCLE_ASSET: {
          const { circleId, path } = payload as { circleId: string; path: string };
          const asset = await rpc.fetchCircleAsset(circleId, path);
          sendResponse(asset);
          break;
        }
        case MSG_GET_NFT_CONTENT: {
          if (!vault.isUnlocked()) { sendResponse({ error: 'locked' }); break; }
          const { contractAddr } = payload as { contractAddr: string };
          const caller = vault.getAddress();
          try {
            // Get contract info: name|symbol|totalMinted|maxSupply|royaltyBps
            const infoResp = await rpc.rpcCall('contract_call', [contractAddr, 'get_contract_info', [], caller]) as Record<string, unknown>;
            const infoRaw = String(infoResp.result ?? infoResp);
            const parts = infoRaw.split('|');
            const name = parts[0] ?? '';
            const symbol = parts[1] ?? '';
            const totalMinted = parseInt(parts[2] ?? '0', 10);
            const maxSupply = parseInt(parts[3] ?? '0', 10);
            const royaltyBps = parseInt(parts[4] ?? '0', 10);

            // Get token URI from token 0 to derive metadata circle
            let metaCircle: string | null = null;
            let imgUri: string | null = null;
            try {
              const tokenUriResp = await rpc.rpcCall('contract_call', [contractAddr, 'token_uri', [0], caller]) as Record<string, unknown>;
              const tokenUri0 = String(tokenUriResp.result ?? tokenUriResp);
              if (tokenUri0 && tokenUri0.startsWith('oct://')) {
                metaCircle = tokenUri0.replace(/^oct:\/\//, '').split('/')[0];
                // Fetch first token metadata to get image URI
                const metaPath = tokenUri0.replace(/^oct:\/\/[^/]+/, '') || '/0.json';
                const metaAsset = await rpc.fetchCircleAsset(metaCircle, metaPath);
                if (metaAsset.bodyB64) {
                  const metaJson = JSON.parse(atob(metaAsset.bodyB64));
                  imgUri = metaJson.image ?? null;
                }
              }
            } catch { /* token 0 may not exist yet */ }

            // Determine image circle
            let imgCircle: string | null = null;
            if (imgUri && imgUri.startsWith('oct://')) {
              imgCircle = imgUri.replace(/^oct:\/\//, '').split('/')[0];
            }

            // Get all token owners
            const tokens: Array<{ id: number; owner: string; isMine: boolean }> = [];
            for (let i = 0; i < totalMinted; i++) {
              try {
                const ownerResp = await rpc.rpcCall('contract_call', [contractAddr, 'owner_of', [i], caller]) as Record<string, unknown>;
                const owner = String(ownerResp.result ?? ownerResp);
                tokens.push({ id: i, owner, isMine: owner === caller });
              } catch { /* skip */ }
            }

            sendResponse({
              name, symbol, totalMinted, maxSupply, royaltyBps,
              metaCircle, imgCircle, imgUri,
              tokens,
              callerAddr: caller,
            });
          } catch (err) {
            sendResponse({ error: (err as Error).message ?? 'failed to load NFT content' });
          }
          break;
        }
        case MSG_GET_ZKTLS_CLAIMS: {
          try {
            const claims = await getAllCachedProofs();
            claims.sort((a, b) => b.timestamp - a.timestamp);
            sendResponse({ claims });
          } catch (e) {
            sendResponse({ claims: [], error: (e as Error).message });
          }
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
        await setJob(msg.jobId, { status: 'running', step: msg.step });
      } else if (msg.type === 'jobError' && msg.jobId) {
        await setJob(msg.jobId, { status: 'error', error: msg.error });
      }
    });
    port.onDisconnect.addListener(() => { offscreenPort = null; });
  }
});



let currentJobStorageKey: string | null = null;
