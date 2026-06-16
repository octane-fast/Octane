/**
 * Centralized job storage API backed by IndexedDB.
 * Encapsulates the key naming convention for job state and satellite data.
 *
 * Previously used chrome.storage.local (~5 MB quota). IDB gives much more
 * headroom for satellite blobs (crypto results, params, stealth data).
 * Core wallet info (seed, accounts, settings) stays in chrome.storage.local.
 */

import {
  JOB_PREFIX, JOB_DEFAULT_CLEANUP_DELAY_MS,
  JOB_SUFFIX_CRYPTO, JOB_SUFFIX_PARAMS,
  JOB_SUFFIX_STEALTH, JOB_SUFFIX_STEALTH_PARAMS, JOB_SUFFIX_CLAIM,
  JOB_STATUS_PENDING_UNLOCK,
  JOB_STATUS_DONE, JOB_STATUS_ERROR, JOB_STATUS_CANCELLED,
  JOB_STATUS_CRYPTO_DONE, JOB_STATUS_RUNNING,
} from './constants';

// ─── IndexedDB Setup ────────────────────────────────────────────────────────

const DB_NAME = 'octane-jobs';
const DB_VERSION = 1;
const STORE_NAME = 'jobs';

let _db: IDBDatabase | null = null;

function openDB(): Promise<IDBDatabase> {
  if (_db) return Promise.resolve(_db);
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      req.result.createObjectStore(STORE_NAME);
    };
    req.onsuccess = () => { _db = req.result; resolve(req.result); };
    req.onerror = () => reject(req.error);
  });
}

async function idbGet(key: string): Promise<Record<string, unknown> | undefined> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const req = tx.objectStore(STORE_NAME).get(key);
    req.onsuccess = () => resolve(req.result as Record<string, unknown> | undefined);
    req.onerror = () => reject(req.error);
  });
}

async function idbSet(key: string, value: Record<string, unknown>): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).put(value, key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function idbRemove(keys: string[]): Promise<void> {
  if (keys.length === 0) return;
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    const store = tx.objectStore(STORE_NAME);
    for (const k of keys) store.delete(k);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function idbGetAll(): Promise<Record<string, Record<string, unknown>>> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const store = tx.objectStore(STORE_NAME);
    const keyReq = store.getAllKeys();
    const valReq = store.getAll();
    tx.oncomplete = () => {
      const keys = keyReq.result as string[];
      const vals = valReq.result as Record<string, unknown>[];
      const out: Record<string, Record<string, unknown>> = {};
      keys.forEach((k, i) => { out[k] = vals[i]; });
      resolve(out);
    };
    tx.onerror = () => reject(tx.error);
  });
}

// ─── Key Builders ───────────────────────────────────────────────────────────

const SATELLITE_SUFFIXES = [JOB_SUFFIX_CRYPTO, JOB_SUFFIX_PARAMS, JOB_SUFFIX_STEALTH, JOB_SUFFIX_STEALTH_PARAMS, JOB_SUFFIX_CLAIM] as const;

export function jobKey(id: string) { return `${JOB_PREFIX}${id}`; }
export function jobCryptoKey(id: string) { return `${JOB_PREFIX}${id}${JOB_SUFFIX_CRYPTO}`; }
export function jobParamsKey(id: string) { return `${JOB_PREFIX}${id}${JOB_SUFFIX_PARAMS}`; }
export function jobStealthKey(id: string) { return `${JOB_PREFIX}${id}${JOB_SUFFIX_STEALTH}`; }
export function jobStealthParamsKey(id: string) { return `${JOB_PREFIX}${id}${JOB_SUFFIX_STEALTH_PARAMS}`; }
export function jobClaimKey(id: string) { return `${JOB_PREFIX}${id}${JOB_SUFFIX_CLAIM}`; }

/** All satellite keys for a given job. */
export function satelliteKeys(id: string): string[] {
  return SATELLITE_SUFFIXES.map(s => `${JOB_PREFIX}${id}${s}`);
}

/** All keys (primary + satellites) for a given job. */
export function allKeysForJob(id: string): string[] {
  return [jobKey(id), ...satelliteKeys(id)];
}

// ─── Key Inspection ─────────────────────────────────────────────────────────

/** True if this storage key is a primary job status key (not a satellite). */
export function isStatusKey(key: string): boolean {
  if (!key.startsWith(JOB_PREFIX)) return false;
  return !SATELLITE_SUFFIXES.some(s => key.endsWith(s));
}

/** Extract the job ID from a primary or satellite key. Returns null if not a job key. */
export function jobIdFromKey(key: string): string | null {
  if (!key.startsWith(JOB_PREFIX)) return null;
  const rest = key.slice(JOB_PREFIX.length);
  for (const s of SATELLITE_SUFFIXES) {
    if (rest.endsWith(s)) return rest.slice(0, -s.length);
  }
  return rest;
}

// ─── Storage Operations ─────────────────────────────────────────────────────

export async function getJob(id: string): Promise<Record<string, unknown> | null> {
  return (await idbGet(jobKey(id))) ?? null;
}

export async function setJob(id: string, data: Record<string, unknown>): Promise<void> {
  await idbSet(jobKey(id), data);
}

export async function getJobCrypto(id: string): Promise<Record<string, unknown> | null> {
  return (await idbGet(jobCryptoKey(id))) ?? null;
}

export async function setJobCrypto(id: string, data: Record<string, unknown>): Promise<void> {
  await idbSet(jobCryptoKey(id), data);
}

export async function getJobParams(id: string): Promise<Record<string, unknown> | null> {
  return (await idbGet(jobParamsKey(id))) ?? null;
}

export async function setJobParams(id: string, data: Record<string, unknown>): Promise<void> {
  await idbSet(jobParamsKey(id), data);
}

/** Remove the primary key and all satellite keys for a job. */
export async function removeJob(id: string): Promise<void> {
  await idbRemove(allKeysForJob(id));
}

/** Remove only satellite keys (keep primary status). */
export async function removeSatellites(id: string): Promise<void> {
  await idbRemove(satelliteKeys(id));
}

/**
 * Mark a job as done and schedule full cleanup after a delay.
 */
export function completeJob(id: string, hash: string, cleanupDelay = JOB_DEFAULT_CLEANUP_DELAY_MS): void {
  setJob(id, { status: 'done', hash });
  setTimeout(() => removeJob(id), cleanupDelay);
}

/**
 * Resume all jobs stuck in pending_unlock state.
 * Called after the wallet is unlocked so background crypto can proceed.
 */
export async function resumePendingUnlockJobs(): Promise<void> {
  const all = await idbGetAll();
  const toRemove: string[] = [];
  for (const [key, value] of Object.entries(all)) {
    if (!isStatusKey(key)) continue;
    if ((value as { status?: string })?.status === JOB_STATUS_PENDING_UNLOCK) {
      const id = jobIdFromKey(key);
      if (id) toRemove.push(...allKeysForJob(id));
    }
  }
  if (toRemove.length) await idbRemove(toRemove);
}

/**
 * Touch a job key in IDB (keep-alive signal for the service worker).
 */
export async function touchJob(id: string): Promise<void> {
  await idbGet(jobKey(id));
}

/**
 * Purge stale jobs from IDB on service worker startup.
 * Removes terminal-state jobs, legacy states, and stale running jobs from dead SWs.
 */
export async function cleanupStaleJobs(): Promise<void> {
  const all = await idbGetAll();
  const keysToRemove: string[] = [];

  for (const [key, value] of Object.entries(all)) {
    if (!isStatusKey(key)) continue;
    const jobId = jobIdFromKey(key);
    if (!jobId) continue;
    const status = (value as { status?: string })?.status;
    if (!status) continue;

    if (status === JOB_STATUS_DONE || status === JOB_STATUS_ERROR || status === JOB_STATUS_CANCELLED
      || status === JOB_STATUS_CRYPTO_DONE || status === JOB_STATUS_PENDING_UNLOCK
      || status === JOB_STATUS_RUNNING) {
      keysToRemove.push(...allKeysForJob(jobId));
    }
  }

  if (keysToRemove.length > 0) await idbRemove(keysToRemove);
}
