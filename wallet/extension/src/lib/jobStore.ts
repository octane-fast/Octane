/**
 * Centralized job storage API.
 * Encapsulates the key naming convention for job state and satellite data.
 */

import {
  JOB_PREFIX, JOB_DEFAULT_CLEANUP_DELAY_MS,
  JOB_SUFFIX_CRYPTO, JOB_SUFFIX_PARAMS,
  JOB_SUFFIX_STEALTH, JOB_SUFFIX_STEALTH_PARAMS, JOB_SUFFIX_CLAIM,
  JOB_STATUS_PENDING_UNLOCK,
} from './constants';

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
  const k = jobKey(id);
  const result = await chrome.storage.local.get(k);
  return (result[k] as Record<string, unknown>) ?? null;
}

export async function setJob(id: string, data: Record<string, unknown>): Promise<void> {
  await chrome.storage.local.set({ [jobKey(id)]: data });
}

export async function getJobCrypto(id: string): Promise<Record<string, unknown> | null> {
  const k = jobCryptoKey(id);
  const result = await chrome.storage.local.get(k);
  return (result[k] as Record<string, unknown>) ?? null;
}

export async function setJobCrypto(id: string, data: Record<string, unknown>): Promise<void> {
  await chrome.storage.local.set({ [jobCryptoKey(id)]: data });
}

export async function getJobParams(id: string): Promise<Record<string, unknown> | null> {
  const k = jobParamsKey(id);
  const result = await chrome.storage.local.get(k);
  return (result[k] as Record<string, unknown>) ?? null;
}

export async function setJobParams(id: string, data: Record<string, unknown>): Promise<void> {
  await chrome.storage.local.set({ [jobParamsKey(id)]: data });
}

/** Remove the primary key and all satellite keys for a job. */
export async function removeJob(id: string): Promise<void> {
  await chrome.storage.local.remove(allKeysForJob(id));
}

/** Remove only satellite keys (keep primary status). */
export async function removeSatellites(id: string): Promise<void> {
  await chrome.storage.local.remove(satelliteKeys(id));
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
  // Legacy: old offscreen-path jobs wrote pending_unlock status.
  // New jobs never enter this state. Just clean them up.
  const all = await chrome.storage.local.get(null) as Record<string, { status?: string }>;
  const toRemove: string[] = [];
  for (const key of Object.keys(all)) {
    if (!isStatusKey(key)) continue;
    if (all[key]?.status === JOB_STATUS_PENDING_UNLOCK) {
      const id = jobIdFromKey(key);
      if (id) toRemove.push(...allKeysForJob(id));
    }
  }
  if (toRemove.length) chrome.storage.local.remove(toRemove);
}
