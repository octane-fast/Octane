/**
 * Service worker startup cleanup: purge stale jobs, resume in-progress ones,
 * and remove orphaned approval entries from previous SW lifetimes.
 */
import { isStatusKey, jobIdFromKey, allKeysForJob } from './jobStore';
import {
  JOB_STATUS_DONE, JOB_STATUS_ERROR, JOB_STATUS_CANCELLED,
  JOB_STATUS_CRYPTO_DONE, JOB_STATUS_PENDING_UNLOCK, JOB_STATUS_RUNNING,
  SK_APPROVAL_PREFIX,
} from './constants';

export function runJobCleanup(): void {
  chrome.storage.local.get(null).then((all) => {
    const keysToRemove: string[] = [];

    for (const key of Object.keys(all)) {
      if (!isStatusKey(key)) continue;

      const jobId = jobIdFromKey(key);
      if (!jobId) continue;

      const job = all[key] as { status?: string } | undefined;
      if (!job?.status) continue;

      if (job.status === JOB_STATUS_DONE || job.status === JOB_STATUS_ERROR || job.status === JOB_STATUS_CANCELLED) {
        // Terminal state — remove primary + all satellites
        keysToRemove.push(...allKeysForJob(jobId));
      } else if (job.status === JOB_STATUS_CRYPTO_DONE || job.status === JOB_STATUS_PENDING_UNLOCK) {
        // Legacy offscreen path — no longer resumed, just clean up
        keysToRemove.push(...allKeysForJob(jobId));
      } else if (job.status === JOB_STATUS_RUNNING) {
        // Stale running job from a dead SW — mark as error
        keysToRemove.push(...allKeysForJob(jobId));
      }
    }

    if (keysToRemove.length > 0) {
      const existing = keysToRemove.filter(k => k in all);
      if (existing.length > 0) chrome.storage.local.remove(existing);
    }
  });
}

export function cleanupOrphanedApprovals(): void {
  chrome.storage.local.get(null).then((all) => {
    const stale = Object.keys(all).filter(k => k.startsWith(SK_APPROVAL_PREFIX));
    if (stale.length) chrome.storage.local.remove(stale);
  });
}
