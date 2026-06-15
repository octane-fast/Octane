/**
 * Service worker startup cleanup: purge stale jobs, resume in-progress ones,
 * and remove orphaned approval entries from previous SW lifetimes.
 */
import { cleanupStaleJobs } from './jobStore';
import { SK_APPROVAL_PREFIX } from './constants';

export function runJobCleanup(): void {
  cleanupStaleJobs().catch((e) => console.warn('[cleanup] job cleanup failed:', (e as Error).message));
}

export function cleanupOrphanedApprovals(): void {
  chrome.storage.local.get(null).then((all) => {
    const stale = Object.keys(all).filter(k => k.startsWith(SK_APPROVAL_PREFIX));
    if (stale.length) chrome.storage.local.remove(stale);
  });
}
