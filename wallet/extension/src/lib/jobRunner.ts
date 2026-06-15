/**
 * Unified job runner for background proving + transaction submission.
 *
 * All privacy-preserving jobs (shield, unshield, stealth send, stealth claim)
 * follow the same two-phase pattern:
 *   1. Prove: generate cryptographic proofs (via native/remote/WASM prover)
 *   2. Submit: build and submit the signed transaction (with indefinite retry)
 *
 * This module centralizes:
 *   - Job lifecycle management (running, cancelled, error, done)
 *   - Retry logic with configurable fatal errors
 *   - Storage persistence for service worker restarts
 *   - Cancellation checks at phase boundaries
 */

import { completeJob, getJob, setJob } from './jobStore';
import * as rpc from './rpc';
import * as vault from './keyVault';
import { buildSignedTx } from './txBuilder';
import { getOperationFee } from './fees';

// ─── Types ──────────────────────────────────────────────────────────────────

export interface JobContext {
  jobId: string;
  storageKey: string;
  attempt: number;
  /** Update the job's visible status in storage. */
  update(fields: Record<string, unknown>): Promise<void>;
  /** Check if the user has cancelled this job. */
  isCancelled(): Promise<boolean>;
}

export interface SubmitConfig {
  /** The on-chain operation type (encrypt, decrypt, stealth, claim). */
  opType: 'encrypt' | 'decrypt' | 'stealth' | 'claim';
  /** Transaction recipient (usually self, or 'stealth'). */
  to: string;
  /** Transaction amount as raw string. */
  amount: string;
  /** The encrypted_data JSON payload. */
  encData: string;
  /** Error substrings that should NOT retry (permanent failures). */
  fatalErrors?: string[];
}

export interface JobDefinition<TProveResult = Record<string, string>> {
  jobId: string;
  /** Prove phase: produce the crypto output. Throws on failure. */
  prove: (ctx: JobContext) => Promise<TProveResult>;
  /** Build submit config from prove result. */
  buildSubmit: (ctx: JobContext, proveResult: TProveResult) => SubmitConfig | Promise<SubmitConfig>;
  /** Error substrings during prove phase that should NOT retry. */
  fatalProveErrors?: string[];
  /** Retry delay in ms (default 5000). */
  retryDelay?: number;
  /** Optional: store satellite data for resume after SW restart. */
  persistForResume?: (proveResult: TProveResult) => Promise<void>;
}

// ─── Constants ──────────────────────────────────────────────────────────────

const DEFAULT_RETRY_DELAY = 5000;

// ─── Job Runner ─────────────────────────────────────────────────────────────

function makeContext(jobId: string, attempt: number): JobContext {
  return {
    jobId,
    storageKey: `job_${jobId}`,
    attempt,
    async update(fields: Record<string, unknown>) {
      await setJob(jobId, { status: 'running', ...fields });
    },
    async isCancelled() {
      const data = await getJob(jobId);
      return data?.status === 'cancelled';
    },
  };
}

/**
 * Execute a two-phase job (prove → submit).
 * Handles cancellation, fatal vs transient errors, and indefinite submit retry.
 */
export async function runJob<T extends Record<string, string>>(def: JobDefinition<T>): Promise<void> {
  const { jobId, retryDelay = DEFAULT_RETRY_DELAY } = def;
  const ctx = makeContext(jobId, 0);

  try {
    if (!vault.isUnlocked()) throw new Error('locked');
    if (await ctx.isCancelled()) return;

    // ── Phase 1: Prove ──
    const proveResult = await def.prove(ctx);

    if (await ctx.isCancelled()) return;

    // Persist for potential SW restart before submitting
    if (def.persistForResume) {
      await def.persistForResume(proveResult);
    }

    // ── Phase 2: Submit ──
    await ctx.update({ step: 'Submitting transaction...' });
    const submitConfig = await def.buildSubmit(ctx, proveResult);
    await submitWithRetry(jobId, submitConfig, 0, retryDelay);
  } catch (err) {
    const msg = (err as Error).message ?? '';
    const isFatal = def.fatalProveErrors?.some(e => msg.includes(e)) ?? false;

    if (isFatal || msg === 'locked') {
      await setJob(jobId, { status: 'error', error: msg });
    } else {
      // Transient error in prove phase — report as error (prove is not retried automatically)
      await setJob(jobId, { status: 'error', error: msg });
    }
  }
}

/**
 * Submit a transaction with indefinite retry on transient errors.
 * Can be called standalone to resume a submission after SW restart.
 */
export async function submitWithRetry(
  jobId: string,
  config: SubmitConfig,
  attempt: number,
  retryDelay = DEFAULT_RETRY_DELAY,
): Promise<void> {
  try {
    if (!vault.isUnlocked()) throw new Error('locked');

    // Check cancellation
    const data = await getJob(jobId);
    if (data?.status === 'cancelled') return;

    // Recover attempt from storage on SW restart
    if (attempt === 0 && typeof data?.attempt === 'number') {
      attempt = data.attempt;
    }

    const stepMsg = attempt > 0
      ? `Submitting transaction... (retry ${attempt})`
      : 'Submitting transaction...';
    await setJob(jobId, { status: 'running', step: stepMsg, attempt });

    const address = vault.getAddress();
    const balInfo = await rpc.getBalance(address);
    const nonce = balInfo.nonce + 1;
    const ou = await getOperationFee(config.opType);

    const tx = buildSignedTx({
      from: address,
      to: config.to,
      amount: config.amount,
      nonce,
      ou,
      opType: config.opType,
      encryptedData: config.encData,
    });

    const result = await rpc.submitTransaction(tx);
    completeJob(jobId, result.hash);
  } catch (err) {
    const msg = (err as Error).message ?? 'unknown error';
    const isFatal = config.fatalErrors?.some(e => msg.includes(e)) ?? false;

    if (isFatal) {
      await setJob(jobId, { status: 'error', error: msg });
    } else {
      const nextAttempt = attempt + 1;
      await setJob(jobId, { status: 'running', step: `Submitting transaction... (retry ${nextAttempt} — ${msg})`, attempt: nextAttempt });
      setTimeout(() => submitWithRetry(jobId, config, nextAttempt, retryDelay), retryDelay);
    }
  }
}
