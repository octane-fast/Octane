/**
 * Fee resolution: checks user override in storage, falls back to RPC recommended fee or DEFAULT_FEE.
 */
import { DEFAULT_FEE, SK_FEE_DEFAULT, SK_FEE_ENCRYPT, SK_FEE_DECRYPT, SK_FEE_STEALTH, SK_FEE_CLAIM } from './constants';
import * as rpc from './rpc';

const OP_KEY_MAP: Record<string, string> = {
  encrypt: SK_FEE_ENCRYPT,
  decrypt: SK_FEE_DECRYPT,
  stealth: SK_FEE_STEALTH,
  claim: SK_FEE_CLAIM,
};

/**
 * Get the fee for a privacy operation (encrypt/decrypt/stealth/claim).
 * Returns user override if set, otherwise RPC recommended fee.
 */
export async function getOperationFee(op: 'encrypt' | 'decrypt' | 'stealth' | 'claim'): Promise<string> {
  const key = OP_KEY_MAP[op];
  const stored = await chrome.storage.local.get(key);
  const override = stored[key] as string | undefined;
  if (override) return override;
  const feeInfo = await rpc.getRecommendedFee(op);
  return feeInfo.recommended;
}

/**
 * Get the default fee for standard/contract transactions.
 * Returns user override if set, otherwise DEFAULT_FEE constant.
 */
export async function getDefaultFee(): Promise<string> {
  const stored = await chrome.storage.local.get(SK_FEE_DEFAULT);
  const override = stored[SK_FEE_DEFAULT] as string | undefined;
  return override || DEFAULT_FEE;
}
