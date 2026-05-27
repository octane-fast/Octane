import type { RpcResponse } from './types';

const DEFAULT_RPC_URL = 'https://octra.network/rpc';
let currentRpcUrl = DEFAULT_RPC_URL;
let rpcId = 0;

// Allow runtime override (set via chrome.storage.local 'rpcUrl')
export function setRpcUrl(url: string) { currentRpcUrl = url; }
export function getRpcUrl(): string { return currentRpcUrl; }

// Load saved RPC URL on startup
try {
  chrome.storage.local.get('rpcUrl').then(({ rpcUrl }) => {
    if (rpcUrl) currentRpcUrl = rpcUrl;
  });
} catch { /* not in extension context */ }

// Write operations: slower backoff, tolerant of 429s
const WRITE_MAX_RETRIES = 6;
const WRITE_RETRY_DELAYS = [2000, 3000, 5000, 8000, 10000, 10000];
const WRITE_TIMEOUT_MS = 30000;

// Read operations: fast retries, short timeout
const READ_MAX_RETRIES = 8;
const READ_RETRY_DELAYS = [300, 500, 800, 1000, 1500, 2000, 3000, 5000];
const READ_TIMEOUT_MS = 8000;

async function rpcCall(method: string, params: unknown[] = [], opts?: { fast?: boolean }): Promise<unknown> {
  const fast = opts?.fast ?? false;
  const maxRetries = fast ? READ_MAX_RETRIES : WRITE_MAX_RETRIES;
  const delays = fast ? READ_RETRY_DELAYS : WRITE_RETRY_DELAYS;
  const timeoutMs = fast ? READ_TIMEOUT_MS : WRITE_TIMEOUT_MS;

  let lastError: Error | null = null;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      const res = await fetch(currentRpcUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: ++rpcId,
          method,
          params,
        }),
        signal: controller.signal,
      });
      clearTimeout(timer);
      if (res.status === 429) {
        throw new Error('Rate limited (429) — retrying');
      }
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}: ${res.statusText}`);
      }
      const data: RpcResponse = await res.json();
      if (data.error) throw new Error(data.error.message);
      return data.result;
    } catch (err) {
      lastError = err as Error;
      if (attempt < maxRetries) {
        await new Promise(r => setTimeout(r, delays[attempt]));
      }
    }
  }
  throw lastError!;
}

export async function getBalance(address: string): Promise<{
  formatted: string;
  raw: string;
  nonce: number;
  publicKey: string;
}> {
  const result = await rpcCall('octra_balance', [address], { fast: true }) as Record<string, unknown>;
  return {
    formatted: String(result.balance ?? '0'),
    raw: String(result.balance_raw ?? '0'),
    nonce: Number(result.nonce ?? 0),
    publicKey: String(result.has_public_key ?? ''),
  };
}

export async function getTokensByAddress(address: string): Promise<Array<{
  contract: string;
  name: string;
  symbol: string;
  balance: string;
  decimals: number;
}>> {
  const result = await rpcCall('octra_tokensByAddress', [address], { fast: true }) as Record<string, unknown>;
  const tokens = (result.tokens ?? result) as unknown[];
  if (!Array.isArray(tokens)) return [];
  return tokens.map((t: Record<string, unknown>) => ({
    contract: String(t.address ?? t.contract ?? ''),
    name: String(t.name ?? 'Unknown'),
    symbol: String(t.symbol ?? '???'),
    balance: String(t.balance ?? '0'),
    decimals: Number(t.decimals ?? 6),
  }));
}

export async function contractCall(
  contract: string,
  method: string,
  params: unknown[],
  caller: string,
): Promise<unknown> {
  const result = await rpcCall('contract_call', [contract, method, params, caller], { fast: true });
  return result;
}

export async function getEncryptedBalance(
  address: string,
  signatureB64: string,
  publicKeyB64: string,
): Promise<unknown> {
  return rpcCall('octra_encryptedBalance', [address, signatureB64, publicKeyB64], { fast: true });
}

export async function getRecommendedFee(opType: string = 'call'): Promise<{
  minimum: string;
  recommended: string;
  fast: string;
}> {
  const result = await rpcCall('octra_recommendedFee', [opType], { fast: true }) as Record<string, string>;
  return {
    minimum: result.minimum ?? '1',
    recommended: result.recommended ?? '1000',
    fast: result.fast ?? '2000',
  };
}

export async function submitTransaction(tx: Record<string, unknown>): Promise<{ hash: string }> {
  const result = await rpcCall('octra_submit', [tx]) as Record<string, unknown>;
  return { hash: String(result.tx_hash ?? result.hash ?? '') };
}

export async function getTransaction(hash: string): Promise<Record<string, unknown>> {
  const result = await rpcCall('octra_transaction', [hash], { fast: true });
  return result as Record<string, unknown>;
}

export async function getAccountHistory(address: string, limit: number = 10): Promise<{
  recentTxs: Array<{ epoch: number; hash: string }>;
}> {
  const result = await rpcCall('octra_account', [address, limit], { fast: true }) as Record<string, unknown>;
  const recent = (result.recent_txs ?? []) as Array<{ epoch: number; hash: string }>;
  return { recentTxs: recent };
}

export async function getNetworkInfo(): Promise<Record<string, unknown>> {
  const result = await rpcCall('node_status', [], { fast: true });
  return result as Record<string, unknown>;
}

export async function getPublicKey(address: string): Promise<{ public_key: string | null }> {
  const result = await rpcCall('octra_publicKey', [address], { fast: true }) as Record<string, unknown>;
  const pk = result.public_key;
  return { public_key: pk && typeof pk === 'string' ? pk : null };
}

export async function registerPublicKey(
  address: string,
  pubB64: string,
  sigB64: string,
): Promise<void> {
  await rpcCall('octra_registerPublicKey', [address, pubB64, sigB64]);
}

export async function getPvacPubkey(address: string): Promise<string | null> {
  const result = await rpcCall('octra_pvacPubkey', [address], { fast: true }) as Record<string, unknown>;
  const pk = result.pvac_pubkey;
  return pk && typeof pk === 'string' ? pk : null;
}

export async function registerPvacPubkey(
  address: string,
  pkB64: string,
  sigB64: string,
  pubB64: string,
  aesKatHex: string,
): Promise<void> {
  await rpcCall('octra_registerPvacPubkey', [address, pkB64, sigB64, pubB64, aesKatHex]);
}

export async function getStealthOutputs(sinceEpoch: number = 0): Promise<{ outputs: Array<Record<string, unknown>> }> {
  const result = await rpcCall('octra_stealthOutputs', [sinceEpoch], { fast: true }) as Record<string, unknown>;
  const outputs = (result.outputs ?? []) as Array<Record<string, unknown>>;
  return { outputs };
}

export { rpcCall };
