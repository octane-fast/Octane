import type { RpcResponse } from './types';

const RPC_URL = 'https://octra.network/rpc';
let rpcId = 0;

const MAX_RETRIES = 3;
const RETRY_DELAYS = [1000, 2000, 4000]; // exponential backoff

async function rpcCall(method: string, params: unknown[] = []): Promise<unknown> {
  let lastError: Error | null = null;
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    try {
      const res = await fetch(RPC_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: ++rpcId,
          method,
          params,
        }),
      });
      const data: RpcResponse = await res.json();
      if (data.error) throw new Error(data.error.message);
      return data.result;
    } catch (err) {
      lastError = err as Error;
      if (attempt < MAX_RETRIES) {
        await new Promise(r => setTimeout(r, RETRY_DELAYS[attempt]));
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
  const result = await rpcCall('octra_balance', [address]) as Record<string, unknown>;
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
  const result = await rpcCall('octra_tokensByAddress', [address]) as Record<string, unknown>;
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
  const result = await rpcCall('contract_call', [contract, method, params, caller]);
  return result;
}

export async function getEncryptedBalance(
  address: string,
  signatureB64: string,
  publicKeyB64: string,
): Promise<unknown> {
  return rpcCall('octra_encryptedBalance', [address, signatureB64, publicKeyB64]);
}

export async function getRecommendedFee(opType: string = 'call'): Promise<{
  minimum: string;
  recommended: string;
  fast: string;
}> {
  const result = await rpcCall('octra_recommendedFee', [opType]) as Record<string, string>;
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
  const result = await rpcCall('octra_transaction', [hash]);
  return result as Record<string, unknown>;
}

export async function getAccountHistory(address: string, limit: number = 10): Promise<{
  recentTxs: Array<{ epoch: number; hash: string }>;
}> {
  const result = await rpcCall('octra_account', [address, limit]) as Record<string, unknown>;
  const recent = (result.recent_txs ?? []) as Array<{ epoch: number; hash: string }>;
  return { recentTxs: recent };
}

export async function getNetworkInfo(): Promise<Record<string, unknown>> {
  const result = await rpcCall('node_status', []);
  return result as Record<string, unknown>;
}

export { rpcCall };
