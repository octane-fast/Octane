export interface Wallet {
  address: string;
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export interface AccountBalance {
  formatted: string;
  raw: string;
  nonce: number;
  publicKey: string;
}

export interface TokenBalance {
  contract: string;
  name: string;
  symbol: string;
  decimals: number;
  balance: string;
}

export interface TransactionResult {
  hash: string;
  accepted: boolean;
  status: 'pending' | 'confirmed' | 'rejected' | 'dropped';
}

export interface RpcRequest {
  method: string;
  params?: unknown[];
}

export interface RpcResponse {
  jsonrpc: string;
  id: number;
  result?: unknown;
  error?: { code: number; message: string };
}

export interface OctraProvider {
  readonly isOctra: true;
  request(args: { method: string; params?: readonly unknown[] | object }): Promise<unknown>;
  on(event: string, listener: (...args: unknown[]) => void): this;
  removeListener(event: string, listener: (...args: unknown[]) => void): this;
}
