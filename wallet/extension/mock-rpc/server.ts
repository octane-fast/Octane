/**
 * Mock Octra RPC Server — local testnet for wallet development.
 *
 * Run:   npx tsx mock-rpc/server.ts
 * Then:  Set RPC_URL to http://localhost:18332/rpc in the extension
 *
 * Features:
 * - In-memory account state (balances, nonces, encrypted balances)
 * - Faucet: any address starts with 1000 OCT public + 500 OCT private
 * - Shield/Unshield operations update balances immediately
 * - Transactions are "confirmed" instantly
 * - No signature verification (accepts anything)
 */

import { createServer, IncomingMessage, ServerResponse } from 'http';
import { randomBytes } from 'crypto';

const PORT = 18332;
const MICRO = 1_000_000; // 1 OCT = 1,000,000 micro-units

// --- In-memory state ---

interface Account {
  balance_raw: bigint;        // public balance (micro-units)
  nonce: number;
  public_key: string | null;
  pvac_pubkey: string | null;
  pvac_aes_kat: string | null;
  encrypted_balance: string;  // cipher string (hfhe_v1|...)
}

const accounts = new Map<string, Account>();
const transactions = new Map<string, Record<string, unknown>>();

// Default faucet balance
const DEFAULT_PUBLIC_BALANCE = BigInt(1000) * BigInt(MICRO);

function getOrCreateAccount(address: string): Account {
  if (!accounts.has(address)) {
    accounts.set(address, {
      balance_raw: DEFAULT_PUBLIC_BALANCE,
      nonce: 0,
      public_key: null,
      pvac_pubkey: null,
      pvac_aes_kat: null,
      encrypted_balance: '',  // empty = no private balance yet
    });
  }
  return accounts.get(address)!;
}

function formatBalance(raw: bigint): string {
  const whole = raw / BigInt(MICRO);
  const frac = raw % BigInt(MICRO);
  return `${whole}.${frac.toString().padStart(6, '0')}`;
}

function fakeTxHash(): string {
  return randomBytes(32).toString('hex');
}

// --- RPC Method Handlers ---

type Handler = (params: unknown[]) => unknown;

const handlers: Record<string, Handler> = {
  octra_balance(params) {
    const address = String(params[0]);
    const acc = getOrCreateAccount(address);
    return {
      balance: formatBalance(acc.balance_raw),
      balance_raw: acc.balance_raw.toString(),
      nonce: acc.nonce,
      has_public_key: acc.public_key ? 'true' : '',
    };
  },

  octra_tokensByAddress(_params) {
    return { tokens: [] };
  },

  octra_encryptedBalance(params) {
    const address = String(params[0]);
    // params[1] = signature, params[2] = pubkey (ignored in mock)
    const acc = getOrCreateAccount(address);
    return {
      cipher: acc.encrypted_balance,
      has_pvac_pubkey: !!acc.pvac_pubkey,
    };
  },

  octra_recommendedFee(_params) {
    return { minimum: '1', recommended: '1000', fast: '2000' };
  },

  octra_submit(params) {
    const tx = params[0] as Record<string, unknown>;
    const hash = fakeTxHash();
    const from = String(tx.from ?? tx.sender ?? '');
    const to = String(tx.to ?? tx.recipient ?? '');
    const amount_raw = BigInt(String(tx.amount_raw ?? tx.amount ?? '0'));
    const fee_raw = BigInt(String(tx.fee ?? '1000'));
    const opType = String(tx.op_type ?? 'standard');

    const fromAcc = getOrCreateAccount(from);

    if (opType === 'standard' || opType === 'send') {
      // Public transfer
      if (fromAcc.balance_raw < amount_raw + fee_raw) {
        return { error: 'insufficient balance' };
      }
      fromAcc.balance_raw -= (amount_raw + fee_raw);
      fromAcc.nonce++;
      if (to) {
        const toAcc = getOrCreateAccount(to);
        toAcc.balance_raw += amount_raw;
      }
    } else if (opType === 'encrypt' || opType === 'shield') {
      // Public → Private (wallet sends op_type: 'encrypt')
      if (fromAcc.balance_raw < amount_raw + fee_raw) {
        return { error: 'insufficient balance' };
      }
      fromAcc.balance_raw -= (amount_raw + fee_raw);
      fromAcc.nonce++;
      // Extract cipher from encrypted_data JSON and store it
      if (tx.encrypted_data) {
        try {
          const encObj = JSON.parse(String(tx.encrypted_data));
          fromAcc.encrypted_balance = encObj.cipher || String(tx.encrypted_data);
        } catch {
          fromAcc.encrypted_balance = String(tx.encrypted_data);
        }
      }
    } else if (opType === 'decrypt' || opType === 'unshield') {
      // Private → Public (wallet sends op_type: 'decrypt')
      fromAcc.balance_raw += amount_raw;
      fromAcc.balance_raw -= fee_raw;
      fromAcc.nonce++;
      // Clear encrypted balance (simplified — real chain updates cipher)
      fromAcc.encrypted_balance = '';
    } else {
      // Contract call or other — just deduct fee
      fromAcc.balance_raw -= fee_raw;
      fromAcc.nonce++;
    }

    transactions.set(hash, { hash, ...tx, status: 'confirmed', epoch: Date.now() });
    console.log(`[tx] ${opType} from=${from.slice(0, 12)}... amount=${formatBalance(amount_raw)} hash=${hash.slice(0, 12)}...`);
    return { tx_hash: hash, hash };
  },

  octra_transaction(params) {
    const hash = String(params[0]);
    const tx = transactions.get(hash);
    if (!tx) return { error: 'not found' };
    return tx;
  },

  octra_account(params) {
    const address = String(params[0]);
    getOrCreateAccount(address);
    const recent = [...transactions.values()]
      .filter(t => t.from === address || t.sender === address)
      .slice(-10)
      .map(t => ({ epoch: t.epoch, hash: t.hash }));
    return { recent_txs: recent };
  },

  node_status(_params) {
    return {
      network: 'mocknet',
      epoch: Date.now(),
      peers: 1,
      version: 'mock-1.0.0',
    };
  },

  octra_publicKey(params) {
    const address = String(params[0]);
    const acc = getOrCreateAccount(address);
    return { public_key: acc.public_key };
  },

  octra_registerPublicKey(params) {
    const address = String(params[0]);
    const pubB64 = String(params[1]);
    const acc = getOrCreateAccount(address);
    acc.public_key = pubB64;
    console.log(`[reg] public_key for ${address.slice(0, 12)}...`);
    return { success: true };
  },

  octra_pvacPubkey(params) {
    const address = String(params[0]);
    const acc = getOrCreateAccount(address);
    return { pvac_pubkey: acc.pvac_pubkey };
  },

  octra_registerPvacPubkey(params) {
    const address = String(params[0]);
    const pkB64 = String(params[1]);
    // params[2] = sig, params[3] = pub, params[4] = aesKatHex
    const acc = getOrCreateAccount(address);
    acc.pvac_pubkey = pkB64;
    acc.pvac_aes_kat = String(params[4] ?? '');
    console.log(`[reg] pvac_pubkey for ${address.slice(0, 12)}... (${(pkB64.length / 1024).toFixed(0)}KB)`);
    return { success: true };
  },

  octra_stealthOutputs(_params) {
    return { outputs: [] };
  },

  contract_call(_params) {
    return { result: null };
  },

  // Faucet — give an address free testnet OCT
  faucet_fund(params) {
    const address = String(params[0]);
    const amount = params[1] ? BigInt(String(params[1])) : BigInt(1000) * BigInt(MICRO);
    const acc = getOrCreateAccount(address);
    acc.balance_raw += amount;
    console.log(`[faucet] ${address.slice(0, 12)}... +${formatBalance(amount)} OCT (total: ${formatBalance(acc.balance_raw)})`);
    return { balance: formatBalance(acc.balance_raw), balance_raw: acc.balance_raw.toString() };
  },
};

// --- HTTP Server ---

function handleRequest(req: IncomingMessage, res: ServerResponse) {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  if (req.method !== 'POST') {
    res.writeHead(405);
    res.end('Method not allowed');
    return;
  }

  let body = '';
  req.on('data', chunk => { body += chunk; });
  req.on('end', () => {
    try {
      const { jsonrpc, id, method, params } = JSON.parse(body);
      const handler = handlers[method];
      if (!handler) {
        console.warn(`[rpc] unknown method: ${method}`);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } }));
        return;
      }
      const result = handler(params ?? []);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ jsonrpc: '2.0', id, result }));
    } catch (e: any) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: e.message } }));
    }
  });
}

const server = createServer(handleRequest);
server.listen(PORT, () => {
  console.log(`\n  🧪 Octra Mock RPC running at http://localhost:${PORT}/rpc`);
  console.log(`  📦 Every address gets ${formatBalance(DEFAULT_PUBLIC_BALANCE)} OCT on first access`);
  console.log(`  💰 Faucet: curl -X POST http://localhost:${PORT}/rpc -d '{"jsonrpc":"2.0","id":1,"method":"faucet_fund","params":["<address>"]}'`);
  console.log('');
});
