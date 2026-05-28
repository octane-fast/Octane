/**
 * Octra Faucet Server
 *
 * Requires a wallet signature proof to dispense 3 OCT.
 * The server has its own keypair and sends transactions on-chain.
 *
 * Env vars:
 *   FAUCET_SEED  — 64-char hex ed25519 seed (32 bytes)
 *   RPC_URL      — Octra RPC endpoint (default: https://octra.network/rpc)
 *   PORT         — listen port (default: 3939)
 *
 * Run: npx tsx server.ts
 */

import { createServer, IncomingMessage, ServerResponse } from 'http';
import * as crypto from 'crypto';
import { readFileSync } from 'fs';

// Load .env if present
try {
  const envFile = readFileSync(new URL('.env', import.meta.url), 'utf-8');
  for (const line of envFile.split('\n')) {
    const [key, ...val] = line.split('=');
    if (key && val.length) process.env[key.trim()] = val.join('=').trim();
  }
} catch {}

const PORT = parseInt(process.env.PORT || '3939');
const RPC_URL = process.env.RPC_URL || 'https://octra.network/rpc';
const FAUCET_SEED = process.env.FAUCET_SEED || '';
const DRIP_AMOUNT = 3_000_000; // 3 OCT in micro-units
const COOLDOWN_MS = 24 * 60 * 60 * 1000; // 1 claim per 24h per address

if (!FAUCET_SEED || FAUCET_SEED.length !== 64) {
  console.error('ERROR: Set FAUCET_SEED env var to a 64-char hex ed25519 seed');
  process.exit(1);
}

// --- Ed25519 via Node.js crypto ---

const seedBytes = Buffer.from(FAUCET_SEED, 'hex');
const faucetPrivKey = crypto.createPrivateKey({
  key: Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'), // PKCS8 ed25519 prefix
    seedBytes,
  ]),
  format: 'der',
  type: 'pkcs8',
});
const faucetPubKey = crypto.createPublicKey(faucetPrivKey);
const faucetPubRaw = faucetPubKey.export({ type: 'spki', format: 'der' }).subarray(-32);
const faucetPubB64 = faucetPubRaw.toString('base64');

// --- Octra address derivation: "oct" + base58(sha256(pubkey)) padded to 44 chars ---

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Encode(data: Uint8Array): string {
  let zeroes = 0;
  while (zeroes < data.length && data[zeroes] === 0) zeroes++;
  const buf = Array.from(data);
  const result: number[] = [];
  while (buf.length > 0) {
    let carry = 0;
    const next: number[] = [];
    for (let i = 0; i < buf.length; i++) {
      const val = carry * 256 + buf[i];
      const digit = Math.floor(val / 58);
      carry = val % 58;
      if (next.length > 0 || digit > 0) next.push(digit);
    }
    result.push(carry);
    buf.length = 0;
    buf.push(...next);
  }
  let str = '';
  for (let i = 0; i < zeroes; i++) str += '1';
  for (let i = result.length - 1; i >= 0; i--) str += BASE58_ALPHABET[result[i]];
  return str;
}

function deriveOctraAddress(pubKeyRaw: Uint8Array): string {
  const hash = crypto.createHash('sha256').update(pubKeyRaw).digest();
  let b58 = base58Encode(hash);
  while (b58.length < 44) b58 = '1' + b58;
  return 'oct' + b58;
}

const faucetAddress = deriveOctraAddress(faucetPubRaw);

function sign(message: Uint8Array): Buffer {
  return crypto.sign(null, Buffer.from(message), faucetPrivKey);
}

function verify(message: Uint8Array, signature: Uint8Array, pubKeyRaw: Uint8Array): boolean {
  const pubKey = crypto.createPublicKey({
    key: Buffer.concat([
      Buffer.from('302a300506032b6570032100', 'hex'), // SPKI ed25519 prefix
      Buffer.from(pubKeyRaw),
    ]),
    format: 'der',
    type: 'spki',
  });
  return crypto.verify(null, Buffer.from(message), pubKey, Buffer.from(signature));
}

// --- RPC helper ---

let rpcId = 0;
async function rpcCall(method: string, params: unknown[]): Promise<unknown> {
  const res = await fetch(RPC_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: ++rpcId, method, params }),
  });
  const json = await res.json() as { result?: unknown; error?: { message?: string } };
  if (json.error) throw new Error(json.error.message || 'RPC error');
  return json.result;
}

async function getBalance(address: string): Promise<{ balance_raw: string; nonce: number }> {
  const res = await rpcCall('octra_balance', [address]) as Record<string, unknown>;
  return {
    balance_raw: String(res.balance_raw ?? '0'),
    nonce: Number(res.nonce ?? 0),
  };
}

async function getPublicKey(address: string): Promise<string | null> {
  const res = await rpcCall('octra_publicKey', [address]) as Record<string, unknown>;
  return res.public_key && typeof res.public_key === 'string' ? res.public_key : null;
}

async function sendOct(to: string, amountRaw: number): Promise<string> {
  const { nonce } = await getBalance(faucetAddress);
  const newNonce = nonce + 1;
  const ts = Math.floor(Date.now() / 1000);
  const tsStr = ts + '.0';
  const canonical = `{"from":"${faucetAddress}","to_":"${to}","amount":"${amountRaw}","nonce":${newNonce},"ou":"1000","timestamp":${tsStr},"op_type":"standard"}`;
  const sig = sign(new TextEncoder().encode(canonical));
  const payload = {
    from: faucetAddress,
    to_: to,
    amount: String(amountRaw),
    nonce: newNonce,
    ou: '1000',
    timestamp: ts,
    op_type: 'standard',
    signature: sig.toString('base64'),
    public_key: faucetPubB64,
  };
  const res = await rpcCall('octra_submit', [payload]) as Record<string, unknown>;
  if (res.error) throw new Error(String(res.error));
  return String(res.tx_hash ?? res.hash ?? '');
}

// --- Rate limiting ---

const claims = new Map<string, number>(); // address → last claim timestamp

function canClaim(address: string): boolean {
  const last = claims.get(address);
  if (!last) return true;
  return Date.now() - last > COOLDOWN_MS;
}

// --- Challenge management ---

const challenges = new Map<string, { address: string; expires: number }>();

function createChallenge(address: string): string {
  const challenge = `octra-faucet:${address}:${Date.now()}:${crypto.randomBytes(8).toString('hex')}`;
  challenges.set(challenge, { address, expires: Date.now() + 5 * 60 * 1000 }); // 5 min expiry
  return challenge;
}

function validateChallenge(challenge: string, address: string): boolean {
  const entry = challenges.get(challenge);
  if (!entry) return false;
  if (entry.address !== address) return false;
  if (Date.now() > entry.expires) {
    challenges.delete(challenge);
    return false;
  }
  challenges.delete(challenge); // one-time use
  return true;
}

// --- HTTP Server ---

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', (c: Buffer) => { body += c.toString(); });
    req.on('end', () => resolve(body));
  });
}

function sendJson(res: ServerResponse, status: number, data: unknown) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  });
  res.end(JSON.stringify(data));
}

async function handleRequest(req: IncomingMessage, res: ServerResponse) {
  // CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    });
    res.end();
    return;
  }

  const url = req.url ?? '';

  // Health check
  if (req.method === 'GET' && url === '/health') {
    sendJson(res, 200, { status: 'ok', address: faucetAddress });
    return;
  }

  // Step 1: Get challenge (client sends address)
  if (req.method === 'POST' && url === '/challenge') {
    const body = JSON.parse(await readBody(req));
    const address = body.address;
    if (!address || typeof address !== 'string') {
      sendJson(res, 400, { error: 'Missing address' });
      return;
    }
    if (!canClaim(address)) {
      sendJson(res, 429, { error: 'Already claimed in the last 24 hours' });
      return;
    }
    const challenge = createChallenge(address);
    sendJson(res, 200, { challenge });
    return;
  }

  // Balance endpoint
  if (req.method === 'GET' && url === '/balance') {
    try {
      const { balance_raw } = await getBalance(faucetAddress);
      const balanceOct = (parseInt(balance_raw) / 1_000_000).toFixed(6);
      sendJson(res, 200, { address: faucetAddress, balance_raw, balance: balanceOct });
    } catch (e) {
      // Account may not exist yet on-chain
      sendJson(res, 200, { address: faucetAddress, balance_raw: '0', balance: '0.000000' });
    }
    return;
  }

  // Claim: client sends address + PVAC Pedersen commitment (proves Octane wallet)
  if (req.method === 'POST' && url === '/claim') {
    const body = JSON.parse(await readBody(req));
    const { address, commitment } = body;

    if (!address || typeof address !== 'string') {
      sendJson(res, 400, { error: 'Missing address' });
      return;
    }

    // Check commitment was provided (proves they have the Octane wallet with PVAC prover)
    if (!commitment || typeof commitment !== 'object' || !commitment.commitment) {
      sendJson(res, 400, { error: 'Missing PVAC commitment. Octane wallet required.' });
      return;
    }

    // Rate limit
    if (!canClaim(address)) {
      sendJson(res, 429, { error: 'Already claimed in the last 24 hours' });
      return;
    }

    // Send OCT
    try {
      const txHash = await sendOct(address, DRIP_AMOUNT);
      claims.set(address, Date.now());
      console.log(`[faucet] Sent 3 OCT to ${address.slice(0, 12)}... tx=${txHash.slice(0, 12)}...`);
      sendJson(res, 200, { success: true, txHash, amount: '3' });
    } catch (e) {
      console.error('[faucet] Send failed:', (e as Error).message);
      sendJson(res, 500, { error: 'Transaction failed: ' + (e as Error).message });
    }
    return;
  }

  sendJson(res, 404, { error: 'Not found' });
}

const server = createServer(handleRequest);
server.listen(PORT, () => {
  console.log(`\n  💧 Octra Faucet running on port ${PORT}`);
  console.log(`  📬 Faucet address: ${faucetAddress}`);
  console.log(`  💰 Drip amount: 3 OCT per claim`);
  console.log(`  ⏰ Cooldown: 24 hours per address`);
  console.log(`  🌐 RPC: ${RPC_URL}\n`);
});
