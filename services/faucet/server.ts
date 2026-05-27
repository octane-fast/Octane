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

// Derive faucet address (same as Octra: base64url of pubkey hash)
const addrHash = crypto.createHash('sha256').update(faucetPubRaw).digest();
const faucetAddress = addrHash.toString('base64url').slice(0, 43);

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

  // Step 2: Claim (client sends signed challenge)
  if (req.method === 'POST' && url === '/claim') {
    const body = JSON.parse(await readBody(req));
    const { address, challenge, signature } = body;

    if (!address || !challenge || !signature) {
      sendJson(res, 400, { error: 'Missing address, challenge, or signature' });
      return;
    }

    // Validate challenge
    if (!validateChallenge(challenge, address)) {
      sendJson(res, 400, { error: 'Invalid or expired challenge' });
      return;
    }

    // Rate limit
    if (!canClaim(address)) {
      sendJson(res, 429, { error: 'Already claimed in the last 24 hours' });
      return;
    }

    // Fetch user's public key from chain
    const pubKeyB64 = await getPublicKey(address);
    if (!pubKeyB64) {
      sendJson(res, 400, { error: 'No public key registered for this address. Send a transaction first.' });
      return;
    }

    // Verify signature
    const pubKeyRaw = Buffer.from(pubKeyB64, 'base64');
    const msgBytes = new TextEncoder().encode(challenge);
    const sigBytes = Buffer.from(signature, 'base64');

    let valid = false;
    try {
      valid = verify(msgBytes, sigBytes, pubKeyRaw);
    } catch {
      valid = false;
    }

    if (!valid) {
      sendJson(res, 403, { error: 'Invalid signature' });
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
