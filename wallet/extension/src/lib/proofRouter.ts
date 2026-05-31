/**
 * Proof Router — encapsulates the prover cascade:
 *   1) Native desktop prover (localhost Octane Accelerator)
 *   2) Remote relay prover (paired Accelerator over WebSocket)
 *   3) WASM fallback (offscreen document or in-process)
 */

// --- Constants ---
export const PROVER_URL = 'http://127.0.0.1:19876';
export const PROVER_WS_URL = 'ws://127.0.0.1:19876/prove';

// --- Types ---
export interface PairingConfig {
  relay: string;   // e.g. "wss://relay.octane.fast"
  room: string;    // room ID
  key: string;     // base64 X25519 public key of accelerator
}

export interface RouteOpts {
  operation: string;
  payload: Record<string, string>;
  jobId?: string;
  /** Custom native path (e.g. decrypt uses HTTP POST, not WebSocket) */
  native?: () => Promise<Record<string, unknown> | null>;
  /** WASM / in-process fallback. If omitted, route() returns null when native+remote fail. */
  wasm?: () => Promise<Record<string, unknown>>;
  /** Optional status callback for job updates */
  onStatus?: (step: string, prover: string) => void;
}

type KeyProvider = () => Promise<{ skB64: string; pkB64: string }>;

// --- Prover availability cache ---
let proverAvailableCache: boolean | null = null;
let proverCacheExpiry = 0;
const PROVER_CACHE_TTL_OK = 10_000;   // 10s when available
const PROVER_CACHE_TTL_FAIL = 30_000; // 30s cooldown on failure

// --- Key provider (injected from background) ---
let keyProvider: KeyProvider | null = null;

// --- Public API ---

export function setKeyProvider(provider: KeyProvider): void {
  keyProvider = provider;
}

export function invalidateProverCache(): void {
  proverAvailableCache = null;
}

export async function isProverAvailable(): Promise<boolean> {
  const now = Date.now();
  if (proverAvailableCache !== null && now < proverCacheExpiry) {
    return proverAvailableCache;
  }
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 2000);
    const res = await fetch(`${PROVER_URL}/health`, { signal: ctrl.signal });
    clearTimeout(timer);
    const data = await res.json();
    const available = data.status === 'ready';
    proverAvailableCache = available;
    proverCacheExpiry = now + (available ? PROVER_CACHE_TTL_OK : PROVER_CACHE_TTL_FAIL);
    return available;
  } catch {
    proverAvailableCache = false;
    proverCacheExpiry = now + PROVER_CACHE_TTL_FAIL;
    return false;
  }
}

export async function isRemoteProverConfigured(): Promise<PairingConfig | null> {
  const { pairingConfig } = await chrome.storage.local.get('pairingConfig');
  return (pairingConfig as PairingConfig | undefined) ?? null;
}

/**
 * Ensure prover payload has PVAC keys for initialization & does not contain the raw secret key.
 * Uses cached PVAC keys (NOT the raw signing seed).
 */
async function sanitizeProverPayload(payload: Record<string, string>): Promise<Record<string, string>> {
  if (payload.pvac_sk_b64 && payload.pvac_pk_b64) return payload;
  if (!keyProvider) throw new Error('Key provider not configured');
  const { skB64, pkB64 } = await keyProvider();
  return { ...payload, pvac_sk_b64: skB64, pvac_pk_b64: pkB64 };
}

export function runNativeProver(jobId: string, payload: Record<string, string>): Promise<Record<string, string>> {
  return new Promise((resolve, reject) => {
    const storageKey = `job_${jobId}`;
    const ws = new WebSocket(PROVER_WS_URL);
    let settled = false;

    // Keep service worker alive during long proving operations (Chrome MV3 kills after ~30s idle)
    const keepAlive = setInterval(() => {
      chrome.storage.local.get(storageKey);
    }, 5000);

    const cleanup = () => { clearInterval(keepAlive); };

    ws.onopen = async () => {
      const safe = await sanitizeProverPayload(payload);
      ws.send(JSON.stringify({ ...safe, jobId }));
    };

    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data as string);
        if (msg.type === 'status') {
          chrome.storage.local.set({ [storageKey]: { status: 'running', step: msg.step } });
        } else if (msg.type === 'result' && msg.data) {
          settled = true;
          cleanup();
          ws.close();
          resolve(msg.data);
        } else if (msg.type === 'error') {
          settled = true;
          cleanup();
          ws.close();
          reject(new Error(msg.error ?? 'Prover error'));
        }
      } catch (e) {
        settled = true;
        cleanup();
        ws.close();
        reject(e);
      }
    };

    ws.onerror = () => {
      if (!settled) {
        settled = true;
        cleanup();
        reject(new Error('Prover connection failed'));
      }
    };

    ws.onclose = () => {
      if (!settled) {
        settled = true;
        cleanup();
        reject(new Error('Prover disconnected'));
      }
    };
  });
}

export function runRemoteProver(jobId: string, payload: Record<string, string>, config: PairingConfig): Promise<Record<string, string>> {
  return new Promise((resolve, reject) => {
    const storageKey = `job_${jobId}`;
    const wsUrl = `${config.relay}/room/${config.room}?role=client`;
    const ws = new WebSocket(wsUrl);
    let settled = false;
    let peerConnected = false;

    ws.onopen = () => {
      // Wait for peer_connected before sending payload
    };

    ws.onmessage = async (ev) => {
      try {
        const msg = JSON.parse(ev.data as string);

        // Relay control messages
        if (msg.type === 'peer_connected') {
          peerConnected = true;
          const safe = await sanitizeProverPayload(payload);
          ws.send(JSON.stringify({ ...safe, jobId }));
          return;
        }
        if (msg.type === 'peer_disconnected') {
          if (!settled) {
            settled = true;
            ws.close();
            reject(new Error('Remote prover disconnected'));
          }
          return;
        }

        // Prover messages (forwarded from accelerator)
        if (msg.type === 'status') {
          chrome.storage.local.set({ [storageKey]: { status: 'running', step: msg.step } });
        } else if (msg.type === 'result' && msg.data) {
          settled = true;
          ws.close();
          resolve(msg.data);
        } else if (msg.type === 'error') {
          settled = true;
          ws.close();
          reject(new Error(msg.error ?? 'Remote prover error'));
        }
      } catch (e) {
        settled = true;
        ws.close();
        reject(e);
      }
    };

    ws.onerror = () => {
      if (!settled) {
        settled = true;
        reject(new Error('Relay connection failed'));
      }
    };

    ws.onclose = () => {
      if (!settled) {
        settled = true;
        reject(new Error('Relay disconnected'));
      }
    };

    // Timeout: if no peer_connected after 15s, give up
    setTimeout(() => {
      if (!peerConnected && !settled) {
        settled = true;
        ws.close();
        reject(new Error('Remote prover not reachable (timeout)'));
      }
    }, 15000);
  });
}

/**
 * Route a proof operation through the prover cascade:
 * native desktop → remote relay → WASM fallback
 * Returns null if all provers fail and no wasm callback is provided.
 */
export async function route(opts: RouteOpts): Promise<Record<string, unknown> | null> {
  const { operation, payload, jobId, wasm, onStatus } = opts;

  // 1) Native desktop prover
  if (await isProverAvailable()) {
    onStatus?.('Proving ⚡ Desktop', 'local');
    try {
      if (opts.native) {
        const r = await opts.native();
        if (r) return r;
      } else {
        return await runNativeProver(jobId ?? `${operation}_${Date.now()}`, payload);
      }
    } catch (e) {
      console.warn(`[proofRouter] native failed (${operation}):`, (e as Error).message);
    }
  }

  // 2) Remote relay prover
  const remote = await isRemoteProverConfigured();
  if (remote) {
    onStatus?.('Proving ☁️ Remote', 'remote');
    try {
      return await runRemoteProver(jobId ?? `${operation}_${Date.now()}`, payload, remote);
    } catch (e) {
      console.warn(`[proofRouter] remote failed (${operation}):`, (e as Error).message);
    }
  }

  // 3) WASM fallback (if provided)
  if (wasm) {
    onStatus?.('Proving 🌐 In-Browser', 'wasm');
    return wasm();
  }

  return null;
}
