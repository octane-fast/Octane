// Injected into the page context to provide wallet connectivity per RFC-O-1
// Supports both direct window.octra.request() and @0xio/sdk postMessage protocol

import { DAPP_REQUEST_TIMEOUT_MS } from '../lib/constants';

console.log('[Octane] inpage.js loaded');

interface PendingRequest {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
}

const pending = new Map<number, PendingRequest>();
let nextId = 1;

type Listener = (...args: unknown[]) => void;
const listeners = new Map<string, Set<Listener>>();

// Handle responses from content script (for our direct protocol)
window.addEventListener('message', (event) => {
  if (event.source !== window) return;
  if (event.data?.target !== 'octra-inpage') return;

  const { id, response } = event.data;
  console.log('[Octane] got response for id', id, ':', response);
  const req = pending.get(id);
  if (!req) return;
  pending.delete(id);

  if (response?.error) {
    req.reject(new Error(response.error));
  } else {
    req.resolve(response);
  }
});

const octra = {
  isOctra: true as const,

  async request({ method, params }: { method: string; params?: readonly unknown[] | object }): Promise<unknown> {
    const id = nextId++;
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject });
      window.postMessage(
        { target: 'octra-content', id, method, params: Array.isArray(params) ? params : params ? [params] : [] },
        '*',
      );
      setTimeout(() => {
        if (pending.has(id)) {
          pending.delete(id);
          reject(new Error('Request timed out'));
        }
      }, DAPP_REQUEST_TIMEOUT_MS);
    });
  },

  on(event: string, listener: Listener) {
    if (!listeners.has(event)) listeners.set(event, new Set());
    listeners.get(event)!.add(listener);
    return octra;
  },

  removeListener(event: string, listener: Listener) {
    listeners.get(event)?.delete(listener);
    return octra;
  },
};

Object.defineProperty(window, 'octra', {
  value: octra,
  writable: false,
  configurable: false,
});

// Also expose as window.octraWallet for @0xio/sdk detection
Object.defineProperty(window, 'octraWallet', {
  value: octra,
  writable: false,
  configurable: false,
});

// Expose as window.wallet0xio and window.ZeroXIOWallet for older SDK versions
Object.defineProperty(window, 'wallet0xio', {
  value: octra,
  writable: false,
  configurable: false,
});

Object.defineProperty(window, 'ZeroXIOWallet', {
  value: octra,
  writable: false,
  configurable: false,
});

// --- @0xio/sdk postMessage protocol support ---
// The SDK sends: { source: "0xio-sdk-request", request: { id, method, params, timestamp } }
// We respond: { id, success: true/false, data/error }
window.addEventListener('message', (event) => {
  if (event.source !== window) return;
  if (event.data?.source !== '0xio-sdk-request') return;

  const { request } = event.data;
  if (!request?.id || !request?.method) return;

  console.log('[Octane] SDK request:', request.method, request.id);

  const sdkId = request.id as string;
  const method = request.method as string;
  const params = request.params ?? {};

  // Route through our content script relay, then respond in SDK format
  const internalId = nextId++;
  pending.set(internalId, {
    resolve: (response) => {
      console.log('[Octane] SDK response for', method, ':', response);
      // Transform array responses for connect/getConnectionStatus into expected object format
      let data = response;
      if ((method === 'connect' || method === 'getConnectionStatus') && Array.isArray(response) && response.length > 0) {
        data = { address: response[0], network: 'mainnet', connected: true, isConnected: true };
      }
      // Transform balance response to include 'balance' field
      if (method === 'getBalance' && response && typeof response === 'object' && !Array.isArray(response)) {
        data = { ...response, balance: (response as any).total ?? (response as any).public ?? 0, available: (response as any).total ?? (response as any).public ?? 0 };
      }
      window.postMessage({
        source: '0xio-sdk-bridge',
        response: { id: sdkId, success: true, data },
      }, '*');
    },
    reject: (error) => {
      window.postMessage({
        source: '0xio-sdk-bridge',
        response: {
          id: sdkId,
          success: false,
          error: { code: 'TRANSACTION_FAILED', message: error.message },
        },
      }, '*');
    },
  });

  // Map SDK methods to our internal methods
  let internalMethod = method;
  let internalParams: unknown[] = [];

  switch (method) {
    case 'connect':
      internalMethod = 'octra_requestAccounts';
      break;
    case 'getBalance':
      internalMethod = 'octra_getBalance';
      break;
    case 'sendTransaction':
      internalMethod = 'octra_sendTransaction';
      internalParams = [params];
      break;
    case 'signMessage':
      internalMethod = 'octra_signMessage';
      internalParams = [params.message ?? params];
      break;
    case 'callContract':
      internalMethod = 'octra_callContract';
      internalParams = [params];
      break;
    case 'contractCallView':
    case 'contract_call_view':
      internalMethod = 'octra_contractCallView';
      internalParams = [params];
      break;
    case 'getNetworkInfo':
    case 'get_network_info':
      internalMethod = 'octra_getNetworkInfo';
      break;
    case 'getConnectionStatus':
      internalMethod = 'octra_requestAccounts';
      break;
    case 'ping':
      // Respond immediately to ping
      pending.delete(internalId);
      window.postMessage({
        source: '0xio-sdk-bridge',
        response: { id: sdkId, success: true, data: { pong: true, version: '0.1.0' } },
      }, '*');
      return;
    case 'register_dapp':
      // Acknowledge dApp registration
      pending.delete(internalId);
      window.postMessage({
        source: '0xio-sdk-bridge',
        response: { id: sdkId, success: true, data: { registered: true } },
      }, '*');
      return;
    case 'switchNetwork':
      pending.delete(internalId);
      window.postMessage({
        source: '0xio-sdk-bridge',
        response: { id: sdkId, success: true, data: { network: 'mainnet', switched: true } },
      }, '*');
      return;
    default:
      internalMethod = method.startsWith('octra_') ? method : `octra_${method}`;
      internalParams = Array.isArray(params) ? params : [params];
  }

  window.postMessage(
    { target: 'octra-content', id: internalId, method: internalMethod, params: internalParams },
    '*',
  );

  // Timeout
  setTimeout(() => {
    if (pending.has(internalId)) {
      pending.delete(internalId);
      window.postMessage({
        source: '0xio-sdk-bridge',
        response: {
          id: sdkId,
          success: false,
          error: { code: 'NETWORK_ERROR', message: 'Request timed out' },
        },
      }, '*');
    }
  }, DAPP_REQUEST_TIMEOUT_MS);
});

// Signal to SDKs that the provider is ready
window.dispatchEvent(new Event('octra#initialized'));
window.dispatchEvent(new Event('octraWalletReady'));
window.dispatchEvent(new Event('wallet0xioReady'));
window.dispatchEvent(new Event('0xioWalletReady'));
window.postMessage({ source: '0xio-sdk-bridge', event: { type: 'walletReady' } }, '*');
