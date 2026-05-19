// Injected into the page context to provide window.octra per RFC-O-1

interface PendingRequest {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
}

const pending = new Map<number, PendingRequest>();
let nextId = 1;

type Listener = (...args: unknown[]) => void;
const listeners = new Map<string, Set<Listener>>();

window.addEventListener('message', (event) => {
  if (event.source !== window) return;
  if (event.data?.target !== 'octra-inpage') return;

  const { id, response } = event.data;
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
      // Timeout after 30s
      setTimeout(() => {
        if (pending.has(id)) {
          pending.delete(id);
          reject(new Error('Request timed out'));
        }
      }, 30000);
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
