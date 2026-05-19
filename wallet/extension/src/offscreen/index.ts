/**
 * Offscreen document — thin relay between background service worker
 * and the PVAC Web Worker. The heavy computation runs in the worker
 * so this main thread stays responsive for message passing.
 */

const worker = new Worker('./dist/pvac-worker.js', { type: 'module' });

// Pending request from background
let pendingResolve: ((value: any) => void) | null = null;

// Forward status updates from worker to background
worker.onmessage = (ev: MessageEvent) => {
  const msg = ev.data;
  if (msg.type === 'status') {
    chrome.runtime.sendMessage({ target: 'background', jobUpdate: msg.step });
  } else if (msg.type === 'result') {
    if (pendingResolve) {
      pendingResolve(msg.data);
      pendingResolve = null;
    }
  }
};

worker.onerror = (err) => {
  if (pendingResolve) {
    pendingResolve({ error: `Worker error: ${err.message}` });
    pendingResolve = null;
  }
};

// Listen for messages from background service worker
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.target !== 'offscreen') return;
  // Readiness check
  if (msg.action === 'ping') {
    sendResponse({ pong: true });
    return;
  }
  // Send to worker, wait for result
  pendingResolve = sendResponse;
  worker.postMessage(msg);
  return true; // async response
});
