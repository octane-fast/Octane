/**
 * Offscreen document — thin relay between background service worker
 * and the PVAC Web Worker. Uses port for live updates, sendMessage for final result.
 * NOTE: chrome.storage is NOT available in offscreen documents.
 */

const worker = new Worker('./dist/pvac-worker.js', { type: 'module' });

let currentJobId: string | null = null;
let port: chrome.runtime.Port | null = null;
let pendingResult: any = null;

function connectPort() {
  port = chrome.runtime.connect({ name: 'offscreen' });
  port.onDisconnect.addListener(() => { port = null; });
}
connectPort();

// Forward status updates from worker to background
worker.onmessage = (ev: MessageEvent) => {
  const msg = ev.data;
  if (msg.type === 'status') {
    // Try port first (fast, but only works while SW is alive)
    if (port) {
      try { port.postMessage({ type: 'jobStatus', jobId: currentJobId, step: msg.step }); } catch { port = null; }
    }
  } else if (msg.type === 'result') {
    // Deliver final result — use sendMessage (wakes SW if dead)
    const payload = { target: 'background', action: 'cryptoComplete', jobId: currentJobId, data: msg.data };
    // Try port first
    if (port) {
      try { port.postMessage({ type: 'cryptoResult', jobId: currentJobId, data: msg.data }); return; } catch { port = null; }
    }
    // Port dead — use sendMessage to wake SW
    chrome.runtime.sendMessage(payload).catch(() => {
      // If this also fails, buffer the result — reconnect and retry
      pendingResult = payload;
      reconnectAndDeliver();
    });
  }
};

worker.onerror = (err) => {
  const payload = { target: 'background', action: 'cryptoError', jobId: currentJobId, error: err.message };
  if (port) {
    try { port.postMessage({ type: 'jobError', jobId: currentJobId, error: err.message }); return; } catch { port = null; }
  }
  chrome.runtime.sendMessage(payload).catch(() => {});
};

function reconnectAndDeliver() {
  // Reconnect port and deliver buffered result
  setTimeout(() => {
    connectPort();
    if (port && pendingResult) {
      try {
        port.postMessage({ type: 'cryptoResult', jobId: pendingResult.jobId, data: pendingResult.data });
        pendingResult = null;
      } catch { /* will retry via sendMessage on next attempt */ }
    }
  }, 1000);
}

// Receive work from background via port
port!.onMessage.addListener((msg) => {
  if (msg.action === 'computeUnshield' && msg.jobId) {
    currentJobId = msg.jobId;
    if (port) {
      try { port.postMessage({ type: 'jobStatus', jobId: msg.jobId, step: 'Initializing WASM module...' }); } catch { port = null; }
    }
    worker.postMessage(msg);
  }
  if (msg.action === 'warmup') {
    // Pre-load WASM module so decrypt is instant later
    worker.postMessage({ action: 'init', secretKeyB64: msg.secretKeyB64 });
  }
});

// Also support ping and decrypt via sendMessage
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.target !== 'offscreen') return;
  if (msg.action === 'ping') {
    sendResponse({ pong: true });
    return;
  }
  if (msg.action === 'decrypt') {
    // One-shot decrypt: send to worker, listen for result
    const handler = (ev: MessageEvent) => {
      if (ev.data.type === 'result') {
        worker.removeEventListener('message', handler);
        sendResponse(ev.data.data);
      }
    };
    worker.addEventListener('message', handler);
    worker.postMessage({ action: 'decrypt', pvacSkB64: msg.pvacSkB64, pvacPkB64: msg.pvacPkB64, keyId: msg.keyId, cipherB64: msg.cipherB64 });
    return true; // async sendResponse
  }
});
