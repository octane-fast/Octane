// Content script: injects inpage.js and relays messages between page and extension

const script = document.createElement('script');
script.src = chrome.runtime.getURL('dist/inpage.js');
script.type = 'module';
(document.head || document.documentElement).appendChild(script);
script.onload = () => script.remove();

// Relay from page to background
window.addEventListener('message', (event) => {
  if (event.source !== window) return;
  if (event.data?.target !== 'octra-content') return;

  const { id, method, params } = event.data;
  chrome.runtime.sendMessage({ type: 'RPC_PASSTHROUGH', payload: { method, params } }, (response) => {
    window.postMessage({ target: 'octra-inpage', id, response }, '*');
  });
});
