// Content script: injects inpage.js and relays messages between page and extension

import { MSG_DAPP_REQUEST } from '../lib/constants';

const script = document.createElement('script');
script.src = chrome.runtime.getURL('dist/inpage.js');
(document.head || document.documentElement).appendChild(script);
script.onload = () => script.remove();

// Relay from page to background
window.addEventListener('message', (event) => {
  if (event.source !== window) return;
  if (event.data?.target !== 'octra-content') return;

  const { id, method, params } = event.data;
  const origin = window.location.origin;

  chrome.runtime.sendMessage(
    { type: MSG_DAPP_REQUEST, payload: { method, params, origin } },
    (response) => {
      window.postMessage({ target: 'octra-inpage', id, response }, '*');
    },
  );
});
