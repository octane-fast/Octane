import { FEATURE_TOR, TOR_SOCKS_PORT } from './constants';

export async function enableTorProxy() {
  if (!FEATURE_TOR) return;
  const config: chrome.proxy.ProxyConfig = {
    mode: 'pac_script' as const,
    pacScript: {
      data: `function FindProxyForURL(url, host) {
        if (host === "octra.network") {
          return "SOCKS5 127.0.0.1:${TOR_SOCKS_PORT}";
        }
        return "DIRECT";
      }`,
    },
  };
  await chrome.proxy.settings.set({ value: config, scope: 'regular' });
}

export async function disableTorProxy() {
  if (!FEATURE_TOR) return;
  await chrome.proxy.settings.clear({ scope: 'regular' });
}

/**
 * Check if a Tor SOCKS proxy is listening on the expected port.
 * SOCKS proxies reject HTTP — so any non-timeout error means it's up.
 */
export async function isTorReachable(): Promise<boolean> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 3000);
  try {
    await fetch(`http://127.0.0.1:${TOR_SOCKS_PORT}/`, {
      method: 'GET',
      signal: ctrl.signal,
    });
  } catch (e: any) {
    clearTimeout(timer);
    // AbortError means timeout = nothing listening
    if (e.name === 'AbortError') return false;
    // Any other error (Failed to fetch, connection reset, etc.)
    // means the port IS open — SOCKS proxies reject HTTP requests
    return true;
  }
  clearTimeout(timer);
  return true;
}
