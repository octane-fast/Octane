const MAINNET_EXPLORER = 'https://octrascan.io';
const DEVNET_EXPLORER = 'https://devnet.octrascan.io';
const DEVNET_RPC = 'https://devnet.octrascan.io/rpc';

let explorerBase = MAINNET_EXPLORER;

export function setExplorerFromRpc(rpcUrl: string) {
  explorerBase = rpcUrl === DEVNET_RPC ? DEVNET_EXPLORER : MAINNET_EXPLORER;
}

export function txUrl(hash: string): string {
  return `${explorerBase}/tx.html?hash=${hash}`;
}

export function addressUrl(address: string): string {
  return `${explorerBase}/address.html?addr=${address}`;
}

export function txLink(hash: string, label?: string): string {
  const text = label ?? 'View on OctraScan ↗';
  const url = txUrl(hash);
  return `<a href="${url}" target="_blank" rel="noopener">${text}</a>`;
}
