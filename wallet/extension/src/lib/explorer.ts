const EXPLORER_BASE = 'https://octrascan.io';

export function txUrl(hash: string): string {
  return `${EXPLORER_BASE}/tx.html?hash=${hash}`;
}

export function addressUrl(address: string): string {
  return `${EXPLORER_BASE}/address.html?addr=${address}`;
}

export function txLink(hash: string, label?: string): string {
  const text = label ?? 'View on OctraScan ↗';
  const url = txUrl(hash);
  return `<a href="${url}" target="_blank" rel="noopener">${text}</a>`;
}
