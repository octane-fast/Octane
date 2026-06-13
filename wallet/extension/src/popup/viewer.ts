/**
 * NFT Viewer — standalone page opened from the Content tab.
 * Reads NFT data from chrome.storage.local keyed by URL param `id`.
 */

interface NftViewData {
  name: string;
  description: string;
  imgDataUrl: string;
  tokenId: number;
  collectionName: string;
  collectionSymbol: string;
  attributes: Array<{ trait_type: string; value: string }>;
  rawMeta: Record<string, unknown>;
  contractAddr: string;
}

function escapeHtml(str: string): string {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

async function init() {
  const params = new URLSearchParams(window.location.search);
  const viewId = params.get('id');
  const root = document.getElementById('viewer-root')!;

  if (!viewId) {
    root.innerHTML = '<p class="viewer-error">Missing view ID</p>';
    return;
  }

  const key = `nftView:${viewId}`;
  let data: NftViewData | undefined;

  try {
    const stored = await chrome.storage.local.get(key);
    data = stored[key] as NftViewData | undefined;
    // Clean up after reading
    await chrome.storage.local.remove(key);
  } catch {
    // Fallback: try reading from sessionStorage (for non-extension contexts)
    try {
      const raw = sessionStorage.getItem(key);
      if (raw) data = JSON.parse(raw);
      sessionStorage.removeItem(key);
    } catch { /* ignore */ }
  }

  if (!data) {
    root.innerHTML = '<p class="viewer-error">NFT data not found. Try opening from the wallet again.</p>';
    return;
  }

  document.title = `${data.collectionName} #${data.tokenId}`;

  const attrsHtml = data.attributes.length > 0
    ? `<div class="viewer-attrs">${data.attributes.map(a =>
        `<div class="viewer-attr">
          <span class="viewer-attr-type">${escapeHtml(a.trait_type)}</span>
          <span class="viewer-attr-value">${escapeHtml(String(a.value))}</span>
        </div>`
      ).join('')}</div>`
    : '';

  const rawMetaJson = JSON.stringify(data.rawMeta, null, 2);

  root.innerHTML = `
    <div class="viewer-header">
      <button class="back-btn" id="viewer-close">✕ Close</button>
      <span class="col-name">${escapeHtml(data.collectionName)}</span>
      <span class="token-id">#${data.tokenId}</span>
    </div>
    <div class="viewer-body">
      ${data.imgDataUrl
        ? `<div class="viewer-image-wrap"><img src="${data.imgDataUrl}" alt="${escapeHtml(data.name)}" /></div>`
        : '<div class="viewer-image-wrap" style="height:300px;display:flex;align-items:center;justify-content:center;color:#787884;">No Image</div>'
      }
      <div class="viewer-info">
        <h1 class="viewer-title">${escapeHtml(data.name)}</h1>
        ${data.description ? `<p class="viewer-desc">${escapeHtml(data.description)}</p>` : ''}
        ${attrsHtml}
        <details class="viewer-meta">
          <summary>Raw Metadata</summary>
          <pre>${escapeHtml(rawMetaJson)}</pre>
        </details>
      </div>
    </div>
  `;

  document.getElementById('viewer-close')!.addEventListener('click', () => {
    window.close();
  });
}

init();
