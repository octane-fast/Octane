import { createMnemonic, isValidMnemonic, walletFromMnemonic } from '../lib/crypto';
import { encryptMnemonic, saveWallet, loadWallet, hasWallet, clearWallet } from '../lib/storage';
import type { Account } from '../lib/storage';
import { toBase64 } from '../lib/crypto';
import { txUrl, txLink } from '../lib/explorer';

// Feature flags (must match background)
const FEATURE_TOR = true;

// Screens
const screenSetup = document.getElementById('screen-setup')!;
const screenCreate = document.getElementById('screen-create')!;
const screenImport = document.getElementById('screen-import')!;
const screenUnlock = document.getElementById('screen-unlock')!;
const screenMain = document.getElementById('screen-main')!;

function showScreen(screen: HTMLElement) {
  [screenSetup, screenCreate, screenImport, screenUnlock, screenMain].forEach(s => s.classList.add('hidden'));
  screen.classList.remove('hidden');
}

function showToast(msg: string, duration = 2000) {
  const toast = document.getElementById('toast')!;
  toast.innerHTML = '';
  toast.textContent = msg;
  toast.classList.remove('hidden');
  if (duration > 0) setTimeout(() => toast.classList.add('hidden'), duration);
}

function showStealthClaimToast(outputs: Array<Record<string, unknown>>) {
  const toast = document.getElementById('toast')!;
  const count = outputs.length;
  toast.innerHTML = `<span>🔒 ${count} stealth payment${count > 1 ? 's' : ''} available</span><button id="toast-claim-all" class="toast-action">Claim</button>`;
  toast.classList.remove('hidden');
  document.getElementById('toast-claim-all')!.addEventListener('click', async () => {
    toast.innerHTML = '<span>Claiming...</span>';
    for (const out of outputs) {
      try {
        const res = await sendMsg('STEALTH_CLAIM', { id: out.id, eph_pub: out.eph_pub, enc_amount: out.enc_amount }) as { jobId?: string; amount?: string; error?: string };
        if (res.jobId) {
          await chrome.storage.local.set({ activeClaimJob: res.jobId, activeClaimStart: Date.now() });
          const resultEl = document.getElementById('send-result')!;
          pollJobStatus(res.jobId, resultEl, 'claim');
        } else if (res.error) {
          showToast(`Claim failed: ${res.error}`);
        }
      } catch { showToast('Claim failed'); }
    }
    toast.classList.add('hidden');
  });
}

async function sendMsg(type: string, payload: Record<string, unknown> = {}): Promise<unknown> {
  return chrome.runtime.sendMessage({ type, payload });
}

// Init
async function init() {
  // Hide Tor UI when feature is disabled
  if (!FEATURE_TOR) {
    document.querySelectorAll('.tor-toggle, .tor-instructions, .tor-status, [id^="tor-"]').forEach(el => {
      (el as HTMLElement).style.display = 'none';
    });
    // Also hide the header Tor toggle
    document.querySelectorAll('.header-actions .toggle-row').forEach(el => {
      (el as HTMLElement).style.display = 'none';
    });
  } else {
    // Sync Tor toggle state from storage
    const { torEnabled } = await chrome.storage.local.get('torEnabled');
    const torSetup = document.getElementById('tor-toggle-setup') as HTMLInputElement;
    const torUnlock = document.getElementById('tor-toggle-unlock') as HTMLInputElement;
    const torMain = document.getElementById('tor-toggle-main') as HTMLInputElement;
    torSetup.checked = !!torEnabled;
    torUnlock.checked = !!torEnabled;
    torMain.checked = !!torEnabled;
  }

  const walletExists = await hasWallet();
  if (walletExists) {
    showScreen(screenUnlock);
  } else {
    showScreen(screenSetup);
  }
}

// Tor toggle sync
function setupTorToggles() {
  if (!FEATURE_TOR) return;
  const torSetup = document.getElementById('tor-toggle-setup') as HTMLInputElement;
  const torUnlock = document.getElementById('tor-toggle-unlock') as HTMLInputElement;
  const torMain = document.getElementById('tor-toggle-main') as HTMLInputElement;
  const torStatusSetup = document.getElementById('tor-status-setup')!;
  const torStatus = document.getElementById('tor-status')!;

  function setAllToggles(checked: boolean) {
    torSetup.checked = checked;
    torUnlock.checked = checked;
    torMain.checked = checked;
  }

  function setTorStatus(state: 'checking' | 'connected' | 'failed' | 'off') {
    const msg = {
      checking: 'Checking Tor connection...',
      connected: '\u2713 Connected via Tor',
      failed: '\u2717 Cannot reach Tor proxy \u2014 is Tor Browser running?',
      off: '',
    }[state];
    const cls = 'tor-status tor-status-' + state;
    torStatus.className = cls;
    torStatus.textContent = msg;
    torStatusSetup.className = cls;
    torStatusSetup.textContent = msg;
  }

  async function onTorToggle(enabled: boolean) {
    if (enabled) {
      setTorStatus('checking');
      const res = await sendMsg('SET_TOR', { enabled: true }) as { success?: boolean; error?: string };
      if (res.error) {
        setTorStatus('failed');
        setAllToggles(false);
        await chrome.storage.local.set({ torEnabled: false });
        return;
      }
      await chrome.storage.local.set({ torEnabled: true });
      setAllToggles(true);
      setTorStatus('connected');
      showToast('Tor routing enabled');
    } else {
      const confirmed = confirm('Disconnect from Tor? Your RPC traffic will no longer be routed privately.');
      if (!confirmed) {
        setAllToggles(true);
        return;
      }
      await sendMsg('SET_TOR', { enabled: false });
      await chrome.storage.local.set({ torEnabled: false });
      setAllToggles(false);
      setTorStatus('off');
      showToast('Tor routing disabled');
    }
  }

  torSetup.addEventListener('change', () => onTorToggle(torSetup.checked));
  torUnlock.addEventListener('change', () => onTorToggle(torUnlock.checked));
  torMain.addEventListener('change', () => onTorToggle(torMain.checked));
}
setupTorToggles();

// Setup
document.getElementById('btn-create')!.addEventListener('click', () => {
  const mnemonic = createMnemonic();
  document.getElementById('mnemonic-display')!.textContent = mnemonic;
  (document.getElementById('mnemonic-display')! as HTMLElement).dataset.mnemonic = mnemonic;
  showScreen(screenCreate);
});

document.getElementById('btn-import')!.addEventListener('click', () => {
  showScreen(screenImport);
});

document.getElementById('btn-back-setup')!.addEventListener('click', () => showScreen(screenSetup));
document.getElementById('btn-back-setup2')!.addEventListener('click', () => showScreen(screenSetup));

// Create wallet
document.getElementById('btn-confirm-create')!.addEventListener('click', async () => {
  const mnemonic = (document.getElementById('mnemonic-display')! as HTMLElement).dataset.mnemonic!;
  const pw = (document.getElementById('create-password') as HTMLInputElement).value;
  const pw2 = (document.getElementById('create-password-confirm') as HTMLInputElement).value;
  if (!pw || pw.length < 4) { showToast('Password too short'); return; }
  if (pw !== pw2) { showToast('Passwords do not match'); return; }

  const wallet = walletFromMnemonic(mnemonic, 0);
  const encrypted = await encryptMnemonic(mnemonic, pw);
  await saveWallet({
    encryptedSeed: encrypted,
    accounts: [{ name: 'Account 1', hdIndex: 0, address: wallet.address }],
    activeIndex: 0,
  });
  await sendMsg('UNLOCK', { encryptedSeed: encrypted, password: pw, hdIndex: 0 });
  await loadMainScreen();
});

// Import wallet
document.getElementById('btn-confirm-import')!.addEventListener('click', async () => {
  const mnemonic = (document.getElementById('import-mnemonic') as HTMLTextAreaElement).value.trim().toLowerCase();
  const pw = (document.getElementById('import-password') as HTMLInputElement).value;
  if (!isValidMnemonic(mnemonic)) { showToast('Invalid seed phrase'); return; }
  if (!pw || pw.length < 4) { showToast('Password too short'); return; }

  const wallet = walletFromMnemonic(mnemonic, 0);
  const encrypted = await encryptMnemonic(mnemonic, pw);
  await saveWallet({
    encryptedSeed: encrypted,
    accounts: [{ name: 'Account 1', hdIndex: 0, address: wallet.address }],
    activeIndex: 0,
  });
  await sendMsg('UNLOCK', { encryptedSeed: encrypted, password: pw, hdIndex: 0 });
  await loadMainScreen();
});

// Unlock
document.getElementById('btn-unlock')!.addEventListener('click', doUnlock);
document.getElementById('unlock-password')!.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') doUnlock();
});

async function doUnlock() {
  const pw = (document.getElementById('unlock-password') as HTMLInputElement).value;
  const state = await loadWallet();
  if (!state) { showToast('No wallet found'); return; }
  const activeAccount = state.accounts[state.activeIndex];
  try {
    const res = await sendMsg('UNLOCK', { encryptedSeed: state.encryptedSeed, password: pw, hdIndex: activeAccount.hdIndex }) as { success?: boolean; error?: string };
    if (res.error) { showToast('Incorrect password'); return; }
    await loadMainScreen();
  } catch {
    showToast('Incorrect password');
  }
}

// Lock
document.getElementById('btn-lock')!.addEventListener('click', async () => {
  await sendMsg('LOCK');
  showScreen(screenUnlock);
});

// Copy address
document.getElementById('btn-copy-address')!.addEventListener('click', () => {
  const addr = document.getElementById('display-address')!.getAttribute('data-full')!;
  navigator.clipboard.writeText(addr);
  showToast('Copied!');
});

// Tabs
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    const target = (tab as HTMLElement).dataset.tab!;
    document.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));
    document.getElementById(`tab-${target}`)!.classList.remove('hidden');

  });
});

// === Polling Services ===
// Centralized polling for all live data updates

async function refreshPublicBalance() {
  const balRes = await sendMsg('GET_BALANCE') as { formatted?: string; error?: string };
  const publicBal = balRes.formatted ?? '0';
  document.getElementById('display-public-balance')!.textContent = publicBal;
  const pub = parseFloat(publicBal) || 0;
  const privEl = document.getElementById('display-private-balance')!;
  const priv = parseFloat(privEl.textContent || '0') || 0;
  document.getElementById('display-balance')!.textContent = `${(pub + priv).toFixed(2)} OCT`;
}

async function refreshPrivateBalance() {
  const privEl = document.getElementById('display-private-balance')!;
  try {
    const privPromise = sendMsg('GET_DECRYPTED_BALANCE') as Promise<{ balance?: string; error?: string }>;
    const timeout = new Promise<{ error: string }>((resolve) => setTimeout(() => resolve({ error: 'timeout' }), 4000));
    const privRes = await Promise.race([privPromise, timeout]);
    if (!privRes.error && privRes.balance !== undefined) {
      privEl.classList.remove('shimmer');
      privEl.textContent = privRes.balance;
      // Update total
      const pubEl = document.getElementById('display-public-balance')!;
      const pub = parseFloat(pubEl.textContent || '0') || 0;
      const priv = parseFloat(privRes.balance) || 0;
      document.getElementById('display-balance')!.textContent = `${(pub + priv).toFixed(2)} OCT`;
    }
  } catch { /* silent */ }
}

async function refreshTokens() {
  const tokRes = await sendMsg('GET_TOKENS') as { tokens?: Array<{ name: string; symbol: string; balance: string; decimals: number }> };

  // Find octUSD balance from token list (used by swap modal)
  const octUsd = tokRes.tokens?.find(t => t.symbol === 'octUSD');
  const octUsdBal = octUsd ? (Number(octUsd.balance) / Math.pow(10, octUsd.decimals)).toFixed(octUsd.decimals > 4 ? 4 : octUsd.decimals) : '0';
  // Store for swap modal reference
  (window as any).__octUsdBal = octUsdBal;
}

// --- octUSD Swap Modal ---
const OCTUSD_CONTRACT = 'oct2hJMZbBdAAKTBXK61vs1TUx8oQNZVZyEpR4SXGFXgtvE';
let swapDirection: 'buy' | 'sell' = 'buy';
let octUsdPrice = 0; // raw int from contract (e.g. 56877 means $0.056877/OCT)

async function fetchOctUsdPrice(): Promise<number> {
  const res = await sendMsg('RPC_PASSTHROUGH', { method: 'contract_call', params: [OCTUSD_CONTRACT, 'get_octra_price', [], ''] }) as { result?: number; error?: string };
  if (res.result !== undefined) {
    octUsdPrice = Number(res.result);
  }
  return octUsdPrice;
}

function openSwapModal() {
  const modal = document.getElementById('swap-modal')!;
  modal.classList.remove('hidden');
  swapDirection = 'buy';
  updateSwapTabs();
  (document.getElementById('swap-input') as HTMLInputElement).value = '';
  document.getElementById('swap-preview')!.textContent = '';
  document.getElementById('swap-result')!.textContent = '';
  (document.getElementById('btn-swap-confirm') as HTMLButtonElement).disabled = true;
  // Fetch price
  document.getElementById('swap-rate')!.textContent = 'Loading rate...';
  fetchOctUsdPrice().then(p => {
    if (p > 0) {
      const priceUsd = (p / 1_000_000).toFixed(6);
      document.getElementById('swap-rate')!.textContent = `1 OCT = ${priceUsd} octUSD`;
    } else {
      document.getElementById('swap-rate')!.textContent = 'Could not fetch price';
    }
  });
}

function updateSwapTabs() {
  document.querySelectorAll('.swap-tab').forEach(t => {
    t.classList.toggle('active', (t as HTMLElement).dataset.dir === swapDirection);
  });
  const label = document.getElementById('swap-input-label')!;
  const input = document.getElementById('swap-input') as HTMLInputElement;
  if (swapDirection === 'buy') {
    label.textContent = 'You pay (OCT)';
    input.placeholder = '0.00';
  } else {
    label.textContent = 'You sell (octUSD)';
    input.placeholder = '0.00';
  }
  document.getElementById('swap-preview')!.textContent = '';
  input.value = '';
  (document.getElementById('btn-swap-confirm') as HTMLButtonElement).disabled = true;
}

document.getElementById('swap-close')!.addEventListener('click', () => {
  document.getElementById('swap-modal')!.classList.add('hidden');
});

document.querySelectorAll('.swap-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    swapDirection = (tab as HTMLElement).dataset.dir as 'buy' | 'sell';
    updateSwapTabs();
  });
});

document.getElementById('swap-input')!.addEventListener('input', () => {
  const val = (document.getElementById('swap-input') as HTMLInputElement).value.trim();
  const num = parseFloat(val);
  const preview = document.getElementById('swap-preview')!;
  const btn = document.getElementById('btn-swap-confirm') as HTMLButtonElement;
  if (!val || isNaN(num) || num <= 0 || octUsdPrice <= 0) {
    preview.textContent = '';
    btn.disabled = true;
    return;
  }
  btn.disabled = false;
  if (swapDirection === 'buy') {
    // Paying OCT, receiving octUSD: mint_amount = (oct_raw * price) / 1e6
    const octUsdReceived = (num * octUsdPrice) / 1_000_000;
    preview.textContent = `≈ ${octUsdReceived.toFixed(4)} octUSD`;
  } else {
    // Selling octUSD, receiving OCT: oct = (amount * 1e6) / price
    const octReceived = (num * 1_000_000) / octUsdPrice;
    preview.textContent = `≈ ${octReceived.toFixed(6)} OCT`;
  }
});

document.getElementById('btn-swap-confirm')!.addEventListener('click', async () => {
  const btn = document.getElementById('btn-swap-confirm') as HTMLButtonElement;
  const resultEl = document.getElementById('swap-result')!;
  const val = (document.getElementById('swap-input') as HTMLInputElement).value.trim();
  const num = parseFloat(val);
  if (!val || isNaN(num) || num <= 0) return;

  btn.disabled = true;
  btn.textContent = 'Submitting...';
  resultEl.textContent = '';

  try {
    let res: { hash?: string; error?: string };
    if (swapDirection === 'buy') {
      // mint: send OCT to contract
      res = await sendMsg('SWAP_OCTUSD', { direction: 'buy', amount: val }) as { hash?: string; error?: string };
    } else {
      // redeem: burn octUSD
      res = await sendMsg('SWAP_OCTUSD', { direction: 'sell', amount: val }) as { hash?: string; error?: string };
    }
    if (res.error) {
      resultEl.textContent = res.error;
      resultEl.style.color = 'var(--error, #ef4444)';
    } else {
      resultEl.textContent = `Success! TX: ${res.hash?.slice(0, 12)}…`;
      resultEl.style.color = 'var(--success, #22c55e)';
      (document.getElementById('swap-input') as HTMLInputElement).value = '';
      document.getElementById('swap-preview')!.textContent = '';
    }
  } catch (err) {
    resultEl.textContent = (err as Error).message ?? 'Unknown error';
    resultEl.style.color = 'var(--error, #ef4444)';
  }
  btn.textContent = 'Confirm Swap';
  btn.disabled = false;
});

async function scanForStealthPayments() {
  try {
    const res = await sendMsg('STEALTH_SCAN', {}) as { outputs?: Array<Record<string, unknown>>; error?: string };
    if (res.outputs && res.outputs.length > 0) {
      showStealthClaimToast(res.outputs);
    }
  } catch { /* silent */ }
}

const PollingService = {
  timers: [] as ReturnType<typeof setInterval>[],

  start() {
    this.stop(); // Clear any existing timers
    // Public balance + tokens: every 3s (fast, no PVAC)
    this.timers.push(setInterval(async () => {
      await refreshPublicBalance();
      await refreshTokens();
    }, 3000));
    // Private balance: every 10s (may be slow due to PVAC)
    this.timers.push(setInterval(() => { refreshPrivateBalance(); }, 10000));
    refreshPrivateBalance(); // fire immediately
    // Activity: every 10s
    this.timers.push(setInterval(() => loadActivity(), 10000));
    // Stealth scan: every 30s
    scanForStealthPayments();
    this.timers.push(setInterval(() => scanForStealthPayments(), 30000));
  },

  stop() {
    this.timers.forEach(t => clearInterval(t));
    this.timers = [];
  },
};

// Main screen
async function loadMainScreen() {
  showScreen(screenMain);
  checkActiveJob();

  // Populate account selector from background (fresh derivation)
  const accRes = await sendMsg('GET_ACCOUNTS') as { accounts?: Array<{ name: string; hdIndex: number; address: string }>; activeHdIndex?: number; error?: string };
  const select = document.getElementById('account-select') as HTMLSelectElement;
  if (accRes.accounts) {
    select.innerHTML = accRes.accounts.map((acc, i) => {
      const isActive = acc.hdIndex === (accRes.activeHdIndex ?? 0);
      return `<option value="${i}"${isActive ? ' selected' : ''}>${escapeHtml(acc.name)} (${acc.address.slice(0, 8)}…${acc.address.slice(-6)})</option>`;
    }).join('');
  }

  const addrRes = await sendMsg('GET_ADDRESS') as { address?: string; error?: string };
  if (addrRes.error) { showToast('Incorrect password'); showScreen(screenUnlock); return; }
  const fullAddr = addrRes.address!;
  const addrEl = document.getElementById('display-address')!;
  addrEl.setAttribute('data-full', fullAddr);
  addrEl.textContent = fullAddr.slice(0, 12) + '…' + fullAddr.slice(-10);

  // Initial data load — fetch public balance + tokens immediately, private balance async
  await refreshPublicBalance();
  await refreshTokens();
  await loadActivity();

  // Start polling services (includes private balance)
  PollingService.start();
}

// In-memory activity cache, keyed by tx_hash for deduplication
const activityCache = new Map<string, Record<string, unknown>>();
let lastActivityHtml = '';
let activityLoading = false;

async function loadActivity() {
  if (activityLoading) return;
  activityLoading = true;
  try {
  const actList = document.getElementById('activity-list')!;
  const pendingEl = document.getElementById('activity-pending')!;

  // Show running jobs at top (separate element, no flicker on main list)
  const { activeUnshieldJob, activeUnshieldStart, activeShieldJob, activeShieldStart, activeStealthJob, activeStealthStart, activeClaimJob, activeClaimStart } =
    await chrome.storage.local.get(['activeUnshieldJob', 'activeUnshieldStart', 'activeShieldJob', 'activeShieldStart', 'activeStealthJob', 'activeStealthStart', 'activeClaimJob', 'activeClaimStart']);

  const activeJobId = activeUnshieldJob || activeShieldJob || activeStealthJob || activeClaimJob;
  const activeStart = activeUnshieldJob ? activeUnshieldStart : activeShieldJob ? activeShieldStart : activeClaimJob ? activeClaimStart : activeStealthStart;
  const activeLabel = activeUnshieldJob ? 'Unshielding' : activeStealthJob ? 'Stealth Send' : activeClaimJob ? 'Claiming' : 'Shielding';
  const activeTypeClass = activeUnshieldJob ? 'unshield' : activeStealthJob ? 'stealth' : activeClaimJob ? 'claim' : 'shield';

  if (activeJobId) {
    const job = await sendMsg('GET_JOB_STATUS', { jobId: activeJobId }) as { status: string; step?: string };
    if (job.status === 'running' || job.status === 'pending_unlock' || job.status === 'crypto_done') {
      const elapsed = activeStart ? Math.floor((Date.now() - activeStart) / 1000) : 0;
      const timeStr = elapsed < 60 ? `${elapsed}s ago` : `${Math.floor(elapsed / 60)}m ${elapsed % 60}s ago`;
      pendingEl.innerHTML = `<div class="activity-item pending">
        <div class="activity-row"><span class="activity-type ${activeTypeClass}">${activeLabel}</span><span class="activity-amount">In Progress</span></div>
        <div class="activity-row"><span class="activity-addr">${escapeHtml(job.step ?? 'working...')}</span><span class="activity-time">${timeStr}</span></div>
        <div class="activity-row"><button class="cancel-unshield" data-job="${escapeHtml(activeJobId)}">Cancel</button></div>
      </div>`;
      pendingEl.querySelector('.cancel-unshield')?.addEventListener('click', async (e) => {
        e.stopPropagation();
        const jobId = (e.target as HTMLElement).dataset.job!;
        await sendMsg('CANCEL_JOB', { jobId });
        await chrome.storage.local.remove(['activeUnshieldJob', 'activeUnshieldStart', 'activeShieldJob', 'activeShieldStart', 'activeStealthJob', 'activeStealthStart', 'activeClaimJob', 'activeClaimStart']);
        pendingEl.innerHTML = '';
        if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
        const resultEl = document.getElementById('send-result');
        if (resultEl) resultEl.textContent = `${activeLabel} cancelled.`;
      });
    } else {
      pendingEl.innerHTML = '';
    }
  } else {
    pendingEl.innerHTML = '';
  }

  const myAddr = document.getElementById('display-address')!.getAttribute('data-full') ?? '';
  const res = await sendMsg('GET_ACTIVITY') as { transactions?: Array<Record<string, unknown>>; error?: string };

  // Merge new results into cache (add-only); on error, keep existing cache
  if (!res.error && res.transactions && res.transactions.length > 0) {
    for (const tx of res.transactions) {
      const hash = String(tx.tx_hash ?? '');
      if (hash) activityCache.set(hash, tx);
    }
  }

  // Render from cache
  if (activityCache.size === 0) {
    const emptyHtml = '<p class="muted">No recent activity</p>';
    if (lastActivityHtml !== emptyHtml) {
      actList.innerHTML = emptyHtml;
      lastActivityHtml = emptyHtml;
    }
    return;
  }

  // Sort by timestamp descending
  const sorted = [...activityCache.values()].sort((a, b) => Number(b.timestamp ?? 0) - Number(a.timestamp ?? 0));

  const newHtml = sorted.map(tx => {
    const from = String(tx.from ?? '');
    const to = String(tx.to ?? tx.to_ ?? '');
    const amountRaw = Number(tx.amount_raw ?? tx.amount ?? 0);
    const amount = (amountRaw / 1000000).toFixed(6).replace(/\.?0+$/, '');
    const opType = String(tx.op_type ?? 'standard');
    const hash = String(tx.tx_hash ?? '');
    const ts = Number(tx.timestamp ?? 0);
    const time = ts ? new Date(ts * 1000).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : '';

    let typeLabel: string;
    let typeClass: string;
    let counterparty: string;
    if (opType === 'encrypt') {
      typeLabel = 'Shield';
      typeClass = 'shield';
      counterparty = to;
    } else if (opType === 'decrypt') {
      typeLabel = 'Unshield';
      typeClass = 'unshield';
      counterparty = to;
    } else if (opType === 'call') {
      typeLabel = 'Contract Call';
      typeClass = 'call';
      counterparty = to;
    } else if (from === myAddr) {
      typeLabel = 'Sent';
      typeClass = 'send';
      counterparty = to;
    } else {
      typeLabel = 'Received';
      typeClass = 'receive';
      counterparty = from;
    }

    return `<div class="activity-item" data-hash="${escapeHtml(hash)}" title="View on OctraScan">
      <div class="activity-row"><span class="activity-type ${typeClass}">${typeLabel}</span><span class="activity-amount">${amount ? amount + ' OCT' : ''}</span></div>
      <div class="activity-row"><span class="activity-addr">${escapeHtml(counterparty)}</span><span class="activity-time">${time}</span></div>
    </div>`;
  }).join('');

  // Only update DOM if content actually changed
  if (newHtml !== lastActivityHtml) {
    actList.innerHTML = newHtml;
    lastActivityHtml = newHtml;

    // Click to open on explorer
    actList.querySelectorAll('.activity-item').forEach(el => {
      el.addEventListener('click', () => {
        const hash = (el as HTMLElement).dataset.hash;
        if (hash) window.open(txUrl(hash), '_blank');
      });
    });
  }
  } finally { activityLoading = false; }
}

// Switch account
document.getElementById('account-select')!.addEventListener('change', async (e) => {
  const idx = parseInt((e.target as HTMLSelectElement).value);
  const state = await loadWallet();
  if (!state) return;
  state.activeIndex = idx;
  await saveWallet(state);
  const account = state.accounts[idx];
  await sendMsg('SWITCH_ACCOUNT', { hdIndex: account.hdIndex });
  await loadMainScreen();
});

// Add account
document.getElementById('btn-add-account')!.addEventListener('click', async () => {
  if (!confirm('Create a new account?')) return;
  const state = await loadWallet();
  if (!state) return;
  const nextHdIndex = Math.max(...state.accounts.map(a => a.hdIndex)) + 1;
  const name = `Account ${state.accounts.length + 1}`;
  const res = await sendMsg('ADD_ACCOUNT', { name, hdIndex: nextHdIndex }) as { address?: string; error?: string };
  if (res.error) { showToast(res.error); return; }
  state.accounts.push({ name, hdIndex: nextHdIndex, address: res.address! });
  state.activeIndex = state.accounts.length - 1;
  await saveWallet(state);
  await sendMsg('SWITCH_ACCOUNT', { hdIndex: nextHdIndex });
  await loadMainScreen();
  showToast(`${name} created`);
});

// Send - address suggestions
const sendToInput = document.getElementById('send-to') as HTMLInputElement;
const suggestionsEl = document.getElementById('send-to-suggestions')!;
let cachedAccounts: Array<{ name: string; hdIndex: number; address: string }> = [];

function getAddressSuggestions(): Array<{ label: string; address: string }> {
  const myAddr = document.getElementById('display-address')?.getAttribute('data-full') ?? '';
  return cachedAccounts
    .filter(acc => acc.address !== myAddr)
    .map(acc => ({ label: acc.name, address: acc.address }));
}

sendToInput.addEventListener('focus', async () => {
  const res = await sendMsg('GET_ACCOUNTS') as { accounts?: Array<{ name: string; hdIndex: number; address: string }> };
  cachedAccounts = res.accounts ?? [];
  showSuggestions('');
});

sendToInput.addEventListener('input', () => {
  showSuggestions(sendToInput.value);
});

sendToInput.addEventListener('blur', () => {
  setTimeout(() => suggestionsEl.classList.add('hidden'), 150);
});

function showSuggestions(filter: string) {
  const all = getAddressSuggestions();
  const filtered = filter
    ? all.filter(s => s.address.toLowerCase().includes(filter.toLowerCase()) || s.label.toLowerCase().includes(filter.toLowerCase()))
    : all;
  if (filtered.length === 0) {
    suggestionsEl.classList.add('hidden');
    return;
  }
  suggestionsEl.innerHTML = filtered.map(s =>
    `<div class="suggestion-item" data-addr="${escapeHtml(s.address)}"><span class="suggestion-label">${escapeHtml(s.label)}</span><span>${escapeHtml(s.address.slice(0, 14))}…${escapeHtml(s.address.slice(-8))}</span></div>`
  ).join('');
  suggestionsEl.classList.remove('hidden');
  suggestionsEl.querySelectorAll('.suggestion-item').forEach(el => {
    el.addEventListener('mousedown', (e) => {
      e.preventDefault();
      sendToInput.value = (el as HTMLElement).dataset.addr!;
      suggestionsEl.classList.add('hidden');
    });
  });
}

// Send / Shield / Unshield
let sendMode: 'send' | 'stealth' = 'send';
const submitSendBtn = document.getElementById('btn-submit-send') as HTMLButtonElement;
const submitShieldBtn = document.getElementById('btn-submit-shield') as HTMLButtonElement;
const submitUnshieldBtn = document.getElementById('btn-submit-unshield') as HTMLButtonElement;
const stealthToggleInput = document.getElementById('stealth-toggle-input') as HTMLInputElement;

function updateSendState() {
  const amount = (document.getElementById('send-amount') as HTMLInputElement).value.trim();
  const to = (document.getElementById('send-to') as HTMLInputElement).value.trim();
  submitSendBtn.disabled = !(amount && to);
}

function updateShieldState() {
  const amount = (document.getElementById('shield-amount') as HTMLInputElement).value.trim();
  submitShieldBtn.disabled = !amount;
}

function updateUnshieldState() {
  const amount = (document.getElementById('unshield-amount') as HTMLInputElement).value.trim();
  submitUnshieldBtn.disabled = !amount;
}

// Stealth toggle switch
stealthToggleInput.addEventListener('change', () => {
  if (stealthToggleInput.checked) {
    sendMode = 'stealth';
    submitSendBtn.textContent = 'Confirm Stealth Send';
  } else {
    sendMode = 'send';
    submitSendBtn.textContent = 'Confirm Send';
  }
});

// Validate inputs on typing
document.getElementById('send-amount')!.addEventListener('input', updateSendState);
document.getElementById('send-to')!.addEventListener('input', updateSendState);
document.getElementById('shield-amount')!.addEventListener('input', updateShieldState);
document.getElementById('unshield-amount')!.addEventListener('input', updateUnshieldState);

// Send submit handler
submitSendBtn.addEventListener('click', async () => {
  const amount = (document.getElementById('send-amount') as HTMLInputElement).value.trim();
  const to = (document.getElementById('send-to') as HTMLInputElement).value.trim();
  const resultEl = document.getElementById('send-result')!;
  if (!to || !amount) { showToast('Fill in all fields'); return; }

  if (sendMode === 'stealth') {
    resultEl.textContent = 'Stealth sending...';
    const res = await sendMsg('STEALTH_SEND', { to, amount }) as { jobId?: string; error?: string };
    if (res.error) {
      resultEl.textContent = `Error: ${res.error}`;
    } else if (res.jobId) {
      await chrome.storage.local.set({ activeStealthJob: res.jobId, activeStealthStart: Date.now() });
      pollJobStatus(res.jobId, resultEl, 'stealth');
    }
  } else {
    resultEl.textContent = 'Sending...';
    const res = await sendMsg('SEND_TRANSACTION', { to, amount }) as { hash?: string; error?: string };
    if (res.error) {
      resultEl.textContent = `Error: ${res.error}`;
    } else {
      resultEl.innerHTML = txLink(res.hash!, 'Confirmed — View on OctraScan ↗');
      showToast('Transaction sent!');
    }
  }
});

// Shield submit handler
submitShieldBtn.addEventListener('click', async () => {
  const amount = (document.getElementById('shield-amount') as HTMLInputElement).value.trim();
  if (!amount) { showToast('Enter an amount'); return; }
  const resultEl = document.getElementById('shield-result')!;
  resultEl.textContent = 'Shielding...';
  const res = await sendMsg('ENCRYPT_BALANCE', { amount }) as { jobId?: string; error?: string };
  if (res.error) {
    resultEl.textContent = `Error: ${res.error}`;
  } else if (res.jobId) {
    await chrome.storage.local.set({ activeShieldJob: res.jobId, activeShieldStart: Date.now() });
    pollJobStatus(res.jobId, resultEl, 'shield');
  }
});

// Unshield submit handler
submitUnshieldBtn.addEventListener('click', async () => {
  const amount = (document.getElementById('unshield-amount') as HTMLInputElement).value.trim();
  if (!amount) { showToast('Enter an amount'); return; }
  const resultEl = document.getElementById('unshield-result')!;
  resultEl.textContent = 'Unshielding...';
  const res = await sendMsg('DECRYPT_BALANCE', { amount }) as { jobId?: string; error?: string };
  if (res.error) {
    resultEl.textContent = `Error: ${res.error}`;
  } else if (res.jobId) {
    await chrome.storage.local.set({ activeUnshieldJob: res.jobId, activeUnshieldStart: Date.now() });
    pollJobStatus(res.jobId, resultEl, 'unshield');
  }
});

function escapeHtml(str: string): string {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// --- Job polling (shield + unshield + stealth) ---
let pollTimer: ReturnType<typeof setInterval> | null = null;

function pollJobStatus(jobId: string, resultEl: HTMLElement, jobType: 'shield' | 'unshield' | 'stealth' | 'claim' = 'unshield') {
  const label = jobType === 'shield' ? 'Shielding' : jobType === 'stealth' ? 'Stealth sending' : jobType === 'claim' ? 'Claiming' : 'Unshielding';
  const storageKeys = jobType === 'shield'
    ? ['activeShieldJob', 'activeShieldStart']
    : jobType === 'stealth'
    ? ['activeStealthJob', 'activeStealthStart']
    : jobType === 'claim'
    ? ['activeClaimJob', 'activeClaimStart']
    : ['activeUnshieldJob', 'activeUnshieldStart'];

  resultEl.textContent = `${label} — starting...`;
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    const res = await sendMsg('GET_JOB_STATUS', { jobId }) as { status: string; step?: string; hash?: string; error?: string };
    if (res.status === 'running') {
      resultEl.textContent = `${label} — ${res.step ?? 'working...'}`;
    } else if (res.status === 'pending_unlock') {
      resultEl.textContent = `${label} — ${res.step ?? 'waiting for unlock...'}`;
    } else if (res.status === 'crypto_done') {
      resultEl.textContent = `${label} — submitting transaction...`;
    } else if (res.status === 'done') {
      clearInterval(pollTimer!);
      pollTimer = null;
      await chrome.storage.local.remove(storageKeys);
      resultEl.innerHTML = txLink(res.hash!, 'Confirmed — View on OctraScan ↗');
      showToast(jobType === 'shield' ? 'Funds shielded!' : jobType === 'claim' ? 'Stealth funds claimed!' : jobType === 'stealth' ? 'Stealth send complete!' : 'Funds unshielded!');
      loadActivity();
    } else if (res.status === 'error') {
      clearInterval(pollTimer!);
      pollTimer = null;
      await chrome.storage.local.remove(storageKeys);
      resultEl.textContent = `Error: ${res.error}`;
    } else if (res.status === 'cancelled') {
      clearInterval(pollTimer!);
      pollTimer = null;
      resultEl.textContent = `${label} cancelled.`;
    }
  }, 2000);
}

// Check for running jobs on popup open
async function checkActiveJob() {
  const { activeUnshieldJob, activeShieldJob, activeStealthJob, activeClaimJob } = await chrome.storage.local.get(['activeUnshieldJob', 'activeShieldJob', 'activeStealthJob', 'activeClaimJob']);
  const resultEl = document.getElementById('send-result')!;
  if (activeUnshieldJob) {
    pollJobStatus(activeUnshieldJob, resultEl, 'unshield');
  } else if (activeShieldJob) {
    pollJobStatus(activeShieldJob, resultEl, 'shield');
  } else if (activeStealthJob) {
    pollJobStatus(activeStealthJob, resultEl, 'stealth');
  } else if (activeClaimJob) {
    pollJobStatus(activeClaimJob, resultEl, 'claim');
  }
}

init();
