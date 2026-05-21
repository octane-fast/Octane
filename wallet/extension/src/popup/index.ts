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
  toast.textContent = msg;
  toast.classList.remove('hidden');
  setTimeout(() => toast.classList.add('hidden'), duration);
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
    if (target === 'send') fetchEncryptedBalance();
  });
});

// === Polling Services ===
// Centralized polling for all live data updates

async function refreshBalance() {
  const balRes = await sendMsg('GET_BALANCE') as { formatted?: string; error?: string };
  if (balRes.formatted) {
    document.getElementById('display-balance')!.textContent = `${balRes.formatted} OCT`;
  }
}

async function refreshTokens() {
  const balText = document.getElementById('display-balance')!.textContent?.replace(' OCT', '') ?? '0';
  const tokRes = await sendMsg('GET_TOKENS') as { tokens?: Array<{ name: string; symbol: string; balance: string; decimals: number }> };
  const tokenList = document.getElementById('token-list')!;
  let html = `<div class="token-item"><div><div class="token-name">Octra</div><div class="token-symbol">OCT</div></div><div class="token-balance">${escapeHtml(balText)}</div></div>`;
  if (tokRes.tokens && tokRes.tokens.length > 0) {
    html += tokRes.tokens.map(t => {
      const bal = (Number(t.balance) / Math.pow(10, t.decimals)).toFixed(t.decimals > 4 ? 4 : t.decimals);
      return `<div class="token-item"><div><div class="token-name">${escapeHtml(t.name)}</div><div class="token-symbol">${escapeHtml(t.symbol)}</div></div><div class="token-balance">${escapeHtml(bal)}</div></div>`;
    }).join('');
  }
  tokenList.innerHTML = html;
}

const PollingService = {
  timers: [] as ReturnType<typeof setInterval>[],

  start() {
    this.stop(); // Clear any existing timers
    // Balance + tokens: every 3s
    this.timers.push(setInterval(async () => {
      await refreshBalance();
      await refreshTokens();
    }, 3000));
    // Activity: every 1s
    this.timers.push(setInterval(() => loadActivity(), 1000));
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

  // Initial data load
  await refreshBalance();
  await refreshTokens();
  await loadActivity();

  // Start polling services
  PollingService.start();
}

// In-memory activity cache, keyed by tx_hash for deduplication
const activityCache = new Map<string, Record<string, unknown>>();
let lastActivityHtml = '';

async function loadActivity() {
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
const sendModeButtons = document.querySelectorAll('.sub-tab');
let sendMode: 'send' | 'shield' | 'unshield' | 'stealth' = 'send';
const submitBtn = document.getElementById('btn-submit-action') as HTMLButtonElement;

function updateConfirmState() {
  const amount = (document.getElementById('send-amount') as HTMLInputElement).value.trim();
  const to = (document.getElementById('send-to') as HTMLInputElement).value.trim();
  const filled = (sendMode === 'send' || sendMode === 'stealth') ? (!!amount && !!to) : !!amount;
  submitBtn.disabled = !filled;
}

sendModeButtons.forEach(btn => {
  btn.addEventListener('click', () => {
    const mode = (btn as HTMLElement).dataset.mode as 'send' | 'shield' | 'unshield' | 'stealth';
    sendMode = mode;
    sendModeButtons.forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    // Show/hide recipient field based on mode
    const toWrap = document.querySelector('.send-to-wrap') as HTMLElement;
    toWrap.style.display = (sendMode === 'send' || sendMode === 'stealth') ? '' : 'none';
    // Show/hide shielded balance (only relevant for shield/unshield/stealth)
    const ebRow = document.querySelector('.encrypted-balance-row') as HTMLElement;
    ebRow.style.display = (sendMode === 'send') ? 'none' : '';
    // Show/hide stealth inbox
    const stealthInbox = document.getElementById('stealth-inbox')!;
    stealthInbox.classList.toggle('hidden', sendMode !== 'stealth');
    // Update submit button label
    const labels: Record<string, string> = { send: 'Confirm Send', shield: 'Confirm Shield', unshield: 'Confirm Unshield', stealth: 'Confirm Stealth Send' };
    submitBtn.textContent = labels[sendMode];
    updateConfirmState();
  });
});

// Validate inputs on typing
document.getElementById('send-amount')!.addEventListener('input', updateConfirmState);
document.getElementById('send-to')!.addEventListener('input', updateConfirmState);

async function fetchEncryptedBalance() {
  const el = document.getElementById('encrypted-balance-display')!;
  // Check if there's an encrypted balance, show reveal button
  const res = await sendMsg('GET_ENCRYPTED_BALANCE') as { encryptedBalance?: { cipher?: string }; error?: string };
  if (res.error) {
    el.textContent = '0 OCT';
  } else {
    const cipher = (res.encryptedBalance as { cipher?: string })?.cipher;
    if (!cipher || cipher === '0') {
      el.textContent = '0 OCT';
    } else {
      el.innerHTML = '<button id="btn-decrypt-balance" class="decrypt-btn" title="Decrypt shielded balance">Reveal</button>';
      document.getElementById('btn-decrypt-balance')!.addEventListener('click', revealShieldedBalance);
    }
  }
}

async function revealShieldedBalance() {
  const el = document.getElementById('encrypted-balance-display')!;
  const btn = document.getElementById('btn-decrypt-balance') as HTMLButtonElement | null;
  if (btn) { btn.disabled = true; btn.textContent = 'Decrypting...'; }
  const res = await sendMsg('GET_DECRYPTED_BALANCE') as { balance?: string; error?: string };
  if (res.error) {
    el.textContent = 'Error';
  } else {
    el.textContent = `${res.balance ?? '0'} OCT`;
  }
}

// Bind initial decrypt button from HTML
document.getElementById('btn-decrypt-balance')?.addEventListener('click', revealShieldedBalance);

// Single submit handler based on current mode
submitBtn.addEventListener('click', async () => {
  const amount = (document.getElementById('send-amount') as HTMLInputElement).value.trim();
  const resultEl = document.getElementById('send-result')!;

  if (sendMode === 'send') {
    const to = (document.getElementById('send-to') as HTMLInputElement).value.trim();
    if (!to || !amount) { showToast('Fill in all fields'); return; }
    resultEl.textContent = 'Sending...';
    const res = await sendMsg('SEND_TRANSACTION', { to, amount }) as { hash?: string; error?: string };
    if (res.error) {
      resultEl.textContent = `Error: ${res.error}`;
    } else {
      resultEl.innerHTML = txLink(res.hash!, 'Confirmed — View on OctraScan ↗');
      showToast('Transaction sent!');
    }
  } else if (sendMode === 'stealth') {
    const to = (document.getElementById('send-to') as HTMLInputElement).value.trim();
    if (!to || !amount) { showToast('Fill in all fields'); return; }
    resultEl.textContent = 'Stealth sending...';
    const res = await sendMsg('STEALTH_SEND', { to, amount }) as { jobId?: string; error?: string };
    if (res.error) {
      resultEl.textContent = `Error: ${res.error}`;
    } else if (res.jobId) {
      await chrome.storage.local.set({ activeStealthJob: res.jobId, activeStealthStart: Date.now() });
      pollJobStatus(res.jobId, resultEl, 'stealth');
    }
  } else {
    await handleShieldAction();
  }
});

async function handleShieldAction() {
  const amount = (document.getElementById('send-amount') as HTMLInputElement).value.trim();
  if (!amount) { showToast('Enter an amount'); return; }
  const resultEl = document.getElementById('send-result')!;
  if (sendMode === 'shield') {
    resultEl.textContent = 'Shielding...';
    const res = await sendMsg('ENCRYPT_BALANCE', { amount }) as { jobId?: string; error?: string };
    if (res.error) {
      resultEl.textContent = `Error: ${res.error}`;
    } else if (res.jobId) {
      await chrome.storage.local.set({ activeShieldJob: res.jobId, activeShieldStart: Date.now() });
      pollJobStatus(res.jobId, resultEl, 'shield');
    }
  } else {
    resultEl.textContent = 'Unshielding...';
    const res = await sendMsg('DECRYPT_BALANCE', { amount }) as { jobId?: string; error?: string };
    if (res.error) {
      resultEl.textContent = `Error: ${res.error}`;
    } else if (res.jobId) {
      // Save job ID + start time and start polling
      await chrome.storage.local.set({ activeUnshieldJob: res.jobId, activeUnshieldStart: Date.now() });
      pollJobStatus(res.jobId, resultEl, 'unshield');
    }
  }
}

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
      fetchEncryptedBalance();
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

// --- Stealth Inbox: Scan + Claim ---
document.getElementById('btn-stealth-scan')!.addEventListener('click', async () => {
  const scanBtn = document.getElementById('btn-stealth-scan') as HTMLButtonElement;
  const outputsEl = document.getElementById('stealth-outputs')!;
  scanBtn.disabled = true;
  scanBtn.textContent = 'Scanning...';
  outputsEl.innerHTML = '<p class="muted">Scanning...</p>';

  try {
    const res = await sendMsg('STEALTH_SCAN', {}) as { outputs?: Array<Record<string, unknown>>; error?: string };
    if (res.error) {
      outputsEl.innerHTML = `<p class="muted" style="color:#ef4444">${res.error}</p>`;
      return;
    }
    const outputs = res.outputs ?? [];
    if (outputs.length === 0) {
      outputsEl.innerHTML = '<p class="muted">No pending stealth payments found.</p>';
      return;
    }
    outputsEl.innerHTML = '';
    for (const out of outputs) {
      const item = document.createElement('div');
      item.className = 'stealth-output-item';
      const sender = String(out.sender ?? '').slice(0, 12) + '...';
      item.innerHTML = `
        <div class="stealth-output-info">
          <div class="stealth-output-sender" title="${String(out.sender ?? '')}">From: ${sender}</div>
        </div>
        <button class="claim-btn" data-id="${out.id}" data-eph="${out.eph_pub}" data-enc="${out.enc_amount}">Claim</button>
      `;
      outputsEl.appendChild(item);
    }
    // Attach claim handlers
    outputsEl.querySelectorAll('.claim-btn').forEach(btn => {
      btn.addEventListener('click', async () => {
        const claimBtn = btn as HTMLButtonElement;
        const id = claimBtn.dataset.id!;
        const eph_pub = claimBtn.dataset.eph!;
        const enc_amount = claimBtn.dataset.enc!;
        claimBtn.disabled = true;
        claimBtn.textContent = 'Claiming...';
        try {
          const res = await sendMsg('STEALTH_CLAIM', { id, eph_pub, enc_amount }) as { jobId?: string; amount?: string; error?: string };
          if (res.error) {
            claimBtn.textContent = 'Error';
            claimBtn.title = res.error;
            showToast(`Claim failed: ${res.error}`);
          } else if (res.jobId) {
            const amtNum = Number(res.amount ?? 0) / 1_000_000;
            claimBtn.textContent = `Claiming ${amtNum} OCT...`;
            await chrome.storage.local.set({ activeClaimJob: res.jobId, activeClaimStart: Date.now() });
            const resultEl = document.getElementById('send-result') ?? claimBtn.parentElement!;
            pollJobStatus(res.jobId, resultEl, 'claim');
          }
        } catch (err) {
          claimBtn.textContent = 'Error';
          showToast('Claim failed');
        }
      });
    });
  } catch (err) {
    outputsEl.innerHTML = '<p class="muted" style="color:#ef4444">Scan failed</p>';
  } finally {
    scanBtn.disabled = false;
    scanBtn.textContent = 'Scan';
  }
});

init();
