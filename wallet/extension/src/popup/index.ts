import { createMnemonic, isValidMnemonic, walletFromMnemonic } from '../lib/crypto';
import { encryptMnemonic, saveWallet, loadWallet, hasWallet, clearWallet } from '../lib/storage';
import type { Account } from '../lib/storage';
import { toBase64 } from '../lib/crypto';
import { txUrl, txLink } from '../lib/explorer';

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
  // Sync Tor toggle state from storage
  const { torEnabled } = await chrome.storage.local.get('torEnabled');
  const torSetup = document.getElementById('tor-toggle-setup') as HTMLInputElement;
  const torUnlock = document.getElementById('tor-toggle-unlock') as HTMLInputElement;
  const torMain = document.getElementById('tor-toggle-main') as HTMLInputElement;
  torSetup.checked = !!torEnabled;
  torUnlock.checked = !!torEnabled;
  torMain.checked = !!torEnabled;

  const walletExists = await hasWallet();
  if (walletExists) {
    showScreen(screenUnlock);
  } else {
    showScreen(screenSetup);
  }
}

// Tor toggle sync
function setupTorToggles() {
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

  // Load balance
  const balRes = await sendMsg('GET_BALANCE') as { formatted?: string; error?: string };
  document.getElementById('display-balance')!.textContent = `${balRes.formatted ?? '0'} OCT`;

  // Load tokens
  const tokRes = await sendMsg('GET_TOKENS') as { tokens?: Array<{ name: string; symbol: string; balance: string; decimals: number }> };
  const tokenList = document.getElementById('token-list')!;
  // Always show native OCT first
  const octBal = balRes.formatted ?? '0';
  let tokensHtml = `<div class="token-item"><div><div class="token-name">Octra</div><div class="token-symbol">OCT</div></div><div class="token-balance">${escapeHtml(octBal)}</div></div>`;
  if (tokRes.tokens && tokRes.tokens.length > 0) {
    tokensHtml += tokRes.tokens.map(t => {
      const bal = (Number(t.balance) / Math.pow(10, t.decimals)).toFixed(t.decimals > 4 ? 4 : t.decimals);
      return `<div class="token-item"><div><div class="token-name">${escapeHtml(t.name)}</div><div class="token-symbol">${escapeHtml(t.symbol)}</div></div><div class="token-balance">${escapeHtml(bal)}</div></div>`;
    }).join('');
  }
  tokenList.innerHTML = tokensHtml;

  // Load activity
  loadActivity();
}

async function loadActivity() {
  const actList = document.getElementById('activity-list')!;
  actList.innerHTML = '<p class="muted">Loading...</p>';

  // Show running unshield job at top
  const { activeUnshieldJob } = await chrome.storage.local.get('activeUnshieldJob');
  let pendingHtml = '';
  if (activeUnshieldJob) {
    const job = await sendMsg('GET_JOB_STATUS', { jobId: activeUnshieldJob }) as { status: string; step?: string };
    if (job.status === 'running') {
      pendingHtml = `<div class="activity-item pending">
        <div class="activity-row"><span class="activity-type unshield">Unshielding</span><span class="activity-amount">In Progress</span></div>
        <div class="activity-row"><span class="activity-addr">${escapeHtml(job.step ?? 'working...')}</span><span class="activity-time">Now</span></div>
      </div>`;
    }
  }

  const myAddr = document.getElementById('display-address')!.getAttribute('data-full') ?? '';
  const res = await sendMsg('GET_ACTIVITY') as { transactions?: Array<Record<string, unknown>>; error?: string };
  if (res.error || !res.transactions || res.transactions.length === 0) {
    actList.innerHTML = pendingHtml || '<p class="muted">No recent activity</p>';
    return;
  }
  actList.innerHTML = pendingHtml + res.transactions.map(tx => {
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
    if (opType === 'call') {
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

  // Click to open on explorer
  actList.querySelectorAll('.activity-item').forEach(el => {
    el.addEventListener('click', () => {
      const hash = (el as HTMLElement).dataset.hash;
      if (hash) window.open(txUrl(hash), '_blank');
    });
  });
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
const sendModeButtons = document.querySelectorAll('.send-mode-btn');
let sendMode: 'send' | 'shield' | 'unshield' = 'send';

sendModeButtons.forEach(btn => {
  btn.addEventListener('click', () => {
    const id = btn.id;
    if (id === 'btn-send') sendMode = 'send';
    else if (id === 'btn-shield') sendMode = 'shield';
    else if (id === 'btn-unshield') sendMode = 'unshield';
    sendModeButtons.forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    // Show/hide recipient field based on mode
    const toWrap = document.querySelector('.send-to-wrap') as HTMLElement;
    toWrap.style.display = sendMode === 'send' ? '' : 'none';
  });
});

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

document.getElementById('btn-send')!.addEventListener('click', async () => {
  if (sendMode !== 'send') return handleShieldAction();
  const to = (document.getElementById('send-to') as HTMLInputElement).value.trim();
  const amount = (document.getElementById('send-amount') as HTMLInputElement).value.trim();
  if (!to || !amount) { showToast('Fill in all fields'); return; }
  const resultEl = document.getElementById('send-result')!;
  resultEl.textContent = 'Sending...';
  const res = await sendMsg('SEND_TRANSACTION', { to, amount }) as { hash?: string; error?: string };
  if (res.error) {
    resultEl.textContent = `Error: ${res.error}`;
  } else {
    resultEl.innerHTML = txLink(res.hash!, 'Confirmed — View on OctraScan ↗');
    showToast('Transaction sent!');
  }
});

document.getElementById('btn-shield')!.addEventListener('click', async () => {
  sendMode = 'shield';
  sendModeButtons.forEach(b => b.classList.remove('active'));
  document.getElementById('btn-shield')!.classList.add('active');
  (document.querySelector('.send-to-wrap') as HTMLElement).style.display = 'none';
  await handleShieldAction();
});

document.getElementById('btn-unshield')!.addEventListener('click', async () => {
  sendMode = 'unshield';
  sendModeButtons.forEach(b => b.classList.remove('active'));
  document.getElementById('btn-unshield')!.classList.add('active');
  (document.querySelector('.send-to-wrap') as HTMLElement).style.display = 'none';
  await handleShieldAction();
});

async function handleShieldAction() {
  const amount = (document.getElementById('send-amount') as HTMLInputElement).value.trim();
  if (!amount) { showToast('Enter an amount'); return; }
  const resultEl = document.getElementById('send-result')!;
  if (sendMode === 'shield') {
    resultEl.textContent = 'Shielding...';
    const res = await sendMsg('ENCRYPT_BALANCE', { amount }) as { hash?: string; error?: string };
    if (res.error) {
      resultEl.textContent = `Error: ${res.error}`;
    } else {
      resultEl.innerHTML = txLink(res.hash!, 'Confirmed — View on OctraScan ↗');
      showToast('Funds shielded!');
      fetchEncryptedBalance();
    }
  } else {
    resultEl.textContent = 'Unshielding...';
    const res = await sendMsg('DECRYPT_BALANCE', { amount }) as { jobId?: string; error?: string };
    if (res.error) {
      resultEl.textContent = `Error: ${res.error}`;
    } else if (res.jobId) {
      // Save job ID and start polling
      await chrome.storage.local.set({ activeUnshieldJob: res.jobId });
      pollJobStatus(res.jobId, resultEl);
    }
  }
}

function escapeHtml(str: string): string {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// --- Unshield job polling ---
let pollTimer: ReturnType<typeof setInterval> | null = null;

function pollJobStatus(jobId: string, resultEl: HTMLElement) {
  resultEl.textContent = 'Unshielding — starting...';
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    const res = await sendMsg('GET_JOB_STATUS', { jobId }) as { status: string; step?: string; hash?: string; error?: string };
    if (res.status === 'running') {
      resultEl.textContent = `Unshielding — ${res.step ?? 'working...'}`;
    } else if (res.status === 'done') {
      clearInterval(pollTimer!);
      pollTimer = null;
      await chrome.storage.local.remove('activeUnshieldJob');
      resultEl.innerHTML = txLink(res.hash!, 'Confirmed — View on OctraScan ↗');
      showToast('Funds unshielded!');
      fetchEncryptedBalance();
      loadActivity();
    } else if (res.status === 'error') {
      clearInterval(pollTimer!);
      pollTimer = null;
      await chrome.storage.local.remove('activeUnshieldJob');
      resultEl.textContent = `Error: ${res.error}`;
    }
  }, 2000);
}

// Check for running unshield job on popup open
async function checkActiveJob() {
  const { activeUnshieldJob } = await chrome.storage.local.get('activeUnshieldJob');
  if (activeUnshieldJob) {
    const resultEl = document.getElementById('send-result')!;
    pollJobStatus(activeUnshieldJob, resultEl);
  }
}

init();
