import { createMnemonic, isValidMnemonic, walletFromMnemonic } from '../lib/crypto';
import { encryptMnemonic, saveWallet, loadWallet, hasWallet } from '../lib/storage';
import { txUrl, setExplorerFromRpc } from '../lib/explorer';
import {
  MSG_UNLOCK, MSG_LOCK, MSG_SET_TOR,
  MSG_SET_RPC_URL, MSG_GET_RPC_URL, MSG_IS_UNLOCKED,
  MSG_SWITCH_ACCOUNT, MSG_GET_ACCOUNTS, MSG_ADD_ACCOUNT, MSG_GET_ADDRESS,
  MSG_CHECK_STEALTH_READY, MSG_DERIVE_PVAC_KEYS,
  MSG_GET_BALANCE, MSG_GET_DECRYPTED_BALANCE,
  MSG_ENCRYPT_BALANCE, MSG_DECRYPT_BALANCE,
  MSG_GET_JOB_STATUS, MSG_CANCEL_JOB, MSG_SEND_TRANSACTION,
  MSG_GET_ACTIVITY,
  MSG_STEALTH_SEND, MSG_STEALTH_SCAN,
  MSG_STEALTH_CLAIM, MSG_IMPORT_PAIRING, MSG_REMOVE_PAIRING,
  MSG_GET_PROVER_STATUS, MSG_SET_PROVER_MODE,
  MSG_GET_NFT_CONTENT, MSG_FETCH_CIRCLE_ASSET,
  SK_FEE_DEFAULT, SK_FEE_ENCRYPT, SK_FEE_DECRYPT, SK_FEE_STEALTH, SK_FEE_CLAIM,
} from '../lib/constants';

// Feature flags (must match background)
const FEATURE_TOR = true;

// Account epoch — incremented on every account switch to discard stale async results
let accountEpoch = 0;

// Screens
const screenSetup = document.getElementById('screen-setup')!;
const screenCreate = document.getElementById('screen-create')!;
const screenImport = document.getElementById('screen-import')!;
const screenUnlock = document.getElementById('screen-unlock')!;
const screenProverRec = document.getElementById('screen-prover-rec')!;
const screenMain = document.getElementById('screen-main')!;

function showScreen(screen: HTMLElement) {
  [screenSetup, screenCreate, screenImport, screenUnlock, screenProverRec, screenMain].forEach(s => s.classList.add('hidden'));
  screen.classList.remove('hidden');
}

function showToast(msg: string, duration = 3500) {
  const toast = document.getElementById('toast')!;
  toast.innerHTML = '';
  toast.textContent = msg;
  toast.classList.remove('hidden');
  if (duration > 0) setTimeout(() => toast.classList.add('hidden'), duration);
}

function showActionToast(msg: string, opts?: { action?: string; goActivity?: boolean; duration?: number }) {
  const toast = document.getElementById('toast')!;
  const actionLabel = opts?.action ?? (opts?.goActivity ? 'View' : '');
  if (actionLabel) {
    toast.innerHTML = `<span>${msg}</span><button class="toast-action" id="toast-act-btn">${actionLabel}</button>`;
    toast.classList.remove('hidden');
    document.getElementById('toast-act-btn')!.addEventListener('click', () => {
      toast.classList.add('hidden');
      if (opts?.goActivity) switchToTab('activity');
    });
  } else {
    toast.innerHTML = '';
    toast.textContent = msg;
    toast.classList.remove('hidden');
  }
  const dur = opts?.duration ?? (actionLabel ? 8000 : 4000);
  if (dur > 0) setTimeout(() => toast.classList.add('hidden'), dur);
}

function switchToTab(tab: string) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  const target = document.querySelector(`.tab[data-tab="${tab}"]`) as HTMLElement | null;
  if (target) target.classList.add('active');
  document.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));
  document.getElementById(`tab-${tab}`)?.classList.remove('hidden');
  if (tab === 'activity') loadActivity();
}

function showStealthClaimToast(outputs: Array<Record<string, unknown>>) {
  const toast = document.getElementById('toast')!;
  const count = outputs.length;
  toast.innerHTML = `<span><svg class="icon-sm" viewBox="0 0 24 24" fill="currentColor" stroke="none" style="vertical-align:-2px;margin-right:4px"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4" fill="none" stroke="currentColor" stroke-width="2"/></svg>${count} stealth payment${count > 1 ? 's' : ''} available</span><button id="toast-claim-all" class="toast-action">Claim</button>`;
  toast.classList.remove('hidden');
  document.getElementById('toast-claim-all')!.addEventListener('click', async () => {
    toast.classList.add('hidden');
    // Pre-populate a placeholder job so loadActivity shows "In Progress" immediately
    const placeholderJobId = 'claim_pending_' + Date.now();
    await chrome.storage.local.set({ activeClaimJob: placeholderJobId, activeClaimStart: Date.now(), activeClaimAmount: '' });
    switchToTab('activity');
    for (const out of outputs) {
      try {
        const res = await sendMsg(MSG_STEALTH_CLAIM, { id: out.id, eph_pub: out.eph_pub, enc_amount: out.enc_amount }) as { jobId?: string; amount?: string; error?: string };
        if (res.jobId) {
          const claimAmount = res.amount ?? '';
          await chrome.storage.local.set({ activeClaimJob: res.jobId, activeClaimStart: Date.now(), activeClaimAmount: claimAmount });
          pollJobStatus(res.jobId, 'claim');
          activityLoading = false;
          loadActivity();
        } else if (res.error) {
          await chrome.storage.local.remove(['activeClaimJob', 'activeClaimStart', 'activeClaimAmount']);
          document.getElementById('activity-pending')!.innerHTML = '';
          showActionToast(`Claim failed: ${res.error}`, { duration: 4000 });
        }
      } catch {
        await chrome.storage.local.remove(['activeClaimJob', 'activeClaimStart', 'activeClaimAmount']);
        document.getElementById('activity-pending')!.innerHTML = '';
        showActionToast('Claim failed', { duration: 3000 });
      }
    }
  });
}

async function sendMsg(type: string, payload: Record<string, unknown> = {}): Promise<unknown> {
  return chrome.runtime.sendMessage({ type, payload });
}

function checkForUpdate() {
  chrome.runtime.requestUpdateCheck().then((result) => {
    if (result.status === 'update_available') {
      document.getElementById('update-banner')?.classList.remove('hidden');
    }
  }).catch(() => { /* throttled or unavailable */ });
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
    // Skip lock screen if vault is already unlocked in the service worker
    const status = await sendMsg(MSG_IS_UNLOCKED) as { unlocked?: boolean };
    if (status.unlocked) {
      await maybeShowProverRec();
    } else {
      showScreen(screenUnlock);
      checkForUpdate();
    }
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
      const res = await sendMsg(MSG_SET_TOR, { enabled: true }) as { success?: boolean; error?: string };
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
      await sendMsg(MSG_SET_TOR, { enabled: false });
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

// Create wallet – enable button when both passwords filled & match
const createPwInput = document.getElementById('create-password') as HTMLInputElement;
const createPwConfirm = document.getElementById('create-password-confirm') as HTMLInputElement;
const btnConfirmCreate = document.getElementById('btn-confirm-create') as HTMLButtonElement;
function updateCreateState() {
  btnConfirmCreate.disabled = !(createPwInput.value.length >= 4 && createPwConfirm.value === createPwInput.value);
}
createPwInput.addEventListener('input', updateCreateState);
createPwConfirm.addEventListener('input', updateCreateState);

// Import wallet – enable button when mnemonic + password filled
const importMnemonicInput = document.getElementById('import-mnemonic') as HTMLTextAreaElement;
const importPwInput = document.getElementById('import-password') as HTMLInputElement;
const btnConfirmImport = document.getElementById('btn-confirm-import') as HTMLButtonElement;
function updateImportState() {
  const words = importMnemonicInput.value.trim().split(/\s+/);
  btnConfirmImport.disabled = !(words.length >= 12 && importPwInput.value.length >= 4);
}
importMnemonicInput.addEventListener('input', updateImportState);
importPwInput.addEventListener('input', updateImportState);

// Create wallet
document.getElementById('btn-confirm-create')!.addEventListener('click', async () => {
  const mnemonic = (document.getElementById('mnemonic-display')! as HTMLElement).dataset.mnemonic!;
  const pw = (document.getElementById('create-password') as HTMLInputElement).value;
  const pw2 = (document.getElementById('create-password-confirm') as HTMLInputElement).value;
  if (!pw || pw.length < 4) { showToast('Password too short'); return; }
  if (pw !== pw2) { showToast('Passwords do not match'); return; }

  const pvacOverlay = document.getElementById('pvac-loading')!;
  pvacOverlay.classList.remove('hidden');

  const wallet = walletFromMnemonic(mnemonic, 0);
  const encrypted = await encryptMnemonic(mnemonic, pw);
  await saveWallet({
    encryptedSeed: encrypted,
    accounts: [{ name: 'Account 1', hdIndex: 0, address: wallet.address }],
    activeIndex: 0,
  });
  await sendMsg(MSG_UNLOCK, { encryptedSeed: encrypted, password: pw, hdIndex: 0 });
  await sendMsg(MSG_DERIVE_PVAC_KEYS);
  pvacOverlay.classList.add('hidden');
  await maybeShowProverRec();
});

// Import wallet
document.getElementById('btn-confirm-import')!.addEventListener('click', async () => {
  const mnemonic = (document.getElementById('import-mnemonic') as HTMLTextAreaElement).value.trim().toLowerCase();
  const pw = (document.getElementById('import-password') as HTMLInputElement).value;
  if (!isValidMnemonic(mnemonic)) { showToast('Invalid seed phrase'); return; }
  if (!pw || pw.length < 4) { showToast('Password too short'); return; }

  const pvacOverlay = document.getElementById('pvac-loading')!;
  pvacOverlay.classList.remove('hidden');

  const wallet = walletFromMnemonic(mnemonic, 0);
  const encrypted = await encryptMnemonic(mnemonic, pw);
  await saveWallet({
    encryptedSeed: encrypted,
    accounts: [{ name: 'Account 1', hdIndex: 0, address: wallet.address }],
    activeIndex: 0,
  });
  await sendMsg(MSG_UNLOCK, { encryptedSeed: encrypted, password: pw, hdIndex: 0 });
  await sendMsg(MSG_DERIVE_PVAC_KEYS);
  pvacOverlay.classList.add('hidden');
  await maybeShowProverRec();
});

// Unlock
const unlockBtn = document.getElementById('btn-unlock') as HTMLButtonElement;
const unlockPwInput = document.getElementById('unlock-password') as HTMLInputElement;
unlockBtn.addEventListener('click', doUnlock);
unlockPwInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') doUnlock();
});
unlockPwInput.addEventListener('input', () => {
  const hasText = unlockPwInput.value.length > 0;
  unlockBtn.disabled = !hasText;
});

async function doUnlock() {
  const pw = (document.getElementById('unlock-password') as HTMLInputElement).value;
  const state = await loadWallet();
  if (!state) { showToast('No wallet found'); return; }
  const activeAccount = state.accounts[state.activeIndex];
  try {
    const res = await sendMsg(MSG_UNLOCK, { encryptedSeed: state.encryptedSeed, password: pw, hdIndex: activeAccount.hdIndex }) as { success?: boolean; error?: string };
    if ('error' in res) { showToast('Incorrect password'); return; }
    await maybeShowProverRec();
  } catch (e) {
    showToast('Incorrect password');
  }
}

/** Show prover recommendation if no prover detected, otherwise go straight to main */
async function maybeShowProverRec() {
  const { proverRecDismissed } = await chrome.storage.local.get('proverRecDismissed');
  if (proverRecDismissed) { await loadMainScreen(); return; }
  const status = await sendMsg(MSG_GET_PROVER_STATUS) as { local?: boolean; remote?: boolean };
  if (status.local || status.remote) { await loadMainScreen(); return; }
  showScreen(screenProverRec);
}

document.getElementById('btn-skip-prover-rec')!.addEventListener('click', async () => {
  await chrome.storage.local.set({ proverRecDismissed: true });
  await loadMainScreen();
});

// External links (no inline onclick — CSP)
document.getElementById('btn-get-octra')!.addEventListener('click', () => {
  window.open('https://octane-fast.github.io/Octane/dev/faucet.html', '_blank');
});
document.getElementById('btn-download-accelerator')!.addEventListener('click', () => {
  window.open('https://octane-fast.github.io/octane-accelerator/', '_blank');
});
document.getElementById('btn-download-accelerator-cta')!.addEventListener('click', () => {
  window.open('https://octane-fast.github.io/octane-accelerator/', '_blank');
});

// Lock
document.getElementById('btn-lock')?.addEventListener('click', async () => {
  await sendMsg(MSG_LOCK);
  showScreen(screenUnlock);
});

// Copy address
document.getElementById('btn-copy-address')!.addEventListener('click', () => {
  const addr = document.getElementById('display-address')!.getAttribute('data-full')!;
  navigator.clipboard.writeText(addr);
  showToast('Copied!');
});

// Tooltip for account icons
const acctTooltip = document.getElementById('account-tooltip')!;
function bindTip(el: HTMLElement, text: string) {
  el.addEventListener('mouseenter', () => { acctTooltip.textContent = text; });
}
bindTip(document.getElementById('stealth-badge')!, 'Stealth ready');
bindTip(document.getElementById('btn-copy-address')!, 'Copy address');
bindTip(document.getElementById('btn-add-account')!, 'Add account');

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

function getCurrentAddress(): string {
  return document.getElementById('display-address')?.getAttribute('data-full') || '';
}

async function updateBalanceCache(total: number) {
  const addr = getCurrentAddress();
  if (!addr) return;
  const key = `bal_${addr}`;
  await chrome.storage.local.set({ [key]: total });
}

async function getCachedBalance(addr: string): Promise<number> {
  const key = `bal_${addr}`;
  const result = await chrome.storage.local.get(key);
  return result[key] ?? 0;
}

function updateGetOctButton(total: number) {
  const getBtn = document.getElementById('btn-get-octra');
  if (getBtn) getBtn.style.display = total > 0 ? 'none' : '';
}

function formatTotal(n: number): string {
  const s = n.toFixed(6).replace(/0+$/, '').replace(/\.$/, '');
  const [int, frac = ''] = s.split('.');
  return int + '.' + (frac + '00').slice(0, Math.max(2, frac.length));
}

async function refreshPublicBalance() {
  const epoch = accountEpoch;
  const balRes = await sendMsg(MSG_GET_BALANCE) as { formatted?: string; error?: string };
  if (epoch !== accountEpoch) return; // stale
  const publicBal = balRes.formatted ?? '0';
  document.getElementById('display-public-balance')!.textContent = publicBal;
  const pub = parseFloat(publicBal) || 0;
  const privEl = document.getElementById('display-private-balance')!;
  const priv = parseFloat(privEl.textContent || '0') || 0;
  const total = pub + priv;
  document.getElementById('display-balance')!.textContent = `${formatTotal(total)} OCT`;
  updateGetOctButton(total);
  await updateBalanceCache(total);
}

async function refreshPrivateBalance() {
  const epoch = accountEpoch;
  const privEl = document.getElementById('display-private-balance')!;
  try {
    const privPromise = sendMsg(MSG_GET_DECRYPTED_BALANCE) as Promise<{ balance?: string; error?: string }>;
    const timeout = new Promise<{ error: string }>((resolve) => setTimeout(() => resolve({ error: 'timeout' }), 8000));
    const privRes = await Promise.race([privPromise, timeout]);
    if (epoch !== accountEpoch) return; // stale
    if (!privRes.error && privRes.balance !== undefined) {
      privEl.classList.remove('shimmer');
      privEl.textContent = privRes.balance;
      // Update total
      const pubEl = document.getElementById('display-public-balance')!;
      const pub = parseFloat(pubEl.textContent || '0') || 0;
      const priv = parseFloat(privRes.balance) || 0;
      const total = pub + priv;
      document.getElementById('display-balance')!.textContent = `${formatTotal(total)} OCT`;
      updateGetOctButton(total);
      await updateBalanceCache(total);
    }
  } catch { /* silent */ }
}



async function scanForStealthPayments() {
  const { activeClaimJob } = await chrome.storage.local.get('activeClaimJob');
  if (activeClaimJob) return;

  const epoch = accountEpoch;
  try {
    const res = await sendMsg(MSG_STEALTH_SCAN, {}) as { outputs?: Array<Record<string, unknown>>; error?: string };
    if (epoch !== accountEpoch) return;
    if (res.error) { console.warn('[stealth-scan] error: %s', res.error); return; }
    if (res.outputs && res.outputs.length > 0) {
      console.log('[stealth-scan] found %d claimable output(s)', res.outputs.length);
      showStealthClaimToast(res.outputs);
    }
  } catch (e) { console.warn('[stealth-scan] exception: %s', (e as Error).message); }
}

const PollingService = {
  timers: [] as ReturnType<typeof setInterval>[],

  start() {
    this.stop(); // Clear any existing timers
    // Public balance: every 3s (fast, no PVAC)
    this.timers.push(setInterval(async () => {
      await refreshPublicBalance();
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
  const epoch = accountEpoch;
  showScreen(screenMain);
  checkActiveJob();

  // Update prover mode label in header
  const status = await sendMsg(MSG_GET_PROVER_STATUS) as { local?: boolean; remote?: boolean; mode?: string };
  if (epoch !== accountEpoch) return;
  const mode = status.mode ?? 'browser';
  updateProverModeLabel(mode);

  // Populate account selector from background (fresh derivation)
  const accRes = await sendMsg(MSG_GET_ACCOUNTS) as { accounts?: Array<{ name: string; hdIndex: number; address: string }>; activeHdIndex?: number; error?: string };
  if (epoch !== accountEpoch) return;
  const select = document.getElementById('account-select') as HTMLSelectElement;
  if (accRes.accounts) {
    select.innerHTML = accRes.accounts.map((acc, i) => {
      const isActive = acc.hdIndex === (accRes.activeHdIndex ?? 0);
      return `<option value="${i}"${isActive ? ' selected' : ''}>${escapeHtml(acc.name)} (${acc.address.slice(0, 8)}…${acc.address.slice(-6)})</option>`;
    }).join('');
  }

  const addrRes = await sendMsg(MSG_GET_ADDRESS) as { address?: string; error?: string };
  if (epoch !== accountEpoch) return;
  if (addrRes.error) { showToast('Incorrect password'); showScreen(screenUnlock); return; }
  const fullAddr = addrRes.address!;
  const addrEl = document.getElementById('display-address')!;
  addrEl.setAttribute('data-full', fullAddr);
  addrEl.textContent = fullAddr.slice(0, 12) + '…' + fullAddr.slice(-10);

  // Immediately hide Get OCT button if cached balance exists
  const cachedBal = await getCachedBalance(fullAddr);
  updateGetOctButton(cachedBal);

  // Initial data load — fetch public balance immediately, private balance async
  await refreshPublicBalance();
  await loadActivity();

  // Check stealth readiness (public key registered on-chain)
  updateStealthBadge();

  // Start polling services (includes private balance)
  PollingService.start();
}

async function updateStealthBadge() {
  const epoch = accountEpoch;
  const badge = document.getElementById('stealth-badge')!;
  const res = await sendMsg(MSG_CHECK_STEALTH_READY) as { ready?: boolean; reason?: string };
  if (epoch !== accountEpoch) return; // stale
  if (res.ready) {
    badge.innerHTML = '<svg class="icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>';
    badge.classList.remove('hidden', 'not-ready');
    badge.onmouseenter = () => { acctTooltip.textContent = 'Stealth ready'; };
  } else if (res.reason === 'no_funds') {
    // No badge for unfunded accounts — nothing actionable
    badge.classList.add('hidden');
  } else {
    badge.innerHTML = '<svg class="icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10" stroke-dasharray="50" stroke-dashoffset="15" stroke-linecap="round"/></svg>';
    badge.classList.remove('hidden');
    badge.classList.add('not-ready');
    badge.onmouseenter = () => { acctTooltip.textContent = 'Registering…'; };
  }
}

// In-memory activity cache, keyed by tx_hash for deduplication
const activityCache = new Map<string, Record<string, unknown>>();
let lastActivityHtml = '';
let activityLoading = false;

async function loadActivity() {
  if (activityLoading) return;
  activityLoading = true;
  const epoch = accountEpoch;
  try {
    const actList = document.getElementById('activity-list')!;
    const pendingEl = document.getElementById('activity-pending')!;

    // Show running jobs at top (separate element, no flicker on main list)
    const { activeUnshieldJob, activeUnshieldStart, activeShieldJob, activeShieldStart, activeStealthJob, activeStealthStart, activeClaimJob, activeClaimStart } =
      await chrome.storage.local.get(['activeUnshieldJob', 'activeUnshieldStart', 'activeShieldJob', 'activeShieldStart', 'activeStealthJob', 'activeStealthStart', 'activeClaimJob', 'activeClaimStart']);

    const activeJobId = activeUnshieldJob || activeShieldJob || activeStealthJob || activeClaimJob;
    const activeStart = activeUnshieldJob ? activeUnshieldStart : activeShieldJob ? activeShieldStart : activeClaimJob ? activeClaimStart : activeStealthStart;
    const activeLabel = activeUnshieldJob ? 'Unshielding' : activeShieldJob ? 'Shielding' : activeStealthJob ? 'Stealth Send' : activeClaimJob ? 'Claiming' : '';
    const activeTypeClass = activeUnshieldJob ? 'unshield' : activeShieldJob ? 'shield' : activeStealthJob ? 'stealth' : activeClaimJob ? 'claim' : '';

    if (activeJobId) {
      const isPlaceholder = activeJobId.startsWith('claim_pending_');
      const job = isPlaceholder
        ? { status: 'running', step: 'Starting claim...' }
        : await sendMsg(MSG_GET_JOB_STATUS, { jobId: activeJobId }) as { status: string; step?: string };
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
          await sendMsg(MSG_CANCEL_JOB, { jobId });
          await chrome.storage.local.remove(['activeUnshieldJob', 'activeUnshieldStart', 'activeShieldJob', 'activeShieldStart', 'activeStealthJob', 'activeStealthStart', 'activeClaimJob', 'activeClaimStart']);
          pendingEl.innerHTML = '';
          if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
          showActionToast(`${activeLabel} cancelled`, { duration: 3000 });
        });
      } else {
        pendingEl.innerHTML = '';
      }
    } else {
      pendingEl.innerHTML = '';
    }

    const myAddr = document.getElementById('display-address')!.getAttribute('data-full') ?? '';
    const res = await sendMsg(MSG_GET_ACTIVITY) as { transactions?: Array<Record<string, unknown>>; error?: string };
    if (epoch !== accountEpoch) return; // stale

    // Merge new results into cache (add-only); on error, keep existing cache
    if (!res.error && res.transactions && res.transactions.length > 0) {
      for (const tx of res.transactions) {
        const hash = String(tx.tx_hash ?? '');
        if (!hash) continue;
        const existing = activityCache.get(hash);
        // Preserve locally-known amount for claim/stealth (on-chain amount is always 0)
        if (existing && existing.amount_raw && Number(tx.amount_raw ?? tx.amount ?? 0) === 0) {
          const opType = String(tx.op_type ?? '');
          if (opType === 'claim' || opType === 'stealth') {
            tx.amount_raw = existing.amount_raw;
          }
        }
        activityCache.set(hash, tx);
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
      const isPending = Boolean(tx._pending);

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
      } else if (opType === 'stealth') {
        typeLabel = 'Stealth Send';
        typeClass = 'stealth';
        counterparty = to;
      } else if (opType === 'claim') {
        typeLabel = 'Stealth Claim';
        typeClass = 'claim';
        counterparty = from;
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

      const amountDisplay = amountRaw > 0 ? amount + ' OCT' : '';
      const pendingBadge = isPending ? ' <span class="activity-pending-badge">Confirming</span>' : '';
      return `<div class="activity-item${isPending ? ' confirming' : ''}" data-hash="${escapeHtml(hash)}" title="View on OctraScan">
      <div class="activity-row"><span class="activity-type ${typeClass}">${typeLabel}${pendingBadge}</span><span class="activity-amount">${amountDisplay}</span></div>
      <div class="activity-row"><span class="activity-addr">${isPending ? 'Waiting for confirmation...' : escapeHtml(counterparty)}</span><span class="activity-time">${time}</span></div>
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
  accountEpoch++; // invalidate in-flight requests from previous account
  PollingService.stop();
  await sendMsg(MSG_SWITCH_ACCOUNT, { hdIndex: account.hdIndex });

  // Reset displayed balance, activity, stealth badge, and input fields immediately
  document.getElementById('stealth-badge')!.classList.add('hidden');
  document.getElementById('display-balance')!.textContent = '0.00 OCT';
  document.getElementById('display-public-balance')!.textContent = '0.00';
  (document.getElementById('send-amount') as HTMLInputElement).value = '';
  (document.getElementById('send-to') as HTMLInputElement).value = '';
  shieldAmountInput.value = '';
  unshieldAmountIdx = 0;
  unshieldAmountInput.value = formatUnshieldAmount(UNSHIELD_AMOUNTS[0]);
  submitShieldBtn.disabled = true;
  submitSendBtn.disabled = true;
  const privEl = document.getElementById('display-private-balance')!;
  privEl.textContent = '···';
  privEl.classList.add('shimmer');
  document.getElementById('activity-list')!.innerHTML = '<p class="muted">Loading…</p>';
  document.getElementById('activity-pending')!.innerHTML = '';
  activityCache.clear();
  lastActivityHtml = '';

  // Check cached balance to decide Get OCT button visibility immediately
  const cachedBal = await getCachedBalance(account.address);
  updateGetOctButton(cachedBal);

  await loadMainScreen();
});

// Add account
document.getElementById('btn-add-account')!.addEventListener('click', async () => {
  if (!confirm('Create a new account?')) return;
  const state = await loadWallet();
  if (!state) return;
  const pvacOverlay = document.getElementById('pvac-loading')!;
  pvacOverlay.classList.remove('hidden');
  const nextHdIndex = Math.max(...state.accounts.map(a => a.hdIndex)) + 1;
  const name = `Account ${state.accounts.length + 1}`;
  const res = await sendMsg(MSG_ADD_ACCOUNT, { name, hdIndex: nextHdIndex }) as { address?: string; error?: string };
  if (res.error) { pvacOverlay.classList.add('hidden'); showToast(res.error); return; }
  state.accounts.push({ name, hdIndex: nextHdIndex, address: res.address! });
  state.activeIndex = state.accounts.length - 1;
  await saveWallet(state);
  accountEpoch++; // invalidate in-flight requests from previous account
  PollingService.stop();
  await sendMsg(MSG_SWITCH_ACCOUNT, { hdIndex: nextHdIndex });
  await sendMsg(MSG_DERIVE_PVAC_KEYS);
  pvacOverlay.classList.add('hidden');
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
  const res = await sendMsg(MSG_GET_ACCOUNTS) as { accounts?: Array<{ name: string; hdIndex: number; address: string }> };
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
      updateSendState();
    });
  });
}

// Send / Shield / Unshield
let sendMode: 'send' | 'stealth' = 'send';
let shieldDirection: 'shield' | 'unshield' = 'shield';
const submitSendBtn = document.getElementById('btn-submit-send') as HTMLButtonElement;
const submitShieldBtn = document.getElementById('btn-submit-shield') as HTMLButtonElement;

// Send mode toggle (Public / Stealth)
const sendModeToggle = document.getElementById('send-mode-toggle') as HTMLElement;
const sendAmountInput = document.getElementById('send-amount') as HTMLInputElement;

document.querySelectorAll('#send-mode-toggle .shield-dir').forEach(btn => {
  btn.addEventListener('click', () => {
    const dir = (btn as HTMLElement).dataset.dir as 'public' | 'stealth';
    sendMode = dir === 'stealth' ? 'stealth' : 'send';
    document.querySelectorAll('#send-mode-toggle .shield-dir').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    sendModeToggle.classList.toggle('unshield', dir === 'stealth');
    submitSendBtn.textContent = sendMode === 'stealth' ? 'Confirm Stealth Send' : 'Confirm Send';
    updateSendState();
  });
});

function updateSendState() {
  const to = (document.getElementById('send-to') as HTMLInputElement).value.trim();
  const amount = sendAmountInput.value.trim();
  submitSendBtn.disabled = !(amount && to);
}

// Shield/Unshield amount inputs
const shieldAmountInput = document.getElementById('shield-amount') as HTMLInputElement;
const unshieldAmountWrap = document.getElementById('unshield-amount-wrap') as HTMLElement;
const UNSHIELD_AMOUNTS = [1, 10, 100, 1000, 10000, 100000, 1000000];
let unshieldAmountIdx = 0;
const unshieldAmountInput = document.getElementById('unshield-amount') as HTMLInputElement;
function formatUnshieldAmount(n: number): string { return n.toLocaleString(); }
unshieldAmountInput.value = formatUnshieldAmount(UNSHIELD_AMOUNTS[unshieldAmountIdx]);

document.getElementById('unshield-amount-up')!.addEventListener('click', () => {
  if (unshieldAmountIdx < UNSHIELD_AMOUNTS.length - 1) {
    unshieldAmountIdx++;
    unshieldAmountInput.value = formatUnshieldAmount(UNSHIELD_AMOUNTS[unshieldAmountIdx]);
  }
});
document.getElementById('unshield-amount-down')!.addEventListener('click', () => {
  if (unshieldAmountIdx > 0) {
    unshieldAmountIdx--;
    unshieldAmountInput.value = formatUnshieldAmount(UNSHIELD_AMOUNTS[unshieldAmountIdx]);
  }
});

// Update shield button disabled state based on mode
function updateShieldBtnState() {
  if (shieldDirection === 'shield') {
    submitShieldBtn.disabled = !shieldAmountInput.value.trim();
  } else {
    submitShieldBtn.disabled = false; // stepper always valid
  }
}

// Shield direction toggle
const shieldToggleContainer = document.getElementById('shield-mode-toggle') as HTMLElement;
document.querySelectorAll('#shield-mode-toggle .shield-dir').forEach(btn => {
  btn.addEventListener('click', () => {
    shieldDirection = (btn as HTMLElement).dataset.dir as 'shield' | 'unshield';
    document.querySelectorAll('#shield-mode-toggle .shield-dir').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    shieldToggleContainer.classList.toggle('unshield', shieldDirection === 'unshield');
    submitShieldBtn.textContent = shieldDirection === 'shield' ? 'Confirm Shield' : 'Confirm Unshield';
    // Swap between plain input and stepper
    if (shieldDirection === 'shield') {
      shieldAmountInput.classList.remove('hidden');
      unshieldAmountWrap.classList.add('hidden');
    } else {
      shieldAmountInput.classList.add('hidden');
      unshieldAmountWrap.classList.remove('hidden');
    }
    updateShieldBtnState();
  });
});

shieldAmountInput.addEventListener('input', updateShieldBtnState);

// Validate inputs on typing
document.getElementById('send-amount')!.addEventListener('input', updateSendState);
document.getElementById('send-to')!.addEventListener('input', updateSendState);

// Send submit handler
submitSendBtn.addEventListener('click', async () => {
  const to = (document.getElementById('send-to') as HTMLInputElement).value.trim();
  const amount = sendAmountInput.value.trim();
  if (!to || !amount) { showToast('Fill in all fields'); return; }

  if (sendMode === 'stealth') {
    const res = await sendMsg(MSG_STEALTH_SEND, { to, amount }) as { jobId?: string; error?: string };
    if (res.error) {
      const msg = res.error === 'recipient_no_pvac'
        ? 'Recipient must have funds to receive stealth sends'
        : `Error: ${res.error}`;
      showActionToast(msg, { duration: 4000 });
    } else if (res.jobId) {
      showActionToast('Private transfer started', { action: 'View', goActivity: true });
      sendAmountInput.value = '';
      (document.getElementById('send-to') as HTMLInputElement).value = '';
      submitSendBtn.disabled = true;
      await chrome.storage.local.set({ activeStealthJob: res.jobId, activeStealthStart: Date.now() });
      pollJobStatus(res.jobId, 'stealth');
    }
  } else {
    showActionToast('Transfer started', { action: 'View', goActivity: true });
    const res = await sendMsg(MSG_SEND_TRANSACTION, { to, amount }) as { hash?: string; error?: string };
    if (res.error) {
      showActionToast(`Error: ${res.error}`, { duration: 4000 });
    } else {
      (document.getElementById('send-amount') as HTMLInputElement).value = '';
      (document.getElementById('send-to') as HTMLInputElement).value = '';
      submitSendBtn.disabled = true;
      // Inject synthetic activity entry immediately (indexer may lag)
      if (res.hash) {
        const myAddr = document.getElementById('display-address')!.getAttribute('data-full') ?? '';
        let rawAmount = 0;
        if (amount.includes('.')) {
          const [intPart, fracPart] = amount.split('.');
          rawAmount = Number(BigInt(intPart) * 1000000n + BigInt((fracPart + '000000').slice(0, 6)));
        } else {
          rawAmount = Number(BigInt(amount) * 1000000n);
        }
        activityCache.set(res.hash, {
          tx_hash: res.hash, timestamp: Math.floor(Date.now() / 1000),
          from: myAddr, to, op_type: 'standard', amount_raw: rawAmount,
          _pending: true,
        });
      }
      showActionToast('Transaction confirmed!', { action: 'View', goActivity: true });
      activityLoading = false;
      loadActivity();
    }
  }
});

// Shield/Unshield submit handler
submitShieldBtn.addEventListener('click', async () => {
  const amount = shieldDirection === 'shield'
    ? shieldAmountInput.value.trim()
    : String(UNSHIELD_AMOUNTS[unshieldAmountIdx]);
  if (!amount) { showToast('Enter an amount'); return; }
  if (shieldDirection === 'shield') {
    showActionToast('Shield started', { action: 'View', goActivity: true });
    const res = await sendMsg(MSG_ENCRYPT_BALANCE, { amount }) as { jobId?: string; error?: string };
    if (res.error) {
      showActionToast(`Error: ${res.error}`, { duration: 4000 });
    } else if (res.jobId) {
      shieldAmountInput.value = '';
      await chrome.storage.local.set({ activeShieldJob: res.jobId, activeShieldStart: Date.now(), activeShieldAmount: amount });
      pollJobStatus(res.jobId, 'shield');
    }
  } else {
    showActionToast('Unshield started', { action: 'View', goActivity: true });
    const res = await sendMsg(MSG_DECRYPT_BALANCE, { amount }) as { jobId?: string; error?: string };
    if (res.error) {
      showActionToast(`Error: ${res.error}`, { duration: 4000 });
    } else if (res.jobId) {
      unshieldAmountIdx = 0;
      unshieldAmountInput.value = formatUnshieldAmount(UNSHIELD_AMOUNTS[0]);
      await chrome.storage.local.set({ activeUnshieldJob: res.jobId, activeUnshieldStart: Date.now(), activeUnshieldAmount: amount });
      pollJobStatus(res.jobId, 'unshield');
    }
  }
});

function escapeHtml(str: string): string {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// --- Job polling (shield + unshield + stealth) ---
let pollTimer: ReturnType<typeof setInterval> | null = null;

function pollJobStatus(jobId: string, jobType: 'shield' | 'unshield' | 'stealth' | 'claim' = 'unshield') {
  const label = jobType === 'shield' ? 'Shield' : jobType === 'stealth' ? 'Private transfer' : jobType === 'claim' ? 'Claim' : 'Unshield';
  const storageKeys = jobType === 'shield'
    ? ['activeShieldJob', 'activeShieldStart', 'activeShieldAmount']
    : jobType === 'stealth'
      ? ['activeStealthJob', 'activeStealthStart', 'activeStealthAmount']
      : jobType === 'claim'
        ? ['activeClaimJob', 'activeClaimStart', 'activeClaimAmount']
        : ['activeUnshieldJob', 'activeUnshieldStart', 'activeUnshieldAmount'];
  const amountKey = jobType === 'shield' ? 'activeShieldAmount'
    : jobType === 'stealth' ? 'activeStealthAmount'
      : jobType === 'claim' ? 'activeClaimAmount'
        : 'activeUnshieldAmount';

  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    const res = await sendMsg(MSG_GET_JOB_STATUS, { jobId }) as { status: string; step?: string; prover?: string; hash?: string; error?: string };
    if (res.status === 'running' || res.status === 'pending_unlock' || res.status === 'crypto_done') {
      // silently polling — toast already shown at start
    } else if (res.status === 'done') {
      clearInterval(pollTimer!);
      pollTimer = null;
      // Read stored amount before clearing keys
      const stored = await chrome.storage.local.get(amountKey);
      const jobAmount = stored[amountKey] ?? '';
      await chrome.storage.local.remove(storageKeys);
      // Inject synthetic activity entry so it shows immediately (indexer may lag)
      if (res.hash) {
        const myAddr = document.getElementById('display-address')!.getAttribute('data-full') ?? '';
        const opType = jobType === 'shield' ? 'encrypt' : jobType === 'unshield' ? 'decrypt' : jobType === 'stealth' ? 'stealth' : jobType === 'claim' ? 'claim' : 'standard';
        // Parse amount to raw (claim/stealth amounts are already raw from background)
        let rawAmount = 0;
        if (jobAmount) {
          if (jobType === 'claim' || jobType === 'stealth') {
            rawAmount = Number(jobAmount);
          } else if (jobAmount.includes('.')) {
            const [intPart, fracPart] = jobAmount.split('.');
            rawAmount = Number(BigInt(intPart) * 1000000n + BigInt((fracPart + '000000').slice(0, 6)));
          } else {
            rawAmount = Number(BigInt(jobAmount) * 1000000n);
          }
        }
        activityCache.set(res.hash, {
          tx_hash: res.hash, timestamp: Math.floor(Date.now() / 1000),
          from: myAddr, to: myAddr, op_type: opType, amount_raw: rawAmount,
          _pending: true,
        });
      }
      const doneMsg = jobType === 'shield' ? 'Funds shielded!' : jobType === 'claim' ? 'Stealth funds claimed!' : jobType === 'stealth' ? 'Private transfer complete!' : 'Funds unshielded!';
      showActionToast(doneMsg, { action: 'View', goActivity: true });
      // Force activity refresh even if one is already in-flight
      activityLoading = false;
      loadActivity();
    } else if (res.status === 'error') {
      clearInterval(pollTimer!);
      pollTimer = null;
      await chrome.storage.local.remove(storageKeys);
      showActionToast(`${label} failed: ${res.error}`, { duration: 4000 });
    } else if (res.status === 'cancelled') {
      clearInterval(pollTimer!);
      pollTimer = null;
      showActionToast(`${label} cancelled`, { duration: 3000 });
    }
  }, 2000);
}

// Check for running jobs on popup open
async function checkActiveJob() {
  const { activeUnshieldJob, activeShieldJob, activeStealthJob, activeClaimJob } = await chrome.storage.local.get(['activeUnshieldJob', 'activeShieldJob', 'activeStealthJob', 'activeClaimJob']);
  if (activeUnshieldJob) {
    pollJobStatus(activeUnshieldJob, 'unshield');
  } else if (activeShieldJob) {
    pollJobStatus(activeShieldJob, 'shield');
  } else if (activeStealthJob) {
    pollJobStatus(activeStealthJob, 'stealth');
  } else if (activeClaimJob) {
    pollJobStatus(activeClaimJob, 'claim');
  }
}

// --- Prover Settings ---
const proverModal = document.getElementById('prover-modal')!;
const proverModeLabel = document.getElementById('prover-mode-label')!;
const proverModeBtn = document.getElementById('btn-prover-settings')!;

document.getElementById('btn-prover-settings')!.addEventListener('click', () => {
  proverModal.classList.remove('hidden');
  refreshProverStatus();
});
document.getElementById('prover-close')!.addEventListener('click', () => proverModal.classList.add('hidden'));
proverModal.addEventListener('click', (e) => { if (e.target === proverModal) proverModal.classList.add('hidden'); });

// Network toggle (mainnet ↔ devnet)
const networkLabel = document.getElementById('network-label')!;
const DEVNET_RPC = 'https://devnet.octrascan.io/rpc';
const MAIN_RPC = 'https://octra.network/rpc';

(async () => {
  const res = await sendMsg(MSG_GET_RPC_URL) as { rpcUrl?: string };
  networkLabel.textContent = res.rpcUrl === DEVNET_RPC ? 'devnet' : 'mainnet';
  networkLabel.style.color = res.rpcUrl === DEVNET_RPC ? '#c8a420' : '';
  setExplorerFromRpc(res.rpcUrl ?? MAIN_RPC);
})();

document.getElementById('btn-network')!.addEventListener('click', async () => {
  const res = await sendMsg(MSG_GET_RPC_URL) as { rpcUrl?: string };
  const isDevnet = res.rpcUrl === DEVNET_RPC;
  const newUrl = isDevnet ? MAIN_RPC : DEVNET_RPC;
  await sendMsg(MSG_SET_RPC_URL, { url: newUrl });
  setExplorerFromRpc(newUrl);
  networkLabel.textContent = isDevnet ? 'mainnet' : 'devnet';
  networkLabel.style.color = isDevnet ? '' : '#c8a420';
  showToast(isDevnet ? 'Switched to Mainnet' : 'Switched to Devnet');
  // Refresh balances and activity for the new network
  refreshPublicBalance();
  refreshPrivateBalance();
  loadActivity();
});

async function refreshProverStatus() {
  const res = await sendMsg(MSG_GET_PROVER_STATUS) as { local?: boolean; remote?: boolean; mode?: string };
  const localInd = document.getElementById('prover-local-indicator')!;
  const remoteInd = document.getElementById('prover-remote-indicator')!;
  localInd.className = `prover-indicator ${res.local ? 'online' : 'offline'}`;
  remoteInd.className = `prover-indicator ${res.remote ? 'online' : 'offline'}`;

  // Set radio to current mode
  const currentMode = res.mode ?? (res.local ? 'local' : res.remote ? 'remote' : 'browser');
  const radio = proverModal.querySelector(`input[value="${currentMode}"]`) as HTMLInputElement | null;
  if (radio) radio.checked = true;
  updateProverModeLabel(currentMode);

  const removeBtn = document.getElementById('btn-remove-pairing') as HTMLButtonElement;
  removeBtn.style.display = res.remote ? '' : 'none';

  // Only show download CTA if neither local nor remote is available
  const cta = document.getElementById('prover-cta')!;
  if (res.local || res.remote) {
    cta.classList.add('hidden');
  } else {
    cta.classList.remove('hidden');
  }
}

function updateProverModeLabel(mode: string) {
  const labels: Record<string, string> = { local: 'Prover: Desktop', remote: 'Prover: Remote', browser: 'Prover: Wallet (slow)' };
  proverModeLabel.textContent = labels[mode] ?? 'Prover: Wallet (slow)';
  proverModeBtn.className = 'prover-mode-btn' + (mode === 'local' ? ' active-local' : mode === 'remote' ? ' active-remote' : '');
}

// Radio change handler
proverModal.querySelectorAll('input[name="prover-mode"]').forEach((radio) => {
  radio.addEventListener('change', async (e) => {
    const mode = (e.target as HTMLInputElement).value;
    await sendMsg(MSG_SET_PROVER_MODE, { mode });
    updateProverModeLabel(mode);
  });
});

document.getElementById('prover-file-input')!.addEventListener('change', async (e) => {
  const file = (e.target as HTMLInputElement).files?.[0];
  if (!file) return;
  const text = await file.text();
  const res = await sendMsg(MSG_IMPORT_PAIRING, { fileContent: text }) as { ok?: boolean; error?: string };
  if (res.ok) {
    showToast('Pairing imported!');
    refreshProverStatus();
  } else {
    showToast(res.error ?? 'Import failed');
  }
  (e.target as HTMLInputElement).value = '';
});

document.getElementById('btn-remove-pairing')!.addEventListener('click', async () => {
  await sendMsg(MSG_REMOVE_PAIRING);
  showToast('Pairing removed');
  refreshProverStatus();
});

// --- Settings Modal ---
// Fee UI displays values in microOCT; storage holds raw values (×1000)
const FEE_UI_DIVISOR = 1000;

const settingsModal = document.getElementById('settings-modal')!;
document.getElementById('btn-settings')!.addEventListener('click', async () => {
  settingsModal.classList.remove('hidden');
  // Load current overrides and display ÷100
  const keys = [SK_FEE_DEFAULT, SK_FEE_ENCRYPT, SK_FEE_DECRYPT, SK_FEE_STEALTH, SK_FEE_CLAIM];
  const stored = await chrome.storage.local.get(keys) as Record<string, string>;
  const toDisplay = (raw: string | undefined) => raw ? String(Math.round(Number(raw) / FEE_UI_DIVISOR)) : '';
  (document.getElementById('fee-default') as HTMLInputElement).value = toDisplay(stored[SK_FEE_DEFAULT]);
  (document.getElementById('fee-encrypt') as HTMLInputElement).value = toDisplay(stored[SK_FEE_ENCRYPT]);
  (document.getElementById('fee-decrypt') as HTMLInputElement).value = toDisplay(stored[SK_FEE_DECRYPT]);
  (document.getElementById('fee-stealth') as HTMLInputElement).value = toDisplay(stored[SK_FEE_STEALTH]);
  (document.getElementById('fee-claim') as HTMLInputElement).value = toDisplay(stored[SK_FEE_CLAIM]);
});
document.getElementById('settings-close')!.addEventListener('click', () => settingsModal.classList.add('hidden'));
settingsModal.addEventListener('click', (e) => { if (e.target === settingsModal) settingsModal.classList.add('hidden'); });

document.getElementById('btn-save-fees')!.addEventListener('click', async () => {
  const getValue = (id: string) => (document.getElementById(id) as HTMLInputElement).value.trim();
  const updates: Record<string, string> = {};
  const removals: string[] = [];

  const fields: [string, string][] = [
    ['fee-default', SK_FEE_DEFAULT],
    ['fee-encrypt', SK_FEE_ENCRYPT],
    ['fee-decrypt', SK_FEE_DECRYPT],
    ['fee-stealth', SK_FEE_STEALTH],
    ['fee-claim', SK_FEE_CLAIM],
  ];

  for (const [inputId, key] of fields) {
    const val = getValue(inputId);
    if (val && /^\d+$/.test(val)) {
      updates[key] = String(Number(val) * FEE_UI_DIVISOR);
    } else {
      removals.push(key);
    }
  }

  if (Object.keys(updates).length > 0) await chrome.storage.local.set(updates);
  if (removals.length > 0) await chrome.storage.local.remove(removals);
  showToast('Fees saved');
  settingsModal.classList.add('hidden');
});

// ─── NFT Content Tab ────────────────────────────────────────────────────────

interface NftToken {
  id: number;
  owner: string;
  isMine: boolean;
  meta?: { name?: string; description?: string; image?: string; attributes?: Array<{ trait_type: string; value: string }> };
  imgDataUrl?: string;
}

interface NftCollection {
  name: string;
  symbol: string;
  totalMinted: number;
  maxSupply: number;
  royaltyBps: number;
  metaCircle: string | null;
  imgCircle: string | null;
  imgUri: string | null;
  tokens: NftToken[];
  callerAddr: string;
}

let nftCache: NftCollection | null = null;

async function loadNftContent(contractAddr: string) {
  const grid = document.getElementById('nft-grid')!;
  const header = document.getElementById('nft-collection-header')!;
  const empty = document.getElementById('nft-empty')!;
  const loading = document.getElementById('nft-loading')!;

  // Reset UI
  grid.innerHTML = '';
  header.classList.add('hidden');
  empty.classList.add('hidden');
  loading.classList.remove('hidden');

  try {
    const res = await sendMsg(MSG_GET_NFT_CONTENT, { contractAddr }) as NftCollection & { error?: string };
    if (res.error) {
      loading.classList.add('hidden');
      empty.classList.remove('hidden');
      empty.querySelector('p')!.textContent = `Error: ${res.error}`;
      return;
    }

    nftCache = res;

    // Show collection header
    const nameEl = document.getElementById('nft-col-name')!;
    const statsEl = document.getElementById('nft-col-stats')!;
    nameEl.textContent = res.name ? `${res.name} (${res.symbol})` : contractAddr.slice(0, 16) + '…';
    const mineCount = res.tokens.filter(t => t.isMine).length;
    statsEl.textContent = `${res.totalMinted} minted · ${mineCount} yours`;
    header.classList.remove('hidden');

    // Filter: show only tokens owned by the user
    const myTokens = res.tokens.filter(t => t.isMine);

    if (myTokens.length === 0) {
      loading.classList.add('hidden');
      empty.classList.remove('hidden');
      empty.querySelector('p')!.textContent = 'No NFTs owned by this address';
      return;
    }

    // Render placeholder cards
    grid.innerHTML = myTokens.map(t => `
      <div class="nft-card" data-token-id="${t.id}">
        <div class="nft-card-img-wrap">
          <div class="shimmer nft-card-img-placeholder"></div>
        </div>
        <div class="nft-card-info">
          <span class="nft-card-name">${res.name} #${t.id}</span>
          <span class="nft-card-desc loading-text">Loading…</span>
        </div>
      </div>
    `).join('');
    loading.classList.add('hidden');

    // Fetch metadata + images for each token in parallel (max 4 concurrent)
    const concurrency = 4;
    let idx = 0;
    async function fetchNext() {
      while (idx < myTokens.length) {
        const token = myTokens[idx++];
        await fetchAndRenderToken(res, token);
      }
    }
    const workers = Array.from({ length: Math.min(concurrency, myTokens.length) }, () => fetchNext());
    await Promise.all(workers);

  } catch (err) {
    loading.classList.add('hidden');
    empty.classList.remove('hidden');
    empty.querySelector('p')!.textContent = `Error: ${(err as Error).message}`;
  }
}

async function fetchAndRenderToken(collection: NftCollection, token: NftToken) {
  const card = document.querySelector(`.nft-card[data-token-id="${token.id}"]`) as HTMLElement | null;
  if (!card) return;

  try {
    // 1. Fetch metadata JSON from the metadata circle
    if (collection.metaCircle && collection.metaCircle !== 'null') {
      const metaPath = `/${token.id}.json`;
      try {
        const metaAsset = await sendMsg(MSG_FETCH_CIRCLE_ASSET, {
          circleId: collection.metaCircle,
          path: metaPath,
        }) as { bodyB64?: string; error?: string };
        if (metaAsset.bodyB64) {
          token.meta = JSON.parse(atob(metaAsset.bodyB64));
        }
      } catch { /* metadata fetch failed, use defaults */ }
    }

    // 2. Fetch image from the image circle
    if (token.meta?.image && token.meta.image.startsWith('oct://')) {
      const imgPath = token.meta.image.replace(/^oct:\/\/[^/]+/, '') || '/';
      const imgCircleId = token.meta.image.replace(/^oct:\/\//, '').split('/')[0];
      try {
        const imgAsset = await sendMsg(MSG_FETCH_CIRCLE_ASSET, {
          circleId: imgCircleId,
          path: imgPath,
        }) as { bodyB64?: string; contentType?: string };
        if (imgAsset.bodyB64) {
          const ct = imgAsset.contentType || 'image/png';
          token.imgDataUrl = `data:${ct};base64,${imgAsset.bodyB64}`;
        }
      } catch { /* image fetch failed */ }
    }

    // 3. Update the card DOM
    const imgWrap = card.querySelector('.nft-card-img-wrap')!;
    const nameEl = card.querySelector('.nft-card-name')!;
    const descEl = card.querySelector('.nft-card-desc')!;

    // 4. Add hover overlay with "View in browser" button
    const overlay = document.createElement('div');
    overlay.className = 'nft-card-overlay';
    overlay.innerHTML = '<button class="nft-card-overlay-btn">View in browser ↗</button>';
    overlay.querySelector('button')!.addEventListener('click', (e) => {
      e.stopPropagation();
      openNftViewer(collection, token);
    });
    card.appendChild(overlay);

    if (token.imgDataUrl) {
      imgWrap.innerHTML = `<img class="nft-card-img" src="${token.imgDataUrl}" alt="${collection.name} #${token.id}" />`;
    } else {
      imgWrap.innerHTML = `<div class="nft-card-img-placeholder no-img">No Image</div>`;
    }

    nameEl.textContent = token.meta?.name || `${collection.name} #${token.id}`;
    if (token.meta?.description) {
      descEl.textContent = token.meta.description;
      descEl.classList.remove('loading-text');
    } else {
      descEl.textContent = `Token #${token.id}`;
      descEl.classList.remove('loading-text');
    }

    // Add attributes if present
    if (token.meta?.attributes && token.meta.attributes.length > 0) {
      const attrsHtml = token.meta.attributes
        .map(a => `<span class="nft-attr"><span class="nft-attr-type">${escapeHtml(a.trait_type)}</span> ${escapeHtml(String(a.value))}</span>`)
        .join('');
      const attrsEl = document.createElement('div');
      attrsEl.className = 'nft-attrs';
      attrsEl.innerHTML = attrsHtml;
      card.querySelector('.nft-card-info')!.appendChild(attrsEl);
    }
  } catch {
    const descEl = card.querySelector('.nft-card-desc');
    if (descEl) {
      descEl.textContent = 'Failed to load';
      descEl.classList.remove('loading-text');
    }
  }
}

function openNftViewer(collection: NftCollection, token: NftToken) {
  const viewId = `${collection.name}_${token.id}_${Date.now()}`;
  const key = `nftView:${viewId}`;
  const data = {
    name: token.meta?.name || `${collection.name} #${token.id}`,
    description: token.meta?.description || '',
    imgDataUrl: token.imgDataUrl || '',
    tokenId: token.id,
    collectionName: collection.name,
    collectionSymbol: collection.symbol,
    attributes: token.meta?.attributes || [],
    rawMeta: token.meta || {},
    contractAddr: '',
  };
  chrome.storage.local.set({ [key]: data }).then(() => {
    const viewerUrl = chrome.runtime.getURL('dist/src/popup/viewer.html') + `?id=${encodeURIComponent(viewId)}`;
    chrome.tabs.create({ url: viewerUrl });
  });
}

// Load button handler
const nftContractInput = document.getElementById('nft-contract-input') as HTMLInputElement;
const btnLoadNft = document.getElementById('btn-load-nft') as HTMLButtonElement;

btnLoadNft.addEventListener('click', () => {
  const addr = nftContractInput.value.trim();
  if (!addr || !addr.startsWith('oct')) {
    showToast('Enter a valid contract address');
    return;
  }
  loadNftContent(addr);
});

nftContractInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') btnLoadNft.click();
});

init();
