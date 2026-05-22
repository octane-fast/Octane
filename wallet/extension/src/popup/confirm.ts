// Confirmation popup logic — reads pending request from storage, shows details, sends response

interface PendingApproval {
  id: string;
  type: 'connect' | 'sign_message' | 'send_transaction' | 'call_contract';
  origin: string;
  data: Record<string, unknown>;
}

const params = new URLSearchParams(window.location.search);
const approvalId = params.get('id');

if (!approvalId) {
  document.body.textContent = 'No approval request.';
  throw new Error('Missing approval id');
}

const titleEl = document.getElementById('title')!;
const originEl = document.getElementById('origin')!;
const detailsEl = document.getElementById('details')!;
const warningEl = document.getElementById('warning')!;
const btnApprove = document.getElementById('btn-approve')!;
const btnReject = document.getElementById('btn-reject')!;

async function load() {
  const key = `approval_${approvalId}`;
  const stored = await chrome.storage.local.get(key);
  const approval: PendingApproval | undefined = stored[key];

  if (!approval) {
    document.body.textContent = 'Approval request expired.';
    return;
  }

  originEl.textContent = approval.origin;

  switch (approval.type) {
    case 'connect':
      titleEl.textContent = 'Connect Wallet';
      detailsEl.innerHTML = `
        <div class="row"><span class="label">This site wants to:</span></div>
        <div class="row"><span class="value">• View your wallet address</span></div>
        <div class="row"><span class="value">• Check your balance</span></div>
      `;
      break;

    case 'sign_message':
      titleEl.textContent = 'Sign Message';
      detailsEl.innerHTML = `
        <div class="row"><span class="label">Message:</span></div>
        <div class="message-preview">${escapeHtml(String(approval.data.message ?? ''))}</div>
      `;
      warningEl.textContent = 'Only sign messages you understand. This does not send a transaction.';
      break;

    case 'send_transaction':
      titleEl.textContent = 'Send Transaction';
      detailsEl.innerHTML = `
        <div class="row"><span class="label">To:</span> <span class="value">${escapeHtml(String(approval.data.to ?? ''))}</span></div>
        <div class="row"><span class="label">Amount:</span> <span class="value">${approval.data.amount} OCT</span></div>
        ${approval.data.message ? `<div class="row"><span class="label">Memo:</span> <span class="value">${escapeHtml(String(approval.data.message))}</span></div>` : ''}
      `;
      warningEl.textContent = 'This will transfer OCT from your wallet.';
      break;

    case 'call_contract':
      titleEl.textContent = 'Contract Call';
      detailsEl.innerHTML = `
        <div class="row"><span class="label">Contract:</span> <span class="value">${escapeHtml(String(approval.data.contract ?? ''))}</span></div>
        <div class="row"><span class="label">Method:</span> <span class="value">${escapeHtml(String(approval.data.method ?? ''))}</span></div>
        <div class="row"><span class="label">Params:</span></div>
        <div class="message-preview">${escapeHtml(JSON.stringify(approval.data.params ?? [], null, 2))}</div>
        ${approval.data.amount && approval.data.amount !== '0' ? `<div class="row"><span class="label">OCT attached:</span> <span class="value">${approval.data.amount}</span></div>` : ''}
      `;
      warningEl.textContent = 'This will execute a smart contract function.';
      break;
  }

  btnApprove.addEventListener('click', () => respond(true));
  btnReject.addEventListener('click', () => respond(false));
}

function respond(approved: boolean) {
  chrome.runtime.sendMessage({
    type: 'APPROVAL_RESPONSE',
    payload: { id: approvalId, approved },
  }, () => {
    window.close();
  });
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

load();
