/* empty css             */const r=new URLSearchParams(window.location.search),o=r.get("id");if(!o)throw document.body.textContent="No approval request.",new Error("Missing approval id");const t=document.getElementById("title"),i=document.getElementById("origin"),n=document.getElementById("details"),l=document.getElementById("warning"),d=document.getElementById("btn-approve"),p=document.getElementById("btn-reject");async function v(){const e=`approval_${o}`,a=(await chrome.storage.local.get(e))[e];if(!a){document.body.textContent="Approval request expired.";return}switch(i.textContent=a.origin,a.type){case"connect":t.textContent="Connect Wallet",n.innerHTML=`
        <div class="row"><span class="label">This site wants to:</span></div>
        <div class="row"><span class="value">• View your wallet address</span></div>
        <div class="row"><span class="value">• Check your balance</span></div>
      `;break;case"sign_message":t.textContent="Sign Message",n.innerHTML=`
        <div class="row"><span class="label">Message:</span></div>
        <div class="message-preview">${s(String(a.data.message??""))}</div>
      `,l.textContent="Only sign messages you understand. This does not send a transaction.";break;case"send_transaction":t.textContent="Send Transaction",n.innerHTML=`
        <div class="row"><span class="label">To:</span> <span class="value">${s(String(a.data.to??""))}</span></div>
        <div class="row"><span class="label">Amount:</span> <span class="value">${a.data.amount} OCT</span></div>
        ${a.data.message?`<div class="row"><span class="label">Memo:</span> <span class="value">${s(String(a.data.message))}</span></div>`:""}
      `,l.textContent="This will transfer OCT from your wallet.";break;case"call_contract":t.textContent="Contract Call",n.innerHTML=`
        <div class="row"><span class="label">Contract:</span> <span class="value">${s(String(a.data.contract??""))}</span></div>
        <div class="row"><span class="label">Method:</span> <span class="value">${s(String(a.data.method??""))}</span></div>
        <div class="row"><span class="label">Params:</span></div>
        <div class="message-preview">${s(JSON.stringify(a.data.params??[],null,2))}</div>
        ${a.data.amount&&a.data.amount!=="0"?`<div class="row"><span class="label">OCT attached:</span> <span class="value">${a.data.amount}</span></div>`:""}
      `,l.textContent="This will execute a smart contract function.";break}d.addEventListener("click",()=>c(!0)),p.addEventListener("click",()=>c(!1))}function c(e){chrome.runtime.sendMessage({type:"APPROVAL_RESPONSE",payload:{id:o,approved:e}},()=>{window.close()})}function s(e){return e.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;")}v();
