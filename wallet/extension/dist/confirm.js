/* empty css             */const c=new URLSearchParams(window.location.search),o=c.get("id");if(!o)throw document.body.textContent="No approval request.",new Error("Missing approval id");const s=document.getElementById("title"),i=document.getElementById("origin"),n=document.getElementById("details"),l=document.getElementById("warning"),d=document.getElementById("btn-approve"),p=document.getElementById("btn-reject");async function v(){const t=`approval_${o}`,a=(await chrome.storage.local.get(t))[t];if(!a){document.body.textContent="Approval request expired.";return}switch(i.textContent=a.origin,a.type){case"connect":s.textContent="Connect Wallet",n.innerHTML=`
        <div class="row"><span class="label">This site wants to:</span></div>
        <div class="row"><span class="value">• View your wallet address</span></div>
        <div class="row"><span class="value">• Check your balance</span></div>
      `;break;case"sign_message":s.textContent="Sign Message",n.innerHTML=`
        <div class="row"><span class="label">Message:</span></div>
        <div class="message-preview">${e(String(a.data.message??""))}</div>
      `,l.textContent="Only sign messages you understand. This does not send a transaction.";break;case"send_transaction":s.textContent="Send Transaction",n.innerHTML=`
        <div class="row"><span class="label">To:</span> <span class="value">${e(String(a.data.to??""))}</span></div>
        <div class="row"><span class="label">Amount:</span> <span class="value">${a.data.amount} OCT</span></div>
        ${a.data.message?`<div class="row"><span class="label">Memo:</span> <span class="value">${e(String(a.data.message))}</span></div>`:""}
      `,l.textContent="This will transfer OCT from your wallet.";break;case"call_contract":s.textContent="Contract Call",n.innerHTML=`
        <div class="row"><span class="label">Contract:</span> <span class="value">${e(String(a.data.contract??""))}</span></div>
        <div class="row"><span class="label">Method:</span> <span class="value">${e(String(a.data.method??""))}</span></div>
        <div class="row"><span class="label">Params:</span></div>
        <div class="message-preview">${e(JSON.stringify(a.data.params??[],null,2))}</div>
        ${a.data.amount&&a.data.amount!=="0"?`<div class="row"><span class="label">OCT attached:</span> <span class="value">${a.data.amount}</span></div>`:""}
      `,l.textContent="This will execute a smart contract function.";break;case"pvac_decrypt":s.textContent="Decrypt Private Value",n.innerHTML=`
        <div class="row"><span class="label">Action:</span> <span class="value">${e(String(a.data.operation??"Decrypt a ciphertext"))}</span></div>
      `,l.textContent="This will reveal a private encrypted value to the requesting site.";break;case"pvac_prove":s.textContent="PVAC Proof Request",n.innerHTML=`
        <div class="row"><span class="label">Operation:</span> <span class="value">${e(String(a.data.operation??"Generate proof"))}</span></div>
        ${a.data.detail?`<div class="row"><span class="label">Details:</span> <span class="value">${e(String(a.data.detail))}</span></div>`:""}
      `,l.textContent="This will use your private key to generate a cryptographic proof.";break}d.addEventListener("click",()=>r(!0)),p.addEventListener("click",()=>r(!1))}function r(t){chrome.runtime.sendMessage({type:"APPROVAL_RESPONSE",payload:{id:o,approved:t}},()=>{window.close()})}function e(t){return t.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;")}v();
