/**
 * PVAC Web Worker — runs heavy WASM computation off the main thread.
 * The offscreen document delegates here so message passing stays responsive.
 */
import PvacModuleFactory from '../lib/pvac-wasm/pvac.js';

let module: any = null;
let initialized = false;
let initializedKeyId: string | null = null;

async function ensureModule(): Promise<any> {
  if (module) return module;
  module = await PvacModuleFactory();
  return module;
}

function initPvacFromKeys(skBytes: Uint8Array, pkBytes: Uint8Array): boolean {
  const skPtr = module._malloc(skBytes.length);
  module.HEAPU8.set(skBytes, skPtr);
  const pkPtr = module._malloc(pkBytes.length);
  module.HEAPU8.set(pkBytes, pkPtr);
  const ok = module._pvac_wasm_init_from_keys(skPtr, skBytes.length, pkPtr, pkBytes.length);
  module._free(skPtr);
  module._free(pkPtr);
  initialized = ok === 1;
  return initialized;
}

function encryptValue(amountRaw: bigint, randomSeed: Uint8Array): Uint8Array {
  const seedPtr = module._malloc(32);
  module.HEAPU8.set(randomSeed, seedPtr);
  const outLenPtr = module._malloc(4);
  const dataPtr = module._pvac_wasm_encrypt(Number(amountRaw & 0xFFFFFFFFn), seedPtr, outLenPtr);
  const outLen = module.getValue(outLenPtr, 'i32');
  const result = new Uint8Array(module.HEAPU8.buffer, dataPtr, outLen).slice();
  module._pvac_wasm_free(dataPtr);
  module._free(seedPtr);
  module._free(outLenPtr);
  return result;
}

function decryptValue(cipherData: Uint8Array): bigint {
  const ptr = module._malloc(cipherData.length);
  module.HEAPU8.set(cipherData, ptr);

  // Use 64-bit output pointer variant if available
  if (module._pvac_wasm_decrypt64) {
    const outPtr = module._malloc(8); // two uint32_t
    const ok = module._pvac_wasm_decrypt64(ptr, cipherData.length, outPtr);
    if (ok === 1) {
      const lo = module.getValue(outPtr, 'i32') >>> 0;       // unsigned lower 32 bits
      const hi = module.getValue(outPtr + 4, 'i32') >>> 0;   // unsigned upper 32 bits
      module._free(outPtr);
      module._free(ptr);
      return BigInt(hi) * 0x100000000n + BigInt(lo);
    }
    module._free(outPtr);
    module._free(ptr);
    return 0n; // decrypt failed (null keys or bad cipher)
  }

  // Fallback: old 32-bit function (treat as unsigned)
  const val = module._pvac_wasm_decrypt(ptr, cipherData.length);
  module._free(ptr);
  return BigInt(val >>> 0);
}

function pedersenCommit(amount: bigint, blinding: Uint8Array): Uint8Array {
  const blindPtr = module._malloc(32);
  module.HEAPU8.set(blinding, blindPtr);
  const outPtr = module._pvac_wasm_pedersen_commit(Number(amount & 0xFFFFFFFFn), blindPtr);
  const result = new Uint8Array(module.HEAPU8.buffer, outPtr, 32).slice();
  module._pvac_wasm_free(outPtr);
  module._free(blindPtr);
  return result;
}

function makeZeroProofBound(cipherData: Uint8Array, amount: bigint, blinding: Uint8Array): Uint8Array {
  const cPtr = module._malloc(cipherData.length);
  module.HEAPU8.set(cipherData, cPtr);
  const bPtr = module._malloc(32);
  module.HEAPU8.set(blinding, bPtr);
  const outLenPtr = module._malloc(4);
  const dataPtr = module._pvac_wasm_make_zero_proof_bound(
    cPtr, cipherData.length, Number(amount & 0xFFFFFFFFn), bPtr, outLenPtr
  );
  const outLen = module.getValue(outLenPtr, 'i32');
  const result = new Uint8Array(module.HEAPU8.buffer, dataPtr, outLen).slice();
  module._pvac_wasm_free(dataPtr);
  module._free(cPtr);
  module._free(bPtr);
  module._free(outLenPtr);
  return result;
}

function makeRangeProof(cipherData: Uint8Array, value: bigint): Uint8Array {
  const cPtr = module._malloc(cipherData.length);
  module.HEAPU8.set(cipherData, cPtr);
  const outLenPtr = module._malloc(4);
  const dataPtr = module._pvac_wasm_make_range_proof(
    cPtr, cipherData.length, Number(value & 0xFFFFFFFFn), outLenPtr
  );
  const outLen = module.getValue(outLenPtr, 'i32');
  const result = new Uint8Array(module.HEAPU8.buffer, dataPtr, outLen).slice();
  module._pvac_wasm_free(dataPtr);
  module._free(cPtr);
  module._free(outLenPtr);
  return result;
}

function ctSub(cipherA: Uint8Array, cipherB: Uint8Array): Uint8Array {
  const aPtr = module._malloc(cipherA.length);
  module.HEAPU8.set(cipherA, aPtr);
  const bPtr = module._malloc(cipherB.length);
  module.HEAPU8.set(cipherB, bPtr);
  const outLenPtr = module._malloc(4);
  const dataPtr = module._pvac_wasm_ct_sub(aPtr, cipherA.length, bPtr, cipherB.length, outLenPtr);
  const outLen = module.getValue(outLenPtr, 'i32');
  const result = new Uint8Array(module.HEAPU8.buffer, dataPtr, outLen).slice();
  module._pvac_wasm_free(dataPtr);
  module._free(aPtr);
  module._free(bPtr);
  module._free(outLenPtr);
  return result;
}

function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function fromBase64(b64: string): Uint8Array {
  if (!b64) return new Uint8Array(0);
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// Post status update to main thread (which forwards to background)
function postStatus(step: string) {
  self.postMessage({ type: 'status', step });
}

// Handle messages from the offscreen main thread
self.onmessage = async (ev: MessageEvent) => {
  const msg = ev.data;
  try {
    await ensureModule();

    switch (msg.action) {
      case 'init': {
        const sk = fromBase64(msg.pvacSkB64);
        const pk = fromBase64(msg.pvacPkB64);
        const ok = initPvacFromKeys(sk, pk);
        initializedKeyId = msg.keyId;
        self.postMessage({ type: 'result', data: { ok } });
        break;
      }
      case 'computeUnshield': {
        const currentCipherBytes = fromBase64(msg.currentCipherB64);
        const decAmountRaw = BigInt(msg.decAmountRaw);
        const seedBytes = fromBase64(msg.seedB64);
        const blindingBytes = fromBase64(msg.blindingB64);

        if (!initialized || msg.keyId !== initializedKeyId) {
          const sk = fromBase64(msg.pvacSkB64);
          const pk = fromBase64(msg.pvacPkB64);
          if (!initPvacFromKeys(sk, pk)) {
            self.postMessage({ type: 'result', data: { error: 'PVAC init failed' } });
            return;
          }
          initializedKeyId = msg.keyId;
        }

        const currentDecrypted = decryptValue(currentCipherBytes);
        if (currentDecrypted < decAmountRaw) {
          self.postMessage({ type: 'result', data: { error: `Insufficient shielded balance: have ${currentDecrypted}, need ${decAmountRaw}` } });
          return;
        }

        postStatus('Encrypting amount...');
        const cipherBytes = encryptValue(decAmountRaw, seedBytes);
        const cipherStr = 'hfhe_v1|' + toBase64(cipherBytes);

        const commitBytes = pedersenCommit(decAmountRaw, blindingBytes);
        const commitB64 = toBase64(commitBytes);

        postStatus('Generating zero proof...');
        const zpBytes = makeZeroProofBound(cipherBytes, decAmountRaw, blindingBytes);
        const zpStr = 'zkzp_v2|' + toBase64(zpBytes);

        postStatus('Generating range proof (this takes a few minutes)...');
        const newBalCipherBytes = ctSub(currentCipherBytes, cipherBytes);
        const newBalValue = currentDecrypted - decAmountRaw;
        const rpBytes = makeRangeProof(newBalCipherBytes, newBalValue);
        const rpStr = 'rp_v1|' + toBase64(rpBytes);

        self.postMessage({
          type: 'result',
          data: {
            cipher: cipherStr,
            amount_commitment: commitB64,
            zero_proof: zpStr,
            blinding: toBase64(blindingBytes),
            range_proof_balance: rpStr,
          },
        });
        break;
      }
      case 'decrypt': {
        // Re-init if key differs from last init
        if (!initialized || msg.keyId !== initializedKeyId) {
          const sk = fromBase64(msg.pvacSkB64);
          const pk = fromBase64(msg.pvacPkB64);
          initPvacFromKeys(sk, pk);
          initializedKeyId = msg.keyId;
        }
        const cipherBytes = fromBase64(msg.cipherB64);
        const val = decryptValue(cipherBytes);
        self.postMessage({ type: 'result', data: { value: String(val) } });
        break;
      }
      case 'pvac_encrypt': {
        if (!initialized || msg.keyId !== initializedKeyId) {
          initPvacFromKeys(fromBase64(msg.pvacSkB64), fromBase64(msg.pvacPkB64));
          initializedKeyId = msg.keyId;
        }
        const seed = new Uint8Array(32);
        crypto.getRandomValues(seed);
        const ct = encryptValue(BigInt(msg.value), seed);
        self.postMessage({ type: 'result', data: { ciphertext: toBase64(ct) } });
        break;
      }
      case 'pvac_decrypt': {
        if (!initialized || msg.keyId !== initializedKeyId) {
          initPvacFromKeys(fromBase64(msg.pvacSkB64), fromBase64(msg.pvacPkB64));
          initializedKeyId = msg.keyId;
        }
        const ct2 = fromBase64(msg.ciphertext);
        const decVal = decryptValue(ct2);
        self.postMessage({ type: 'result', data: { value: Number(decVal) } });
        break;
      }
      case 'pvac_rangeProof': {
        if (!initialized || msg.keyId !== initializedKeyId) {
          initPvacFromKeys(fromBase64(msg.pvacSkB64), fromBase64(msg.pvacPkB64));
          initializedKeyId = msg.keyId;
        }
        const rpCt = fromBase64(msg.ciphertext);
        const rpBytes2 = makeRangeProof(rpCt, BigInt(msg.value));
        self.postMessage({ type: 'result', data: { proof: toBase64(rpBytes2) } });
        break;
      }
      case 'pvac_commit': {
        if (!initialized || msg.keyId !== initializedKeyId) {
          initPvacFromKeys(fromBase64(msg.pvacSkB64), fromBase64(msg.pvacPkB64));
          initializedKeyId = msg.keyId;
        }
        const blindBytes = msg.blinding ? fromBase64(msg.blinding) : (() => { const b = new Uint8Array(32); crypto.getRandomValues(b); return b; })();
        const commitment = pedersenCommit(BigInt(msg.value), blindBytes);
        self.postMessage({ type: 'result', data: { commitment: toBase64(commitment), blinding: toBase64(blindBytes) } });
        break;
      }
      case 'pvac_zeroProof': {
        if (!initialized || msg.keyId !== initializedKeyId) {
          initPvacFromKeys(fromBase64(msg.pvacSkB64), fromBase64(msg.pvacPkB64));
          initializedKeyId = msg.keyId;
        }
        const zpCt = fromBase64(msg.ciphertext);
        const zpBlinding = fromBase64(msg.blinding);
        const zpBytes2 = makeZeroProofBound(zpCt, BigInt(msg.value), zpBlinding);
        self.postMessage({ type: 'result', data: { proof: toBase64(zpBytes2) } });
        break;
      }
      case 'pvac_ctSub': {
        if (!initialized || msg.keyId !== initializedKeyId) {
          initPvacFromKeys(fromBase64(msg.pvacSkB64), fromBase64(msg.pvacPkB64));
          initializedKeyId = msg.keyId;
        }
        const subResult = ctSub(fromBase64(msg.a), fromBase64(msg.b));
        self.postMessage({ type: 'result', data: { ciphertext: toBase64(subResult) } });
        break;
      }
      default:
        self.postMessage({ type: 'result', data: { error: `Unknown action: ${msg.action}` } });
    }
  } catch (err) {
    self.postMessage({ type: 'result', data: { error: (err as Error).message } });
  }
};
