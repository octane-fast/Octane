/**
 * PVAC Web Worker — runs heavy WASM computation off the main thread.
 * The offscreen document delegates here so message passing stays responsive.
 */
import PvacModuleFactory from '../lib/pvac-wasm/pvac.js';

let module: any = null;
let initialized = false;

async function ensureModule(): Promise<any> {
  if (module) return module;
  module = await PvacModuleFactory();
  return module;
}

function initPvac(secretKey32: Uint8Array): boolean {
  const seedPtr = module._malloc(32);
  module.HEAPU8.set(secretKey32.slice(0, 32), seedPtr);
  const ok = module._pvac_wasm_init(seedPtr, 32);
  module._free(seedPtr);
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
  const val = module._pvac_wasm_decrypt(ptr, cipherData.length);
  module._free(ptr);
  return BigInt(val);
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
        const key = fromBase64(msg.secretKeyB64);
        const ok = initPvac(key);
        self.postMessage({ type: 'result', data: { ok } });
        break;
      }
      case 'computeUnshield': {
        const currentCipherBytes = fromBase64(msg.currentCipherB64);
        const decAmountRaw = BigInt(msg.decAmountRaw);
        const seedBytes = fromBase64(msg.seedB64);
        const blindingBytes = fromBase64(msg.blindingB64);

        if (!initialized) {
          const key = fromBase64(msg.secretKeyB64);
          if (!initPvac(key)) {
            self.postMessage({ type: 'result', data: { error: 'PVAC init failed' } });
            return;
          }
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
        if (!initialized) {
          const key = fromBase64(msg.secretKeyB64);
          initPvac(key);
        }
        const cipherBytes = fromBase64(msg.cipherB64);
        const val = decryptValue(cipherBytes);
        self.postMessage({ type: 'result', data: { value: String(val) } });
        break;
      }
      default:
        self.postMessage({ type: 'result', data: { error: `Unknown action: ${msg.action}` } });
    }
  } catch (err) {
    self.postMessage({ type: 'result', data: { error: (err as Error).message } });
  }
};
