/**
 * TypeScript wrapper for PVAC WASM module.
 * FILE: src/lib/pvac.ts
 * STATUS: OUR CODE
 *
 * Provides encrypt/decrypt/proof operations for shielded transactions.
 * The WASM module is built from pvac-wasm/ (see pvac-wasm/README.md).
 */

// Static import — dynamic import() is forbidden in service workers
import PvacModuleFactory from './pvac-wasm/pvac.js';

let module: any = null;
let initialized = false;

async function loadModule(): Promise<any> {
  if (module) return module;
  module = await PvacModuleFactory();
  return module;
}

export async function initPvac(secretKey32: Uint8Array): Promise<boolean> {
  await loadModule();
  const seedPtr = module._malloc(32);
  module.HEAPU8.set(secretKey32.slice(0, 32), seedPtr);
  const ok = module._pvac_wasm_init(seedPtr, 32);
  module._free(seedPtr);
  initialized = ok === 1;
  return initialized;
}

export async function initPvacFromKeys(skBytes: Uint8Array, pkBytes: Uint8Array): Promise<boolean> {
  await loadModule();
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

export function isInitialized(): boolean {
  return initialized;
}

export function encryptValue(amountRaw: bigint, randomSeed: Uint8Array): Uint8Array {
  if (!initialized) throw new Error('PVAC not initialized');
  const seedPtr = module._malloc(32);
  module.HEAPU8.set(randomSeed, seedPtr);
  const outLenPtr = module._malloc(4);

  const dataPtr = module._pvac_wasm_encrypt(
    Number(amountRaw & 0xFFFFFFFFn),
    seedPtr,
    outLenPtr
  );
  const outLen = module.getValue(outLenPtr, 'i32');
  const result = new Uint8Array(module.HEAPU8.buffer, dataPtr, outLen).slice();

  module._pvac_wasm_free(dataPtr);
  module._free(seedPtr);
  module._free(outLenPtr);
  return result;
}

export function decryptValue(cipherData: Uint8Array): bigint {
  if (!initialized) throw new Error('PVAC not initialized');
  const ptr = module._malloc(cipherData.length);
  module.HEAPU8.set(cipherData, ptr);
  const val = module._pvac_wasm_decrypt(ptr, cipherData.length);
  module._free(ptr);
  return BigInt(val);
}

export function pedersenCommit(amount: bigint, blinding: Uint8Array): Uint8Array {
  if (!initialized) throw new Error('PVAC not initialized');
  const blindPtr = module._malloc(32);
  module.HEAPU8.set(blinding, blindPtr);
  const outPtr = module._pvac_wasm_pedersen_commit(Number(amount & 0xFFFFFFFFn), blindPtr);
  const result = new Uint8Array(module.HEAPU8.buffer, outPtr, 32).slice();
  module._pvac_wasm_free(outPtr);
  module._free(blindPtr);
  return result;
}

export function makeZeroProofBound(
  cipherData: Uint8Array,
  amount: bigint,
  blinding: Uint8Array
): Uint8Array {
  if (!initialized) throw new Error('PVAC not initialized');
  const ctPtr = module._malloc(cipherData.length);
  module.HEAPU8.set(cipherData, ctPtr);
  const blindPtr = module._malloc(32);
  module.HEAPU8.set(blinding, blindPtr);
  const outLenPtr = module._malloc(4);

  const dataPtr = module._pvac_wasm_make_zero_proof_bound(
    ctPtr, cipherData.length,
    Number(amount & 0xFFFFFFFFn),
    blindPtr,
    outLenPtr
  );
  const outLen = module.getValue(outLenPtr, 'i32');
  const result = dataPtr ? new Uint8Array(module.HEAPU8.buffer, dataPtr, outLen).slice() : new Uint8Array(0);

  if (dataPtr) module._pvac_wasm_free(dataPtr);
  module._free(ctPtr);
  module._free(blindPtr);
  module._free(outLenPtr);
  return result;
}

export function makeRangeProof(cipherData: Uint8Array, value: bigint): Uint8Array {
  if (!initialized) throw new Error('PVAC not initialized');
  const ctPtr = module._malloc(cipherData.length);
  module.HEAPU8.set(cipherData, ctPtr);
  const outLenPtr = module._malloc(4);

  const dataPtr = module._pvac_wasm_make_range_proof(
    ctPtr, cipherData.length,
    Number(value & 0xFFFFFFFFn),
    outLenPtr
  );
  const outLen = module.getValue(outLenPtr, 'i32');
  const result = dataPtr ? new Uint8Array(module.HEAPU8.buffer, dataPtr, outLen).slice() : new Uint8Array(0);

  if (dataPtr) module._pvac_wasm_free(dataPtr);
  module._free(ctPtr);
  module._free(outLenPtr);
  return result;
}

export function ctSub(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (!initialized) throw new Error('PVAC not initialized');
  const aPtr = module._malloc(a.length);
  module.HEAPU8.set(a, aPtr);
  const bPtr = module._malloc(b.length);
  module.HEAPU8.set(b, bPtr);
  const outLenPtr = module._malloc(4);

  const dataPtr = module._pvac_wasm_ct_sub(aPtr, a.length, bPtr, b.length, outLenPtr);
  const outLen = module.getValue(outLenPtr, 'i32');
  const result = dataPtr ? new Uint8Array(module.HEAPU8.buffer, dataPtr, outLen).slice() : new Uint8Array(0);

  if (dataPtr) module._pvac_wasm_free(dataPtr);
  module._free(aPtr);
  module._free(bPtr);
  module._free(outLenPtr);
  return result;
}

export function getPubkey(): Uint8Array {
  if (!initialized) throw new Error('PVAC not initialized');
  const outLenPtr = module._malloc(4);
  const dataPtr = module._pvac_wasm_get_pubkey(outLenPtr);
  const outLen = module.getValue(outLenPtr, 'i32');
  const result = new Uint8Array(module.HEAPU8.buffer, dataPtr, outLen).slice();
  module._pvac_wasm_free(dataPtr);
  module._free(outLenPtr);
  return result;
}

export function getSeckey(): Uint8Array {
  if (!initialized) throw new Error('PVAC not initialized');
  const outLenPtr = module._malloc(4);
  const dataPtr = module._pvac_wasm_get_seckey(outLenPtr);
  const outLen = module.getValue(outLenPtr, 'i32');
  if (!dataPtr || outLen === 0) { module._free(outLenPtr); return new Uint8Array(0); }
  const result = new Uint8Array(module.HEAPU8.buffer, dataPtr, outLen).slice();
  module._pvac_wasm_free(dataPtr);
  module._free(outLenPtr);
  return result;
}

export function getAesKat(): Uint8Array {
  if (!initialized) throw new Error('PVAC not initialized');
  const outPtr = module._malloc(16);
  module._pvac_wasm_aes_kat(outPtr);
  const result = new Uint8Array(module.HEAPU8.buffer, outPtr, 16).slice();
  module._free(outPtr);
  return result;
}

export function commitCt(cipherData: Uint8Array): Uint8Array {
  if (!initialized) throw new Error('PVAC not initialized');
  const ctPtr = module._malloc(cipherData.length);
  module.HEAPU8.set(cipherData, ctPtr);
  const outPtr = module._pvac_wasm_commit_ct(ctPtr, cipherData.length);
  if (!outPtr) {
    module._free(ctPtr);
    throw new Error('commit_ct failed');
  }
  const result = new Uint8Array(module.HEAPU8.buffer, outPtr, 32).slice();
  module._pvac_wasm_free(outPtr);
  module._free(ctPtr);
  return result;
}
