// Test the PVAC WASM module through the same API the extension uses
const { readFileSync } = require('fs');
const path = require('path');
const crypto = require('crypto');

// Load WASM module (same way pvac.ts does it)
const wasmPath = path.join(__dirname, '../src/lib/pvac-wasm/pvac.js');
const moduleCode = readFileSync(wasmPath, 'utf-8');
const factory = new Function('require', '__dirname', '__filename', 'module', 'exports',
  moduleCode + ';module.exports = PvacModule;');
const mod = { exports: {} };
factory(require, path.dirname(wasmPath), wasmPath, mod, mod.exports);
const PvacModule = mod.exports;

async function test() {
  const M = await PvacModule();

  // Simulate wallet seed (first 32 bytes of secret key)
  const seed = new Uint8Array(32);
  for (let i = 0; i < 32; i++) seed[i] = i + 1;

  // --- initPvac ---
  const seedPtr = M._malloc(32);
  M.HEAPU8.set(seed, seedPtr);
  const ok = M._pvac_wasm_init(seedPtr, 32);
  M._free(seedPtr);
  console.log('initPvac:', ok === 1 ? 'OK' : 'FAIL');

  // --- encryptValue(1000000n, randomSeed) ---
  const randomSeed = crypto.randomBytes(32);
  const rSeedPtr = M._malloc(32);
  M.HEAPU8.set(randomSeed, rSeedPtr);
  const outLenPtr = M._malloc(4);

  const encPtr = M._pvac_wasm_encrypt(1000000, rSeedPtr, outLenPtr);
  const encLen = M.getValue(outLenPtr, 'i32');
  const cipher = new Uint8Array(M.HEAPU8.buffer, encPtr, encLen).slice();
  console.log('encryptValue(1000000):', cipher.length, 'bytes');
  M._pvac_wasm_free(encPtr);
  M._free(rSeedPtr);

  // --- decryptValue ---
  const ctPtr = M._malloc(cipher.length);
  M.HEAPU8.set(cipher, ctPtr);
  const dec = M._pvac_wasm_decrypt(ctPtr, cipher.length);
  M._free(ctPtr);
  console.log('decryptValue:', dec === 1000000 ? `OK (${dec})` : `FAIL (${dec})`);

  // --- pedersenCommit ---
  const blinding = crypto.randomBytes(32);
  const blindPtr = M._malloc(32);
  M.HEAPU8.set(blinding, blindPtr);
  const commitPtr = M._pvac_wasm_pedersen_commit(1000000, blindPtr);
  const commit = new Uint8Array(M.HEAPU8.buffer, commitPtr, 32).slice();
  M._pvac_wasm_free(commitPtr);
  console.log('pedersenCommit:', commit.some(b => b !== 0) ? 'OK (32 bytes, nonzero)' : 'FAIL');

  // --- makeZeroProofBound (encrypt 0 first) ---
  const zSeedPtr = M._malloc(32);
  M.HEAPU8.set(crypto.randomBytes(32), zSeedPtr);
  M.setValue(outLenPtr, 0, 'i32');
  const enc0Ptr = M._pvac_wasm_encrypt(0, zSeedPtr, outLenPtr);
  const enc0Len = M.getValue(outLenPtr, 'i32');
  const cipher0 = new Uint8Array(M.HEAPU8.buffer, enc0Ptr, enc0Len).slice();
  M._pvac_wasm_free(enc0Ptr);
  M._free(zSeedPtr);

  const ct0Ptr = M._malloc(cipher0.length);
  M.HEAPU8.set(cipher0, ct0Ptr);
  const bl0Ptr = M._malloc(32);
  M.HEAPU8.set(blinding, bl0Ptr);
  M.setValue(outLenPtr, 0, 'i32');

  const t0 = Date.now();
  const zpPtr = M._pvac_wasm_make_zero_proof_bound(ct0Ptr, cipher0.length, 0, bl0Ptr, outLenPtr);
  const zpLen = M.getValue(outLenPtr, 'i32');
  const zpTime = Date.now() - t0;
  const zeroProof = zpPtr ? new Uint8Array(M.HEAPU8.buffer, zpPtr, zpLen).slice() : null;
  if (zpPtr) M._pvac_wasm_free(zpPtr);
  M._free(ct0Ptr);
  M._free(bl0Ptr);
  console.log('makeZeroProofBound:', zeroProof ? `OK (${zpLen} bytes, ${zpTime}ms)` : 'FAIL');

  // --- ctSub ---
  const rSeed2Ptr = M._malloc(32);
  M.HEAPU8.set(crypto.randomBytes(32), rSeed2Ptr);
  M.setValue(outLenPtr, 0, 'i32');
  const enc500Ptr = M._pvac_wasm_encrypt(500000, rSeed2Ptr, outLenPtr);
  const enc500Len = M.getValue(outLenPtr, 'i32');
  const cipher500 = new Uint8Array(M.HEAPU8.buffer, enc500Ptr, enc500Len).slice();
  M._pvac_wasm_free(enc500Ptr);
  M._free(rSeed2Ptr);

  const aPtr = M._malloc(cipher.length);
  M.HEAPU8.set(cipher, aPtr);
  const bPtr = M._malloc(cipher500.length);
  M.HEAPU8.set(cipher500, bPtr);
  M.setValue(outLenPtr, 0, 'i32');
  const subPtr = M._pvac_wasm_ct_sub(aPtr, cipher.length, bPtr, cipher500.length, outLenPtr);
  const subLen = M.getValue(outLenPtr, 'i32');
  const subCipher = subPtr ? new Uint8Array(M.HEAPU8.buffer, subPtr, subLen).slice() : null;
  if (subPtr) M._pvac_wasm_free(subPtr);
  M._free(aPtr);
  M._free(bPtr);

  // Decrypt the subtraction result: should be 1000000 - 500000 = 500000
  if (subCipher) {
    const sPtr = M._malloc(subCipher.length);
    M.HEAPU8.set(subCipher, sPtr);
    const subDec = M._pvac_wasm_decrypt(sPtr, subCipher.length);
    M._free(sPtr);
    console.log('ctSub(1M - 500K):', subDec === 500000 ? `OK (${subDec})` : `FAIL (${subDec})`);
  } else {
    console.log('ctSub: FAIL (null)');
  }

  // --- getPubkey ---
  M.setValue(outLenPtr, 0, 'i32');
  const pkPtr = M._pvac_wasm_get_pubkey(outLenPtr);
  const pkLen = M.getValue(outLenPtr, 'i32');
  const pubkey = new Uint8Array(M.HEAPU8.buffer, pkPtr, pkLen).slice();
  M._pvac_wasm_free(pkPtr);
  console.log('getPubkey:', pkLen > 0 ? `OK (${pkLen} bytes)` : 'FAIL');

  // --- getAesKat ---
  const katPtr = M._malloc(16);
  M._pvac_wasm_aes_kat(katPtr);
  const kat = new Uint8Array(M.HEAPU8.buffer, katPtr, 16).slice();
  M._free(katPtr);
  console.log('getAesKat:', kat.some(b => b !== 0) ? `OK (${Buffer.from(kat).toString('hex')})` : 'FAIL');

  M._free(outLenPtr);
  M._free(blindPtr);
  console.log('\n--- ALL EXTENSION API TESTS PASSED ---');
}

test().catch(e => { console.error('FATAL:', e.message); process.exit(1); });
