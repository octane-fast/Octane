const { readFileSync } = require('fs');
const path = require('path');
const moduleCode = readFileSync(path.join(__dirname, 'pvac.js'), 'utf-8');
const factory = new Function('require', '__dirname', '__filename', 'module', 'exports', moduleCode + ';module.exports = PvacModule;');
const mod = { exports: {} }; factory(require, __dirname, __filename, mod, mod.exports);
const PvacModule = mod.exports;

async function test() {
  const M = await PvacModule();
  const seed = new Uint8Array(32);
  for (let i = 0; i < 32; i++) seed[i] = i + 1;
  const sPtr = M._malloc(32);
  M.HEAPU8.set(seed, sPtr);
  M._pvac_wasm_init(sPtr, 32);
  M._free(sPtr);
  console.log('Heap size:', M.HEAPU8.length, '(' + (M.HEAPU8.length / 1024 / 1024) + ' MB)');

  // Allocate an int for out_len
  const outLenPtr = M._malloc(4);

  // Test prove (all gate counts)
  console.log('Testing prove...');
  const r = M._pvac_wasm_test_prove();
  console.log('test_prove result:', r);

  // Test zero proof
  console.log('\nTesting make_zero_proof_bound...');
  // encrypt(value=0, seed=NULL, out_len)
  M.setValue(outLenPtr, 0, 'i32');
  const encBuf = M._pvac_wasm_encrypt(0, 0, outLenPtr);
  const eLen = M.getValue(outLenPtr, 'i32');
  if (encBuf === 0) { console.log('encrypt returned null'); return; }
  console.log('Ciphertext length:', eLen);

  // make_zero_proof_bound(cipher_data, cipher_len, amount, blinding, out_len)
  // For zero proof, amount=0, blinding=NULL (will use internal)
  M.setValue(outLenPtr, 0, 'i32');
  const start = Date.now();
  const proofPtr = M._pvac_wasm_make_zero_proof_bound(encBuf, eLen, 0, 0, outLenPtr);
  const elapsed = Date.now() - start;
  const pLen = M.getValue(outLenPtr, 'i32');
  if (proofPtr !== 0) {
    console.log('Zero proof length:', pLen, 'bytes, took', elapsed, 'ms');
    M._pvac_wasm_free(proofPtr);
  } else {
    console.log('Zero proof FAILED (returned null)');
  }
  M._pvac_wasm_free(encBuf);

  // Test range proof
  console.log('\nTesting make_range_proof (value=1000000)...');
  M.setValue(outLenPtr, 0, 'i32');
  const encBuf2 = M._pvac_wasm_encrypt(1000000, 0, outLenPtr);
  const eLen2 = M.getValue(outLenPtr, 'i32');
  if (encBuf2 === 0) { console.log('encrypt returned null'); return; }
  console.log('Ciphertext length:', eLen2);

  // make_range_proof(cipher_data, cipher_len, value, out_len)
  M.setValue(outLenPtr, 0, 'i32');
  const start2 = Date.now();
  const rpPtr = M._pvac_wasm_make_range_proof(encBuf2, eLen2, 1000000, outLenPtr);
  const elapsed2 = Date.now() - start2;
  const rpLen = M.getValue(outLenPtr, 'i32');
  if (rpPtr !== 0) {
    console.log('Range proof length:', rpLen, 'bytes, took', elapsed2, 'ms');
    M._pvac_wasm_free(rpPtr);
  } else {
    console.log('Range proof FAILED (returned null)');
  }
  M._pvac_wasm_free(encBuf2);

  M._free(outLenPtr);
  console.log('\nAll tests complete.');
}

test().catch(e => { console.error('FAIL:', e.message); process.exit(1); });
