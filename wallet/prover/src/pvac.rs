//! FFI bindings to the PVAC C API (compiled natively via build.rs)

#![allow(non_camel_case_types)]

use std::ptr;
use std::slice;

// Opaque handles
pub type pvac_params = *mut std::ffi::c_void;
pub type pvac_pubkey = *mut std::ffi::c_void;
pub type pvac_seckey = *mut std::ffi::c_void;
pub type pvac_cipher = *mut std::ffi::c_void;
pub type pvac_zero_proof = *mut std::ffi::c_void;
pub type pvac_range_proof = *mut std::ffi::c_void;

extern "C" {
    pub fn pvac_default_params() -> pvac_params;
    pub fn pvac_keygen_from_seed(
        prm: pvac_params,
        seed: *const u8,
        pk_out: *mut pvac_pubkey,
        sk_out: *mut pvac_seckey,
    );
    pub fn pvac_enc_value_seeded(
        pk: pvac_pubkey,
        sk: pvac_seckey,
        val: u64,
        seed: *const u8,
    ) -> pvac_cipher;
    pub fn pvac_dec_value(pk: pvac_pubkey, sk: pvac_seckey, ct: pvac_cipher) -> u64;
    pub fn pvac_ct_sub(pk: pvac_pubkey, a: pvac_cipher, b: pvac_cipher) -> pvac_cipher;
    pub fn pvac_pedersen_commit(amount: u64, blinding: *const u8, out: *mut u8);
    pub fn pvac_make_zero_proof_bound(
        pk: pvac_pubkey,
        sk: pvac_seckey,
        ct: pvac_cipher,
        amount: u64,
        blinding: *const u8,
    ) -> pvac_zero_proof;
    pub fn pvac_make_range_proof(
        pk: pvac_pubkey,
        sk: pvac_seckey,
        ct: pvac_cipher,
        value: u64,
    ) -> pvac_range_proof;

    pub fn pvac_serialize_cipher(ct: pvac_cipher, len: *mut usize) -> *mut u8;
    pub fn pvac_deserialize_cipher(data: *const u8, len: usize) -> pvac_cipher;
    pub fn pvac_serialize_zero_proof(zp: pvac_zero_proof, len: *mut usize) -> *mut u8;
    pub fn pvac_serialize_range_proof(rp: pvac_range_proof, len: *mut usize) -> *mut u8;

    pub fn pvac_free_params(p: pvac_params);
    pub fn pvac_free_pubkey(p: pvac_pubkey);
    pub fn pvac_free_seckey(p: pvac_seckey);
    pub fn pvac_free_cipher(p: pvac_cipher);
    pub fn pvac_free_zero_proof(p: pvac_zero_proof);
    pub fn pvac_free_range_proof(p: pvac_range_proof);
    pub fn pvac_commit_ct(pk: pvac_pubkey, ct: pvac_cipher, out: *mut u8);
    pub fn pvac_free_bytes(buf: *mut u8);
}

/// Safe wrapper around PVAC operations
pub struct PvacContext {
    params: pvac_params,
    pk: pvac_pubkey,
    sk: pvac_seckey,
}

unsafe impl Send for PvacContext {}
unsafe impl Sync for PvacContext {}

impl PvacContext {
    pub fn new(seed: &[u8; 32]) -> Option<Self> {
        unsafe {
            let params = pvac_default_params();
            if params.is_null() {
                return None;
            }
            let mut pk: pvac_pubkey = ptr::null_mut();
            let mut sk: pvac_seckey = ptr::null_mut();
            pvac_keygen_from_seed(params, seed.as_ptr(), &mut pk, &mut sk);
            if pk.is_null() || sk.is_null() {
                pvac_free_params(params);
                return None;
            }
            Some(Self { params, pk, sk })
        }
    }

    pub fn decrypt(&self, cipher_bytes: &[u8]) -> u64 {
        unsafe {
            let ct = pvac_deserialize_cipher(cipher_bytes.as_ptr(), cipher_bytes.len());
            if ct.is_null() {
                return 0;
            }
            let val = pvac_dec_value(self.pk, self.sk, ct);
            pvac_free_cipher(ct);
            val
        }
    }

    pub fn encrypt(&self, amount: u64, seed: &[u8; 32]) -> Vec<u8> {
        unsafe {
            let ct = pvac_enc_value_seeded(self.pk, self.sk, amount, seed.as_ptr());
            let mut len: usize = 0;
            let data = pvac_serialize_cipher(ct, &mut len);
            let result = slice::from_raw_parts(data, len).to_vec();
            pvac_free_bytes(data);
            pvac_free_cipher(ct);
            result
        }
    }

    pub fn pedersen_commit(&self, amount: u64, blinding: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        unsafe {
            pvac_pedersen_commit(amount, blinding.as_ptr(), out.as_mut_ptr());
        }
        out
    }

    pub fn make_zero_proof_bound(
        &self,
        cipher_bytes: &[u8],
        amount: u64,
        blinding: &[u8; 32],
    ) -> Option<Vec<u8>> {
        unsafe {
            let ct = pvac_deserialize_cipher(cipher_bytes.as_ptr(), cipher_bytes.len());
            if ct.is_null() {
                return None;
            }
            let zp = pvac_make_zero_proof_bound(self.pk, self.sk, ct, amount, blinding.as_ptr());
            pvac_free_cipher(ct);
            if zp.is_null() {
                return None;
            }
            let mut len: usize = 0;
            let data = pvac_serialize_zero_proof(zp, &mut len);
            let result = slice::from_raw_parts(data, len).to_vec();
            pvac_free_bytes(data);
            pvac_free_zero_proof(zp);
            Some(result)
        }
    }

    pub fn ct_sub(&self, a_bytes: &[u8], b_bytes: &[u8]) -> Option<Vec<u8>> {
        unsafe {
            let a = pvac_deserialize_cipher(a_bytes.as_ptr(), a_bytes.len());
            let b = pvac_deserialize_cipher(b_bytes.as_ptr(), b_bytes.len());
            if a.is_null() || b.is_null() {
                if !a.is_null() { pvac_free_cipher(a); }
                if !b.is_null() { pvac_free_cipher(b); }
                return None;
            }
            let result_ct = pvac_ct_sub(self.pk, a, b);
            pvac_free_cipher(a);
            pvac_free_cipher(b);
            if result_ct.is_null() {
                return None;
            }
            let mut len: usize = 0;
            let data = pvac_serialize_cipher(result_ct, &mut len);
            let result = slice::from_raw_parts(data, len).to_vec();
            pvac_free_bytes(data);
            pvac_free_cipher(result_ct);
            Some(result)
        }
    }

    pub fn make_range_proof(&self, cipher_bytes: &[u8], value: u64) -> Option<Vec<u8>> {
        unsafe {
            let ct = pvac_deserialize_cipher(cipher_bytes.as_ptr(), cipher_bytes.len());
            if ct.is_null() {
                return None;
            }
            let rp = pvac_make_range_proof(self.pk, self.sk, ct, value);
            pvac_free_cipher(ct);
            if rp.is_null() {
                return None;
            }
            let mut len: usize = 0;
            let data = pvac_serialize_range_proof(rp, &mut len);
            let result = slice::from_raw_parts(data, len).to_vec();
            pvac_free_bytes(data);
            pvac_free_range_proof(rp);
            Some(result)
        }
    }

    pub fn commit_ct(&self, cipher_bytes: &[u8]) -> Option<[u8; 32]> {
        unsafe {
            let ct = pvac_deserialize_cipher(cipher_bytes.as_ptr(), cipher_bytes.len());
            if ct.is_null() {
                return None;
            }
            let mut out = [0u8; 32];
            pvac_commit_ct(self.pk, ct, out.as_mut_ptr());
            pvac_free_cipher(ct);
            Some(out)
        }
    }
}

impl Drop for PvacContext {
    fn drop(&mut self) {
        unsafe {
            pvac_free_seckey(self.sk);
            pvac_free_pubkey(self.pk);
            pvac_free_params(self.params);
        }
    }
}
