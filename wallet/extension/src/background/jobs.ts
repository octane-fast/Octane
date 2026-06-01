/**
 * Job definitions for all privacy-preserving transaction types.
 *
 * Each export creates a JobDefinition that the jobRunner executes.
 * All proving logic (routeProof cascade + WASM fallback) lives here,
 * keeping index.ts focused on message routing.
 */

import { toBase64, fromBase64 } from '../lib/crypto';
import * as rpc from '../lib/rpc';
import * as vault from '../lib/keyVault';
import {
  isInitialized, encryptValue, decryptValue,
  pedersenCommit, makeZeroProofBound, makeRangeProof, ctSub, commitCt,
} from '../lib/pvac';
import { route as routeProof } from '../lib/proofRouter';
import { SIG_ENCRYPTED_BALANCE, STEALTH_DATA_VERSION } from '../lib/constants';
import { prepareStealthSend, computeClaimSecret, hexEncode } from '../lib/stealth';
import type { JobDefinition, JobContext } from '../lib/jobRunner';

// ─── Shield (Encrypt) ───────────────────────────────────────────────────────

export function shieldJob(jobId: string, amountRaw: bigint): JobDefinition {
  return {
    jobId,
    async prove(ctx) {
      const result = await routeProof({
        operation: 'shield',
        payload: {
          operation: 'shield',
          amountRaw: String(amountRaw),
          seedB64: toBase64(crypto.getRandomValues(new Uint8Array(32))),
          blindingB64: toBase64(crypto.getRandomValues(new Uint8Array(32))),
        },
        jobId,
        onStatus: (step) => ctx.update({ step }),
        wasm: async () => {
          if (!isInitialized()) await vault.requirePvacKeys();
          const seed = crypto.getRandomValues(new Uint8Array(32));
          const blinding = crypto.getRandomValues(new Uint8Array(32));
          const ct = encryptValue(amountRaw, seed);
          const commitment = pedersenCommit(amountRaw, blinding);
          const zp = makeZeroProofBound(ct, amountRaw, blinding);
          return {
            cipher: 'hfhe_v1|' + toBase64(ct),
            amount_commitment: toBase64(commitment),
            zero_proof: 'zkzp_v2|' + toBase64(zp),
            blinding: toBase64(blinding),
          };
        },
      }) as Record<string, string>;

      return result;
    },
    buildSubmit(_ctx, proveResult) {
      const encData = JSON.stringify({
        cipher: proveResult.cipher,
        amount_commitment: proveResult.amount_commitment,
        zero_proof: proveResult.zero_proof,
        blinding: proveResult.blinding,
      });
      return {
        opType: 'encrypt',
        to: vault.getAddress(),
        amount: String(amountRaw),
        encData,
      };
    },
  };
}

// ─── Unshield (Decrypt) ─────────────────────────────────────────────────────

export function unshieldJob(jobId: string, decAmountRaw: bigint): JobDefinition {
  return {
    jobId,
    async prove(ctx) {
      const address = vault.getAddress();

      await ctx.update({ step: 'Fetching encrypted balance...' });
      const ebMsg = new TextEncoder().encode(`${SIG_ENCRYPTED_BALANCE}|${address}`);
      const ebSig = vault.sign(ebMsg);
      const ebResult = await rpc.getEncryptedBalance(address, toBase64(ebSig), toBase64(vault.getPublicKey())) as Record<string, unknown>;
      const currentCipherStr = String(ebResult?.cipher ?? '');
      if (!currentCipherStr || currentCipherStr === '0') throw new Error('No encrypted balance');
      const currentCipherB64 = currentCipherStr.startsWith('hfhe_v1|') ? currentCipherStr.slice(8) : currentCipherStr;

      const seed = crypto.getRandomValues(new Uint8Array(32));
      const blinding = crypto.getRandomValues(new Uint8Array(32));

      const basePayload: Record<string, string> = {
        operation: 'unshield',
        currentCipherB64,
        decAmountRaw: String(decAmountRaw),
        amountRaw: String(decAmountRaw),
        seedB64: toBase64(seed),
        blindingB64: toBase64(blinding),
      };

      const { skB64, pkB64 } = await vault.requirePvacKeys();
      const payload = { ...basePayload, pvac_sk_b64: skB64, pvac_pk_b64: pkB64, pvacSkB64: skB64, pvacPkB64: pkB64 };

      const result = await routeProof({
        operation: 'unshield',
        payload,
        jobId,
        onStatus: (step, prover) => ctx.update({ step, prover }),
        wasm: async () => {
          if (!isInitialized()) await vault.requirePvacKeys();
          const wSeed = crypto.getRandomValues(new Uint8Array(32));
          const currentCipher = fromBase64(currentCipherB64);
          const ebDecrypted = decryptValue(currentCipher);
          if (ebDecrypted < decAmountRaw) throw new Error(`Insufficient encrypted balance: have ${ebDecrypted}, need ${decAmountRaw}`);
          const ctDelta = encryptValue(decAmountRaw, wSeed);
          const newBalCipher = ctSub(currentCipher, ctDelta);
          const newBalValue = ebDecrypted - decAmountRaw;
          const rpBal = makeRangeProof(newBalCipher, newBalValue);
          const amtCommit = pedersenCommit(decAmountRaw, blinding);
          const zp = makeZeroProofBound(ctDelta, decAmountRaw, blinding);
          const ctCommitment = commitCt(ctDelta);
          return {
            cipher: 'hfhe_v1|' + toBase64(ctDelta),
            commitment: toBase64(ctCommitment),
            amount_commitment: toBase64(amtCommit),
            zero_proof: 'zkzp_v2|' + toBase64(zp),
            blinding: toBase64(blinding),
            range_proof_balance: 'rp_v1|' + toBase64(rpBal),
          };
        },
      }) as Record<string, string>;

      return result;
    },
    buildSubmit(_ctx, proveResult) {
      const encData = JSON.stringify({
        cipher: proveResult.cipher,
        amount_commitment: proveResult.amount_commitment,
        zero_proof: proveResult.zero_proof,
        blinding: proveResult.blinding,
        range_proof_balance: proveResult.range_proof_balance,
        ...(proveResult.range_proof_delta ? { range_proof_delta: proveResult.range_proof_delta } : {}),
        ...(proveResult.commitment ? { commitment: proveResult.commitment } : {}),
      });
      return {
        opType: 'decrypt',
        to: vault.getAddress(),
        amount: String(decAmountRaw),
        encData,
      };
    },
  };
}

// ─── Stealth Send ───────────────────────────────────────────────────────────

export function stealthSendJob(jobId: string, to: string, amountRaw: bigint): JobDefinition {
  return {
    jobId,
    fatalProveErrors: [
      'no public key registered',
      'Invalid recipient public key',
      'invalid amount',
      'Insufficient encrypted balance',
    ],
    async prove(ctx) {
      const address = vault.getAddress();

      // [1] Get recipient's public key
      await ctx.update({ step: 'Fetching recipient public key...' });
      const recipientPkResult = await rpc.getPublicKey(to);
      if (!recipientPkResult.public_key) throw new Error('Recipient has no public key registered — they must make at least one transaction first');
      const theirSigningPk = fromBase64(recipientPkResult.public_key);
      if (theirSigningPk.length !== 32) throw new Error('Invalid recipient public key');

      // [2] ECDH key exchange + stealth envelope
      await ctx.update({ step: 'Key exchange...' });
      const ephSk = crypto.getRandomValues(new Uint8Array(32));
      ephSk[0] &= 248;
      ephSk[31] &= 127;
      ephSk[31] |= 64;
      const blinding = crypto.getRandomValues(new Uint8Array(32));
      const stealth = await prepareStealthSend(theirSigningPk, ephSk, amountRaw, blinding, to);

      // [3] Check encrypted balance
      await ctx.update({ step: 'Checking encrypted balance...' });
      const ebMsg = new TextEncoder().encode(`${SIG_ENCRYPTED_BALANCE}|${address}`);
      const ebSig = vault.sign(ebMsg);
      const ebResult = await rpc.getEncryptedBalance(address, toBase64(ebSig), toBase64(vault.getPublicKey())) as Record<string, unknown>;
      const currentCipherStr = String(ebResult?.cipher ?? '');
      if (!currentCipherStr || currentCipherStr === '0') throw new Error('No encrypted balance available');
      const currentCipherB64 = currentCipherStr.startsWith('hfhe_v1|') ? currentCipherStr.slice(8) : currentCipherStr;

      // [4] Route through prover cascade
      const stealthSeed = crypto.getRandomValues(new Uint8Array(32));
      const stealthPayload: Record<string, string> = {
        operation: 'stealth',
        currentCipherB64,
        amountRaw: String(amountRaw),
        seedB64: toBase64(stealthSeed),
        blindingB64: toBase64(blinding),
      };

      const proverResult = (await routeProof({
        operation: 'stealth',
        payload: stealthPayload,
        jobId,
        onStatus: (step, prover) => ctx.update({ step, prover }),
        wasm: async () => {
          if (!isInitialized()) await vault.requirePvacKeys();
          const seed = crypto.getRandomValues(new Uint8Array(32));
          const ctDelta = encryptValue(amountRaw, seed);
          const amtCommit = pedersenCommit(amountRaw, blinding);
          const sendZkp = makeZeroProofBound(ctDelta, amountRaw, blinding);
          const currentCipher = fromBase64(currentCipherB64);
          const ebDecrypted = decryptValue(currentCipher);
          if (ebDecrypted < amountRaw) throw new Error(`Insufficient encrypted balance: have ${ebDecrypted}, need ${amountRaw}`);
          const newBalCipher = ctSub(currentCipher, ctDelta);
          const newBalValue = ebDecrypted - amountRaw;
          const rpDelta = makeRangeProof(ctDelta, amountRaw);
          const rpBal = makeRangeProof(newBalCipher, newBalValue);
          const ctCommitment = commitCt(ctDelta);
          return {
            cipher: 'hfhe_v1|' + toBase64(ctDelta),
            commitment: toBase64(ctCommitment),
            range_proof_delta: 'rp_v1|' + toBase64(rpDelta),
            range_proof_balance: 'rp_v1|' + toBase64(rpBal),
            amount_commitment: toBase64(amtCommit),
            zero_proof: 'zkzp_v2|' + toBase64(sendZkp),
          };
        },
      }))!;

      // Build stealth data envelope
      const stealthData = JSON.stringify({
        version: STEALTH_DATA_VERSION,
        delta_cipher: proverResult.cipher,
        commitment: proverResult.commitment ?? proverResult.amount_commitment,
        range_proof_delta: proverResult.range_proof_delta,
        range_proof_balance: proverResult.range_proof_balance,
        eph_pub: toBase64(stealth.ephPk),
        stealth_tag: hexEncode(stealth.tag),
        enc_amount: stealth.encAmount,
        claim_pub: hexEncode(stealth.claimPub),
        amount_commitment: proverResult.amount_commitment,
        send_zero_proof: proverResult.zero_proof ?? proverResult.send_zero_proof,
      });

      return { stealthData } as unknown as Record<string, string>;
    },
    buildSubmit(_ctx, proveResult) {
      return {
        opType: 'stealth',
        to: 'stealth',
        amount: '0',
        encData: (proveResult as unknown as { stealthData: string }).stealthData,
      };
    },
  };
}

// ─── Stealth Claim ──────────────────────────────────────────────────────────

export function stealthClaimJob(
  jobId: string,
  outputId: string,
  claimSecret: Uint8Array,
  amount: bigint,
  blinding: Uint8Array,
): JobDefinition {
  return {
    jobId,
    fatalProveErrors: [
      'already claimed',
      'output not found',
      'bad_commitment',
      'invalid signature',
      'bad_claim_secret',
    ],
    async prove(ctx) {
      const claimSeed = crypto.getRandomValues(new Uint8Array(32));
      const claimPayload: Record<string, string> = {
        operation: 'claim',
        amountRaw: String(amount),
        seedB64: toBase64(claimSeed),
        blindingB64: toBase64(blinding),
      };

      const proverResult = (await routeProof({
        operation: 'claim',
        payload: claimPayload,
        jobId,
        onStatus: (step, prover) => ctx.update({ step, prover }),
        wasm: async () => {
          if (!isInitialized()) await vault.requirePvacKeys();
          const seed = crypto.getRandomValues(new Uint8Array(32));
          const ctClaim = encryptValue(amount, seed);
          const ctCommitment = commitCt(ctClaim);
          const zpBytes = makeZeroProofBound(ctClaim, amount, blinding);
          return {
            cipher: 'hfhe_v1|' + toBase64(ctClaim),
            commitment: toBase64(ctCommitment),
            zero_proof: 'zkzp_v2|' + toBase64(zpBytes),
          };
        },
      }))!;

      const claimData = JSON.stringify({
        version: STEALTH_DATA_VERSION,
        output_id: Number(outputId),
        claim_cipher: proverResult.cipher,
        commitment: proverResult.commitment ?? proverResult.amount_commitment,
        claim_secret: hexEncode(claimSecret),
        zero_proof: proverResult.zero_proof,
      });

      return { claimData } as unknown as Record<string, string>;
    },
    buildSubmit(_ctx, proveResult) {
      return {
        opType: 'claim',
        to: vault.getAddress(),
        amount: '0',
        encData: (proveResult as unknown as { claimData: string }).claimData,
        fatalErrors: [
          'already claimed',
          'output not found',
          'bad_commitment',
          'invalid signature',
          'bad_claim_secret',
        ],
      };
    },
  };
}
