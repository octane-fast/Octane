import { toBase64 } from './crypto';
import * as vault from './keyVault';

export interface TxFields {
  from: string;
  to: string;
  amount: string;
  nonce: number;
  ou: string;
  opType: string;
  encryptedData?: string;
  message?: string;
}

export interface SignedTx {
  from: string;
  to_: string;
  amount: string;
  nonce: number;
  ou: string;
  timestamp: number;
  op_type: string;
  encrypted_data?: string;
  message?: string;
  signature: string;
  public_key: string;
  [key: string]: unknown;
}

/**
 * Build the canonical JSON string used for transaction signing.
 * Field order must match what the node expects for signature verification.
 */
export function buildCanonical(fields: TxFields, timestamp: number): string {
  const tsStr = timestamp + '.0';
  let canonical = `{"from":"${fields.from}","to_":"${fields.to}","amount":"${fields.amount}","nonce":${fields.nonce},"ou":"${fields.ou}","timestamp":${tsStr},"op_type":"${fields.opType}"`;

  if (fields.encryptedData !== undefined) {
    const escaped = fields.encryptedData.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    canonical += `,"encrypted_data":"${escaped}"`;
  }
  if (fields.message !== undefined) {
    const escaped = fields.message.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    canonical += `,"message":"${escaped}"`;
  }
  canonical += '}';
  return canonical;
}

/**
 * Build a signed transaction payload ready for submission.
 * Handles canonical JSON construction, signing, and payload assembly.
 */
export function buildSignedTx(fields: TxFields): SignedTx {
  const timestamp = Math.floor(Date.now() / 1000);
  const canonical = buildCanonical(fields, timestamp);
  const sig = vault.sign(new TextEncoder().encode(canonical));

  const tx: SignedTx = {
    from: fields.from,
    to_: fields.to,
    amount: fields.amount,
    nonce: fields.nonce,
    ou: fields.ou,
    timestamp,
    op_type: fields.opType,
    signature: toBase64(sig),
    public_key: toBase64(vault.getPublicKey()),
  };

  if (fields.encryptedData !== undefined) {
    tx.encrypted_data = fields.encryptedData;
  }
  if (fields.message !== undefined) {
    tx.message = fields.message;
  }

  return tx;
}
