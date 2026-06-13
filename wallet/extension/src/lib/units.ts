/**
 * Unit conversion utilities for OCT amounts.
 * 1 OCT = 1,000,000 raw (micro-OCT).
 */

const DECIMALS = 6;
const MULTIPLIER = 1_000_000n;

/** Parse a human-readable amount string (e.g. "1.5") to raw micro-OCT bigint. */
export function parseAmountRaw(amount: string): bigint {
  if (amount.includes('.')) {
    const [intPart, fracPart] = amount.split('.');
    const frac = (fracPart + '000000').slice(0, DECIMALS);
    return BigInt(intPart) * MULTIPLIER + BigInt(frac);
  }
  return BigInt(amount) * MULTIPLIER;
}

/** Format a raw micro-OCT bigint to a human-readable string (e.g. "1.5"). */
export function formatAmountHuman(raw: bigint): string {
  const whole = raw / MULTIPLIER;
  const frac = raw % MULTIPLIER;
  if (frac === 0n) return `${whole}`;
  return `${whole}.${String(frac).padStart(DECIMALS, '0').replace(/0+$/, '')}`;
}
