---
name: octra-development
description: 'Develop, compile, deploy, and interact with smart contracts on the Octra blockchain. Use when writing AML contracts, deploying via webcli, calling contract methods, handling OCS-01 tokens, or debugging Octra-specific issues.'
---

# Octra Blockchain Development

## Network

- **RPC**: `https://octra.network/rpc`
- **Version**: v3.0.0-irmin
- **Token units**: 1 OCT = 10^6 raw units (balance_raw)

## AML Language

- Keyword is `contract` (NOT `program` — `program` silently compiles to empty stub)
- File extension: `.aml`
- Types: `int`, `string`, `bool`, `address`, `map[K]V`
- Context builtins: `caller`, `origin`, `self_addr`, `value`, `epoch`
- Other builtins: `ed25519_ok(pk, msg, sig)`, `transfer(addr, amount)`, `concat()`, `to_string()`, `require()`, `emit`
- State declared in `state { }` block
- Events declared with `event Name(field: type, ...)`
- View functions use `view fn` prefix

## ed25519 Verification

**CRITICAL**: Octra's `ed25519_ok(pk, msg, sig)` expects **base64-encoded** public keys and signatures, NOT hex.

- The webcli signs transactions with base64 signatures
- When using ed25519 in contracts, store keys and pass signatures in base64
- Convert hex to base64: `base64.b64encode(binascii.unhexlify(hex_str)).decode()`

## Compilation

- `octra_compileAmlMulti` is BROKEN on the current node (returns 8-instruction stub)
- Use `octra_compileAml` (single-file) — inline interfaces, strip `import` statements
- Compile via direct RPC: `{"method": "octra_compileAml", "params": [source_code]}`

## Webcli

- Binary: `/tmp/webcli/octra_wallet`
- **Must run from `/tmp/webcli/`** (serves `static/` UI relative to binary location)
- Start: `cd /tmp/webcli && ./octra_wallet --port 8420 --data-dir /Users/chriscushman/octra/data`
- RPC: defaults to `https://octra.network/rpc` (hardcoded fallback was patched from old IP)
- UI: `http://127.0.0.1:8420` (only works when started from `/tmp/webcli/`)
- Unlock: `POST /api/wallet/unlock` with `{"file":"data/wallet_EfXCJva6.oct","pin":"123456"}`
- Import wallet: `POST /api/wallet/import` with `{"mnemonic": "...", "pin": "..."}`

### Deploy Contract

```
POST /api/contract/deploy
{
  "bytecode": "<hex from compilation>",
  "params": "<JSON string of constructor args>",  // e.g. "[\"pubkey\", 40151]"
  "ou": "200000"
}
```

- Default ou is 50000000 (too high for most wallets) — always pass `"ou": "200000"`
- Recommended fee from RPC: `octra_recommendedFee("deploy")` → typically 200000

### Call Contract (Write)

```
POST /api/contract/call
{
  "address": "octXXX...",
  "method": "method_name",
  "params": [arg1, arg2, "string_arg"],   // JSON ARRAY, not string!
  "ou": "200000",
  "amount": "0"                           // optional, for payable calls
}
```

**IMPORTANT**: `params` must be a JSON array, NOT a JSON string. Passing a string causes double-escaping.

### Read Contract (View)

```
POST to RPC:
{
  "method": "contract_call",
  "params": ["contract_addr", "method_name", [args], "caller_addr"]
}
```

## OCS-01 Token Standard (ERC20 equivalent)

Required methods: `transfer`, `grant` (approve), `pull` (transferFrom), `balance_of`, `allowance`, `get_name`, `get_symbol`, `get_total_supply`

## Transaction Fees

- `octra_recommendedFee("deploy")` → `{"minimum": "1", "recommended": "200000", "fast": "400000"}`
- `octra_recommendedFee("call")` → similar structure
- Always check recommended fee before deploying

## Common Errors

| Error | Cause | Fix |
|-------|-------|-----|
| "insufficient balance" on deploy | Default ou too high (50M) | Pass `"ou": "200000"` |
| Contract compiles to 8 instructions | Used `program` instead of `contract` | Change keyword to `contract` |
| Empty compilation result | Used `octra_compileAmlMulti` | Use `octra_compileAml` with inlined code |
| "invalid oracle signature" | Passed hex sig/pk to `ed25519_ok` | Convert to base64 |
| Params not reaching contract | Passed params as JSON string | Pass as JSON array |
| bad_commitment (stealth) | Used pedersen_commit for commitment field | Use commit_ct (ciphertext hash) |
| invalid_claim_secret (stealth) | Domain strings don't match node protocol | Use exact strings: OCTRA_STEALTH_TAG_V1, OCTRA_CLAIM_SECRET_V1, OCTRA_CLAIM_BIND_V1 |

## Stealth Protocol

Domain separation strings (must match exactly between all clients and node):
- **Tag**: `"OCTRA_STEALTH_TAG_V1"` — `SHA-256(shared_secret || domain)[0..16]`
- **Claim secret**: `"OCTRA_CLAIM_SECRET_V1"` — `SHA-256(shared_secret || domain)`
- **Claim pub**: `"OCTRA_CLAIM_BIND_V1"` — `SHA-256(claim_secret || recipient_addr || domain)`

Stealth send tx: `op_type="stealth"`, `to_="stealth"`, encrypted_data has tag/ephemeral_pub/claim_pub/cipher/commitment/zero_proof.
Stealth claim tx: `op_type="claim"`, `to_=self_address`, encrypted_data has output_id(integer)/claim_cipher/commitment/claim_secret/zero_proof.

The `commitment` field must be computed via `commit_ct` (ciphertext commitment hash), NOT `pedersen_commit`.
