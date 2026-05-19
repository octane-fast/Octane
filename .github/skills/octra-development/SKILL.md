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
- Start: `octra_wallet --port 8420 --rpc http://46.101.86.250:8080/rpc`
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
