/**
 * Shared constants for the Octane wallet extension.
 */

// ─── Timeouts ───────────────────────────────────────────────────────────────

/**
 * Maximum time (ms) a dApp request can wait for a response.
 * Covers the full round trip: approval popup → user action → background processing → response.
 * If the user doesn't approve or the operation doesn't complete within this window,
 * the dApp receives a "Request timed out" error.
 */
export const DAPP_REQUEST_TIMEOUT_MS = 180_000; // 3 minutes

// ─── Network ────────────────────────────────────────────────────────────────

/** SOCKS5 port used by the Tor proxy (Tor Browser default). */
export const TOR_SOCKS_PORT = 9150;

/** Default transaction fee in raw units (used when caller doesn't specify). */
export const DEFAULT_FEE = '10000';

/** Stealth/claim envelope version used by the node for parsing. */
export const STEALTH_DATA_VERSION = 5;

// ─── Feature Flags ──────────────────────────────────────────────────────────

/** Enable Tor proxy routing for RPC requests to octra.network. */
export const FEATURE_TOR = true;

// ─── Job Statuses ───────────────────────────────────────────────────────────

export const JOB_STATUS_DONE = 'done';
export const JOB_STATUS_ERROR = 'error';
export const JOB_STATUS_CANCELLED = 'cancelled';
export const JOB_STATUS_RUNNING = 'running';
export const JOB_STATUS_CRYPTO_DONE = 'crypto_done';
export const JOB_STATUS_PENDING_UNLOCK = 'pending_unlock';

// ─── Job Key Convention ─────────────────────────────────────────────────────

export const JOB_PREFIX = 'job_';
export const JOB_SUFFIX_CRYPTO = '_crypto';
export const JOB_SUFFIX_PARAMS = '_params';
export const JOB_SUFFIX_STEALTH = '_stealth';
export const JOB_SUFFIX_STEALTH_PARAMS = '_stealth_params';
export const JOB_SUFFIX_CLAIM = '_claim';
export const JOB_DEFAULT_CLEANUP_DELAY_MS = 30_000;

// ─── Popup Paths ────────────────────────────────────────────────────────────

export const POPUP_UNLOCK_PATH = 'dist/src/popup/index.html?unlock=dapp';
export const POPUP_CONFIRM_PATH = 'dist/src/popup/confirm.html';

/** Unlock popup window dimensions. */
export const POPUP_UNLOCK_WIDTH = 380;
export const POPUP_UNLOCK_HEIGHT = 540;

/** Approval/confirm popup window dimensions. */
export const POPUP_CONFIRM_WIDTH = 400;
export const POPUP_CONFIRM_HEIGHT = 420;

/** Timeout (ms) for user to respond to unlock/approval prompts (2 minutes). */
export const APPROVAL_TIMEOUT_MS = 120_000;

// ─── Approval Types ─────────────────────────────────────────────────────────

export const APPROVAL_CONNECT = 'connect' as const;
export const APPROVAL_SIGN_MESSAGE = 'sign_message' as const;
export const APPROVAL_SEND_TX = 'send_transaction' as const;
export const APPROVAL_CALL_CONTRACT = 'call_contract' as const;
export const APPROVAL_PVAC_DECRYPT = 'pvac_decrypt' as const;
export const APPROVAL_PVAC_PROVE = 'pvac_prove' as const;

// ─── Message Types (internal chrome.runtime messages) ───────────────────────

export const MSG_APPROVAL_RESPONSE = 'APPROVAL_RESPONSE' as const;
export const MSG_UNLOCK = 'UNLOCK' as const;
export const MSG_LOCK = 'LOCK' as const;
export const MSG_SET_TOR = 'SET_TOR' as const;
export const MSG_SET_RPC_URL = 'SET_RPC_URL' as const;
export const MSG_GET_RPC_URL = 'GET_RPC_URL' as const;
export const MSG_IS_UNLOCKED = 'IS_UNLOCKED' as const;
export const MSG_SWITCH_ACCOUNT = 'SWITCH_ACCOUNT' as const;
export const MSG_GET_ACCOUNTS = 'GET_ACCOUNTS' as const;
export const MSG_ADD_ACCOUNT = 'ADD_ACCOUNT' as const;
export const MSG_GET_ADDRESS = 'GET_ADDRESS' as const;
export const MSG_CHECK_STEALTH_READY = 'CHECK_STEALTH_READY' as const;
export const MSG_DERIVE_PVAC_KEYS = 'DERIVE_PVAC_KEYS' as const;
export const MSG_GET_BALANCE = 'GET_BALANCE' as const;
export const MSG_GET_TOKENS = 'GET_TOKENS' as const;
export const MSG_GET_ENCRYPTED_BALANCE = 'GET_ENCRYPTED_BALANCE' as const;
export const MSG_GET_DECRYPTED_BALANCE = 'GET_DECRYPTED_BALANCE' as const;
export const MSG_ENCRYPT_BALANCE = 'ENCRYPT_BALANCE' as const;
export const MSG_DECRYPT_BALANCE = 'DECRYPT_BALANCE' as const;
export const MSG_GET_JOB_STATUS = 'GET_JOB_STATUS' as const;
export const MSG_CANCEL_UNSHIELD = 'CANCEL_UNSHIELD' as const;
export const MSG_CANCEL_JOB = 'CANCEL_JOB' as const;
export const MSG_SIGN_MESSAGE = 'SIGN_MESSAGE' as const;
export const MSG_SEND_TRANSACTION = 'SEND_TRANSACTION' as const;
export const MSG_CONTRACT_CALL = 'CONTRACT_CALL' as const;
export const MSG_SWAP_OCTUSD = 'SWAP_OCTUSD' as const;
export const MSG_GET_ACTIVITY = 'GET_ACTIVITY' as const;
export const MSG_DAPP_REQUEST = 'DAPP_REQUEST' as const;
export const MSG_RPC_PASSTHROUGH = 'RPC_PASSTHROUGH' as const;
export const MSG_STEALTH_SEND = 'STEALTH_SEND' as const;
export const MSG_STEALTH_SCAN = 'STEALTH_SCAN' as const;
export const MSG_STEALTH_CLAIM = 'STEALTH_CLAIM' as const;
export const MSG_IMPORT_PAIRING = 'IMPORT_PAIRING' as const;
export const MSG_REMOVE_PAIRING = 'REMOVE_PAIRING' as const;
export const MSG_GET_PROVER_STATUS = 'GET_PROVER_STATUS' as const;
export const MSG_SET_PROVER_MODE = 'SET_PROVER_MODE' as const;
export const MSG_FETCH_CIRCLE_ASSET = 'FETCH_CIRCLE_ASSET' as const;
export const MSG_GET_NFT_CONTENT = 'GET_NFT_CONTENT' as const;

// ─── Offscreen Actions ──────────────────────────────────────────────────────

export const ACTION_INIT = 'init' as const;
export const ACTION_DECRYPT = 'decrypt' as const;
export const ACTION_COMPUTE_UNSHIELD = 'computeUnshield' as const;
export const ACTION_WARMUP = 'warmup' as const;
export const ACTION_PING = 'ping' as const;
export const ACTION_CRYPTO_COMPLETE = 'cryptoComplete' as const;
export const ACTION_CRYPTO_ERROR = 'cryptoError' as const;

// ─── Storage Keys ───────────────────────────────────────────────────────────

export const SK_APPROVAL_PREFIX = 'approval_';
export const SK_JOB_PREFIX = 'job_';

export const SK_TOR_ENABLED = 'torEnabled';
export const SK_RPC_URL = 'rpcUrl';
export const SK_PROVER_MODE = 'proverMode';
export const SK_PAIRING_CONFIG = 'pairingConfig';
export const SK_PROVER_REC_DISMISSED = 'proverRecDismissed';
export const SK_ACTIVE_UNSHIELD_JOB = 'activeUnshieldJob';
export const SK_ACTIVE_UNSHIELD_START = 'activeUnshieldStart';
export const SK_ACTIVE_UNSHIELD_AMOUNT = 'activeUnshieldAmount';
export const SK_ACTIVE_SHIELD_JOB = 'activeShieldJob';
export const SK_ACTIVE_SHIELD_START = 'activeShieldStart';
export const SK_ACTIVE_SHIELD_AMOUNT = 'activeShieldAmount';
export const SK_ACTIVE_STEALTH_JOB = 'activeStealthJob';
export const SK_ACTIVE_STEALTH_START = 'activeStealthStart';
export const SK_ACTIVE_CLAIM_JOB = 'activeClaimJob';
export const SK_ACTIVE_CLAIM_START = 'activeClaimStart';
export const SK_ACTIVE_CLAIM_AMOUNT = 'activeClaimAmount';
export const SK_STEALTH_LAST_EPOCH = 'stealthLastEpoch_';  // + address
export const SK_STEALTH_PENDING = 'stealthPending_';        // + address
export const SK_STEALTH_CLAIMED = 'stealthClaimed_';        // + address (ids of claimed outputs)

// Fee override keys (stored as string micro-OCT values, empty = use recommended)
export const SK_FEE_DEFAULT = 'feeOverride_default';
export const SK_FEE_ENCRYPT = 'feeOverride_encrypt';
export const SK_FEE_DECRYPT = 'feeOverride_decrypt';
export const SK_FEE_STEALTH = 'feeOverride_stealth';
export const SK_FEE_CLAIM = 'feeOverride_claim';

// ─── Error Strings ──────────────────────────────────────────────────────────

export const ERR_LOCKED = 'locked';
export const ERR_WALLET_LOCKED = 'Wallet is locked';
export const ERR_NO_WALLET = 'no wallet';
export const ERR_INVALID_AMOUNT = 'invalid amount';
export const ERR_MISSING_VALUE = 'missing value';
export const ERR_USER_REJECTED_CONNECTION = 'User rejected connection';
export const ERR_USER_REJECTED_SIGNATURE = 'User rejected signature request';
export const ERR_USER_REJECTED_TX = 'User rejected transaction';
export const ERR_USER_REJECTED_CONTRACT = 'User rejected contract call';
export const ERR_USER_REJECTED_REQUEST = 'User rejected request';
export const ERR_USER_REJECTED_DECRYPT = 'User rejected decrypt request';
export const ERR_RECIPIENT_NO_PVAC = 'recipient_no_pvac';
export const ERR_INVALID_CALLDATA = 'Invalid contract call data';
export const ERR_MISSING_CIPHERTEXT = 'Missing ciphertext';

// ─── Network Info ───────────────────────────────────────────────────────────

export interface NetworkInfo {
  id: string;
  name: string;
  rpcUrl: string;
  explorerUrl: string;
  supportsPrivacy: boolean;
  isTestnet: boolean;
  color: string;
}

export function getNetworkInfo(rpcUrl: string): NetworkInfo {
  if (rpcUrl.includes('devnet')) {
    return {
      id: 'devnet',
      name: 'Octra Devnet',
      rpcUrl,
      explorerUrl: 'https://devnet.octrascan.io',
      supportsPrivacy: true,
      isTestnet: true,
      color: '#f59e0b',
    };
  }
  return {
    id: 'mainnet',
    name: 'Octra Mainnet',
    rpcUrl,
    explorerUrl: 'https://octrascan.io',
    supportsPrivacy: true,
    isTestnet: false,
    color: '#6366f1',
  };
}

// ─── RPC Signing Prefixes ───────────────────────────────────────────────────

export const SIG_ENCRYPTED_BALANCE = 'octra_encryptedBalance';
