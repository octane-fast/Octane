/**
 * IndexedDB-backed cache for zkTLS proof results.
 * Avoids chrome.storage.local's ~5 MB quota — proofs can be large.
 */

const DB_NAME = 'octane-zktls';
const DB_VERSION = 1;
const STORE_NAME = 'proofs';

export interface CachedZktlsProof {
  id: string;
  result: Record<string, unknown>;
  timestamp: number;
  url: string;
  headers: Record<string, string>;
  origin: string;
}

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      req.result.createObjectStore(STORE_NAME, { keyPath: 'id' });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export async function getCachedProof(id: string): Promise<CachedZktlsProof | null> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const store = tx.objectStore(STORE_NAME);
    const req = store.get(id);
    req.onsuccess = () => resolve(req.result ?? null);
    req.onerror = () => reject(req.error);
  });
}

export async function setCachedProof(entry: CachedZktlsProof): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    const store = tx.objectStore(STORE_NAME);
    store.put(entry);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function getAllCachedProofs(): Promise<CachedZktlsProof[]> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const store = tx.objectStore(STORE_NAME);
    const req = store.getAll();
    req.onsuccess = () => resolve(req.result ?? []);
    req.onerror = () => reject(req.error);
  });
}
