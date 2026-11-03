/** Origin-local recovery identity. Storage damage never creates a replacement wallet. */
import { HDKey } from "@scure/bip32";
import { generateMnemonic, mnemonicToSeedSync, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { bech32 } from "@scure/base";
import { hkdf } from "@noble/hashes/hkdf.js";
import { ripemd160 } from "@noble/hashes/legacy.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { identityToRecipient } from "age-encryption";
import canonicalize from "canonicalize";
import { parseStrictEventJson } from "./strictEventJson";
import { scriptAddress } from "./swap/address";
import { NETWORK_NAMES, type NetworkName } from "./swap/config";
import type { RecoveryKey } from "./recoveryKeys";
import { MAX_RECOVERY_CIPHERTEXT_BYTES } from "./recoveryAgeContainer";

export const WALLET_DATABASE = "rillswap-browser-wallet-v1";
export const WALLET_SCHEME = "bip84-rillswap-v1";
const STORE = "identity";
const RECORD = "wallet";
// Historical namespace for opaque checkpoints, including terms. Never evidence of funding.
const SNAPSHOT_PREFIX = "funded:";
const INDEX_LIMIT = 2 ** 31;
const encoder = new TextEncoder();

interface WalletRecord {
  format: "rillswap-browser-wallet";
  version: 1;
  scheme: typeof WALLET_SCHEME;
  mnemonic: string;
  createdAt: number;
  nextIndex: Record<NetworkName, number>;
  backupVerified: boolean;
}

export interface WalletBackup {
  readonly format: "rillswap-browser-recovery";
  readonly version: 1;
  readonly scheme: typeof WALLET_SCHEME;
  readonly mnemonic: string;
}

export interface RefundAllocation {
  readonly version: 1;
  readonly scheme: typeof WALLET_SCHEME;
  readonly identityFingerprint: string;
  readonly network: NetworkName;
  readonly index: number;
  readonly path: string;
  readonly script: string;
  readonly address: string;
}

export class BrowserWalletError extends Error {
  constructor(message = "Browser recovery storage is unavailable or damaged. Keep your existing backups; no replacement key was created.") {
    super(message);
    this.name = "BrowserWalletError";
  }
}

const exactKeys = (value: object, names: readonly string[]): boolean =>
  Object.keys(value).length === names.length && names.every((name) => Object.hasOwn(value, name));
const mnemonicValid = (value: unknown): value is string => typeof value === "string" &&
  value.split(" ").length === 12 && value === value.normalize("NFKD").trim().replace(/\s+/g, " ") && validateMnemonic(value, wordlist);

function validateRecord(value: unknown): WalletRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new BrowserWalletError();
  const record = value as WalletRecord;
  if (!exactKeys(record, ["format", "version", "scheme", "mnemonic", "createdAt", "nextIndex", "backupVerified"]) ||
      record.format !== "rillswap-browser-wallet" || record.version !== 1 || record.scheme !== WALLET_SCHEME ||
      !mnemonicValid(record.mnemonic) || !Number.isSafeInteger(record.createdAt) || record.createdAt < 0 ||
      typeof record.backupVerified !== "boolean" || !record.nextIndex || typeof record.nextIndex !== "object" ||
      !exactKeys(record.nextIndex, NETWORK_NAMES) || NETWORK_NAMES.some((name) =>
        !Number.isSafeInteger(record.nextIndex[name]) || record.nextIndex[name] < 0 || record.nextIndex[name] > INDEX_LIMIT)) {
    throw new BrowserWalletError();
  }
  return record;
}

const backupOf = (record: Pick<WalletRecord, "mnemonic">): WalletBackup => ({
  format: "rillswap-browser-recovery", version: 1, scheme: WALLET_SCHEME, mnemonic: record.mnemonic,
});
const fingerprint = (backup: WalletBackup): string => bytesToHex(sha256(encoder.encode(canonicalize(backup)!)));

/** A matching-backup check is not restoration and carries no counter history. */
export function parseWalletBackup(text: string): WalletBackup {
  try {
    const value = parseStrictEventJson(text, 4096);
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new BrowserWalletError();
    const backup = value as WalletBackup;
    if (!exactKeys(backup, ["format", "version", "scheme", "mnemonic"]) ||
        backup.format !== "rillswap-browser-recovery" || backup.version !== 1 || backup.scheme !== WALLET_SCHEME ||
        !mnemonicValid(backup.mnemonic)) throw new BrowserWalletError();
    return Object.freeze({ ...backup });
  } catch { throw new BrowserWalletError("Invalid recovery-key backup. The current browser key was not changed."); }
}

/** Fixed v1 scheme: 128-bit English mnemonic, NFKD, and an empty BIP39 passphrase. */
export async function walletRecoveryKey(backup: WalletBackup): Promise<RecoveryKey> {
  const validated = parseWalletBackup(canonicalize(backup)!);
  const seed = mnemonicToSeedSync(validated.mnemonic, "");
  const scalar = hkdf(sha256, seed, encoder.encode("RillSwap/browser-recovery/v1"), encoder.encode("age-x25519/v1"), 32);
  try {
    const identity = bech32.encodeFromBytes("AGE-SECRET-KEY-", scalar).toUpperCase();
    const recipient = await identityToRecipient(identity);
    return Object.freeze({ identity, recipient,
      file: encoder.encode(`# RillSwap derived age key. Keep private.\n# public key: ${recipient}\n${identity}\n`),
    });
  } finally { seed.fill(0); scalar.fill(0); }
}

/** Offline decryption key only. Does not restore browser state or reset address counters. */
export function recoveryKeyFromWords(words: string): Promise<RecoveryKey> {
  if (typeof words !== "string" || words.length > 4096) throw new BrowserWalletError("Invalid recovery words");
  return walletRecoveryKey({ format: "rillswap-browser-recovery", version: 1, scheme: WALLET_SCHEME,
    mnemonic: words.normalize("NFKD").trim().replace(/\s+/g, " ") });
}

/** Distinct test-network accounts. Mainnet is standard BIP84 account zero. */
export function refundDerivationPath(network: NetworkName, index: number): string {
  if (!NETWORK_NAMES.includes(network) || !Number.isSafeInteger(index) || index < 0 || index >= INDEX_LIMIT) {
    throw new BrowserWalletError("Recovery address network or index exhausted or invalid");
  }
  const accounts: Record<NetworkName, number> = { mainnet: 0, signet: 0, testnet4: 1, regtest: 2 };
  return `m/84'/${network === "mainnet" ? 0 : 1}'/${accounts[network]}'/0/${index}`;
}

/** Exported for offline recovery; callers must compare the script with signed terms. */
export function deriveRefundKey(backup: WalletBackup, network: NetworkName, index: number): {
  privateKey: Uint8Array; script: string; path: string;
} {
  const validated = parseWalletBackup(canonicalize(backup)!);
  const path = refundDerivationPath(network, index);
  const seed = mnemonicToSeedSync(validated.mnemonic, "");
  const nodes: HDKey[] = [];
  try {
    let node = HDKey.fromMasterSeed(seed); nodes.push(node);
    for (const segment of path.split("/").slice(1)) {
      const child = Number.parseInt(segment, 10) + (segment.endsWith("'") ? INDEX_LIMIT : 0);
      node = node.deriveChild(child); nodes.push(node);
      if (node.index !== child) throw new BrowserWalletError("BIP32 skipped a child; this address allocation was refused");
    }
    if (!node.publicKey || !node.privateKey) throw new BrowserWalletError();
    return { privateKey: Uint8Array.from(node.privateKey), path,
      script: `0014${bytesToHex(ripemd160(sha256(node.publicKey)))}` };
  } finally { seed.fill(0); for (const node of nodes) node.wipePrivateData(); }
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    let denied = false;
    const request = indexedDB.open(WALLET_DATABASE, 1);
    request.onupgradeneeded = (event) => {
      if (event.oldVersion !== 0) { request.transaction?.abort(); return; }
      request.result.createObjectStore(STORE);
    };
    request.onerror = () => reject(new BrowserWalletError());
    request.onblocked = () => { denied = true; reject(new BrowserWalletError("Recovery storage is open in another incompatible tab. Keep existing backups.")); };
    request.onsuccess = () => {
      const db = request.result;
      if (denied) { db.close(); return; }
      if (db.objectStoreNames.length !== 1 || !db.objectStoreNames.contains(STORE)) {
        db.close(); reject(new BrowserWalletError()); return;
      }
      const store = db.transaction(STORE).objectStore(STORE);
      if (store.keyPath !== null || store.autoIncrement || store.indexNames.length !== 0) {
        db.close(); reject(new BrowserWalletError()); return;
      }
      db.onversionchange = () => db.close();
      resolve(db);
    };
  });
}

/** Resolve only after commit, never on a request's intermediate success event. */
function access<T>(db: IDBDatabase, mode: IDBTransactionMode, action: (value: unknown, store: IDBObjectStore) => T): Promise<T> {
  return new Promise((resolve, reject) => {
    let tx: IDBTransaction;
    try { tx = db.transaction(STORE, mode, { durability: mode === "readwrite" ? "strict" : "default" }); }
    catch (error) {
      if (!(error instanceof TypeError)) { reject(new BrowserWalletError()); return; }
      try { tx = db.transaction(STORE, mode); } catch { reject(new BrowserWalletError()); return; }
    }
    let result: T, failure: unknown;
    const request = tx.objectStore(STORE).get(RECORD);
    request.onsuccess = () => {
      try { result = action(request.result, tx.objectStore(STORE)); }
      catch (error) { failure = error; tx.abort(); }
    };
    tx.oncomplete = () => resolve(result);
    tx.onabort = tx.onerror = () => reject(failure instanceof BrowserWalletError ? failure : new BrowserWalletError());
  });
}

export class BrowserRecoveryWallet {
  private constructor(private readonly db: IDBDatabase, readonly newlyCreated: boolean) {}

  static async open(): Promise<BrowserRecoveryWallet> {
    let db: IDBDatabase | undefined;
    try {
      db = await openDatabase();
      const existing = await access(db, "readonly", (value) => value === undefined ? undefined : validateRecord(value));
      let created = false;
      if (existing === undefined) {
        const candidate: WalletRecord = { format: "rillswap-browser-wallet", version: 1, scheme: WALLET_SCHEME,
          mnemonic: generateMnemonic(wordlist, 128), createdAt: Date.now(),
          nextIndex: { mainnet: 0, signet: 0, testnet4: 0, regtest: 0 }, backupVerified: false };
        created = await access(db, "readwrite", (value, store) => {
          if (value !== undefined) { validateRecord(value); return false; }
          // A surviving recovery record proves prior use, not a fresh identity.
          const count = store.count();
          count.onsuccess = () => { if (count.result !== 0) store.transaction.abort(); else store.add(candidate, RECORD); };
          return true;
        });
      }
      await access(db, "readonly", (value) => validateRecord(value));
      return new BrowserRecoveryWallet(db, created);
    } catch (error) {
      db?.close();
      throw error instanceof BrowserWalletError ? error : new BrowserWalletError();
    }
  }

  close(): void { this.db.close(); }

  /** Immutable encrypted terms/funded checkpoint: strict commit and independent exact readback. */
  async saveFundedRecovery(network: NetworkName, ciphertext: Uint8Array): Promise<string> {
    const record = snapshotRecord(network, ciphertext);
    const id = snapshotId(record);
    await snapshotAccess(this.db, "readwrite", (store, done) => {
      const request = store.get(id);
      request.onsuccess = () => {
        try {
          if (request.result === undefined) store.add(record, id);
          else if (!snapshotEqual(validateSnapshot(id, request.result), record)) throw new BrowserWalletError();
          done(undefined);
        } catch { store.transaction.abort(); }
      };
    });
    const saved = await this.readFundedRecovery(id);
    if (!snapshotEqual(saved, record)) throw new BrowserWalletError("Funded recovery readback failed. Keep the download; funding publication was refused.");
    return id;
  }

  async readFundedRecovery(id: string): Promise<FundedRecoverySnapshot> {
    if (!id.startsWith(SNAPSHOT_PREFIX)) throw new BrowserWalletError();
    return snapshotAccess(this.db, "readonly", (store, done) => {
      const request = store.get(id);
      request.onsuccess = () => {
        try { done(validateSnapshot(id, request.result)); } catch { store.transaction.abort(); }
      };
    });
  }

  /** Damaged entries remain present and visible without hiding valid backups. */
  async listFundedRecoveries(): Promise<readonly FundedRecoveryDescriptor[]> {
    return snapshotAccess(this.db, "readonly", (store, done) => {
      const entries: FundedRecoveryDescriptor[] = [];
      const request = store.openCursor(IDBKeyRange.bound(SNAPSHOT_PREFIX, `${SNAPSHOT_PREFIX}\uffff`));
      request.onsuccess = () => {
        const cursor = request.result;
        if (!cursor) { done(entries); return; }
        const id = String(cursor.key);
        try { entries.push({ id, network: validateSnapshot(id, cursor.value).network }); }
        catch { entries.push({ id, error: "Saved recovery is damaged or unsupported. Keep existing backups." }); }
        cursor.continue();
      };
    });
  }

  async info(): Promise<{ fingerprint: string; backupVerified: boolean; recipient: string }> {
    const record = await access(this.db, "readonly", validateRecord);
    const backup = backupOf(record);
    return { fingerprint: fingerprint(backup), backupVerified: record.backupVerified,
      recipient: (await walletRecoveryKey(backup)).recipient };
  }

  async exportBackup(): Promise<Uint8Array> {
    const record = await access(this.db, "readonly", validateRecord);
    return encoder.encode(canonicalize(backupOf(record))!);
  }

  async recoveryKey(): Promise<RecoveryKey> {
    return walletRecoveryKey(backupOf(await access(this.db, "readonly", validateRecord)));
  }

  async verifyBackup(text: string): Promise<void> {
    const backup = parseWalletBackup(text);
    await access(this.db, "readwrite", (value, store) => {
      const record = validateRecord(value);
      if (record.mnemonic !== backup.mnemonic) throw new BrowserWalletError("This backup belongs to a different recovery key. The current key was not changed.");
      store.put({ ...record, backupVerified: true }, RECORD);
    });
  }

  async allocateRefund(network: NetworkName): Promise<RefundAllocation> {
    if (!NETWORK_NAMES.includes(network)) throw new BrowserWalletError("Unsupported recovery address network");
    const allocation = await access(this.db, "readwrite", (value, store) => {
      const record = validateRecord(value), index = record.nextIndex[network];
      if (index >= INDEX_LIMIT) throw new BrowserWalletError("Recovery address index exhausted");
      store.put({ ...record, nextIndex: { ...record.nextIndex, [network]: index + 1 } }, RECORD);
      return { backup: backupOf(record), index };
    });
    const derived = deriveRefundKey(allocation.backup, network, allocation.index);
    derived.privateKey.fill(0);
    return Object.freeze({ version: 1, scheme: WALLET_SCHEME, identityFingerprint: fingerprint(allocation.backup),
      network, index: allocation.index, path: derived.path, script: derived.script, address: scriptAddress(derived.script, network) });
  }
}

export interface FundedRecoverySnapshot {
  readonly version: 1;
  readonly network: NetworkName;
  readonly ciphertext: Uint8Array;
}
export type FundedRecoveryDescriptor = { readonly id: string; readonly network: NetworkName } | { readonly id: string; readonly error: string };

function snapshotRecord(network: NetworkName, ciphertext: Uint8Array): FundedRecoverySnapshot {
  if (!NETWORK_NAMES.includes(network) || !(ciphertext instanceof Uint8Array) || ciphertext.length === 0 ||
      ciphertext.length > MAX_RECOVERY_CIPHERTEXT_BYTES) throw new BrowserWalletError("Funded recovery bytes or network are invalid");
  return { version: 1, network, ciphertext: Uint8Array.from(ciphertext) };
}
const snapshotId = (record: FundedRecoverySnapshot): string => `${SNAPSHOT_PREFIX}${record.network}:${bytesToHex(sha256(record.ciphertext))}`;
function validateSnapshot(id: string, value: unknown): FundedRecoverySnapshot {
  if (!value || typeof value !== "object" || !exactKeys(value, ["version", "network", "ciphertext"])) throw new BrowserWalletError();
  const record = value as FundedRecoverySnapshot;
  if (record.version !== 1) throw new BrowserWalletError();
  const validated = snapshotRecord(record.network, record.ciphertext);
  if (snapshotId(validated) !== id) throw new BrowserWalletError();
  return validated;
}
const snapshotEqual = (a: FundedRecoverySnapshot, b: FundedRecoverySnapshot): boolean => a.version === b.version && a.network === b.network &&
  a.ciphertext.length === b.ciphertext.length && a.ciphertext.every((byte, index) => byte === b.ciphertext[index]);

/** Snapshot authority cannot use the wallet helper's weaker-durability fallback. */
function snapshotAccess<T>(db: IDBDatabase, mode: IDBTransactionMode, action: (store: IDBObjectStore, done: (result: T) => void) => void): Promise<T> {
  return new Promise((resolve, reject) => {
    let tx: IDBTransaction;
    try {
      tx = db.transaction(STORE, mode, { durability: mode === "readwrite" ? "strict" : "default" });
      if (mode === "readwrite" && tx.durability !== "strict") { tx.abort(); throw new BrowserWalletError(); }
    } catch { reject(new BrowserWalletError()); return; }
    let result: T, completed = false;
    tx.oncomplete = () => completed ? resolve(result) : reject(new BrowserWalletError());
    tx.onabort = tx.onerror = () => reject(new BrowserWalletError());
    try { action(tx.objectStore(STORE), (value) => { result = value; completed = true; }); }
    catch { tx.abort(); }
  });
}
