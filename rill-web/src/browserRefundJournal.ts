/**
 * Immutable, origin-local refund intents. No secrets, networking, signing,
 * startup actions, automatic retries, or repair. Signed bytes are spending
 * capabilities. Reauthorize them against the recovery file before exposure.
 */
import canonicalize from "canonicalize";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { isSupportedRecoveryNetwork, type ConstructedRecoveryRefund } from "./recoveryInspection";
import { validateMempoolApi, type NetworkName } from "./swap/config";
import { MAX_TRANSACTION_BYTES, parseRecoveryFundingTransaction, parseTransaction, serializeTransaction } from "./swap/transaction";

const DATABASE = "rillswap-refund-submissions";
const STORE = "intents";
const HEX32 = /^[0-9a-f]{64}$/;
const encoder = new TextEncoder();
const MAX_SATS = 2100000000000000n;

export type RefundSubmissionState = "prepared" | "submission-unknown" | "accepted";
interface RefundJournalCommon {
  readonly networkIdentity: unknown;
  readonly api: string;
  readonly broadcastApi: string;
  /** Public transaction bytes, retained for offline reauthorization, never UTXO proof. */
  readonly rawFundingTransactionHex: string;
  readonly refund: ConstructedRecoveryRefund;
}

/** Legacy records retain their exact shape; independent selections never invent revision metadata. */
export type RefundJournalDraft = RefundJournalCommon & (
  { readonly fundingAttemptId: string; readonly bindingRevision: number } | { readonly selection: "outpoint" }
);

export type RefundJournalRecord = RefundJournalDraft & {
  readonly id: string;
  readonly signedDigest: string;
  readonly createdAt: number;
  readonly updatedAt: number;
  readonly state: RefundSubmissionState;
};

export class RefundJournalRefusedError extends Error {
  constructor() {
    super("Refund intent storage could not be verified. Keep your backups; no intent was replaced or retried.");
    this.name = "RefundJournalRefusedError";
  }
}

function require(condition: boolean): void { if (!condition) throw new RefundJournalRefusedError(); }
function object(value: unknown, fields: readonly string[]): Record<string, unknown> {
  require(value !== null && typeof value === "object" && !Array.isArray(value));
  const result = value as Record<string, unknown>;
  require(Object.keys(result).length === fields.length && fields.every((field) => Object.hasOwn(result, field)));
  return result;
}
function hex(value: unknown, min: number, max: number): string {
  require(typeof value === "string" && value.length >= min * 2 && value.length <= max * 2 && /^(?:[0-9a-f]{2})+$/.test(value));
  return value as string;
}
function sats(value: unknown): bigint {
  require(typeof value === "string" && /^(0|[1-9][0-9]{0,15})$/.test(value));
  const amount = BigInt(value as string); require(amount <= MAX_SATS); return amount;
}
const integer = (value: unknown, min: number, max: number): boolean => typeof value === "number" && Number.isSafeInteger(value) && value >= min && value <= max;

function snapshotNetwork(value: unknown): Record<string, unknown> {
  const network = JSON.parse(canonicalize(value)!) as Record<string, unknown>;
  require(isSupportedRecoveryNetwork(network));
  return Object.freeze(network);
}

function recordId(network: unknown, txid: string, vout: number): string {
  require(HEX32.test(txid) && integer(vout, 0, 0xffffffff));
  return bytesToHex(sha256(encoder.encode(canonicalize({ networkIdentity: network, txid, vout })!)));
}

/** Integrity checks only, not ownership, UTXO evidence, or signature authorization. */
function draftSnapshot(value: unknown): RefundJournalDraft {
  const draft = object(value, draftFields(value));
  const networkIdentity = snapshotNetwork(draft.networkIdentity);
  require(typeof draft.api === "string");
  const api = validateMempoolApi(draft.api as string, networkIdentity.name as NetworkName);
  require(api === draft.api);
  require(typeof draft.broadcastApi === "string");
  const broadcastApi = validateMempoolApi(draft.broadcastApi as string, networkIdentity.name as NetworkName);
  require(broadcastApi === draft.broadcastApi);
  let selector: { readonly selection: "outpoint" } | { readonly fundingAttemptId: string; readonly bindingRevision: number };
  if (Object.hasOwn(draft, "selection")) {
    require(draft.selection === "outpoint"); selector = { selection: "outpoint" };
  } else {
    require(typeof draft.fundingAttemptId === "string" && HEX32.test(draft.fundingAttemptId));
    require(integer(draft.bindingRevision, 0, 63));
    selector = { fundingAttemptId: draft.fundingAttemptId as string, bindingRevision: draft.bindingRevision as number };
  }
  const data = object(draft.refund, ["transactionHex", "txid", "contractHash", "fundingTxid", "fundingVout", "destinationScript", "refundLockHeight", "feeSat", "outputValueSat", "vsize"]);
  const transactionHex = hex(data.transactionHex, 60, MAX_TRANSACTION_BYTES);
  const transaction = parseTransaction(hexToBytes(transactionHex));
  require(data.txid === transaction.txid && typeof data.contractHash === "string" && HEX32.test(data.contractHash));
  require(typeof data.fundingTxid === "string" && HEX32.test(data.fundingTxid) && integer(data.fundingVout, 0, 0xffffffff));
  require(integer(data.refundLockHeight, 1, 499999999) && transaction.locktime === data.refundLockHeight);
  require(transaction.inputs.length === 1 && transaction.outputs.length === 1);
  const input = transaction.inputs[0]!, output = transaction.outputs[0]!;
  require(input.txid === data.fundingTxid && input.vout === data.fundingVout && input.sequence === 0xfffffffd && input.scriptSig.length === 0);
  require(input.witness.length === 3 && input.witness[0]!.length === 64 && input.witness[2]!.length === 65);
  const destinationScript = hex(data.destinationScript, 22, 34);
  require(/^(0014[0-9a-f]{40}|5120[0-9a-f]{64})$/.test(destinationScript) && bytesToHex(output.script) === destinationScript);
  const fee = sats(data.feeSat), outputValue = sats(data.outputValueSat);
  require(output.value === outputValue && outputValue >= (output.script.length === 22 ? 294n : 330n));
  const baseSize = serializeTransaction(transaction, false).length;
  require(data.vsize === Math.ceil((baseSize * 3 + transaction.raw.length) / 4));
  const rawFundingTransactionHex = hex(draft.rawFundingTransactionHex, 60, MAX_TRANSACTION_BYTES);
  const funding = ("selection" in selector ? parseRecoveryFundingTransaction : parseTransaction)(hexToBytes(rawFundingTransactionHex));
  require(funding.txid === data.fundingTxid);
  const prevout = funding.outputs[data.fundingVout as number];
  require(prevout !== undefined && prevout.value === fee + outputValue && /^5120[0-9a-f]{64}$/.test(bytesToHex(prevout.script)));
  const refund = Object.freeze({ transactionHex, txid: data.txid as string, contractHash: data.contractHash as string,
    fundingTxid: data.fundingTxid as string, fundingVout: data.fundingVout as number, destinationScript,
    refundLockHeight: data.refundLockHeight as number, feeSat: data.feeSat as string, outputValueSat: data.outputValueSat as string,
    vsize: data.vsize as number });
  return Object.freeze({ networkIdentity, api, broadcastApi, ...selector,
    rawFundingTransactionHex, refund });
}

function draftFields(value: unknown): readonly string[] {
  const outpoint = value !== null && typeof value === "object" && Object.hasOwn(value, "selection");
  return ["networkIdentity", "api", "broadcastApi", ...(outpoint ? ["selection"] : ["fundingAttemptId", "bindingRevision"]), "rawFundingTransactionHex", "refund"];
}

function validateRecord(value: unknown): RefundJournalRecord {
  const data = object(value, ["id", "signedDigest", "createdAt", "updatedAt", "state", ...draftFields(value)]);
  const { id: _id, signedDigest: _digest, createdAt: _created, updatedAt: _updated, state: _state, ...draftData } = data;
  const draft = draftSnapshot(draftData);
  require(data.id === recordId(draft.networkIdentity, draft.refund.fundingTxid, draft.refund.fundingVout));
  require(data.signedDigest === bytesToHex(sha256(hexToBytes(draft.refund.transactionHex))));
  require(integer(data.createdAt, 0, Number.MAX_SAFE_INTEGER) && integer(data.updatedAt, data.createdAt as number, Number.MAX_SAFE_INTEGER));
  require(["prepared", "submission-unknown", "accepted"].includes(data.state as string));
  return Object.freeze({ ...draft, id: data.id as string, signedDigest: data.signedDigest as string,
    createdAt: data.createdAt as number, updatedAt: data.updatedAt as number, state: data.state as RefundSubmissionState });
}

function sameDraft(record: RefundJournalRecord, draft: RefundJournalDraft): boolean {
  const project = (item: RefundJournalDraft) => ({ networkIdentity: item.networkIdentity, api: item.api, broadcastApi: item.broadcastApi,
    ...("selection" in item ? { selection: item.selection } : { fundingAttemptId: item.fundingAttemptId, bindingRevision: item.bindingRevision }),
    rawFundingTransactionHex: item.rawFundingTransactionHex, refund: item.refund });
  return canonicalize(project(record)) === canonicalize(project(draft));
}

export class BrowserRefundJournal {
  private constructor(private readonly db: IDBDatabase) {}

  /** Explicit action only. Absent storage never proves that no previous refund was exposed. */
  static async open(): Promise<BrowserRefundJournal> {
    try {
      const db = await new Promise<IDBDatabase>((resolve, reject) => {
        let refused = false;
        const request = indexedDB.open(DATABASE);
        request.onupgradeneeded = (event) => {
          if ((event as IDBVersionChangeEvent).oldVersion !== 0 || request.result.objectStoreNames.length !== 0) {
            refused = true; request.transaction!.abort(); return;
          }
          request.result.createObjectStore(STORE, { keyPath: "id" });
        };
        request.onblocked = request.onerror = () => { refused = true; reject(new RefundJournalRefusedError()); };
        request.onsuccess = () => {
          const db = request.result;
          if (refused || db.objectStoreNames.length !== 1 || !db.objectStoreNames.contains(STORE)) {
            db.close(); reject(new RefundJournalRefusedError()); return;
          }
          const store = db.transaction(STORE).objectStore(STORE);
          if (store.keyPath !== "id" || store.autoIncrement || store.indexNames.length !== 0) {
            db.close(); reject(new RefundJournalRefusedError()); return;
          }
          db.onversionchange = () => db.close();
          resolve(db);
        };
      });
      return new BrowserRefundJournal(db);
    } catch { throw new RefundJournalRefusedError(); }
  }

  close(): void { this.db.close(); }

  private async access<T>(id: string, write: boolean, operation: (value: unknown, store: IDBObjectStore) => T): Promise<T> {
    try {
      return await new Promise<T>((resolve, reject) => {
        const tx = this.db.transaction(STORE, write ? "readwrite" : "readonly", write ? { durability: "strict" } : {});
        if (write && tx.durability !== "strict") { tx.abort(); reject(new RefundJournalRefusedError()); return; }
        let result: T;
        tx.onabort = tx.onerror = () => reject(new RefundJournalRefusedError());
        tx.oncomplete = () => resolve(result);
        const store = tx.objectStore(STORE), request = store.get(id);
        request.onsuccess = () => {
          try { result = operation(request.result, store); }
          catch { tx.abort(); }
        };
      });
    } catch { throw new RefundJournalRefusedError(); }
  }

  async get(networkIdentity: unknown, fundingTxid: string, fundingVout: number): Promise<RefundJournalRecord | undefined> {
    try {
      const id = recordId(snapshotNetwork(networkIdentity), fundingTxid, fundingVout);
      return await this.access(id, false, (value) => {
        if (value === undefined) return undefined;
        const record = validateRecord(value); require(record.id === id); return record;
      });
    } catch { throw new RefundJournalRefusedError(); }
  }

  async prepare(input: RefundJournalDraft): Promise<RefundJournalRecord> {
    try {
      const draft = draftSnapshot(input), id = recordId(draft.networkIdentity, draft.refund.fundingTxid, draft.refund.fundingVout);
      const record = await this.access(id, true, (value, store) => {
        if (value !== undefined) {
          const existing = validateRecord(value); require(existing.id === id && sameDraft(existing, draft) && existing.state === "prepared");
          return existing; // Exact stored bytes, never a re-signed equivalent transaction.
        }
        const now = Date.now();
        const created = validateRecord({ ...draft, id, signedDigest: bytesToHex(sha256(hexToBytes(draft.refund.transactionHex))),
          createdAt: now, updatedAt: now, state: "prepared" });
        store.add(created); return created;
      });
      return await this.readback(record);
    } catch { throw new RefundJournalRefusedError(); }
  }

  /** Atomic winner only. Commit and readback must finish BEFORE export or POST. Never roll back. */
  async beginExposure(expected: RefundJournalRecord): Promise<RefundJournalRecord> {
    try {
      const snapshot = validateRecord(expected);
      require(snapshot.state === "prepared");
      const record = await this.access(snapshot.id, true, (value, store) => {
        const current = validateRecord(value);
        require(current.id === snapshot.id && current.signedDigest === snapshot.signedDigest && sameDraft(current, snapshot) && current.state === "prepared");
        const updated = validateRecord({ ...current, state: "submission-unknown", updatedAt: Math.max(Date.now(), current.updatedAt) });
        store.put(updated); return updated;
      });
      return await this.readback(record);
    } catch { throw new RefundJournalRefusedError(); }
  }

  /** Explicit manual re-export only. Does NOT authorize a second application POST or reset state. */
  async reexportIdentical(expected: RefundJournalRecord): Promise<RefundJournalRecord> {
    try {
      const snapshot = validateRecord(expected);
      require(snapshot.state !== "prepared");
      return await this.access(snapshot.id, false, (value) => {
        const current = validateRecord(value);
        require(current.id === snapshot.id && current.signedDigest === snapshot.signedDigest && sameDraft(current, snapshot) && current.state !== "prepared");
        return current;
      });
    } catch { throw new RefundJournalRefusedError(); }
  }

  /** An exact txid response means accepted by the API, not mined, settled, or complete. */
  async markAccepted(expected: RefundJournalRecord, returnedTxid: string): Promise<RefundJournalRecord> {
    try {
      const snapshot = validateRecord(expected); require(snapshot.state === "submission-unknown" && returnedTxid === snapshot.refund.txid);
      const record = await this.access(snapshot.id, true, (value, store) => {
        const current = validateRecord(value);
        require(current.id === snapshot.id && current.signedDigest === snapshot.signedDigest && sameDraft(current, snapshot) && current.state === "submission-unknown");
        const updated = validateRecord({ ...current, state: "accepted", updatedAt: Math.max(Date.now(), current.updatedAt) });
        store.put(updated); return updated;
      });
      return await this.readback(record);
    } catch { throw new RefundJournalRefusedError(); }
  }

  private async readback(expected: RefundJournalRecord): Promise<RefundJournalRecord> {
    const stored = await this.get(expected.networkIdentity, expected.refund.fundingTxid, expected.refund.fundingVout);
    require(stored !== undefined && canonicalize(stored) === canonicalize(expected));
    return stored!;
  }
}
