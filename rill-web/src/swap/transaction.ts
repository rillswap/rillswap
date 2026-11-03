/**
 * Bounded Bitcoin transaction and finalized-PSBT parsing for funding review.
 *
 * Mirrors rill-core's funding parser limits: version 2, 1..100 inputs and
 * outputs, canonical CompactSize, no trailing bytes, no coinbase input, and
 * no superfluous witness marker. Input values come from the PSBT's
 * witness_utxo declarations (the wallet's claim, not a verified UTXO).
 */
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils.js";

export const MAX_TRANSACTION_BYTES = 100_000;
const MAX_ITEMS = 100;
const MAX_SCRIPT_BYTES = 10_000;
const MAX_WITNESS_ITEMS = 500;
const MAX_SATS = 2_100_000_000_000_000n;
const PSBT_MAGIC = "70736274ff";

export class TransactionRefusedError extends Error {
  constructor(reason: string) {
    super(`Transaction refused: ${reason}`);
    this.name = "TransactionRefusedError";
  }
}

export interface TxInput {
  readonly txid: string; // display (reversed) order
  readonly vout: number;
  readonly scriptSig: Uint8Array;
  readonly sequence: number;
  readonly witness: readonly Uint8Array[];
}

export interface TxOutput {
  readonly value: bigint;
  readonly script: Uint8Array;
}

export interface Transaction {
  readonly version: number;
  readonly inputs: readonly TxInput[];
  readonly outputs: readonly TxOutput[];
  readonly locktime: number;
  readonly txid: string;
  readonly raw: Uint8Array;
}

class Reader {
  offset = 0;
  constructor(readonly bytes: Uint8Array) {}

  take(length: number): Uint8Array {
    if (length < 0 || this.offset + length > this.bytes.length) throw new TransactionRefusedError("truncated");
    const out = this.bytes.slice(this.offset, this.offset + length);
    this.offset += length;
    return out;
  }

  u8(): number {
    return this.take(1)[0]!;
  }

  u32(): number {
    const b = this.take(4);
    return (b[0]! | (b[1]! << 8) | (b[2]! << 16)) + b[3]! * 2 ** 24;
  }

  u64(): bigint {
    const b = this.take(8);
    let value = 0n;
    for (let index = 7; index >= 0; index -= 1) value = (value << 8n) | BigInt(b[index]!);
    return value;
  }

  compactSize(limit: number): number {
    const first = this.u8();
    let value: number;
    let minimum: number;
    if (first < 0xfd) return checkLimit(first, limit);
    if (first === 0xfd) {
      const b = this.take(2);
      value = b[0]! | (b[1]! << 8);
      minimum = 0xfd;
    } else if (first === 0xfe) {
      value = this.u32();
      minimum = 0x10000;
    } else {
      throw new TransactionRefusedError("CompactSize too large");
    }
    if (value < minimum) throw new TransactionRefusedError("non-canonical CompactSize");
    return checkLimit(value, limit);
  }

  bytesWithLength(limit: number): Uint8Array {
    return this.take(this.compactSize(limit));
  }

  get done(): boolean {
    return this.offset === this.bytes.length;
  }
}

function checkLimit(value: number, limit: number): number {
  if (value > limit) throw new TransactionRefusedError("item count or size over limit");
  return value;
}

const hash256 = (bytes: Uint8Array): Uint8Array => sha256(sha256(bytes));
const reversedHex = (bytes: Uint8Array): string => bytesToHex(Uint8Array.from(bytes).reverse());

function u32le(value: number): Uint8Array {
  return Uint8Array.of(value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff);
}

function u64le(value: bigint): Uint8Array {
  const out = new Uint8Array(8);
  for (let index = 0; index < 8; index += 1) out[index] = Number((value >> BigInt(8 * index)) & 0xffn);
  return out;
}

function compactSizeBytes(value: number): Uint8Array {
  if (value < 0xfd) return Uint8Array.of(value);
  if (value <= 0xffff) return Uint8Array.of(0xfd, value & 0xff, value >> 8);
  return concatBytes(Uint8Array.of(0xfe), u32le(value));
}

const withLength = (bytes: Uint8Array): Uint8Array => concatBytes(compactSizeBytes(bytes.length), bytes);

function outpointBytes(input: TxInput): Uint8Array {
  const hash = hexToBytes(input.txid).reverse();
  return concatBytes(hash, u32le(input.vout));
}

export function serializeTransaction(
  tx: Pick<Transaction, "version" | "inputs" | "outputs" | "locktime">,
  withWitness: boolean,
): Uint8Array {
  const segwit = withWitness && tx.inputs.some((input) => input.witness.length > 0);
  const parts: Uint8Array[] = [u32le(tx.version)];
  if (segwit) parts.push(Uint8Array.of(0x00, 0x01));
  parts.push(compactSizeBytes(tx.inputs.length));
  for (const input of tx.inputs) {
    parts.push(outpointBytes(input), withLength(input.scriptSig), u32le(input.sequence));
  }
  parts.push(compactSizeBytes(tx.outputs.length));
  for (const output of tx.outputs) parts.push(u64le(output.value), withLength(output.script));
  if (segwit) {
    for (const input of tx.inputs) {
      parts.push(compactSizeBytes(input.witness.length), ...input.witness.map(withLength));
    }
  }
  parts.push(u32le(tx.locktime));
  return concatBytes(...parts);
}

function readInputs(reader: Reader): { txid: string; vout: number; scriptSig: Uint8Array; sequence: number }[] {
  const count = reader.compactSize(MAX_ITEMS);
  if (count === 0) throw new TransactionRefusedError("no inputs");
  return Array.from({ length: count }, () => {
    const hash = reader.take(32);
    const vout = reader.u32();
    if (hash.every((byte) => byte === 0) && vout === 0xffffffff) {
      throw new TransactionRefusedError("coinbase input");
    }
    return { txid: reversedHex(hash), vout, scriptSig: reader.bytesWithLength(MAX_SCRIPT_BYTES), sequence: reader.u32() };
  });
}

function readOutputs(reader: Reader): TxOutput[] {
  const count = reader.compactSize(MAX_ITEMS);
  if (count === 0) throw new TransactionRefusedError("no outputs");
  return Array.from({ length: count }, () => {
    const value = reader.u64();
    if (value > MAX_SATS) throw new TransactionRefusedError("output value out of range");
    return { value, script: reader.bytesWithLength(MAX_SCRIPT_BYTES) };
  });
}

/** Parse one complete version-2 transaction; witness data is optional. */
export function parseTransaction(raw: Uint8Array): Transaction {
  return parseTransactionBytes(raw, true);
}

/** Recovery observes existing funding bytes, not live version-2 funding policy. */
export function parseRecoveryFundingTransaction(raw: Uint8Array): Transaction {
  return parseTransactionBytes(raw, false);
}

function parseTransactionBytes(raw: Uint8Array, requireVersionTwo: boolean): Transaction {
  if (raw.length === 0 || raw.length > MAX_TRANSACTION_BYTES) throw new TransactionRefusedError("size unsupported");
  const reader = new Reader(raw);
  const version = reader.u32();
  if (requireVersionTwo && version !== 2) throw new TransactionRefusedError("version must be 2");
  const segwit = raw[4] === 0x00;
  if (segwit && reader.take(2)[1] !== 0x01) throw new TransactionRefusedError("witness flag");
  const bare = readInputs(reader);
  const outputs = readOutputs(reader);
  const witnesses = bare.map(() =>
    segwit
      ? Array.from({ length: reader.compactSize(MAX_WITNESS_ITEMS) }, () =>
          reader.bytesWithLength(MAX_TRANSACTION_BYTES),
        )
      : [],
  );
  if (segwit && witnesses.every((stack) => stack.length === 0)) {
    throw new TransactionRefusedError("superfluous witness marker");
  }
  const locktime = reader.u32();
  if (!reader.done) throw new TransactionRefusedError("trailing bytes");
  const inputs = bare.map((input, index) => ({ ...input, witness: witnesses[index]! }));
  const tx = { version, inputs, outputs, locktime };
  return { ...tx, txid: reversedHex(hash256(serializeTransaction(tx, false))), raw };
}

export interface FinalizedFunding {
  readonly transaction: Transaction;
  /** Declared value of each input's spent output, in input order. */
  readonly inputValues: readonly bigint[];
}

type PsbtMap = Map<string, Uint8Array>;

function readMap(reader: Reader): PsbtMap {
  const map: PsbtMap = new Map();
  for (;;) {
    const key = reader.bytesWithLength(MAX_TRANSACTION_BYTES);
    if (key.length === 0) return map;
    const id = bytesToHex(key);
    if (map.has(id)) throw new TransactionRefusedError("duplicate PSBT key");
    map.set(id, reader.bytesWithLength(MAX_TRANSACTION_BYTES));
  }
}

/**
 * Extract the signed transaction from a finalized PSBT (BIP174 v0). Every
 * input must be native segwit: a final witness, no final scriptSig, and a
 * witness_utxo declaring its value.
 */
export function extractFinalizedPsbt(psbt: Uint8Array): FinalizedFunding {
  if (psbt.length > 4 * MAX_TRANSACTION_BYTES || bytesToHex(psbt.slice(0, 5)) !== PSBT_MAGIC) {
    throw new TransactionRefusedError("not a PSBT");
  }
  const reader = new Reader(psbt);
  reader.take(5);
  const global = readMap(reader);
  const unsignedBytes = global.get("00");
  const version = global.get("fb");
  if (!unsignedBytes || (version !== undefined && bytesToHex(version) !== "00000000")) {
    throw new TransactionRefusedError("PSBT version 0 with an unsigned transaction required");
  }
  const unsigned = parseTransaction(unsignedBytes);
  if (unsigned.inputs.some((input) => input.scriptSig.length > 0 || input.witness.length > 0)) {
    throw new TransactionRefusedError("PSBT unsigned transaction carries signatures");
  }
  const inputValues: bigint[] = [];
  const inputs = unsigned.inputs.map((input) => {
    const map = readMap(reader);
    const utxo = map.get("01");
    const witness = map.get("08");
    const scriptSig = map.get("07");
    if (!utxo || !witness || (scriptSig && scriptSig.length > 0)) {
      throw new TransactionRefusedError("every input must be finalized native segwit with a witness_utxo");
    }
    const utxoReader = new Reader(utxo);
    const value = utxoReader.u64();
    utxoReader.bytesWithLength(MAX_SCRIPT_BYTES);
    const witnessReader = new Reader(witness);
    const stack = Array.from({ length: witnessReader.compactSize(MAX_WITNESS_ITEMS) }, () =>
      witnessReader.bytesWithLength(MAX_TRANSACTION_BYTES),
    );
    if (!utxoReader.done || !witnessReader.done || value > MAX_SATS || stack.length === 0) {
      throw new TransactionRefusedError("PSBT input record malformed");
    }
    inputValues.push(value);
    return { ...input, witness: stack };
  });
  for (let index = 0; index < unsigned.outputs.length; index += 1) readMap(reader);
  if (!reader.done) throw new TransactionRefusedError("trailing PSBT bytes");
  const transaction = parseTransaction(serializeTransaction({ ...unsigned, inputs }, true));
  return { transaction, inputValues };
}
