/**
 * Shared BOLT11 decoding for browser and merchant clients (no node required).
 *
 * `decodeBolt11` follows the specification's reader rules; `invoiceBinding`
 * then applies the same admission policy as rill-provider's LND adapter and
 * produces the RS-001 InvoiceBinding the provider must echo exactly.
 */
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { bech32 } from "@scure/base";

const MAX_INVOICE_CHARS = 2048;
const SIGNATURE_WORDS = 104;
const DEFAULT_EXPIRY_SECONDS = 3600;
const DEFAULT_MIN_FINAL_CLTV = 18;
const HASH_WORDS = 52;
const PAYEE_WORDS = 53;
const MULTIPLIER: Record<string, bigint> = { "": 100_000_000_000n, m: 100_000_000n, u: 100_000n, n: 100n };
const ACCEPTED_FEATURES = new Set([8, 9, 14, 15, 17, 25]);
// s, x, n, c: fields that must appear at most once (see parseFields). A
// repeated `9` stays last-wins; tests/bolt11Metadata.test.ts relies on it.
const BINDING_TAGS = new Set([16, 6, 19, 24]);
const encoder = new TextEncoder();

export class InvoiceRejectedError extends Error {
  constructor(reason: string) {
    super(`Invoice refused: ${reason}`);
    this.name = "InvoiceRejectedError";
  }
}

export interface DecodedInvoice {
  readonly currency: string;
  readonly amountMsat: bigint | null;
  readonly timestamp: number;
  readonly paymentHash: string | null;
  readonly paymentSecret: string | null;
  readonly payee: string;
  readonly expirySeconds: number;
  readonly minFinalCltvDelta: number;
  readonly features: ReadonlySet<number>;
  readonly blindedPaths: boolean;
}

export interface InvoiceBinding {
  readonly bolt11_sha256: string;
  readonly payment_hash: string;
  readonly amount_msat: string;
  readonly payee_compressed_pubkey: string;
  readonly created_at: number;
  readonly expires_at: number;
  readonly min_final_cltv_delta: number;
}

function wordsToInt(words: readonly number[]): number {
  let value = 0;
  for (const word of words) value = value * 32 + word;
  return value;
}

/** 5-bit groups to bytes, zero-padding the final partial byte. */
function wordsToBytes(words: readonly number[], exact: boolean): Uint8Array {
  const out: number[] = [];
  let accumulator = 0;
  let bits = 0;
  for (const word of words) {
    accumulator = (accumulator << 5) | word;
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      out.push((accumulator >> bits) & 0xff);
    }
    accumulator &= (1 << bits) - 1;
  }
  if (bits > 0 && !exact) out.push((accumulator << (8 - bits)) & 0xff);
  return Uint8Array.from(out);
}

function amountMsat(amount: string): bigint | null {
  if (amount === "") return null;
  const match = /^([1-9][0-9]*)([munp]?)$/.exec(amount);
  if (!match) throw new InvoiceRejectedError("amount malformed");
  const value = BigInt(match[1]!);
  const unit = match[2]!;
  if (unit === "p") {
    if (value % 10n !== 0n) throw new InvoiceRejectedError("sub-millisatoshi amount");
    return value / 10n;
  }
  return value * MULTIPLIER[unit]!;
}

function featureBits(words: readonly number[]): Set<number> {
  const bits = new Set<number>();
  words.forEach((word, index) => {
    for (let bit = 0; bit < 5; bit += 1) {
      if (word & (1 << bit)) bits.add((words.length - 1 - index) * 5 + bit);
    }
  });
  return bits;
}

/** Decode and authenticate one BOLT11 string (reader rules only, no policy). */
export function decodeBolt11(invoice: string): DecodedInvoice {
  if (typeof invoice !== "string" || invoice.length === 0 || invoice.length > MAX_INVOICE_CHARS) {
    throw new InvoiceRejectedError("length unsupported");
  }
  let decoded: { prefix: string; words: number[] };
  try {
    decoded = bech32.decode(invoice as `${string}1${string}`, MAX_INVOICE_CHARS);
  } catch {
    throw new InvoiceRejectedError("bech32 invalid");
  }
  const hrp = decoded.prefix;
  const words = Array.from(decoded.words);
  const human = /^ln([a-z]+?)((?:[0-9]+[a-z]?)?)$/.exec(hrp);
  if (!human) throw new InvoiceRejectedError("prefix malformed");
  const currency = human[1]!;
  const amount = amountMsat(human[2]!);
  if (words.length < 7 + SIGNATURE_WORDS) throw new InvoiceRejectedError("too short");
  const data = words.slice(0, -SIGNATURE_WORDS);
  const signature = wordsToBytes(words.slice(-SIGNATURE_WORDS), true);
  const fields = parseFields(data.slice(7));
  const digest = sha256(new Uint8Array([...encoder.encode(hrp), ...wordsToBytes(data, false)]));
  const payee = authenticate(signature, digest, fields.payee);
  return {
    currency,
    amountMsat: amount,
    timestamp: wordsToInt(data.slice(0, 7)),
    paymentHash: fields.paymentHash,
    paymentSecret: fields.paymentSecret,
    payee,
    expirySeconds: fields.expiry ?? DEFAULT_EXPIRY_SECONDS,
    minFinalCltvDelta: fields.minFinalCltv ?? DEFAULT_MIN_FINAL_CLTV,
    features: fields.features,
    blindedPaths: fields.blindedPaths,
  };
}

interface Fields {
  description: string | null;
  paymentHash: string | null;
  paymentSecret: string | null;
  payee: Uint8Array | null;
  expiry: number | null;
  minFinalCltv: number | null;
  features: Set<number>;
  blindedPaths: boolean;
  metadataHash: string | null;
  metadataHashCount: number;
  metadataHashCanonical: boolean;
  hasDescription: boolean;
}

function parseFields(words: readonly number[]): Fields {
  const fields: Fields = {
    description: null,
    paymentHash: null,
    paymentSecret: null,
    payee: null,
    expiry: null,
    minFinalCltv: null,
    features: new Set(),
    blindedPaths: false,
    metadataHash: null,
    metadataHashCount: 0,
    metadataHashCanonical: false,
    hasDescription: false,
  };
  const seen = new Set<number>();
  let index = 0;
  while (index < words.length) {
    if (index + 3 > words.length) throw new InvoiceRejectedError("tagged field truncated");
    const type = words[index]!;
    const length = words[index + 1]! * 32 + words[index + 2]!;
    const value = words.slice(index + 3, index + 3 + length);
    if (value.length !== length) throw new InvoiceRejectedError("tagged field truncated");
    index += 3 + length;
    // Private facts for the explicit metadata-bound profile only. Ordinary
    // readers keep their original policy and public decoded/binding shapes.
    if (type === 13) {
      fields.hasDescription = true;
      fields.description ??= new TextDecoder().decode(wordsToBytes(value, true));
    }
    if (type === 23) {
      fields.metadataHashCount++;
      if (length === HASH_WORDS && fields.metadataHash === null) {
        fields.metadataHash = bytesToHex(wordsToBytes(value, false).slice(0, 32));
        fields.metadataHashCanonical = (value[HASH_WORDS - 1]! & 15) === 0;
      }
    }
    // BOLT11 reader requirements reject every wrong-length p/h/s/n occurrence.
    // Duplicate binding rejection is our stricter application policy, not a
    // claim that the unmerged lightning/bolts#1357 is a normative requirement.
    if (type === 1) {
      if (length !== HASH_WORDS) throw new InvoiceRejectedError("payment hash length invalid");
      if (fields.paymentHash !== null) throw new InvoiceRejectedError("multiple payment hashes");
    }
    if (((type === 16 || type === 23) && length !== HASH_WORDS) || (type === 19 && length !== PAYEE_WORDS)) {
      throw new InvoiceRejectedError("fixed-length field invalid");
    }
    // Secret, payee, expiry and CLTV feed the binding and payment.
    // Readers disagree on repeats (LND keeps the first), so refuse them.
    if (BINDING_TAGS.has(type)) {
      if (seen.has(type)) throw new InvoiceRejectedError("duplicate binding field");
      seen.add(type);
    }
    if (type === 1 && length === HASH_WORDS && fields.paymentHash === null) {
      fields.paymentHash = bytesToHex(wordsToBytes(value, false).slice(0, 32));
    } else if (type === 16 && length === HASH_WORDS && fields.paymentSecret === null) {
      fields.paymentSecret = bytesToHex(wordsToBytes(value, false).slice(0, 32));
    } else if (type === 19 && length === PAYEE_WORDS && fields.payee === null) {
      fields.payee = wordsToBytes(value, false).slice(0, 33);
    } else if (type === 6 && fields.expiry === null && length > 0 && length <= 10) {
      fields.expiry = wordsToInt(value);
    } else if (type === 24 && fields.minFinalCltv === null && length > 0 && length <= 10) {
      fields.minFinalCltv = wordsToInt(value);
    } else if (type === 5) {
      fields.features = featureBits(value);
    } else if (type === 20) {
      fields.blindedPaths = true;
    }
  }
  return fields;
}

/** Optional authenticated display metadata only, never a signed swap binding or payment secret. */
export function invoiceDescription(invoice: string): string | null {
  decodeBolt11(invoice);
  const { words } = bech32.decode(invoice as `${string}1${string}`, MAX_INVOICE_CHARS);
  return parseFields(Array.from(words).slice(7, -SIGNATURE_WORDS)).description;
}

function authenticate(signature: Uint8Array, digest: Uint8Array, payee: Uint8Array | null): string {
  const recovery = signature[64]!;
  const compact = signature.slice(0, 64);
  try {
    if (payee !== null) {
      // With an explicit payee the signature must verify, and in low-S form.
      if (!secp256k1.verify(compact, digest, payee, { prehash: false, lowS: true })) {
        throw new Error("signature");
      }
      return bytesToHex(payee);
    }
    if (recovery > 3) throw new Error("recovery flag");
    const recovered = secp256k1.Signature.fromBytes(compact, "compact")
      .addRecoveryBit(recovery)
      .recoverPublicKey(digest);
    return recovered.toHex(true);
  } catch {
    throw new InvoiceRejectedError("signature invalid");
  }
}

/** BOLT11 currency per supported network name (testnet3 and testnet4 share `tb`). */
export const INVOICE_CURRENCY: Readonly<Record<string, string>> = {
  mainnet: "bc",
  testnet3: "tb",
  testnet4: "tb",
  signet: "tbs",
  regtest: "bcrt",
};

/**
 * Admit one invoice for `networkName` under rill-provider's LND policy and
 * return its binding. Expiry against the clock is the caller's check.
 */
export function invoiceBinding(invoice: string, networkName: string): InvoiceBinding {
  if (!/^ln[a-z0-9]{1,2046}$/.test(invoice)) throw new InvoiceRejectedError("not lowercase BOLT11");
  const decoded = decodeBolt11(invoice);
  if (decoded.currency !== INVOICE_CURRENCY[networkName]) {
    throw new InvoiceRejectedError("invoice is not for the selected network");
  }
  const features = decoded.features;
  const one = (a: number, b: number): boolean => features.has(a) !== features.has(b);
  if (![...features].every((bit) => ACCEPTED_FEATURES.has(bit)) || !one(8, 9) || !one(14, 15)) {
    throw new InvoiceRejectedError("feature bits unsupported");
  }
  if (decoded.paymentSecret === null || decoded.paymentHash === null || decoded.blindedPaths) {
    throw new InvoiceRejectedError("payment secret, hash, or route form unsupported");
  }
  const amount = decoded.amountMsat;
  if (amount === null || amount <= 0n || amount % 1000n !== 0n) {
    throw new InvoiceRejectedError("amount must be a positive whole number of satoshis");
  }
  if (decoded.expirySeconds <= 0 || decoded.minFinalCltvDelta <= 0) {
    throw new InvoiceRejectedError("expiry or final CLTV unsupported");
  }
  return {
    bolt11_sha256: bytesToHex(sha256(encoder.encode(invoice))),
    payment_hash: decoded.paymentHash,
    amount_msat: amount.toString(),
    payee_compressed_pubkey: decoded.payee,
    created_at: decoded.timestamp,
    expires_at: decoded.timestamp + decoded.expirySeconds,
    min_final_cltv_delta: decoded.minFinalCltvDelta,
  };
}

/** Explicit strict hash-bound profile, not a requirement of current LNURL-pay.
 * The signature authenticates invoice contents, not an independently expected
 * merchant identity, order, amount, expiry or settlement. Callers pin those.
 */
export function invoiceMetadataBinding(invoice: string, networkName: string, metadata: string): InvoiceBinding {
  if (typeof metadata !== "string" || metadata.length > 16384) throw new InvoiceRejectedError("metadata size or type unsupported");
  const encoded = encoder.encode(metadata);
  if (encoded.length > 16384 || new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(encoded) !== metadata) throw new InvoiceRejectedError("metadata UTF-8 unsupported");
  // This authenticates the full original payload using the unchanged admission
  // policy. Re-reading its private tag facts does not authenticate another invoice.
  const binding = invoiceBinding(invoice, networkName);
  const decoded = bech32.decode(invoice as `${string}1${string}`, MAX_INVOICE_CHARS);
  const fields = parseFields(decoded.words.slice(7, -SIGNATURE_WORDS));
  if (fields.metadataHashCount !== 1 || fields.metadataHash === null || !fields.metadataHashCanonical || fields.hasDescription) throw new InvoiceRejectedError("metadata description tags unsupported");
  // Hash exact UTF-8 bytes, without Unicode normalization or JSON reserialization.
  if (fields.metadataHash !== bytesToHex(sha256(encoded))) throw new InvoiceRejectedError("metadata hash differs");
  return binding;
}
